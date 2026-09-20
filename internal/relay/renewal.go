package relay

import (
	"context"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"log/slog"
	"math/big"
	"net"
	"net/http"
	"sync/atomic"
	"time"

	"connectrpc.com/connect"
	"golang.org/x/net/http2"

	"github.com/ultherego/flotestro/internal/endpoints"
	agentv1 "github.com/ultherego/flotestro/internal/genproto/flotestro/agent/v1"
	"github.com/ultherego/flotestro/internal/genproto/flotestro/agent/v1/agentv1connect"
	"github.com/ultherego/flotestro/internal/identitystore"
)

// renewalThreshold says when to start renewing: once less than a third of the
// validity period is left.
const renewalThreshold = 1.0 / 3.0

// The intervals of the checks.
const (
	minCheckInterval   = time.Minute
	maxCheckInterval   = time.Hour
	intervalAfterError = 10 * time.Minute
)

// The identity of a relay together with the material that has to be switched
// atomically.
type Identity struct {
	RelayID     string
	Certificate tls.Certificate
	CAPool      *x509.CertPool
	NotAfter    time.Time
	TrustPEM    []byte
}

// Live holds the current material of a relay and allows swapping it while the
// relay works.
type Live struct {
	current atomic.Pointer[Identity]
	// registration says whether the listener is to let connections without a
	// client certificate in.
	registration atomic.Bool
}

// NewLive creates a handle on the current identity of a relay.
func NewLive(identity Identity) *Live {
	live := &Live{}
	live.current.Store(&identity)
	return live
}

// Current returns the current identity.
func (z *Live) Current() Identity { return *z.current.Load() }

// Swap puts a new identity in place.
func (z *Live) Swap(identity Identity) { z.current.Store(&identity) }

// Certificate returns the server certificate for the TLS handshake with an
// agent.
func (z *Live) Certificate(*tls.ClientHelloInfo) (*tls.Certificate, error) {
	identity := z.current.Load()
	return &identity.Certificate, nil
}

// ClientConfiguration returns the settings of the handshake for the agents of
// the site.
func (z *Live) ClientConfiguration(*tls.ClientHelloInfo) (*tls.Config, error) {
	identity := z.current.Load()
	requirement := tls.RequireAndVerifyClientCert
	if z.registration.Load() {
		requirement = tls.VerifyClientCertIfGiven
	}
	return &tls.Config{
		GetCertificate: z.Certificate,
		ClientAuth:     requirement,
		ClientCAs:      identity.CAPool,
		MinVersion:     tls.VersionTLS13,
		NextProtos:     []string{"h2"},
	}, nil
}

// MediatesRegistration says that the relay also accepts hosts without an
// identity.
func (z *Live) MediatesRegistration(enabled bool) { z.registration.Store(enabled) }

// RenewalOptions describe the renewal of the certificate of a relay.
type RenewalOptions struct {
	StateDir string
	// Gateways are the addresses of the centre in order of priority - the same
	// list the data path uses. The certificate of a relay carries a whole site,
	// so its renewal must not depend on one instance of the centre being up.
	Gateways []string
	// Names are a wish of the relay.
	Names   []string
	Version string
	Log     *slog.Logger
	// AfterRenewal is called once the identity has been swapped.
	AfterRenewal func(Identity)
}

// KeepCertificate renews the certificate of the relay before it expires.
func KeepCertificate(ctx context.Context, live *Live, options RenewalOptions) {
	log := options.Log
	if log == nil {
		log = slog.Default()
	}
	timer := time.NewTimer(checkInterval(live.Current()))
	defer timer.Stop()

	for {
		if needsRenewal(live.Current()) {
			renewed, answered, err := renew(ctx, live.Current(), options)
			if err != nil {
				log.Warn("the certificate of the relay could not be renewed",
					"err", err, "expires", live.Current().NotAfter.Format(time.RFC3339))
				select {
				case <-ctx.Done():
					return
				case <-time.After(intervalAfterError):
					continue
				}
			}
			// The swap first, the notification afterwards: the new handshakes are to go
			// with the new certificate from the first moment rather than from the point
			// where somebody finishes handling an event.
			live.Swap(renewed)
			log.Info("the certificate of the relay was renewed",
				"relay_id", renewed.RelayID, "gateway", answered,
				"expires", renewed.NotAfter.Format(time.RFC3339))
			if options.AfterRenewal != nil {
				options.AfterRenewal(renewed)
			}
		}

		timer.Reset(checkInterval(live.Current()))
		select {
		case <-ctx.Done():
			return
		case <-timer.C:
		}
	}
}

// checkInterval scales the checking to the lifetime of the certificate.
func checkInterval(identity Identity) time.Duration {
	whole := identity.NotAfter.Sub(startOf(identity))
	if whole <= 0 {
		return minCheckInterval
	}
	interval := whole / 40
	if interval > maxCheckInterval {
		return maxCheckInterval
	}
	if interval < minCheckInterval {
		return minCheckInterval
	}
	// Full jitter spreads the relays out after a failure of the centre.
	// Without it they all come back in the same second and topple it again.
	return interval/2 + randomDuration(interval/2)
}

// needsRenewal decides on the basis of the remaining part of the validity
// period.
func needsRenewal(identity Identity) bool {
	if identity.NotAfter.IsZero() {
		// An unknown date does not mean "still a long way off". An attempt to renew
		// is cheap, and not knowing the validity is a reason in itself.
		return true
	}
	whole := identity.NotAfter.Sub(startOf(identity))
	if whole <= 0 {
		return true
	}
	return time.Until(identity.NotAfter) < time.Duration(float64(whole)*renewalThreshold)
}

func startOf(identity Identity) time.Time {
	if len(identity.Certificate.Certificate) == 0 {
		return time.Time{}
	}
	leaf, err := x509.ParseCertificate(identity.Certificate.Certificate[0])
	if err != nil {
		return time.Time{}
	}
	return leaf.NotBefore
}

// renew exchanges a new key pair for a certificate and writes it atomically.
// It also returns the address of the gateway that answered.
func renew(ctx context.Context, current_ Identity, options RenewalOptions) (Identity, string, error) {
	store := identitystore.New(options.StateDir)
	key, err := store.NewKey()
	if err != nil {
		return Identity{}, "", err
	}
	dns, addresses := splitNames(options.Names)
	csrPEM, err := identitystore.Request(key, current_.RelayID, dns, addresses)
	if err != nil {
		return Identity{}, "", err
	}

	// The addresses are tried in order of priority, with the same classes and the
	// same jittered pause the data path uses.
	message, answered, err := requestCertificate(ctx,
		endpoints.New(options.Gateways, 0, 0),
		func(ctx context.Context, gatewayURL string) (*agentv1.RenewRelayCertificateResponse, error) {
			response, err := renewalClient(current_, gatewayURL).RenewCertificate(ctx,
				connect.NewRequest(&agentv1.RenewRelayCertificateRequest{
					CsrPem:          csrPEM,
					Build:           &agentv1.AgentBuild{AgentVersion: options.Version},
					AdvertisedNames: options.Names,
				}))
			if err != nil {
				return nil, fmt.Errorf("the renewal was rejected: %w", err)
			}
			return response.Msg, nil
		})
	if err != nil {
		return Identity{}, "", err
	}

	// The trust bundle changes only at a rotation of the CA of the fleet.
	bundle := message.GetClientCaBundlePem()
	if len(bundle) == 0 {
		bundle = current_.TrustPEM
	}
	if len(bundle) == 0 {
		return Identity{}, "", fmt.Errorf("a renewal without a trust bundle")
	}

	saved, err := store.Commit(identitystore.Generation{
		Key:            key,
		CertificatePEM: message.GetCertificatePem(),
		TrustPEM:       bundle,
	})
	if err != nil {
		// A rejected generation does not touch what the relay works with: better to
		// stay on the old certificate and try again in a moment than to be left with
		// half a pair and cut off a whole site.
		return Identity{}, "", fmt.Errorf("the new identity was rejected: %w", err)
	}
	return Identity{
		RelayID:     saved.HostID,
		Certificate: saved.Certificate,
		CAPool:      saved.CAPool,
		NotAfter:    saved.NotAfter,
		TrustPEM:    saved.TrustPEM,
	}, answered, nil
}

// requestCertificate asks the gateways in order until one answers and says
// which one did. When none does, the answer names every address tried.
func requestCertificate(ctx context.Context, gateways *endpoints.Manager,
	exchange func(ctx context.Context, gatewayURL string) (*agentv1.RenewRelayCertificateResponse, error),
) (*agentv1.RenewRelayCertificateResponse, string, error) {
	var message *agentv1.RenewRelayCertificateResponse
	answered, err := gateways.Try(ctx, func(ctx context.Context, gatewayURL string) error {
		response, err := exchange(ctx, gatewayURL)
		if err != nil {
			return err
		}
		message = response
		return nil
	})
	if err != nil {
		return nil, "", err
	}
	return message, answered, nil
}

// renewalClient speaks to one gateway over mTLS with the current certificate:
// it is the proof of the identity of the relay.
func renewalClient(current_ Identity, gatewayURL string) agentv1connect.RelayServiceClient {
	return agentv1connect.NewRelayServiceClient(&http.Client{
		Timeout: 60 * time.Second,
		Transport: &http2.Transport{
			TLSClientConfig: &tls.Config{
				Certificates: []tls.Certificate{current_.Certificate},
				RootCAs:      current_.CAPool,
				MinVersion:   tls.VersionTLS13,
			},
		},
	}, gatewayURL)
}

// splitNames divides the network names into IP addresses and DNS names.
func splitNames(names []string) ([]string, []net.IP) {
	var dns []string
	var addresses []net.IP
	for _, name := range names {
		if address := net.ParseIP(name); address != nil {
			addresses = append(addresses, address)
			continue
		}
		dns = append(dns, name)
	}
	return dns, addresses
}

// randomDuration returns a random interval from the range [0, upper).
func randomDuration(upper time.Duration) time.Duration {
	if upper <= 0 {
		return 0
	}
	n, err := rand.Int(rand.Reader, big.NewInt(int64(upper)))
	if err != nil {
		return upper / 2
	}
	return time.Duration(n.Int64())
}
