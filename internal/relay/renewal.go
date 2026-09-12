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

	agentv1 "github.com/ultherego/flotestro/internal/genproto/flotestro/agent/v1"
	"github.com/ultherego/flotestro/internal/genproto/flotestro/agent/v1/agentv1connect"
	"github.com/ultherego/flotestro/internal/identitystore"
)

// renewalThreshold says when to start renewing: once less than a third of the
// validity period is left. The certificate of a relay lives seven days, so
// around two days are left for the retries - rather than the last hours before
// the expiry, in which a failure of the centre cuts off a whole site.
const renewalThreshold = 1.0 / 3.0

// The intervals of the checks. The short lifetime of the certificate of a
// relay calls for looking more often than with an agent, but not for polling
// in a loop.
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
//
// The swap is atomic, because the listener of the relay reaches for the
// certificate at every TLS handshake. A renewal must not require a restart of
// the process: a restart tears down the sessions of every agent of the site at
// once, while a renewal happens regularly and is not an operational event in
// itself.
type Live struct {
	current atomic.Pointer[Identity]
	// registration says whether the listener is to let connections without a
	// client certificate in. It is enabled only when the relay mediates in the
	// registration.
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
// the site. The trust set is read at every handshake: after a rotation of the
// CA of the fleet the relay is to accept the new certificates of the agents
// without a restart.
//
// Whether a client certificate is required depends on whether the relay
// mediates in the registration as well. A host before its enrollment has
// nothing to present itself with, so the handshake must not demand one; every
// RPC then checks the certificate separately and refuses everything but the
// registration itself without it.
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
	StateDir   string
	GatewayURL string
	// Names are a wish of the relay. The centre issues what it has in its
	// registry; we send them so that a divergence between the configuration
	// and the registry is visible in the panel rather than only in rejected
	// connections of the agents.
	Names   []string
	Version string
	Log     *slog.Logger
	// AfterRenewal is called once the identity has been swapped. The relay
	// then refreshes its connection to the centre so that it goes with the new
	// certificate.
	AfterRenewal func(Identity)
}

// KeepCertificate renews the certificate of the relay before it expires.
//
// A relay without a valid certificate is not only cut off itself: it stops
// mediating for a whole site. That is why it renews earlier than an agent and
// tries more often after an error.
func KeepCertificate(ctx context.Context, live *Live, options RenewalOptions) {
	log := options.Log
	if log == nil {
		log = slog.Default()
	}
	timer := time.NewTimer(checkInterval(live.Current()))
	defer timer.Stop()

	for {
		if needsRenewal(live.Current()) {
			renewed, err := renew(ctx, live.Current(), options)
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
			// The swap first, the notification afterwards: the new handshakes
			// are to go with the new certificate from the first moment rather
			// than from the point where somebody finishes handling an event.
			live.Swap(renewed)
			log.Info("the certificate of the relay was renewed",
				"relay_id", renewed.RelayID,
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
		// An unknown date does not mean "still a long way off". An attempt to
		// renew is cheap, and not knowing the validity is a reason in
		// itself.
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
func renew(ctx context.Context, current_ Identity, options RenewalOptions) (Identity, error) {
	store := identitystore.New(options.StateDir)
	key, err := store.NewKey()
	if err != nil {
		return Identity{}, err
	}
	dns, addresses := splitNames(options.Names)
	csrPEM, err := identitystore.Request(key, current_.RelayID, dns, addresses)
	if err != nil {
		return Identity{}, err
	}

	// The renewal goes over mTLS with the current certificate: it is the proof
	// of the identity of the relay. The enrollment token takes no part in
	// it.
	client_ := agentv1connect.NewRelayServiceClient(&http.Client{
		Timeout: 60 * time.Second,
		Transport: &http2.Transport{
			TLSClientConfig: &tls.Config{
				Certificates: []tls.Certificate{current_.Certificate},
				RootCAs:      current_.CAPool,
				MinVersion:   tls.VersionTLS13,
			},
		},
	}, options.GatewayURL)

	response, err := client_.RenewCertificate(ctx,
		connect.NewRequest(&agentv1.RenewRelayCertificateRequest{
			CsrPem:          csrPEM,
			Build:           &agentv1.AgentBuild{AgentVersion: options.Version},
			AdvertisedNames: options.Names,
		}))
	if err != nil {
		return Identity{}, fmt.Errorf("the renewal was rejected: %w", err)
	}

	// The trust bundle changes only at a rotation of the CA of the fleet. When
	// the centre did not send one, the one in force goes into the generation:
	// a generation has to be a complete set rather than a key without a named
	// trust.
	bundle := response.Msg.GetClientCaBundlePem()
	if len(bundle) == 0 {
		bundle = current_.TrustPEM
	}
	if len(bundle) == 0 {
		return Identity{}, fmt.Errorf("a renewal without a trust bundle")
	}

	saved, err := store.Commit(identitystore.Generation{
		Key:            key,
		CertificatePEM: response.Msg.GetCertificatePem(),
		TrustPEM:       bundle,
	})
	if err != nil {
		// A rejected generation does not touch what the relay works with:
		// better to stay on the old certificate and try again in a moment than
		// to be left with half a pair and cut off a whole site.
		return Identity{}, fmt.Errorf("the new identity was rejected: %w", err)
	}
	return Identity{
		RelayID:     saved.HostID,
		Certificate: saved.Certificate,
		CAPool:      saved.CAPool,
		NotAfter:    saved.NotAfter,
		TrustPEM:    saved.TrustPEM,
	}, nil
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
