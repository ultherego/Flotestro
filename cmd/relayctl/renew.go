package main

import (
	"context"
	"crypto/tls"
	"errors"
	"flag"
	"fmt"
	"io"
	"net"
	"net/http"
	"time"

	"connectrpc.com/connect"
	"golang.org/x/net/http2"

	"github.com/ultherego/flotestro/internal/ctl"
	"github.com/ultherego/flotestro/internal/endpoints"
	agentv1 "github.com/ultherego/flotestro/internal/genproto/flotestro/agent/v1"
	"github.com/ultherego/flotestro/internal/genproto/flotestro/agent/v1/agentv1connect"
	"github.com/ultherego/flotestro/internal/identitystore"
	"github.com/ultherego/flotestro/internal/relayconfig"
)

// renewCommand forces a renewal of the certificate of the relay.
func renewCommand(args []string, out, errOut io.Writer) int {
	flags := flag.NewFlagSet("renew", flag.ContinueOnError)
	flags.SetOutput(errOut)
	path := flags.String("config", relayconfig.DefaultPath, "the configuration file of the relay")
	timeout := flags.Duration("timeout", 2*time.Minute, "the time limit for the renewal")
	if err := flags.Parse(args); err != nil {
		return 2
	}

	cfg, err := relayconfig.Load(*path)
	if err != nil {
		fmt.Fprintf(errOut, "config: %s\n  %v\n", *path, err)
		return 1
	}
	ctx, cancel := context.WithTimeout(context.Background(), *timeout)
	defer cancel()

	r := renewal{
		StateDir: cfg.Relay.StateDir,
		// Every gateway of the configuration, in its order of priority: the
		// certificate of a relay carries a whole site, and its renewal must not
		// depend on one instance of the centre being up.
		Gateways: cfg.Upstream.GatewayURLs,
		Names:    cfg.Relay.AdvertisedNames,
		Now:      time.Now,
		Identity: readIdentity,
		Renew:    renewNow,
	}
	return r.run(ctx, out, errOut)
}

// renewal gathers what a forced renewal touches, so that a test can run it
// on a temporary directory with a clock of its own and without a centre.
type renewal struct {
	StateDir string
	// Gateways are the addresses of the centre in order of priority, the
	// same list the relay's own upstream connection uses.
	Gateways []string
	Names    []string
	Now      func() time.Time
	Identity func(stateDir string) storedIdentity
	Renew    func(ctx context.Context, stateDir, gatewayURL string, names []string) (*identitystore.Identity, error)
}

// run carries the renewal out.
func (r renewal) run(ctx context.Context, out, errOut io.Writer) int {
	now := r.Now()
	throttle := ctl.Throttle{StateDir: r.StateDir}
	if last, wait, tooSoon := throttle.TooSoon(now); tooSoon {
		fmt.Fprintf(errOut, "the last forced renewal was %s ago; the next one is allowed in %s (at %s)\n",
			ctl.Rounded(now.Sub(last)), ctl.Rounded(wait),
			last.Add(ctl.ForcedRenewalInterval).UTC().Format(time.RFC3339))
		return 2
	}

	identity := r.Identity(r.StateDir)
	if !identity.Present {
		fmt.Fprintf(errOut, "identity_missing: %s\n", identity.Err)
		fmt.Fprintln(errOut, "a renewal needs a certificate to renew with; enroll the relay: sudo -u flotestro-relay flotestro-relayctl enroll")
		return 1
	}
	if identity.Expired {
		// An expired certificate proves nothing over mTLS, so there is no
		// path but a new enrollment.
		fmt.Fprintf(errOut, "identity_expired: the certificate of relay/%s expired at %s\n",
			identity.RelayID, identity.NotAfter.UTC().Format(time.RFC3339))
		fmt.Fprintln(errOut, "a renewal needs a valid certificate; enroll the relay again")
		return 1
	}
	if err := sameOwner(r.StateDir, "renew"); err != nil {
		fmt.Fprintf(errOut, "%v\n", err)
		return 1
	}

	// The attempt is recorded before it is made: a refusal by the gateway counts
	// as much as a success, and a script must not be able to hammer the gateway
	// by retrying a failure.
	if err := throttle.Record(now); err != nil {
		fmt.Fprintf(errOut, "the renewal record was not written: %v\n", err)
		return 1
	}

	// The addresses of the centre are tried in order until one answers, and the
	// one that did is printed: a site whose relay renewed against the standby is
	// a fact the operator reads here.
	var renewed *identitystore.Identity
	answered, err := endpoints.New(r.Gateways, 0, 0).Try(ctx,
		func(ctx context.Context, gatewayURL string) error {
			identity, err := r.Renew(ctx, r.StateDir, gatewayURL, r.Names)
			if err != nil {
				return err
			}
			renewed = identity
			return nil
		})
	if err != nil {
		fmt.Fprintf(errOut, "the renewal failed: %v\n", err)
		return 1
	}
	fmt.Fprintf(out, "Renewed:      relay/%s\n", renewed.HostID)
	fmt.Fprintf(out, "Centre:       %s\n", answered)
	fmt.Fprintf(out, "Certificate:  valid until %s\n", renewed.NotAfter.UTC().Format(time.RFC3339))
	// The daemon has no local channel to be told about the new generation, and
	// the previous certificate stays valid until its term - so the sessions of
	// the site go on, and the switch happens at the next start.
	fmt.Fprintln(out, "The running relay keeps the previous certificate; to switch: systemctl restart flotestro-relay.service")
	return 0
}

// renewNow exchanges a new key pair for a certificate and writes it
// atomically, the way the daemon does.
func renewNow(ctx context.Context, stateDir, gatewayURL string, names []string) (*identitystore.Identity, error) {
	store := identitystore.New(stateDir)
	current, err := store.Current()
	if err != nil {
		return nil, err
	}
	key, err := store.NewKey()
	if err != nil {
		return nil, err
	}
	dns, addresses := splitNames(names)
	csrPEM, err := identitystore.Request(key, current.HostID, dns, addresses)
	if err != nil {
		return nil, err
	}

	// The renewal goes over mTLS with the current certificate: it is the
	// proof of the identity of the relay.
	client_ := agentv1connect.NewRelayServiceClient(&http.Client{
		Timeout: 60 * time.Second,
		Transport: &http2.Transport{
			TLSClientConfig: &tls.Config{
				Certificates: []tls.Certificate{current.Certificate},
				RootCAs:      current.CAPool,
				MinVersion:   tls.VersionTLS13,
			},
		},
	}, gatewayURL)
	response, err := client_.RenewCertificate(ctx,
		connect.NewRequest(&agentv1.RenewRelayCertificateRequest{
			CsrPem:          csrPEM,
			Build:           &agentv1.AgentBuild{AgentVersion: version},
			AdvertisedNames: names,
		}))
	if err != nil {
		return nil, fmt.Errorf("the renewal was rejected: %w", err)
	}

	// The trust bundle changes only at a rotation of the CA of the fleet.
	bundle := response.Msg.GetClientCaBundlePem()
	if len(bundle) == 0 {
		bundle = current.TrustPEM
	}
	if len(bundle) == 0 {
		return nil, errors.New("a renewal without a trust bundle")
	}
	saved, err := store.Commit(identitystore.Generation{
		Key:            key,
		CertificatePEM: response.Msg.GetCertificatePem(),
		TrustPEM:       bundle,
	})
	if err != nil {
		// A rejected generation does not touch what the relay works with: better to
		// stay on the old certificate than to be left with half a pair.
		return nil, fmt.Errorf("the new identity was rejected: %w", err)
	}
	return saved, nil
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
