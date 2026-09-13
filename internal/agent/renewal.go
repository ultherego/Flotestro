package agent

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"path/filepath"
	"time"

	"connectrpc.com/connect"
	"golang.org/x/net/http2"

	agentv1 "github.com/ultherego/flotestro/internal/genproto/flotestro/agent/v1"
	"github.com/ultherego/flotestro/internal/genproto/flotestro/agent/v1/agentv1connect"
	"github.com/ultherego/flotestro/internal/identitystore"
)

// renewalThreshold says when to start renewing: when less than a third of the
// validity period is left. With a 30-day certificate that gives about ten days
// for retries, which is the margin for a failure of the centre required by the
// document - and not the last hour before the expiry.
const renewalThreshold = 1.0 / 3.0

// maxRenewalCheckInterval bounds the interval between checks from above. A
// renewal is not urgent to the minute; checking more often would load the fleet
// for no reason.
const maxRenewalCheckInterval = 6 * time.Hour

// minRenewalCheckInterval guards against polling in a loop should the
// certificate have a very short lifetime.
const minRenewalCheckInterval = time.Minute

// checkInterval scales the checking to the certificate's lifetime. A fixed
// six-hour interval would be useless with an hourly certificate and
// needlessly frequent with a yearly one.
func checkInterval(notAfter, notBefore time.Time) time.Duration {
	total := notAfter.Sub(notBefore)
	if total <= 0 {
		return minRenewalCheckInterval
	}
	interval := total / 20
	if interval > maxRenewalCheckInterval {
		return maxRenewalCheckInterval
	}
	if interval < minRenewalCheckInterval {
		return minRenewalCheckInterval
	}
	return interval
}

// renewalRetryInterval applies after a failed attempt. The centre may be
// unavailable for the moment, and there are still many days until the expiry.
const renewalRetryInterval = 30 * time.Minute

// RenewalOptions describes the renewal of the certificate of the agent.
type RenewalOptions struct {
	StateDir   string
	GatewayURL string
	Log        *slog.Logger
	// OnRenewed is called after a new certificate has been written. The agent
	// then breaks the session so that the next one goes with the new identity.
	OnRenewed func()
}

// KeepCertificateFresh renews the certificate of the agent before it expires.
//
// Without it the whole fleet stops connecting on the day the certificates
// expire, because the agent has no way back other than a new enrollment with a
// token that is no longer on the host.
func KeepCertificateFresh(ctx context.Context, identity *Identity, options RenewalOptions) {
	log := options.Log
	if log == nil {
		log = slog.Default()
	}
	timer := time.NewTimer(checkInterval(identity.NotAfter, leafNotBefore(identity)))
	defer timer.Stop()

	for {
		if needsRenewal(identity.NotAfter, leafNotBefore(identity)) {
			if err := renewCertificate(ctx, identity, options); err != nil {
				log.Warn("the certificate of the agent was not renewed",
					"err", err, "expires", identity.NotAfter.Format(time.RFC3339))
				select {
				case <-ctx.Done():
					return
				case <-time.After(renewalRetryInterval):
					continue
				}
			}
			log.Info("the certificate of the agent was renewed", "expires", identity.NotAfter.Format(time.RFC3339))
			if options.OnRenewed != nil {
				options.OnRenewed()
			}
		}

		// The interval follows from the current certificate, so after a renewal it
		// adjusts to the new deadline.
		timer.Reset(checkInterval(identity.NotAfter, leafNotBefore(identity)))
		select {
		case <-ctx.Done():
			return
		case <-timer.C:
		}
	}
}

// needsRenewal decides on the basis of the remaining share of the validity
// period and not on a fixed number of days: a shorter certificate is to be
// renewed more often.
func needsRenewal(notAfter, notBefore time.Time) bool {
	if notAfter.IsZero() {
		// An unknown deadline must not mean "there is still plenty of time". An
		// attempt to renew is cheap, and the lack of knowledge about the validity
		// is a reason in itself.
		return true
	}
	total := notAfter.Sub(notBefore)
	if total <= 0 {
		return true
	}
	return time.Until(notAfter) < time.Duration(float64(total)*renewalThreshold)
}

func leafNotBefore(identity *Identity) time.Time {
	if len(identity.Certificate.Certificate) == 0 {
		return time.Time{}
	}
	leaf, err := x509.ParseCertificate(identity.Certificate.Certificate[0])
	if err != nil {
		return time.Time{}
	}
	return leaf.NotBefore
}

// renewCertificate exchanges a new key pair for a certificate and stores it
// atomically. The old material stays on the disk until the new one is complete:
// an interruption halfway must not leave the host without an identity.
func renewCertificate(ctx context.Context, identity *Identity, options RenewalOptions) error {
	store := identitystore.New(options.StateDir)
	// The key is created by the store: with a hardware profile a new generation
	// is created inside the chip and never leaves it, and the renewal does not
	// notice that.
	key, err := store.NewKey()
	if err != nil {
		return err
	}
	// The subject in the CSR is only a hint; the identity is granted by the
	// control plane on the basis of the certificate the agent authenticates
	// with.
	csrPEM, err := identitystore.Request(key, identity.HostID, nil, nil)
	if err != nil {
		return err
	}

	// The renewal goes over mTLS with the current certificate: that is the proof
	// of identity. The enrollment token takes no part in it.
	client := agentv1connect.NewAgentServiceClient(&http.Client{
		Timeout: 60 * time.Second,
		Transport: &http2.Transport{
			TLSClientConfig: &tls.Config{
				Certificates: []tls.Certificate{identity.Certificate},
				RootCAs:      identity.CAPool,
				MinVersion:   tls.VersionTLS13,
			},
		},
	}, options.GatewayURL)

	response, err := client.RenewCertificate(ctx, connect.NewRequest(&agentv1.RenewCertificateRequest{
		CsrPem: csrPEM,
		Build:  &agentv1.AgentBuild{AgentVersion: Version},
	}))
	if err != nil {
		return fmt.Errorf("the renewal was refused: %w", err)
	}

	// The trust bundle changes only when the CA rotates. When the panel did not
	// send one, the generation gets the one in force: a generation has to be a
	// complete set and not a key and a certificate without a statement of
	// trust.
	bundle := response.Msg.GetCaBundlePem()
	if len(bundle) == 0 {
		bundle = identity.TrustPEM
	}
	if len(bundle) == 0 {
		return fmt.Errorf("a renewal without a trust bundle")
	}

	renewed, err := store.Commit(identitystore.Generation{
		Key:            key,
		CertificatePEM: response.Msg.GetCertificatePem(),
		TrustPEM:       bundle,
	})
	if err != nil {
		// A refused generation does not touch what the host works with: better to
		// stay on the old certificate and try again in half an hour than to be
		// left with half a pair.
		return fmt.Errorf("the new identity was refused: %w", err)
	}
	*identity = *fromIdentity(renewed)
	return nil
}

// writeAtomic writes a file through a temporary file and a rename. An
// interruption halfway through the write would leave the agent with a damaged
// key, that is without a way back into the fleet.
func writeAtomic(path string, data []byte, mode os.FileMode) error {
	temporary := path + ".new"
	if err := os.WriteFile(temporary, data, mode); err != nil {
		return err
	}
	if err := os.Rename(temporary, path); err != nil {
		_ = os.Remove(temporary)
		return err
	}
	// The directory has to reach the disk together with the file, otherwise
	// after a power failure the rename can disappear and the temporary file
	// stay.
	if dir, err := os.Open(filepath.Dir(path)); err == nil {
		_ = dir.Sync()
		_ = dir.Close()
	}
	return nil
}
