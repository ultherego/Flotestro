package agent

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"path/filepath"
	"time"

	"connectrpc.com/connect"

	"github.com/ultherego/flotestro/internal/endpoints"
	agentv1 "github.com/ultherego/flotestro/internal/genproto/flotestro/agent/v1"
	"github.com/ultherego/flotestro/internal/genproto/flotestro/agent/v1/agentv1connect"
	"github.com/ultherego/flotestro/internal/identitystore"
	"github.com/ultherego/flotestro/internal/relayproof"
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
	StateDir string
	// Gateways are the addresses of the panel in order of priority - the
	// same list the session uses. A renewal that knew only one address
	// would tie the certificate of the host to one instance of the panel
	// being up, which is the one thing a fleet with several of them must
	// not depend on. GatewayURL is the single address of a caller that has
	// one; it is used when the list is empty.
	Gateways   []string
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

	// The addresses are tried in order of priority until one answers, with
	// the same classes and the same jittered pause the session uses: a
	// gateway that is not there is passed over, a revoked identity stops
	// the attempts everywhere. One CSR for all of them - the key of the
	// new generation is created once, and a gateway that refused it has
	// not seen the key of another.
	var response *connect.Response[agentv1.RenewCertificateResponse]
	answered, err := endpoints.New(options.gateways(), 0, 0).Try(ctx,
		func(ctx context.Context, gatewayURL string) error {
			// The renewal goes over mTLS with the current certificate: that is
			// the proof of identity. The enrollment token takes no part in it.
			// The material is read once, so the handshake and the proof use the
			// same key.
			material := identity.Certificate
			peer := newPeerIdentity()
			client := agentv1connect.NewAgentServiceClient(&http.Client{
				Timeout:   60 * time.Second,
				Transport: newObservedHTTP2Client(material, identity.CAPool, peer).Transport,
			}, gatewayURL)

			request := &agentv1.RenewCertificateRequest{
				CsrPem: csrPEM,
				Build:  &agentv1.AgentBuild{AgentVersion: Version},
			}
			// Through a relay the handshake proves the relay, so the request has
			// to carry the host's own proof: a challenge the panel issued for
			// this host and this relay, signed with the key the host holds now
			// together with the CSR, and the envelope over the request. The
			// challenge is asked for first - the call is also what makes the
			// handshake happen and tells the agent whom it reached. A panel from
			// before the challenge answers Unimplemented, and the renewal goes on
			// as before: such a panel accepts a direct renewal on the handshake
			// alone. The proof is bound to the address it was asked at, so it is
			// made again for every gateway tried.
			if err := proveRenewal(ctx, client, peer, material, identity.HostID, request, csrPEM, options.Log); err != nil {
				return err
			}
			answer, err := client.RenewCertificate(ctx, connect.NewRequest(request))
			if err != nil {
				return fmt.Errorf("the renewal was refused: %w", err)
			}
			response = answer
			return nil
		})
	if err != nil {
		return err
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
	if options.Log != nil && answered != "" {
		options.Log.Info("the gateway that answered the renewal", "gateway", answered)
	}
	// The renewal carries the panel's current capability keys: a rotated
	// key reaches the helper here, and again with the next session.
	deliverHelperTrust(ctx, response.Msg.GetHelperTrust(), options.Log)
	return nil
}

// gateways is the list of addresses a renewal may use: the configured
// list, or the single address of a caller that has one.
func (o RenewalOptions) gateways() []string {
	if len(o.Gateways) > 0 {
		return o.Gateways
	}
	if o.GatewayURL != "" {
		return []string{o.GatewayURL}
	}
	return nil
}

// proveRenewal asks the panel for a challenge and binds the request to the
// current host key when the path goes through a relay. On a direct
// connection the challenge is asked for all the same - the agent does not
// know whom it reached until the handshake - and the proof is attached;
// the gateway ignores it there, because the handshake is the proof.
func proveRenewal(ctx context.Context, client agentv1connect.AgentServiceClient, peer *peerIdentity,
	material tls.Certificate, hostID string, request *agentv1.RenewCertificateRequest, csrPEM []byte,
	log *slog.Logger) error {
	if log == nil {
		log = slog.Default()
	}
	challenge, err := client.RequestIdentityChallenge(ctx, connect.NewRequest(&agentv1.IdentityChallengeRequest{}))
	if err != nil {
		if connect.CodeOf(err) == connect.CodeUnimplemented {
			// A panel from before the challenge. A relay in the path would
			// have forwarded the refusal of the panel just the same, and a
			// relayed renewal never worked against such a panel.
			log.Info("the panel issues no renewal challenge; renewing on the handshake alone")
			return nil
		}
		return fmt.Errorf("the renewal challenge was refused: %w", err)
	}
	relayID := peer.relayID(ctx, handshakeWait)
	if named := challenge.Msg.GetRelayId(); named != relayID {
		// The panel bound the challenge to another relay than the one this
		// connection reached - or to none. The proof would not verify;
		// better to say so here than to spend the challenge on a refusal.
		return fmt.Errorf("the challenge names relay %q, the connection reached %q", named, relayID)
	}
	signer := newEnvelopeSigner(material, hostID, relayID, log)
	if signer == nil {
		return errors.New("the identity carries no key to sign the renewal proof with")
	}
	block, _ := pem.Decode(csrPEM)
	if block == nil {
		return errors.New("the certificate request is not PEM")
	}
	proof, err := relayproof.SignRenewalProof(signer.Key(), block.Bytes, challenge.Msg.GetChallenge(), relayID)
	if err != nil {
		return err
	}
	request.ServerChallenge = challenge.Msg.GetChallenge()
	request.Proof = proof
	// The envelope signs the request as it stands without the envelope
	// itself; the gateway clears the field before it digests.
	envelope, err := signer.SignRequest(relayproof.KindRenewCertificate, request)
	if err != nil {
		return err
	}
	request.Identity = envelope
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

// RenewNow renews the stored certificate at once, however much of its
// validity is left.
//
// The operator's tool uses it: the daemon renews on its own schedule, and a
// forced renewal is the way out when the panel rotated its CA or the operator
// wants a fresh key pair today. It takes the same path as the scheduled
// renewal - the current certificate proves the identity over mTLS, the new
// generation is committed atomically, and the previous one stays on disk
// until the store cleans it up.
//
// The running daemon keeps the identity it loaded at start: nothing on the
// host tells it about the new generation, and the previous certificate stays
// valid until its term, so the session goes on. The new certificate is used
// from the next start of the service.
func RenewNow(ctx context.Context, stateDir, gatewayURL string) (*Identity, error) {
	store := identitystore.New(stateDir)
	current, err := store.Current()
	if err != nil {
		// A host from before the generation store has its files loose in
		// the state directory; the daemon moves them at start, and the tool
		// has to do the same to have something to renew with.
		p := paths(stateDir)
		if moved, migrateErr := store.Migrate(p.Key, p.Cert, p.CA); !moved || migrateErr != nil {
			return nil, err
		}
		if current, err = store.Current(); err != nil {
			return nil, err
		}
	}
	identity := fromIdentity(current)
	if err := renewCertificate(ctx, identity, RenewalOptions{StateDir: stateDir, GatewayURL: gatewayURL}); err != nil {
		return nil, err
	}
	return identity, nil
}
