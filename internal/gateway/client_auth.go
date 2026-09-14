package gateway

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"log/slog"
	"sync"
	"time"

	"github.com/ultherego/flotestro/internal/audit"
	"github.com/ultherego/flotestro/internal/hosts"
	"github.com/ultherego/flotestro/internal/pki"
)

// The refusal of a client certificate, before any session exists.
//
// Go's TLS server checks a client certificate against the trust set and
// ends the handshake when it is expired, and nothing of the application
// sees it: the host shows as offline in the panel, like a machine that is
// switched off. An agent that let its certificate lapse is nothing of the
// sort - it is a host the operator can bring back with a recovery order -
// so the gateway does the verification itself, inside the handshake, and
// writes down whom it turned away and why before the handshake fails.
//
// The certificate is refused at the TLS layer all the same: the verifier
// returns the error, the handshake ends and no session opens. What changes
// is that the refusal has a name on it. The identity in a certificate is
// trusted for that only when the chain leads to a CA of the fleet: an
// expired certificate of ours still names its host truthfully, a
// certificate of a stranger names whoever it likes.

// RefusalStore records a refusal against the host it concerns.
type RefusalStore interface {
	RecordConnectionRefusal(ctx context.Context, hostID, code, detail string) (bool, error)
}

// ClientVerifier verifies the client certificates of the gateway listener
// and attributes the refusals.
type ClientVerifier struct {
	// roots is read at every handshake: the trust set changes when the CA
	// is exchanged, and a copy from the start would refuse every host that
	// renewed under the new one.
	roots    func() *x509.CertPool
	refusals RefusalStore
	audit    *audit.Recorder
	log      *slog.Logger
	now      func() time.Time

	// recent remembers the last time a refusal of a host was written, so
	// an agent retrying every few seconds with the same dead certificate
	// costs one row and one trail entry a minute rather than one each.
	mu     sync.Mutex
	recent map[string]time.Time
}

// refusalQuiet is how long a repeated refusal of the same host for the
// same reason stays unrecorded.
const refusalQuiet = time.Minute

// NewClientVerifier builds the verifier over the trust set of the fleet.
func NewClientVerifier(roots func() *x509.CertPool, refusals RefusalStore,
	recorder *audit.Recorder, log *slog.Logger) *ClientVerifier {
	return &ClientVerifier{
		roots:    roots,
		refusals: refusals,
		audit:    recorder,
		log:      log,
		now:      time.Now,
		recent:   make(map[string]time.Time),
	}
}

// Apply installs the verifier in a server configuration. The built-in
// verification is switched off - RequireAnyClientCert - because with it on
// the handshake would end on an expired certificate before this code sees
// it; the verifier is the verification from then on, and a configuration
// that switches the check off without installing the hook is not built
// here.
func (v *ClientVerifier) Apply(config *tls.Config) {
	config.ClientAuth = tls.RequireAnyClientCert
	config.VerifyPeerCertificate = v.VerifyPeerCertificate
}

// VerifyPeerCertificate is the handshake hook. The chains argument is
// always empty, because the built-in verification is off; the chain is
// built here from the raw certificates the client sent.
func (v *ClientVerifier) VerifyPeerCertificate(rawCerts [][]byte, _ [][]*x509.Certificate) error {
	if len(rawCerts) == 0 {
		return errors.New("no client certificate")
	}
	leaf, err := x509.ParseCertificate(rawCerts[0])
	if err != nil {
		return fmt.Errorf("the client certificate does not parse: %w", err)
	}
	intermediates := x509.NewCertPool()
	for _, raw := range rawCerts[1:] {
		cert, err := x509.ParseCertificate(raw)
		if err != nil {
			return fmt.Errorf("a certificate of the client chain does not parse: %w", err)
		}
		intermediates.AddCert(cert)
	}
	verdict := ClassifyClientCertificate(leaf, intermediates, v.roots(), v.now())
	if verdict.Code == "" {
		return nil
	}
	v.record(leaf, verdict)
	return verdict.Err
}

// record puts the refusal on the trail and, when the certificate names a
// host of the fleet, on the host. The handshake has no context of its own,
// so the writes get a short one: a slow database must not hold the
// handshake, and the refusal stands whether or not it was written.
func (v *ClientVerifier) record(leaf *x509.Certificate, verdict CertificateVerdict) {
	v.log.Warn("a client certificate was refused at the handshake",
		"reason", verdict.Code, "kind", verdict.Kind, "identity", verdict.Identity,
		"serial", leaf.SerialNumber.String(), "detail", verdict.Detail)
	if !v.due(verdict.Kind + "/" + verdict.Identity + "/" + verdict.Code) {
		return
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if verdict.HostID != "" && v.refusals != nil {
		if _, err := v.refusals.RecordConnectionRefusal(ctx, verdict.HostID, verdict.Code, verdict.Detail); err != nil {
			v.log.Error("the refusal was not recorded on the host", "host_id", verdict.HostID, "err", err)
		}
	}
	if v.audit == nil {
		return
	}
	// A refused stranger has no identity to speak of, so the entry stands
	// under the subject of the certificate it presented; a refused host
	// of the fleet stands under its own identifier like every other
	// refusal of its session.
	actor, targetType, targetID := leaf.Subject.CommonName, "certificate", leaf.SerialNumber.String()
	if verdict.HostID != "" {
		actor, targetType, targetID = verdict.HostID, "host", verdict.HostID
	}
	v.audit.Record(ctx, audit.Event{
		ActorType: audit.ActorAgent, ActorID: actor,
		Action: "agent.session.open", TargetType: targetType, TargetID: targetID,
		Outcome: audit.OutcomeDenied,
		Detail: map[string]any{
			"reason": verdict.Code, "serial": leaf.SerialNumber.String(),
			"subject": leaf.Subject.CommonName, "issuer": leaf.Issuer.CommonName,
			"not_before": leaf.NotBefore, "not_after": leaf.NotAfter,
			"detail": verdict.Detail, "layer": "handshake",
		},
	})
}

// due says whether the refusal under the key is to be written now, and
// remembers that it was. The keys are identities from certificates the
// fleet signed - every stranger shares the one empty key - so the map
// cannot be flooded from outside; it is pruned all the same, because a
// large fleet in trouble must not keep every host in memory for good.
func (v *ClientVerifier) due(key string) bool {
	now := v.now()
	v.mu.Lock()
	defer v.mu.Unlock()
	if last, seen := v.recent[key]; seen && now.Sub(last) < refusalQuiet {
		return false
	}
	if len(v.recent) > 4096 {
		for k, at := range v.recent {
			if now.Sub(at) >= refusalQuiet {
				delete(v.recent, k)
			}
		}
	}
	v.recent[key] = now
	return true
}

// CertificateVerdict says why a client certificate was refused. An empty
// Code is a certificate the fleet accepts.
type CertificateVerdict struct {
	Code string
	// Kind and Identity are what the certificate names - host or relay,
	// and its identifier - and are filled in only when the chain leads to
	// a CA of the fleet. HostID is the identity of a host certificate,
	// which is where a refusal can be attributed to a row of the fleet.
	Kind     string
	Identity string
	HostID   string
	// Detail is the one-line account for the operator: the validity of
	// the certificate, or what the verification said.
	Detail string
	// Err is what the handshake ends with.
	Err error
}

// ClassifyClientCertificate verifies the leaf against the trust set at the
// given moment and names the refusal.
//
// Go's verification reports an expired leaf and an expired issuer alike,
// and does not say whether the chain would have held at all. The
// classification asks that second question itself - a verification at a
// moment inside the leaf's own validity - because the answer decides
// whether the identity in the certificate may be believed: a certificate
// the fleet signed that has merely run out still names its host, and an
// unknown one names nobody.
func ClassifyClientCertificate(leaf *x509.Certificate, intermediates, roots *x509.CertPool,
	now time.Time) CertificateVerdict {
	options := x509.VerifyOptions{
		Roots: roots, Intermediates: intermediates, CurrentTime: now,
		KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
	}
	_, err := leaf.Verify(options)
	if err == nil {
		return CertificateVerdict{}
	}

	var invalid x509.CertificateInvalidError
	if errors.As(err, &invalid) && invalid.Reason == x509.Expired {
		// Verified at the middle of its own validity: a chain that holds
		// then was signed by the fleet, and only the time is wrong.
		atIssue := options
		atIssue.CurrentTime = leaf.NotBefore.Add(leaf.NotAfter.Sub(leaf.NotBefore) / 2)
		if _, chainErr := leaf.Verify(atIssue); chainErr == nil {
			verdict := CertificateVerdict{
				Detail: fmt.Sprintf("serial %s valid from %s to %s", leaf.SerialNumber,
					leaf.NotBefore.UTC().Format(time.RFC3339), leaf.NotAfter.UTC().Format(time.RFC3339)),
			}
			verdict.Kind, verdict.Identity, _ = pki.IdentityFromCert(leaf)
			if verdict.Kind == "host" {
				verdict.HostID = verdict.Identity
			}
			switch {
			case now.Before(leaf.NotBefore):
				verdict.Code = hosts.RefusalCertificateNotYetValid
				verdict.Err = fmt.Errorf("%s: the certificate is not valid before %s",
					verdict.Code, leaf.NotBefore.UTC().Format(time.RFC3339))
			case now.After(leaf.NotAfter):
				verdict.Code = hosts.RefusalCertificateExpired
				verdict.Err = fmt.Errorf("%s: the certificate expired at %s",
					verdict.Code, leaf.NotAfter.UTC().Format(time.RFC3339))
			default:
				// The leaf is in its window and the chain is not: an
				// issuer that ran out. The name is signed by a CA that no
				// longer counts, so it is not believed either.
				return CertificateVerdict{
					Code:   hosts.RefusalUnknownCertificate,
					Detail: "the issuing CA is outside its validity: " + err.Error(),
					Err:    fmt.Errorf("%s: %w", hosts.RefusalUnknownCertificate, err),
				}
			}
			return verdict
		}
	}
	return CertificateVerdict{
		Code:   hosts.RefusalUnknownCertificate,
		Detail: err.Error(),
		Err:    fmt.Errorf("%s: %w", hosts.RefusalUnknownCertificate, err),
	}
}
