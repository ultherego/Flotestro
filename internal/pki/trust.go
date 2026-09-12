package pki

import (
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"
)

// Trust is the fleet's set of CAs: one that signs and any number of
// withdrawn ones that are still recognised.
//
// Rotating a CA must not break the fleet. A new CA has to be recognised by
// the panel before it starts signing, and the old one has to stay recognised
// for the whole validity of the agent certificates issued with it. The set
// therefore applies in both directions: the panel trusts every entry, and the
// agent gets them all in the bundle at enrollment and at every renewal.
type Trust struct {
	mu sync.RWMutex
	// active signs new certificates.
	active *CA
	// pending is already recognised and distributed in the bundle, but signs
	// nothing yet. This state is the essence of a safe rotation: if the new
	// CA signed at once, after a restart the panel would present a server
	// certificate no agent recognises except those that managed to renew.
	pending *CA
	// pendingAt is the moment of preparation; it is what decides which hosts
	// have managed to get the new bundle.
	pendingAt time.Time
	// retired ones are still recognised but sign nothing any more.
	retired []*CA
	dir     string
}

// retiredDir holds the CAs withdrawn from signing.
const retiredDir = "ca-retired"

// pendingCertFile and pendingKeyFile hold the CA prepared to take over.
const (
	pendingCertFile = "ca-pending.pem"
	pendingKeyFile  = "ca-pending.key"
	// pendingAtFile records the moment the CA was prepared. The start of the
	// certificate's validity is not enough: it is deliberately backdated by
	// an hour to allow for clock skew, so a host renewed just before the
	// preparation would look like one that already knows the new CA.
	pendingAtFile = "ca-pending.at"
)

// EnsureTrust reads the set of CAs from the state directory, creating the
// first CA on the first start.
func EnsureTrust(dir string) (*Trust, error) {
	active, err := EnsureCA(dir)
	if err != nil {
		return nil, err
	}
	trust := &Trust{active: active, dir: dir}

	certPEM, certErr := os.ReadFile(filepath.Join(dir, pendingCertFile))
	keyPEM, keyErr := os.ReadFile(filepath.Join(dir, pendingKeyFile))
	if certErr == nil && keyErr == nil {
		pending, err := parseCA(certPEM, keyPEM)
		if err != nil {
			return nil, fmt.Errorf("%s: %w", pendingCertFile, err)
		}
		trust.pending = pending
		// A missing or damaged marker must not stop the panel. We then take
		// the current moment, that is, the assumption that no host knows the
		// new CA yet: the handover of signing will be held back until the
		// certificates are renewed. An error in this direction costs waiting,
		// an error in the other one cuts off the fleet.
		trust.pendingAt = time.Now().UTC()
		if stamp, err := os.ReadFile(filepath.Join(dir, pendingAtFile)); err == nil {
			if parsed, err := time.Parse(time.RFC3339, strings.TrimSpace(string(stamp))); err == nil {
				trust.pendingAt = parsed
			}
		}
		if err := writeFileAtomic(filepath.Join(dir, pendingAtFile),
			[]byte(trust.pendingAt.Format(time.RFC3339)), 0o644); err != nil {
			return nil, err
		}
	} else if certErr != nil && !os.IsNotExist(certErr) {
		return nil, certErr
	}

	entries, err := os.ReadDir(filepath.Join(dir, retiredDir))
	if err != nil && !os.IsNotExist(err) {
		return nil, fmt.Errorf("directory of withdrawn CAs: %w", err)
	}
	for _, entry := range entries {
		if entry.IsDir() || filepath.Ext(entry.Name()) != ".pem" {
			continue
		}
		path := filepath.Join(dir, retiredDir, entry.Name())
		certPEM, err := os.ReadFile(path)
		if err != nil {
			return nil, err
		}
		// A withdrawn CA keeps no key with it: it has nothing left to sign,
		// and keeping a key without need only increases the risk.
		cert, err := parseCertificateOnly(certPEM)
		if err != nil {
			return nil, fmt.Errorf("%s: %w", entry.Name(), err)
		}
		trust.retired = append(trust.retired, &CA{Certificate: cert, PEM: certPEM})
	}
	return trust, nil
}

// Active returns the CA signing new certificates.
func (t *Trust) Active() *CA {
	t.mu.RLock()
	defer t.mu.RUnlock()
	return t.active
}

// Pool builds the trust pool for verifying agent certificates.
func (t *Trust) Pool() *x509.CertPool {
	t.mu.RLock()
	defer t.mu.RUnlock()
	pool := x509.NewCertPool()
	pool.AddCert(t.active.Certificate)
	if t.pending != nil {
		pool.AddCert(t.pending.Certificate)
	}
	for _, ca := range t.retired {
		pool.AddCert(ca.Certificate)
	}
	return pool
}

// Bundle returns every recognised CA in PEM format. The agent stores it
// locally, so it has to contain the CA that is only about to start signing as
// well.
func (t *Trust) Bundle() []byte {
	t.mu.RLock()
	defer t.mu.RUnlock()
	bundle := make([]byte, 0, len(t.active.PEM))
	bundle = append(bundle, t.active.PEM...)
	if t.pending != nil {
		bundle = append(bundle, t.pending.PEM...)
	}
	for _, ca := range t.retired {
		bundle = append(bundle, ca.PEM...)
	}
	return bundle
}

// Authority describes one CA for the overview and the metrics.
type Authority struct {
	Subject     string    `json:"subject"`
	Serial      string    `json:"serial"`
	Fingerprint string    `json:"fingerprint"`
	NotBefore   time.Time `json:"not_before"`
	NotAfter    time.Time `json:"not_after"`
	// State: active signs, pending waits to take over, retired is still
	// recognised. An "active" flag alone would not tell the last two
	// apart.
	State string `json:"state"`
	// PreparedAt is the moment the CA was prepared. It is what decides which
	// hosts have already got the new bundle.
	PreparedAt time.Time `json:"prepared_at,omitempty"`
}

// Authorities lists the trust set, starting with the signing CA.
func (t *Trust) Authorities() []Authority {
	t.mu.RLock()
	defer t.mu.RUnlock()

	list := []Authority{describe(t.active, "active")}
	if t.pending != nil {
		prepared := describe(t.pending, "pending")
		prepared.PreparedAt = t.pendingAt
		list = append(list, prepared)
	}
	for _, ca := range t.retired {
		list = append(list, describe(ca, "retired"))
	}
	sort.SliceStable(list[1:], func(i, j int) bool {
		return list[1+i].NotAfter.Before(list[1+j].NotAfter)
	})
	return list
}

func describe(ca *CA, state string) Authority {
	authority := Authority{
		Subject:     ca.Certificate.Subject.CommonName,
		Serial:      ca.Certificate.SerialNumber.String(),
		Fingerprint: fingerprintHex(ca.Certificate.Raw),
		NotBefore:   ca.Certificate.NotBefore,
		NotAfter:    ca.Certificate.NotAfter,
		State:       state,
	}
	return authority
}

// Prepare creates a new CA and admits it into the trust set, but does not let
// it sign yet.
//
// This is the first of the two phases of a rotation. From this moment the
// panel recognises the new CA, and every agent gets it in the bundle at its
// next certificate renewal. Only once the whole fleet has the new CA locally
// may it start signing.
//
// A single-phase rotation would look like it worked until the panel's first
// restart: a server certificate issued by the new CA would not be recognised
// by any agent that had not managed to renew, and the whole fleet would lose
// its connection.
func (t *Trust) Prepare() (Authority, error) {
	t.mu.Lock()
	defer t.mu.Unlock()

	if t.pending != nil {
		return Authority{}, fmt.Errorf("a CA prepared to take over already exists")
	}
	created, certPEM, keyPEM, err := newCA()
	if err != nil {
		return Authority{}, err
	}
	created.AgentTTL = t.active.AgentTTL

	if err := writeFileAtomic(filepath.Join(t.dir, pendingCertFile), certPEM, 0o644); err != nil {
		return Authority{}, err
	}
	// The CA key is the most sensitive material in the system.
	if err := writeFileAtomic(filepath.Join(t.dir, pendingKeyFile), keyPEM, 0o600); err != nil {
		return Authority{}, err
	}
	now := time.Now().UTC()
	if err := writeFileAtomic(filepath.Join(t.dir, pendingAtFile),
		[]byte(now.Format(time.RFC3339)), 0o644); err != nil {
		return Authority{}, err
	}
	t.pending = created
	t.pendingAt = now

	prepared := describe(created, "pending")
	prepared.PreparedAt = now
	return prepared, nil
}

// Activate hands signing over to the prepared CA and moves the previous one
// to the recognised ones.
//
// The caller checks beforehand that every host already has the new CA
// locally; here we only guard the consistency of the set itself.
func (t *Trust) Activate() (Authority, error) {
	t.mu.Lock()
	defer t.mu.Unlock()

	if t.pending == nil {
		return Authority{}, fmt.Errorf("there is no CA prepared to take over")
	}

	// We record the previous CA as withdrawn before the new one becomes the
	// signing one: an interruption at this point leaves the fleet with a CA
	// the panel still recognises.
	if err := os.MkdirAll(filepath.Join(t.dir, retiredDir), 0o700); err != nil {
		return Authority{}, err
	}
	previous := filepath.Join(t.dir, retiredDir,
		t.active.Certificate.SerialNumber.String()+".pem")
	if err := os.WriteFile(previous, t.active.PEM, 0o644); err != nil {
		return Authority{}, err
	}

	pendingKey, err := os.ReadFile(filepath.Join(t.dir, pendingKeyFile))
	if err != nil {
		return Authority{}, err
	}
	if err := writeFileAtomic(filepath.Join(t.dir, "ca.pem"), t.pending.PEM, 0o644); err != nil {
		return Authority{}, err
	}
	if err := writeFileAtomic(filepath.Join(t.dir, "ca.key"), pendingKey, 0o600); err != nil {
		return Authority{}, err
	}
	_ = os.Remove(filepath.Join(t.dir, pendingCertFile))
	_ = os.Remove(filepath.Join(t.dir, pendingKeyFile))
	_ = os.Remove(filepath.Join(t.dir, pendingAtFile))

	t.retired = append(t.retired, &CA{Certificate: t.active.Certificate, PEM: t.active.PEM})
	t.active = t.pending
	t.pending = nil
	return describe(t.active, "active"), nil
}

// Pending returns the CA prepared to take over together with the moment it was prepared.
func (t *Trust) Pending() (*CA, time.Time) {
	t.mu.RLock()
	defer t.mu.RUnlock()
	return t.pending, t.pendingAt
}

// Retire removes a withdrawn CA from the trust set.
//
// The operation is irreversible for the hosts that still hold a certificate
// issued by that CA: they stop being let in. That is why the panel refuses as
// long as such hosts exist - the decision to cut them off is taken separately,
// by revoking a certificate or quarantining a host.
func (t *Trust) Retire(fingerprint string, hostsUsing int) error {
	t.mu.Lock()
	defer t.mu.Unlock()

	if hostsUsing > 0 {
		return fmt.Errorf("%d hosts still use this CA", hostsUsing)
	}
	if fingerprintHex(t.active.Certificate.Raw) == fingerprint {
		return fmt.Errorf("the CA that signs new certificates cannot be removed")
	}
	if t.pending != nil && fingerprintHex(t.pending.Certificate.Raw) == fingerprint {
		// Abandoning a prepared CA is allowed: nothing has been signed with
		// it yet, and the agents that got it will simply stop knowing it at
		// their next renewal.
		_ = os.Remove(filepath.Join(t.dir, pendingCertFile))
		_ = os.Remove(filepath.Join(t.dir, pendingKeyFile))
		_ = os.Remove(filepath.Join(t.dir, pendingAtFile))
		t.pending = nil
		t.pendingAt = time.Time{}
		return nil
	}

	for index, ca := range t.retired {
		if fingerprintHex(ca.Certificate.Raw) != fingerprint {
			continue
		}
		path := filepath.Join(t.dir, retiredDir, ca.Certificate.SerialNumber.String()+".pem")
		if err := os.Remove(path); err != nil && !os.IsNotExist(err) {
			return err
		}
		t.retired = append(t.retired[:index], t.retired[index+1:]...)
		return nil
	}
	return fmt.Errorf("no CA with the fingerprint %s was found", fingerprint)
}

// NotAfter returns the deadline of the signing CA; the metrics watch exactly that one.
func (t *Trust) NotAfter() time.Time {
	t.mu.RLock()
	defer t.mu.RUnlock()
	return t.active.NotAfter()
}

// parseCertificateOnly reads a certificate without a private key.
func parseCertificateOnly(certPEM []byte) (*x509.Certificate, error) {
	block, _ := pem.Decode(certPEM)
	if block == nil {
		return nil, fmt.Errorf("no PEM block")
	}
	return x509.ParseCertificate(block.Bytes)
}

func fingerprintHex(der []byte) string {
	sum := sha256.Sum256(der)
	return hex.EncodeToString(sum[:])
}

// writeFileAtomic replaces a file through a temporary file and a rename.
// An interruption halfway through writing the CA key would leave the panel
// without the identity of the whole fleet.
func writeFileAtomic(path string, data []byte, mode os.FileMode) error {
	temporary := path + ".new"
	if err := os.WriteFile(temporary, data, mode); err != nil {
		return err
	}
	if err := os.Rename(temporary, path); err != nil {
		_ = os.Remove(temporary)
		return err
	}
	if dir, err := os.Open(filepath.Dir(path)); err == nil {
		_ = dir.Sync()
		_ = dir.Close()
	}
	return nil
}
