package pki

import (
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"
)

// Trust is the fleet's set of CAs: one that signs and any number of withdrawn
// ones that are still recognised.
type Trust struct {
	mu sync.RWMutex
	// active signs new certificates.
	active *CA
	// pending is already recognised and distributed in the bundle, but signs
	// nothing yet.
	pending *CA
	// pendingAt is the moment of preparation; it is what decides which hosts
	// have managed to get the new bundle.
	pendingAt time.Time
	// retired ones are still recognised but sign nothing any more.
	retired []*CA
	dir     string
	// onActivate runs after a handover of signing; see SetActivationHook.
	onActivate func(active *CA)
}

// retiredDir holds the CAs withdrawn from signing.
const retiredDir = "ca-retired"

// pendingCertFile and pendingKeyFile hold the CA prepared to take over.
const (
	pendingCertFile = "ca-pending.pem"
	pendingKeyFile  = "ca-pending.key"
	// pendingAtFile records the moment the CA was prepared.
	pendingAtFile = "ca-pending.at"
)

// EnsureTrust reads the set of CAs from the state directory when it
// holds material and creates the first CA only when it holds nothing.
func EnsureTrust(dir string) (*Trust, error) {
	if HasAnyMaterial(dir) {
		return OpenTrust(dir)
	}
	return InitTrust(dir)
}

// InitTrust creates the first CA of an installation. It refuses a
// directory that already holds material, the same way Init does.
func InitTrust(dir string) (*Trust, error) {
	if _, err := Init(dir); err != nil {
		return nil, err
	}
	return OpenTrust(dir)
}

// OpenTrust reads the set of CAs and creates nothing.
func OpenTrust(dir string) (*Trust, error) {
	active, err := Open(dir)
	if errors.Is(err, ErrStateMismatch) {
		recovered, finished, finishErr := finishInterruptedActivation(dir)
		if finishErr != nil {
			return nil, finishErr
		}
		if !finished {
			return nil, err
		}
		active = recovered
	} else if err != nil {
		return nil, err
	}
	trust := &Trust{active: active, dir: dir}

	certPEM, certErr := os.ReadFile(filepath.Join(dir, pendingCertFile))
	keyPEM, keyErr := os.ReadFile(filepath.Join(dir, pendingKeyFile))
	switch {
	case certErr == nil && keyErr == nil:
		pending, err := parseCA(certPEM, keyPEM)
		if err != nil {
			return nil, fmt.Errorf("%w: %s: %v", ErrStateMismatch, pendingCertFile, err)
		}
		if err := pending.VerifyPair(); err != nil {
			return nil, fmt.Errorf("%s: %w", pendingCertFile, err)
		}
		if pending.Certificate.Equal(active.Certificate) {
			// The activation wrote both files and was interrupted before
			// it removed the pending ones: nothing is pending any more.
			removePending(dir)
			break
		}
		trust.pending = pending
		// A missing or damaged marker must not stop the panel.
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
	case os.IsNotExist(certErr) && os.IsNotExist(keyErr):
	case certErr != nil && !os.IsNotExist(certErr):
		return nil, certErr
	case keyErr != nil && !os.IsNotExist(keyErr):
		return nil, keyErr
	default:
		// One pending file without the other is a preparation that was interrupted
		// or a key removed by hand; either way the pair is not one the panel may
		// ever sign with.
		return nil, fmt.Errorf("%w: %s and %s do not come as a pair",
			ErrStateMismatch, pendingCertFile, pendingKeyFile)
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
			return nil, fmt.Errorf("%w: %s: %v", ErrStateMismatch, entry.Name(), err)
		}
		trust.retired = append(trust.retired, &CA{Certificate: cert, PEM: certPEM})
	}
	return trust, nil
}

// finishInterruptedActivation completes an activation that wrote the new key
// and not yet the new certificate.
func finishInterruptedActivation(dir string) (*CA, bool, error) {
	keyPEM, err := os.ReadFile(filepath.Join(dir, caKeyFile))
	if err != nil {
		return nil, false, nil
	}
	pendingPEM, err := os.ReadFile(filepath.Join(dir, pendingCertFile))
	if err != nil {
		return nil, false, nil
	}
	candidate, err := parseCA(pendingPEM, keyPEM)
	if err != nil || candidate.VerifyPair() != nil {
		return nil, false, nil
	}
	if err := writeFileAtomic(filepath.Join(dir, caCertFile), pendingPEM, 0o644); err != nil {
		return nil, false, err
	}
	removePending(dir)
	active, err := Open(dir)
	if err != nil {
		return nil, false, err
	}
	return active, true, nil
}

// removePending deletes the files of the CA prepared to take over.
func removePending(dir string) {
	_ = os.Remove(filepath.Join(dir, pendingCertFile))
	_ = os.Remove(filepath.Join(dir, pendingKeyFile))
	_ = os.Remove(filepath.Join(dir, pendingAtFile))
}

// SetActivationHook registers what runs once a prepared CA has taken over
// signing on disk.
func (t *Trust) SetActivationHook(hook func(active *CA)) {
	t.mu.Lock()
	defer t.mu.Unlock()
	t.onActivate = hook
}

// Retired returns the withdrawn CAs that are still recognised.
func (t *Trust) Retired() []*CA {
	t.mu.RLock()
	defer t.mu.RUnlock()
	return append([]*CA(nil), t.retired...)
}

// Dir returns the state directory the set is read from.
func (t *Trust) Dir() string { return t.dir }

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

// Bundle returns every recognised CA in PEM format.
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
	// recognised.
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
	created.ReservedNames = t.active.ReservedNames

	// The CA key is the most sensitive material in the system.
	if err := writeFileAtomic(filepath.Join(t.dir, pendingKeyFile), keyPEM, 0o600); err != nil {
		return Authority{}, err
	}
	if err := writeFileAtomic(filepath.Join(t.dir, pendingCertFile), certPEM, 0o644); err != nil {
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

// Activate hands signing over to the prepared CA and moves the previous one to
// the recognised ones.
func (t *Trust) Activate() (Authority, error) {
	authority, hook, active, err := t.activate()
	if err != nil {
		return authority, err
	}
	// The hook runs outside the lock: it reads the set it is told about.
	if hook != nil {
		hook(active)
	}
	return authority, nil
}

// activate is the handover under the lock; it hands back the hook to run
// once the lock is released.
func (t *Trust) activate() (Authority, func(*CA), *CA, error) {
	t.mu.Lock()
	defer t.mu.Unlock()

	if t.pending == nil {
		return Authority{}, nil, nil, fmt.Errorf("there is no CA prepared to take over")
	}

	// We record the previous CA as withdrawn before the new one becomes the
	// signing one: an interruption at this point leaves the fleet with a CA the
	// panel still recognises.
	if err := os.MkdirAll(filepath.Join(t.dir, retiredDir), 0o700); err != nil {
		return Authority{}, nil, nil, err
	}
	previous := filepath.Join(t.dir, retiredDir,
		t.active.Certificate.SerialNumber.String()+".pem")
	if err := os.WriteFile(previous, t.active.PEM, 0o644); err != nil {
		return Authority{}, nil, nil, err
	}

	pendingKey, err := os.ReadFile(filepath.Join(t.dir, pendingKeyFile))
	if err != nil {
		return Authority{}, nil, nil, err
	}
	// The pair on disk is checked before anything is replaced: a pending key that
	// does not match the pending certificate would become the signing pair of the
	// fleet and nothing would say so until the first renewal failed.
	incoming, err := parseCA(t.pending.PEM, pendingKey)
	if err != nil {
		return Authority{}, nil, nil, fmt.Errorf("%w: %v", ErrStateMismatch, err)
	}
	if err := incoming.VerifyPair(); err != nil {
		return Authority{}, nil, nil, err
	}
	// The key goes first and the certificate second.
	if err := writeFileAtomic(filepath.Join(t.dir, caKeyFile), pendingKey, 0o600); err != nil {
		return Authority{}, nil, nil, err
	}
	if err := writeFileAtomic(filepath.Join(t.dir, caCertFile), t.pending.PEM, 0o644); err != nil {
		return Authority{}, nil, nil, err
	}
	// Read back what landed: the pair on disk is what the next start will
	// sign with, and it has to be the one that was just checked.
	landed, err := Open(t.dir)
	if err != nil {
		return Authority{}, nil, nil, err
	}
	if !landed.Certificate.Equal(incoming.Certificate) {
		return Authority{}, nil, nil, fmt.Errorf("%w: the CA read back after the handover is not the prepared one",
			ErrStateMismatch)
	}
	removePending(t.dir)

	t.retired = append(t.retired, &CA{Certificate: t.active.Certificate, PEM: t.active.PEM})
	// The policy of the authority - the lifetime it issues and the names it keeps
	// for the panel - is the installation's, not the key's: a CA read from disk
	// as pending carries none of it and takes it over here.
	if t.pending.AgentTTL == 0 {
		t.pending.AgentTTL = t.active.AgentTTL
	}
	if t.pending.ReservedNames == nil {
		t.pending.ReservedNames = t.active.ReservedNames
	}
	t.active = t.pending
	t.pending = nil
	return describe(t.active, "active"), t.onActivate, t.active, nil
}

// Pending returns the CA prepared to take over together with the moment it was prepared.
func (t *Trust) Pending() (*CA, time.Time) {
	t.mu.RLock()
	defer t.mu.RUnlock()
	return t.pending, t.pendingAt
}

// Retire removes a withdrawn CA from the trust set.
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
		// Abandoning a prepared CA is allowed: nothing has been signed with it yet,
		// and the agents that got it will simply stop knowing it at their next
		// renewal.
		removePending(t.dir)
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
