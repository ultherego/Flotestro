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
	// store is where this set lives: the state directory, or the database
	// of an installation that has moved its keys there.
	store AuthorityStore
	dir   string
	// onActivate runs after a handover of signing; see SetActivationHook.
	onActivate func(active *CA)
}

// retiredDir holds the CAs withdrawn from signing.
const retiredDir = RetiredCertDir

// pendingCertFile and pendingKeyFile hold the CA prepared to take over.
const (
	pendingCertFile = PendingCertFile
	pendingKeyFile  = PendingKeyFile
	// pendingAtFile records the moment the CA was prepared.
	pendingAtFile = PreparedAtFile
)

// EnsureTrust reads the set of CAs from the state directory when it
// holds material and creates the first CA only when it holds nothing.
func EnsureTrust(dir string) (*Trust, error) {
	return EnsureTrustFrom(NewDirectoryAuthorities(dir))
}

// EnsureTrustFrom does the same wherever the installation keeps its
// authorities.
func EnsureTrustFrom(store AuthorityStore) (*Trust, error) {
	held, err := store.HasMaterial()
	if err != nil {
		return nil, err
	}
	if held {
		return OpenTrustFrom(store)
	}
	return InitTrustFrom(store)
}

// InitTrust creates the first CA of an installation. It refuses a
// directory that already holds material, the same way Init does.
func InitTrust(dir string) (*Trust, error) {
	if _, err := Init(dir); err != nil {
		return nil, err
	}
	return OpenTrust(dir)
}

// InitTrustFrom creates the first CA of an installation in a store that holds
// no material.
func InitTrustFrom(store AuthorityStore) (*Trust, error) {
	if _, err := InitFrom(store); err != nil {
		return nil, err
	}
	return OpenTrustFrom(store)
}

// OpenTrust reads the set of CAs of a state directory and creates nothing.
func OpenTrust(dir string) (*Trust, error) {
	return OpenTrustFrom(NewDirectoryAuthorities(dir))
}

// OpenTrustFrom reads the set of CAs wherever the installation keeps it and
// creates nothing.
func OpenTrustFrom(store AuthorityStore) (*Trust, error) {
	active, err := OpenFrom(store)
	if errors.Is(err, ErrStateMismatch) {
		recovered, finished, repairErr := repairActivation(store)
		if repairErr != nil {
			return nil, repairErr
		}
		if !finished {
			return nil, err
		}
		active = recovered
	} else if err != nil {
		return nil, err
	}
	trust := &Trust{active: active, store: store}
	if directory, ok := store.(*DirectoryAuthorities); ok {
		trust.dir = directory.Dir()
	}

	keyPEM, certPEM, preparedAt, err := store.ReadPrepared()
	if err != nil {
		return nil, err
	}
	switch {
	case certPEM != nil && keyPEM != nil:
		pending, err := parseCA(certPEM, keyPEM)
		if err != nil {
			return nil, fmt.Errorf("%w: the CA prepared to take over: %v", ErrStateMismatch, err)
		}
		if err := pending.VerifyPair(); err != nil {
			return nil, fmt.Errorf("the CA prepared to take over: %w", err)
		}
		if pending.Certificate.Equal(active.Certificate) {
			// The activation wrote the new pair and was interrupted before it
			// dropped the prepared one: nothing is pending any more.
			if err := store.DropPrepared(); err != nil {
				return nil, err
			}
			break
		}
		trust.pending = pending
		trust.pendingAt = preparedAt
		if trust.pendingAt.IsZero() {
			// A moment of preparation that was lost must not stop the panel. It
			// is taken as now and written back, so that the next start does not
			// move it again.
			trust.pendingAt = time.Now().UTC()
			if err := store.WritePrepared(keyPEM, certPEM, trust.pendingAt); err != nil {
				return nil, err
			}
		}
	case certPEM == nil && keyPEM == nil:
	default:
		// One half of a prepared CA without the other is a preparation that was
		// interrupted or a key removed by hand; either way the pair is not one
		// the panel may ever sign with.
		return nil, fmt.Errorf("%w: the CA prepared to take over is missing its key or its certificate",
			ErrStateMismatch)
	}

	retired, err := store.ReadRetired()
	if err != nil {
		return nil, err
	}
	for _, certPEM := range retired {
		// A withdrawn CA keeps no key with it: it has nothing left to sign,
		// and keeping a key without need only increases the risk.
		cert, err := parseCertificateOnly(certPEM)
		if err != nil {
			return nil, fmt.Errorf("%w: a withdrawn CA of %s: %v", ErrStateMismatch, store.Describe(), err)
		}
		trust.retired = append(trust.retired, &CA{Certificate: cert, PEM: certPEM})
	}
	return trust, nil
}

// repairActivation lets a store that can be interrupted between two writes
// finish a handover it was caught in the middle of.
func repairActivation(store AuthorityStore) (*CA, bool, error) {
	half, ok := store.(repairer)
	if !ok {
		return nil, false, nil
	}
	return half.repairActivation()
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

// Dir returns the state directory the set is read from. It is empty for an
// installation whose authorities are rows of the database.
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

	now := time.Now().UTC()
	if err := t.store.WritePrepared(keyPEM, certPEM, now); err != nil {
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
	if err := t.store.WriteRetired(t.active.Certificate.SerialNumber.String(), t.active.PEM); err != nil {
		return Authority{}, nil, nil, err
	}

	pendingKey, _, _, err := t.store.ReadPrepared()
	if err != nil {
		return Authority{}, nil, nil, err
	}
	if pendingKey == nil {
		return Authority{}, nil, nil, fmt.Errorf("%w: the CA prepared to take over has no private key left",
			ErrStateMismatch)
	}
	// The stored pair is checked before anything is replaced: a pending key that
	// does not match the pending certificate would become the signing pair of the
	// fleet and nothing would say so until the first renewal failed.
	incoming, err := parseCA(t.pending.PEM, pendingKey)
	if err != nil {
		return Authority{}, nil, nil, fmt.Errorf("%w: %v", ErrStateMismatch, err)
	}
	if err := incoming.VerifyPair(); err != nil {
		return Authority{}, nil, nil, err
	}
	if err := t.store.WriteActive(pendingKey, t.pending.PEM); err != nil {
		return Authority{}, nil, nil, err
	}
	// Read back what landed: what the store holds is what the next start will
	// sign with, and it has to be the one that was just checked.
	landed, err := OpenFrom(t.store)
	if err != nil {
		return Authority{}, nil, nil, err
	}
	if !landed.Certificate.Equal(incoming.Certificate) {
		return Authority{}, nil, nil, fmt.Errorf("%w: the CA read back after the handover is not the prepared one",
			ErrStateMismatch)
	}
	if err := t.store.DropPrepared(); err != nil {
		return Authority{}, nil, nil, err
	}

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
		if err := t.store.DropPrepared(); err != nil {
			return err
		}
		t.pending = nil
		t.pendingAt = time.Time{}
		return nil
	}

	for index, ca := range t.retired {
		if fingerprintHex(ca.Certificate.Raw) != fingerprint {
			continue
		}
		if err := t.store.DropRetired(ca.Certificate.SerialNumber.String()); err != nil {
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

// ParseCertificatePEM reads a certificate that stands on its own, without the
// key that goes with it: the public half of an authority, as it lies in a file
// or travels in a bundle.
func ParseCertificatePEM(certPEM []byte) (*x509.Certificate, error) {
	return parseCertificateOnly(certPEM)
}
