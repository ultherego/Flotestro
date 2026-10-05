package pki

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/rand"
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
	// onPrepare runs after an authority has been admitted to the set; see
	// SetPreparationHook.
	onPrepare func(prepared *CA)
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
	set, err := readTrust(store)
	if err != nil {
		return nil, err
	}
	trust := &Trust{store: store}
	if directory, ok := store.(*DirectoryAuthorities); ok {
		trust.dir = directory.Dir()
	}
	trust.active, trust.pending, trust.pendingAt, trust.retired =
		set.active, set.pending, set.pendingAt, set.retired
	return trust, nil
}

// trustSet is the set of CAs as a store holds it. Opening a trust set and
// refreshing one read it the same way, through readTrust, so the two cannot
// come to disagree about what the store says.
type trustSet struct {
	active    *CA
	pending   *CA
	pendingAt time.Time
	retired   []*CA
}

// readTrust reads the whole set from the store, finishing an activation the
// store was caught in the middle of and repairing a moment of preparation that
// was lost. It returns an error rather than a half-read set: a trust set that
// is missing a part of itself refuses the hosts that part underwrites.
func readTrust(store AuthorityStore) (*trustSet, error) {
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
	set := &trustSet{active: active}

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
		set.pending = pending
		set.pendingAt = preparedAt
		if set.pendingAt.IsZero() {
			// A moment of preparation that was lost must not stop the panel. It
			// is taken as now and written back, so that the next start does not
			// move it again.
			set.pendingAt = time.Now().UTC()
			if err := store.WritePrepared(keyPEM, certPEM, set.pendingAt); err != nil {
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
		set.retired = append(set.retired, &CA{Certificate: cert, PEM: certPEM})
	}
	return set, nil
}

// Refresh re-reads the set from the store into this object, so that everything
// holding it - the pool of the gateway, the issuer, the metrics - follows an
// authority another replica activated. Swapping in a freshly opened set
// instead would leave every one of those holders on the object they were given
// at the start, signing with and trusting an authority the installation has
// withdrawn.
//
// A store that cannot be read leaves the set exactly as it was and says why: a
// half-refreshed trust set is worse than a stale one.
func (t *Trust) Refresh() error {
	set, err := readTrust(t.store)
	if err != nil {
		return err
	}

	t.mu.Lock()
	defer t.mu.Unlock()
	// The policy of the authority - the lifetime it issues and the names it
	// keeps for the panel - belongs to the installation and not to the key, and
	// an authority read from a store carries none of it.
	if set.active.AgentTTL == 0 {
		set.active.AgentTTL = t.active.AgentTTL
	}
	if set.active.Reserved == nil {
		set.active.Reserved = t.active.Reserved
	}
	t.active, t.pending, t.pendingAt, t.retired =
		set.active, set.pending, set.pendingAt, set.retired
	return nil
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

// SetPreparationHook registers what runs once a new CA has been admitted to
// the trust set. It is how the rest of the installation gets told that the set
// in the store has moved; a replica that is never told goes on handing the
// hosts a bundle without the new CA, and they would be cut off the moment it
// took over signing.
func (t *Trust) SetPreparationHook(hook func(prepared *CA)) {
	t.mu.Lock()
	defer t.mu.Unlock()
	t.onPrepare = hook
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
	authority, hook, prepared, err := t.prepare()
	if err != nil {
		return authority, err
	}
	// The hook runs outside the lock: it reads the set it is told about.
	if hook != nil {
		hook(prepared)
	}
	return authority, nil
}

// prepare is the admission under the lock; it hands back the hook to run once
// the lock is released.
func (t *Trust) prepare() (Authority, func(*CA), *CA, error) {
	t.mu.Lock()
	defer t.mu.Unlock()

	if t.pending != nil {
		return Authority{}, nil, nil, fmt.Errorf("a CA prepared to take over already exists")
	}
	created, certPEM, keyPEM, err := newCA()
	if err != nil {
		return Authority{}, nil, nil, err
	}
	created.AgentTTL = t.active.AgentTTL
	created.Reserved = t.active.Reserved

	now := time.Now().UTC()
	if err := t.store.WritePrepared(keyPEM, certPEM, now); err != nil {
		return Authority{}, nil, nil, err
	}
	t.pending = created
	t.pendingAt = now

	prepared := describe(created, "pending")
	prepared.PreparedAt = now
	return prepared, t.onPrepare, created, nil
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
	if t.pending.Reserved == nil {
		t.pending.Reserved = t.active.Reserved
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

// trustBundlePrefix separates a signature over a trust bundle from every other
// signature an authority's key makes, a certificate above all.
const trustBundlePrefix = "flotestro-ca-bundle/1\n"

// trustBundleDigest is what is signed: the prefix and the bundle, so the
// signature cannot be read as one over anything else.
func trustBundleDigest(bundle []byte) []byte {
	digest := sha256.New()
	digest.Write([]byte(trustBundlePrefix))
	digest.Write(bundle)
	return digest.Sum(nil)
}

// SignTrustBundle vouches with the key of this authority for the set of
// authorities a host is handed.
//
// A host verifies the certificate it is given against the trust it already
// holds, which proves that the answer comes from somebody who can make that
// authority sign - but the bundle travels in the same answer and a relay
// carries that answer. The relay is trusted to pass it on, not to decide what
// the fleet trusts, and only the authority itself can produce this.
func (ca *CA) SignTrustBundle(bundle []byte) ([]byte, error) {
	if ca == nil || ca.PrivateKey == nil {
		return nil, fmt.Errorf("%w: the authority has no key to vouch for a trust bundle with", ErrStateMismatch)
	}
	if len(bundle) == 0 {
		return nil, fmt.Errorf("an empty trust bundle is not vouched for")
	}
	return ecdsa.SignASN1(rand.Reader, ca.PrivateKey, trustBundleDigest(bundle))
}

// AdoptableTrust says whether the set of authorities an answer offers may be
// written as the ones this peer trusts.
//
// A rotation legitimately adds an authority, so the answer cannot be judged by
// what it changes; it is judged by who says so. Only an authority the peer
// already believes in can vouch for the set, and the vouch is required over
// every change: an authority appended, one taken away, the same set in another
// order. An answer that carries none leaves the peer on the trust it has.
//
// Agents, relays and relayctl all ask this one function. The relay used to ask
// nothing at all and wrote down whatever answered the renewal as the
// authorities of its whole site.
func AdoptableTrust(held, offered, vouch []byte) error {
	if len(held) == 0 || bytes.Equal(offered, held) {
		return nil
	}
	if err := VerifyTrustBundle(held, offered, vouch); err != nil {
		return fmt.Errorf("the renewal carries a different set of authorities and no authority this host "+
			"trusts vouched for it, so this is not a change the panel can be shown to have made: %w", err)
	}
	return nil
}

// VerifyTrustBundle says whether an authority of the given trust vouched for
// the bundle. The host asks it of the trust it holds now: a bundle that adds
// an authority is adopted because an authority the host already believes in
// says so, and not because it arrived with a certificate that verifies.
func VerifyTrustBundle(trustPEM, bundle, signature []byte) error {
	if len(signature) == 0 {
		return fmt.Errorf("the trust bundle carries no signature of the authority in force")
	}
	digest := trustBundleDigest(bundle)
	authorities := 0
	rest := trustPEM
	for {
		var block *pem.Block
		block, rest = pem.Decode(rest)
		if block == nil {
			break
		}
		if block.Type != "CERTIFICATE" {
			continue
		}
		cert, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			return fmt.Errorf("an authority of the trust held: %w", err)
		}
		public, ok := cert.PublicKey.(*ecdsa.PublicKey)
		if !ok {
			continue
		}
		authorities++
		if ecdsa.VerifyASN1(public, digest, signature) {
			return nil
		}
	}
	if authorities == 0 {
		return fmt.Errorf("the trust held names no authority that could vouch for a bundle")
	}
	return fmt.Errorf("no authority of the %d this host trusts vouched for the trust bundle", authorities)
}

// IssuerIDsOfBundle names every authority a trust bundle carries, by the same
// identifier a certificate row names its issuer with. It is what a host is
// recorded as having been given: the generation of the trust, read from the
// bytes that were handed over rather than from the moment they went out.
func IssuerIDsOfBundle(bundlePEM []byte) ([]string, error) {
	var ids []string
	rest := bundlePEM
	for {
		var block *pem.Block
		block, rest = pem.Decode(rest)
		if block == nil {
			break
		}
		if block.Type != "CERTIFICATE" {
			continue
		}
		cert, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			return nil, fmt.Errorf("a certificate of the trust bundle: %w", err)
		}
		ids = append(ids, IssuerIDOf(cert))
	}
	if len(ids) == 0 {
		return nil, fmt.Errorf("the trust bundle carries no certificate")
	}
	return ids, nil
}
