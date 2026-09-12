// Package identitystore keeps the agent's identity as indivisible
// generations.
//
// The key, the certificate and the trust bundle are one whole. Written
// separately, each with its own atomic write, they give a window in which the
// host has the key of one pair and the certificate of another - and can no
// longer log in to the fleet. Recovering such a host requires walking up to
// it, so that is the failure this whole package exists to prevent.
//
// A new generation comes into being alongside, is checked and fsynced, and
// only then is it pointed at by the atomically replaced "current" symlink.
// The previous one stays on disk: when the new one turns out to be bad, there
// is something to go back to.
package identitystore

import (
	"crypto"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/ultherego/flotestro/internal/pki"
)

// The names of the store's files and directories.
const (
	IdentityDir    = "identity"
	GenerationsDir = "generations"
	CurrentName    = "current"
	nextName       = ".current-next"
	newPrefix      = ".new-"

	KeyName         = "agent.key"
	CertificateName = "agent.pem"
	TrustName       = "trust-bundle.pem"
)

// GenerationsKept says how many generations stay on disk.
//
// The current one and one previous: more is needed for nothing, and each of
// them is a private key that had better not lie around longer than it must.
const GenerationsKept = 2

// The store's errors. The codes are part of the contract with the operator -
// they are what shows up on a host that has no connection with the panel.
var (
	ErrIdentityMissing = errors.New("identity_missing")
	ErrKeyPair         = errors.New("key_pair")
	ErrTrust           = errors.New("trust_bundle_invalid")
	ErrChain           = errors.New("certificate_chain")
	ErrIdentityURI     = errors.New("identity_uri_missing")
)

// Generation is the complete cryptographic material of a host.
type Generation struct {
	// Key is the source of the private material. An interface, because a key
	// cannot always be exported - a hardware profile leaves it in the chip
	// and gives out signing only.
	Key Key
	// KeyPEM is the way for a key that is an ordinary file. Empty when Key is
	// given; given when the caller already has the material.
	KeyPEM          []byte
	CertificatePEM  []byte
	TrustPEM        []byte
}

// key returns the generation's key regardless of the way it was given.
func (g Generation) key() (Key, error) {
	if g.Key != nil {
		return g.Key, nil
	}
	if len(g.KeyPEM) == 0 {
		return nil, fmt.Errorf("%w: a generation without a key", ErrKeyPair)
	}
	return KeyFromPEM(g.KeyPEM)
}

// Identity is a loaded generation ready to be used in a connection.
type Identity struct {
	HostID      string
	Certificate tls.Certificate
	CAPool      *x509.CertPool
	NotBefore   time.Time
	NotAfter    time.Time
	// Dir names the generation this identity comes from.
	Dir string
	// TrustPEM stays in memory, because a renewal has to write the complete
	// set even when the panel sent no new bundle.
	TrustPEM []byte
}

// Store manages the host's identity directory.
type Store struct {
	root   string
	source KeySource
}

// New creates the store in the agent's state directory.
func New(stateDir string) *Store {
	return NewWithSource(stateDir, Software())
}

// NewWithSource creates the store with the given source of keys.
//
// A hardware profile replaces the source alone: the rest of the store, the
// enrollment and the renewal do not know where the key lies, and are not
// meant to.
func NewWithSource(stateDir string, source KeySource) *Store {
	if source == nil {
		source = Software()
	}
	return &Store{root: filepath.Join(stateDir, IdentityDir), source: source}
}

// NewKey creates a key matching this store's source.
func (m *Store) NewKey() (Key, error) { return m.source.New() }

// Dir returns the identity directory.
func (m *Store) Dir() string { return m.root }

// Check verifies a generation before any change on disk.
//
// The order matters: first the key-certificate pair, then the chain to the
// trust bundle, and the identity in the certificate last. Each of them means
// something different to the operator.
func Check(g Generation) error {
	key, err := g.key()
	if err != nil {
		return err
	}
	block, _ := pem.Decode(g.CertificatePEM)
	if block == nil {
		return fmt.Errorf("%w: certyfikat nie zawiera bloku PEM", ErrKeyPair)
	}
	leaf, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return fmt.Errorf("%w: %v", ErrKeyPair, err)
	}
	// The pair is checked through the public key rather than by combining the
	// certificate with the private material: a hardware key cannot be
	// combined, and it is known anyway whether it matches.
	if !keysMatch(leaf.PublicKey, key.Public()) {
		return fmt.Errorf("%w: certyfikat nie pasuje do klucza", ErrKeyPair)
	}
	roots := x509.NewCertPool()
	if !roots.AppendCertsFromPEM(g.TrustPEM) {
		return ErrTrust
	}
	if _, err := leaf.Verify(x509.VerifyOptions{
		Roots:       roots,
		KeyUsages:   []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
		CurrentTime: time.Now(),
	}); err != nil {
		return fmt.Errorf("%w: %v", ErrChain, err)
	}
	// The store keeps the agent's identity and the relay's identity: it
	// records a key with a certificate rather than a role. The kind is
	// settled by what is done with that certificate, and the services on the
	// other side check it.
	if _, _, err := pki.IdentityFromCert(leaf); err != nil {
		return fmt.Errorf("%w: %v", ErrIdentityURI, err)
	}
	return nil
}

// Commit records a new generation and switches "current" to it.
//
// The order is the whole content of this function: nothing switches the
// identity before the complete set lies on disk and passes verification. An
// interruption at any point leaves the host on the previous, working
// generation.
func (m *Store) Commit(g Generation) (*Identity, error) {
	if err := Check(g); err != nil {
		return nil, err
	}
	generations := filepath.Join(m.root, GenerationsDir)
	if err := os.MkdirAll(generations, 0o700); err != nil {
		return nil, err
	}

	temporary, err := os.MkdirTemp(generations, newPrefix)
	if err != nil {
		return nil, err
	}
	committed := false
	defer func() {
		if !committed {
			_ = os.RemoveAll(temporary)
		}
	}()
	if err := os.Chmod(temporary, 0o700); err != nil {
		return nil, err
	}

	// The key writes itself: only it knows what persisting it means. The
	// certificate and the bundle are not secret and can be read by diagnostic
	// tools.
	key, err := g.key()
	if err != nil {
		return nil, err
	}
	if err := key.Save(temporary); err != nil {
		return nil, err
	}
	if err := writeWithSync(filepath.Join(temporary, CertificateName), g.CertificatePEM, 0o644); err != nil {
		return nil, err
	}
	if err := writeWithSync(filepath.Join(temporary, TrustName), g.TrustPEM, 0o644); err != nil {
		return nil, err
	}
	if err := syncDir(temporary); err != nil {
		return nil, err
	}

	serial, err := serialNumber(g.CertificatePEM)
	if err != nil {
		return nil, err
	}
	target := filepath.Join(generations, serial)
	// The same serial number means the same certificate: a write repeated
	// after an interrupted start is to give the same result rather than an
	// error.
	if _, err := os.Stat(target); err == nil {
		if err := os.RemoveAll(target); err != nil {
			return nil, err
		}
	}
	if err := os.Rename(temporary, target); err != nil {
		return nil, err
	}
	committed = true
	if err := syncDir(generations); err != nil {
		return nil, err
	}

	if err := m.switchTo(serial); err != nil {
		return nil, err
	}
	if err := m.Clean(); err != nil {
		return nil, err
	}
	return m.Current()
}

// switchTo replaces the "current" symlink in one atomic move.
func (m *Store) switchTo(serial string) error {
	next := filepath.Join(m.root, nextName)
	_ = os.Remove(next)
	if err := os.Symlink(filepath.Join(GenerationsDir, serial), next); err != nil {
		return err
	}
	if err := os.Rename(next, filepath.Join(m.root, CurrentName)); err != nil {
		_ = os.Remove(next)
		return err
	}
	return syncDir(m.root)
}

// Current loads the identity pointed at by "current".
//
// We resolve the symlink to the real generation directory: that directory is
// the answer to "what is the host using now", not the symlink path, which is
// always the same.
func (m *Store) Current() (*Identity, error) {
	dir, err := filepath.EvalSymlinks(filepath.Join(m.root, CurrentName))
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrIdentityMissing, err)
	}
	return load(dir, m.source)
}

// Previous loads the generation from before the current one.
//
// It stays on disk so that there is something to go back to when the new one
// turns out to be bad - for example when the panel issues a certificate it
// then does not recognise itself.
func (m *Store) Previous() (*Identity, error) {
	current, err := os.Readlink(filepath.Join(m.root, CurrentName))
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrIdentityMissing, err)
	}
	names, err := m.generations()
	if err != nil {
		return nil, err
	}
	currentName := filepath.Base(current)
	for i := len(names) - 1; i >= 0; i-- {
		if names[i] == currentName {
			continue
		}
		return load(filepath.Join(m.root, GenerationsDir, names[i]), m.source)
	}
	return nil, ErrIdentityMissing
}

// Clean removes the traces of interrupted writes and the surplus
// generations.
//
// Called at start and after every commit: a temporary directory left after a
// crash and the ".current-next" symlink are rubbish rather than state.
func (m *Store) Clean() error {
	// A temporary symlink is never the host's identity: either it was renamed
	// to "current" or it does not exist.
	_ = os.Remove(filepath.Join(m.root, nextName))

	generations := filepath.Join(m.root, GenerationsDir)
	entries, err := os.ReadDir(generations)
	if err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		return err
	}
	for _, entry := range entries {
		if strings.HasPrefix(entry.Name(), newPrefix) {
			_ = os.RemoveAll(filepath.Join(generations, entry.Name()))
		}
	}

	current := ""
	if target, err := os.Readlink(filepath.Join(m.root, CurrentName)); err == nil {
		current = filepath.Base(target)
	}
	names, err := m.generations()
	if err != nil {
		return err
	}
	// We delete from the oldest and never the current one: the generation the
	// host is working on is not surplus even when it is the oldest.
	toRemove := len(names) - GenerationsKept
	for i := 0; i < len(names) && toRemove > 0; i++ {
		if names[i] == current {
			continue
		}
		if err := os.RemoveAll(filepath.Join(generations, names[i])); err != nil {
			return err
		}
		toRemove--
	}
	return nil
}

// generations returns the names of the generations ordered from the oldest.
func (m *Store) generations() ([]string, error) {
	entries, err := os.ReadDir(filepath.Join(m.root, GenerationsDir))
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, err
	}
	type generationEntry struct {
		name string
		time time.Time
	}
	var collected []generationEntry
	for _, entry := range entries {
		if !entry.IsDir() || strings.HasPrefix(entry.Name(), newPrefix) {
			continue
		}
		info, err := entry.Info()
		if err != nil {
			continue
		}
		collected = append(collected, generationEntry{name: entry.Name(), time: info.ModTime()})
	}
	sort.Slice(collected, func(i, j int) bool {
		if collected[i].time.Equal(collected[j].time) {
			return collected[i].name < collected[j].name
		}
		return collected[i].time.Before(collected[j].time)
	})
	names := make([]string, 0, len(collected))
	for _, entry := range collected {
		names = append(names, entry.name)
	}
	return names, nil
}

// load reads the complete set from a generation directory.
//
// The source loads the key rather than this function: for a hardware key the
// directory holds a handle rather than material, and only the source knows
// what to do with it.
func load(dir string, source KeySource) (*Identity, error) {
	if source == nil {
		source = Software()
	}
	key, err := source.Load(dir)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrIdentityMissing, err)
	}
	certPEM, err := os.ReadFile(filepath.Join(dir, CertificateName))
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrIdentityMissing, err)
	}
	trustPEM, err := os.ReadFile(filepath.Join(dir, TrustName))
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrIdentityMissing, err)
	}

	block, _ := pem.Decode(certPEM)
	if block == nil {
		return nil, fmt.Errorf("%w: certyfikat nie zawiera bloku PEM", ErrKeyPair)
	}
	pair := tls.Certificate{Certificate: [][]byte{block.Bytes}, PrivateKey: key.Signer()}
	leaf, err := x509.ParseCertificate(pair.Certificate[0])
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrKeyPair, err)
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(trustPEM) {
		return nil, ErrTrust
	}
	_, hostID, err := pki.IdentityFromCert(leaf)
	if err != nil {
		// Older fleet certificates may have no URI SAN. The common name is
		// then the only thing the host knows about itself - and better than
		// refusing to start.
		hostID = leaf.Subject.CommonName
	}
	pair.Leaf = leaf
	return &Identity{
		HostID: hostID, Certificate: pair, CAPool: pool,
		NotBefore: leaf.NotBefore, NotAfter: leaf.NotAfter,
		Dir: dir, TrustPEM: trustPEM,
	}, nil
}

// serialNumber names a generation by the certificate's serial number.
//
// The name has to be different for different certificates and the same for a
// repeated write of the same one - a serial number does both.
func serialNumber(certPEM []byte) (string, error) {
	block, _ := pem.Decode(certPEM)
	if block == nil {
		return "", fmt.Errorf("%w: certyfikat nie jest poprawnym PEM", ErrKeyPair)
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return "", fmt.Errorf("%w: %v", ErrKeyPair, err)
	}
	return cert.SerialNumber.Text(16), nil
}

// writeWithSync writes a file and forces it to be durable.
func writeWithSync(path string, data []byte, mode os.FileMode) error {
	file, err := os.OpenFile(path, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, mode)
	if err != nil {
		return err
	}
	if _, err := file.Write(data); err != nil {
		file.Close()
		return err
	}
	if err := file.Sync(); err != nil {
		file.Close()
		return err
	}
	return file.Close()
}

// syncDir forces the durability of the rename within a directory itself.
func syncDir(path string) error {
	dir, err := os.Open(path)
	if err != nil {
		return err
	}
	defer dir.Close()
	return dir.Sync()
}

// Migrate moves an identity from the old file layout into generations.
//
// A host set up before the store was introduced has its key, certificate and
// bundle loose in the state directory. Moving them as a whole happens once
// and does not delete the originals: should anything go wrong, the previous
// version of the agent has something to start from.
//
// It returns true when a migration really happened.
func (m *Store) Migrate(keyPath, certPath, trustPath string) (bool, error) {
	if _, err := os.Lstat(filepath.Join(m.root, CurrentName)); err == nil {
		return false, nil
	}
	keyPEM, err := os.ReadFile(keyPath)
	if err != nil {
		return false, nil
	}
	certPEM, err := os.ReadFile(certPath)
	if err != nil {
		return false, nil
	}
	trustPEM, err := os.ReadFile(trustPath)
	if err != nil {
		return false, nil
	}
	if err := os.MkdirAll(m.root, 0o700); err != nil {
		return false, err
	}
	if _, err := m.Commit(Generation{
		KeyPEM: keyPEM, CertificatePEM: certPEM, TrustPEM: trustPEM,
	}); err != nil {
		// An identity that cannot be verified is not an identity to move:
		// the host has to go through enrollment again.
		return false, err
	}
	return true, nil
}

// keysMatch says whether the certificate describes this key.
func keysMatch(fromCertificate, public crypto.PublicKey) bool {
	comparable, ok := public.(interface{ Equal(crypto.PublicKey) bool })
	if !ok {
		return false
	}
	return comparable.Equal(fromCertificate)
}
