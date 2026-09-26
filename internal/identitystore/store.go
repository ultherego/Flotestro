// Package identitystore keeps the agent's identity as indivisible generations.
// The key, the certificate and the trust bundle are one whole.
package identitystore

import (
	"crypto"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"golang.org/x/sys/unix"

	"github.com/ultherego/flotestro/internal/pki"
)

// The names of the store's files and directories.
const (
	IdentityDir    = "identity"
	GenerationsDir = "generations"
	CurrentName    = "current"
	nextName       = ".current-next"
	newPrefix      = ".new-"
	// stalePrefix marks a complete generation of a serial that is being
	// written again: set aside rather than deleted, and swept by Clean.
	stalePrefix = ".stale-"

	KeyName         = "agent.key"
	CertificateName = "agent.pem"
	TrustName       = "trust-bundle.pem"
)

// GenerationsKept says how many generations stay on disk.
const GenerationsKept = 2

// lockName is the file every change of the store is serialised on. The agent
// daemon, the relay daemon and the operator running agentctl or relayctl all
// write into one directory, and two of them at once were enough to lose a
// host's identity: the staging directory of one was removed by the Clean of the
// other, and the shared name of the symlink temp let one publish the other's
// generation while reporting its own.
const lockName = "identity.lock"

// withLock runs a change of the store under an exclusive lock. Every path that
// writes takes it; the reads do not, because a read follows one symlink and a
// symlink is replaced in one move.
func (m *Store) withLock(run func() error) error {
	if err := os.MkdirAll(m.root, 0o700); err != nil {
		return err
	}
	fd, err := unix.Open(filepath.Join(m.root, lockName),
		unix.O_RDWR|unix.O_CREAT|unix.O_CLOEXEC, 0o600)
	if err != nil {
		return fmt.Errorf("the lock of the identity store: %w", err)
	}
	defer unix.Close(fd)
	if err := unix.Flock(fd, unix.LOCK_EX); err != nil {
		return fmt.Errorf("locking the identity store: %w", err)
	}
	defer func() { _ = unix.Flock(fd, unix.LOCK_UN) }()
	return run()
}

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
	// Key is the source of the private material.
	Key Key
	// KeyPEM is the way for a key that is an ordinary file. Empty when Key is
	// given; given when the caller already has the material.
	KeyPEM         []byte
	CertificatePEM []byte
	TrustPEM       []byte
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
func Check(g Generation) error {
	key, err := g.key()
	if err != nil {
		return err
	}
	block, _ := pem.Decode(g.CertificatePEM)
	if block == nil {
		return fmt.Errorf("%w: the certificate carries no PEM block", ErrKeyPair)
	}
	leaf, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return fmt.Errorf("%w: %v", ErrKeyPair, err)
	}
	// The pair is checked through the public key rather than by combining the
	// certificate with the private material: a hardware key cannot be combined,
	// and it is known anyway whether it matches.
	if !keysMatch(leaf.PublicKey, key.Public()) {
		return fmt.Errorf("%w: the certificate does not match the key", ErrKeyPair)
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
	// The store keeps the agent's identity and the relay's identity: it records a
	// key with a certificate rather than a role.
	if _, _, err := pki.IdentityFromCert(leaf); err != nil {
		return fmt.Errorf("%w: %v", ErrIdentityURI, err)
	}
	return nil
}

// Commit records a new generation and switches "current" to it.
func (m *Store) Commit(g Generation) (*Identity, error) {
	var identity *Identity
	err := m.withLock(func() error {
		var err error
		identity, err = m.commitLocked(g)
		return err
	})
	return identity, err
}

func (m *Store) commitLocked(g Generation) (*Identity, error) {
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

	// The key writes itself: only it knows what persisting it means.
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
	// The name has to be free: the store never removes a generation to make room
	// for another.
	if err := renameNoReplace(temporary, target); err != nil {
		if !errors.Is(err, os.ErrExist) {
			return nil, err
		}
		if m.isCurrent(serial) {
			if _, err := load(target, m.source); err == nil {
				return m.Current()
			}
			return nil, fmt.Errorf("%w: the active generation %s is damaged and cannot be replaced in place",
				ErrKeyPair, serial)
		}
		if _, err := setAside(generations, serial); err != nil {
			return nil, err
		}
		if err := renameNoReplace(temporary, target); err != nil {
			return nil, err
		}
	}
	committed = true
	if err := syncDir(generations); err != nil {
		return nil, err
	}

	if err := m.switchTo(serial); err != nil {
		return nil, err
	}
	if err := m.cleanLocked(); err != nil {
		return nil, err
	}
	return m.Current()
}

// isCurrent says whether "current" points at the named generation.
func (m *Store) isCurrent(serial string) bool {
	target, err := os.Readlink(filepath.Join(m.root, CurrentName))
	return err == nil && filepath.Base(target) == serial
}

// setAside moves a generation directory that is not the active one under
// a stale name, so its serial is free for the copy being written.
func setAside(generations, serial string) (string, error) {
	suffix := make([]byte, 8)
	if _, err := rand.Read(suffix); err != nil {
		return "", err
	}
	aside := filepath.Join(generations, stalePrefix+serial+"-"+hex.EncodeToString(suffix))
	if err := renameNoReplace(filepath.Join(generations, serial), aside); err != nil {
		return "", err
	}
	return aside, nil
}

// renameNoReplaceFallback is the check-then-move for a filesystem without the
// atomic form.
func renameNoReplaceFallback(oldPath, newPath string) error {
	if _, err := os.Lstat(newPath); err == nil {
		return &os.LinkError{Op: "rename", Old: oldPath, New: newPath, Err: os.ErrExist}
	} else if !errors.Is(err, os.ErrNotExist) {
		return err
	}
	return os.Rename(oldPath, newPath)
}

// switchTo replaces the "current" symlink in one atomic move. The temporary
// name is this call's own: a shared one let a second writer remove the symlink
// this one had just made, and then publish its own target under this one's
// rename.
func (m *Store) switchTo(serial string) error {
	name := make([]byte, 8)
	if _, err := rand.Read(name); err != nil {
		return err
	}
	next := filepath.Join(m.root, nextName+hex.EncodeToString(name))
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
func (m *Store) Current() (*Identity, error) {
	dir, err := filepath.EvalSymlinks(filepath.Join(m.root, CurrentName))
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrIdentityMissing, err)
	}
	return load(dir, m.source)
}

// Previous loads the generation from before the current one.
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

// Clean removes the traces of interrupted writes and the surplus generations.
func (m *Store) Clean() error {
	return m.withLock(m.cleanLocked)
}

func (m *Store) cleanLocked() error {
	// A temporary symlink is never the host's identity: either it was renamed
	// to "current" or it does not exist. The names carry a random tail now, so
	// the leftovers of an interrupted move are swept by prefix.
	if entries, err := os.ReadDir(m.root); err == nil {
		for _, entry := range entries {
			if strings.HasPrefix(entry.Name(), nextName) {
				_ = os.Remove(filepath.Join(m.root, entry.Name()))
			}
		}
	}

	generations := filepath.Join(m.root, GenerationsDir)
	entries, err := os.ReadDir(generations)
	if err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		return err
	}
	// A half-written generation and a copy set aside by a repeated write are
	// never pointed at by "current"; both are rubbish rather than state.
	for _, entry := range entries {
		if strings.HasPrefix(entry.Name(), newPrefix) || strings.HasPrefix(entry.Name(), stalePrefix) {
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
		if !entry.IsDir() || strings.HasPrefix(entry.Name(), ".") {
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
		return nil, fmt.Errorf("%w: the certificate carries no PEM block", ErrKeyPair)
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
		// Older fleet certificates may have no URI SAN.
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
func serialNumber(certPEM []byte) (string, error) {
	block, _ := pem.Decode(certPEM)
	if block == nil {
		return "", fmt.Errorf("%w: the certificate is not valid PEM", ErrKeyPair)
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
func (m *Store) Migrate(keyPath, certPath, trustPath string) (bool, error) {
	if _, err := os.Lstat(filepath.Join(m.root, CurrentName)); err == nil {
		return false, nil
	}
	// A file that is not there means there is nothing to move. A file that is
	// there and cannot be read means something else entirely - the wrong owner,
	// the wrong mode, a broken disk - and answering "no identity here" to that
	// sent the operator to enroll a host that already had one.
	keyPEM, err := readLegacy(keyPath)
	if err != nil || keyPEM == nil {
		return false, err
	}
	certPEM, err := readLegacy(certPath)
	if err != nil || certPEM == nil {
		return false, err
	}
	trustPEM, err := readLegacy(trustPath)
	if err != nil || trustPEM == nil {
		return false, err
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

// readLegacy reads one file of the old layout. A missing file is no identity
// and no error; anything else is an error, because it is not the same thing.
func readLegacy(path string) ([]byte, error) {
	content, err := os.ReadFile(path)
	if errors.Is(err, fs.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("the identity of the previous layout at %s: %w", path, err)
	}
	return content, nil
}

// keysMatch says whether the certificate describes this key.
func keysMatch(fromCertificate, public crypto.PublicKey) bool {
	comparable, ok := public.(interface{ Equal(crypto.PublicKey) bool })
	if !ok {
		return false
	}
	return comparable.Equal(fromCertificate)
}
