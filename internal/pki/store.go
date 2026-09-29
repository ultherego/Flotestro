package pki

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"
)

// Where the authorities of an installation are kept.
//
// They used to be files of one machine's state directory, and for an
// installation that has not moved its keys they still are. Once the keys are
// rows of the database, every replica has to read the same set the same way,
// and the CA is the half of the state that cannot be left behind: a panel that
// reads its signing key from one machine's disk is not a replica, it is the
// installation.

// AuthorityStore is where an installation keeps its certificate authorities:
// the one that signs, the one prepared to take over from it, and the
// certificates of those withdrawn from signing.
//
// A write is one step. A reader arriving in the middle of an activation finds
// the authority that was there or the one that is, never a key of one beside
// the certificate of the other.
type AuthorityStore interface {
	// Describe names the place the material is read from, for the refusals
	// that have to tell an operator where to look.
	Describe() string
	// HasMaterial says whether anything of an authority is kept here at
	// all: a signing pair or half of one, a prepared authority, a withdrawn
	// certificate.
	HasMaterial() (bool, error)
	// ReadActive returns the authority that signs. A half that is not there
	// comes back nil, because which half is missing is what tells a key
	// removed by hand from an installation that never had one.
	ReadActive() (keyPEM, certPEM []byte, err error)
	// ReadPrepared returns the authority prepared to take over and the
	// moment it was prepared. A zero moment is one that was lost.
	ReadPrepared() (keyPEM, certPEM []byte, preparedAt time.Time, err error)
	// ReadRetired returns the certificates withdrawn from signing. They
	// carry no key: a withdrawn authority has nothing left to sign, and
	// keeping its key would only be a risk.
	ReadRetired() ([][]byte, error)
	// WriteActive makes this pair the one that signs.
	WriteActive(keyPEM, certPEM []byte) error
	// WritePrepared records the authority prepared to take over, with the
	// moment it was prepared.
	WritePrepared(keyPEM, certPEM []byte, preparedAt time.Time) error
	// DropPrepared abandons the prepared authority. Nothing was signed with
	// it, so nothing is lost with it.
	DropPrepared() error
	// WriteRetired keeps the certificate of an authority withdrawn from
	// signing, under the serial it is known by.
	WriteRetired(serial string, certPEM []byte) error
	// DropRetired forgets a withdrawn certificate. A serial that is not
	// there is not an error: the set is meant to end up without it.
	DropRetired(serial string) error
}

// repairer is a store whose writes can be interrupted between them, and which
// can therefore be found half way through an activation. A store whose writes
// are one transaction has nothing to repair and does not implement this.
type repairer interface {
	// repairActivation completes a handover that wrote the new key and not
	// yet the new certificate, and says whether it had anything to do.
	repairActivation() (*CA, bool, error)
}

// DirectoryAuthorities keeps the authorities as files of the state directory:
// ca.key and ca.pem, the prepared pair beside them, and the withdrawn
// certificates in ca-retired.
type DirectoryAuthorities struct {
	dir string
}

// NewDirectoryAuthorities reads and writes the authorities of a state
// directory.
func NewDirectoryAuthorities(dir string) *DirectoryAuthorities {
	return &DirectoryAuthorities{dir: dir}
}

// Dir returns the state directory the authorities live in.
func (d *DirectoryAuthorities) Dir() string { return d.dir }

// Describe implements AuthorityStore.
func (d *DirectoryAuthorities) Describe() string { return d.dir }

// HasMaterial implements AuthorityStore.
func (d *DirectoryAuthorities) HasMaterial() (bool, error) {
	return HasAnyMaterial(d.dir), nil
}

// ReadActive implements AuthorityStore.
func (d *DirectoryAuthorities) ReadActive() ([]byte, []byte, error) {
	return d.pair(caKeyFile, caCertFile)
}

// ReadPrepared implements AuthorityStore.
func (d *DirectoryAuthorities) ReadPrepared() ([]byte, []byte, time.Time, error) {
	keyPEM, certPEM, err := d.pair(pendingKeyFile, pendingCertFile)
	if err != nil {
		return nil, nil, time.Time{}, err
	}
	var preparedAt time.Time
	// A marker that is gone or unreadable is not a reason to refuse the
	// authority it belongs to; the caller takes the moment as now.
	if stamp, err := os.ReadFile(filepath.Join(d.dir, pendingAtFile)); err == nil {
		if parsed, err := time.Parse(time.RFC3339, strings.TrimSpace(string(stamp))); err == nil {
			preparedAt = parsed
		}
	}
	return keyPEM, certPEM, preparedAt, nil
}

// pair reads a key and a certificate, either of which may be absent.
func (d *DirectoryAuthorities) pair(keyFile, certFile string) ([]byte, []byte, error) {
	keyPEM, keyErr := os.ReadFile(filepath.Join(d.dir, keyFile))
	if keyErr != nil && !os.IsNotExist(keyErr) {
		return nil, nil, keyErr
	}
	certPEM, certErr := os.ReadFile(filepath.Join(d.dir, certFile))
	if certErr != nil && !os.IsNotExist(certErr) {
		return nil, nil, certErr
	}
	if keyErr != nil {
		keyPEM = nil
	}
	if certErr != nil {
		certPEM = nil
	}
	return keyPEM, certPEM, nil
}

// ReadRetired implements AuthorityStore.
func (d *DirectoryAuthorities) ReadRetired() ([][]byte, error) {
	entries, err := os.ReadDir(filepath.Join(d.dir, retiredDir))
	if err != nil && !os.IsNotExist(err) {
		return nil, fmt.Errorf("directory of withdrawn CAs: %w", err)
	}
	var certificates [][]byte
	for _, entry := range entries {
		if entry.IsDir() || filepath.Ext(entry.Name()) != ".pem" {
			continue
		}
		certPEM, err := os.ReadFile(filepath.Join(d.dir, retiredDir, entry.Name()))
		if err != nil {
			return nil, err
		}
		certificates = append(certificates, certPEM)
	}
	return certificates, nil
}

// WriteActive implements AuthorityStore. The key goes first and the
// certificate second, so that an interruption leaves the pair the next start
// can finish rather than a certificate nothing can sign for.
func (d *DirectoryAuthorities) WriteActive(keyPEM, certPEM []byte) error {
	if err := os.MkdirAll(d.dir, 0o700); err != nil {
		return fmt.Errorf("state directory: %w", err)
	}
	// The CA key is the most sensitive material in the system.
	if err := writeFileAtomic(filepath.Join(d.dir, caKeyFile), keyPEM, 0o600); err != nil {
		return err
	}
	return writeFileAtomic(filepath.Join(d.dir, caCertFile), certPEM, 0o644)
}

// WritePrepared implements AuthorityStore.
func (d *DirectoryAuthorities) WritePrepared(keyPEM, certPEM []byte, preparedAt time.Time) error {
	if err := os.MkdirAll(d.dir, 0o700); err != nil {
		return fmt.Errorf("state directory: %w", err)
	}
	// The CA key is the most sensitive material in the system.
	if err := writeFileAtomic(filepath.Join(d.dir, pendingKeyFile), keyPEM, 0o600); err != nil {
		return err
	}
	if err := writeFileAtomic(filepath.Join(d.dir, pendingCertFile), certPEM, 0o644); err != nil {
		return err
	}
	return writeFileAtomic(filepath.Join(d.dir, pendingAtFile),
		[]byte(preparedAt.UTC().Format(time.RFC3339)), 0o644)
}

// DropPrepared implements AuthorityStore.
func (d *DirectoryAuthorities) DropPrepared() error {
	for _, name := range []string{pendingCertFile, pendingKeyFile, pendingAtFile} {
		if err := os.Remove(filepath.Join(d.dir, name)); err != nil && !os.IsNotExist(err) {
			return err
		}
	}
	return nil
}

// WriteRetired implements AuthorityStore.
func (d *DirectoryAuthorities) WriteRetired(serial string, certPEM []byte) error {
	if err := os.MkdirAll(filepath.Join(d.dir, retiredDir), 0o700); err != nil {
		return err
	}
	return os.WriteFile(filepath.Join(d.dir, retiredDir, serial+".pem"), certPEM, 0o644)
}

// DropRetired implements AuthorityStore.
func (d *DirectoryAuthorities) DropRetired(serial string) error {
	err := os.Remove(filepath.Join(d.dir, retiredDir, serial+".pem"))
	if err != nil && !os.IsNotExist(err) {
		return err
	}
	return nil
}

// repairActivation implements repairer: an activation that wrote the new key
// and died before the new certificate leaves a key that matches the prepared
// certificate and nothing else, which is enough to finish the handover.
func (d *DirectoryAuthorities) repairActivation() (*CA, bool, error) {
	keyPEM, err := os.ReadFile(filepath.Join(d.dir, caKeyFile))
	if err != nil {
		return nil, false, nil
	}
	pendingPEM, err := os.ReadFile(filepath.Join(d.dir, pendingCertFile))
	if err != nil {
		return nil, false, nil
	}
	candidate, err := parseCA(pendingPEM, keyPEM)
	if err != nil || candidate.VerifyPair() != nil {
		return nil, false, nil
	}
	if err := writeFileAtomic(filepath.Join(d.dir, caCertFile), pendingPEM, 0o644); err != nil {
		return nil, false, err
	}
	if err := d.DropPrepared(); err != nil {
		return nil, false, err
	}
	active, err := OpenFrom(d)
	if err != nil {
		return nil, false, err
	}
	return active, true, nil
}
