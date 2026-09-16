// Package secrets stores the values that must not travel through tasks.
//
// The rule is single and hard: the value of a secret appears neither in a
// task, nor in the audit trail, nor in the inventory. The task carries a
// reference - a name and a version - and the host reaches for the content
// only when it starts the operation, on the strength of a short lease issued
// for that one task. The panel records the fact of issuance, never the issued
// value.
package secrets

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"time"
)

// The boundaries of a secret. A private key fits in a few kilobytes; a value
// larger than that is not a secret but a file.
const (
	MaxValue  = 64 << 10
	KeyLength = 32
)

// LeaseWindow bounds the time between issuing a lease and fetching the value.
//
// The lease is short on purpose: it comes into being when the task is
// delivered to the host and is to last for its execution, not for anything
// after it.
const LeaseWindow = 5 * time.Minute

var (
	// ErrNotFound means a secret or a version that does not exist.
	ErrNotFound = errors.New("there is no such secret")
	// ErrRetired means a retired secret: it exists in the history, but it can
	// no longer be issued.
	ErrRetired = errors.New("the secret has been retired")
	// ErrNoLease means a fetch without a valid lease - or with a lease
	// already used. Both are a refusal rather than a technical error.
	ErrNoLease = errors.New("no valid lease for this secret")
	// ErrDestroyed means a version whose content has been destroyed.
	ErrDestroyed = errors.New("the content of this version has been destroyed")
)

var secretName = regexp.MustCompile(`^[a-z0-9][a-z0-9._-]{1,62}$`)

// ValidateName checks the name of a secret.
//
// The name reaches tasks, the audit trail and the interface, so it has to be
// short, unambiguous and free of characters that obscure anything.
func ValidateName(name string) error {
	if !secretName.MatchString(name) {
		return fmt.Errorf("secret name %q: lowercase letters, digits, a dot, a dash and an underscore are allowed (2-63 characters)", name)
	}
	return nil
}

// ValidateValue checks the content of a secret.
func ValidateValue(value []byte) error {
	if len(value) == 0 {
		return errors.New("a secret without a value is not a secret")
	}
	if len(value) > MaxValue {
		return fmt.Errorf("the value is larger than %d bytes", MaxValue)
	}
	return nil
}

// Secret is the metadata of a secret. The structure has no field for the
// value and must not have one: it is what travels to the interface and to the
// API.
type Secret struct {
	ID             string     `json:"id"`
	Name           string     `json:"name"`
	Description    string     `json:"description,omitempty"`
	CurrentVersion int        `json:"current_version"`
	CreatedBy      string     `json:"created_by"`
	CreatedAt      time.Time  `json:"created_at"`
	UpdatedAt      time.Time  `json:"updated_at"`
	RetiredAt      *time.Time `json:"retired_at,omitempty"`
	Versions       []Version  `json:"versions,omitempty"`
}

// Issuable says whether a value can still be issued from the secret.
func (s Secret) Issuable() bool { return s.RetiredAt == nil && s.CurrentVersion > 0 }

// Version describes one version of a secret - without its content.
type Version struct {
	Version   int        `json:"version"`
	SizeBytes int        `json:"size_bytes"`
	CreatedBy string     `json:"created_by"`
	CreatedAt time.Time  `json:"created_at"`
	Destroyed *time.Time `json:"destroyed_at,omitempty"`
	// EnvelopeVersion says how the value is sealed: 1 is the value under
	// the installation's key directly, 2 a data key of its own wrapped by
	// the key named in KeyID. The operator reads it during a key rotation:
	// a version still on the old key is one the rotation has not reached.
	EnvelopeVersion int    `json:"envelope_version"`
	KeyID           string `json:"key_id,omitempty"`
}

// Lease entitles one host to fetch one version of one secret within one
// task.
type Lease struct {
	ID         string     `json:"id"`
	SecretID   string     `json:"secret_id"`
	SecretName string     `json:"secret_name"`
	Version    int        `json:"version"`
	JobID      string     `json:"job_id"`
	HostID     string     `json:"host_id"`
	IssuedAt   time.Time  `json:"issued_at"`
	ExpiresAt  time.Time  `json:"expires_at"`
	RedeemedAt *time.Time `json:"redeemed_at,omitempty"`
	RevokedAt  *time.Time `json:"revoked_at,omitempty"`
}

// Valid says whether the lease entitles a fetch at the given moment.
func (d Lease) Valid(now time.Time) bool {
	return d.RedeemedAt == nil && d.RevokedAt == nil && now.Before(d.ExpiresAt)
}

// Cipher is the primitive of the store: AES-256-GCM under one key.
//
// It serves two things that must stay apart in the reader's mind. A version
// written before the envelope was introduced has its value sealed directly
// under the installation's key, and that is what Encrypt and Decrypt do; the
// local key provider wraps the per-version data keys with the same
// primitive. The key itself lies in a file rather than in the database: a
// copy of the database without that file is not enough to read anything.
// That is the whole difference between a secret store and a column of
// passwords.
type Cipher struct {
	aead cipher.AEAD
}

// ErrKeyMissing means the key file is not there. The store never creates
// one in its place on its own: a key that appears by itself next to an
// existing database is the beginning of two installations sharing one
// name, and the startup guard is the only place allowed to decide that
// nothing depends on the old one yet.
var ErrKeyMissing = errors.New("secrets_key_missing")

// NewCipher builds the primitive over raw key material.
func NewCipher(key []byte) (*Cipher, error) {
	if len(key) != KeyLength {
		return nil, fmt.Errorf("the secret store key has %d bytes instead of %d", len(key), KeyLength)
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	return &Cipher{aead: aead}, nil
}

// ReadKeyFile reads raw key material from a file. A missing file is
// ErrKeyMissing, so the caller can tell "not there" from "unreadable".
func ReadKeyFile(path string) ([]byte, error) {
	key, err := os.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) {
		return nil, fmt.Errorf("%w: %s", ErrKeyMissing, path)
	}
	if err != nil {
		return nil, err
	}
	if len(key) != KeyLength {
		return nil, fmt.Errorf("%s: the secret store key has %d bytes instead of %d", path, len(key), KeyLength)
	}
	return key, nil
}

// OpenCipher reads the key from a file. It creates nothing: a missing file
// is ErrKeyMissing and the decision what that means belongs to the caller.
func OpenCipher(path string) (*Cipher, error) {
	key, err := ReadKeyFile(path)
	if err != nil {
		return nil, err
	}
	return NewCipher(key)
}

// InitCipher creates a new key in a file that must not exist yet and
// returns the primitive over it.
//
// The explicit initialisation is the only way a key comes into being. The
// file is created exclusively and written through a temporary name, so
// two processes racing for the same path cannot both believe they own the
// key, and a crash halfway leaves no half-written file under the final
// name.
func InitCipher(path string) (*Cipher, error) {
	key := make([]byte, KeyLength)
	if _, err := io.ReadFull(rand.Reader, key); err != nil {
		return nil, err
	}
	if err := WriteKeyFile(path, key); err != nil {
		return nil, err
	}
	return NewCipher(key)
}

// WriteKeyFile persists key material so that the file is either complete
// or absent, and refuses to replace an existing key.
//
// Key material is written with the narrowest mode, synced to disk and
// renamed into place, and the directory is synced after the rename: a key
// that a power cut turns into an empty file is a store nobody can open.
func WriteKeyFile(path string, key []byte) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return err
	}
	if _, err := os.Lstat(path); err == nil {
		return fmt.Errorf("%s: a key already exists and is not replaced", path)
	}
	temporary := path + ".new"
	file, err := os.OpenFile(temporary, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o600)
	if err != nil {
		return err
	}
	if _, err := file.Write(key); err != nil {
		file.Close()
		_ = os.Remove(temporary)
		return err
	}
	if err := file.Sync(); err != nil {
		file.Close()
		_ = os.Remove(temporary)
		return err
	}
	if err := file.Close(); err != nil {
		_ = os.Remove(temporary)
		return err
	}
	// The final name must still be free: the exclusive create above
	// guarded the temporary name only.
	if err := os.Link(temporary, path); err != nil {
		_ = os.Remove(temporary)
		return err
	}
	_ = os.Remove(temporary)
	if dir, err := os.Open(filepath.Dir(path)); err == nil {
		_ = dir.Sync()
		_ = dir.Close()
	}
	return nil
}

// NonceSize is the length of the nonce Encrypt produces.
func (s *Cipher) NonceSize() int { return s.aead.NonceSize() }

// Encrypt returns the nonce and the ciphertext of one version of one
// secret sealed the first way: directly under this key. New versions go
// through Seal instead; this stays for the tests of the old rows and for
// the one place that still writes this way, the local provider's own
// wrapping of data keys.
//
// The identifier and the version go in as the associated data: the
// ciphertext then opens only in the row it was written for. Without that a
// ciphertext moved between rows of the database - the current version of
// a password swapped for an old one, or the value of one secret put under
// the name of another - would decrypt as if nothing had happened.
func (s *Cipher) Encrypt(value []byte, secretID string, version int) (nonce, ciphertext []byte, err error) {
	nonce = make([]byte, s.aead.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, nil, err
	}
	return nonce, s.aead.Seal(nil, nonce, value, associatedData(secretID, version)), nil
}

// Decrypt returns the value of a version sealed the first way.
//
// A version written before the associated data was introduced carries
// none, so a ciphertext that does not open with it is tried once more the
// old way. Such a version stays readable and is not rewritten in place:
// the next rotation writes the new version bound to its row, and the old
// one goes when it is destroyed. The order of the two attempts matters -
// the bound one first, so a moved ciphertext of the new kind never opens.
func (s *Cipher) Decrypt(nonce, ciphertext []byte, secretID string, version int) ([]byte, error) {
	value, err := s.aead.Open(nil, nonce, ciphertext, associatedData(secretID, version))
	if err == nil {
		return value, nil
	}
	return s.aead.Open(nil, nonce, ciphertext, nil)
}

// associatedData renders the row key the ciphertext is bound to.
func associatedData(secretID string, version int) []byte {
	return []byte(secretID + "|" + strconv.Itoa(version))
}

// Fingerprint computes the checksum of a value.
//
// The fingerprint serves the host to check that it got what the panel issued.
// It is recorded neither in the database nor in the audit trail: for a short
// value the fingerprint itself is sometimes a hint, and the store is not to
// leave hints.
func Fingerprint(value []byte) string {
	sum := sha256.Sum256(value)
	return hex.EncodeToString(sum[:])
}
