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

// Cipher protects the values of secrets with a key from outside the database.
//
// The key lies in a file rather than in the database: a copy of the database
// without that file is not enough to read anything. That is the whole
// difference between a secret store and a column of passwords.
type Cipher struct {
	aead cipher.AEAD
}

// OpenCipher reads the key from a file and creates a new one when it is
// missing.
//
// We create the key ourselves, because a panel without a secret store cannot
// perform some operations, and refusing to start would be worse than that. In
// return we say outright that without a copy of this file the secrets cannot
// be recovered.
func OpenCipher(path string) (*Cipher, bool, error) {
	key, err := os.ReadFile(path)
	created := false
	switch {
	case err == nil:
		if len(key) != KeyLength {
			return nil, false, fmt.Errorf("the secret store key has %d bytes instead of %d",
				len(key), KeyLength)
		}
	case errors.Is(err, os.ErrNotExist):
		key = make([]byte, KeyLength)
		if _, err := io.ReadFull(rand.Reader, key); err != nil {
			return nil, false, err
		}
		if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
			return nil, false, err
		}
		if err := os.WriteFile(path, key, 0o600); err != nil {
			return nil, false, err
		}
		created = true
	default:
		return nil, false, err
	}

	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, false, err
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return nil, false, err
	}
	return &Cipher{aead: aead}, created, nil
}

// Encrypt returns the nonce and the ciphertext.
func (s *Cipher) Encrypt(value []byte) (nonce, ciphertext []byte, err error) {
	nonce = make([]byte, s.aead.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, nil, err
	}
	return nonce, s.aead.Seal(nil, nonce, value, nil), nil
}

// Decrypt returns the value of the secret.
func (s *Cipher) Decrypt(nonce, ciphertext []byte) ([]byte, error) {
	return s.aead.Open(nil, nonce, ciphertext, nil)
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
