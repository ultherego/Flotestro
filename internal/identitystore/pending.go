package identitystore

import (
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"time"

	"github.com/google/uuid"
)

// PendingName is the record of an enrollment attempt that has not ended yet.
//
// It lies in the identity directory next to the generations rather than
// among them: it is not an identity, only the material of an attempt whose
// answer the host is still waiting for.
const PendingName = "pending.json"

// PendingMaxAge is how long an attempt stays worth repeating.
//
// A token lives at most a day, so an attempt older than that has no token
// to be repeated with. Past that age the record is abandoned and the next
// enrollment starts with a fresh key.
const PendingMaxAge = 24 * time.Hour

// The errors of the pending record.
var (
	ErrPendingMissing = errors.New("pending_missing")
	ErrPendingInvalid = errors.New("pending_invalid")
)

// Pending is an enrollment attempt persisted before its first network
// request.
//
// The point of the record is a retry after a lost answer: the panel keeps
// the attempt under its identifier and the digest of the CSR, and gives the
// same certificate back only to the same pair. A retry that generated a new
// key would ask under the old number with a new CSR - and be refused as a
// reuse of the request.
//
// The token is deliberately absent. It lives in the memory of the process
// or in a systemd credential, and the record on disk would keep it far
// longer than its use.
type Pending struct {
	ClientRequestID string `json:"client_request_id"`
	// KeyPEM is the private key of the attempt. The file is readable by its
	// owner alone, and the material goes to no log and no audit.
	KeyPEM []byte `json:"key_pem"`
	CSRPEM []byte `json:"csr_pem"`
	// TokenPrefix is the non-secret opening of the token the attempt was
	// started with, when the token had a recognisable one. It lets the
	// operator match the attempt to an order in the panel; a few characters
	// tell nothing about the secret itself.
	TokenPrefix string    `json:"token_prefix,omitempty"`
	CreatedAt   time.Time `json:"created_at"`
}

// Key returns the private key of the attempt.
func (p Pending) Key() (Key, error) { return KeyFromPEM(p.KeyPEM) }

// Age says how long ago the attempt was started.
func (p Pending) Age(now time.Time) time.Duration { return now.Sub(p.CreatedAt) }

// Stale says whether the attempt is too old to be repeated.
func (p Pending) Stale(now time.Time) bool { return p.Age(now) > PendingMaxAge }

// check verifies that the record is complete enough to be repeated.
func (p Pending) check() error {
	if _, err := uuid.Parse(p.ClientRequestID); err != nil {
		return fmt.Errorf("%w: the attempt identifier: %v", ErrPendingInvalid, err)
	}
	if _, err := p.Key(); err != nil {
		return fmt.Errorf("%w: %v", ErrPendingInvalid, err)
	}
	if block, _ := pem.Decode(p.CSRPEM); block == nil || block.Type != "CERTIFICATE REQUEST" {
		return fmt.Errorf("%w: the request is not a PEM certificate request", ErrPendingInvalid)
	}
	if p.CreatedAt.IsZero() {
		return fmt.Errorf("%w: the attempt has no start time", ErrPendingInvalid)
	}
	return nil
}

// PendingPath returns the path of the record.
func (m *Store) PendingPath() string { return filepath.Join(m.root, PendingName) }

// PreparePending creates the key and the request of a new attempt and
// records them before anything goes to the network.
//
// The order is the whole point: the record has to be durable before the
// first request, because the answer to that request may be the one that is
// lost. The identifier comes from the given source of randomness and the
// time from the given clock, so that a test can repeat an attempt to the
// byte.
func (m *Store) PreparePending(random io.Reader, now time.Time, name string,
	dns []string, addresses []net.IP, tokenPrefix string) (*Pending, error) {
	key, err := m.source.New()
	if err != nil {
		return nil, err
	}
	keyPEM, err := exportKey(key)
	if err != nil {
		return nil, err
	}
	csrPEM, err := Request(key, name, dns, addresses)
	if err != nil {
		return nil, err
	}
	id, err := uuid.NewRandomFromReader(random)
	if err != nil {
		return nil, fmt.Errorf("the attempt identifier: %w", err)
	}
	pending := &Pending{
		ClientRequestID: id.String(),
		KeyPEM:          keyPEM,
		CSRPEM:          csrPEM,
		TokenPrefix:     tokenPrefix,
		CreatedAt:       now.UTC(),
	}
	if err := m.SavePending(*pending); err != nil {
		return nil, err
	}
	return pending, nil
}

// SavePending writes the record so that it is either whole or absent.
//
// A temporary file, a sync and a rename: a crash halfway through the write
// must not leave a record that parses as an attempt with half a key.
func (m *Store) SavePending(p Pending) error {
	if err := p.check(); err != nil {
		return err
	}
	if err := os.MkdirAll(m.root, 0o700); err != nil {
		return err
	}
	content, err := json.MarshalIndent(p, "", "  ")
	if err != nil {
		return err
	}
	path := m.PendingPath()
	temporary := path + ".tmp"
	// The record carries the private key, so the file is readable by its
	// owner alone - from the first byte, not after a chmod.
	if err := writeWithSync(temporary, append(content, '\n'), 0o600); err != nil {
		_ = os.Remove(temporary)
		return err
	}
	if err := os.Rename(temporary, path); err != nil {
		_ = os.Remove(temporary)
		return err
	}
	return syncDir(m.root)
}

// LoadPending reads the record of an unfinished attempt.
//
// A record that cannot be repeated is reported as invalid rather than
// missing: the caller then decides whether to discard it, and the operator
// can see it in the status meanwhile.
func (m *Store) LoadPending() (*Pending, error) {
	content, err := os.ReadFile(m.PendingPath())
	if err != nil {
		if os.IsNotExist(err) {
			return nil, ErrPendingMissing
		}
		return nil, fmt.Errorf("%w: %v", ErrPendingInvalid, err)
	}
	var pending Pending
	if err := json.Unmarshal(content, &pending); err != nil {
		return nil, fmt.Errorf("%w: %v", ErrPendingInvalid, err)
	}
	if err := pending.check(); err != nil {
		return nil, err
	}
	return &pending, nil
}

// RemovePending abandons the attempt. A record that is not there is not an
// error: the attempt is over either way.
func (m *Store) RemovePending() error {
	err := os.Remove(m.PendingPath())
	if err != nil && !os.IsNotExist(err) {
		return err
	}
	_ = os.Remove(m.PendingPath() + ".tmp")
	return nil
}

// exportKey gives out the material of a key that lives in software.
//
// A hardware key has no material to give: its attempt would need a handle
// rather than PEM, and that profile does not exist yet. Refusing here is
// better than recording an attempt that cannot be repeated.
func exportKey(key Key) ([]byte, error) {
	software, ok := key.(*softwareKey)
	if !ok {
		return nil, fmt.Errorf("%w: a pending attempt needs a key that can be written as PEM", ErrKeyNotExportable)
	}
	return software.materialPEM()
}
