package identity

import (
	"sync"
	"time"
)

// A one-time value of a change - the password the directory generated on a
// reset - is handed to the requester once and to nobody else.

// secretLifetime is how long a one-time value waits for its requester.
const secretLifetime = 15 * time.Minute

// secretState is what a read of the vault found.
type secretState int

const (
	secretAbsent secretState = iota
	secretWaiting
	secretConsumed
)

type oneTimeSecret struct {
	value     string
	requester string
	expiresAt time.Time
	consumed  bool
}

// secretVault keeps the waiting values by change identifier.
type secretVault struct {
	mu      sync.Mutex
	secrets map[string]oneTimeSecret
}

func newSecretVault() *secretVault {
	return &secretVault{secrets: map[string]oneTimeSecret{}}
}

// keep stores a value for the requester of the change.
func (v *secretVault) keep(changeID, requester, value string) {
	v.mu.Lock()
	defer v.mu.Unlock()
	v.sweep()
	v.secrets[changeID] = oneTimeSecret{
		value: value, requester: requester, expiresAt: time.Now().Add(secretLifetime),
	}
}

// take hands the value out once.
func (v *secretVault) take(changeID, requester string) (string, secretState) {
	v.mu.Lock()
	defer v.mu.Unlock()
	v.sweep()
	secret, ok := v.secrets[changeID]
	if !ok {
		return "", secretAbsent
	}
	if secret.requester != requester {
		return "", secretAbsent
	}
	if secret.consumed {
		return "", secretConsumed
	}
	// The value leaves the map with the read; the record that it was read stays
	// until the deadline, so a second read is told "consumed" rather than "never
	// existed".
	v.secrets[changeID] = oneTimeSecret{requester: requester, expiresAt: secret.expiresAt, consumed: true}
	return secret.value, secretWaiting
}

// waiting says whether a value waits for this requester.
func (v *secretVault) waiting(changeID, requester string) bool {
	v.mu.Lock()
	defer v.mu.Unlock()
	v.sweep()
	secret, ok := v.secrets[changeID]
	return ok && secret.requester == requester && !secret.consumed
}

// sweep drops the values past their deadline. It runs under the lock.
func (v *secretVault) sweep() {
	now := time.Now()
	for id, secret := range v.secrets {
		if now.After(secret.expiresAt) {
			delete(v.secrets, id)
		}
	}
}

// KeepSecret stores the one-time value of a change for its requester. It
// lives in this process only; see the note at the top of the file.
func (s *Store) KeepSecret(changeID, requester, value string) {
	s.vault().keep(changeID, requester, value)
}

// vault returns the store's vault; a store built without the constructor
// gets one on first use rather than a nil dereference.
func (s *Store) vault() *secretVault {
	if s.secrets == nil {
		s.secrets = newSecretVault()
	}
	return s.secrets
}

// TakeSecret hands the one-time value of a change to its requester once.
func (s *Store) TakeSecret(changeID, requester string) (value string, handedOut, consumed bool) {
	value, state := s.vault().take(changeID, requester)
	return value, state == secretWaiting, state == secretConsumed
}

// SecretWaiting says whether a one-time value of the change waits for
// this requester.
func (s *Store) SecretWaiting(changeID, requester string) bool {
	return s.vault().waiting(changeID, requester)
}
