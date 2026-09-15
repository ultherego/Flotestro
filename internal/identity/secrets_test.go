package identity

import (
	"testing"
	"time"
)

func TestAOneTimeSecretIsHandedToTheRequesterOnce(t *testing.T) {
	vault := newSecretVault()
	vault.keep("change-1", "alice", "Zx9-temporary")

	if !vault.waiting("change-1", "alice") {
		t.Fatal("the value does not wait for its requester")
	}
	// Somebody else gets the same answer as for a value that never
	// existed: the endpoint tells nobody but the requester whether a
	// value is there.
	if vault.waiting("change-1", "bob") {
		t.Fatal("the value waits for a different person")
	}
	if value, state := vault.take("change-1", "bob"); value != "" || state != secretAbsent {
		t.Fatalf("a different person read %q with state %v", value, state)
	}

	value, state := vault.take("change-1", "alice")
	if value != "Zx9-temporary" || state != secretWaiting {
		t.Fatalf("the requester read %q with state %v", value, state)
	}
	// The second read finds the value gone, and is told it was consumed
	// rather than that it never existed.
	if value, state := vault.take("change-1", "alice"); value != "" || state != secretConsumed {
		t.Fatalf("the second read gave %q with state %v", value, state)
	}
	if vault.waiting("change-1", "alice") {
		t.Fatal("a consumed value still waits")
	}
	if _, state := vault.take("change-2", "alice"); state != secretAbsent {
		t.Fatalf("a change without a value gave state %v", state)
	}
}

func TestAOneTimeSecretGoesAwayWithTheDeadline(t *testing.T) {
	vault := newSecretVault()
	vault.keep("change-1", "alice", "Zx9-temporary")
	vault.mu.Lock()
	secret := vault.secrets["change-1"]
	secret.expiresAt = time.Now().Add(-time.Second)
	vault.secrets["change-1"] = secret
	vault.mu.Unlock()
	if _, state := vault.take("change-1", "alice"); state != secretAbsent {
		t.Fatalf("a value past its deadline was still there: state %v", state)
	}
}
