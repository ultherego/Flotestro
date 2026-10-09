package main

import (
	"strings"
	"testing"
	"time"

	"github.com/ultherego/flotestro/internal/identitystore"
)

// enroll asked for the identity to be ensured, which keeps the one already
// there, and then said "the relay was registered" with that identity's own
// expiry - as if it had just been issued.
//
// A relay pointed at a rebuilt installation is the case. On 09.10 the gate
// raised one: the token was new, the registration reported success, and the
// relay went on holding a certificate from 05.10 and a trust bundle from
// 01.10, of an installation that no longer existed. What it said afterwards
// was "tls: failed to verify certificate", which sends a reader to the
// panel's certificate rather than to the relay's own identity, and the stage
// failed with "no session reaches the panel through the relay".
func TestEnrollRefusesWhenTheRelayAlreadyHoldsAnIdentity(t *testing.T) {
	held := &identitystore.Identity{
		HostID:   "8eeb7962-be6d-4990-8ad8-e5a819c81b54",
		NotAfter: time.Date(2026, 10, 12, 18, 48, 13, 0, time.UTC),
		Dir:      "/var/lib/flotestro-relay/identity/generations/a5f9f224",
	}
	refusal := refuseHeldIdentity(held, false)
	if refusal == nil {
		t.Fatal("a relay that already holds an identity was registered again, which keeps the old one")
	}
	for _, want := range []string{
		"relay_already_enrolled", // the name a reader can search for
		"8eeb7962",               // which identity it found
		"2026-10-12T18:48:13Z",   // and until when it is valid
		"Nothing was registered", // so the message cannot be read as success
		"-replace",               // and what to do about it
		"a5f9f224",               // where the superseded identity sits
	} {
		if !strings.Contains(refusal.Error(), want) {
			t.Errorf("the refusal does not say %q: %v", want, refusal)
		}
	}
}

// A first registration is the ordinary case and must not be refused.
func TestEnrollProceedsWithNoIdentityHeld(t *testing.T) {
	if refusal := refuseHeldIdentity(nil, false); refusal != nil {
		t.Errorf("a relay with no identity was refused its first registration: %v", refusal)
	}
}

// And an operator who says what they mean is let through.
func TestReplaceRegistersOverTheHeldIdentity(t *testing.T) {
	held := &identitystore.Identity{HostID: "a-relay", NotAfter: time.Now().Add(time.Hour)}
	if refusal := refuseHeldIdentity(held, true); refusal != nil {
		t.Errorf("-replace was refused: %v", refusal)
	}
}

// A state directory with nothing in it is a first registration, not an error:
// the registration that follows writes what belongs there.
func TestAnEmptyStateDirectoryIsNotAnError(t *testing.T) {
	held, err := heldIdentity(t.TempDir())
	if err != nil {
		t.Fatalf("an empty state directory was reported as an error: %v", err)
	}
	if held != nil {
		t.Errorf("an empty state directory held an identity: %+v", held)
	}
}

// And a configuration that names no state directory is one, because there is
// nowhere to write the identity to.
func TestNoStateDirectoryIsAnError(t *testing.T) {
	if _, err := heldIdentity(""); err == nil {
		t.Error("a relay with no state directory was allowed to register")
	}
}
