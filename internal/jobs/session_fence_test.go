package jobs

import (
	"errors"
	"strings"
	"testing"
)

// A delivery over a session the host has left is refused with a typed reason
// the scheduler recognises, carrying the code the error guide documents.
func TestAStaleSessionRefusalIsTyped(t *testing.T) {
	wrapped := errors.Join(ErrSessionStale, errors.New("recording the delivery"))
	if !errors.Is(wrapped, ErrSessionStale) {
		t.Fatal("the stale-session error does not survive wrapping")
	}
	if !strings.HasPrefix(ErrSessionStale.Error(), "session_stale") {
		t.Fatalf("the stale-session error does not carry its code: %q", ErrSessionStale)
	}
}

// A closed session row and a superseded owner are two refusals with two codes:
// the first sends the task back for the host's current session, the second
// says the instance that wrote no longer owns the host.
func TestAStaleSessionAndAStaleFenceAreDifferentRefusals(t *testing.T) {
	if errors.Is(ErrSessionStale, ErrStaleFence) || errors.Is(ErrStaleFence, ErrSessionStale) {
		t.Fatal("the two refusals read as one")
	}
	if strings.HasPrefix(ErrStaleFence.Error(), "session_stale:") {
		t.Fatalf("the stale-fence error carries the stale-session code: %q", ErrStaleFence)
	}
}
