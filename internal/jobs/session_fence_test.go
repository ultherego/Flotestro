package jobs

import (
	"errors"
	"strings"
	"testing"
)

// A delivery over a session the host has left is refused with a typed
// reason the scheduler recognises, and the reason carries the code the
// error guide documents, so a released attempt reads the same on the
// screen as on the trail.
func TestAStaleSessionRefusalIsTyped(t *testing.T) {
	wrapped := errors.Join(ErrSessionStale, errors.New("recording the delivery"))
	if !errors.Is(wrapped, ErrSessionStale) {
		t.Fatal("the stale-session error does not survive wrapping")
	}
	if !strings.HasPrefix(ErrSessionStale.Error(), "session_stale") {
		t.Fatalf("the stale-session error does not carry its code: %q", ErrSessionStale)
	}
}
