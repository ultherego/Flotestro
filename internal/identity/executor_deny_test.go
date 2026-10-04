package identity

import (
	"errors"
	"strings"
	"testing"
)

// Preserving an account the panel knows nobody by ended the whole change as
// partially_applied, over a step that had nothing to do: the lock path made
// the distinction and the preserve path did not. One function makes it now, and
// this holds both ends of it.
func TestAnAccountWithNoPanelIdentityIsNotAFailedDenial(t *testing.T) {
	phase := deniedLocally(startPhase("the local denial marker"), 0,
		errors.New("the panel holds no identity under that name: "+ErrNoPrincipal.Error()),
		"identities marked", "nothing to deny locally")
	// A plain error of that text is still a failure: the distinction is made on
	// the sentinel, not on the words.
	if phase.Status != "failed" {
		t.Fatalf("an unrecognised error became %q", phase.Status)
	}

	phase = deniedLocally(startPhase("the local denial marker"), 0, ErrNoPrincipal,
		"identities marked", "nothing to deny locally")
	if phase.Status != "skipped" {
		t.Fatalf("an account with no panel identity became %q", phase.Status)
	}
	if !strings.Contains(phase.Message, "nothing to deny locally") {
		t.Errorf("the phase does not say what it skipped: %q", phase.Message)
	}

	phase = deniedLocally(startPhase("the local denial marker"), 2, nil,
		"identities marked", "nothing to deny locally")
	if phase.Status != "succeeded" || !strings.Contains(phase.Message, "2") {
		t.Fatalf("a denial that marked two identities became %q (%s)", phase.Status, phase.Message)
	}
}
