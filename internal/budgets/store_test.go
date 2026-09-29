package budgets

import (
	"errors"
	"testing"
)

// The two losses a renewal can report are told apart by their errors: a
// takeover is a loss as well, so a caller that only knows ErrLeaseLost still
// sees it, and one that has to stop can ask for the takeover alone.
func TestATakeoverIsALostLeaseThatCanStillBeToldApart(t *testing.T) {
	if !errors.Is(ErrFenceStale, ErrLeaseLost) {
		t.Error("a lease held under another token is a lease this caller lost")
	}
	if errors.Is(ErrLeaseLost, ErrFenceStale) {
		t.Error("a grant that merely ran out must not read as a takeover")
	}
}
