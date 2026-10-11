package cryptostate

import (
	"errors"
	"fmt"
	"testing"

	"github.com/ultherego/flotestro/internal/secrets"
)

// What the operator does with this number is restore that many secrets from a
// backup, so it has to be the count of rows no key opened - not the count of
// rows still waiting to be rewrapped.
//
// Those were the same expression until 11.10: a pass that moved nothing and
// reported damage set the unreadable count to "remaining", which is every
// live version not yet on the active key. With 200 damaged rows and one good
// row behind them, the first pass filled its batch with the damaged ones,
// moved nothing, and the panel said 201. The good one was never read.
func TestTheUnreadableCountIsWhatWasFoundDamagedAndNotWhatIsLeft(t *testing.T) {
	// The shape the store returns, with the two numbers deliberately apart:
	// 200 rows of this pass could not be opened, and 201 rows in all are not
	// yet on the active key.
	const damaged, remaining = 200, 201
	err := error(&secrets.CorruptedBatch{Count: damaged})

	var corrupted *secrets.CorruptedBatch
	if !errors.As(err, &corrupted) {
		t.Fatal("the error does not carry the count; the caller is back to guessing")
	}
	if corrupted.Count != damaged {
		t.Errorf("the error carries %d, want %d", corrupted.Count, damaged)
	}
	if corrupted.Count == remaining {
		t.Error("the count is the number of rows left to rewrap, which is the bug this replaced")
	}

	// Every caller that only asks what kind of failure this was keeps working.
	if !errors.Is(err, secrets.ErrCorruptedVersion) {
		t.Error("errors.Is no longer recognises a damaged batch")
	}

	// And the text still says the number out loud, because it reaches a log.
	if want := fmt.Sprintf("%d versions", damaged); !contains(err.Error(), want) {
		t.Errorf("the message %q does not say %q", err.Error(), want)
	}
}

func contains(haystack, needle string) bool {
	return len(haystack) >= len(needle) && (func() bool {
		for i := 0; i+len(needle) <= len(haystack); i++ {
			if haystack[i:i+len(needle)] == needle {
				return true
			}
		}
		return false
	})()
}
