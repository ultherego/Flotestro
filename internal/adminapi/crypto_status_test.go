package adminapi

import (
	"strings"
	"testing"

	"github.com/ultherego/flotestro/internal/cryptostate"
	"github.com/ultherego/flotestro/internal/secrets"
)

// The crypto block had one sentence for two states: versions the rewrap has
// not reached yet, and versions no key of the installation opens. The first
// clears itself at the next tick and the second never does, and an operator
// reading "the rewrap runs in the background" about the second was told to
// wait for something that had already finished failing.
func TestWhatTheCryptoBlockSaysAboutWorkLeftOver(t *testing.T) {
	waiting := cryptostate.Report{
		ActiveKeyID:   "legacy",
		Keys:          []string{"legacy"},
		VersionsByKey: map[string]int{"legacy": 3, secrets.LegacyFormLabel: 1},
		PendingRewrap: 1,
	}
	line := cryptoAttention(waiting)
	if !strings.Contains(line, "the rewrap runs in the background") {
		t.Fatalf("a backlog the rewrap will clear is not described as one: %q", line)
	}

	// The same backlog, after a pass that could not move it. One step across
	// the line and the sentence has to change, because the repair does.
	stuck := waiting
	stuck.UnreadableVersions = 1
	line = cryptoAttention(stuck)
	if strings.Contains(line, "the rewrap runs in the background") {
		t.Fatalf("a version no key opens is described as work in progress: %q", line)
	}
	for _, part := range []string{"cannot be opened by any key", "crypto verify-secrets", "restore them from a backup"} {
		if !strings.Contains(line, part) {
			t.Fatalf("the line does not say %q: %q", part, line)
		}
	}

	// And an installation with nothing owed says nothing about the rewrap, but
	// still offers the key a finished rotation left behind.
	done := cryptostate.Report{
		ActiveKeyID:   "k-new",
		Keys:          []string{"k-new", "legacy"},
		VersionsByKey: map[string]int{"k-new": 4},
	}
	line = cryptoAttention(done)
	if !strings.Contains(line, "legacy") || strings.Contains(line, "rewrap") {
		t.Fatalf("a finished rotation is not described as one: %q", line)
	}
	if cryptoAttention(cryptostate.Report{ActiveKeyID: "k-new", Keys: []string{"k-new"},
		VersionsByKey: map[string]int{"k-new": 4}}) != "" {
		t.Fatal("an installation with nothing to say about is given something to say")
	}
}
