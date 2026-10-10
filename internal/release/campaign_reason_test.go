package release

import (
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

// A campaign that fails has no pause reason: that field is written when
// something pauses it. A failure message printing the state and that field
// together therefore reads "the campaign ended in state failed ()" - the
// empty parenthesis the gate on 9bfd2bc answered with, which named the state
// and said nothing about the cause, sending the reader to the logs of four
// machines. The targets carry the cause, and whyItEnded reads them.
//
// This is a ratchet rather than a note, because the pattern is the obvious
// thing to write and came back once already.
var stateWithPauseReason = regexp.MustCompile(`(\w+)\.State,\s*(\w+)\.PauseReason\)`)

func TestNoCampaignFailureBlamesTheEmptyPauseReason(t *testing.T) {
	root := filepath.Join("..", "..", "tests", "integration")
	entries, err := os.ReadDir(root)
	if err != nil {
		t.Fatalf("reading the suite: %v", err)
	}

	var problems []string
	read := 0
	for _, entry := range entries {
		if entry.IsDir() || !strings.HasSuffix(entry.Name(), "_test.go") {
			continue
		}
		content, err := os.ReadFile(filepath.Join(root, entry.Name()))
		if err != nil {
			t.Fatalf("reading %s: %v", entry.Name(), err)
		}
		read++
		for _, match := range stateWithPauseReason.FindAllSubmatchIndex(content, -1) {
			line := strings.Count(string(content[:match[0]]), "\n") + 1
			held := string(content[match[2]:match[3]])
			problems = append(problems, fmt.Sprintf(
				"%s:%d prints %s.State next to %s.PauseReason; a failed campaign has no pause "+
					"reason, so that message says \"(%s)\" with nothing in it. "+
					"Say why with h.whyItEnded(%s), which reads the targets.",
				entry.Name(), line, held, string(content[match[4]:match[5]]), "", held))
		}
	}
	if read == 0 {
		t.Fatal("no file of the suite was read, so this guard is looking in the wrong place")
	}
	for _, problem := range problems {
		t.Error(problem)
	}
	t.Logf("%d files of the suite read", read)
}

// And the guard has to be able to see the pattern it is named after.
func TestTheGuardSeesAStateNextToAPauseReason(t *testing.T) {
	seen := stateWithPauseReason.FindStringSubmatch(
		`t.Fatalf("the campaign ended in state %s (%s)", final.State, final.PauseReason)`)
	if len(seen) != 3 || seen[1] != "final" || seen[2] != "final" {
		t.Fatalf("the pattern did not match the message it is named after: %v", seen)
	}
	// The assertions that are genuinely about a pause are not it: they print
	// the reason on its own, with no state beside it.
	if stateWithPauseReason.MatchString(
		`t.Errorf("pause reason = %q, expected maintenance_window_closed_mid_reboot", paused.PauseReason)`) {
		t.Error("an assertion about the pause reason itself was taken for a failure message")
	}
}
