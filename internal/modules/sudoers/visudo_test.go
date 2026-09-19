package sudoers

import (
	"strings"
	"testing"
	"testing/fstest"
	"time"
)

// What sudo 1.9 prints when it refuses a file: the diagnostic names the file
// and the line, and around it the policy line itself is quoted back.
const visudoRefusal = `/etc/sudoers.d/ops:3:10: unknown defaults entry "authenticat"
Defaults:ops !authenticat
         ^~~~~~~~~~~~~~~~^
ubuntu ALL=(ALL) NOPASSWD: /usr/bin/deploy --site warsaw
visudo: /etc/sudoers.d/ops: parse error
`

// The checker's message is a fact the panel shows; the policy lines it quotes
// name accounts, hosts and commands, and those stay on the host.
func TestTheCheckerMessageKeepsTheDiagnosticsAndDropsTheQuotedPolicy(t *testing.T) {
	kept := sanitizeCheckerOutput(visudoRefusal)
	for _, want := range []string{`unknown defaults entry "authenticat"`, "/etc/sudoers.d/ops: parse error"} {
		if !strings.Contains(kept, want) {
			t.Errorf("the diagnostic %q was dropped from %q", want, kept)
		}
	}
	for _, unwanted := range []string{"ubuntu", "deploy", "warsaw", "^~"} {
		if strings.Contains(kept, unwanted) {
			t.Errorf("the quoted policy leaked %q into %q", unwanted, kept)
		}
	}

	if accepted := sanitizeCheckerOutput("/etc/sudoers: parsed OK\n/etc/sudoers.d/ops: parsed OK\n"); accepted !=
		"/etc/sudoers: parsed OK\n/etc/sudoers.d/ops: parsed OK" {
		t.Errorf("an accepted file: %q", accepted)
	}

	// A host with hundreds of drop-ins must not push its whole policy into
	// the inventory, and one endless line must not either.
	many := strings.Repeat("/etc/sudoers.d/x: parsed OK\n", 40)
	if lines := strings.Count(sanitizeCheckerOutput(many), "\n") + 1; lines != maxCheckerLines {
		t.Errorf("the message kept %d lines, expected %d", lines, maxCheckerLines)
	}
	long := sanitizeCheckerOutput("/etc/sudoers: syntax error " + strings.Repeat("x", 500))
	if runes := []rune(long); len(runes) != maxCheckerLength+1 {
		t.Errorf("a long line kept %d runes", len(runes))
	}
}

// The three answers of the checker, as the panel has to tell them apart: it
// took the files, it refused them, or it never said.
func TestTheCheckerResultSaysWhetherAnythingWasProved(t *testing.T) {
	for _, tc := range []struct {
		name            string
		check           *SyntaxCheck
		accepted, known bool
		refused         bool
	}{
		{name: "nothing reported", check: nil},
		{name: "no checker on the host", check: &SyntaxCheck{Reason: "visudo was not found on this host"}},
		{name: "checker did not run", check: &SyntaxCheck{Available: true, Reason: "visudo did not finish within 15s"}},
		{name: "files taken", check: &SyntaxCheck{Available: true, Ran: true}, accepted: true, known: true},
		{name: "files refused", check: &SyntaxCheck{Available: true, Ran: true, ExitCode: 1}, known: true, refused: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			accepted, known := tc.check.Accepted()
			if accepted != tc.accepted || known != tc.known {
				t.Errorf("accepted=%v known=%v, expected %v and %v", accepted, known, tc.accepted, tc.known)
			}
			if refused := tc.check.Refused(); refused != tc.refused {
				t.Errorf("refused=%v, expected %v", refused, tc.refused)
			}
		})
	}
}

// The snapshot the host sends carries the checker's answer next to the parsed
// rules: two answers to two different questions, both facts.
func TestTheSystemSnapshotCarriesTheCheckerResult(t *testing.T) {
	original := runSyntaxCheck
	t.Cleanup(func() { runSyntaxCheck = original })
	now := time.Date(2026, 9, 19, 10, 0, 0, 0, time.UTC)
	runSyntaxCheck = func(at time.Time) *SyntaxCheck {
		return &SyntaxCheck{
			Tool: "/usr/sbin/visudo", Available: true, Ran: true, ExitCode: 1,
			Output: "/etc/sudoers: syntax error near line 24", CheckedAt: at.UTC(),
		}
	}

	snapshot := ParseSystem(fstest.MapFS{
		"etc/sudoers": &fstest.MapFile{Data: []byte("Defaults\tenv_reset\n%sudo\tALL=(ALL:ALL) ALL\n")},
	}, now)
	if len(snapshot.Rules) != 1 || len(snapshot.Problems) != 0 {
		t.Fatalf("the parse itself changed: %d rules, %d problems", len(snapshot.Rules), len(snapshot.Problems))
	}
	if snapshot.SyntaxCheck == nil || !snapshot.SyntaxCheck.Refused() {
		t.Fatalf("the checker's answer did not reach the snapshot: %+v", snapshot.SyntaxCheck)
	}
	if !snapshot.SyntaxCheck.CheckedAt.Equal(now) {
		t.Errorf("checked at %s, expected %s", snapshot.SyntaxCheck.CheckedAt, now)
	}
}
