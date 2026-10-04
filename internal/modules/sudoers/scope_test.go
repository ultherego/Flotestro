package sudoers

import (
	"testing"
	"testing/fstest"
	"time"
)

// A scope is not decoration. Defaults:%wheel !authenticate turns the password
// off for that group and for nobody else, and the judgement used to ask only
// about the global scope - so a configuration giving a whole group passwordless
// root was reported as carrying no such rule, on the screen an operator reads
// to believe the opposite.
func TestADefaultScopedToAGroupIsSeen(t *testing.T) {
	files := fstest.MapFS{
		"etc/sudoers": &fstest.MapFile{Data: []byte(
			"Defaults:%wheel !authenticate\n" +
				"%wheel ALL=(ALL) ALL\n")},
	}
	snapshot := Parse(files, "/etc/sudoers", time.Now())
	rules, complete := snapshot.RootWithoutPassword()
	if !complete {
		t.Fatal("a policy of one file with a user-scoped default is answerable in full")
	}
	if len(rules) != 1 {
		t.Fatalf("rules = %d, want the one the scoped default covers", len(rules))
	}
}

// The other mistake would be treating any scope as global: a default about one
// command concerns that command, and one about another host concerns that host.
// Neither can be resolved from the files, so the answer is unknown - never a
// quiet no.
func TestADefaultScopedToSomethingTheFilesCannotResolveIsUnknown(t *testing.T) {
	for _, line := range []string{
		"Defaults!/usr/bin/id !authenticate",
		"Defaults@other-host !authenticate",
		"Defaults>operator !authenticate",
	} {
		files := fstest.MapFS{
			"etc/sudoers": &fstest.MapFile{Data: []byte(line + "\n%wheel ALL=(ALL) ALL\n")},
		}
		snapshot := Parse(files, "/etc/sudoers", time.Now())
		rules, complete := snapshot.RootWithoutPassword()
		if complete {
			t.Errorf("%q was answered in full, and it cannot be", line)
		}
		if len(rules) != 0 {
			t.Errorf("%q was counted as a passwordless grant: %d rules", line, len(rules))
		}
	}
}

// A default for another group leaves this rule alone.
func TestADefaultForAnotherGroupDoesNotCoverTheRule(t *testing.T) {
	files := fstest.MapFS{
		"etc/sudoers": &fstest.MapFile{Data: []byte(
			"Defaults:%backup !authenticate\n" +
				"%wheel ALL=(ALL) ALL\n")},
	}
	snapshot := Parse(files, "/etc/sudoers", time.Now())
	rules, complete := snapshot.RootWithoutPassword()
	if !complete {
		t.Fatal("a user-scoped default is answerable")
	}
	if len(rules) != 0 {
		t.Errorf("a default for %%backup was read as covering the rule for %%wheel: %d", len(rules))
	}
}
