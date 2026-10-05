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

// A default for another account leaves this rule alone: two account names are
// two accounts, and that the files do settle.
func TestADefaultForAnotherUserDoesNotCoverTheRule(t *testing.T) {
	files := fstest.MapFS{
		"etc/sudoers": &fstest.MapFile{Data: []byte(
			"Defaults:bob !authenticate\n" +
				"alice ALL=(ALL) ALL\n")},
	}
	snapshot := Parse(files, "/etc/sudoers", time.Now())
	rules, complete := snapshot.RootWithoutPassword()
	if !complete {
		t.Fatal("two account names are two accounts, and that is answerable")
	}
	if len(rules) != 0 {
		t.Errorf("a default for bob was read as covering the rule for alice: %d", len(rules))
	}
}

// Two different groups are not two different sets of accounts: whoever is in
// both has passwordless root from this pair of lines. Which accounts those are
// is in /etc/group, so the files answer "unknown" - a quiet no here is the same
// mistake as asking only about the global scope was.
func TestADefaultForAnotherGroupIsUnknown(t *testing.T) {
	files := fstest.MapFS{
		"etc/sudoers": &fstest.MapFile{Data: []byte(
			"Defaults:%backup !authenticate\n" +
				"%wheel ALL=(ALL) ALL\n")},
	}
	snapshot := Parse(files, "/etc/sudoers", time.Now())
	rules, complete := snapshot.RootWithoutPassword()
	if complete {
		t.Error("whether an account is in both of the two groups is not in these files")
	}
	if len(rules) != 0 {
		t.Errorf("an unresolved membership was counted as a grant: %d", len(rules))
	}
}

// The scope reaches the rule through the grantee ALL: it names every account,
// so it names the one the default names, and no group membership has to be
// resolved to see it. This pair reported complete=true with no passwordless
// grant, on the screen an operator reads to believe alice needs a password
// (audit of 6c38561, HMISC-01).
func TestAScopedDefaultAgainstARuleForEveryoneIsSeen(t *testing.T) {
	files := fstest.MapFS{
		"etc/sudoers": &fstest.MapFile{Data: []byte(
			"Defaults:alice !authenticate\n" +
				"ALL ALL=(ALL) ALL\n")},
	}
	snapshot := Parse(files, "/etc/sudoers", time.Now())
	rules, complete := snapshot.RootWithoutPassword()
	if !complete {
		t.Fatal("a named account against the grantee ALL needs no group to resolve")
	}
	if len(rules) != 1 {
		t.Fatalf("rules = %d, want the rule alice may use without a password", len(rules))
	}
}

// A rule that grants to everyone and takes the one account back is no way to
// root for that account.
func TestAnExcludedAccountIsNotCoveredByTheRuleThatExcludesIt(t *testing.T) {
	files := fstest.MapFS{
		"etc/sudoers": &fstest.MapFile{Data: []byte(
			"Defaults:alice !authenticate\n" +
				"ALL,!alice ALL=(ALL) ALL\n")},
	}
	snapshot := Parse(files, "/etc/sudoers", time.Now())
	rules, complete := snapshot.RootWithoutPassword()
	if !complete {
		t.Fatal("an exclusion written as a name is answerable")
	}
	if len(rules) != 0 {
		t.Errorf("the rule that excludes alice was counted as hers: %d", len(rules))
	}
}

// A default for one account against a rule for a group is the same unknown
// from the other side: whether alice is in %wheel is not in these files.
func TestADefaultForAUserAgainstARuleForAGroupIsUnknown(t *testing.T) {
	files := fstest.MapFS{
		"etc/sudoers": &fstest.MapFile{Data: []byte(
			"Defaults:alice !authenticate\n" +
				"%wheel ALL=(ALL) ALL\n")},
	}
	snapshot := Parse(files, "/etc/sudoers", time.Now())
	if _, complete := snapshot.RootWithoutPassword(); complete {
		t.Error("whether alice is in the group the rule names is not in these files")
	}
}
