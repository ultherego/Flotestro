package sudoers

import (
	"fmt"
	"testing"
	"testing/fstest"
	"time"
)

// A policy read only in part used to look whole: the walk stopped at its limit
// and recorded nothing - no file, no problem - while a read error eight lines
// below records the file with its reason. The questions asked of the snapshot,
// such as who may become root without a password, were then answered from the
// part that happened to be read.
func TestAPolicyStoppedAtTheLimitSaysSo(t *testing.T) {
	files := fstest.MapFS{
		"etc/sudoers": &fstest.MapFile{Data: []byte("#includedir /etc/sudoers.d\n")},
	}
	// More drop-ins than the walk will read, and the one that matters last.
	for i := range maxFiles + 10 {
		files[fmt.Sprintf("etc/sudoers.d/%03d-filler", i)] = &fstest.MapFile{
			Data: []byte("alice ALL=(ALL) ALL\n"),
		}
	}
	files["etc/sudoers.d/zzz-last"] = &fstest.MapFile{
		Data: []byte("Defaults !authenticate\n"),
	}

	snapshot := Parse(files, "/etc/sudoers", time.Now())

	if !snapshot.Truncated {
		t.Fatal("the walk stopped at its limit and the snapshot does not say so")
	}
	if snapshot.Complete() {
		t.Error("a policy read in part reports itself complete")
	}
	if len(snapshot.Problems) == 0 {
		t.Error("nothing was recorded about the files that were not read")
	}
	// The line that turns authentication off is in the file the walk never
	// reached. PasswordlessGlobally therefore answers false - which is why the
	// caller has to ask Complete first, and why Truncated has to exist.
	if snapshot.PasswordlessGlobally() {
		t.Log("the line was reached after all; the limit may have moved")
	}
}

// A policy that fits is whole, and must not be marked otherwise: a flag that
// is always set is a flag nobody can act on.
func TestAPolicyThatFitsIsComplete(t *testing.T) {
	files := fstest.MapFS{
		"etc/sudoers": &fstest.MapFile{Data: []byte(
			"Defaults !authenticate\nalice ALL=(ALL) NOPASSWD: ALL\n")},
	}
	snapshot := Parse(files, "/etc/sudoers", time.Now())
	if snapshot.Truncated {
		t.Error("a policy of one file was reported as stopped at the limit")
	}
	if !snapshot.Complete() {
		t.Errorf("a policy of one file is not complete: %q", snapshot.UnavailableReason)
	}
	if !snapshot.PasswordlessGlobally() {
		t.Error("the global Defaults !authenticate was not seen")
	}
}
