package hostname

import "testing"

func TestValidateAcceptsLabelsAndFullyQualifiedNames(t *testing.T) {
	for _, name := range []string{"web01", "web-01", "db.internal.example", "a", "x1.y2.z3"} {
		if err := Validate(name); err != nil {
			t.Errorf("%q was rejected: %v", name, err)
		}
	}
}

// The name goes into hostnamectl and into /etc/hosts. Upper-case letters
// are refused rather than folded: the host would end up with a name other
// than the one the operator approved.
func TestValidateRejectsWhatCannotBeAHostname(t *testing.T) {
	for _, name := range []string{
		"", "Web01", "-web", "web-", "web_01", "web 01", "web.", ".web",
		"localhost", "db.localhost", "web01;reboot", "a..b",
		"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
	} {
		if err := Validate(name); err == nil {
			t.Errorf("%q was accepted", name)
		}
	}
}

func TestRewriteHostsTouchesOnlyWholeNames(t *testing.T) {
	content := "127.0.0.1\tlocalhost\n" +
		"127.0.1.1\tdb db.example.internal\n" +
		"10.0.0.5\tdb-backup db-backup.example.internal # the second one\n" +
		"::1\tlocalhost ip6-localhost\n"
	rewritten, changed := RewriteHosts(content, "db.example.internal", "storage.example.internal")
	if !changed {
		t.Fatal("the file names the old hostname and was reported unchanged")
	}
	expected := "127.0.0.1\tlocalhost\n" +
		"127.0.1.1\tstorage storage.example.internal\n" +
		"10.0.0.5\tdb-backup db-backup.example.internal # the second one\n" +
		"::1\tlocalhost ip6-localhost\n"
	if rewritten != expected {
		t.Fatalf("rewritten:\n%s\nexpected:\n%s", rewritten, expected)
	}

	// Idempotent: a second pass finds nothing to rename.
	again, changedAgain := RewriteHosts(rewritten, "db.example.internal", "storage.example.internal")
	if changedAgain || again != rewritten {
		t.Error("a second rewrite changed the file again")
	}
}

func TestRewriteHostsLeavesAFileWithoutTheNameAlone(t *testing.T) {
	content := "127.0.0.1\tlocalhost\n10.0.0.5\tother\n"
	rewritten, changed := RewriteHosts(content, "db", "storage")
	if changed || rewritten != content {
		t.Error("a file without the old name was changed")
	}
	if _, changed := RewriteHosts(content, "", "storage"); changed {
		t.Error("an empty previous name changed the file")
	}
}

func TestRewriteHostsCollapsesNamesThatBecomeEqual(t *testing.T) {
	content := "127.0.1.1\tdb db.example.internal\n"
	rewritten, changed := RewriteHosts(content, "db.example.internal", "db")
	if !changed {
		t.Fatal("the rename was not applied")
	}
	if rewritten != "127.0.1.1\tdb\n" {
		t.Fatalf("rewritten: %q", rewritten)
	}
}
