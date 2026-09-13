package logs

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// A panel that can read any file of root can read private keys and
// /etc/shadow. The scope is enumerated, not given in the task.
func TestTheAllowlistLimitsTheScope(t *testing.T) {
	allowlist := Allowlist{Patterns: []string{"/var/log/*.log", "/var/log/syslog"}}

	for _, path := range []string{"/var/log/nginx.log", "/var/log/syslog"} {
		if !allowlist.Allows(path) {
			t.Errorf("an allowed path %q was rejected", path)
		}
	}
	for _, path := range []string{
		"/etc/shadow",
		"/root/.ssh/id_ed25519",
		"var/log/nginx.log",
		"/var/log/nginx/access.log",
	} {
		if allowlist.Allows(path) {
			t.Errorf("a path outside the scope %q was accepted", path)
		}
	}
}

// A pattern describes the path, not where it leads. A path with ".." matches
// the pattern textually while leaving the directory the pattern describes.
func TestAPathClimbingUpIsRejected(t *testing.T) {
	allowlist := Allowlist{Patterns: []string{"/var/log/*.log", "/var/log/*"}}
	for _, path := range []string{
		"/var/log/../../etc/shadow",
		"/var/log/./syslog",
		"/var/log//syslog",
	} {
		if allowlist.Allows(path) {
			t.Errorf("the path %q was accepted", path)
		}
	}
}

// A symlink in the log directory would allow any file of root to be read
// despite a correct allowlist.
func TestTheReadDoesNotFollowASymlink(t *testing.T) {
	directory := t.TempDir()
	secret := filepath.Join(directory, "secret.txt")
	if err := os.WriteFile(secret, []byte("password\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(directory, "impostor.log")
	if err := os.Symlink(secret, link); err != nil {
		t.Skipf("the system does not allow creating symlinks: %v", err)
	}

	allowlist := Allowlist{Patterns: []string{filepath.Join(directory, "*.log")}}
	_, err := Read(allowlist, link, 10)
	if err == nil {
		t.Fatal("the read followed the symlink")
	}
	if !strings.Contains(err.Error(), "symbolic link") {
		t.Errorf("error = %v, expected a refusal because of the symlink", err)
	}
}

// The cause of a failure is usually near the end of the log, so the tail is
// returned and it is said directly that the rest was skipped.
func TestTheReadReturnsTheTailAndMarksTheCut(t *testing.T) {
	directory := t.TempDir()
	path := filepath.Join(directory, "big.log")
	var content strings.Builder
	for i := 0; i < 50; i++ {
		content.WriteString("line ")
		content.WriteString(strings.Repeat("x", 10))
		content.WriteString("\n")
	}
	if err := os.WriteFile(path, []byte(content.String()), 0o600); err != nil {
		t.Fatal(err)
	}

	allowlist := Allowlist{Patterns: []string{filepath.Join(directory, "*.log")}}
	fragment, err := Read(allowlist, path, 10)
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	if len(fragment.Lines) != 10 {
		t.Errorf("lines = %d, expected 10", len(fragment.Lines))
	}
	if !fragment.Truncated {
		t.Error("the cut was not marked")
	}
	if fragment.SizeBytes == 0 {
		t.Error("the size of the file was not given")
	}
}

// A directory and a socket are not a log; a read from a pipe would hang
// forever.
func TestTheReadRefusesANonFile(t *testing.T) {
	directory := t.TempDir()
	subdirectory := filepath.Join(directory, "logs.log")
	if err := os.Mkdir(subdirectory, 0o755); err != nil {
		t.Fatal(err)
	}
	allowlist := Allowlist{Patterns: []string{filepath.Join(directory, "*.log")}}
	if _, err := Read(allowlist, subdirectory, 10); err == nil {
		t.Error("a directory was read like a file")
	}
}

// A missing administrator file must not mean "everything is allowed".
func TestAMissingFileGivesTheDefaultList(t *testing.T) {
	allowlist := LoadAllowlist(filepath.Join(t.TempDir(), "missing.allow"))
	if len(allowlist.Patterns) == 0 {
		t.Fatal("an empty scope with a missing file")
	}
	if allowlist.Allows("/etc/shadow") {
		t.Error("the default list allows /etc/shadow")
	}
	if !allowlist.Allows("/var/log/syslog") {
		t.Error("the default list does not allow a typical log")
	}
}
