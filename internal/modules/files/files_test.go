package files

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// A panel that can write an arbitrary path can replace /etc/shadow and
// private keys. The ban is checked before the allowlist and cannot be
// bypassed by an administrator entry.
func TestForbiddenPathsAreRejectedDespiteAllowlist(t *testing.T) {
	allowlist := Allowlist{Patterns: []string{"/etc/*", "/etc/ssh/*", "/root/*"}, Source: "test"}

	for _, path := range []string{
		"/etc/shadow",
		"/etc/sudoers",
		"/etc/sudoers.d/90-admin",
		"/etc/ssh/ssh_host_ed25519_key",
		"/etc/ssh/sshd_config",
		"/root/.ssh/authorized_keys",
		"/etc/pam.d/sshd",
	} {
		err := allowlist.Allows(path)
		if !errors.Is(err, ErrForbidden) {
			t.Errorf("path %q: %v", path, err)
		}
	}
}

func TestPathOutsideAllowlistIsRejected(t *testing.T) {
	allowlist := Allowlist{Patterns: []string{"/etc/motd", "/opt/flotestro/etc/*"}, Source: "test"}

	for _, path := range []string{"/etc/hosts", "/var/lib/x", "etc/motd", "/etc/../etc/motd"} {
		if err := allowlist.Allows(path); err == nil {
			t.Errorf("accepted path %q", path)
		}
	}
	for _, path := range []string{"/etc/motd", "/opt/flotestro/etc/app.conf"} {
		if err := allowlist.Allows(path); err != nil {
			t.Errorf("rejected path %q: %v", path, err)
		}
	}
}

// The permissions and the owner are set on the new file before it takes
// the place of the old one: otherwise a window remains in which the file
// already sits in place with default permissions.
func TestAtomicWriteSetsPermissionsBeforeReplacement(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "app.conf")

	if err := WriteAtomically(path, []byte("a=1\n"), 0o640, -1, -1); err != nil {
		t.Fatal(err)
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0o640 {
		t.Errorf("permissions = %04o", info.Mode().Perm())
	}
	// No temporary file remains after the write: a configuration directory
	// collects garbage faster than anybody notices it.
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 1 {
		t.Errorf("%d files left in the directory", len(entries))
	}

	// A write without given permissions keeps the permissions of the
	// existing file: a content change is not a decision about access.
	if err := WriteAtomically(path, []byte("a=2\n"), 0, -1, -1); err != nil {
		t.Fatal(err)
	}
	info, _ = os.Stat(path)
	if info.Mode().Perm() != 0o640 {
		t.Errorf("permissions after a write without a mode = %04o", info.Mode().Perm())
	}
}

func TestWritePermissionsAreChecked(t *testing.T) {
	for _, mode := range []string{"777", "666", "4755", "2755", "999", "1234567"} {
		if _, err := ValidateMode(mode); err == nil {
			t.Errorf("accepted permissions %q", mode)
		}
	}
	for _, mode := range []string{"", "644", "600", "0640", "755"} {
		if _, err := ValidateMode(mode); err != nil {
			t.Errorf("rejected permissions %q: %v", mode, err)
		}
	}
}

func TestFileContentIsChecked(t *testing.T) {
	if err := ValidateContent("key = value\n"); err != nil {
		t.Errorf("rejected valid content: %v", err)
	}
	if err := ValidateContent("a\x00b"); err == nil {
		t.Error("accepted content with a zero byte")
	}
	if err := ValidateContent(strings.Repeat("a", MaxSize+1)); err == nil {
		t.Error("accepted content bigger than the module limit")
	}
}

func TestValidatorIsSelectedForFile(t *testing.T) {
	validator, has, err := SelectValidator("/etc/app/config.json", "")
	if err != nil || !has || validator.Name != "json" {
		t.Errorf("validator = %+v, %v, %v", validator, has, err)
	}
	if err := validator.BuiltIn(`{"a": 1}`); err != nil {
		t.Errorf("rejected valid JSON: %v", err)
	}
	if err := validator.BuiltIn(`{"a": }`); err == nil {
		t.Error("accepted broken JSON")
	}

	if _, _, err := SelectValidator("/etc/motd", "no-such-thing"); err == nil {
		t.Error("accepted an unknown validator")
	}
	// A file the panel knows no check for does not get one by force.
	if _, has, _ := SelectValidator("/etc/motd", ""); has {
		t.Error("a validator was selected for a text file")
	}

	unit, _, _ := SelectValidator("/etc/systemd/system/app.service", "")
	if unit.Name != "systemd-unit" || len(unit.Command) == 0 {
		t.Errorf("unit validator = %+v", unit)
	}
}

func TestContentFingerprintIsStable(t *testing.T) {
	if Fingerprint([]byte("a")) != Fingerprint([]byte("a")) {
		t.Error("the fingerprint of the same content differs")
	}
	if Fingerprint([]byte("a")) == Fingerprint([]byte("b")) {
		t.Error("the fingerprint of different content is the same")
	}
	if len(Fingerprint(nil)) != 64 {
		t.Errorf("fingerprint of empty content = %q", Fingerprint(nil))
	}
}
