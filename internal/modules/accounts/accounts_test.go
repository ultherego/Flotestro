package accounts

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// Two ed25519 keys: the same wire format, another last byte. The private
// material does not exist and is not needed for anything.
const (
	keyOne = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIHZ8Kx3vQOZKq0M0hDPuJHf5Zx1kJHgqRqYqGZ6XxLm1 one@laptop"
	keyTwo = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIHZ8Kx3vQOZKq0M0hDPuJHf5Zx1kJHgqRqYqGZ6XxLm2 two@laptop"
)

func fingerprintOf(t *testing.T, key string) string {
	t.Helper()
	line, err := ParseKey(KeyInput{PublicKey: key})
	if err != nil {
		t.Fatal(err)
	}
	return line.Fingerprint
}

// The editor touches the lines it was asked about and nothing else: a comment,
// an unreadable line and the options in front of a key all come out as they
// went in.
func TestAddingAKeyKeepsEveryOtherLine(t *testing.T) {
	content := "# keys of the deploy account\n" +
		"command=\"/usr/bin/rrsync /srv\",no-pty " + keyOne + "\n" +
		"\n" +
		"this line is not a key\n"
	lines := ParseKeyFile([]byte(content))
	if len(lines) != 4 {
		t.Fatalf("lines = %d, expected 4", len(lines))
	}
	if lines[1].Fingerprint == "" || lines[0].Fingerprint != "" || lines[3].Fingerprint != "" {
		t.Fatalf("the key line was not told from the others: %+v", lines)
	}

	edited, change, err := AddKeys(lines, []KeyInput{{PublicKey: keyTwo}})
	if err != nil {
		t.Fatal(err)
	}
	rendered := Render(edited)
	if !strings.HasPrefix(rendered, content) {
		t.Fatalf("the existing lines changed:\n%s", rendered)
	}
	if !strings.HasSuffix(rendered, keyTwo+"\n") {
		t.Fatalf("the new key was not appended:\n%s", rendered)
	}
	if len(change.Added) != 1 || change.Added[0] != fingerprintOf(t, keyTwo) || len(change.Removed) != 0 {
		t.Fatalf("change = %+v", change)
	}
	if len(change.Before) != 1 || len(change.After) != 2 {
		t.Fatalf("before/after = %v / %v", change.Before, change.After)
	}
}

// A key already in the file is not written twice: neither when it comes with
// other options or another comment, nor when the same order names it twice.
func TestAddingIsIdempotentByFingerprint(t *testing.T) {
	lines := ParseKeyFile([]byte("from=\"10.0.0.0/8\" " + keyOne + "\n"))
	edited, change, err := AddKeys(lines, []KeyInput{
		{PublicKey: strings.TrimSuffix(keyOne, " one@laptop"), Comment: "another comment"},
		{PublicKey: keyTwo},
		{PublicKey: keyTwo},
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(edited) != 2 {
		t.Fatalf("lines after the add = %d, expected 2:\n%s", len(edited), Render(edited))
	}
	if edited[0].Text != "from=\"10.0.0.0/8\" "+keyOne {
		t.Fatalf("the existing line was rewritten: %q", edited[0].Text)
	}
	if len(change.Added) != 1 {
		t.Fatalf("added = %v, expected the second key once", change.Added)
	}

	again, repeat, err := AddKeys(edited, []KeyInput{{PublicKey: keyTwo}})
	if err != nil {
		t.Fatal(err)
	}
	if !repeat.NoOp() || Render(again) != Render(edited) {
		t.Fatalf("a repeated add changed the file: %+v", repeat)
	}
}

// A comment given apart lands on the line only when the key has none of
// its own; the one in the file is the one people grep for.
func TestACommentIsAppendedOnlyWhenTheKeyHasNone(t *testing.T) {
	bare := strings.TrimSuffix(keyOne, " one@laptop")
	line, err := ParseKey(KeyInput{PublicKey: bare, Comment: "jane@laptop"})
	if err != nil {
		t.Fatal(err)
	}
	if line.Text != bare+" jane@laptop" || line.Comment != "jane@laptop" {
		t.Fatalf("line = %+v", line)
	}
	line, err = ParseKey(KeyInput{PublicKey: keyOne, Comment: "ignored"})
	if err != nil {
		t.Fatal(err)
	}
	if line.Text != keyOne || line.Comment != "one@laptop" {
		t.Fatalf("line = %+v", line)
	}
}

// Material that is not a public key is refused before anything is
// written: a private key, a second line, a type sshd does not know.
func TestMaterialThatIsNotAPublicKeyIsRefused(t *testing.T) {
	for name, key := range map[string]string{
		"a private key":      "-----BEGIN OPENSSH PRIVATE KEY-----",
		"two lines":          keyOne + "\n" + keyTwo,
		"garbage":            "ssh-ed25519 notbase64 x",
		"empty":              "   ",
		"a type without key": "ssh-ed25519",
	} {
		if _, err := ParseKey(KeyInput{PublicKey: key}); !errors.Is(err, ErrInvalidKey) {
			t.Errorf("%s: err = %v, expected ErrInvalidKey", name, err)
		}
	}
	if _, _, err := AddKeys(nil, []KeyInput{{PublicKey: "nope"}}); !errors.Is(err, ErrInvalidKey) {
		t.Errorf("an add with bad material: err = %v", err)
	}
}

// A removal drops the named lines and nothing else, and refuses to remove
// what is not there unless told the key may be missing.
func TestRemovingByFingerprint(t *testing.T) {
	content := "# comment\n" + keyOne + "\n" + "no-pty " + keyTwo + "\n"
	lines := ParseKeyFile([]byte(content))
	one := fingerprintOf(t, keyOne)

	edited, change, err := RemoveKeys(lines, []string{one}, false)
	if err != nil {
		t.Fatal(err)
	}
	if Render(edited) != "# comment\nno-pty "+keyTwo+"\n" {
		t.Fatalf("rendered:\n%s", Render(edited))
	}
	if len(change.Removed) != 1 || change.Removed[0] != one || len(change.Added) != 0 {
		t.Fatalf("change = %+v", change)
	}

	_, _, err = RemoveKeys(edited, []string{one}, false)
	var missing *KeyNotFoundError
	if !errors.As(err, &missing) || len(missing.Fingerprints) != 1 || missing.Fingerprints[0] != one {
		t.Fatalf("removing a key that is not there: err = %v", err)
	}
	same, change, err := RemoveKeys(edited, []string{one}, true)
	if err != nil || !change.NoOp() || Render(same) != Render(edited) {
		t.Fatalf("ignore_missing: err=%v change=%+v", err, change)
	}
}

// A key on two lines - once plain, once with options - is one key by
// fingerprint: the inventory lists it once, and a removal takes both lines,
// because leaving one would leave the access.
func TestADuplicateFingerprintIsOneKey(t *testing.T) {
	lines := ParseKeyFile([]byte(keyOne + "\n" + "no-pty " + keyOne + "\n"))
	if fingerprints := Fingerprints(lines); len(fingerprints) != 1 {
		t.Fatalf("fingerprints = %v", fingerprints)
	}
	edited, change, err := RemoveKeys(lines, []string{fingerprintOf(t, keyOne)}, false)
	if err != nil {
		t.Fatal(err)
	}
	if len(edited) != 0 || len(change.Removed) != 1 || len(change.After) != 0 {
		t.Fatalf("edited=%v change=%+v", edited, change)
	}
}

// A replace writes exactly the given list; the difference names what
// went and what came, so an approval knows what it covers.
func TestReplacingNamesWhatGoesAndWhatComes(t *testing.T) {
	lines := ParseKeyFile([]byte("# comment\n" + keyOne + "\n"))
	edited, change, err := ReplaceKeys(lines, []KeyInput{{PublicKey: keyTwo}})
	if err != nil {
		t.Fatal(err)
	}
	if Render(edited) != keyTwo+"\n" {
		t.Fatalf("rendered:\n%s", Render(edited))
	}
	if len(change.Added) != 1 || len(change.Removed) != 1 ||
		change.Added[0] != fingerprintOf(t, keyTwo) || change.Removed[0] != fingerprintOf(t, keyOne) {
		t.Fatalf("change = %+v", change)
	}
	empty, change, err := ReplaceKeys(edited, nil)
	if err != nil || len(empty) != 0 || len(change.After) != 0 || len(change.Removed) != 1 {
		t.Fatalf("emptying: err=%v change=%+v", err, change)
	}
}

func TestSameFingerprintsIgnoresOrderAndSpace(t *testing.T) {
	if !SameFingerprints([]string{"SHA256:b", " SHA256:a"}, []string{"SHA256:a", "SHA256:b "}) {
		t.Error("the same set in another order was taken as different")
	}
	if SameFingerprints([]string{"SHA256:a"}, []string{"SHA256:a", "SHA256:b"}) {
		t.Error("a longer list was taken as the same")
	}
	if !SameFingerprints(nil, []string{}) {
		t.Error("no keys and an empty list are the same picture")
	}
}

// Rendering keeps the file byte for byte when nothing changed, and a file
// without a final newline gets one: sshd reads the last line either way, and a
// later append must not glue itself to it.
func TestRenderRoundTrip(t *testing.T) {
	content := "# a\n\n" + keyOne + "\n"
	if got := Render(ParseKeyFile([]byte(content))); got != content {
		t.Fatalf("round trip changed the file:\n%q\n%q", content, got)
	}
	if got := Render(ParseKeyFile([]byte(keyOne))); got != keyOne+"\n" {
		t.Fatalf("a missing final newline was not added: %q", got)
	}
	if got := Render(ParseKeyFile(nil)); got != "" {
		t.Fatalf("an empty file rendered as %q", got)
	}
}

// One classifier for both sides: the file says where people start and end, and
// everything outside - including nobody at 65534 - is the system's.
func TestTheUIDRangeComesFromLoginDefs(t *testing.T) {
	uidRange := ParseLoginDefs("# comment\nUID_MIN\t\t 500 # inline\nUID_MAX\t\t 50000\nSYS_UID_MAX 499\nGID_MIN 1000\n")
	if uidRange.Min != 500 || uidRange.Max != 50000 || uidRange.SystemMax != 499 || uidRange.Source != "login.defs" {
		t.Fatalf("range = %+v", uidRange)
	}
	for uid, system := range map[int64]bool{0: true, 499: true, 500: false, 50000: false, 50001: true, 65534: true} {
		if uidRange.IsSystem(uid) != system {
			t.Errorf("uid %d: system = %v, expected %v", uid, uidRange.IsSystem(uid), system)
		}
	}

	// A range that ends before it starts is a broken file, not a host
	// without people.
	if broken := ParseLoginDefs("UID_MIN 5000\nUID_MAX 100\n"); broken != DefaultUIDRange() {
		t.Errorf("a broken range gave %+v", broken)
	}
	if silent := ParseLoginDefs("GID_MIN 1000\n"); silent != DefaultUIDRange() {
		t.Errorf("a silent file gave %+v", silent)
	}

	directory := t.TempDir()
	path := filepath.Join(directory, "login.defs")
	if err := os.WriteFile(path, []byte("UID_MIN 2000\nUID_MAX 3000\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	fromFile := ParseUIDRange(path)
	if fromFile.Min != 2000 || fromFile.Max != 3000 || fromFile.Source != path {
		t.Errorf("from the file: %+v", fromFile)
	}
	if missing := ParseUIDRange(filepath.Join(directory, "absent")); missing != DefaultUIDRange() {
		t.Errorf("a missing file gave %+v", missing)
	}
}

// The privileged groups are a setting with the document's default; the
// setting is cleaned, never emptied.
func TestPrivilegedGroupsAreASetting(t *testing.T) {
	t.Cleanup(func() { SetPrivilegedGroups(nil) })
	if got := PrivilegedGroupsIn([]string{"users", "docker", "sudo"}); len(got) != 2 || got[0] != "docker" || got[1] != "sudo" {
		t.Fatalf("default classification = %v", got)
	}
	SetPrivilegedGroups([]string{" Wheel ", "adm", "", "adm"})
	if got := PrivilegedGroups(); len(got) != 2 || got[0] != "adm" || got[1] != "wheel" {
		t.Fatalf("set = %v", got)
	}
	if got := PrivilegedGroupsIn([]string{"sudo"}); len(got) != 0 {
		t.Fatalf("sudo stayed privileged after the setting replaced the list: %v", got)
	}
	SetPrivilegedGroups([]string{"", "  "})
	if got := PrivilegedGroups(); len(got) != len(DefaultPrivilegedGroups) {
		t.Fatalf("an empty setting did not fall back to the default: %v", got)
	}
}

// The managed file counts only when sshd reads it: the check reads the
// effective configuration, token unexpanded, as sshd -T prints it.
func TestManagedFileMustBeInAuthorizedKeysFile(t *testing.T) {
	if ManagedFileReadBySSHD("port 22\nauthorizedkeysfile .ssh/authorized_keys .ssh/authorized_keys2\n") {
		t.Error("a server without the managed file was taken as reading it")
	}
	if !ManagedFileReadBySSHD("authorizedkeysfile .ssh/authorized_keys " + ManagedKeysPattern + "\n") {
		t.Error("a server that lists the managed file was not recognised")
	}
	if ManagedKeysPath("jane") != "/etc/ssh/authorized_keys.d/jane/60-flotestro.keys" {
		t.Errorf("path = %s", ManagedKeysPath("jane"))
	}
}
