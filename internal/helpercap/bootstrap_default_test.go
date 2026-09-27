package helpercap

import (
	"os"
	"path/filepath"
	"testing"
	"time"
)

// The safe answer is the one nobody has to choose. Until this release an unset
// bootstrap policy meant "take the first panel that reaches the socket", which
// is the decision about who owns a host, made by whoever got there first.
func TestAnUnsetBootstrapPolicyIsPinned(t *testing.T) {
	for _, value := range []string{"", "   ", "PINNED", "pinned"} {
		policy, err := ParseBootstrap(value)
		if err != nil {
			t.Fatalf("%q: %v", value, err)
		}
		if policy != BootstrapPinned {
			t.Errorf("%q gave %s, expected %s", value, policy, BootstrapPinned)
		}
	}
	// Taking the first bundle on trust is still possible; it is now written down.
	policy, err := ParseBootstrap("tofu")
	if err != nil || policy != BootstrapTOFU {
		t.Errorf("tofu gave %s, %v", policy, err)
	}
}

// A helper with no configuration file at all runs on the same answer.
func TestSettingsWithoutAFileArePinned(t *testing.T) {
	settings, err := LoadSettings(filepath.Join(t.TempDir(), "absent.yaml"))
	if err != nil {
		t.Fatalf("loading settings without a file: %v", err)
	}
	if settings.Bootstrap != BootstrapPinned {
		t.Errorf("a helper with no file runs on %s, expected %s", settings.Bootstrap, BootstrapPinned)
	}
	if settings.PinPath != DefaultPinPath {
		t.Errorf("the pin is read from %s, expected %s", settings.PinPath, DefaultPinPath)
	}
}

// What the package writes into /etc on a first installation, and what a
// laboratory writes instead: both are read back as what they say.
func TestTheShippedFileIsPinnedAndALaboratoryCanSayOtherwise(t *testing.T) {
	read := func(t *testing.T, body string) Settings {
		t.Helper()
		path := filepath.Join(t.TempDir(), "helper.yaml")
		if err := os.WriteFile(path, []byte(body), 0o644); err != nil {
			t.Fatal(err)
		}
		settings, err := LoadSettings(path)
		if err != nil {
			t.Fatalf("reading %s: %v", path, err)
		}
		return settings
	}
	shipped, err := os.ReadFile("../../packaging/helper.yaml")
	if err != nil {
		t.Skipf("the packaged file is not here: %v", err)
	}
	if got := read(t, string(shipped)).Bootstrap; got != BootstrapPinned {
		t.Errorf("the packaged helper.yaml runs on %s, expected %s", got, BootstrapPinned)
	}
	lab := "schema_version: 1\ncapabilities:\n  mode: enforce\n  bootstrap: tofu\n"
	if got := read(t, lab).Bootstrap; got != BootstrapTOFU {
		t.Errorf("a laboratory that asked for %s got %s", BootstrapTOFU, got)
	}
}

// The pin is a trust anchor: a file somebody else may rewrite chooses the panel
// for this host, and a link moves the decision somewhere nobody looked.
func TestThePinIsRefusedWhenAnybodyElseCouldHaveWrittenIt(t *testing.T) {
	dir := t.TempDir()
	store := TrustStore{Dir: filepath.Join(dir, "trust.d"),
		HostIDPath:  filepath.Join(dir, "host-id"),
		PinPath:     filepath.Join(dir, "panel-trust.pin"),
		RequireRoot: true}

	target := filepath.Join(dir, "elsewhere.pin")
	if err := os.WriteFile(target, []byte("\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(target, store.PinPath); err != nil {
		t.Skipf("this filesystem takes no symbolic links: %v", err)
	}
	if _, err := store.Pins(); err == nil {
		t.Error("a pin behind a symbolic link was read as if it were the file")
	}
	if err := os.Remove(store.PinPath); err != nil {
		t.Fatal(err)
	}

	// Group-writable is the other way somebody else decides.
	if err := os.WriteFile(store.PinPath, []byte("\n"), 0o664); err != nil {
		t.Fatal(err)
	}
	if os.Geteuid() == 0 {
		if _, err := store.Pins(); err == nil {
			t.Error("a pin anybody in the group could rewrite was read")
		}
	}
}

// A host that is already enrolled is not asked about its pin again: the policy
// decides the first bundle and nothing after it. An upgrade that flipped the
// default must not cut a running fleet off from its panel.
func TestAnEnrolledHostIsUnaffectedByThePolicy(t *testing.T) {
	panel := newSigner(t)
	dir := t.TempDir()
	store := TrustStore{Dir: filepath.Join(dir, "trust.d"),
		HostIDPath: filepath.Join(dir, "host-id"),
		PinPath:    filepath.Join(dir, "panel-trust.pin"),
		Bootstrap:  BootstrapTOFU}
	if _, err := store.Apply(panel.TrustBundle("host-1", time.Now())); err != nil {
		t.Fatalf("the first enrollment: %v", err)
	}
	// The upgrade: the same host, the same keyring, the new default.
	store.Bootstrap = BootstrapPinned
	if _, err := store.Apply(panel.TrustBundle("host-1", time.Now())); err != nil {
		t.Fatalf("an enrolled host was cut off by the new default: %v", err)
	}
}
