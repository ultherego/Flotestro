package packages

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestScriptletFailuresAreNamedFromTheOutput(t *testing.T) {
	output := strings.Join([]string{
		"[3/3] Installing flotestro-lab-broken-0 100% |   9.0 KiB/s | 768.0   B |  00m00s",
		">>> Running %post scriptlet: flotestro-lab-broken-0:1.0.0-1.noarch",
		">>> Non-critical error in %post scriptlet: flotestro-lab-broken-0:1.0.0-1.noarch",
		">>> Scriptlet output:",
		">>> flotestro-lab-broken: the maintainer script of this package fails by design;",
		">>> [RPM] %post(flotestro-lab-broken-1.0.0-1.noarch) scriptlet failed, exit status 1",
		"Error in POSTIN scriptlet in rpm package my-tool-2.0-1.fc42.x86_64",
		"Complete!",
	}, "\n")
	got := scriptletFailures(output)
	want := []string{"flotestro-lab-broken", "my-tool"}
	if strings.Join(got, ",") != strings.Join(want, ",") {
		t.Fatalf("scriptletFailures = %v, want %v", got, want)
	}
	if got := scriptletFailures("Complete!\n"); len(got) != 0 {
		t.Fatalf("a clean transaction names %v", got)
	}
}

// TestHoldNeedsTheVersionlockPlugin guards the declaration of the dnf adapter:
// a host without the plugin has no hold, says which package brings it back,
// and refuses the operation with its own code before dnf is started.
func TestHoldNeedsTheVersionlockPlugin(t *testing.T) {
	restore := versionlockPaths
	versionlockPaths = []string{filepath.Join(t.TempDir(), "nothing-here")}
	defer func() { versionlockPaths = restore }()

	if VersionlockInstalled() {
		t.Fatal("the plugin was found although nothing is installed")
	}
	if DNFFeatures(true, VersionlockInstalled())["hold"] {
		t.Error("the hold is reported on a host without the plugin")
	}
	reason := DNFReason(true, VersionlockInstalled())
	if !strings.Contains(reason, "versionlock") || !strings.Contains(reason, "dnf5-plugin-versionlock") {
		t.Errorf("the reason names neither the plugin nor the package: %q", reason)
	}

	apply, err := (&DNF{}).SetHold(context.Background(), []string{"kernel"}, true)
	if err == nil {
		t.Fatal("the hold was accepted on a host without the plugin")
	}
	if !errors.Is(err, ErrVersionlockMissing) {
		t.Errorf("err = %v, expected the refusal of a missing plugin", err)
	}
	code, ok := ErrorCodeOf(err)
	if !ok || code != ErrorVersionlockMissing {
		t.Errorf("code = %q, %v", code, ok)
	}
	if !Refused(err) {
		t.Error("nothing was attempted, so the error is a refusal of the host")
	}
	if len(apply.Output) != 0 {
		t.Errorf("the refusal carries the output of a command that never ran: %q", apply.Output)
	}
}

// TestVersionlockIsFoundByItsFile guards the detection itself: the registry is
// built without starting a process, so the plugin is recognised by the files a
// distribution installs it as.
func TestVersionlockIsFoundByItsFile(t *testing.T) {
	directory := t.TempDir()
	plugin := filepath.Join(directory, "versionlock.so")
	if err := os.WriteFile(plugin, []byte("plugin"), 0o644); err != nil {
		t.Fatal(err)
	}
	restore := versionlockPaths
	versionlockPaths = []string{filepath.Join(directory, "versionlock.*")}
	defer func() { versionlockPaths = restore }()

	if !VersionlockInstalled() {
		t.Fatal("the plugin file was not recognised")
	}
	if !DNFFeatures(true, VersionlockInstalled())["hold"] {
		t.Error("the hold is hidden on a host that has the plugin")
	}
	if DNFReason(true, VersionlockInstalled()) != "" {
		t.Error("a host that can hold a package has nothing to explain")
	}
	if DNFReason(false, false) == "" {
		t.Error("a host without dnf has to say so")
	}
}
