package packages

import (
	"context"
	"os"
	"testing"
)

// Removing the agent cuts the host off from the panel, and therefore also
// from repairing what has just been broken. Removing the kernel or the
// bootloader leaves a machine that will not come up.
func TestProtectedPackagesAreRecognised(t *testing.T) {
	protected := []string{
		"flotestro-agent", "openssh-server", "systemd", "sudo",
		"linux-image-6.12.48+deb13-amd64", "grub-pc", "grub-efi-amd64",
		"apt", "dpkg", "dnf", "rpm", "kernel-core", "systemd-sysv",
		"SYSTEMD", "systemd:amd64",
	}
	for _, pkg := range protected {
		if !Protected(pkg) {
			t.Errorf("the package %q was not recognised as protected", pkg)
		}
	}
}

// The protection must not spill over everything: a panel that refuses to
// remove anything is not a management panel.
func TestOrdinaryPackagesAreNotProtected(t *testing.T) {
	ordinary := []string{"nginx", "htop", "sl", "postgresql-16", "vim", "curl", "", "  "}
	for _, pkg := range ordinary {
		if Protected(pkg) {
			t.Errorf("the package %q was treated as protected", pkg)
		}
	}
}

// The operator is to know which package blocks the operation rather than only
// that something blocks it.
func TestTheProtectedOnesInASetNameTheCulprit(t *testing.T) {
	result := ProtectedInSet([]string{"nginx", "systemd", "htop", "linux-image-6.12"})
	if len(result) != 2 {
		t.Fatalf("found %d protected ones, expected 2: %v", len(result), result)
	}
	if result[0] != "systemd" || result[1] != "linux-image-6.12" {
		t.Errorf("protected = %v", result)
	}
	if ProtectedInSet([]string{"nginx", "htop"}) != nil {
		t.Error("a set without protected packages returned a non-empty list")
	}
}

// TestTheEnvironmentSuspendsNeedrestart guards the boundary that cost a job in
// the laboratory: needrestart restarted the helper in the middle of the
// transaction the helper was running, and the result ended with "the answer of
// the helper: EOF". A restart is a decision of the panel rather than a side
// effect of an upgrade.
func TestTheEnvironmentSuspendsNeedrestart(t *testing.T) {
	testEnvironment := environment()
	wanted := map[string]bool{
		"NEEDRESTART_MODE=l":             false,
		"DEBIAN_FRONTEND=noninteractive": false,
	}
	for _, entry := range testEnvironment {
		if _, ok := wanted[entry]; ok {
			wanted[entry] = true
		}
	}
	for entry, found := range wanted {
		if !found {
			t.Errorf("the environment of a transaction does not set %s", entry)
		}
	}
}

// TestAnAbandonedHoldReleasesOnlyOurOwn guards the boundary of the cleanup: a
// hold placed by the administrator of the host stays, and our own - left by a
// transaction that died with its process - disappears. Without that a host
// with an interrupted upgrade had the agent package held for good and no later
// replacement of the agent could go through.
func TestAnAbandonedHoldReleasesOnlyOurOwn(t *testing.T) {
	directory := t.TempDir()
	if err := SetRuntimeDir(directory); err != nil {
		t.Fatal(err)
	}

	// Without a trace there is nothing to release: somebody else's hold stays
	// untouched.
	released, err := ReleaseAbandonedHold(context.Background())
	if err != nil {
		t.Fatalf("the cleanup without a trace: %v", err)
	}
	if released {
		t.Error("a hold we had not placed was released")
	}

	// The trace disappears even when the tool is missing: otherwise the
	// attempt would repeat at every start of the helper.
	if err := os.WriteFile(holdTrace(), []byte(AgentPackage), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := ReleaseAbandonedHold(context.Background()); err != nil {
		t.Fatalf("the cleanup with a trace: %v", err)
	}
	if _, err := os.Stat(holdTrace()); !os.IsNotExist(err) {
		t.Error("the trace of the hold stayed after the cleanup")
	}
}
