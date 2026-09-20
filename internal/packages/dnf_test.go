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

// The security metadata of this family is incomplete rather than absent: what
// an advisory classifies is read, what none covers stays unknown.
func TestDNFAdvisoriesClassifyThePendingUpdates(t *testing.T) {
	output := strings.Join([]string{
		"Last metadata expiration check: 0:01:00 ago.",
		"FEDORA-2026-1a2b3c4d5e Moderate/Sec.  kernel-core-6.16.8-200.fc42.x86_64",
		"FEDORA-2026-2b3c4d5e6f bugfix         NetworkManager-1:1.52.2-1.fc42.x86_64",
		"FEDORA-2026-3c4d5e6f70 security       moderate   openssl-1:3.2.4-1.fc42.noarch",
	}, "\n")
	types := ParseDNFUpdateinfoList(output)

	if security, known := types.Security("kernel-core", "x86_64"); !security || !known {
		t.Errorf("kernel-core = security %v, known %v", security, known)
	}
	if security, known := types.Security("NetworkManager", "x86_64"); security || !known {
		t.Errorf("a bug fix was read as a security update: security %v, known %v", security, known)
	}
	// dnf5 writes the type and the severity in two columns; the bare name
	// answers for an architecture the advisory did not name.
	if security, known := types.Security("openssl", "x86_64"); !security || !known {
		t.Errorf("openssl = security %v, known %v", security, known)
	}
	if _, known := types.Security("docker-ce", "x86_64"); known {
		t.Error("a package no advisory covers was classified")
	}
}

// The classified half of a security plan is carried out; the rest stays in the
// plan as a block, so the host is neither patched in silence nor reported clean.
func TestDNFSecurityPlanKeepsTheClassifiedAndBlocksTheRest(t *testing.T) {
	types := ParseDNFUpdateinfoList(strings.Join([]string{
		"FEDORA-2026-1a2b3c4d5e Moderate/Sec.  kernel-core-6.16.8-200.fc42.x86_64",
		"FEDORA-2026-2b3c4d5e6f bugfix         NetworkManager-1:1.52.2-1.fc42.x86_64",
	}, "\n"))
	pending := []Change{
		{Name: "kernel-core", Architecture: "x86_64", CandidateVersion: "6.16.8-200.fc42"},
		{Name: "NetworkManager", Architecture: "x86_64", CandidateVersion: "1:1.52.2-1.fc42"},
		{Name: "docker-ce", Architecture: "x86_64", CandidateVersion: "3:27.3.1-1.fc42"},
	}
	changes, blocked, err := classifyPending(pending, types)
	if err != nil {
		t.Fatalf("the plan was refused although a security update was classified: %v", err)
	}
	if len(changes) != 1 || changes[0].Name != "kernel-core" || !changes[0].Security {
		t.Errorf("the changes of the plan = %+v", changes)
	}
	// A known bug fix is not a block: the host said what it is.
	if len(blocked) != 1 || blocked[0].Name != "docker-ce" {
		t.Fatalf("the blocked entries = %+v", blocked)
	}
	if !strings.Contains(blocked[0].Status, "no advisory") {
		t.Errorf("the block does not say why: %q", blocked[0].Status)
	}
}

// A plan that would change nothing and cannot classify what is pending reads
// as a clean host everywhere after it, so it is a refusal instead.
func TestDNFSecurityPlanRefusesWhenItWouldChangeNothing(t *testing.T) {
	types := ParseDNFUpdateinfoList("FEDORA-2026-2b3c4d5e6f bugfix  NetworkManager-1:1.52.2-1.fc42.x86_64")
	pending := []Change{
		{Name: "NetworkManager", Architecture: "x86_64"},
		{Name: "docker-ce", Architecture: "x86_64"},
	}
	_, _, err := classifyPending(pending, types)
	if err == nil {
		t.Fatal("a plan with nothing to change and an unclassified update was accepted")
	}
	if !errors.Is(err, ErrSecurityUnknown) || !strings.Contains(err.Error(), "docker-ce") {
		t.Errorf("the refusal = %v", err)
	}
	// A host whose pending updates are all known bug fixes is clean, not
	// unclassifiable: an empty plan there is the truth.
	changes, blocked, err := classifyPending(pending[:1], types)
	if err != nil || len(changes) != 0 || len(blocked) != 0 {
		t.Errorf("a host with only bug fixes pending = %+v, %+v, %v", changes, blocked, err)
	}
}

// A security-only order this host cannot classify is a refusal with the same
// code the Arch adapter uses, not a plan with nothing in it.
func TestDNFSecurityRefusalCarriesTheSharedCode(t *testing.T) {
	err := dnfSecurityUnknown{"no advisory of this host classifies docker-ce"}
	if !errors.Is(err, ErrSecurityUnknown) {
		t.Errorf("err = %v does not answer the shared sentinel", err)
	}
	if code, ok := ErrorCodeOf(err); !ok || code != ErrorSecurityUnknown {
		t.Errorf("the code of the refusal is %q", code)
	}
	if !Refused(err) {
		t.Error("the refusal was counted as a failed transaction")
	}
	if strings.Contains(err.Error(), "Arch") {
		t.Errorf("a refusal of a dnf host names Arch: %q", err.Error())
	}
}

// The plan of an order without the security filter is what it always was: the
// advisories are not read and nothing is marked out of the repository name.
func TestDNFPlanWithoutTheFilterMarksNoSecurity(t *testing.T) {
	var none DNFAdvisoryTypes
	if security, known := none.Security("kernel-core", "x86_64"); security || known {
		t.Errorf("an unread classification answered security %v, known %v", security, known)
	}
	change, ok := parseDNFUpdateLine("kernel-core.x86_64   6.16.8-200.fc42   updates-security")
	if !ok || change.Security {
		t.Errorf("the name of a repository classified the change: %+v", change)
	}
}
