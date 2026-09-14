package helper

import (
	"errors"
	"log/slog"
	"reflect"
	"testing"

	"github.com/ultherego/flotestro/internal/opspec"
)

// TestScopeWrapsTheSameArgvUnderSystemdRun: the tool and its arguments reach
// the process unchanged, only prefixed with the scope - no shell in between.
func TestScopeWrapsTheSameArgvUnderSystemdRun(t *testing.T) {
	runner := scopeRunner{
		lookPath: func(file string) (string, error) {
			if file != "systemd-run" {
				t.Fatalf("looked up %q, expected systemd-run", file)
			}
			return "/usr/bin/systemd-run", nil
		},
		log: slog.New(slog.DiscardHandler),
	}
	argv := []string{"/usr/bin/apt-get", "-o", "Dpkg::Options::=--force-confdef", "upgrade", "a b"}
	wrapped, scoped := runner.wrap("0b0e7a3e-0000-4000-8000-000000000001", opspec.FamilyPackages,
		opspec.ResourceLimits{CPUWeight: 50, IOWeight: 50, MemoryHighBytes: 512 << 20}, argv)
	if !scoped {
		t.Fatal("the operation was not scoped although systemd-run exists")
	}
	want := []string{
		"/usr/bin/systemd-run", "--scope", "--quiet",
		"--unit=flotestro-op-0b0e7a3e-0000-4000-8000-000000000001",
		"--description=Flotestro: packages operation",
		"--property=CPUWeight=50", "--property=IOWeight=50", "--property=MemoryHigh=536870912",
		"--",
		"/usr/bin/apt-get", "-o", "Dpkg::Options::=--force-confdef", "upgrade", "a b",
	}
	if !reflect.DeepEqual(wrapped, want) {
		t.Fatalf("argv = %q\nexpected %q", wrapped, want)
	}
	// The original array is not touched: the caller may still use it.
	if argv[0] != "/usr/bin/apt-get" || len(argv) != 5 {
		t.Fatalf("the original argv was changed: %q", argv)
	}
}

// TestScopeFallsBackWithoutSystemdRun: a host without the tool runs the
// same argv plainly, and says why.
func TestScopeFallsBackWithoutSystemdRun(t *testing.T) {
	runner := scopeRunner{
		lookPath: func(string) (string, error) { return "", errors.New("not found") },
		log:      slog.New(slog.DiscardHandler),
	}
	argv := []string{"/usr/bin/restic", "backup", "/srv"}
	wrapped, scoped := runner.wrap("task", opspec.FamilyBackups, opspec.FamilyLimits(opspec.FamilyBackups), argv)
	if scoped {
		t.Fatal("the operation was scoped without systemd-run")
	}
	if !reflect.DeepEqual(wrapped, argv) {
		t.Fatalf("argv = %q, expected the plain %q", wrapped, argv)
	}
}

// TestScopeIsSkippedWhenNobodyAsked: empty limits mean a plain run, and the
// path is not even looked up.
func TestScopeIsSkippedWhenNobodyAsked(t *testing.T) {
	runner := scopeRunner{
		lookPath: func(string) (string, error) {
			t.Fatal("systemd-run was looked up for an operation without limits")
			return "", nil
		},
	}
	argv := []string{"/usr/sbin/fsck", "-n", "/dev/sdb1"}
	wrapped, scoped := runner.wrap("task", opspec.FamilyStorage, opspec.FamilyLimits(opspec.FamilyStorage), argv)
	if scoped || !reflect.DeepEqual(wrapped, argv) {
		t.Fatalf("argv = %q, scoped = %v; expected the plain argv", wrapped, scoped)
	}
}

// TestScopeUnitNameIsFiltered: the identifier arrives from the network, so
// only what a unit name takes gets into it.
func TestScopeUnitNameIsFiltered(t *testing.T) {
	cases := map[string]string{
		"abc-123":      "flotestro-op-abc-123",
		"a b/c;d":      "flotestro-op-abcd",
		"":             "flotestro-op-unnamed",
		"../../evil\n": "flotestro-op-....evil",
	}
	for in, want := range cases {
		if got := scopeUnit(in); got != want {
			t.Errorf("scopeUnit(%q) = %q, expected %q", in, got, want)
		}
	}
}

// TestFamilyLimitsTable guards the numbers the panel and the host share.
func TestFamilyLimitsTable(t *testing.T) {
	packages := opspec.ActionPackageUpgrade.ResourceLimits()
	if packages != (opspec.ResourceLimits{CPUWeight: 50, IOWeight: 50, MemoryHighBytes: 512 << 20}) {
		t.Errorf("packages limits = %+v", packages)
	}
	backups := opspec.ActionBackupRun.ResourceLimits()
	if backups != (opspec.ResourceLimits{CPUWeight: 30, IOWeight: 30, MemoryHighBytes: 1 << 30}) {
		t.Errorf("backups limits = %+v", backups)
	}
	if !opspec.ActionUnitRestart.ResourceLimits().Empty() {
		t.Error("a unit restart has a resource scope")
	}
	if !opspec.ActionFilesystemCheck.ResourceLimits().Empty() {
		t.Error("a filesystem check has a resource scope by default")
	}
}
