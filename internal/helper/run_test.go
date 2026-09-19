package helper

import (
	"context"
	"errors"
	"log/slog"
	"reflect"
	"sync/atomic"
	"testing"

	"github.com/ultherego/flotestro/internal/helper/runscope"
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
		log:      slog.New(slog.DiscardHandler),
		sequence: new(atomic.Uint64),
	}
	argv := []string{"/usr/bin/apt-get", "-o", "Dpkg::Options::=--force-confdef", "upgrade", "a b"}
	wrapped, scoped := runner.wrap("0b0e7a3e-0000-4000-8000-000000000001", opspec.FamilyPackages,
		opspec.ResourceLimits{CPUWeight: 50, IOWeight: 50, MemoryHighBytes: 512 << 20}, argv)
	if !scoped {
		t.Fatal("the operation was not scoped although systemd-run exists")
	}
	want := []string{
		"/usr/bin/systemd-run", "--scope", "--quiet",
		"--unit=flotestro-op-0b0e7a3e-0000-4000-8000-000000000001-1",
		"--description=Flotestro: packages operation",
		"--property=CollectMode=inactive-or-failed",
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
		"abc-123":      "flotestro-op-abc-123-7",
		"a b/c;d":      "flotestro-op-abcd-7",
		"":             "flotestro-op-unnamed-7",
		"../../evil\n": "flotestro-op-....evil-7",
	}
	for in, want := range cases {
		if got := scopeUnit(in, 7); got != want {
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

// TestScopeContextCarriesThePrefixOfTheRequest: the modules that start their
// own tools read the same prefix out of the context, and a family without
// limits leaves them a bare run.
func TestScopeContextCarriesThePrefixOfTheRequest(t *testing.T) {
	server := &Server{
		log: slog.New(slog.DiscardHandler),
		scopes: scopeRunner{
			lookPath: func(string) (string, error) { return "/usr/bin/systemd-run", nil },
			log:      slog.New(slog.DiscardHandler),
			sequence: new(atomic.Uint64),
		},
	}
	argv := []string{"/usr/bin/restic", "backup", "/srv"}

	ctx := server.scopeContext(context.Background(), "task-1", opspec.FamilyBackups)
	want := []string{
		"/usr/bin/systemd-run", "--scope", "--quiet",
		// The probe that decided on the scope took number 1; the first tool
		// is the second unit of the task.
		"--unit=flotestro-op-task-1-2",
		"--description=Flotestro: backups operation",
		"--property=CollectMode=inactive-or-failed",
		"--property=CPUWeight=30", "--property=IOWeight=30", "--property=MemoryHigh=1073741824",
		"--",
		"/usr/bin/restic", "backup", "/srv",
	}
	if got := runscope.Apply(ctx, argv); !reflect.DeepEqual(got, want) {
		t.Fatalf("argv = %q\nexpected %q", got, want)
	}
	// Two tools of the same operation do not share a backing array.
	first := runscope.Apply(ctx, []string{"/usr/bin/restic", "check"})
	second := runscope.Apply(ctx, []string{"/usr/bin/restic", "forget"})
	if first[len(first)-1] != "check" || second[len(second)-1] != "forget" {
		t.Fatalf("the tools were mixed up: %q and %q", first, second)
	}
	// Each tool has a unit of its own: systemd refuses a name that is
	// still loaded from the tool before, and a scope is collected late.
	if first[unitArgIndex] == second[unitArgIndex] {
		t.Fatalf("two tools of one task share the unit %q", first[unitArgIndex])
	}

	// A family without limits clears the scope, even one recorded higher up.
	bare := server.scopeContext(ctx, "task-1", opspec.FamilyStorage)
	if got := runscope.Apply(bare, argv); !reflect.DeepEqual(got, argv) {
		t.Fatalf("argv = %q, expected the plain %q", got, argv)
	}
}
