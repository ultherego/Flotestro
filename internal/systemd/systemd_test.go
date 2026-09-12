package systemd

import (
	"errors"
	"strings"
	"testing"
)

func TestValidateUnitRejectsInjections(t *testing.T) {
	// A unit name is never interpreted by a shell, but validation is a second
	// line of defence and has to reject such shapes outright.
	invalid := []string{
		"",
		"nginx",                         // no type suffix
		"../../etc/passwd",              // a path
		"nginx.service; rm -rf /",       // a command separator
		"nginx.service && reboot",       // command chaining
		"$(reboot).service",             // command substitution
		"`reboot`.service",              // command substitution
		"nginx.service\nrestart",        // a newline
		"nginx.conf",                    // an unknown unit type
		"/etc/systemd/system/x.service", // an absolute path
	}
	for _, unit := range invalid {
		if err := ValidateUnit(unit); err == nil {
			t.Errorf("the invalid name %q was accepted", unit)
		}
	}
}

func TestValidateUnitAcceptsValidNames(t *testing.T) {
	valid := []string{
		"nginx.service",
		"getty@tty1.service",
		"my-app.service",
		"backup.timer",
		"app.socket",
		"multi-user.target",
	}
	for _, unit := range valid {
		if err := ValidateUnit(unit); err != nil {
			t.Errorf("the valid name %q was rejected: %v", unit, err)
		}
	}
}

func TestValidateUnitProtectsCriticalUnits(t *testing.T) {
	// Stopping these units would cut off the way to repair the host.
	protected := []string{
		"flotestro-agent.service",
		"sshd.service",
		"ssh.service",
		"NetworkManager.service",
		"systemd-networkd.service",
		"systemd-journald.service",
	}
	for _, unit := range protected {
		err := ValidateUnit(unit)
		if err == nil {
			t.Errorf("the protected unit %q was allowed", unit)
			continue
		}
		if !errors.Is(err, ErrProtectedUnit) {
			t.Errorf("for %q ErrProtectedUnit was expected, got %v", unit, err)
		}
		if !IsProtected(unit) {
			t.Errorf("IsProtected(%q) = false", unit)
		}
	}
}

func TestValidateUnitBlocksMountsAndSwap(t *testing.T) {
	// Unmounting a filesystem from under a running host belongs to the
	// storage module, which requires a preflight and an emergency way out.
	for _, unit := range []string{"srv-data.mount", "swapfile.swap"} {
		err := ValidateUnit(unit)
		if err == nil || !errors.Is(err, ErrProtectedUnit) {
			t.Errorf("%q was allowed: %v", unit, err)
		}
	}
}

func TestOperationKnown(t *testing.T) {
	for _, op := range []Operation{
		OperationStart, OperationStop, OperationRestart, OperationReload,
		OperationEnable, OperationDisable, OperationMask, OperationUnmask,
		OperationResetFail,
	} {
		if !op.Known() {
			t.Errorf("%s should be known", op)
		}
	}
	// The list of operations is closed: there is no "arbitrary systemctl
	// command" operation. Isolate changes the target of the whole system,
	// kill sends an arbitrary signal, daemon-reexec restarts pid 1 - none of
	// them is an operation on a unit.
	for _, op := range []Operation{"", "daemon-reexec", "isolate", "kill", "set-property"} {
		if Operation(op).Known() {
			t.Errorf("the unsupported operation %q was accepted", op)
		}
	}
}

func TestUnitStateHealthyTellsARestartLoopApart(t *testing.T) {
	// "active" must not hide a unit that is restarting over and over.
	looping := UnitState{ActiveState: "active", SubState: "auto-restart"}
	if looping.Healthy() {
		t.Error("a unit in an auto-restart loop was treated as healthy")
	}
	running := UnitState{ActiveState: "active", SubState: "running"}
	if !running.Healthy() {
		t.Error("a running unit was treated as unhealthy")
	}
	failed := UnitState{ActiveState: "failed", SubState: "failed"}
	if failed.Healthy() {
		t.Error("a failed unit was treated as healthy")
	}
}

func TestShownPropertiesAreComplete(t *testing.T) {
	// A missing property in the query would mean a silent zero in the task's
	// result.
	required := []string{"ActiveState", "SubState", "UnitFileState", "Result", "NRestarts"}
	joined := strings.Join(shownProperties, ",")
	for _, property := range required {
		if !strings.Contains(joined, property) {
			t.Errorf("the property %s is missing from the query to systemd", property)
		}
	}
}

func TestApplyArgsPassesNoArgumentToNoBlock(t *testing.T) {
	// A regression: "--no-block=false" is rejected by systemctl, because that
	// option takes no value. The whole call then ended with code 1, although
	// the unit was fine.
	args := applyArgs("nginx.service", OperationRestart)
	for _, arg := range args {
		if strings.HasPrefix(arg, "--no-block=") {
			t.Fatalf("the --no-block option got an argument: %q", arg)
		}
	}
	if args[0] != "restart" || args[1] != "nginx.service" {
		t.Fatalf("unexpected arguments: %v", args)
	}
	// The absence of --no-block is deliberate: we have to learn the result of the operation.
	for _, arg := range args {
		if arg == "--no-block" {
			t.Fatal("--no-block makes the state after the operation be read too early")
		}
	}
}
