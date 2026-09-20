package systemd

import (
	"errors"
	"fmt"
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
	// The list of operations is closed: there is no "arbitrary systemctl command"
	// operation.
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
	// option takes no value.
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

// loadedLine is one row of "systemctl list-units --all --plain".
func loadedLine(name, active, sub, description string) string {
	return name + " loaded " + active + " " + sub + " " + description
}

func unitByName(units []Unit, name string) (Unit, bool) {
	for _, unit := range units {
		if unit.Name == name {
			return unit, true
		}
	}
	return Unit{}, false
}

func TestMergeUnitsShowsUnitFilesSystemdNeverLoaded(t *testing.T) {
	// A service that is installed and switched off is never loaded, and a list
	// without it cannot be told from a host that does not have it at all.
	listing := strings.Join([]string{
		loadedLine("cron.service", "active", "running", "Regular background program"),
		loadedLine("nginx.service", "failed", "failed", "A high performance web server"),
	}, "\n")
	files := map[string]string{
		"cron.service":    "enabled",
		"nginx.service":   "enabled",
		"apache2.service": "disabled",
	}
	units, truncated := mergeUnits(listing, files)
	if truncated {
		t.Error("a short list was reported as truncated")
	}
	if len(units) != 3 {
		t.Fatalf("units = %d, want 3: %+v", len(units), units)
	}
	// The list stays in name order, as the loaded listing alone used to be.
	if units[0].Name != "apache2.service" || units[1].Name != "cron.service" || units[2].Name != "nginx.service" {
		t.Errorf("the merged list is out of order: %+v", units)
	}
	// A loaded row keeps exactly what the host said about it.
	loaded, _ := unitByName(units, "cron.service")
	if loaded.LoadState != "loaded" || loaded.ActiveState != "active" || loaded.SubState != "running" ||
		loaded.UnitFileState != "enabled" || loaded.Description != "Regular background program" {
		t.Errorf("the loaded unit was changed: %+v", loaded)
	}
	// The never-loaded one has a file state and no invented runtime state.
	never, _ := unitByName(units, "apache2.service")
	if never.UnitFileState != "disabled" {
		t.Errorf("unit file state = %q, want disabled", never.UnitFileState)
	}
	if never.LoadState != StateUnknown || never.ActiveState != StateUnknown || never.SubState != StateUnknown {
		t.Errorf("a unit nobody loaded got a runtime state: %+v", never)
	}
}

func TestMergeUnitsLeavesTemplatesOut(t *testing.T) {
	// A template is a file, not a unit an operator can start; the instances
	// are the runnable ones, and an instance that runs is loaded anyway.
	files := map[string]string{
		"getty@.service":     "enabled",
		"user@.service":      "static",
		"getty@tty1.service": "enabled",
	}
	units, _ := mergeUnits("", files)
	for _, unit := range units {
		if strings.Contains(unit.Name, "@.") {
			t.Errorf("the template %q was listed as a unit", unit.Name)
		}
	}
	if _, found := unitByName(units, "getty@tty1.service"); !found {
		t.Error("the instance of a template is a unit and should be listed")
	}
}

func TestMergeUnitsIgnoresUnitFilesOfOtherTypes(t *testing.T) {
	// The unit files cover types the loaded listing does not ask for; a merge
	// that took them in would show slices and devices no one asked about.
	files := map[string]string{
		"user.slice":        "static",
		"session-1.scope":   "transient",
		"dev-sda.device":    "static",
		"swapfile.swap":     "generated",
		"backup.timer":      "disabled",
		"docker.socket":     "enabled",
		"srv-data.mount":    "generated",
		"multi-user.target": "static",
		"a-path.path":       "disabled",
	}
	units, _ := mergeUnits("", files)
	if len(units) != 5 {
		t.Fatalf("units = %+v, want only the listed types", units)
	}
	for _, unit := range units {
		if !listedType(unit.Name) {
			t.Errorf("the unit %q is not of a listed type", unit.Name)
		}
	}
}

func TestMergeUnitsKeepsLoadedUnitsWhenTruncating(t *testing.T) {
	// The limit has to fall on the units nobody loaded first: a running unit
	// dropped for a disabled unit file would be a worse list than before.
	var lines []string
	files := map[string]string{}
	for i := 0; i < maxUnits; i++ {
		name := fmt.Sprintf("loaded-%03d.service", i)
		lines = append(lines, loadedLine(name, "active", "running", "a loaded unit"))
		files[name] = "enabled"
	}
	files["aaa-never-loaded.service"] = "disabled"

	units, truncated := mergeUnits(strings.Join(lines, "\n"), files)
	if !truncated {
		t.Error("a list cut off by the limit was not marked truncated")
	}
	if len(units) != maxUnits {
		t.Fatalf("units = %d, want %d", len(units), maxUnits)
	}
	if _, found := unitByName(units, "aaa-never-loaded.service"); found {
		t.Error("a never-loaded unit took the place of a loaded one")
	}
}

func TestMergeUnitsDoesNotMarkAFullListTruncated(t *testing.T) {
	// Exactly as many units as the limit allows is a complete list.
	var lines []string
	for i := 0; i < maxUnits; i++ {
		lines = append(lines, loadedLine(fmt.Sprintf("loaded-%03d.service", i), "active", "running", "a loaded unit"))
	}
	units, truncated := mergeUnits(strings.Join(lines, "\n"), map[string]string{})
	if truncated || len(units) != maxUnits {
		t.Fatalf("units = %d, truncated = %v", len(units), truncated)
	}
}

func TestMergeUnitsTruncatesNeverLoadedUnitsInNameOrder(t *testing.T) {
	// Which units the limit lets through must not depend on the order a map
	// hands its keys out, or two reads of one host would disagree.
	files := map[string]string{}
	for i := 0; i < maxUnits+10; i++ {
		files[fmt.Sprintf("file-%03d.service", i)] = "disabled"
	}
	first, truncated := mergeUnits("", files)
	if !truncated {
		t.Error("a list cut off by the limit was not marked truncated")
	}
	second, _ := mergeUnits("", files)
	for i := range first {
		if first[i].Name != second[i].Name {
			t.Fatalf("two merges of the same host disagree at %d: %q vs %q", i, first[i].Name, second[i].Name)
		}
	}
	if first[len(first)-1].Name != fmt.Sprintf("file-%03d.service", maxUnits-1) {
		t.Errorf("the list was not cut in name order: last = %q", first[len(first)-1].Name)
	}
}
