// Package systemd is the adapter for systemd units. The root helper uses it,
// so the code is deliberately small and accepts no data it has not
// validated.
package systemd

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os/exec"
	"regexp"
	"strconv"
	"strings"
	"time"
)

const systemctlPath = "/usr/bin/systemctl"

// Operation is a typed operation on a unit. There is no "arbitrary systemctl
// command" operation.
type Operation string

const (
	OperationStart   Operation = "start"
	OperationStop    Operation = "stop"
	OperationRestart Operation = "restart"
	OperationReload  Operation = "reload"
)

// Known checks whether the operation is supported.
func (o Operation) Known() bool {
	switch o {
	case OperationStart, OperationStop, OperationRestart, OperationReload,
		OperationEnable, OperationDisable, OperationMask, OperationUnmask,
		OperationResetFail:
		return true
	default:
		return false
	}
}

var (
	// ErrProtectedUnit means a unit whose touching can cut the host off from
	// the control plane or stop the agent itself.
	ErrProtectedUnit = errors.New("protected unit")
	// ErrInvalidUnit means a name that is not a valid unit name.
	ErrInvalidUnit = errors.New("invalid unit name")

	// A unit name per systemd.unit(5): letters, digits and : _ . \ - @ plus
	// the required type suffix. The pattern rejects paths and shell
	// characters.
	unitPattern = regexp.MustCompile(
		`^[A-Za-z0-9:_.\\@-]+\.(service|socket|timer|target|path|mount|automount|swap|slice|scope)$`)

	// protectedUnits are the units a typed operation must not touch. Stopping
	// the agent would cut off the remote repair of the consequences, and
	// stopping sshd or the network would cut off the emergency way in.
	protectedUnits = map[string]struct{}{
		"flotestro-agent.service":         {},
		"flotestro-helper.service":        {},
		"flotestro-helper.socket":         {},
		"flotestro-control-plane.service": {},
		"sshd.service":                    {},
		"ssh.service":                     {},
		"sshd.socket":                     {},
		"systemd-networkd.service":        {},
		"NetworkManager.service":          {},
		"networking.service":              {},
		"systemd-journald.service":        {},
		"systemd-journald.socket":         {},
		"dbus.service":                    {},
		"dbus-broker.service":             {},
		"systemd-logind.service":          {},
		"local-fs.target":                 {},
		"remote-fs.target":                {},
	}
)

// ValidateUnit checks the unit name and the protection policy.
func ValidateUnit(unit string) error {
	if !unitPattern.MatchString(unit) {
		return fmt.Errorf("%w: %q", ErrInvalidUnit, unit)
	}
	if _, protected := protectedUnits[unit]; protected {
		return fmt.Errorf("%w: %q", ErrProtectedUnit, unit)
	}
	// Mount and swap units can cut the filesystem from under a running host,
	// so they are not available through this adapter.
	if strings.HasSuffix(unit, ".mount") || strings.HasSuffix(unit, ".swap") {
		return fmt.Errorf("%w: %q requires the separate storage module", ErrProtectedUnit, unit)
	}
	return nil
}

// IsProtected says whether the unit is on the protected list.
func IsProtected(unit string) bool {
	_, protected := protectedUnits[unit]
	return protected
}

// UnitState separates the states systemd tells apart. Thanks to that
// "active" does not hide a unit in an auto-restart loop.
type UnitState struct {
	Name          string `json:"name"`
	LoadState     string `json:"load_state"`
	ActiveState   string `json:"active_state"`
	SubState      string `json:"sub_state"`
	UnitFileState string `json:"unit_file_state"`
	Result        string `json:"result"`
	MainPID       uint32 `json:"main_pid"`
	NRestarts     uint32 `json:"n_restarts"`
}

// Healthy says whether the unit runs and is not in a restart loop.
func (u UnitState) Healthy() bool {
	return u.ActiveState == "active" && u.SubState != "auto-restart"
}

var shownProperties = []string{
	"Names", "LoadState", "ActiveState", "SubState", "UnitFileState",
	"Result", "MainPID", "NRestarts",
}

// Show reads the state of a unit. We use the key=value format, which is not
// translated, instead of the human-readable output of "systemctl status".
func Show(ctx context.Context, unit string) (UnitState, error) {
	if !unitPattern.MatchString(unit) {
		return UnitState{}, fmt.Errorf("%w: %q", ErrInvalidUnit, unit)
	}
	args := append([]string{"show", unit, "--no-pager"}, "--property="+strings.Join(shownProperties, ","))
	stdout, _, err := run(ctx, 15*time.Second, args...)
	if err != nil {
		return UnitState{}, err
	}

	state := UnitState{Name: unit}
	for _, line := range strings.Split(stdout, "\n") {
		key, value, found := strings.Cut(strings.TrimSpace(line), "=")
		if !found {
			continue
		}
		switch key {
		case "Names":
			if value != "" {
				state.Name = strings.Fields(value)[0]
			}
		case "LoadState":
			state.LoadState = value
		case "ActiveState":
			state.ActiveState = value
		case "SubState":
			state.SubState = value
		case "UnitFileState":
			state.UnitFileState = value
		case "Result":
			state.Result = value
		case "MainPID":
			state.MainPID = parseUint32(value)
		case "NRestarts":
			state.NRestarts = parseUint32(value)
		}
	}
	return state, nil
}

// Apply carries out an operation on a unit. The name is validated again
// right before execution, regardless of who sent it.
func Apply(ctx context.Context, unit string, operation Operation, timeout time.Duration) (stdout, stderr string, exitCode int, err error) {
	if !operation.Known() {
		return "", "", -1, fmt.Errorf("unknown operation %q", operation)
	}
	if err := ValidateUnit(unit); err != nil {
		return "", "", -1, err
	}
	out, errOut, err := run(ctx, timeout, applyArgs(unit, operation)...)
	code := 0
	var exitErr *exec.ExitError
	if errors.As(err, &exitErr) {
		code = exitErr.ExitCode()
		err = nil
	} else if err != nil {
		code = -1
	}
	return out, errOut, code, err
}

// applyArgs builds the arguments of the call. We deliberately do not pass
// --no-block: the operation is to finish before we read the unit's state,
// because otherwise the result would describe the state from before the
// change.
func applyArgs(unit string, operation Operation) []string {
	return []string{string(operation), unit, "--no-pager"}
}

// The stable error codes of unit operations. They come from systemctl's exit
// code, which is a stable interface, rather than from a translated
// message.
const (
	ErrorUnitNotFound   = "unit_not_found"
	ErrorUnitNotActive  = "unit_not_active"
	ErrorUnitActionFail = "unit_action_failed"
)

// ErrorCodeForExit translates systemctl's exit code into a stable error
// code. systemctl returns 4 and 5 for a unit that does not exist and 3 for an
// inactive unit; the rest is a general failure of the operation.
func ErrorCodeForExit(exitCode int) string {
	switch exitCode {
	case 0:
		return ""
	case 3:
		return ErrorUnitNotActive
	case 4, 5:
		return ErrorUnitNotFound
	default:
		return ErrorUnitActionFail
	}
}

// ScheduleReboot schedules a reboot of the host after the given delay.
// We use a transient systemd timer, because shutdown takes whole minutes and
// a campaign needs a dozen or so seconds to send the result back before the
// host disappears from the network.
func ScheduleReboot(ctx context.Context, delay time.Duration, reason string) (stdout, stderr string, exitCode int, err error) {
	return SchedulePower(ctx, delay, reason, "reboot")
}

// SchedulePower schedules a reboot or a shutdown of the host.
//
// The unit carries the panel's name, so on the host the operator sees that
// the order comes from here rather than being somebody's "shutdown -h" from a
// console.
//
// The logind inhibitors are checked higher up, in the helper: it is the one
// that knows whether the operator agreed to skip them, and it is the one to
// speak about them in the result.
func SchedulePower(ctx context.Context, delay time.Duration, reason, operation string) (stdout, stderr string, exitCode int, err error) {
	if delay < time.Second {
		delay = time.Second
	}
	// We aim at the target unit rather than at "systemctl poweroff": the
	// latter goes through logind, and logind asks polkit for consent. A
	// process in a systemd unit has no session, so polkit has nobody to ask
	// and answers "Access denied" - the unit dies a dozen seconds after the
	// panel has already reported success. Starting the target unit goes
	// straight to the manager, which trusts root, and performs the same
	// shutdown of the system. The logind inhibitors are checked by the helper
	// before we schedule anything.
	args := []string{
		"--collect",
		"--on-active=" + strconv.Itoa(int(delay.Seconds())) + "s",
		"--unit=flotestro-" + operation,
		"--description=" + reason,
		systemctlPath, "start", "--job-mode=replace-irreversibly", operation + ".target",
	}
	out, errOut, err := runTool(ctx, 30*time.Second, systemdRunPath, args...)
	code := 0
	var exitErr *exec.ExitError
	if errors.As(err, &exitErr) {
		code = exitErr.ExitCode()
		err = nil
	} else if err != nil {
		code = -1
	}
	return out, errOut, code, err
}

const systemdRunPath = "/usr/bin/systemd-run"

// run starts systemctl with a fixed path and an array of arguments. We never
// use sh -c, so a unit name cannot become a command.
func run(ctx context.Context, timeout time.Duration, args ...string) (string, string, error) {
	return runTool(ctx, timeout, systemctlPath, args...)
}

func runTool(ctx context.Context, timeout time.Duration, path string, args ...string) (string, string, error) {
	cmdCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	var stdout, stderr bytes.Buffer
	cmd := exec.CommandContext(cmdCtx, path, args...)
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	// LC_ALL=C stabilises the messages that end up in the task's result.
	cmd.Env = []string{"LC_ALL=C", "LANG=C", "PATH=/usr/sbin:/usr/bin:/sbin:/bin"}
	err := cmd.Run()
	if cmdCtx.Err() != nil {
		return stdout.String(), stderr.String(), cmdCtx.Err()
	}
	return stdout.String(), stderr.String(), err
}

func parseUint32(value string) uint32 {
	parsed, err := strconv.ParseUint(strings.TrimSpace(value), 10, 32)
	if err != nil {
		return 0
	}
	return uint32(parsed)
}

// OperationEnable and OperationMask are separate from start/stop, because
// they change what the host will do after a reboot rather than its state now.
// A unit that is enabled and a unit that is running are two different things;
// each has its own permission.
const (
	OperationEnable    Operation = "enable"
	OperationDisable   Operation = "disable"
	OperationMask      Operation = "mask"
	OperationUnmask    Operation = "unmask"
	OperationResetFail Operation = "reset-failed"
)

// maxUnits bounds the full list. A host with a thousand units is not an
// error, but moving all of them into the panel helps nobody more than the
// first few hundred do.
const maxUnits = 500

// Unit describes a unit on the list.
type Unit struct {
	Name        string `json:"name"`
	LoadState   string `json:"load_state"`
	ActiveState string `json:"active_state"`
	SubState    string `json:"sub_state"`
	Description string `json:"description,omitempty"`
	// UnitFileState says what the host will do after a reboot: enabled,
	// disabled, masked or static. Empty means a unit without a file.
	UnitFileState string `json:"unit_file_state,omitempty"`
}

// List returns the units loaded on the host.
//
// The list is fetched at the operator's request rather than in the inventory
// cycle: it changes often, it is long and it interests only whoever is
// looking at the tab right now.
func List(ctx context.Context) ([]Unit, bool, error) {
	stdout, _, err := run(ctx, 30*time.Second,
		"list-units", "--all", "--no-pager", "--no-legend", "--plain", "--type=service,socket,timer,target,path,mount")
	if err != nil {
		return nil, false, err
	}
	// The state of the unit files is a separate query: list-units does not
	// give it, and without it what the host will do after a reboot is not
	// visible.
	files := unitFileStates(ctx)

	var units []Unit
	for _, line := range strings.Split(stdout, "\n") {
		fields := strings.Fields(line)
		if len(fields) < 4 || !strings.Contains(fields[0], ".") {
			continue
		}
		unit := Unit{
			Name:          fields[0],
			LoadState:     fields[1],
			ActiveState:   fields[2],
			SubState:      fields[3],
			UnitFileState: files[fields[0]],
		}
		if len(fields) > 4 {
			unit.Description = strings.Join(fields[4:], " ")
		}
		units = append(units, unit)
		if len(units) >= maxUnits {
			// A truncated list is marked so that it does not look complete.
			return units, true, nil
		}
	}
	return units, false, nil
}

// unitFileStates reads what the host will do after a reboot. A failed read
// returns an empty map: not knowing about a unit file does not invalidate the
// unit's current state.
func unitFileStates(ctx context.Context) map[string]string {
	stdout, _, err := run(ctx, 30*time.Second, "list-unit-files", "--no-pager", "--no-legend", "--plain")
	if err != nil {
		return map[string]string{}
	}
	states := map[string]string{}
	for _, line := range strings.Split(stdout, "\n") {
		fields := strings.Fields(line)
		if len(fields) >= 2 {
			states[fields[0]] = fields[1]
		}
	}
	return states
}
