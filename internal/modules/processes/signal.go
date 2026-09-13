package processes

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
)

// Signals allowed by the module. The list is closed: there is no "send any
// signal" operation. Signals that stop a process or change its behaviour in
// a way that is hard to undo do not belong to diagnostics.
const (
	SignalTERM = "TERM"
	SignalKILL = "KILL"
	SignalHUP  = "HUP"
)

var signalNumbers = map[string]syscall.Signal{
	SignalTERM: syscall.SIGTERM,
	SignalKILL: syscall.SIGKILL,
	SignalHUP:  syscall.SIGHUP,
}

var (
	// ErrUnknownSignal means a signal outside the closed list.
	ErrUnknownSignal = errors.New("unsupported signal")
	// ErrProtectedProcess means a process whose killing would cut the host
	// off from management or stop the whole system.
	ErrProtectedProcess = errors.New("protected process")
	// ErrProcessChanged means a PID reused by the kernel.
	ErrProcessChanged = errors.New("a different process is already running under this PID")
)

// KnownSignal checks whether the signal is supported.
func KnownSignal(name string) bool {
	_, ok := signalNumbers[name]
	return ok
}

// Protected describes the processes that must not be touched.
type Protected struct {
	// PIDs of our own processes: the agent and the helper. Killing either
	// would cut the host off from the panel, and therefore also from
	// repairing what has just been broken.
	Own []int32
}

// Send sends a signal to a process bound to its start time.
//
// The PID alone does not identify a process: the kernel reuses numbers, so a
// signal sent a moment after viewing the list may hit something entirely
// different from what the operator intended. That is why the start time is
// checked right before sending.
func Send(root string, pid int32, expectedStart uint64, signal string, protected Protected) error {
	number, ok := signalNumbers[signal]
	if !ok {
		return fmt.Errorf("%w: %s", ErrUnknownSignal, signal)
	}
	if pid <= 1 {
		// PID 1 is the init system: stopping it ends the whole host.
		return fmt.Errorf("%w: PID %d", ErrProtectedProcess, pid)
	}
	for _, own := range protected.Own {
		if pid == own {
			return fmt.Errorf("%w: PID %d belongs to the management agent", ErrProtectedProcess, pid)
		}
	}

	current, err := processStart(root, pid)
	if err != nil {
		return err
	}
	if expectedStart != 0 && current != expectedStart {
		return fmt.Errorf("%w: PID %d", ErrProcessChanged, pid)
	}
	return syscall.Kill(int(pid), number)
}

// processStart reads the process start time.
func processStart(root string, pid int32) (uint64, error) {
	if root == "" {
		root = "/proc"
	}
	data, err := os.ReadFile(filepath.Join(root, strconv.FormatInt(int64(pid), 10), "stat"))
	if err != nil {
		return 0, fmt.Errorf("process %d does not exist", pid)
	}
	process, ok := parseStat(string(data))
	if !ok {
		return 0, fmt.Errorf("unreadable state of process %d", pid)
	}
	return process.StartTimeTicks, nil
}

// OwnPIDs returns the PIDs of the processes the module must not kill: itself
// and its parent. The helper is started by systemd, so its parent is pid 1 -
// protected separately.
func OwnPIDs() []int32 {
	return []int32{int32(os.Getpid()), int32(os.Getppid())}
}

// DescribeSignal translates a signal into a sentence for the operator.
func DescribeSignal(signal string) string {
	switch strings.ToUpper(signal) {
	case SignalTERM:
		return "request to terminate"
	case SignalKILL:
		return "forced kill with no chance to clean up"
	case SignalHUP:
		return "configuration reload"
	}
	return signal
}
