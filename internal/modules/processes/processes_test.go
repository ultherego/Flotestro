package processes

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// The process name is in parentheses and may contain spaces and parentheses
// themselves. Splitting the whole line on spaces would give wrong fields for
// such names - and the start time, which guards against PID reuse, depends
// on them.
func TestParseStatHandlesNameWithSpaces(t *testing.T) {
	line := "1234 (my program (test)) S 1 1234 1234 0 -1 4194304 100 0 0 0 " +
		"11 22 0 0 20 0 7 0 987654 12345678 1000 " + strings.Repeat("0 ", 20)

	process, ok := parseStat(line)
	if !ok {
		t.Fatal("process state not read")
	}
	if process.Name != "my program (test)" {
		t.Errorf("name = %q", process.Name)
	}
	if process.State != "S" || process.PPID != 1 {
		t.Errorf("state = %q, ppid = %d", process.State, process.PPID)
	}
	if process.CPUTicks != 33 {
		t.Errorf("cpu time = %d, want 33 (11 + 22)", process.CPUTicks)
	}
	if process.Threads != 7 {
		t.Errorf("threads = %d", process.Threads)
	}
	if process.StartTimeTicks != 987654 {
		t.Errorf("start time = %d", process.StartTimeTicks)
	}
}

// The PID alone does not identify a process: the kernel reuses numbers. A
// signal sent after viewing the list could hit something entirely different.
func TestSignalRefusesOnDifferentStartTime(t *testing.T) {
	root := makeProc(t, 4242, 111111)

	err := Send(root, 4242, 999999, SignalTERM, Protected{})
	if err == nil {
		t.Fatal("signal went through despite a different start time")
	}
	if !strings.Contains(err.Error(), "different process") {
		t.Errorf("error = %v", err)
	}
}

// The signal list is closed: there is no "send any signal" operation.
func TestUnknownSignalIsRejected(t *testing.T) {
	root := makeProc(t, 4242, 111111)
	for _, signal := range []string{"STOP", "SEGV", "USR1", "", "9"} {
		if KnownSignal(signal) {
			t.Errorf("signal %q considered supported", signal)
		}
		if err := Send(root, 4242, 111111, signal, Protected{}); err == nil {
			t.Errorf("signal %q was sent", signal)
		}
	}
}

// Killing the init process ends the host, and killing the agent cuts it off
// from the panel - and therefore from repairing what has just been broken.
func TestProtectedProcessesAreRejected(t *testing.T) {
	root := makeProc(t, 4242, 111111)

	if err := Send(root, 1, 0, SignalTERM, Protected{}); err == nil {
		t.Error("signal sent to PID 1")
	}
	if err := Send(root, 4242, 111111, SignalKILL, Protected{Own: []int32{4242}}); err == nil {
		t.Error("signal sent to the agent's own process")
	}
}

// The cgroup says what manages the process. An operator seeing only a PID
// would have to guess whose it is.
func TestOwnerFromCgroup(t *testing.T) {
	unit, container := ownerFromCgroup("0::/system.slice/nginx.service\n")
	if unit != "nginx.service" || container != "" {
		t.Errorf("unit = %q, container = %q", unit, container)
	}

	unit, container = ownerFromCgroup(
		"0::/system.slice/docker-5c5b63d3119a59ac7a7a7f2a18342dbd.scope\n")
	if container != "5c5b63d3119a59ac7a7a7f2a18342dbd" {
		t.Errorf("container = %q", container)
	}
	if unit != "" {
		t.Errorf("container was also taken for a unit: %q", unit)
	}
}

// The snapshot has an upper bound, but must say how many processes it hides.
func TestSnapshotReportsTruncation(t *testing.T) {
	root := t.TempDir()
	for pid := 100; pid < 110; pid++ {
		writeProc(t, root, pid, uint64(pid*1000))
	}

	snapshot := Collect(root, SortByPID, 4)
	if snapshot.Total != 10 {
		t.Errorf("total = %d, want 10", snapshot.Total)
	}
	if len(snapshot.Processes) != 4 {
		t.Errorf("returned %d processes, want 4", len(snapshot.Processes))
	}
	if !snapshot.Truncated {
		t.Error("truncation not flagged")
	}
	if snapshot.Processes[0].PID != 100 {
		t.Errorf("sorting by PID did not work: %d", snapshot.Processes[0].PID)
	}
}

func makeProc(t *testing.T, pid int, start uint64) string {
	t.Helper()
	root := t.TempDir()
	writeProc(t, root, pid, start)
	return root
}

func writeProc(t *testing.T, root string, pid int, start uint64) {
	t.Helper()
	dir := filepath.Join(root, itoa(pid))
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	line := itoa(pid) + " (test) S 1 1 1 0 -1 0 0 0 0 0 1 2 0 0 20 0 1 0 " +
		utoa(start) + " 0 100 " + strings.Repeat("0 ", 20)
	if err := os.WriteFile(filepath.Join(dir, "stat"), []byte(line), 0o644); err != nil {
		t.Fatal(err)
	}
}

func itoa(value int) string { return utoa(uint64(value)) }
func utoa(value uint64) string {
	if value == 0 {
		return "0"
	}
	var digits []byte
	for value > 0 {
		digits = append([]byte{byte('0' + value%10)}, digits...)
		value /= 10
	}
	return string(digits)
}
