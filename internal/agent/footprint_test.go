package agent

import (
	"context"
	"math"
	"os"
	"path/filepath"
	"strconv"
	"testing"
	"time"
)

// The status file of a process as the kernel prints it; the fields around
// VmRSS are there so the parser has to find the right line.
const statusFixture = "Name:\tflotestro-agent\n" +
	"Umask:\t0022\n" +
	"State:\tS (sleeping)\n" +
	"Pid:\t4242\n" +
	"VmPeak:\t 1234567 kB\n" +
	"VmSize:\t 1200000 kB\n" +
	"VmRSS:\t   34568 kB\n" +
	"RssAnon:\t   20000 kB\n" +
	"Threads:\t12\n"

// The stat line of a process whose name has a space and a parenthesis in it:
// the fields are counted from the last closing parenthesis, or utime would
// land on the wrong column.
func statFixture(utime, stime uint64) string {
	return "4242 (flotestro (agent) v0) S 1 4242 4242 0 -1 4194560 2000 0 0 0 " +
		strconv.FormatUint(utime, 10) + " " + strconv.FormatUint(stime, 10) + " 0 0 20 0 12 0 12345 1228800000 8642 18446744073709551615 1 1 0 0 0 0 0 0 0 0 0 0 17 3 0 0 0 0 0\n"
}

func TestParseVmRSSReadsKilobytesAsBytes(t *testing.T) {
	rss, ok := parseVmRSS(statusFixture)
	if !ok || rss != 34568*1024 {
		t.Errorf("VmRSS = %d, %v; want %d", rss, ok, 34568*1024)
	}
	// A process that swapped out entirely, or a status without the line,
	// has no resident size to report.
	if _, ok := parseVmRSS("Name:\tx\nVmSize:\t 10 kB\n"); ok {
		t.Error("a status without VmRSS gave a value")
	}
	if _, ok := parseVmRSS("VmRSS:\n"); ok {
		t.Error("an empty VmRSS gave a value")
	}
}

func TestParseProcessTicksCountsFromTheCommandName(t *testing.T) {
	ticks, ok := parseProcessTicks(statFixture(150, 50))
	if !ok || ticks != 200 {
		t.Errorf("utime+stime = %d, %v; want 200", ticks, ok)
	}
	if _, ok := parseProcessTicks("4242 (short) S 1 2 3\n"); ok {
		t.Error("a truncated stat line gave a value")
	}
	if _, ok := parseProcessTicks(""); ok {
		t.Error("an empty stat line gave a value")
	}
}

func TestParseMainPIDReadsTheSystemctlLine(t *testing.T) {
	pid, err := parseMainPID("MainPID=1234\n")
	if err != nil || pid != 1234 {
		t.Errorf("MainPID = %d, %v", pid, err)
	}
	// Zero is what systemd prints for a unit that is not running; the
	// caller treats it as no PID, and this parser as the number it is.
	pid, err = parseMainPID("MainPID=0\n")
	if err != nil || pid != 0 {
		t.Errorf("MainPID of a stopped unit = %d, %v", pid, err)
	}
	if _, err := parseMainPID("ActiveState=inactive\n"); err == nil {
		t.Error("an output without MainPID parsed")
	}
}

// selfFixture adds the agent's own procfs files to a host fixture: the
// status, the stat line and a set of descriptors.
func selfFixture(t *testing.T, root string, stat string, fds int) {
	t.Helper()
	self := filepath.Join(root, "self")
	if err := os.MkdirAll(filepath.Join(self, "fd"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(self, "status"), []byte(statusFixture), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(self, "stat"), []byte(stat), 0o644); err != nil {
		t.Fatal(err)
	}
	for i := 0; i < fds; i++ {
		if err := os.WriteFile(filepath.Join(self, "fd", strconv.Itoa(i)), nil, 0o644); err != nil {
			t.Fatal(err)
		}
	}
}

func TestFootprintRidesAlongWithTheSample(t *testing.T) {
	root := procFixture(t, "cpu 100 0 50 800 20 0 5 25 0 0")
	selfFixture(t, root, statFixture(100, 20), 7)
	// The helper's status under its PID, as systemd would name it.
	helper := filepath.Join(root, "777")
	if err := os.MkdirAll(helper, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(helper, "status"), []byte("Name:\tflotestro-agent-helper\nVmRSS:\t   9000 kB\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	sampler := fixtureSampler(t, root)
	sampler.HelperPID = func(context.Context) (int, bool) { return 777, true }

	first, err := sampler.Sample()
	if err != nil {
		t.Fatalf("first sample: %v", err)
	}
	if first.AgentRssBytes == nil || *first.AgentRssBytes != 34568*1024 {
		t.Errorf("agent_rss_bytes = %v", first.AgentRssBytes)
	}
	// The first reading has no interval to measure the CPU over: the
	// field is absent, not zero.
	if first.AgentCpuPercent != nil {
		t.Errorf("agent_cpu_percent on the first sample = %v, want absent", *first.AgentCpuPercent)
	}
	if first.AgentGoroutines == nil || *first.AgentGoroutines == 0 {
		t.Errorf("agent_goroutines = %v", first.AgentGoroutines)
	}
	if first.AgentOpenFds == nil || *first.AgentOpenFds != 7 {
		t.Errorf("agent_open_fds = %v, want 7", first.AgentOpenFds)
	}
	if first.HelperRssBytes == nil || *first.HelperRssBytes != 9000*1024 {
		t.Errorf("helper_rss_bytes = %v", first.HelperRssBytes)
	}

	// Sixty seconds later the process spent 180 more ticks: 1.8 s of one
	// core over a minute is three per cent.
	later := sampler.Now().Add(60 * time.Second)
	sampler.Now = func() time.Time { return later }
	if err := os.WriteFile(filepath.Join(root, "self", "stat"), []byte(statFixture(250, 50)), 0o644); err != nil {
		t.Fatal(err)
	}
	second, err := sampler.Sample()
	if err != nil {
		t.Fatalf("second sample: %v", err)
	}
	if second.AgentCpuPercent == nil || math.Abs(*second.AgentCpuPercent-3) > 0.01 {
		t.Errorf("agent_cpu_percent = %v, want 3", second.AgentCpuPercent)
	}
}

func TestFootprintLeavesOutWhatItCannotRead(t *testing.T) {
	// A procfs without the self directory: the host counters are there, the
	// agent's own are not.
	root := procFixture(t, "cpu 100 0 50 800 20 0 5 25 0 0")
	sampler := fixtureSampler(t, root)
	// A helper that systemd says is not running.
	sampler.HelperPID = func(context.Context) (int, bool) { return 0, false }
	sample, err := sampler.Sample()
	if err != nil {
		t.Fatalf("sample: %v", err)
	}
	if sample.AgentRssBytes != nil || sample.AgentCpuPercent != nil || sample.AgentOpenFds != nil {
		t.Errorf("unreadable footprint reported as rss %v cpu %v fds %v",
			sample.AgentRssBytes, sample.AgentCpuPercent, sample.AgentOpenFds)
	}
	if sample.HelperRssBytes != nil {
		t.Errorf("a stopped helper reported rss %v", *sample.HelperRssBytes)
	}
	// The goroutine count comes from the runtime, not from procfs, so it
	// is the one figure still there.
	if sample.AgentGoroutines == nil {
		t.Error("agent_goroutines is absent")
	}
}

// TestTheAgentHandsBackWhatItNoLongerUses: a sample above the release
// threshold frees the pages once and reports what the host sees afterwards.
func TestTheAgentHandsBackWhatItNoLongerUses(t *testing.T) {
	root := procFixture(t, "cpu 100 0 50 800 20 0 5 25 0 0")
	selfFixture(t, root, statFixture(100, 20), 7)
	sampler := fixtureSampler(t, root)
	released := 0
	sampler.Release = func() {
		released++
		// The release gives the pages back: the host now sees less.
		status := "Name:\tflotestro-agent\nVmRSS:\t   18000 kB\nThreads:\t12\n"
		if err := os.WriteFile(filepath.Join(root, "self", "status"), []byte(status), 0o644); err != nil {
			t.Fatal(err)
		}
	}

	first, err := sampler.Sample()
	if err != nil {
		t.Fatalf("first sample: %v", err)
	}
	if released != 1 {
		t.Errorf("the agent freed %d times at %d bytes resident, want once", released, 34568*1024)
	}
	if first.AgentRssBytes == nil || *first.AgentRssBytes != 18000*1024 {
		t.Errorf("agent_rss_bytes = %v; the sample must say what the host sees after the release", first.AgentRssBytes)
	}

	// A minute later the agent is small: nothing to hand back.
	base := time.Date(2026, 9, 13, 12, 0, 0, 0, time.UTC)
	sampler.Now = func() time.Time { return base.Add(time.Minute) }
	if _, err := sampler.Sample(); err != nil {
		t.Fatalf("second sample: %v", err)
	}
	if released != 1 {
		t.Errorf("the agent freed %d times, want once: below the threshold it has nothing to hand back", released)
	}

	// It grows again within the same five minutes: the release waits, so
	// a burst of tasks is not paid for with a collection every minute.
	if err := os.WriteFile(filepath.Join(root, "self", "status"), []byte(statusFixture), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := sampler.Sample(); err != nil {
		t.Fatalf("third sample: %v", err)
	}
	if released != 1 {
		t.Errorf("the agent freed %d times within five minutes, want once", released)
	}
}
