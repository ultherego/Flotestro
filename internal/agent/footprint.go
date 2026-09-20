package agent

import (
	"bufio"
	"context"
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"runtime/debug"
	"strconv"
	"strings"
	"sync"
	"time"
)

// The agent measures itself the way it measures the host: from procfs, once a
// minute, into the same sample.

const (
	// helperUnit is the systemd unit of the root helper.
	helperUnit = "flotestro-helper.service"
	// userHz is the unit of the CPU times in /proc/[pid]/stat.
	userHz = 100
)

// Footprint is what the agent knows about its own cost on the host. A nil
// field is a value that could not be read.
type Footprint struct {
	RSSBytes       *uint64
	CPUPercent     *float64
	Goroutines     *uint32
	OpenFDs        *uint32
	HelperRSSBytes *uint64
}

// mayRelease says whether enough time has passed since the last release.
// The sampler is the only caller, so the clock of the sample decides.
func (s *Sampler) mayRelease() bool {
	now := s.Now()
	if !s.releasedAt.IsZero() && now.Sub(s.releasedAt) < releaseEvery {
		return false
	}
	s.releasedAt = now
	return true
}

// release hands the free pages back to the host. Replaced in tests.
func (s *Sampler) release() {
	if s.Release != nil {
		s.Release()
		return
	}
	debug.FreeOSMemory()
}

// processCPU is a snapshot of the busy time of a process: the CPU counter
// in USER_HZ ticks and the moment it was read.
type processCPU struct {
	ticks uint64
	at    time.Time
}

// releaseThreshold is the resident size past which the agent hands the pages
// it no longer uses back to the host.
const (
	releaseThreshold = 24 << 20
	// releaseUrgent is where holding the pages costs more than the collection
	// that hands them back. A large read - the package list of a Debian host -
	// leaves the process here, and waiting out the ordinary interval keeps it
	// near the budget for as long as the tasks keep arriving.
	releaseUrgent    = 28 << 20
	releaseEvery     = 5 * time.Minute
	taskReleaseEvery = 30 * time.Second
	// taskReleaseFloor bounds the forced collections when task after task
	// leaves the process above releaseUrgent: prompt, but not every task.
	taskReleaseFloor = 5 * time.Second
)

// pagesHeld reads what this process holds, and whether it could be read.
func pagesHeld(procRoot string) (uint64, bool) {
	data, err := os.ReadFile(filepath.Join(procRoot, "self", "status"))
	if err != nil {
		return 0, false
	}
	return parseVmRSS(string(data))
}

// releaseInterval is how long a finished task waits before handing the pages
// back again. Close to the budget it is the floor rather than the interval.
func releaseInterval(rss uint64) time.Duration {
	if rss >= releaseUrgent {
		return taskReleaseFloor
	}
	return taskReleaseEvery
}

// taskRelease is the release after a task. It is its own clock, so the
// sampler's rhythm and the tasks' do not cancel each other out.
var taskRelease struct {
	mu sync.Mutex
	at time.Time
}

// releaseAfterTask hands back what a finished task no longer needs.
func releaseAfterTask() {
	rss, ok := pagesHeld("/proc")
	if !ok || rss < releaseThreshold {
		return
	}
	taskRelease.mu.Lock()
	now := time.Now()
	if !taskRelease.at.IsZero() && now.Sub(taskRelease.at) < releaseInterval(rss) {
		taskRelease.mu.Unlock()
		return
	}
	taskRelease.at = now
	taskRelease.mu.Unlock()
	debug.FreeOSMemory()
}

// footprint reads the agent's own numbers.
func (s *Sampler) footprint(ctx context.Context) Footprint {
	var fp Footprint
	self := filepath.Join(s.ProcRoot, "self")

	if data, err := os.ReadFile(filepath.Join(self, "status")); err == nil {
		if rss, ok := parseVmRSS(string(data)); ok {
			fp.RSSBytes = &rss
		}
	}
	if rss := fp.RSSBytes; rss != nil && *rss >= releaseThreshold && s.mayRelease() {
		s.release()
		if data, err := os.ReadFile(filepath.Join(self, "status")); err == nil {
			if released, ok := parseVmRSS(string(data)); ok {
				fp.RSSBytes = &released
			}
		}
	}

	fp.CPUPercent = s.readProcessCPU(filepath.Join(self, "stat"))

	// The runtime knows its goroutines; a count is always available and
	// says whether a task handler was left behind.
	goroutines := uint32(runtime.NumGoroutine())
	fp.Goroutines = &goroutines

	if count, ok := countOpenFDs(filepath.Join(self, "fd")); ok {
		fp.OpenFDs = &count
	}

	if s.HelperPID != nil {
		if pid, ok := s.HelperPID(ctx); ok {
			if data, err := os.ReadFile(filepath.Join(s.ProcRoot, strconv.Itoa(pid), "status")); err == nil {
				if rss, ok := parseVmRSS(string(data)); ok {
					fp.HelperRSSBytes = &rss
				}
			}
		}
	}
	return fp
}

// readProcessCPU returns the busy percentage of the process since the previous
// snapshot, as a share of one core, and stores the current one.
func (s *Sampler) readProcessCPU(statPath string) *float64 {
	data, err := os.ReadFile(statPath)
	if err != nil {
		return nil
	}
	ticks, ok := parseProcessTicks(string(data))
	if !ok {
		return nil
	}
	current := processCPU{ticks: ticks, at: s.Now()}
	previous := s.previousProcess
	s.previousProcess = &current
	if previous == nil {
		return nil
	}
	seconds := current.at.Sub(previous.at).Seconds()
	if seconds <= 0 || current.ticks < previous.ticks {
		// A clock that went backwards or a counter that did: the process did not
		// restart - the counter belongs to this process - so this is a reading
		// nothing can be made of.
		return nil
	}
	value := float64(current.ticks-previous.ticks) / userHz / seconds * 100
	return &value
}

// parseVmRSS reads the resident set size out of /proc/[pid]/status. The
// file reports kilobytes; the sample carries bytes like every other size.
func parseVmRSS(status string) (uint64, bool) {
	scanner := bufio.NewScanner(strings.NewReader(status))
	for scanner.Scan() {
		key, rest, ok := strings.Cut(scanner.Text(), ":")
		if !ok || key != "VmRSS" {
			continue
		}
		fields := strings.Fields(rest)
		if len(fields) == 0 {
			return 0, false
		}
		value, err := strconv.ParseUint(fields[0], 10, 64)
		if err != nil {
			return 0, false
		}
		return value * 1024, true
	}
	return 0, false
}

// parseProcessTicks reads utime plus stime out of /proc/[pid]/stat.
func parseProcessTicks(stat string) (uint64, bool) {
	end := strings.LastIndex(stat, ")")
	if end < 0 {
		return 0, false
	}
	fields := strings.Fields(stat[end+1:])
	if len(fields) < 13 {
		return 0, false
	}
	utime, errUser := strconv.ParseUint(fields[11], 10, 64)
	stime, errSystem := strconv.ParseUint(fields[12], 10, 64)
	if errUser != nil || errSystem != nil {
		return 0, false
	}
	return utime + stime, true
}

// countOpenFDs counts the entries of /proc/[pid]/fd.
func countOpenFDs(dir string) (uint32, bool) {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return 0, false
	}
	return uint32(len(entries)), true
}

// helperMainPID asks systemd for the main PID of the helper.
func helperMainPID(ctx context.Context) (int, bool) {
	result := runCommand(ctx, 10*time.Second, "/usr/bin/systemctl", "show", "-p", "MainPID", helperUnit)
	if !result.Ran || result.ExitCode != 0 {
		return 0, false
	}
	pid, err := parseMainPID(result.Stdout)
	if err != nil || pid <= 0 {
		return 0, false
	}
	return pid, true
}

// parseMainPID reads the "MainPID=1234" line systemctl show prints.
func parseMainPID(output string) (int, error) {
	for _, line := range strings.Split(output, "\n") {
		key, value, ok := strings.Cut(strings.TrimSpace(line), "=")
		if !ok || key != "MainPID" {
			continue
		}
		return strconv.Atoi(strings.TrimSpace(value))
	}
	return 0, errors.New("systemctl show printed no MainPID")
}
