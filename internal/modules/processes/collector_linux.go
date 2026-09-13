// Package processes reads the host processes from /proc.
//
// The module is a diagnostic, not an observability system. A snapshot is
// taken only on the operator's request and has an upper size bound: a
// continuous stream of process metrics belongs to Prometheus, not to the
// management panel.
package processes

import (
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
)

// Process describes one host process.
type Process struct {
	PID  int32  `json:"pid"`
	PPID int32  `json:"ppid"`
	User string `json:"user,omitempty"`
	UID  uint32 `json:"uid"`
	// Command is the full command line; empty for kernel processes, which
	// have none.
	Command string `json:"command,omitempty"`
	// Name comes from /proc/<pid>/stat and exists for kernel processes too.
	Name  string `json:"name"`
	State string `json:"state"`
	// RSSBytes is the resident memory. Zero for a kernel process is the
	// truth, not missing data.
	RSSBytes int64 `json:"rss_bytes"`
	Threads  int32 `json:"threads"`
	// StartTimeTicks binds the process to its identifier. The PID alone is
	// reused by the kernel, so a signal sent a moment later could hit an
	// entirely different process.
	StartTimeTicks uint64 `json:"start_time_ticks"`
	// CPUTicks is the total processor time. The panel does not derive
	// percentages from it: that needs two measurements and the snapshot is
	// one.
	CPUTicks uint64 `json:"cpu_ticks"`
	// Unit and Container point at what manages the process. Without them
	// the operator sees a PID and has to guess whose it is.
	Unit      string `json:"unit,omitempty"`
	Container string `json:"container,omitempty"`
}

// Snapshot is the result of one read.
type Snapshot struct {
	Processes []Process `json:"processes"`
	// Total says how many processes were on the host. The list may be
	// shorter than this number: a truncated list without it would look
	// complete.
	Total     int   `json:"total"`
	Truncated bool  `json:"truncated"`
	ClockHz   int64 `json:"clock_hz"`
}

// MaxProcesses bounds one snapshot.
const MaxProcesses = 500

// Sorting decides which processes make it into the result when there are
// more than the limit. The choice belongs to the operator: they look either
// for a memory hog, a CPU hog, or a specific command.
const (
	SortByRSS     = "rss"
	SortByCPU     = "cpu"
	SortByPID     = "pid"
	SortByStarted = "started"
)

// Collect reads the host processes.
//
// The read comes from /proc and needs no root: the panel shows what every
// user of the host can see. Sending a signal does need privileges and goes
// through the helper.
func Collect(root string, sortBy string, limit int) Snapshot {
	if root == "" {
		root = "/proc"
	}
	if limit <= 0 || limit > MaxProcesses {
		limit = MaxProcesses
	}

	entries, err := os.ReadDir(root)
	if err != nil {
		return Snapshot{ClockHz: clockHz}
	}

	users := readUsers("/etc/passwd")
	var list []Process
	for _, entry := range entries {
		pid, err := strconv.ParseInt(entry.Name(), 10, 32)
		if err != nil {
			continue
		}
		process, ok := readProcess(root, int32(pid), users)
		if !ok {
			// A process that vanished during the read is not an error: the
			// snapshot describes a moment, and the moment has passed.
			continue
		}
		list = append(list, process)
	}

	snapshot := Snapshot{Total: len(list), ClockHz: clockHz}
	sortProcesses(list, sortBy)
	if len(list) > limit {
		list = list[:limit]
		snapshot.Truncated = true
	}
	snapshot.Processes = list
	return snapshot
}

func sortProcesses(list []Process, sortBy string) {
	switch sortBy {
	case SortByCPU:
		sort.Slice(list, func(i, j int) bool { return list[i].CPUTicks > list[j].CPUTicks })
	case SortByPID:
		sort.Slice(list, func(i, j int) bool { return list[i].PID < list[j].PID })
	case SortByStarted:
		sort.Slice(list, func(i, j int) bool {
			return list[i].StartTimeTicks > list[j].StartTimeTicks
		})
	default:
		// Memory by default: it is what most often runs out on a host, and
		// its shortage is the first thing seen.
		sort.Slice(list, func(i, j int) bool { return list[i].RSSBytes > list[j].RSSBytes })
	}
}

// readProcess assembles the description of one process.
func readProcess(root string, pid int32, users map[uint32]string) (Process, bool) {
	dir := filepath.Join(root, strconv.FormatInt(int64(pid), 10))
	stat, err := os.ReadFile(filepath.Join(dir, "stat"))
	if err != nil {
		return Process{}, false
	}
	process, ok := parseStat(string(stat))
	if !ok {
		return Process{}, false
	}
	process.PID = pid

	if data, err := os.ReadFile(filepath.Join(dir, "cmdline")); err == nil {
		// Arguments are separated by a zero byte; an empty cmdline means a
		// kernel process, not a missing command.
		process.Command = strings.TrimSpace(strings.ReplaceAll(string(data), "\x00", " "))
	}
	if data, err := os.ReadFile(filepath.Join(dir, "status")); err == nil {
		process.UID = uidFromStatus(string(data))
		process.User = users[process.UID]
	}
	if data, err := os.ReadFile(filepath.Join(dir, "cgroup")); err == nil {
		process.Unit, process.Container = ownerFromCgroup(string(data))
	}
	return process, true
}

// parseStat reads /proc/<pid>/stat.
//
// The process name is in parentheses and may contain spaces and parentheses
// themselves, so the numeric fields are read only after the last closing
// parenthesis - splitting the whole line on spaces would give wrong results
// for such names.
func parseStat(line string) (Process, bool) {
	open := strings.IndexByte(line, '(')
	close := strings.LastIndexByte(line, ')')
	if open < 0 || close < open {
		return Process{}, false
	}
	process := Process{Name: line[open+1 : close]}

	fields := strings.Fields(line[close+1:])
	// Fields counted from the third stat field: state, ppid, ...
	if len(fields) < 20 {
		return Process{}, false
	}
	process.State = fields[0]
	process.PPID = int32(number(fields[1]))
	process.CPUTicks = uint64(number(fields[11])) + uint64(number(fields[12]))
	process.Threads = int32(number(fields[17]))
	process.StartTimeTicks = uint64(number(fields[19]))
	// RSS is in memory pages.
	if len(fields) > 21 {
		process.RSSBytes = number(fields[21]) * int64(os.Getpagesize())
	}
	return process, true
}

func number(text string) int64 {
	value, _ := strconv.ParseInt(text, 10, 64)
	return value
}

func uidFromStatus(status string) uint32 {
	for _, line := range strings.Split(status, "\n") {
		if !strings.HasPrefix(line, "Uid:") {
			continue
		}
		fields := strings.Fields(line)
		if len(fields) > 1 {
			return uint32(number(fields[1]))
		}
	}
	return 0
}

// ownerFromCgroup recognises the systemd unit and the Docker container.
// An operator seeing only a PID would have to guess whose it is.
func ownerFromCgroup(cgroup string) (unit, container string) {
	for _, line := range strings.Split(cgroup, "\n") {
		parts := strings.SplitN(line, ":", 3)
		if len(parts) < 3 {
			continue
		}
		path := parts[2]
		if index := strings.Index(path, "docker-"); index >= 0 {
			rest := path[index+len("docker-"):]
			if end := strings.Index(rest, ".scope"); end > 0 {
				container = rest[:end]
			}
		}
		for _, segment := range strings.Split(path, "/") {
			if strings.HasSuffix(segment, ".service") || strings.HasSuffix(segment, ".scope") {
				if !strings.HasPrefix(segment, "docker-") {
					unit = segment
				}
			}
		}
	}
	return unit, container
}

// readUsers maps a UID to a name. An unknown UID stays unknown: an empty
// name is more honest than an invented one.
func readUsers(path string) map[uint32]string {
	data, err := os.ReadFile(path)
	if err != nil {
		return map[uint32]string{}
	}
	users := map[uint32]string{}
	for _, line := range strings.Split(string(data), "\n") {
		fields := strings.Split(line, ":")
		if len(fields) < 3 {
			continue
		}
		users[uint32(number(fields[2]))] = fields[0]
	}
	return users
}

// clockHz is the kernel tick frequency. It converts the process start time
// to wall-clock time on the interface side.
const clockHz = 100
