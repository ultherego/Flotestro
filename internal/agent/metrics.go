package agent

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"log/slog"
	"math/rand/v2"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"syscall"
	"time"

	agentv1 "github.com/ultherego/flotestro/internal/genproto/flotestro/agent/v1"
)

// The resource sample travels separately from the heartbeat: the heartbeat
// carries decision signals and must stay small and cheap, while a sample is a
// measurement the panel keeps for charts and alert rules. The two also have
// different rhythms - a heartbeat spreads over a jitter window to protect the
// panel, a sample wants an even interval so that the rates it yields mean
// something.
const (
	// defaultMetricsInterval is used when the session configuration names
	// no interval.
	defaultMetricsInterval = 60 * time.Second
	// metricsJitter is the most a sample is delayed past its interval. A few
	// seconds are enough to keep a fleet started at once from sampling in
	// lockstep; more would bend the interval the panel computes rates over.
	metricsJitter = 5 * time.Second
)

// realFilesystems are the filesystem types that live on a disk. A pseudo
// filesystem, an overlay or a tmpfs is left out: a full /run or a full
// container layer says nothing the operator would act on with a disk.
var realFilesystems = map[string]bool{
	"ext2": true, "ext3": true, "ext4": true, "xfs": true, "btrfs": true,
	"zfs": true, "vfat": true, "exfat": true, "f2fs": true,
}

// FilesystemUsage is what statfs answers about one mount.
type FilesystemUsage struct {
	TotalBytes  uint64
	UsedBytes   uint64
	InodesTotal uint64
	InodesUsed  uint64
}

// Sampler reads the host resource counters from the kernel files.
//
// The roots and the clock are fields rather than constants so that a test
// can point the sampler at fixtures and a fixed time; the production sampler
// reads /proc and the real clock.
type Sampler struct {
	// ProcRoot is the mount point of procfs; /proc by default.
	ProcRoot string
	// Now is the clock the sample is stamped with.
	Now func() time.Time
	// Statfs answers the usage of a mount. The default asks the kernel.
	Statfs func(mount string) (FilesystemUsage, error)
	// HelperPID names the process of the root helper, when it runs. The
	// default asks systemd; nil means the helper is never measured.
	HelperPID func(ctx context.Context) (int, bool)

	// previous is the CPU counter snapshot the next sample is measured
	// against.
	previous *cpuCounters
	// previousProcess is the agent's own CPU snapshot, measured the same
	// way.
	previousProcess *processCPU
}

// NewSampler returns a sampler reading the real host.
func NewSampler() *Sampler {
	return &Sampler{ProcRoot: "/proc", Now: time.Now, Statfs: statfsUsage, HelperPID: helperMainPID}
}

// Run sends a sample every interval until the context ends.
//
// The CPU counters are primed at the start, so the first sample already
// carries a percentage over a real interval rather than the average since
// boot - which would say nothing about the host now.
func (s *Sampler) Run(ctx context.Context, interval time.Duration,
	send func(*agentv1.MetricsSample) error, log *slog.Logger) {
	if interval <= 0 {
		interval = defaultMetricsInterval
	}
	if _, err := s.readCPU(); err != nil {
		log.Debug("the CPU counters were not primed", "err", err)
	}
	// The agent's own counter is primed for the same reason; without it the
	// first sample would carry no CPU figure for the agent at all.
	s.readProcessCPU(filepath.Join(s.ProcRoot, "self", "stat"))
	for {
		select {
		case <-ctx.Done():
			return
		case <-time.After(interval + time.Duration(rand.Int64N(int64(metricsJitter)))):
		}
		sample, err := s.SampleContext(ctx)
		if err != nil {
			// A host without a readable procfs is not a reason to end the
			// session: the panel then shows the host without metrics, and the
			// tasks keep flowing.
			log.Warn("the resource sample was not taken", "err", err)
			continue
		}
		if err := send(sample); err != nil {
			log.Debug("the resource sample was not sent", "err", err)
			return
		}
	}
}

// Sample reads one set of counters. The CPU percentage covers the time since
// the previous call; on the first call it covers the time since boot.
func (s *Sampler) Sample() (*agentv1.MetricsSample, error) {
	return s.SampleContext(context.Background())
}

// SampleContext is Sample with the context the helper lookup runs under.
func (s *Sampler) SampleContext(ctx context.Context) (*agentv1.MetricsSample, error) {
	now := s.Now()
	sample := &agentv1.MetricsSample{SampledAtUnix: now.Unix()}

	cpu, err := s.readCPU()
	if err != nil {
		return nil, err
	}
	sample.CpuPercent = cpu

	if err := s.readLoad(sample); err != nil {
		return nil, err
	}
	if err := s.readMemory(sample); err != nil {
		return nil, err
	}
	if err := s.readUptime(sample); err != nil {
		return nil, err
	}
	// A mount that cannot be measured or an interface list that cannot be
	// read leaves its list empty rather than failing the whole sample: the
	// CPU and memory are still worth reporting.
	sample.Filesystems = s.readFilesystems()
	sample.Interfaces = s.readInterfaces()
	// The agent's own footprint rides along; a value it could not read
	// stays unset, so the panel shows it unknown rather than zero.
	fp := s.footprint(ctx)
	sample.AgentRssBytes = fp.RSSBytes
	sample.AgentCpuPercent = fp.CPUPercent
	sample.AgentGoroutines = fp.Goroutines
	sample.AgentOpenFds = fp.OpenFDs
	sample.HelperRssBytes = fp.HelperRSSBytes
	return sample, nil
}

// cpuCounters is the first line of /proc/stat in jiffies.
type cpuCounters struct {
	busy, total uint64
}

// readCPU returns the busy percentage since the previous snapshot and stores
// the current one.
func (s *Sampler) readCPU() (float64, error) {
	file, err := os.Open(filepath.Join(s.ProcRoot, "stat"))
	if err != nil {
		return 0, err
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		fields := strings.Fields(scanner.Text())
		if len(fields) < 5 || fields[0] != "cpu" {
			continue
		}
		var current cpuCounters
		for i, field := range fields[1:] {
			value, err := strconv.ParseUint(field, 10, 64)
			if err != nil {
				return 0, fmt.Errorf("/proc/stat: %w", err)
			}
			current.total += value
			// Idle (index 3) and iowait (index 4) are the time the CPU had
			// nothing to do; everything else is work, steal included - a
			// stolen CPU is a CPU the host does not have.
			if i != 3 && i != 4 {
				current.busy += value
			}
		}
		previous := s.previous
		s.previous = &current
		if previous == nil || current.total <= previous.total {
			// No previous snapshot, or counters that went backwards after a
			// reboot: the average since boot is the only honest number.
			return percent(current.busy, current.total), nil
		}
		return percent(current.busy-previous.busy, current.total-previous.total), nil
	}
	if err := scanner.Err(); err != nil {
		return 0, err
	}
	return 0, errors.New("/proc/stat has no cpu line")
}

func percent(part, whole uint64) float64 {
	if whole == 0 {
		return 0
	}
	value := float64(part) * 100 / float64(whole)
	if value > 100 {
		return 100
	}
	return value
}

func (s *Sampler) readLoad(sample *agentv1.MetricsSample) error {
	data, err := os.ReadFile(filepath.Join(s.ProcRoot, "loadavg"))
	if err != nil {
		return err
	}
	fields := strings.Fields(string(data))
	if len(fields) < 3 {
		return errors.New("/proc/loadavg is too short")
	}
	targets := []*float64{&sample.Load1, &sample.Load5, &sample.Load15}
	for i, target := range targets {
		value, err := strconv.ParseFloat(fields[i], 64)
		if err != nil {
			return fmt.Errorf("/proc/loadavg: %w", err)
		}
		*target = value
	}
	return nil
}

func (s *Sampler) readMemory(sample *agentv1.MetricsSample) error {
	file, err := os.Open(filepath.Join(s.ProcRoot, "meminfo"))
	if err != nil {
		return err
	}
	defer file.Close()

	values := map[string]uint64{}
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		key, rest, ok := strings.Cut(scanner.Text(), ":")
		if !ok {
			continue
		}
		fields := strings.Fields(rest)
		if len(fields) == 0 {
			continue
		}
		value, err := strconv.ParseUint(fields[0], 10, 64)
		if err != nil {
			continue
		}
		// The file reports kilobytes; the sample carries bytes like every
		// other size in the panel.
		values[key] = value * 1024
	}
	if err := scanner.Err(); err != nil {
		return err
	}
	total, ok := values["MemTotal"]
	if !ok {
		return errors.New("/proc/meminfo has no MemTotal")
	}
	available, ok := values["MemAvailable"]
	if !ok {
		// A kernel too old for MemAvailable: free plus the caches is the
		// closest answer.
		available = values["MemFree"] + values["Buffers"] + values["Cached"]
	}
	if available > total {
		available = total
	}
	sample.MemoryTotal = total
	sample.MemoryAvailable = available
	sample.MemoryUsed = total - available
	sample.SwapTotal = values["SwapTotal"]
	if free := values["SwapFree"]; free <= sample.SwapTotal {
		sample.SwapUsed = sample.SwapTotal - free
	}
	return nil
}

func (s *Sampler) readUptime(sample *agentv1.MetricsSample) error {
	data, err := os.ReadFile(filepath.Join(s.ProcRoot, "uptime"))
	if err != nil {
		return err
	}
	fields := strings.Fields(string(data))
	if len(fields) == 0 {
		return errors.New("/proc/uptime is empty")
	}
	uptime, err := strconv.ParseFloat(fields[0], 64)
	if err != nil {
		return fmt.Errorf("/proc/uptime: %w", err)
	}
	sample.UptimeSeconds = uint64(uptime)
	return nil
}

// readFilesystems lists the real filesystems with their usage. The last
// mount on a path is the visible one, so a path mounted twice is reported
// once, as the kernel shows it.
func (s *Sampler) readFilesystems() []*agentv1.FilesystemSample {
	file, err := os.Open(filepath.Join(s.ProcRoot, "mounts"))
	if err != nil {
		return nil
	}
	defer file.Close()

	byMount := map[string]*agentv1.FilesystemSample{}
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		fields := strings.Fields(scanner.Text())
		if len(fields) < 3 || !realFilesystems[fields[2]] {
			continue
		}
		mount := unescapeMount(fields[1])
		byMount[mount] = &agentv1.FilesystemSample{
			Mount: mount, Device: unescapeMount(fields[0]), Fstype: fields[2],
		}
	}
	mounts := make([]string, 0, len(byMount))
	for mount := range byMount {
		mounts = append(mounts, mount)
	}
	sort.Strings(mounts)

	list := make([]*agentv1.FilesystemSample, 0, len(byMount))
	for _, mount := range mounts {
		entry := byMount[mount]
		usage, err := s.Statfs(mount)
		if err != nil {
			// A mount that does not answer - a hung network share, a device
			// pulled out - is left out rather than reported as empty.
			continue
		}
		entry.TotalBytes = usage.TotalBytes
		entry.UsedBytes = usage.UsedBytes
		entry.InodesTotal = usage.InodesTotal
		entry.InodesUsed = usage.InodesUsed
		list = append(list, entry)
	}
	return list
}

// unescapeMount decodes the octal escapes of /proc/mounts; a space in a
// mount path arrives as \040.
func unescapeMount(value string) string {
	if !strings.Contains(value, `\`) {
		return value
	}
	var out strings.Builder
	for i := 0; i < len(value); i++ {
		if value[i] == '\\' && i+3 < len(value) {
			if code, err := strconv.ParseUint(value[i+1:i+4], 8, 8); err == nil {
				out.WriteByte(byte(code))
				i += 3
				continue
			}
		}
		out.WriteByte(value[i])
	}
	return out.String()
}

// statfsUsage asks the kernel about one mount.
func statfsUsage(mount string) (FilesystemUsage, error) {
	var stat syscall.Statfs_t
	if err := syscall.Statfs(mount, &stat); err != nil {
		return FilesystemUsage{}, err
	}
	unit := uint64(stat.Bsize)
	usage := FilesystemUsage{
		TotalBytes:  stat.Blocks * unit,
		InodesTotal: stat.Files,
	}
	if stat.Blocks >= stat.Bfree {
		usage.UsedBytes = (stat.Blocks - stat.Bfree) * unit
	}
	if stat.Files >= stat.Ffree {
		usage.InodesUsed = stat.Files - stat.Ffree
	}
	return usage, nil
}

// readInterfaces reads the cumulative traffic counters of every interface
// but the loopback.
func (s *Sampler) readInterfaces() []*agentv1.InterfaceSample {
	file, err := os.Open(filepath.Join(s.ProcRoot, "net", "dev"))
	if err != nil {
		return nil
	}
	defer file.Close()

	var list []*agentv1.InterfaceSample
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		name, counters, ok := strings.Cut(scanner.Text(), ":")
		if !ok {
			// The two header lines have no colon in the interface position.
			continue
		}
		name = strings.TrimSpace(name)
		if name == "" || name == "lo" {
			continue
		}
		fields := strings.Fields(counters)
		// Eight receive columns, then eight transmit columns; the first of
		// each group is the byte count.
		if len(fields) < 9 {
			continue
		}
		rx, errRx := strconv.ParseUint(fields[0], 10, 64)
		tx, errTx := strconv.ParseUint(fields[8], 10, 64)
		if errRx != nil || errTx != nil {
			continue
		}
		list = append(list, &agentv1.InterfaceSample{Name: name, RxBytes: rx, TxBytes: tx})
	}
	sort.Slice(list, func(i, j int) bool { return list[i].Name < list[j].Name })
	return list
}
