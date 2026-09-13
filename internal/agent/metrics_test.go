package agent

import (
	"errors"
	"math"
	"os"
	"path/filepath"
	"testing"
	"time"
)

// procFixture writes a procfs the sampler can read: the counters of a host
// at one moment.
func procFixture(t *testing.T, cpuLine string) string {
	t.Helper()
	root := t.TempDir()
	files := map[string]string{
		"stat": cpuLine + "\n" +
			"cpu0 100 0 50 800 20 0 5 0 0 0\n" +
			"intr 12345\n",
		"loadavg": "0.52 0.31 0.15 1/234 5678\n",
		"meminfo": "MemTotal:        4000000 kB\n" +
			"MemFree:          500000 kB\n" +
			"MemAvailable:    3000000 kB\n" +
			"Buffers:          100000 kB\n" +
			"Cached:          1000000 kB\n" +
			"SwapTotal:       2000000 kB\n" +
			"SwapFree:        1500000 kB\n",
		"uptime": "86400.55 172800.00\n",
		"mounts": "sysfs /sys sysfs rw,nosuid 0 0\n" +
			"proc /proc proc rw 0 0\n" +
			"/dev/sda1 / ext4 rw,relatime 0 0\n" +
			"tmpfs /run tmpfs rw,nosuid 0 0\n" +
			"overlay /var/lib/docker/overlay2/abc/merged overlay rw 0 0\n" +
			"/dev/sdb1 /mnt/data\\040disk xfs rw 0 0\n" +
			"/dev/sdc1 /mnt/broken btrfs rw 0 0\n" +
			"/dev/sda1 / ext4 rw,relatime 0 0\n",
		"net/dev": "Inter-|   Receive                                                |  Transmit\n" +
			" face |bytes    packets errs drop fifo frame compressed multicast|bytes    packets errs drop fifo colls carrier compressed\n" +
			"    lo: 1000 10 0 0 0 0 0 0 1000 10 0 0 0 0 0 0\n" +
			"  eth0: 500000 400 0 0 0 0 0 0 250000 300 0 0 0 0 0 0\n" +
			"docker0: 42 1 0 0 0 0 0 0 84 2 0 0 0 0 0 0\n",
	}
	for name, content := range files {
		path := filepath.Join(root, name)
		if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	return root
}

func fixtureSampler(t *testing.T, root string) *Sampler {
	t.Helper()
	return &Sampler{
		ProcRoot: root,
		Now:      func() time.Time { return time.Date(2026, 9, 13, 12, 0, 0, 0, time.UTC) },
		Statfs: func(mount string) (FilesystemUsage, error) {
			switch mount {
			case "/":
				return FilesystemUsage{TotalBytes: 100e9, UsedBytes: 40e9, InodesTotal: 6e6, InodesUsed: 1e6}, nil
			case "/mnt/data disk":
				return FilesystemUsage{TotalBytes: 2e12, UsedBytes: 1.9e12, InodesTotal: 1e8, InodesUsed: 5e7}, nil
			}
			return FilesystemUsage{}, errors.New("the mount does not answer")
		},
	}
}

func TestSampleReadsTheKernelCounters(t *testing.T) {
	// user nice system idle iowait irq softirq steal guest guest_nice
	sampler := fixtureSampler(t, procFixture(t, "cpu 100 0 50 800 20 0 5 25 0 0"))
	sample, err := sampler.Sample()
	if err != nil {
		t.Fatalf("sample: %v", err)
	}
	if sample.GetSampledAtUnix() != sampler.Now().Unix() {
		t.Errorf("sampled_at = %d", sample.GetSampledAtUnix())
	}
	// Without a previous snapshot the percentage covers the time since
	// boot: 180 busy of 1000 jiffies.
	if math.Abs(sample.GetCpuPercent()-18) > 0.01 {
		t.Errorf("cpu_percent since boot = %v, want 18", sample.GetCpuPercent())
	}
	if sample.GetLoad1() != 0.52 || sample.GetLoad5() != 0.31 || sample.GetLoad15() != 0.15 {
		t.Errorf("load = %v %v %v", sample.GetLoad1(), sample.GetLoad5(), sample.GetLoad15())
	}
	const kB = 1024
	if sample.GetMemoryTotal() != 4000000*kB || sample.GetMemoryAvailable() != 3000000*kB ||
		sample.GetMemoryUsed() != 1000000*kB {
		t.Errorf("memory = total %d used %d available %d",
			sample.GetMemoryTotal(), sample.GetMemoryUsed(), sample.GetMemoryAvailable())
	}
	if sample.GetSwapTotal() != 2000000*kB || sample.GetSwapUsed() != 500000*kB {
		t.Errorf("swap = total %d used %d", sample.GetSwapTotal(), sample.GetSwapUsed())
	}
	if sample.GetUptimeSeconds() != 86400 {
		t.Errorf("uptime = %d", sample.GetUptimeSeconds())
	}

	// The pseudo filesystems, the overlay and the tmpfs are left out; the
	// mount that does not answer statfs too. The root mounted twice is one
	// entry, and the escaped space in the path is decoded.
	filesystems := sample.GetFilesystems()
	if len(filesystems) != 2 {
		t.Fatalf("filesystems = %v", filesystems)
	}
	root, data := filesystems[0], filesystems[1]
	if root.GetMount() != "/" || root.GetDevice() != "/dev/sda1" || root.GetFstype() != "ext4" ||
		root.GetTotalBytes() != 100e9 || root.GetUsedBytes() != 40e9 ||
		root.GetInodesTotal() != 6e6 || root.GetInodesUsed() != 1e6 {
		t.Errorf("root filesystem = %v", root)
	}
	if data.GetMount() != "/mnt/data disk" || data.GetFstype() != "xfs" || data.GetUsedBytes() != 1.9e12 {
		t.Errorf("data filesystem = %v", data)
	}

	// The loopback is left out; the counters stay cumulative.
	interfaces := sample.GetInterfaces()
	if len(interfaces) != 2 {
		t.Fatalf("interfaces = %v", interfaces)
	}
	if interfaces[0].GetName() != "docker0" || interfaces[1].GetName() != "eth0" {
		t.Errorf("interface order = %s, %s", interfaces[0].GetName(), interfaces[1].GetName())
	}
	if interfaces[1].GetRxBytes() != 500000 || interfaces[1].GetTxBytes() != 250000 {
		t.Errorf("eth0 = rx %d tx %d", interfaces[1].GetRxBytes(), interfaces[1].GetTxBytes())
	}
}

func TestCPUPercentCoversTheIntervalSinceThePreviousSample(t *testing.T) {
	sampler := fixtureSampler(t, procFixture(t, "cpu 100 0 50 800 20 0 5 25 0 0"))
	if _, err := sampler.Sample(); err != nil {
		t.Fatalf("first sample: %v", err)
	}
	// Sixty jiffies later: 45 busy (user 30, system 10, steal 5), 15 idle.
	sampler.ProcRoot = procFixture(t, "cpu 130 0 60 815 20 0 5 30 0 0")
	sample, err := sampler.Sample()
	if err != nil {
		t.Fatalf("second sample: %v", err)
	}
	if math.Abs(sample.GetCpuPercent()-75) > 0.01 {
		t.Errorf("cpu_percent over the interval = %v, want 75", sample.GetCpuPercent())
	}

	// Counters that went backwards mean a reboot: the answer is the average
	// since boot again, never a negative number or a wrap.
	sampler.ProcRoot = procFixture(t, "cpu 10 0 10 80 0 0 0 0 0 0")
	sample, err = sampler.Sample()
	if err != nil {
		t.Fatalf("sample after the reboot: %v", err)
	}
	if math.Abs(sample.GetCpuPercent()-20) > 0.01 {
		t.Errorf("cpu_percent after the reboot = %v, want 20", sample.GetCpuPercent())
	}
}

func TestSampleFailsWithoutTheCPUCounters(t *testing.T) {
	sampler := fixtureSampler(t, procFixture(t, "cpu 1 2 3 4 5 6 7 8 9 10"))
	if err := os.Remove(filepath.Join(sampler.ProcRoot, "stat")); err != nil {
		t.Fatal(err)
	}
	if _, err := sampler.Sample(); err == nil {
		t.Fatal("a sample without /proc/stat did not fail")
	}
}

func TestUnescapeMountDecodesOctalEscapes(t *testing.T) {
	cases := map[string]string{
		`/mnt/data\040disk`: "/mnt/data disk",
		`/plain`:            "/plain",
		`/tab\011here`:      "/tab\there",
		`/trailing\`:        `/trailing\`,
	}
	for in, want := range cases {
		if got := unescapeMount(in); got != want {
			t.Errorf("unescapeMount(%q) = %q, want %q", in, got, want)
		}
	}
}
