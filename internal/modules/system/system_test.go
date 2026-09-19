package system

import (
	"io/fs"
	"slices"
	"strings"
	"testing"
	"testing/fstest"
	"time"
)

const cpuinfoTwoSockets = `processor	: 0
vendor_id	: GenuineIntel
model name	: Intel(R) Xeon(R) Gold 6338 CPU @ 2.00GHz
cpu MHz		: 2000.000
physical id	: 0
core id		: 0
cpu cores	: 2
flags		: fpu vme de pse tsc msr pae mce cx8 apic sep lm constant_tsc aes avx avx2 avx512f vmx smep smap pti md_clear
bugs		: spectre_v1 spectre_v2

processor	: 1
vendor_id	: GenuineIntel
model name	: Intel(R) Xeon(R) Gold 6338 CPU @ 2.00GHz
physical id	: 0
core id		: 1
cpu cores	: 2
flags		: fpu vme de pse tsc msr pae mce cx8 apic sep lm constant_tsc aes avx avx2 avx512f vmx smep smap pti md_clear

processor	: 2
vendor_id	: GenuineIntel
model name	: Intel(R) Xeon(R) Gold 6338 CPU @ 2.00GHz
physical id	: 1
core id		: 0
cpu cores	: 2
flags		: fpu vme de pse tsc msr pae mce cx8 apic sep lm constant_tsc aes avx avx2 avx512f vmx smep smap pti md_clear

processor	: 3
vendor_id	: GenuineIntel
model name	: Intel(R) Xeon(R) Gold 6338 CPU @ 2.00GHz
physical id	: 1
core id		: 1
cpu cores	: 2
flags		: fpu vme de pse tsc msr pae mce cx8 apic sep lm constant_tsc aes avx avx2 avx512f vmx smep smap pti md_clear
`

const cpuinfoARM = `processor	: 0
BogoMIPS	: 108.00
Features	: fp asimd evtstrm crc32 cpuid
CPU implementer	: 0x41
CPU architecture: 8

processor	: 1
BogoMIPS	: 108.00
Features	: fp asimd evtstrm crc32 cpuid
CPU implementer	: 0x41
CPU architecture: 8

Hardware	: BCM2835
Revision	: c03111
Model		: Raspberry Pi 4 Model B Rev 1.1
`

func TestParseCPUInfoCountsTheLayoutAcrossSockets(t *testing.T) {
	cpu := ParseCPUInfo(cpuinfoTwoSockets)
	if cpu.Model != "Intel(R) Xeon(R) Gold 6338 CPU @ 2.00GHz" || cpu.Vendor != "GenuineIntel" {
		t.Fatalf("model = %q, vendor = %q", cpu.Model, cpu.Vendor)
	}
	if cpu.Threads == nil || *cpu.Threads != 4 {
		t.Errorf("threads = %v, expected 4", cpu.Threads)
	}
	if cpu.Sockets == nil || *cpu.Sockets != 2 {
		t.Errorf("sockets = %v, expected 2", cpu.Sockets)
	}
	if cpu.Cores == nil || *cpu.Cores != 4 {
		t.Errorf("cores = %v, expected 4 (two per socket)", cpu.Cores)
	}
	if cpu.MHz == nil || *cpu.MHz != 2000 {
		t.Errorf("MHz = %v", cpu.MHz)
	}
	// The flag summary keeps what an operator asks about and counts the
	// rest rather than listing it.
	for _, flag := range []string{"vmx", "aes", "avx512f", "pti", "md_clear", "lm"} {
		if !slices.Contains(cpu.Flags, flag) {
			t.Errorf("the summary lacks %s: %v", flag, cpu.Flags)
		}
	}
	if slices.Contains(cpu.Flags, "fpu") {
		t.Error("the summary lists fpu, which nobody asks about")
	}
	if cpu.FlagCount != 22 {
		t.Errorf("flag count = %d, expected 22", cpu.FlagCount)
	}
}

// An ARM cpuinfo names no sockets and no core ids: the layout stays unknown
// rather than becoming zero, and the model comes from the board lines at the
// end of the file.
func TestParseCPUInfoLeavesAnUnknownLayoutUnknown(t *testing.T) {
	cpu := ParseCPUInfo(cpuinfoARM)
	if cpu.Threads == nil || *cpu.Threads != 2 {
		t.Errorf("threads = %v, expected 2", cpu.Threads)
	}
	if cpu.Cores != nil || cpu.Sockets != nil {
		t.Errorf("cores = %v, sockets = %v: an unknown layout became a number", cpu.Cores, cpu.Sockets)
	}
	if cpu.Model != "Raspberry Pi 4 Model B Rev 1.1" {
		t.Errorf("model = %q", cpu.Model)
	}
	if !slices.Contains(cpu.Flags, "asimd") || !slices.Contains(cpu.Flags, "crc32") {
		t.Errorf("the ARM features are not summarised: %v", cpu.Flags)
	}
}

func TestParseMemInfoConvertsKibibytes(t *testing.T) {
	memory := ParseMemInfo("MemTotal:        8123456 kB\nMemFree:         1234567 kB\nSwapTotal:       2097148 kB\n")
	if memory.TotalBytes == nil || *memory.TotalBytes != 8123456*1024 {
		t.Errorf("total = %v", memory.TotalBytes)
	}
	if memory.SwapTotalBytes == nil || *memory.SwapTotalBytes != 2097148*1024 {
		t.Errorf("swap = %v", memory.SwapTotalBytes)
	}
	if empty := ParseMemInfo(""); empty.TotalBytes != nil {
		t.Error("an empty file gave a memory total")
	}
}

func TestParseOSReleaseReadsTheCodenameAndTheFamilies(t *testing.T) {
	distribution := ParseOSRelease(`PRETTY_NAME="Debian GNU/Linux 12 (bookworm)"
NAME="Debian GNU/Linux"
VERSION_ID="12"
VERSION="12 (bookworm)"
VERSION_CODENAME=bookworm
ID=debian
`)
	if distribution.ID != "debian" || distribution.Version != "12" || distribution.Codename != "bookworm" {
		t.Errorf("distribution = %+v", distribution)
	}
	fedora := ParseOSRelease("ID=fedora\nVERSION_ID=40\nID_LIKE=\"rhel centos\"\n")
	if !slices.Equal(fedora.Like, []string{"rhel", "centos"}) {
		t.Errorf("like = %v", fedora.Like)
	}
}

func TestDetectVirtualizationPrefersTheStrongerEvidence(t *testing.T) {
	cases := []struct {
		name                              string
		container, sysfs, vendor, product string
		flag                              bool
		want                              string
	}{
		{"container marker wins", "docker", "kvm", "QEMU", "Standard PC", true, "docker"},
		{"sysfs hypervisor over dmi", "", "xen", "QEMU", "Standard PC", true, "xen"},
		{"dmi names the hypervisor", "", "", "QEMU", "Standard PC (Q35 + ICH9, 2009)", true, "qemu"},
		{"virtualbox by product", "", "", "innotek GmbH", "VirtualBox", true, "virtualbox"},
		{"vmware by vendor", "", "", "VMware, Inc.", "VMware Virtual Platform", true, "vmware"},
		{"the flag alone", "", "", "Dell Inc.", "PowerEdge R650", true, "hypervisor"},
		{"bare metal", "", "", "Dell Inc.", "PowerEdge R650", false, "none"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := DetectVirtualization(tc.container, tc.sysfs, tc.vendor, tc.product, tc.flag)
			if got.Kind != tc.want {
				t.Errorf("kind = %q, expected %q (source %q)", got.Kind, tc.want, got.Source)
			}
			if got.Source == "" {
				t.Error("a verdict without evidence")
			}
		})
	}
}

func TestTimezoneFromLocaltime(t *testing.T) {
	if zone := TimezoneFromLocaltime("/usr/share/zoneinfo/Europe/Warsaw"); zone != "Europe/Warsaw" {
		t.Errorf("zone = %q", zone)
	}
	if zone := TimezoneFromLocaltime("../usr/share/zoneinfo/UTC"); zone != "UTC" {
		t.Errorf("zone = %q", zone)
	}
	if zone := TimezoneFromLocaltime("/etc/localtime.bak"); zone != "" {
		t.Errorf("a link outside zoneinfo gave %q", zone)
	}
}

// hostTree builds the file system of a virtual machine the way the kernel
// exposes it.
func hostTree() fstest.MapFS {
	return fstest.MapFS{
		"proc/cpuinfo":                      {Data: []byte(cpuinfoTwoSockets)},
		"proc/meminfo":                      {Data: []byte("MemTotal:        4030000 kB\nSwapTotal:             0 kB\n")},
		"proc/cmdline":                      {Data: []byte("BOOT_IMAGE=/boot/vmlinuz-6.1.0-25-amd64 root=UUID=abc ro quiet\n")},
		"proc/uptime":                       {Data: []byte("3600.42 7000.00\n")},
		"proc/sys/kernel/osrelease":         {Data: []byte("6.1.0-25-amd64\n")},
		"proc/sys/kernel/version":           {Data: []byte("#1 SMP PREEMPT_DYNAMIC Debian 6.1.106-3 (2024-08-26)\n")},
		"proc/sys/kernel/arch":              {Data: []byte("x86_64\n")},
		"etc/os-release":                    {Data: []byte("ID=debian\nVERSION_ID=\"12\"\nVERSION_CODENAME=bookworm\nPRETTY_NAME=\"Debian GNU/Linux 12 (bookworm)\"\n")},
		"etc/localtime":                     {Mode: fs.ModeSymlink, Data: []byte("/usr/share/zoneinfo/Europe/Warsaw")},
		"sys/class/dmi/id/sys_vendor":       {Data: []byte("QEMU\n")},
		"sys/class/dmi/id/product_name":     {Data: []byte("Standard PC (Q35 + ICH9, 2009)\n")},
		"sys/class/dmi/id/chassis_type":     {Data: []byte("1\n")},
		"sys/class/dmi/id/bios_vendor":      {Data: []byte("EDK II\n")},
		"sys/class/dmi/id/bios_version":     {Data: []byte("edk2-20230524-3.fc38\n")},
		"sys/class/dmi/id/bios_date":        {Data: []byte("05/24/2023\n")},
		"sys/class/dmi/id/product_serial":   {Mode: 0o400 | permissionDenied},
		"sys/class/dmi/id/product_uuid":     {Mode: 0o400 | permissionDenied},
		"sys/firmware/efi/fw_platform_size": {Data: []byte("64\n")},
	}
}

// permissionDenied marks a file the fake tree refuses to open. MapFS opens
// everything, so the refusal is simulated by a wrapper below.
const permissionDenied fs.FileMode = fs.ModeCharDevice

// refusingFS refuses the files marked with permissionDenied the way the
// kernel refuses an unprivileged reader of the DMI serial number.
type refusingFS struct{ fstest.MapFS }

func (r refusingFS) Open(name string) (fs.File, error) {
	if file, ok := r.MapFS[name]; ok && file.Mode&permissionDenied != 0 {
		return nil, &fs.PathError{Op: "open", Path: name, Err: fs.ErrPermission}
	}
	return r.MapFS.Open(name)
}

// ReadFile is overridden as well: fs.ReadFile takes the shortcut through
// MapFS.ReadFile, which would open the file without asking Open above.
func (r refusingFS) ReadFile(name string) ([]byte, error) {
	if file, ok := r.MapFS[name]; ok && file.Mode&permissionDenied != 0 {
		return nil, &fs.PathError{Op: "open", Path: name, Err: fs.ErrPermission}
	}
	return r.MapFS.ReadFile(name)
}

func TestCollectReadsThePictureAndNamesWhatRootHolds(t *testing.T) {
	now := time.Date(2026, 9, 14, 12, 0, 0, 0, time.UTC)
	snapshot := Collect(refusingFS{hostTree()}, now)

	if snapshot.Kernel.Release != "6.1.0-25-amd64" || snapshot.Kernel.Architecture != "x86_64" {
		t.Errorf("kernel = %+v", snapshot.Kernel)
	}
	if !strings.HasPrefix(snapshot.Kernel.Cmdline, "BOOT_IMAGE=") {
		t.Errorf("cmdline = %q", snapshot.Kernel.Cmdline)
	}
	if snapshot.Distribution.ID != "debian" || snapshot.Distribution.Codename != "bookworm" {
		t.Errorf("distribution = %+v", snapshot.Distribution)
	}
	if snapshot.Timezone != "Europe/Warsaw" {
		t.Errorf("timezone = %q", snapshot.Timezone)
	}
	if snapshot.Boot.UptimeSeconds == nil || *snapshot.Boot.UptimeSeconds != 3600 {
		t.Errorf("uptime = %v", snapshot.Boot.UptimeSeconds)
	}
	if snapshot.Boot.BootedAt == nil || !snapshot.Boot.BootedAt.Equal(now.Add(-time.Hour)) {
		t.Errorf("booted at = %v", snapshot.Boot.BootedAt)
	}
	if snapshot.DMI.Vendor != "QEMU" || snapshot.DMI.ChassisType != "other" {
		t.Errorf("dmi = %+v", snapshot.DMI)
	}
	if snapshot.Firmware.Mode != FirmwareUEFI || snapshot.Firmware.Vendor != "EDK II" {
		t.Errorf("firmware = %+v", snapshot.Firmware)
	}
	if snapshot.Virtualization.Kind != "qemu" {
		t.Errorf("virtualization = %+v", snapshot.Virtualization)
	}
	// The refused serial and UUID are missing with a reason that names the
	// refusal, so the agent knows to ask the helper.
	for _, fact := range []string{FactDMISerial, FactDMIUUID} {
		reason, missing := snapshot.Missing[fact]
		if !missing || !strings.Contains(reason, "permission denied") {
			t.Errorf("%s: missing = %v, reason = %q", fact, missing, reason)
		}
	}
	if snapshot.DMI.Serial != "" || snapshot.DMI.UUID != "" {
		t.Error("a refused read produced a serial number")
	}
	if !slices.Equal(snapshot.MissingFacts(), []string{FactDMISerial, FactDMIUUID}) {
		t.Errorf("missing = %v", snapshot.MissingFacts())
	}
}

func TestSupplementFillsInWhatTheHelperRead(t *testing.T) {
	snapshot := Collect(refusingFS{hostTree()}, time.Now())
	supplemented := snapshot.Supplemented(Supplement{Serial: "VM-1234", UUID: "4c4c4544-0000-2010-8020-80c04f202020"})
	if supplemented.DMI.Serial != "VM-1234" || supplemented.DMI.UUID != "4c4c4544-0000-2010-8020-80c04f202020" {
		t.Errorf("dmi = %+v", supplemented.DMI)
	}
	if len(supplemented.Missing) != 0 {
		t.Errorf("missing after the supplement = %v", supplemented.Missing)
	}
	// A helper that could not read either keeps the fact missing with its
	// own reason - the agent's reason was "ask root", and root answered.
	refused := snapshot.Supplemented(Supplement{Missing: map[string]string{
		FactDMISerial: "the firmware left the serial number blank", FactDMIUUID: "/sys/class/dmi/id/product_uuid does not exist",
	}})
	if refused.Missing[FactDMISerial] != "the firmware left the serial number blank" {
		t.Errorf("missing = %v", refused.Missing)
	}
}

// The tree the root helper reads has the serial numbers open. Placeholders
// the firmware writes in place of a value are not values.
func TestReadSupplementDropsFirmwarePlaceholders(t *testing.T) {
	tree := hostTree()
	tree["sys/class/dmi/id/product_serial"] = &fstest.MapFile{Data: []byte("To Be Filled By O.E.M.\n")}
	tree["sys/class/dmi/id/product_uuid"] = &fstest.MapFile{Data: []byte("03000200-0400-0500-0006-000700080009\n")}
	tree["sys/class/dmi/id/board_serial"] = &fstest.MapFile{Data: []byte("BRD-77\n")}
	supplement := ReadSupplement(tree)
	if supplement.Serial != "" || supplement.BoardSerial != "BRD-77" {
		t.Errorf("supplement = %+v", supplement)
	}
	if supplement.UUID != "03000200-0400-0500-0006-000700080009" {
		t.Errorf("uuid = %q", supplement.UUID)
	}
	if supplement.Missing != nil {
		t.Errorf("missing = %v", supplement.Missing)
	}
}

// A container has no DMI, no firmware and no uptime of its own worth
// naming: every one of those is a reason, not an empty fact.
func TestCollectNamesTheAbsentTablesOfAContainer(t *testing.T) {
	tree := fstest.MapFS{
		"proc/cpuinfo":              {Data: []byte(cpuinfoARM)},
		"proc/meminfo":              {Data: []byte("MemTotal: 1024 kB\n")},
		"proc/sys/kernel/osrelease": {Data: []byte("6.8.0\n")},
		"etc/os-release":            {Data: []byte("ID=alpine\nVERSION_ID=3.20\n")},
		"run/systemd/container":     {Data: []byte("docker\n")},
	}
	snapshot := Collect(tree, time.Now())
	for _, fact := range []string{FactDMI, FactDMISerial, FactDMIUUID, FactFirmware, FactBoot, FactTimezone, FactKernelCmdline} {
		if _, missing := snapshot.Missing[fact]; !missing {
			t.Errorf("%s is not named as missing: %v", fact, snapshot.Missing)
		}
	}
	if snapshot.Virtualization.Kind != "docker" {
		t.Errorf("virtualization = %+v", snapshot.Virtualization)
	}
	if snapshot.Firmware.Mode != "" {
		t.Errorf("a container got the firmware mode %q", snapshot.Firmware.Mode)
	}
}
