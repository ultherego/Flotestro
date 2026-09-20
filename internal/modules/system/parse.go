package system

import (
	"slices"
	"strconv"
	"strings"
)

// notableFlags are the processor flags an operator asks about: whether the
// machine can host virtual machines, whether it is one, which crypto and
// vector instructions it has and which mitigations the kernel found.
var notableFlags = []string{
	// Virtualization: a host of guests, or a guest itself.
	"vmx", "svm", "hypervisor",
	// The instruction sets the workloads depend on.
	"lm", "nx", "sse4_2", "avx", "avx2", "avx512f", "aes", "sha_ni", "rdrand", "rdseed",
	"fsgsbase", "pcid", "constant_tsc", "tsc_deadline_timer",
	// The mitigations the kernel reports as flags.
	"smep", "smap", "pti", "ibrs", "ibpb", "stibp", "ssbd", "md_clear", "flush_l1d",
	// ARM features.
	"asimd", "sha1", "sha2", "crc32", "atomics", "sve",
}

// ParseCPUInfo reads the processor from the content of /proc/cpuinfo. The file
// is one block per logical processor.
func ParseCPUInfo(content string) CPU {
	cpu := CPU{}
	threads := 0
	sockets := map[string]bool{}
	coresBySocket := map[string]int{}
	physicalCores := map[string]bool{}
	seenFlags := false
	// The model is named differently by every architecture; the candidates are
	// kept by key and the best one chosen at the end, so a board that writes both
	// "Hardware" and "Model" is named by the friendlier line.
	models := map[string]string{}
	// The "physical id" of the block being read carries to the "core id" and "cpu
	// cores" lines below it: cpuinfo writes the id before the counts, so the
	// parse is one pass.
	currentSocket := ""
	for _, line := range strings.Split(content, "\n") {
		key, value, found := strings.Cut(line, ":")
		if !found {
			continue
		}
		key = strings.TrimSpace(key)
		value = strings.TrimSpace(value)
		switch key {
		case "processor":
			// ARM cpuinfo has a "processor" line per core too; some MIPS
			// boards write "processor : 0" without a number - both count.
			threads++
		case "vendor_id", "CPU implementer":
			if cpu.Vendor == "" {
				cpu.Vendor = value
			}
		case "model name", "Model", "cpu model", "Hardware":
			// "model name" is the x86 name; the others are what ARM, MIPS and
			// the boards write.
			if _, seen := models[key]; !seen {
				models[key] = value
			}
		case "cpu MHz":
			if cpu.MHz == nil {
				if mhz, err := strconv.ParseFloat(value, 64); err == nil {
					cpu.MHz = &mhz
				}
			}
		case "physical id":
			sockets[value] = true
			currentSocket = value
		case "core id":
			physicalCores[currentSocket+"/"+value] = true
		case "cpu cores":
			if cores, err := strconv.Atoi(value); err == nil {
				coresBySocket[currentSocket] = cores
			}
		case "flags", "Features":
			if seenFlags {
				continue
			}
			seenFlags = true
			all := strings.Fields(value)
			cpu.FlagCount = len(all)
			for _, flag := range notableFlags {
				if slices.Contains(all, flag) {
					cpu.Flags = append(cpu.Flags, flag)
				}
			}
		}
	}
	cpu.Model = firstNonEmpty(models["model name"], models["Model"], models["Hardware"], models["cpu model"])
	if threads > 0 {
		cpu.Threads = &threads
	}
	if len(sockets) > 0 {
		count := len(sockets)
		cpu.Sockets = &count
	}
	// The core count comes from "cpu cores" per socket when the file names it;
	// otherwise from the distinct core ids.
	switch {
	case len(coresBySocket) > 0:
		total := 0
		for _, cores := range coresBySocket {
			total += cores
		}
		cpu.Cores = &total
	case len(physicalCores) > 0:
		total := len(physicalCores)
		cpu.Cores = &total
	}
	return cpu
}

// ParseMemInfo reads the memory totals from the content of /proc/meminfo.
// The values are in kibibytes there and in bytes here.
func ParseMemInfo(content string) Memory {
	memory := Memory{}
	for _, line := range strings.Split(content, "\n") {
		key, value, found := strings.Cut(line, ":")
		if !found {
			continue
		}
		fields := strings.Fields(value)
		if len(fields) == 0 {
			continue
		}
		kib, err := strconv.ParseUint(fields[0], 10, 64)
		if err != nil {
			continue
		}
		bytes := kib * 1024
		switch strings.TrimSpace(key) {
		case "MemTotal":
			memory.TotalBytes = &bytes
		case "SwapTotal":
			memory.SwapTotalBytes = &bytes
		}
	}
	return memory
}

// ParseOSRelease reads the distribution from the content of os-release.
func ParseOSRelease(content string) Distribution {
	values := map[string]string{}
	for _, line := range strings.Split(content, "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		key, value, found := strings.Cut(line, "=")
		if !found {
			continue
		}
		values[strings.TrimSpace(key)] = strings.Trim(strings.TrimSpace(value), `"'`)
	}
	distribution := Distribution{
		ID:         values["ID"],
		Name:       values["NAME"],
		Version:    firstNonEmpty(values["VERSION_ID"], values["VERSION"]),
		Codename:   firstNonEmpty(values["VERSION_CODENAME"], values["UBUNTU_CODENAME"]),
		PrettyName: values["PRETTY_NAME"],
	}
	if like := strings.Fields(values["ID_LIKE"]); len(like) > 0 {
		distribution.Like = like
	}
	return distribution
}

// chassisTypes translates the SMBIOS chassis type into words. The numbers come
// from the SMBIOS specification, table "System Enclosure or Chassis Types".
var chassisTypes = map[string]string{
	"1": "other", "2": "unknown", "3": "desktop", "4": "low profile desktop",
	"5": "pizza box", "6": "mini tower", "7": "tower", "8": "portable",
	"9": "laptop", "10": "notebook", "11": "hand held", "12": "docking station",
	"13": "all in one", "14": "sub notebook", "15": "space-saving", "16": "lunch box",
	"17": "main server chassis", "18": "expansion chassis", "19": "sub chassis",
	"20": "bus expansion chassis", "21": "peripheral chassis", "22": "RAID chassis",
	"23": "rack mount chassis", "24": "sealed-case PC", "25": "multi-system chassis",
	"26": "compact PCI", "27": "advanced TCA", "28": "blade", "29": "blade enclosure",
	"30": "tablet", "31": "convertible", "32": "detachable", "33": "IoT gateway",
	"34": "embedded PC", "35": "mini PC", "36": "stick PC",
}

// ChassisType names an SMBIOS chassis type. An unknown number stays a
// number: the specification grows and a new type is not "unknown".
func ChassisType(code string) string {
	code = strings.TrimSpace(code)
	if name, ok := chassisTypes[code]; ok {
		return name
	}
	return code
}

// DetectVirtualization decides what the host runs on from the evidence it was
// given: systemd's container marker, sysfs, DMI, and the processor flag.
func DetectVirtualization(container, sysfsHypervisor, dmiVendor, dmiProduct string, hypervisorFlag bool) Virtualization {
	if container = strings.TrimSpace(container); container != "" {
		return Virtualization{Kind: container, Source: "/run/systemd/container"}
	}
	if kind := strings.TrimSpace(strings.ToLower(sysfsHypervisor)); kind != "" {
		return Virtualization{Kind: kind, Source: "/sys/hypervisor/type"}
	}
	claim := strings.ToLower(dmiVendor + " " + dmiProduct)
	for _, candidate := range []struct{ marker, kind string }{
		{"vmware", "vmware"}, {"virtualbox", "virtualbox"}, {"kvm", "kvm"},
		{"qemu", "qemu"}, {"bochs", "qemu"}, {"xen", "xen"}, {"microsoft corporation virtual machine", "hyperv"},
		{"hyper-v", "hyperv"}, {"parallels", "parallels"}, {"bhyve", "bhyve"},
		{"amazon ec2", "kvm"}, {"google compute engine", "kvm"}, {"openstack", "kvm"},
	} {
		if strings.Contains(claim, candidate.marker) {
			return Virtualization{Kind: candidate.kind, Source: "dmi: " + strings.TrimSpace(dmiVendor+" "+dmiProduct)}
		}
	}
	if hypervisorFlag {
		return Virtualization{Kind: "hypervisor", Source: "the hypervisor flag of the processor"}
	}
	return Virtualization{Kind: "none", Source: "no hypervisor evidence"}
}

// TimezoneFromLocaltime reads the zone name from the target of the
// /etc/localtime link: everything after the zoneinfo directory.
func TimezoneFromLocaltime(target string) string {
	target = strings.TrimSpace(target)
	if target == "" {
		return ""
	}
	if index := strings.Index(target, "zoneinfo/"); index >= 0 {
		return target[index+len("zoneinfo/"):]
	}
	return ""
}

// ParseUptime reads the seconds since boot from the content of
// /proc/uptime.
func ParseUptime(content string) (uint64, bool) {
	fields := strings.Fields(content)
	if len(fields) == 0 {
		return 0, false
	}
	seconds, err := strconv.ParseFloat(fields[0], 64)
	if err != nil || seconds < 0 {
		return 0, false
	}
	return uint64(seconds), true
}

func firstNonEmpty(values ...string) string {
	for _, value := range values {
		if value != "" {
			return value
		}
	}
	return ""
}
