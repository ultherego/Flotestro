package system

import (
	"errors"
	"io/fs"
	"runtime"
	"slices"
	"strings"
	"time"
)

// The paths the picture is read from, relative to the root of the file
// system the collector was given. They are relative so that a test can
// hand the collector a tree of its own instead of the machine it runs on.
const (
	cpuInfoPath       = "proc/cpuinfo"
	memInfoPath       = "proc/meminfo"
	cmdlinePath       = "proc/cmdline"
	uptimePath        = "proc/uptime"
	kernelReleasePath = "proc/sys/kernel/osrelease"
	kernelVersionPath = "proc/sys/kernel/version"
	kernelArchPath    = "proc/sys/kernel/arch"
	osReleasePath     = "etc/os-release"
	osReleaseFallback = "usr/lib/os-release"
	timezonePath      = "etc/timezone"
	localtimePath     = "etc/localtime"
	dmiDir            = "sys/class/dmi/id"
	firmwareDir       = "sys/firmware"
	efiDir            = "sys/firmware/efi"
	hypervisorPath    = "sys/hypervisor/type"
	containerPath     = "run/systemd/container"
)

// Collect reads the platform picture from the given root. The root is the
// file system of the host - os.DirFS("/") - or a tree a test built.
//
// Everything here is readable without root except the DMI serial numbers
// and the UUID; those are tried, and when the read is refused they land in
// Missing for the helper to supply.
func Collect(root fs.FS, now time.Time) Snapshot {
	snapshot := Snapshot{Missing: map[string]string{}, ObservedAt: now.UTC()}
	missing := func(fact string, err error) {
		snapshot.Missing[fact] = describe(err)
	}

	if content, err := fs.ReadFile(root, cpuInfoPath); err != nil {
		missing(FactCPU, err)
	} else {
		snapshot.CPU = ParseCPUInfo(string(content))
	}

	if content, err := fs.ReadFile(root, memInfoPath); err != nil {
		missing(FactMemory, err)
	} else {
		snapshot.Memory = ParseMemInfo(string(content))
	}

	snapshot.Kernel = Kernel{
		Release:      readTrimmed(root, kernelReleasePath),
		Version:      readTrimmed(root, kernelVersionPath),
		Architecture: firstNonEmpty(readTrimmed(root, kernelArchPath), runtime.GOARCH),
	}
	if snapshot.Kernel.Release == "" {
		missing(FactKernel, errors.New(kernelReleasePath+" could not be read"))
	}
	if content, err := fs.ReadFile(root, cmdlinePath); err != nil {
		missing(FactKernelCmdline, err)
	} else {
		snapshot.Kernel.Cmdline = strings.TrimSpace(string(content))
	}

	if content, err := fs.ReadFile(root, osReleasePath); err == nil {
		snapshot.Distribution = ParseOSRelease(string(content))
	} else if fallback, fallbackErr := fs.ReadFile(root, osReleaseFallback); fallbackErr == nil {
		snapshot.Distribution = ParseOSRelease(string(fallback))
	} else {
		missing(FactDistribution, err)
	}

	snapshot.Timezone = readTimezone(root)
	if snapshot.Timezone == "" {
		missing(FactTimezone, errors.New("neither "+timezonePath+" nor the "+localtimePath+" link names a zone"))
	}

	if content, err := fs.ReadFile(root, uptimePath); err != nil {
		missing(FactBoot, err)
	} else if seconds, ok := ParseUptime(string(content)); !ok {
		missing(FactBoot, errors.New(uptimePath+" has no number in it"))
	} else {
		booted := now.UTC().Add(-time.Duration(seconds) * time.Second).Truncate(time.Second)
		snapshot.Boot = Boot{BootedAt: &booted, UptimeSeconds: &seconds}
	}

	readDMI(root, &snapshot)
	readFirmware(root, &snapshot)

	// The container marker and the hypervisor type are read only when they
	// exist: a bare-metal host has neither, and their absence is evidence,
	// not a failed read.
	snapshot.Virtualization = DetectVirtualization(
		readTrimmed(root, containerPath), readTrimmed(root, hypervisorPath),
		snapshot.DMI.Vendor, snapshot.DMI.Product,
		slices.Contains(snapshot.CPU.Flags, "hypervisor"))

	if len(snapshot.Missing) == 0 {
		snapshot.Missing = nil
	}
	return snapshot
}

// readDMI reads the machine identity from the DMI tables. The public
// fields go into the picture; the serial numbers and the UUID are tried,
// and a refusal is recorded as such rather than as an empty serial.
func readDMI(root fs.FS, snapshot *Snapshot) {
	if _, err := fs.Stat(root, dmiDir); err != nil {
		snapshot.Missing[FactDMI] = "the host has no DMI tables (" + dmiDir + " is absent)"
		snapshot.Missing[FactDMISerial] = snapshot.Missing[FactDMI]
		snapshot.Missing[FactDMIUUID] = snapshot.Missing[FactDMI]
		return
	}
	snapshot.DMI = DMI{
		Vendor:      readTrimmed(root, dmiDir+"/sys_vendor"),
		Product:     readTrimmed(root, dmiDir+"/product_name"),
		Version:     readTrimmed(root, dmiDir+"/product_version"),
		Family:      readTrimmed(root, dmiDir+"/product_family"),
		BoardVendor: readTrimmed(root, dmiDir+"/board_vendor"),
		BoardName:   readTrimmed(root, dmiDir+"/board_name"),
		ChassisType: ChassisType(readTrimmed(root, dmiDir+"/chassis_type")),
	}
	supplement := ReadSupplement(root)
	*snapshot = snapshot.Supplemented(supplement)
	if snapshot.Missing == nil {
		snapshot.Missing = map[string]string{}
	}
}

// ReadSupplement reads the DMI facts that belong to root: the serial
// numbers and the UUID. The helper calls it as root; the agent calls it
// too and gets the refusal it then asks the helper about.
func ReadSupplement(root fs.FS) Supplement {
	supplement := Supplement{Missing: map[string]string{}}
	if _, err := fs.Stat(root, dmiDir); err != nil {
		reason := "the host has no DMI tables (" + dmiDir + " is absent)"
		supplement.Missing[FactDMISerial] = reason
		supplement.Missing[FactDMIUUID] = reason
		return supplement
	}
	serial, err := fs.ReadFile(root, dmiDir+"/product_serial")
	if err != nil {
		supplement.Missing[FactDMISerial] = describe(err)
	} else {
		supplement.Serial = blankToEmpty(string(serial))
		supplement.BoardSerial = blankToEmpty(readTrimmed(root, dmiDir+"/board_serial"))
		supplement.ChassisSerial = blankToEmpty(readTrimmed(root, dmiDir+"/chassis_serial"))
	}
	uuid, err := fs.ReadFile(root, dmiDir+"/product_uuid")
	if err != nil {
		supplement.Missing[FactDMIUUID] = describe(err)
	} else {
		supplement.UUID = blankToEmpty(string(uuid))
	}
	if len(supplement.Missing) == 0 {
		supplement.Missing = nil
	}
	return supplement
}

// readFirmware reads the BIOS identity and decides the boot mode. A host
// without /sys/firmware at all - a container - has no firmware to speak
// of, which is recorded as such.
func readFirmware(root fs.FS, snapshot *Snapshot) {
	snapshot.Firmware = Firmware{
		Vendor:  readTrimmed(root, dmiDir+"/bios_vendor"),
		Version: readTrimmed(root, dmiDir+"/bios_version"),
		Date:    readTrimmed(root, dmiDir+"/bios_date"),
	}
	switch {
	case exists(root, efiDir):
		snapshot.Firmware.Mode = FirmwareUEFI
	case exists(root, firmwareDir):
		snapshot.Firmware.Mode = FirmwareBIOS
	default:
		snapshot.Missing[FactFirmware] = "the host exposes no firmware (" + firmwareDir + " is absent)"
	}
	if snapshot.Firmware.Vendor == "" && snapshot.Firmware.Version == "" {
		if _, err := fs.Stat(root, dmiDir+"/bios_vendor"); err != nil {
			if _, already := snapshot.Missing[FactFirmware]; !already {
				snapshot.Missing[FactFirmware] = "the DMI tables name no firmware (" + describe(err) + ")"
			}
		}
	}
}

// readTimezone reads the zone from /etc/timezone, where Debian writes it,
// and otherwise from the target of the /etc/localtime link, where every
// distribution keeps it.
func readTimezone(root fs.FS) string {
	if zone := readTrimmed(root, timezonePath); zone != "" {
		return zone
	}
	target, err := fs.ReadLink(root, localtimePath)
	if err != nil {
		return ""
	}
	return TimezoneFromLocaltime(target)
}

func readTrimmed(root fs.FS, path string) string {
	content, err := fs.ReadFile(root, path)
	if err != nil {
		return ""
	}
	return strings.TrimSpace(string(content))
}

func exists(root fs.FS, path string) bool {
	_, err := fs.Stat(root, path)
	return err == nil
}

// blankToEmpty drops the placeholders firmware writes when it has no
// value: a serial number of "Not Specified" is no serial number.
func blankToEmpty(value string) string {
	value = strings.TrimSpace(value)
	switch strings.ToLower(value) {
	case "", "none", "not specified", "to be filled by o.e.m.", "default string", "system serial number",
		"0", "00000000-0000-0000-0000-000000000000", "unknown", "n/a":
		return ""
	}
	return value
}

// describe turns a read error into a reason the operator can act on. A
// refused read says so in those words, because the panel tells a refusal
// from a missing file when it decides what is unknown.
func describe(err error) string {
	var pathErr *fs.PathError
	if errors.As(err, &pathErr) {
		switch {
		case errors.Is(err, fs.ErrPermission):
			return "permission denied: only root reads /" + pathErr.Path
		case errors.Is(err, fs.ErrNotExist):
			return "/" + pathErr.Path + " does not exist"
		}
		return "/" + pathErr.Path + ": " + pathErr.Err.Error()
	}
	return err.Error()
}
