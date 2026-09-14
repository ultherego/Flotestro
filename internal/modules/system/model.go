// Package system describes the platform of a host: the processor, the
// memory, the machine identity from DMI, the firmware, the kernel, the
// distribution, the timezone and the boot.
//
// The module gathers facts that change only when somebody changes the
// machine - a kernel upgrade, a firmware update, a move to another
// hypervisor. That is why it is read rarely and why the panel keeps a
// history of what it saw: a host that came up on another kernel is a fact
// worth a row, not a diff the operator has to remember.
//
// Every fact that could not be read is absent and named in Missing with
// its reason. A machine without DMI - a container, an ARM board - is not
// a machine with an empty serial number.
package system

import (
	"slices"
	"time"
)

// The names of the facts that may be missing. They key the Missing map,
// so the panel says which fact is unknown and why rather than "something
// was not read".
const (
	FactCPU            = "cpu"
	FactMemory         = "memory"
	FactDMI            = "dmi"
	FactDMISerial      = "dmi.serial"
	FactDMIUUID        = "dmi.uuid"
	FactFirmware       = "firmware"
	FactKernel         = "kernel"
	FactKernelCmdline  = "kernel.cmdline"
	FactDistribution   = "distribution"
	FactTimezone       = "timezone"
	FactBoot           = "boot"
	FactVirtualization = "virtualization"
)

// Firmware modes.
const (
	FirmwareUEFI = "uefi"
	FirmwareBIOS = "bios"
)

// CPU describes the processor as /proc/cpuinfo reports it.
type CPU struct {
	Model  string `json:"model,omitempty"`
	Vendor string `json:"vendor,omitempty"`
	// Threads is the number of logical processors the kernel sees; Cores
	// and Sockets are the physical layout when the file names it. A pointer
	// that is nil is a layout the file does not describe - ARM cpuinfo has
	// no core ids - not a machine with zero cores.
	Threads *int `json:"threads,omitempty"`
	Cores   *int `json:"cores,omitempty"`
	Sockets *int `json:"sockets,omitempty"`
	// Flags is the summary of the capability flags: the ones an operator
	// asks about, not the whole list of two hundred. FlagCount is the size
	// of the whole list.
	Flags     []string `json:"flags,omitempty"`
	FlagCount int      `json:"flag_count"`
	// MHz is the nominal frequency of the first processor.
	MHz *float64 `json:"mhz,omitempty"`
}

// Memory describes the physical memory and the swap.
type Memory struct {
	TotalBytes     *uint64 `json:"total_bytes,omitempty"`
	SwapTotalBytes *uint64 `json:"swap_total_bytes,omitempty"`
}

// DMI describes the machine as its firmware tables name it.
//
// The vendor and the product are readable by everyone; the serial numbers
// and the UUID only by root, so they come from the helper. A field that is
// empty and not in Missing is a field the firmware left blank.
type DMI struct {
	Vendor        string `json:"vendor,omitempty"`
	Product       string `json:"product,omitempty"`
	Version       string `json:"version,omitempty"`
	Family        string `json:"family,omitempty"`
	BoardVendor   string `json:"board_vendor,omitempty"`
	BoardName     string `json:"board_name,omitempty"`
	ChassisType   string `json:"chassis_type,omitempty"`
	Serial        string `json:"serial,omitempty"`
	UUID          string `json:"uuid,omitempty"`
	BoardSerial   string `json:"board_serial,omitempty"`
	ChassisSerial string `json:"chassis_serial,omitempty"`
}

// Firmware describes the BIOS or UEFI firmware and the mode the host
// booted in.
type Firmware struct {
	Vendor  string `json:"vendor,omitempty"`
	Version string `json:"version,omitempty"`
	Date    string `json:"date,omitempty"`
	// Mode is uefi or bios. Empty means it was not determined.
	Mode string `json:"mode,omitempty"`
}

// Kernel describes the running kernel.
type Kernel struct {
	Release      string `json:"release,omitempty"`
	Version      string `json:"version,omitempty"`
	Architecture string `json:"architecture,omitempty"`
	Cmdline      string `json:"cmdline,omitempty"`
}

// Distribution describes the operating system release.
type Distribution struct {
	ID         string `json:"id,omitempty"`
	Name       string `json:"name,omitempty"`
	Version    string `json:"version,omitempty"`
	Codename   string `json:"codename,omitempty"`
	PrettyName string `json:"pretty_name,omitempty"`
	// Like lists the families the distribution declares itself alike.
	Like []string `json:"like,omitempty"`
}

// Virtualization says what the host runs on, as far as the host can tell.
type Virtualization struct {
	// Kind is the hypervisor or the container runtime - kvm, vmware,
	// virtualbox, xen, hyperv, qemu, docker, lxc, systemd-nspawn - or
	// "none" for bare metal. Empty means it was not determined.
	Kind string `json:"kind,omitempty"`
	// Source names the evidence: the DMI product name, the hypervisor flag,
	// the container marker.
	Source string `json:"source,omitempty"`
}

// Boot describes the current boot of the host.
type Boot struct {
	BootedAt      *time.Time `json:"booted_at,omitempty"`
	UptimeSeconds *uint64    `json:"uptime_seconds,omitempty"`
}

// Snapshot is the platform picture of one host.
type Snapshot struct {
	CPU            CPU            `json:"cpu"`
	Memory         Memory         `json:"memory"`
	DMI            DMI            `json:"dmi"`
	Firmware       Firmware       `json:"firmware"`
	Kernel         Kernel         `json:"kernel"`
	Distribution   Distribution   `json:"distribution"`
	Virtualization Virtualization `json:"virtualization"`
	Timezone       string         `json:"timezone,omitempty"`
	Boot           Boot           `json:"boot"`
	// Missing maps a fact that was not read to the reason. A fact absent
	// from the picture and absent from this map was read and is empty.
	Missing map[string]string `json:"missing,omitempty"`
	// ObservedAt is the moment of the read: the facts are static and the
	// panel says how old the picture is.
	ObservedAt time.Time `json:"observed_at"`
}

// Supplement is the part of the picture only root can read: the DMI
// serial numbers and the UUID. The helper fills it in and the agent lays
// it over its own picture.
type Supplement struct {
	Serial        string `json:"serial,omitempty"`
	UUID          string `json:"uuid,omitempty"`
	BoardSerial   string `json:"board_serial,omitempty"`
	ChassisSerial string `json:"chassis_serial,omitempty"`
	// Missing names the facts the helper could not read either, with the
	// reason.
	Missing map[string]string `json:"missing,omitempty"`
}

// Supplemented lays the privileged facts over the picture. A fact the
// helper could not read stays missing with the helper's reason: the agent
// has no better one.
func (s Snapshot) Supplemented(supplement Supplement) Snapshot {
	result := s
	result.Missing = cloneMissing(s.Missing)
	apply := func(fact, value string) {
		if reason, missing := supplement.Missing[fact]; missing {
			result.Missing[fact] = reason
			return
		}
		delete(result.Missing, fact)
		switch fact {
		case FactDMISerial:
			result.DMI.Serial = value
		case FactDMIUUID:
			result.DMI.UUID = value
		}
	}
	apply(FactDMISerial, supplement.Serial)
	apply(FactDMIUUID, supplement.UUID)
	if _, missing := supplement.Missing[FactDMISerial]; !missing {
		result.DMI.BoardSerial = supplement.BoardSerial
		result.DMI.ChassisSerial = supplement.ChassisSerial
	}
	if len(result.Missing) == 0 {
		result.Missing = nil
	}
	return result
}

// MissingFacts lists the facts the picture lacks, in a stable order.
func (s Snapshot) MissingFacts() []string {
	if len(s.Missing) == 0 {
		return nil
	}
	names := make([]string, 0, len(s.Missing))
	for name := range s.Missing {
		names = append(names, name)
	}
	slices.Sort(names)
	return names
}

func cloneMissing(missing map[string]string) map[string]string {
	result := make(map[string]string, len(missing))
	for key, value := range missing {
		result[key] = value
	}
	return result
}
