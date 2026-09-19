package storage

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
)

// Where the kernel and udev publish what lsblk does not report.
const (
	ByIDDirectory = "/dev/disk/by-id"
	SysClassBlock = "/sys/class/block"
)

// Refusal codes of a destructive device operation.
const (
	// CodeStableIdentityRequired: the plan names the device by nothing that
	// survives a reboot.
	CodeStableIdentityRequired = "stable_identity_required"
	// CodeDiskChanged: the device under the path is not the one the plan
	// was computed for.
	CodeDiskChanged = "disk_changed"
	// CodeDiskInUse: the device carries the root filesystem, mounted partitions
	// or is a member of a volume group, an array or an encrypted container.
	CodeDiskInUse = "disk_in_use"
	// CodeFilesystemErrorsRemain: a repair ran and the filesystem still has
	// errors.
	CodeFilesystemErrorsRemain = "filesystem_errors_remain"
)

// Refusal is a refusal with a typed code. The helper answers with the code,
// the panel shows the reason.
type Refusal struct {
	Code   string
	Reason string
}

func (r *Refusal) Error() string { return r.Reason }

// ValidateDestructiveTarget decides whether a destructive operation may touch
// the observed device.
func ValidateDestructiveTarget(plan DevicePlan, observed Device) error {
	if plan.ByID == "" {
		return &Refusal{Code: CodeStableIdentityRequired,
			Reason: "the plan names " + plan.Device + " by path only; the device has no /dev/disk/by-id link to bind to"}
	}
	// A physical device is known by its WWN or serial; a device-mapper or RAID
	// device has neither and is known by the UUID its by-id link carries.
	if plan.WWN == "" && plan.Serial == "" && !volumeIdentity(plan.ByID) {
		return &Refusal{Code: CodeStableIdentityRequired,
			Reason: "the plan names " + plan.Device + " without a WWN or a serial; the link " +
				filepath.Base(plan.ByID) + " does not identify the hardware"}
	}
	if observed.ByID != plan.ByID || observed.WWN != plan.WWN {
		return &Refusal{Code: CodeDiskChanged,
			Reason: fmt.Sprintf("the device %s is now %s (WWN %q), and the plan was computed for %s (WWN %q)",
				plan.Device, orNone(observed.ByID), observed.WWN, orNone(plan.ByID), plan.WWN)}
	}
	if plan.Serial != "" && observed.Serial != plan.Serial {
		return &Refusal{Code: CodeDiskChanged,
			Reason: fmt.Sprintf("the device %s has the serial %q, and the plan was computed for %q",
				plan.Device, observed.Serial, plan.Serial)}
	}
	switch {
	case observed.RootDevice:
		return &Refusal{Code: CodeDiskInUse,
			Reason: "the device " + plan.Device + " carries the root filesystem of this host"}
	case len(observed.Mountpoints) > 0:
		return &Refusal{Code: CodeDiskInUse,
			Reason: "the device " + plan.Device + " is mounted at " + observed.Mountpoints[0]}
	case observed.HasMountedChildren:
		return &Refusal{Code: CodeDiskInUse,
			Reason: "a partition or volume on " + plan.Device + " is mounted or used as swap"}
	case observed.HasOpenHolders:
		return &Refusal{Code: CodeDiskInUse,
			Reason: "the device " + plan.Device + " is held by " + strings.Join(holdersOf(observed), ", ") +
				" (a volume group, an array or an encrypted container)"}
	}
	return nil
}

func holdersOf(device Device) []string {
	if len(device.Holders) > 0 {
		return device.Holders
	}
	return []string{"another device"}
}

func orNone(value string) string {
	if value == "" {
		return "no by-id link"
	}
	return value
}

// volumeIdentity says whether the by-id link carries the UUID of a
// device-mapper or RAID volume, which is the identity such a device has.
func volumeIdentity(byID string) bool {
	name := filepath.Base(byID)
	for _, prefix := range []string{"dm-uuid-", "md-uuid-", "lvm-pv-uuid-"} {
		if strings.HasPrefix(name, prefix) {
			return true
		}
	}
	return false
}

// byIDRanks orders the by-id links of one device from the most to the least
// telling.
var byIDRanks = []string{
	"wwn-", "nvme-eui.", "scsi-3", "scsi-S", "scsi-", "ata-", "nvme-", "virtio-", "usb-",
	"mmc-", "dm-uuid-", "md-uuid-", "lvm-pv-uuid-",
}

func byIDRank(name string) int {
	for i, prefix := range byIDRanks {
		if strings.HasPrefix(name, prefix) {
			return i
		}
	}
	return -1
}

// ChooseByID picks the by-id path that identifies the device best out of the
// links pointing at it.
func ChooseByID(links []string) string {
	best, bestRank := "", -1
	for _, link := range links {
		name := filepath.Base(link)
		rank := byIDRank(name)
		if rank < 0 {
			continue
		}
		if best == "" || rank < bestRank || (rank == bestRank && name < filepath.Base(best)) {
			best, bestRank = link, rank
		}
	}
	return best
}

// ReadByIDLinks reads the by-id directory and maps every kernel device
// name to the links pointing at it.
func ReadByIDLinks(directory string) (map[string][]string, error) {
	entries, err := os.ReadDir(directory)
	if err != nil {
		return nil, err
	}
	links := map[string][]string{}
	for _, entry := range entries {
		if entry.Type()&os.ModeSymlink == 0 {
			continue
		}
		path := filepath.Join(directory, entry.Name())
		target, err := os.Readlink(path)
		if err != nil {
			continue
		}
		name := filepath.Base(target)
		links[name] = append(links[name], path)
	}
	return links, nil
}

// ReadHolders lists the devices stacked on the named one.
func ReadHolders(sysClassBlock, name string) []string {
	entries, err := os.ReadDir(filepath.Join(sysClassBlock, name, "holders"))
	if err != nil {
		return nil
	}
	var holders []string
	for _, entry := range entries {
		holders = append(holders, entry.Name())
	}
	sort.Strings(holders)
	return holders
}

// ReadIdentity completes the devices with what the host publishes outside
// lsblk: the by-id links and the holders.
func ReadIdentity(devices []Device) {
	links, err := ReadByIDLinks(ByIDDirectory)
	holders := map[string][]string{}
	for _, device := range devices {
		if held := ReadHolders(SysClassBlock, kernelName(device)); len(held) > 0 {
			holders[kernelName(device)] = held
		}
	}
	reason := ""
	if err != nil {
		reason = "the directory " + ByIDDirectory + " could not be read: " + err.Error()
	}
	FillIdentity(devices, links, holders, reason)
}

// FillIdentity assigns the by-id links and the holders and completes the
// topology flags that depend on them.
func FillIdentity(devices []Device, links map[string][]string, holders map[string][]string,
	unavailableReason string) {
	for i := range devices {
		device := &devices[i]
		device.ByID = ChooseByID(links[kernelName(*device)])
		device.Holders = holders[kernelName(*device)]
		switch {
		case device.ByID != "":
			device.IdentityUnavailableReason = ""
		case unavailableReason != "":
			device.IdentityUnavailableReason = unavailableReason
		default:
			device.IdentityUnavailableReason = "no /dev/disk/by-id link names " + device.Path +
				"; the device reports neither a WWN nor a serial"
		}
	}
	CompleteTopology(devices)
}

// kernelName is the name the by-id links and /sys/class/block use. lsblk
// prints the device-mapper name for a volume; the kernel knows it as dm-N.
func kernelName(device Device) string {
	if device.KernelName != "" {
		return device.KernelName
	}
	return device.Name
}

// CompleteTopology fills the fields derived from the whole list: the children
// of every device and whether the device or anything under it carries root, is
// mounted or is held by another device.
func CompleteTopology(devices []Device) {
	children := map[string][]string{}
	for _, device := range devices {
		if device.Parent != "" {
			children[device.Parent] = append(children[device.Parent], device.Path)
		}
	}
	byPath := map[string]int{}
	for i, device := range devices {
		byPath[device.Path] = i
		devices[i].Children = children[device.Path]
	}
	var walk func(path string, depth int) (root, mounted, held bool)
	walk = func(path string, depth int) (bool, bool, bool) {
		index, ok := byPath[path]
		// A topology deeper than the kernel allows is a loop in the input,
		// not a device tree.
		if !ok || depth > 32 {
			return false, false, false
		}
		device := devices[index]
		root, mounted, held := false, false, len(device.Holders) > 0
		for _, point := range device.Mountpoints {
			if point == "/" {
				root = true
			}
			mounted = true
		}
		for _, child := range children[path] {
			childRoot, childMounted, childHeld := walk(child, depth+1)
			root = root || childRoot
			mounted = mounted || childMounted
			held = held || childHeld
		}
		return root, mounted, held
	}
	for i := range devices {
		device := &devices[i]
		root, _, held := walk(device.Path, 0)
		device.RootDevice = root
		device.HasOpenHolders = held
		device.HasMountedChildren = false
		for _, child := range children[device.Path] {
			_, mounted, _ := walk(child, 1)
			if mounted {
				device.HasMountedChildren = true
			}
		}
	}
}

// FstabRevision digests the content of /etc/fstab.
func FstabRevision(content []byte) string {
	sum := sha256.Sum256(content)
	return hex.EncodeToString(sum[:])
}
