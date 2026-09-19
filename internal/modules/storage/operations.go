package storage

import (
	"fmt"
	"regexp"
	"strings"
)

// Paths of the tools changing the disk space.
const (
	LVExtendPath  = "/usr/sbin/lvextend"
	LVCreatePath  = "/usr/sbin/lvcreate"
	LVRemovePath  = "/usr/sbin/lvremove"
	VGExtendPath  = "/usr/sbin/vgextend"
	PVCreatePath  = "/usr/sbin/pvcreate"
	Resize2fsPath = "/usr/sbin/resize2fs"
	XFSGrowPath   = "/usr/sbin/xfs_growfs"
	MkfsExt4Path  = "/usr/sbin/mkfs.ext4"
	MkfsXFSPath   = "/usr/sbin/mkfs.xfs"
	WipefsPath    = "/usr/sbin/wipefs"
)

var (
	lvmSize = regexp.MustCompile(`^\+?\d{1,9}[KMGTkmgt]$|^\+?\d{1,3}%(FREE|VG|PVS)$`)
	fsLabel = regexp.MustCompile(`^[A-Za-z0-9_.-]{0,16}$`)
	// An absolute size: what a new volume or a snapshot is created with.
	lvmAbsoluteSize = regexp.MustCompile(`^\d{1,9}[KMGTkmgt]$|^\d{1,3}%(FREE|VG|PVS|ORIGIN)$`)
	// LVM names: the shape LVM itself accepts. A leading hyphen would be
	// read as an option by every tool the name is handed to.
	lvmName = regexp.MustCompile(`^[A-Za-z0-9+_.][A-Za-z0-9+_.-]{0,62}$`)
)

// lvmReservedNames are the names LVM keeps for itself.
var lvmReservedNames = []string{"snapshot", "pvmove", "_mlog", "_mimage", "_rimage", "_rmeta", "_vorigin"}

// ValidateLVMName checks the name of a group, a volume or a snapshot.
func ValidateLVMName(kind, name string) error {
	if !lvmName.MatchString(name) {
		return fmt.Errorf("the %s name %q must start with a letter, a digit, a dot or an underscore and hold no other punctuation", kind, name)
	}
	if name == "." || name == ".." {
		return fmt.Errorf("the %s name %q is a directory entry, not a name", kind, name)
	}
	for _, reserved := range lvmReservedNames {
		if strings.HasPrefix(name, reserved) || strings.Contains(name, reserved) {
			return fmt.Errorf("the %s name %q uses %q, which LVM keeps for itself", kind, name, reserved)
		}
	}
	return nil
}

// LVCreateArguments assembles the command creating a logical volume in an
// existing group.
func LVCreateArguments(group, name, size string) ([]string, error) {
	if err := ValidateLVMName("group", group); err != nil {
		return nil, err
	}
	if err := ValidateLVMName("volume", name); err != nil {
		return nil, err
	}
	if !lvmAbsoluteSize.MatchString(size) {
		return nil, fmt.Errorf("the size %q must be absolute (10G) or a share of what is free (100%%FREE)", size)
	}
	arguments := []string{LVCreatePath, "--yes", "--name", name}
	if strings.Contains(size, "%") {
		// A share is given in extents, an absolute size in bytes; LVM takes
		// them under two different options and refuses the wrong one.
		arguments = append(arguments, "--extents", size)
	} else {
		arguments = append(arguments, "--size", size)
	}
	return append(arguments, group), nil
}

// LVRemoveArguments assembles the command removing a logical volume or a
// snapshot.
func LVRemoveArguments(path string) ([]string, error) {
	if !devicePath.MatchString(path) {
		return nil, fmt.Errorf("the volume %q is not a path in /dev", path)
	}
	// --yes answers the confirmation prompt; there is nobody at the other
	// end of it, and a tool waiting for an answer hangs until the timeout.
	return []string{LVRemovePath, "--yes", path}, nil
}

// SnapshotArguments assembles the command creating a snapshot of a volume.
func SnapshotArguments(origin, name, size string) ([]string, error) {
	if !devicePath.MatchString(origin) {
		return nil, fmt.Errorf("the volume %q is not a path in /dev", origin)
	}
	if err := ValidateLVMName("snapshot", name); err != nil {
		return nil, err
	}
	if !lvmAbsoluteSize.MatchString(size) {
		return nil, fmt.Errorf("the size %q must be absolute (2G) or a share of the origin (20%%ORIGIN)", size)
	}
	arguments := []string{LVCreatePath, "--yes", "--snapshot", "--name", name}
	if strings.Contains(size, "%") {
		arguments = append(arguments, "--extents", size)
	} else {
		arguments = append(arguments, "--size", size)
	}
	return append(arguments, origin), nil
}

// VGExtendArguments assembles the two commands that add a disk to a group: the
// disk is made a physical volume and then joined to the group.
func VGExtendArguments(group, device string) ([][]string, error) {
	if err := ValidateLVMName("group", group); err != nil {
		return nil, err
	}
	if !devicePath.MatchString(device) {
		return nil, fmt.Errorf("the device %q is not a path in /dev", device)
	}
	return [][]string{
		{PVCreatePath, "--yes", device},
		{VGExtendPath, group, device},
	}, nil
}

// The member operations of a software array.
const (
	RAIDFail   = "--fail"
	RAIDRemove = "--remove"
	RAIDAdd    = "--add"
)

// RAIDMemberArguments assembles "mdadm --manage <array> <verb> <member>".
func RAIDMemberArguments(array, member, verb string) ([]string, error) {
	if err := ValidateArray(array); err != nil {
		return nil, err
	}
	if !devicePath.MatchString(member) {
		return nil, fmt.Errorf("the member %q is not a path in /dev", member)
	}
	switch verb {
	case RAIDFail, RAIDRemove, RAIDAdd:
	default:
		return nil, fmt.Errorf("the panel fails, removes or adds a member, not %q", verb)
	}
	return []string{MDAdmPath, "--manage", array, verb, member}, nil
}

// DeviceIdentity describes what a non-destructive operation expects on the
// host.
type DeviceIdentity struct {
	Path   string
	ByID   string
	WWN    string
	Serial string
	UUID   string
}

// Matches compares the expected identity with the host state.
func (d DeviceIdentity) Matches(device *Device) error {
	if device == nil {
		return fmt.Errorf("the device %s does not exist on this host", d.Path)
	}
	if d.ByID != "" && device.ByID != d.ByID {
		return fmt.Errorf("the device %s is %q, and the plan assumes %q",
			d.Path, device.ByID, d.ByID)
	}
	if d.WWN != "" && device.WWN != d.WWN {
		return fmt.Errorf("the device %s has the WWN %q, and the plan assumes %q",
			d.Path, device.WWN, d.WWN)
	}
	if d.Serial != "" && device.Serial != d.Serial {
		return fmt.Errorf("the device %s has the serial %q, and the plan assumes %q",
			d.Path, device.Serial, d.Serial)
	}
	if d.UUID != "" && device.UUID != d.UUID {
		return fmt.Errorf("the device %s has the UUID %q, and the plan assumes %q",
			d.Path, device.UUID, d.UUID)
	}
	return nil
}

// InUse says whether the device or anything under it is mounted.
func InUse(snapshot Snapshot, path string) string {
	var check func(path string) string
	check = func(path string) string {
		for _, device := range snapshot.Devices {
			if device.Path == path && len(device.Mountpoints) > 0 {
				return device.Mountpoints[0]
			}
		}
		for _, device := range snapshot.Devices {
			if device.Parent != path {
				continue
			}
			if point := check(device.Path); point != "" {
				return point
			}
		}
		return ""
	}
	return check(path)
}

// MatchesVolume says whether the path points at this logical volume.
func MatchesVolume(volume LogicalVolume, path string) bool {
	if path == "" {
		return false
	}
	if volume.Path == path {
		return true
	}
	if path == "/dev/"+volume.Group+"/"+volume.Name {
		return true
	}
	doubled := func(name string) string { return strings.ReplaceAll(name, "-", "--") }
	return path == "/dev/mapper/"+doubled(volume.Group)+"-"+doubled(volume.Name)
}

// LVExtendArguments assembles the command growing a volume.
func LVExtendArguments(path, size string, resizeFS bool) ([]string, error) {
	if !strings.HasPrefix(path, "/dev/") || !devicePath.MatchString(path) {
		return nil, fmt.Errorf("the volume %q is not a path in /dev", path)
	}
	if !lvmSize.MatchString(size) {
		return nil, fmt.Errorf("the size %q must be an increment (+10G) or a share (+100%%FREE)", size)
	}
	if !strings.HasPrefix(size, "+") {
		return nil, fmt.Errorf("the panel grows a volume by the requested amount; the size must start with +")
	}
	arguments := []string{LVExtendPath, "--size", size}
	if resizeFS {
		// A filesystem grown together with the volume is one operation, not two: a
		// volume bigger than the filesystem gives not a byte of space.
		arguments = append(arguments, "--resizefs")
	}
	return append(arguments, path), nil
}

// FSResizeArguments assembles the command growing a filesystem.
func FSResizeArguments(path, fsType, mountpoint string) ([]string, error) {
	if !devicePath.MatchString(path) {
		return nil, fmt.Errorf("the device %q is not a path in /dev", path)
	}
	switch fsType {
	case "ext2", "ext3", "ext4":
		return []string{Resize2fsPath, path}, nil
	case "xfs":
		// xfs_growfs works on a mounted filesystem and takes the mount
		// point, not the device - unlike the rest.
		if mountpoint == "" {
			return nil, fmt.Errorf("xfs grows only while mounted")
		}
		return []string{XFSGrowPath, mountpoint}, nil
	}
	return nil, fmt.Errorf("the panel does not grow the filesystem %q", fsType)
}

// FormatArguments assembles the command creating a filesystem.
func FormatArguments(path, fsType, label string) ([]string, error) {
	if !devicePath.MatchString(path) {
		return nil, fmt.Errorf("the device %q is not a path in /dev", path)
	}
	if !fsLabel.MatchString(label) {
		return nil, fmt.Errorf("the label %q contains a disallowed character", label)
	}
	switch fsType {
	case "ext4":
		arguments := []string{MkfsExt4Path, "-q"}
		if label != "" {
			arguments = append(arguments, "-L", label)
		}
		return append(arguments, path), nil
	case "xfs":
		arguments := []string{MkfsXFSPath, "-q"}
		if label != "" {
			arguments = append(arguments, "-L", label)
		}
		return append(arguments, path), nil
	}
	return nil, fmt.Errorf("the panel creates an ext4 or xfs filesystem, not %q", fsType)
}

// WipeArguments assembles the command removing the filesystem signatures.
func WipeArguments(path string) ([]string, error) {
	if !devicePath.MatchString(path) {
		return nil, fmt.Errorf("the device %q is not a path in /dev", path)
	}
	return []string{WipefsPath, "--all", "--force", path}, nil
}
