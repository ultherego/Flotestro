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
	// An increment starting with "+" means nothing when there is nothing to
	// add to yet, so the two shapes stay apart.
	lvmAbsoluteSize = regexp.MustCompile(`^\d{1,9}[KMGTkmgt]$|^\d{1,3}%(FREE|VG|PVS|ORIGIN)$`)
	// LVM names: the shape LVM itself accepts. A leading hyphen would be
	// read as an option by every tool the name is handed to.
	lvmName = regexp.MustCompile(`^[A-Za-z0-9+_.][A-Za-z0-9+_.-]{0,62}$`)
)

// lvmReservedNames are the names LVM keeps for itself. A volume created
// under one of them either fails outright or collides with what LVM builds
// for a mirror or a move, so the panel refuses before the tool does.
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
//
// The group has to exist: this operation does not create one, because
// creating a group is a decision about which disks a machine gives to LVM
// rather than an operation on a running fleet.
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

// VGExtendArguments assembles the two commands that add a disk to a group:
// the disk is made a physical volume and then joined to the group.
//
// They are two commands and not one on purpose: pvcreate writes an LVM
// label over whatever the device carried, which is why this operation
// binds to the stable identity of the device the same way a format does.
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

// The member operations of a software array. Failing marks a member bad so
// the array stops using it; removing takes it out of the array; adding
// puts a device in as a spare, which the array then rebuilds onto if it is
// short of one.
const (
	RAIDFail   = "--fail"
	RAIDRemove = "--remove"
	RAIDAdd    = "--add"
)

// RAIDMemberArguments assembles "mdadm --manage <array> <verb> <member>".
//
// The array is named by path, because that is the only name mdadm takes -
// but the plan that got here was bound to the array's UUID and the
// member's by-id link, and the host compared both right before this.
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
//
// The path alone is not enough: /dev/sdb after a reboot can be a different
// disk than the one the operator viewed. Every identifier the panel gave
// is compared and the first mismatch refuses. The size is not among them:
// two disks of the same size prove nothing about each other, so a size in
// the order is a description, never a match. Destructive operations go
// through ValidateDestructiveTarget, which requires the identity instead of
// checking whatever was given.
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
//
// The check is conservative and covers descendant devices: a disk formatted
// together with the root partition is the same accident as the system disk
// formatted directly. The mount point is returned, because it explains the
// refusal to the operator better than a bare "the device is busy".
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
//
// The same volume has two names: /dev/<group>/<volume> reported by lvs and
// /dev/mapper/<group>-<volume> visible in lsblk and in fstab. A hyphen in
// the group name is doubled in the latter, because a single one separates
// the group from the volume. Comparing the bare strings therefore drifts
// exactly where the operator looks - in the mount table.
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
//
// Growing goes only upwards: an lvextend shrinking a volume cuts off data
// the filesystem considers its own. Shrinking is a separate operation and
// requires shrinking the filesystem first, so the panel does not do it
// here.
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
		// A filesystem grown together with the volume is one operation, not
		// two: a volume bigger than the filesystem gives not a byte of
		// space.
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
//
// The signatures are wiped, not the whole content: overwriting two
// terabytes with zeros takes hours and is not what the operator asks for
// when they want to reuse a disk. That the data is still physically on the
// platters is a fact the panel is meant to state directly.
func WipeArguments(path string) ([]string, error) {
	if !devicePath.MatchString(path) {
		return nil, fmt.Errorf("the device %q is not a path in /dev", path)
	}
	return []string{WipefsPath, "--all", "--force", path}, nil
}
