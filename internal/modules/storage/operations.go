package storage

import (
	"fmt"
	"regexp"
	"strings"
)

// Paths of the tools changing the disk space.
const (
	LVExtendPath  = "/usr/sbin/lvextend"
	Resize2fsPath = "/usr/sbin/resize2fs"
	XFSGrowPath   = "/usr/sbin/xfs_growfs"
	MkfsExt4Path  = "/usr/sbin/mkfs.ext4"
	MkfsXFSPath   = "/usr/sbin/mkfs.xfs"
	WipefsPath    = "/usr/sbin/wipefs"
)

var (
	lvmSize = regexp.MustCompile(`^\+?\d{1,9}[KMGTkmgt]$|^\+?\d{1,3}%(FREE|VG|PVS)$`)
	fsLabel = regexp.MustCompile(`^[A-Za-z0-9_.-]{0,16}$`)
)

// DeviceIdentity describes what the operation expects on the host.
//
// The path alone is not enough: /dev/sdb after a reboot can be a different
// disk than the one the operator viewed. In formatting and wiping that is
// the difference between an empty disk and somebody else's data, so the
// host checks everything the panel gave - and refuses at the first
// mismatch.
type DeviceIdentity struct {
	Path      string
	Serial    string
	UUID      string
	SizeBytes uint64
}

// Matches compares the expected identity with the host state.
func (d DeviceIdentity) Matches(device *Device) error {
	if device == nil {
		return fmt.Errorf("the device %s does not exist on this host", d.Path)
	}
	if d.Serial != "" && device.Serial != d.Serial {
		return fmt.Errorf("the device %s has the serial %q, and the plan assumes %q",
			d.Path, device.Serial, d.Serial)
	}
	if d.UUID != "" && device.UUID != d.UUID {
		return fmt.Errorf("the device %s has the UUID %q, and the plan assumes %q",
			d.Path, device.UUID, d.UUID)
	}
	// The size decides where the disk has neither a serial nor a UUID.
	if d.SizeBytes != 0 && device.SizeBytes != d.SizeBytes {
		return fmt.Errorf("the device %s has %d bytes, and the plan assumes %d",
			d.Path, device.SizeBytes, d.SizeBytes)
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
