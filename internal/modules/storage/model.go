// Package storage describes the disks, filesystems and mount points of a host.
package storage

import (
	"strings"
	"time"
)

// Block device kinds the module distinguishes.
const (
	TypeDisk      = "disk"
	TypePartition = "part"
	TypeLVM       = "lvm"
	TypeRAID      = "raid"
	TypeCrypt     = "crypt"
)

// Device is one block device.
type Device struct {
	Name string `json:"name"`
	// KernelName is the name under /sys/class/block and the target of the by-id
	// links: a logical volume is "vg-data" to lsblk and "dm-3" to the kernel.
	KernelName string `json:"kernel_name,omitempty"`
	Path       string `json:"path"`
	Type       string `json:"type"`
	// SizeBytes is the device size. Zero means an empty or unread device -
	// and then the reason is carried by the snapshot.
	SizeBytes uint64 `json:"size_bytes"`
	FSType    string `json:"fs_type,omitempty"`
	Label     string `json:"label,omitempty"`
	UUID      string `json:"uuid,omitempty"`
	PartUUID  string `json:"part_uuid,omitempty"`
	Model     string `json:"model,omitempty"`
	Serial    string `json:"serial,omitempty"`
	WWN       string `json:"wwn,omitempty"`
	// ByID is the path under /dev/disk/by-id that names this device by what it is
	// - its WWN, its serial, the UUID of the volume it carries - rather than by
	// where the kernel found it.
	ByID string `json:"by_id,omitempty"`
	// IdentityUnavailableReason says why the device has no by-id link. A
	// missing link is a fact about the device, not an empty string.
	IdentityUnavailableReason string `json:"identity_unavailable_reason,omitempty"`
	// Parent points at the parent device: a partition has a disk, a logical
	// volume has a group. Empty for top-level devices.
	Parent string `json:"parent,omitempty"`
	// Children lists the devices directly under this one: the partitions of
	// a disk, the volumes on a physical volume.
	Children []string `json:"children,omitempty"`
	// Holders lists the kernel names of the devices stacked on top of this one,
	// from /sys/class/block/<name>/holders: a device-mapper target, a software
	// RAID array, an encrypted volume.
	Holders []string `json:"holders,omitempty"`
	// RootDevice says the device or a device under it carries the root
	// filesystem.
	RootDevice         bool `json:"root_device,omitempty"`
	HasMountedChildren bool `json:"has_mounted_children,omitempty"`
	HasOpenHolders     bool `json:"has_open_holders,omitempty"`
	// Rotational tells a spinning disk from an SSD. No value means the
	// kernel did not report it, not that the device does not spin.
	Rotational *bool `json:"rotational,omitempty"`
	ReadOnly   bool  `json:"read_only"`
	// Mountpoints lists the places the device is mounted at. One device can
	// be mounted in several places.
	Mountpoints []string `json:"mountpoints,omitempty"`
	// FSSizeBytes and FSUsedBytes describe the filesystem, not the device:
	// a filesystem is at times smaller than the partition holding it.
	FSSizeBytes  *uint64 `json:"fs_size_bytes,omitempty"`
	FSUsedBytes  *uint64 `json:"fs_used_bytes,omitempty"`
	FSAvailBytes *uint64 `json:"fs_avail_bytes,omitempty"`
}

// Mount is one mount point.
type Mount struct {
	Target string `json:"target"`
	Source string `json:"source"`
	FSType string `json:"fs_type"`
	// Options are the options the filesystem is mounted with now.
	Options string `json:"options,omitempty"`
	// FstabOptions are the options written in /etc/fstab. A difference between
	// them and Options means a mount that behaves differently after a reboot.
	FstabOptions string `json:"fstab_options,omitempty"`
	// InFstab and Mounted separate two questions: whether the entry exists and
	// whether the filesystem is mounted.
	InFstab bool `json:"in_fstab"`
	Mounted bool `json:"mounted"`
	// Managed marks an entry created by the panel.
	Managed bool `json:"managed"`
	// UsedPercent and InodesUsedPercent are the usage. No value means a
	// filesystem that could not be queried - not an empty filesystem.
	UsedPercent       *uint32 `json:"used_percent,omitempty"`
	InodesUsedPercent *uint32 `json:"inodes_used_percent,omitempty"`
	SizeBytes         *uint64 `json:"size_bytes,omitempty"`
	AvailBytes        *uint64 `json:"avail_bytes,omitempty"`
}

// VolumeGroup is an LVM volume group.
type VolumeGroup struct {
	Name string `json:"name"`
	// UUID is the identity of the group.
	UUID      string `json:"uuid,omitempty"`
	SizeBytes uint64 `json:"size_bytes"`
	FreeBytes uint64 `json:"free_bytes"`
	// ExtentSizeBytes is the grain the group allocates in: a volume is always a
	// whole number of extents, so a request that is not one is rounded up by LVM
	// and the plan says so beforehand.
	ExtentSizeBytes uint64 `json:"extent_size_bytes,omitempty"`
	PVCount         int    `json:"pv_count"`
	LVCount         int    `json:"lv_count"`
}

// LogicalVolume is an LVM logical volume.
type LogicalVolume struct {
	Name  string `json:"name"`
	Group string `json:"group"`
	Path  string `json:"path"`
	// UUID is the identity of the volume; the path is a name that another
	// volume can carry after a rename.
	UUID      string `json:"uuid,omitempty"`
	SizeBytes uint64 `json:"size_bytes"`
	// Attributes is lv_attr as LVM prints it. Its first letter says what the
	// volume is: "s" a snapshot, "o" an origin, "-" an ordinary volume.
	Attributes string `json:"attributes,omitempty"`
	// Origin names the volume this one is a snapshot of; empty on an
	// ordinary volume.
	Origin string `json:"origin,omitempty"`
	// DataPercent is how full a snapshot's copy-on-write space is.
	DataPercent *float64 `json:"data_percent,omitempty"`
}

// IsSnapshot says whether the volume is a snapshot of another one.
func (l LogicalVolume) IsSnapshot() bool {
	if l.Origin != "" {
		return true
	}
	// lv_attr: "s" a snapshot, "S" an invalid snapshot, "m" a merging one.
	return len(l.Attributes) > 0 && strings.ContainsRune("sS", rune(l.Attributes[0]))
}

// PhysicalVolume is one disk or partition an LVM group is built out of.
type PhysicalVolume struct {
	Path string `json:"path"`
	// Group is empty on a physical volume that belongs to no group yet:
	// that is a disk prepared for LVM and not used, not a broken one.
	Group     string `json:"group,omitempty"`
	UUID      string `json:"uuid,omitempty"`
	SizeBytes uint64 `json:"size_bytes"`
	FreeBytes uint64 `json:"free_bytes"`
}

// Snapshot is the picture of the host disk space.
type Snapshot struct {
	Devices []Device `json:"devices,omitempty"`
	Mounts  []Mount  `json:"mounts,omitempty"`
	// FstabRevision is the digest of /etc/fstab as it was when the picture was
	// taken.
	FstabRevision string `json:"fstab_revision,omitempty"`
	// Groups and Volumes are empty on a host without LVM.
	Groups               []VolumeGroup    `json:"groups,omitempty"`
	Volumes              []LogicalVolume  `json:"volumes,omitempty"`
	PhysicalVolumes      []PhysicalVolume `json:"physical_volumes,omitempty"`
	LVMUnavailableReason string           `json:"lvm_unavailable_reason,omitempty"`
	// Arrays are the software RAID arrays of the host.
	Arrays                []RAIDArray `json:"arrays,omitempty"`
	RAIDUnavailableReason string      `json:"raid_unavailable_reason,omitempty"`
	ObservedAt            time.Time   `json:"observed_at"`
	UnavailableReason     string      `json:"unavailable_reason,omitempty"`
}

// DegradedArrays lists the arrays that have lost a member or their redundancy.
func (s Snapshot) DegradedArrays() []RAIDArray {
	var degraded []RAIDArray
	for _, array := range s.Arrays {
		if array.Degraded || array.FailedDevices > 0 {
			degraded = append(degraded, array)
		}
	}
	return degraded
}

// GroupAt returns the volume group with the given name or nil.
func (s Snapshot) GroupAt(name string) *VolumeGroup {
	for i := range s.Groups {
		if s.Groups[i].Name == name {
			return &s.Groups[i]
		}
	}
	return nil
}

// VolumeAt resolves a path to a logical volume, whichever of its two names
// the order used.
func (s Snapshot) VolumeAt(path string) *LogicalVolume {
	for i := range s.Volumes {
		if MatchesVolume(s.Volumes[i], path) {
			return &s.Volumes[i]
		}
	}
	return nil
}

// DeviceForVolume finds the block device the kernel has for a logical volume.
func (s Snapshot) DeviceForVolume(volume LogicalVolume) *Device {
	for i := range s.Devices {
		if MatchesVolume(volume, s.Devices[i].Path) {
			return &s.Devices[i]
		}
	}
	return nil
}

// PhysicalVolumeAt returns the physical volume at the path or nil.
func (s Snapshot) PhysicalVolumeAt(path string) *PhysicalVolume {
	for i := range s.PhysicalVolumes {
		if s.PhysicalVolumes[i].Path == path {
			return &s.PhysicalVolumes[i]
		}
	}
	return nil
}

// DeviceAt returns the device with the given path or nil.
func (s Snapshot) DeviceAt(path string) *Device {
	for i := range s.Devices {
		if s.Devices[i].Path == path {
			return &s.Devices[i]
		}
	}
	return nil
}

// MountAt returns the mount point with the given target or nil.
func (s Snapshot) MountAt(target string) *Mount {
	for i := range s.Mounts {
		if s.Mounts[i].Target == target {
			return &s.Mounts[i]
		}
	}
	return nil
}
