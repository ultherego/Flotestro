// Package storage describes the disks, filesystems and mount points of a
// host.
//
// The module reads the kernel state and the volume manager, not /etc/fstab
// itself: the file says what is to be mounted after a reboot, not what is
// mounted now. The difference between the two is usually the reason
// somebody opens this tab at all.
package storage

import "time"

// Block device kinds the module distinguishes.
const (
	TypeDisk      = "disk"
	TypePartition = "part"
	TypeLVM       = "lvm"
	TypeRAID      = "raid"
	TypeCrypt     = "crypt"
)

// Device is one block device.
//
// Identification goes by WWN, serial and UUID, not by /dev/sdX: the device
// name depends on the detection order and after a reboot can point at an
// entirely different disk. In a destructive operation that is the
// difference between wiping the right disk and wiping somebody else's data.
type Device struct {
	Name string `json:"name"`
	Path string `json:"path"`
	Type string `json:"type"`
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
	// Parent points at the parent device: a partition has a disk, a logical
	// volume has a group. Empty for top-level devices.
	Parent string `json:"parent,omitempty"`
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
	// FstabOptions are the options written in /etc/fstab. A difference
	// between them and Options means a mount that behaves differently after
	// a reboot.
	FstabOptions string `json:"fstab_options,omitempty"`
	// InFstab and Mounted separate two questions: whether the entry exists
	// and whether the filesystem is mounted. Four combinations mean four
	// different things, and the operator looks at this tab precisely because
	// of them.
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
	Name      string `json:"name"`
	SizeBytes uint64 `json:"size_bytes"`
	FreeBytes uint64 `json:"free_bytes"`
	PVCount   int    `json:"pv_count"`
	LVCount   int    `json:"lv_count"`
}

// LogicalVolume is an LVM logical volume.
type LogicalVolume struct {
	Name      string `json:"name"`
	Group     string `json:"group"`
	Path      string `json:"path"`
	SizeBytes uint64 `json:"size_bytes"`
}

// Snapshot is the picture of the host disk space.
type Snapshot struct {
	Devices []Device `json:"devices,omitempty"`
	Mounts  []Mount  `json:"mounts,omitempty"`
	// Groups and Volumes are empty on a host without LVM. The
	// unavailability reason is carried by LVMUnavailableReason: no groups
	// and no LVM are two different answers.
	Groups                []VolumeGroup   `json:"groups,omitempty"`
	Volumes               []LogicalVolume `json:"volumes,omitempty"`
	LVMUnavailableReason  string          `json:"lvm_unavailable_reason,omitempty"`
	RAIDUnavailableReason string          `json:"raid_unavailable_reason,omitempty"`
	ObservedAt            time.Time       `json:"observed_at"`
	UnavailableReason     string          `json:"unavailable_reason,omitempty"`
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
