package agent

import (
	"context"
	"os"
	"time"

	"github.com/ultherego/flotestro/internal/modules/storage"
)

// lvmProbe reads the LVM state through the helper: the LVM tools need root.
var lvmProbe func(context.Context) (storage.Snapshot, error)

// SetLVMProbe points at the function that reads the groups and the volumes.
func SetLVMProbe(probe func(context.Context) (storage.Snapshot, error)) {
	lvmProbe = probe
}

// CollectStorage reads the disk topology and the mount points.
//
// Reading the devices and the mounts needs no root. LVM does, so it goes
// through the helper - and a host without LVM gets a reason, not an empty
// list.
func CollectStorage(ctx context.Context) storage.Snapshot {
	snapshot := storage.Snapshot{ObservedAt: time.Now().UTC()}

	if !exists(storage.LsblkPath) {
		snapshot.UnavailableReason = "this host has no lsblk binary"
		return snapshot
	}
	output, err := commandOutput(ctx, storage.LsblkPath, "-J", "-b", "-o",
		columns(storage.LsblkColumns))
	if err != nil {
		snapshot.UnavailableReason = "lsblk: " + err.Error()
		return snapshot
	}
	devices, err := storage.ParseDevices(output)
	if err != nil {
		snapshot.UnavailableReason = err.Error()
		return snapshot
	}
	snapshot.Devices = devices

	mountinfo, err := os.ReadFile("/proc/self/mountinfo")
	if err != nil {
		snapshot.UnavailableReason = "mountinfo: " + err.Error()
		return snapshot
	}
	fstab, _ := os.ReadFile("/etc/fstab")
	snapshot.Mounts = storage.MergeMounts(
		storage.ParseMountinfo(string(mountinfo)), storage.ParseFstab(string(fstab)))
	fillUsage(snapshot.Mounts)

	if lvmProbe != nil {
		lvm, err := lvmProbe(ctx)
		if err != nil {
			snapshot.LVMUnavailableReason = "helper: " + err.Error()
		} else {
			snapshot.Groups = lvm.Groups
			snapshot.Volumes = lvm.Volumes
			snapshot.LVMUnavailableReason = lvm.LVMUnavailableReason
		}
	}
	// The software arrays are read from /proc/mdstat: a missing file means a
	// kernel without the md module, not a host without arrays.
	if _, err := os.Stat("/proc/mdstat"); err != nil {
		snapshot.RAIDUnavailableReason = "this kernel has no software RAID support (/proc/mdstat)"
	}
	return snapshot
}

// columns assembles the list of columns for lsblk.
func columns(names []string) string {
	result := ""
	for i, name := range names {
		if i > 0 {
			result += ","
		}
		result += name
	}
	return result
}
