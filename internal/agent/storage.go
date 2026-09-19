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

// CollectStorage reads the disk topology and the mount points. Reading the
// devices and the mounts needs no root.
func CollectStorage(ctx context.Context) storage.Snapshot {
	snapshot := storage.Snapshot{ObservedAt: time.Now().UTC()}

	if !exists(storage.LsblkPath) {
		snapshot.UnavailableReason = "this host has no lsblk binary"
		return snapshot
	}
	output, err := commandOutput(ctx, storage.LsblkPath, "-J", "-b", "-o",
		storage.Columns(storage.LsblkColumns))
	if err != nil {
		snapshot.UnavailableReason = "lsblk: " + err.Error()
		return snapshot
	}
	devices, err := storage.ParseDevices(output)
	if err != nil {
		snapshot.UnavailableReason = err.Error()
		return snapshot
	}
	// The by-id links and the holders need no root either: /dev/disk/by-id and
	// /sys/class/block are readable by everyone.
	storage.ReadIdentity(devices)
	snapshot.Devices = devices

	mountinfo, err := os.ReadFile("/proc/self/mountinfo")
	if err != nil {
		snapshot.UnavailableReason = "mountinfo: " + err.Error()
		return snapshot
	}
	fstab, _ := os.ReadFile(storage.FstabPath)
	snapshot.Mounts = storage.MergeMounts(
		storage.ParseMountinfo(string(mountinfo)), storage.ParseFstab(string(fstab)))
	snapshot.FstabRevision = storage.FstabRevision(fstab)
	fillUsage(snapshot.Mounts)

	if lvmProbe != nil {
		lvm, err := lvmProbe(ctx)
		if err != nil {
			snapshot.LVMUnavailableReason = "helper: " + err.Error()
			// The arrays were to come from the same call.
			snapshot.Arrays, snapshot.RAIDUnavailableReason = kernelArrays("helper: " + err.Error())
		} else {
			snapshot.Groups = lvm.Groups
			snapshot.Volumes = lvm.Volumes
			snapshot.PhysicalVolumes = lvm.PhysicalVolumes
			snapshot.LVMUnavailableReason = lvm.LVMUnavailableReason
			snapshot.Arrays = lvm.Arrays
			snapshot.RAIDUnavailableReason = lvm.RAIDUnavailableReason
		}
	} else {
		snapshot.Arrays, snapshot.RAIDUnavailableReason = kernelArrays("the agent has no helper to read the array superblocks")
	}
	// mdadm knows nothing about /dev/disk/by-id; the identity a member operation
	// binds to comes from the block device list, which is read above without
	// root.
	storage.FillMemberIdentity(snapshot.Arrays, snapshot.Devices)
	return snapshot
}

// kernelArrays reads /proc/mdstat, which needs no privilege. It is the
// fallback for a read that could not reach the helper.
func kernelArrays(detailReason string) ([]storage.RAIDArray, string) {
	content, err := os.ReadFile(storage.MDStatPath)
	if err != nil {
		return nil, "this kernel has no software RAID (" + storage.MDStatPath + ")"
	}
	arrays, err := storage.ParseMDStat(string(content))
	if err != nil {
		return nil, "reading " + storage.MDStatPath + ": " + err.Error()
	}
	storage.MergeArrayDetail(arrays, nil, detailReason)
	return arrays, ""
}
