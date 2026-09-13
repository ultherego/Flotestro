package storage

import (
	"strings"
	"testing"
)

func deviceState() Snapshot {
	return Snapshot{
		Devices: []Device{
			{Path: "/dev/sdb", FSType: "ext4", UUID: "abc", SizeBytes: 2 << 30},
			{Path: "/dev/sda1", FSType: "ext4", UUID: "root", Mountpoints: []string{"/"}},
			{Path: "/dev/mapper/vg0-data", FSType: "xfs", UUID: "lv", Mountpoints: []string{"/data"}},
			{Path: "/dev/sdc"},
		},
		Groups: []VolumeGroup{{Name: "vg0", FreeBytes: 1 << 30}, {Name: "vg1", FreeBytes: 0}},
		Volumes: []LogicalVolume{{Name: "data", Group: "vg0", Path: "/dev/mapper/vg0-data", SizeBytes: 4 << 30},
			{Name: "full", Group: "vg1", Path: "/dev/mapper/vg1-full"}},
	}
}

func TestCheckPlanRefusesMounted(t *testing.T) {
	ok := ComputeCheck(deviceState(), "/dev/sdb", false)
	if ok.Action != PlanRun || ok.Refusal != "" || ok.UUID != "abc" {
		t.Errorf("check of an unmounted device: %+v", ok)
	}
	mounted := ComputeCheck(deviceState(), "/dev/sda1", false)
	if !strings.Contains(mounted.Refusal, "unmounting") {
		t.Errorf("check of a mounted device without a refusal: %+v", mounted)
	}
	noFS := ComputeCheck(deviceState(), "/dev/sdc", false)
	if !strings.Contains(noFS.Refusal, "no filesystem") {
		t.Errorf("device without a filesystem: %+v", noFS)
	}
	if missing := ComputeCheck(deviceState(), "/dev/sdz", false); missing.Refusal == "" || missing.Found {
		t.Errorf("a device that does not exist: %+v", missing)
	}
}

func TestFSResizePlanDependsOnType(t *testing.T) {
	ext := ComputeFSResize(deviceState(), "/dev/sdb")
	if ext.Action != PlanRun || !strings.Contains(ext.Changes[0], "resize2fs") {
		t.Errorf("ext4: %+v", ext)
	}
	xfs := ComputeFSResize(deviceState(), "/dev/mapper/vg0-data")
	if xfs.Action != PlanRun || !strings.Contains(xfs.Changes[0], "/data") {
		t.Errorf("mounted xfs: %+v", xfs)
	}
	if none := ComputeFSResize(deviceState(), "/dev/sdc"); none.Refusal == "" {
		t.Errorf("a device without a filesystem without a refusal: %+v", none)
	}
}

func TestLVExtendPlanCountsFreeSpace(t *testing.T) {
	ok := ComputeLVExtend(deviceState(), "/dev/vg0/data", "+512M")
	if ok.Action != PlanRun || ok.Group != "vg0" || ok.FreeBytes != 1<<30 || len(ok.Changes) != 2 {
		t.Errorf("extension with free space: %+v", ok)
	}
	full := ComputeLVExtend(deviceState(), "/dev/vg1/full", "+512M")
	if !strings.Contains(full.Refusal, "no free space") {
		t.Errorf("a group without space without a refusal: %+v", full)
	}
	if missing := ComputeLVExtend(deviceState(), "/dev/vg9/x", "+1G"); missing.Refusal == "" {
		t.Errorf("a volume that does not exist: %+v", missing)
	}
	noLVM := ComputeLVExtend(Snapshot{LVMUnavailableReason: "no lvm"}, "/dev/vg0/data", "+1G")
	if noLVM.Refusal != "no lvm" {
		t.Errorf("host without LVM: %+v", noLVM)
	}
	if ok.PlanHash == full.PlanHash || ok.PlanHash == "" {
		t.Error("plan fingerprints do not differ")
	}
}
