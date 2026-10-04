package storage

import (
	"strings"
	"testing"
)

func deviceState() Snapshot {
	return Snapshot{
		Devices: []Device{
			{Path: "/dev/sdb", FSType: "ext4", UUID: "abc", Label: "spare", SizeBytes: 2 << 30},
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

// One payload goes to every host of a campaign, and the letter the kernel
// gives a disk is not the same on two machines: the plans take the device by
// label and by UUID, as every other place that names a device does, and the
// plan they return names the path this host gives it.
func TestADevicePlanTakesTheDeviceByLabelAndByUUID(t *testing.T) {
	for _, named := range []string{"LABEL=spare", "UUID=abc", "/dev/sdb"} {
		plan := ComputeCheck(deviceState(), named, false)
		if plan.Action != PlanRun || plan.Refusal != "" {
			t.Fatalf("%s: %+v", named, plan)
		}
		if plan.Device != "/dev/sdb" {
			t.Fatalf("%s: the plan names the device %q, not the path the host gives it", named, plan.Device)
		}
		// The same device named three ways is one plan: the digest an operator
		// consents to cannot depend on the form the order used.
		if plan.PlanHash != ComputeCheck(deviceState(), "/dev/sdb", false).PlanHash {
			t.Fatalf("%s: a different plan digest than the same device by path", named)
		}
	}
	// And one nothing answers to is refused, not guessed at.
	if plan := ComputeCheck(deviceState(), "LABEL=nowhere", false); plan.Refusal == "" || plan.Found {
		t.Fatalf("a label no device carries: %+v", plan)
	}
	// Growing a filesystem and the destructive pair take the same forms.
	if plan := ComputeFSResize(deviceState(), "LABEL=spare"); plan.Action != PlanRun ||
		plan.Device != "/dev/sdb" {
		t.Fatalf("resize by label: %+v", plan)
	}
	// The destructive pair as well - with a device that carries the stable
	// identity they insist on.
	identified := Snapshot{Devices: []Device{{
		Path: "/dev/sdd", FSType: "ext4", UUID: "def", Label: "scratch", SizeBytes: 2 << 30,
		ByID: "/dev/disk/by-id/wwn-0x5000", WWN: "0x5000", Serial: "S1",
	}}}
	if plan := ComputeWipe(identified, "UUID=def"); plan.Action != PlanRun ||
		plan.Device != "/dev/sdd" {
		t.Fatalf("wipe by uuid: %+v", plan)
	}
	if plan := ComputeFormat(identified, "LABEL=scratch", "ext4", "fresh"); plan.Action != PlanRun ||
		plan.Device != "/dev/sdd" {
		t.Fatalf("format by label: %+v", plan)
	}
}
