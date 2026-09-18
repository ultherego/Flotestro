package storage

import (
	"strings"
	"testing"
)

// A host with one mirror, one volume group and a spare disk: enough to
// plan every layer operation and to refuse the ones that would cost data.
func layerFixture() Snapshot {
	return Snapshot{
		Devices: []Device{
			{Name: "sda1", Path: "/dev/sda1", Type: TypePartition, SizeBytes: 1 << 30,
				ByID: "/dev/disk/by-id/ata-VB1-part1", Serial: "VB1"},
			{Name: "sdb1", Path: "/dev/sdb1", Type: TypePartition, SizeBytes: 1 << 30,
				ByID: "/dev/disk/by-id/ata-VB2-part1", Serial: "VB2"},
			{Name: "sdc", Path: "/dev/sdc", Type: TypeDisk, SizeBytes: 2 << 30,
				ByID: "/dev/disk/by-id/ata-VB3", Serial: "VB3"},
			{Name: "sdd", Path: "/dev/sdd", Type: TypeDisk, SizeBytes: 2 << 30},
			{Name: "vg0-data", Path: "/dev/mapper/vg0-data", Type: TypeLVM, SizeBytes: 4 << 30,
				FSType: "ext4", ByID: "/dev/disk/by-id/dm-uuid-LVM-0001"},
		},
		Groups: []VolumeGroup{{Name: "vg0", UUID: "vg0-uuid", SizeBytes: 16 << 30,
			FreeBytes: 8 << 30, ExtentSizeBytes: 4 << 20, PVCount: 1, LVCount: 1}},
		Volumes: []LogicalVolume{
			{Name: "data", Group: "vg0", Path: "/dev/vg0/data", UUID: "lv-data",
				SizeBytes: 4 << 30, Attributes: "-wi-ao----"},
			{Name: "snap", Group: "vg0", Path: "/dev/vg0/snap", UUID: "lv-snap",
				SizeBytes: 1 << 30, Attributes: "swi-a-s---", Origin: "data"},
		},
		PhysicalVolumes: []PhysicalVolume{
			{Path: "/dev/sde1", Group: "vg0", UUID: "pv-1", SizeBytes: 16 << 30, FreeBytes: 8 << 30},
		},
		Arrays: []RAIDArray{{
			Name: "md0", Path: "/dev/md0", UUID: "array-uuid", Level: "raid1", State: "clean",
			RaidDevices: 2, ActiveDevices: 2, WorkingDevices: 2, Redundant: true,
			Members: []RAIDMember{
				{Path: "/dev/sda1", Role: MemberActive, ByID: "/dev/disk/by-id/ata-VB1-part1", Serial: "VB1"},
				{Path: "/dev/sdb1", Role: MemberActive, ByID: "/dev/disk/by-id/ata-VB2-part1", Serial: "VB2"},
			},
		}},
	}
}

func TestFailingAMemberOfAHealthyMirrorSaysWhatIsLeft(t *testing.T) {
	plan := ComputeRAIDMemberFail(layerFixture(), "/dev/md0", "/dev/sda1")
	if plan.Refusal != "" {
		t.Fatalf("refused: %s", plan.Refusal)
	}
	if plan.Action != PlanRun {
		t.Errorf("action = %q", plan.Action)
	}
	// The plan binds to the array's UUID and the member's by-id link: a
	// path names whatever the kernel assembled under it this boot.
	if plan.ArrayUUID != "array-uuid" || plan.ByID != "/dev/disk/by-id/ata-VB1-part1" {
		t.Errorf("plan = %+v", plan)
	}
	if !strings.Contains(plan.RedundancyAfter, "1 of 2") {
		t.Errorf("redundancy after = %q", plan.RedundancyAfter)
	}
	if plan.PlanHash == "" {
		t.Error("a plan without a fingerprint")
	}
}

func TestAnArrayThatCannotAffordToLoseAMemberRefuses(t *testing.T) {
	for _, tc := range []struct {
		why  string
		make func(Snapshot) Snapshot
		code string
	}{
		{"a level that keeps no copy", func(s Snapshot) Snapshot {
			s.Arrays[0].Level, s.Arrays[0].Redundant = "raid0", false
			return s
		}, CodeArrayRedundancyLost},
		{"an array already degraded", func(s Snapshot) Snapshot {
			s.Arrays[0].Degraded, s.Arrays[0].ActiveDevices = true, 1
			return s
		}, CodeArrayRedundancyLost},
		{"an array rebuilding", func(s Snapshot) Snapshot {
			s.Arrays[0].SyncAction = "recovery"
			return s
		}, CodeArrayRebuilding},
		{"an array without a UUID", func(s Snapshot) Snapshot {
			s.Arrays[0].UUID = ""
			s.Arrays[0].DetailUnavailableReason = "this host has no mdadm"
			return s
		}, CodeArrayUnknown},
		{"a member without a stable identity", func(s Snapshot) Snapshot {
			s.Arrays[0].Members[0].ByID = ""
			return s
		}, CodeStableIdentityRequired},
	} {
		t.Run(tc.why, func(t *testing.T) {
			plan := ComputeRAIDMemberFail(tc.make(layerFixture()), "/dev/md0", "/dev/sda1")
			if plan.RefusalCode != tc.code {
				t.Errorf("code = %q (%s)", plan.RefusalCode, plan.Refusal)
			}
		})
	}
}

// A spare carries nothing, so letting it go costs the array no copy - even
// on an array that has already lost one.
func TestASpareIsFailedEvenOnADegradedArray(t *testing.T) {
	state := layerFixture()
	state.Arrays[0].Degraded = true
	state.Arrays[0].Members = append(state.Arrays[0].Members, RAIDMember{
		Path: "/dev/sdc", Role: MemberSpare, ByID: "/dev/disk/by-id/ata-VB3", Serial: "VB3",
	})
	plan := ComputeRAIDMemberFail(state, "/dev/md0", "/dev/sdc")
	if plan.Refusal != "" || plan.Action != PlanRun {
		t.Errorf("plan = %+v", plan)
	}
}

// Failing a member the array has already written off changes nothing on
// the host, and the plan says so rather than running a tool.
func TestFailingAnAlreadyFailedMemberIsNoChange(t *testing.T) {
	state := layerFixture()
	state.Arrays[0].Members[0].Role = MemberFaulty
	plan := ComputeRAIDMemberFail(state, "/dev/md0", "/dev/sda1")
	if plan.Action != PlanNoChange {
		t.Errorf("action = %q", plan.Action)
	}
}

// A member that still carries data is not removed: the honest order is to
// fail it first, and that makes two decisions out of what is two decisions.
func TestRemovingAMemberThatStillCarriesDataRefuses(t *testing.T) {
	plan := ComputeRAIDMemberRemove(layerFixture(), "/dev/md0", "/dev/sda1")
	if plan.RefusalCode != CodeArrayRedundancyLost {
		t.Errorf("code = %q (%s)", plan.RefusalCode, plan.Refusal)
	}
	if !strings.Contains(plan.Refusal, "mark it failed first") {
		t.Errorf("refusal = %q", plan.Refusal)
	}
}

func TestRemovingAFailedMemberRuns(t *testing.T) {
	state := layerFixture()
	state.Arrays[0].Members[0].Role = MemberFaulty
	plan := ComputeRAIDMemberRemove(state, "/dev/md0", "/dev/sda1")
	if plan.Refusal != "" || plan.Action != PlanRun {
		t.Errorf("plan = %+v", plan)
	}
}

// Adding a device overwrites it with an array superblock, so it is read
// the way a format reads a disk: a stable identity, and nothing on it.
func TestAddingAMemberChecksTheDeviceLikeAFormat(t *testing.T) {
	state := layerFixture()
	plan := ComputeRAIDMemberAdd(state, "/dev/md0", "/dev/sdc")
	if plan.Refusal != "" || plan.Action != PlanRun {
		t.Fatalf("plan = %+v", plan)
	}
	if !strings.Contains(plan.Changes[0], "overwritten") {
		t.Errorf("changes = %+v", plan.Changes)
	}

	nameless := layerFixture()
	if plan := ComputeRAIDMemberAdd(nameless, "/dev/md0", "/dev/sdd"); plan.RefusalCode != CodeStableIdentityRequired {
		t.Errorf("a device without a by-id link was accepted: %+v", plan)
	}

	mounted := layerFixture()
	mounted.Devices[2].Mountpoints = []string{"/srv"}
	if plan := ComputeRAIDMemberAdd(mounted, "/dev/md0", "/dev/sdc"); plan.RefusalCode != CodeDiskInUse {
		t.Errorf("a mounted device was accepted: %+v", plan)
	}

	small := layerFixture()
	small.Devices[2].SizeBytes = 1 << 20
	small.Arrays[0].Members[0].SizeBytes = 1 << 30
	if plan := ComputeRAIDMemberAdd(small, "/dev/md0", "/dev/sdc"); plan.Refusal == "" {
		t.Error("a device too small to take a slot was accepted")
	}
}

func TestCreatingAVolumeNeedsRoomAndAGroupWithAUUID(t *testing.T) {
	plan := ComputeLVCreate(layerFixture(), "vg0", "logs", "1G")
	if plan.Refusal != "" || plan.Action != PlanRun {
		t.Fatalf("plan = %+v", plan)
	}
	if plan.GroupUUID != "vg0-uuid" || plan.RequestedBytes != 1<<30 {
		t.Errorf("plan = %+v", plan)
	}

	full := layerFixture()
	full.Groups[0].FreeBytes = 0
	if plan := ComputeLVCreate(full, "vg0", "logs", "1G"); plan.RefusalCode != CodeVolumeGroupFull {
		t.Errorf("a full group accepted a volume: %+v", plan)
	}

	tooBig := layerFixture()
	if plan := ComputeLVCreate(tooBig, "vg0", "logs", "100G"); plan.RefusalCode != CodeVolumeGroupFull {
		t.Errorf("a group of 8 GiB free accepted 100 GiB: %+v", plan)
	}

	nameless := layerFixture()
	nameless.Groups[0].UUID = ""
	if plan := ComputeLVCreate(nameless, "vg0", "logs", "1G"); plan.RefusalCode != CodeVolumeUnknown {
		t.Errorf("a group without a UUID was accepted: %+v", plan)
	}

	if plan := ComputeLVCreate(layerFixture(), "vg0", "data", "1G"); plan.Refusal == "" {
		t.Error("a name the group already holds was accepted")
	}
	if plan := ComputeLVCreate(layerFixture(), "vg0", "logs", "+1G"); plan.Refusal == "" {
		t.Error("an increment was accepted as the size of a new volume")
	}
}

// A share of what is free is a size too, only not one that can be compared
// with a number of bytes. The group still has to have something free.
func TestAShareOfWhatIsFreeNeedsAGroupWithSomethingFree(t *testing.T) {
	if plan := ComputeLVCreate(layerFixture(), "vg0", "logs", "100%FREE"); plan.Refusal != "" {
		t.Errorf("refused: %s", plan.Refusal)
	}
	full := layerFixture()
	full.Groups[0].FreeBytes = 0
	if plan := ComputeLVCreate(full, "vg0", "logs", "100%FREE"); plan.RefusalCode != CodeVolumeGroupFull {
		t.Errorf("a full group accepted a share of nothing: %+v", plan)
	}
}

func TestASnapshotIsTakenOfAVolumeAndNeverOfASnapshot(t *testing.T) {
	plan := ComputeSnapshotCreate(layerFixture(), "/dev/vg0/data", "data-before", "1G")
	if plan.Refusal != "" || plan.Action != PlanRun {
		t.Fatalf("plan = %+v", plan)
	}
	if plan.OriginUUID != "lv-data" || plan.GroupUUID != "vg0-uuid" {
		t.Errorf("plan = %+v", plan)
	}

	nested := ComputeSnapshotCreate(layerFixture(), "/dev/vg0/snap", "again", "1G")
	if nested.RefusalCode != CodeSnapshotOfSnapshot {
		t.Errorf("a snapshot of a snapshot was accepted: %+v", nested)
	}

	full := layerFixture()
	full.Groups[0].FreeBytes = 0
	if plan := ComputeSnapshotCreate(full, "/dev/vg0/data", "data-before", "1G"); plan.RefusalCode != CodeVolumeGroupFull {
		t.Errorf("a full group accepted a snapshot: %+v", plan)
	}
}

func TestDroppingASnapshotRefusesAnOrdinaryVolume(t *testing.T) {
	plan := ComputeSnapshotRemove(layerFixture(), "/dev/vg0/snap")
	if plan.Refusal != "" || plan.Action != PlanRun {
		t.Fatalf("plan = %+v", plan)
	}
	ordinary := ComputeSnapshotRemove(layerFixture(), "/dev/vg0/data")
	if ordinary.Refusal == "" || !strings.Contains(ordinary.Refusal, "two approvals") {
		t.Errorf("an ordinary volume was dropped as a snapshot: %+v", ordinary)
	}
}

// Removing a volume is the same loss as a format, and a volume with
// snapshots takes them with it: those go first, as their own decision.
func TestRemovingAVolumeTakesTheTreatmentOfAFormat(t *testing.T) {
	origin := ComputeLVRemove(layerFixture(), "/dev/vg0/data")
	if origin.Refusal == "" || !strings.Contains(origin.Refusal, "snap") {
		t.Errorf("a volume with a snapshot on it was accepted: %+v", origin)
	}

	alone := layerFixture()
	alone.Volumes = alone.Volumes[:1]
	alone.Devices[4].Mountpoints = nil
	plan := ComputeLVRemove(alone, "/dev/vg0/data")
	if plan.Refusal != "" || plan.Action != PlanRun {
		t.Fatalf("plan = %+v", plan)
	}
	if plan.VolumeUUID != "lv-data" || plan.ByID != "/dev/disk/by-id/dm-uuid-LVM-0001" {
		t.Errorf("plan = %+v", plan)
	}
	if !Destructive(PlanLVRemove) {
		t.Error("removing a volume is not treated as destructive")
	}

	mounted := layerFixture()
	mounted.Volumes = mounted.Volumes[:1]
	mounted.Devices[4].Mountpoints = []string{"/srv/data"}
	if plan := ComputeLVRemove(mounted, "/dev/vg0/data"); plan.RefusalCode != CodeDiskInUse {
		t.Errorf("a mounted volume was accepted: %+v", plan)
	}
}

func TestExtendingAGroupReadsTheDiskLikeAFormat(t *testing.T) {
	plan := ComputeVGExtend(layerFixture(), "vg0", "/dev/sdc")
	if plan.Refusal != "" || plan.Action != PlanRun {
		t.Fatalf("plan = %+v", plan)
	}
	if plan.GroupUUID != "vg0-uuid" || plan.ByID != "/dev/disk/by-id/ata-VB3" {
		t.Errorf("plan = %+v", plan)
	}

	taken := layerFixture()
	taken.PhysicalVolumes = append(taken.PhysicalVolumes,
		PhysicalVolume{Path: "/dev/sdc", Group: "vg1", UUID: "pv-2", SizeBytes: 2 << 30})
	if plan := ComputeVGExtend(taken, "vg0", "/dev/sdc"); plan.Refusal == "" {
		t.Error("a disk belonging to another group was accepted")
	}

	already := layerFixture()
	already.PhysicalVolumes = append(already.PhysicalVolumes,
		PhysicalVolume{Path: "/dev/sdc", Group: "vg0", UUID: "pv-2", SizeBytes: 2 << 30})
	if plan := ComputeVGExtend(already, "vg0", "/dev/sdc"); plan.Action != PlanNoChange {
		t.Errorf("a disk already in the group = %+v", plan)
	}

	if plan := ComputeVGExtend(layerFixture(), "vg0", "/dev/sdd"); plan.RefusalCode != CodeStableIdentityRequired {
		t.Errorf("a disk without a by-id link was accepted: %+v", plan)
	}
}

// A host the module could not read is not a host without arrays or
// volumes: the reason travels into the refusal instead of an empty list.
func TestAHostThatCouldNotBeReadRefusesWithItsReason(t *testing.T) {
	blind := Snapshot{RAIDUnavailableReason: "this kernel has no software RAID"}
	plan := ComputeRAIDMemberFail(blind, "/dev/md0", "/dev/sda1")
	if plan.RefusalCode != CodeArrayUnknown || !strings.Contains(plan.Refusal, "no software RAID") {
		t.Errorf("plan = %+v", plan)
	}
	noLVM := Snapshot{LVMUnavailableReason: "this host has no LVM tools"}
	if plan := ComputeLVCreate(noLVM, "vg0", "logs", "1G"); plan.RefusalCode != CodeVolumeUnknown {
		t.Errorf("plan = %+v", plan)
	}
}

func TestTheNamesOfTheLayerToolsAreChecked(t *testing.T) {
	for _, bad := range []string{"", "-vg", "vg0;reboot", "vg0/data", "snapshot-of-mine", "."} {
		if err := ValidateLVMName("group", bad); err == nil {
			t.Errorf("%q passed as a group name", bad)
		}
	}
	for _, good := range []string{"vg0", "data", "_private", "0disk", "app.logs"} {
		if err := ValidateLVMName("volume", good); err != nil {
			t.Errorf("%q was refused: %v", good, err)
		}
	}
	if _, err := RAIDMemberArguments("/dev/md0", "/dev/sda1", "--grow"); err == nil {
		t.Error("a verb outside fail, remove and add was accepted")
	}
	arguments, err := RAIDMemberArguments("/dev/md0", "/dev/sda1", RAIDFail)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Join(arguments, " ") != MDAdmPath+" --manage /dev/md0 --fail /dev/sda1" {
		t.Errorf("arguments = %v", arguments)
	}
}

// Creating and destroying an array is outside the panel on purpose, and
// the answer says so with its own code rather than "no such plan".
func TestBuildingOrTearingDownAnArrayIsRefusedByName(t *testing.T) {
	for _, kind := range []string{"raid_create", "raid_destroy", "array_stop", "RAID_CREATE"} {
		refusal := ArrayLifecycleRefusalFor(kind)
		if refusal == nil {
			t.Fatalf("%q was not recognised as an array lifecycle plan", kind)
		}
		if refusal.Code != CodeArrayLifecycleOutOfScope {
			t.Errorf("code = %q", refusal.Code)
		}
	}
	if ArrayLifecycleRefusalFor(PlanRAIDMemberFail) != nil {
		t.Error("a member operation was taken for an array lifecycle one")
	}
	if !KnownPlanKind(PlanSnapshotCreate) || KnownPlanKind("raid_create") {
		t.Error("the list of known plan kinds does not match the plans")
	}
}

func TestSizeInBytesReadsAnLVMSize(t *testing.T) {
	for _, tc := range []struct {
		text     string
		bytes    uint64
		absolute bool
	}{
		{"1G", 1 << 30, true},
		{"+512M", 512 << 20, true},
		{"10T", 10 << 40, true},
		{"100%FREE", 0, false},
		{"", 0, false},
		{"big", 0, false},
	} {
		got, absolute := SizeInBytes(tc.text)
		if got != tc.bytes || absolute != tc.absolute {
			t.Errorf("%q = %d, %v", tc.text, got, absolute)
		}
	}
}
