package storage

import "testing"

// The kernel's own view of two arrays: one healthy mirror and one that has
// lost a member and is rebuilding onto a spare.
const mdstatOutput = `Personalities : [raid1] [raid6] [raid5] [raid4]
md0 : active raid1 sdb1[1] sda1[0]
      1048512 blocks super 1.2 [2/2] [UU]

md1 : active raid5 sdd1[3] sdc1[1](F) sde1[4](S) sdf1[0]
      2095104 blocks super 1.2 level 5, 512k chunk, algorithm 2 [3/2] [U_U]
      [====>................]  recovery = 21.5% (225792/1047552) finish=0.5min speed=25088K/sec

unused devices: <none>
`

// mdadm --detail of the mirror: the UUID lives here and nowhere else.
const mdadmDetailOutput = `/dev/md0:
           Version : 1.2
     Creation Time : Mon Sep 15 09:12:03 2026
        Raid Level : raid1
        Array Size : 1048512 (1023.94 MiB 1073.68 MB)
      Raid Devices : 2
     Total Devices : 2
             State : clean
    Active Devices : 2
   Working Devices : 2
    Failed Devices : 0
     Spare Devices : 0
              Name : lab:0
              UUID : 7f3b2a11:44c0de91:0b7e5521:9a3c1f08
            Events : 17

    Number   Major   Minor   RaidDevice State
       0       8        1        0      active sync   /dev/sda1
       1       8       17        1      active sync   /dev/sdb1
`

// A degraded mirror: one slot has nothing in it, which is a fact about the
// array rather than a row that is missing.
const mdadmDegradedOutput = `/dev/md2:
           Version : 1.2
        Raid Level : raid1
        Array Size : 1048512 (1023.94 MiB 1073.68 MB)
      Raid Devices : 2
             State : clean, degraded
    Active Devices : 1
   Working Devices : 1
    Failed Devices : 1
     Spare Devices : 0
              UUID : 11112222:33334444:55556666:77778888

    Number   Major   Minor   RaidDevice State
       0       8       33        0      active sync   /dev/sdc1
       -       0        0        1      removed

       1       8       49        -      faulty   /dev/sdd1
`

const mdadmScanOutput = `ARRAY /dev/md0 metadata=1.2 name=lab:0 UUID=7f3b2a11:44c0de91:0b7e5521:9a3c1f08
ARRAY /dev/md1 metadata=1.2 name=lab:1 UUID=abcd0001:abcd0002:abcd0003:abcd0004
`

func TestMDStatReadsLevelsMembersAndTheSlotMap(t *testing.T) {
	arrays, err := ParseMDStat(mdstatOutput)
	if err != nil {
		t.Fatal(err)
	}
	if len(arrays) != 2 {
		t.Fatalf("arrays = %d", len(arrays))
	}
	mirror := arrays[0]
	if mirror.Name != "md0" || mirror.Path != "/dev/md0" || mirror.Level != "raid1" {
		t.Errorf("mirror = %+v", mirror)
	}
	if mirror.State != "active" {
		t.Errorf("state = %q", mirror.State)
	}
	// mdstat counts in kibibytes and every other size in the module is in
	// bytes; a mirror of 1048512 blocks is not a gigabyte of anything.
	if mirror.SizeBytes != 1048512*1024 {
		t.Errorf("size = %d", mirror.SizeBytes)
	}
	if mirror.RaidDevices != 2 || mirror.ActiveDevices != 2 || mirror.Degraded {
		t.Errorf("a healthy mirror read as %+v", mirror)
	}
	if !mirror.Redundant {
		t.Error("raid1 read as a level that keeps no copy")
	}
	if len(mirror.Members) != 2 || mirror.MemberAt("/dev/sda1") == nil {
		t.Errorf("members = %+v", mirror.Members)
	}

	degraded := arrays[1]
	if !degraded.Degraded {
		t.Error("[3/2] [U_U] read as a healthy array")
	}
	if degraded.Level != "raid5" {
		t.Errorf("level = %q", degraded.Level)
	}
	if faulty := degraded.MemberAt("/dev/sdc1"); faulty == nil || !faulty.Failed() {
		t.Errorf("the failed member read as %+v", faulty)
	}
	if spare := degraded.MemberAt("/dev/sde1"); spare == nil || spare.Role != MemberSpare {
		t.Errorf("the spare read as %+v", spare)
	}
	if degraded.SpareDevices != 1 || degraded.FailedDevices != 1 {
		t.Errorf("counts = %+v", degraded)
	}
	if degraded.SyncAction != "recovery" || degraded.SyncPercent == nil || *degraded.SyncPercent != 21.5 {
		t.Errorf("rebuild = %q %+v", degraded.SyncAction, degraded.SyncPercent)
	}
	if degraded.SyncFinish != "0.5min" || degraded.SyncSpeed != "25088K/sec" {
		t.Errorf("progress = %+v", degraded)
	}
	if !degraded.Rebuilding() {
		t.Error("an array in recovery read as idle")
	}
}

// A rebuild that is not running has no percentage. Zero would read as a
// rebuild standing still, which is a different state entirely.
func TestAnArrayWithoutARebuildHasNoPercentage(t *testing.T) {
	arrays, err := ParseMDStat(mdstatOutput)
	if err != nil {
		t.Fatal(err)
	}
	if arrays[0].SyncPercent != nil {
		t.Errorf("a mirror at rest reported a rebuild at %v", *arrays[0].SyncPercent)
	}
}

func TestMDAdmDetailCarriesTheUUIDAndTheMemberStates(t *testing.T) {
	array, err := ParseMDAdmDetail(mdadmDetailOutput)
	if err != nil {
		t.Fatal(err)
	}
	if array.Path != "/dev/md0" || array.UUID != "7f3b2a11:44c0de91:0b7e5521:9a3c1f08" {
		t.Errorf("array = %+v", array)
	}
	if array.Level != "raid1" || array.RaidDevices != 2 || array.ActiveDevices != 2 {
		t.Errorf("array = %+v", array)
	}
	if array.SizeBytes != 1048512*1024 {
		t.Errorf("size = %d", array.SizeBytes)
	}
	if len(array.Members) != 2 {
		t.Fatalf("members = %+v", array.Members)
	}
	first := array.Members[0]
	if first.Path != "/dev/sda1" || first.Role != MemberActive || first.Slot == nil || *first.Slot != 0 {
		t.Errorf("member = %+v", first)
	}
}

// A slot with nothing in it is a fact about the array: the array knows the
// slot exists and has nothing to put there.
func TestADegradedArrayReportsItsEmptySlotAndItsFaultyMember(t *testing.T) {
	array, err := ParseMDAdmDetail(mdadmDegradedOutput)
	if err != nil {
		t.Fatal(err)
	}
	if !array.Degraded {
		t.Error("\"clean, degraded\" read as healthy")
	}
	if len(array.Members) != 3 {
		t.Fatalf("members = %+v", array.Members)
	}
	var removed, faulty int
	for _, member := range array.Members {
		switch member.Role {
		case MemberRemoved:
			removed++
		case MemberFaulty:
			faulty++
		}
	}
	if removed != 1 || faulty != 1 {
		t.Errorf("roles = %+v", array.Members)
	}
	if array.DataMembers() != 1 {
		t.Errorf("data members = %d", array.DataMembers())
	}
}

func TestMDAdmScanNamesEveryArrayByUUID(t *testing.T) {
	arrays := ParseMDAdmScan(mdadmScanOutput)
	if len(arrays) != 2 {
		t.Fatalf("arrays = %+v", arrays)
	}
	if arrays["/dev/md0"].UUID != "7f3b2a11:44c0de91:0b7e5521:9a3c1f08" {
		t.Errorf("md0 = %+v", arrays["/dev/md0"])
	}
	if arrays["/dev/md1"].Metadata != "1.2" {
		t.Errorf("md1 = %+v", arrays["/dev/md1"])
	}
}

// The kernel decides which arrays exist; the superblock adds the UUID.
func TestMergingKeepsTheKernelListAndNamesWhatIsMissing(t *testing.T) {
	arrays, err := ParseMDStat(mdstatOutput)
	if err != nil {
		t.Fatal(err)
	}
	detail, err := ParseMDAdmDetail(mdadmDetailOutput)
	if err != nil {
		t.Fatal(err)
	}
	MergeArrayDetail(arrays, map[string]RAIDArray{"/dev/md0": detail}, "this host has no mdadm")
	if len(arrays) != 2 {
		t.Fatalf("arrays = %d", len(arrays))
	}
	if arrays[0].UUID == "" || arrays[0].DetailUnavailableReason != "" {
		t.Errorf("the merged array = %+v", arrays[0])
	}
	if arrays[1].UUID != "" {
		t.Errorf("an array got a UUID nobody read: %+v", arrays[1])
	}
	if arrays[1].DetailUnavailableReason != "this host has no mdadm" {
		t.Errorf("an array without a UUID gave no reason: %+v", arrays[1])
	}
	// The kernel's own facts survive the merge: the second array is still
	// degraded and still rebuilding.
	if !arrays[1].Degraded || arrays[1].SyncAction != "recovery" {
		t.Errorf("the kernel facts were lost: %+v", arrays[1])
	}
}

// mdadm knows nothing about /dev/disk/by-id.
func TestMemberIdentityComesFromTheBlockDeviceList(t *testing.T) {
	arrays, err := ParseMDStat(mdstatOutput)
	if err != nil {
		t.Fatal(err)
	}
	FillMemberIdentity(arrays, []Device{
		{Path: "/dev/sda1", ByID: "/dev/disk/by-id/ata-VB1-part1", Serial: "VB1", SizeBytes: 1073741824},
	})
	sda := arrays[0].MemberAt("/dev/sda1")
	if sda == nil || sda.ByID != "/dev/disk/by-id/ata-VB1-part1" || sda.Serial != "VB1" {
		t.Errorf("member = %+v", sda)
	}
	sdb := arrays[0].MemberAt("/dev/sdb1")
	if sdb == nil || sdb.ByID != "" || sdb.IdentityUnavailableReason == "" {
		t.Errorf("a member without a link gave no reason: %+v", sdb)
	}
}

func TestValidateArrayTakesOnlyAnArrayPath(t *testing.T) {
	for _, good := range []string{"/dev/md0", "/dev/md127", "/dev/md/data"} {
		if err := ValidateArray(good); err != nil {
			t.Errorf("%s was refused: %v", good, err)
		}
	}
	for _, bad := range []string{"", "/dev/sda", "md0", "/dev/md0; rm -rf /", "/dev/md0/../sda"} {
		if err := ValidateArray(bad); err == nil {
			t.Errorf("%q passed as an array", bad)
		}
	}
}
