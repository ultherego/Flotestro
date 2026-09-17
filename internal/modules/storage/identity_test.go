package storage

import (
	"errors"
	"strings"
	"testing"
)

func refusalCodeOf(t *testing.T, err error) string {
	t.Helper()
	var refusal *Refusal
	if !errors.As(err, &refusal) {
		t.Fatalf("not a typed refusal: %v", err)
	}
	return refusal.Code
}

// Two disks of the same size are the most ordinary thing in a fleet. The
// size proves nothing; the WWN, the serial and the by-id link do.
func TestSameSizeOtherWWNIsRefused(t *testing.T) {
	plan := DevicePlan{Device: "/dev/sdb", ByID: "/dev/disk/by-id/wwn-0x5000c500aaaa",
		WWN: "0x5000c500aaaa", Serial: "S1", SizeBytes: 2 << 30}
	observed := Device{Path: "/dev/sdb", ByID: "/dev/disk/by-id/wwn-0x5000c500bbbb",
		WWN: "0x5000c500bbbb", Serial: "S1", SizeBytes: 2 << 30}
	if code := refusalCodeOf(t, ValidateDestructiveTarget(plan, observed)); code != CodeDiskChanged {
		t.Errorf("a disk of the same size and another WWN: %s", code)
	}

	sameSerialOtherLink := Device{Path: "/dev/sdb", ByID: "/dev/disk/by-id/wwn-0x5000c500aaaa",
		WWN: "0x5000c500aaaa", Serial: "S2", SizeBytes: 2 << 30}
	if code := refusalCodeOf(t, ValidateDestructiveTarget(plan, sameSerialOtherLink)); code != CodeDiskChanged {
		t.Errorf("a disk with another serial: %s", code)
	}

	same := Device{Path: "/dev/sdb", ByID: "/dev/disk/by-id/wwn-0x5000c500aaaa",
		WWN: "0x5000c500aaaa", Serial: "S1", SizeBytes: 4 << 30}
	if err := ValidateDestructiveTarget(plan, same); err != nil {
		t.Errorf("the same disk with a grown size was refused: %v", err)
	}
}

// A plan without a by-id link binds to nothing that survives a reboot: it
// is refused before the device is even compared.
func TestMissingByIDIsRefused(t *testing.T) {
	observed := Device{Path: "/dev/sdb", Serial: "S1"}
	plan := DevicePlan{Device: "/dev/sdb", Serial: "S1"}
	if code := refusalCodeOf(t, ValidateDestructiveTarget(plan, observed)); code != CodeStableIdentityRequired {
		t.Errorf("a plan without a by-id link: %s", code)
	}
	// A by-id link without a WWN or a serial behind it names nothing
	// either - unless it carries the UUID of a volume, which is the
	// identity a logical volume has.
	nameOnly := DevicePlan{Device: "/dev/mapper/vg-data", ByID: "/dev/disk/by-id/dm-name-vg-data"}
	if code := refusalCodeOf(t, ValidateDestructiveTarget(nameOnly, Device{Path: "/dev/mapper/vg-data",
		ByID: "/dev/disk/by-id/dm-name-vg-data"})); code != CodeStableIdentityRequired {
		t.Errorf("a plan with a dm-name link only: %s", code)
	}
	volume := DevicePlan{Device: "/dev/mapper/vg-data", ByID: "/dev/disk/by-id/dm-uuid-LVM-abc"}
	if err := ValidateDestructiveTarget(volume, Device{Path: "/dev/mapper/vg-data",
		ByID: "/dev/disk/by-id/dm-uuid-LVM-abc"}); err != nil {
		t.Errorf("a logical volume with a dm-uuid link was refused: %v", err)
	}
	// A VirtualBox disk has no WWN, but a serial and an ata- link: that is
	// a stable identity.
	virtual := DevicePlan{Device: "/dev/sdb", ByID: "/dev/disk/by-id/ata-VBOX_HARDDISK_VB1", Serial: "VB1"}
	if err := ValidateDestructiveTarget(virtual, Device{Path: "/dev/sdb",
		ByID: "/dev/disk/by-id/ata-VBOX_HARDDISK_VB1", Serial: "VB1"}); err != nil {
		t.Errorf("a disk with a serial and no WWN was refused: %v", err)
	}
}

// Whatever stands on the device stops the operation: the root filesystem,
// a mounted partition, a volume group holding the disk.
func TestDeviceInUseIsRefused(t *testing.T) {
	plan := DevicePlan{Device: "/dev/sda", ByID: "/dev/disk/by-id/ata-X_S1", Serial: "S1"}
	base := Device{Path: "/dev/sda", ByID: "/dev/disk/by-id/ata-X_S1", Serial: "S1"}

	root := base
	root.RootDevice = true
	if code := refusalCodeOf(t, ValidateDestructiveTarget(plan, root)); code != CodeDiskInUse {
		t.Errorf("the root device: %s", code)
	}
	mounted := base
	mounted.HasMountedChildren = true
	if code := refusalCodeOf(t, ValidateDestructiveTarget(plan, mounted)); code != CodeDiskInUse {
		t.Errorf("a disk with a mounted partition: %s", code)
	}
	held := base
	held.HasOpenHolders = true
	held.Holders = []string{"dm-0"}
	err := ValidateDestructiveTarget(plan, held)
	if code := refusalCodeOf(t, err); code != CodeDiskInUse || !strings.Contains(err.Error(), "dm-0") {
		t.Errorf("a disk held by a volume group: %s (%v)", code, err)
	}
	own := base
	own.Mountpoints = []string{"/data"}
	if code := refusalCodeOf(t, ValidateDestructiveTarget(plan, own)); code != CodeDiskInUse {
		t.Errorf("a mounted device: %s", code)
	}
	if err := ValidateDestructiveTarget(plan, base); err != nil {
		t.Errorf("a free disk was refused: %v", err)
	}
}

// The by-id link is chosen deterministically and by how much it says:
// the WWN over the serial, and a dm-name never.
func TestByIDPrefersTheWWN(t *testing.T) {
	links := []string{
		"/dev/disk/by-id/ata-VBOX_HARDDISK_VB1",
		"/dev/disk/by-id/wwn-0x5000c500aaaa",
		"/dev/disk/by-id/scsi-SATA_VBOX_HARDDISK_VB1",
	}
	if got := ChooseByID(links); got != "/dev/disk/by-id/wwn-0x5000c500aaaa" {
		t.Errorf("chosen %q", got)
	}
	if got := ChooseByID(links[:1]); got != links[0] {
		t.Errorf("chosen %q", got)
	}
	if got := ChooseByID([]string{"/dev/disk/by-id/dm-name-vg-data"}); got != "" {
		t.Errorf("a dm-name link was taken as an identity: %q", got)
	}
	if got := ChooseByID([]string{"/dev/disk/by-id/dm-name-vg-data", "/dev/disk/by-id/dm-uuid-LVM-abc"}); got != "/dev/disk/by-id/dm-uuid-LVM-abc" {
		t.Errorf("chosen %q", got)
	}
}

// The topology flags come from the whole tree: a disk whose partition is
// a physical volume holding the root volume carries root and is held.
func TestTopologyFlagsFollowTheTree(t *testing.T) {
	devices, err := ParseDevices(lsblkOutput)
	if err != nil {
		t.Fatal(err)
	}
	FillIdentity(devices, map[string][]string{
		"sda":  {"/dev/disk/by-id/ata-VBOX_HARDDISK_VB0808c8f2"},
		"sda1": {"/dev/disk/by-id/ata-VBOX_HARDDISK_VB0808c8f2-part1"},
		"sda5": {"/dev/disk/by-id/ata-VBOX_HARDDISK_VB0808c8f2-part5", "/dev/disk/by-id/lvm-pv-uuid-XYZ"},
	}, map[string][]string{"sda5": {"dm-0"}}, "")
	byPath := map[string]Device{}
	for _, device := range devices {
		byPath[device.Path] = device
	}
	disk := byPath["/dev/sda"]
	if !disk.RootDevice || !disk.HasMountedChildren || !disk.HasOpenHolders {
		t.Errorf("the system disk: %+v", disk)
	}
	if disk.ByID != "/dev/disk/by-id/ata-VBOX_HARDDISK_VB0808c8f2" || disk.IdentityUnavailableReason != "" {
		t.Errorf("the disk identity: %+v", disk)
	}
	if len(disk.Children) != 2 {
		t.Errorf("children of the disk: %v", disk.Children)
	}
	pv := byPath["/dev/sda5"]
	if !pv.HasOpenHolders || len(pv.Holders) != 1 || pv.Holders[0] != "dm-0" ||
		pv.ByID != "/dev/disk/by-id/ata-VBOX_HARDDISK_VB0808c8f2-part5" {
		t.Errorf("the physical volume: %+v", pv)
	}
	boot := byPath["/dev/sda1"]
	if boot.RootDevice || boot.HasMountedChildren || boot.HasOpenHolders {
		t.Errorf("the boot partition: %+v", boot)
	}
	root := byPath["/dev/mapper/debian--13--vg-root"]
	if !root.RootDevice || root.ByID != "" || root.IdentityUnavailableReason == "" {
		t.Errorf("the root volume: %+v", root)
	}
}

// A destructive plan carries the identity and refuses on its own: the
// system disk before consent, a disk without a link before consent.
func TestFormatAndWipePlansCarryTheIdentity(t *testing.T) {
	state := Snapshot{Devices: []Device{
		{Path: "/dev/sda", Type: TypeDisk, ByID: "/dev/disk/by-id/ata-X_S1", Serial: "S1",
			RootDevice: true, HasMountedChildren: true},
		{Path: "/dev/sdb", Type: TypeDisk, ByID: "/dev/disk/by-id/wwn-0xb", WWN: "0xb", Serial: "S2",
			FSType: "ext4", Label: "old", SizeBytes: 2 << 30},
		{Path: "/dev/sdc", Type: TypeDisk, IdentityUnavailableReason: "no link"},
	}}
	system := ComputeFormat(state, "/dev/sda", "ext4", "")
	if system.RefusalCode != CodeDiskInUse || system.Action == PlanRun {
		t.Errorf("formatting the system disk: %+v", system)
	}
	free := ComputeFormat(state, "/dev/sdb", "ext4", "data")
	if free.Action != PlanRun || free.Refusal != "" || free.ByID != "/dev/disk/by-id/wwn-0xb" ||
		free.WWN != "0xb" || free.Serial != "S2" || !strings.Contains(free.Changes[0], "old") {
		t.Errorf("formatting a free disk: %+v", free)
	}
	unnamed := ComputeWipe(state, "/dev/sdc")
	if unnamed.RefusalCode != CodeStableIdentityRequired || unnamed.IdentityUnavailableReason != "no link" {
		t.Errorf("wiping a disk without an identity: %+v", unnamed)
	}
	wipe := ComputeWipe(state, "/dev/sdb")
	if wipe.Action != PlanRun || wipe.PlanHash == free.PlanHash {
		t.Errorf("wiping a free disk: %+v", wipe)
	}
	if missing := ComputeWipe(state, "/dev/sdz"); missing.Refusal == "" || missing.Found {
		t.Errorf("a device that does not exist: %+v", missing)
	}
	if !Destructive(PlanFormat) || !Destructive(PlanWipe) || Destructive(PlanCheck) {
		t.Error("the destructive kinds are misnamed")
	}
}

// An fstab edited between the plan and the change is a different base:
// the fingerprint moves and the change needs a new plan.
func TestMountFingerprintCoversFstabAndTarget(t *testing.T) {
	before := snapshotWithDisk("aaaa-1111")
	before.FstabRevision = FstabRevision([]byte("UUID=root / ext4 defaults 0 1\n"))
	after := snapshotWithDisk("aaaa-1111")
	after.FstabRevision = FstabRevision([]byte("UUID=root / ext4 defaults 0 1\nUUID=x /x ext4 defaults 0 2\n"))

	first := ComputeMount(before, "/dev/sdb", "/mnt/data", "ext4", "", true)
	second := ComputeMount(after, "/dev/sdb", "/mnt/data", "ext4", "", true)
	if first.PlanHash == second.PlanHash || first.FstabRevision == "" {
		t.Errorf("an fstab change did not change the plan fingerprint: %+v", first)
	}
	// The requested source stays out of the fingerprint: the change comes
	// back with the resolved one and has to match the same plan.
	byUUID := ComputeMount(before, "UUID=aaaa-1111", "/mnt/data", "ext4", "", true)
	if byUUID.PlanHash != first.PlanHash {
		t.Error("the same mount requested by path and by UUID gave two fingerprints")
	}
	// The state of the mount point is part of the base as well.
	observed := first
	observed.ObserveTarget(TargetDirectory)
	if observed.PlanHash == first.PlanHash || observed.TargetState != TargetDirectory {
		t.Error("the mount point state did not change the fingerprint")
	}
	unmount := ComputeUnmount(after, "/mnt/data")
	if unmount.FstabRevision != after.FstabRevision {
		t.Errorf("the unmount plan lost the fstab revision: %+v", unmount)
	}
}
