package storage

import (
	"strings"
	"testing"
)

// The path alone is not enough: /dev/sdb after a reboot can be a different
// disk than the one the operator viewed.
func TestDeviceIdentityMustMatch(t *testing.T) {
	device := &Device{Path: "/dev/sdb", Serial: "VB1234", SizeBytes: 2147483648}

	if err := (DeviceIdentity{Path: "/dev/sdb", Serial: "VB1234", SizeBytes: 2147483648}).
		Matches(device); err != nil {
		t.Errorf("rejected a matching device: %v", err)
	}
	if err := (DeviceIdentity{Path: "/dev/sdb", Serial: "OTHER"}).Matches(device); err == nil {
		t.Error("accepted a device with a different serial")
	}
	if err := (DeviceIdentity{Path: "/dev/sdb", SizeBytes: 1024}).Matches(device); err == nil {
		t.Error("accepted a device with a different size")
	}
	if err := (DeviceIdentity{Path: "/dev/sdz"}).Matches(nil); err == nil {
		t.Error("accepted a device that does not exist")
	}
}

// Formatting a disk something stands on is not an operation meant to
// succeed.
func TestDeviceInUseIsRecognisedThroughDescendants(t *testing.T) {
	snapshot := Snapshot{Devices: []Device{
		{Path: "/dev/sda", Type: TypeDisk},
		{Path: "/dev/sda1", Type: TypePartition, Parent: "/dev/sda", Mountpoints: []string{"/boot"}},
		{Path: "/dev/sdb", Type: TypeDisk},
	}}
	if point := InUse(snapshot, "/dev/sda"); point != "/boot" {
		t.Errorf("disk with a mounted partition = %q", point)
	}
	if point := InUse(snapshot, "/dev/sdb"); point != "" {
		t.Errorf("an empty disk treated as busy: %q", point)
	}
}

// Growing goes only upwards: an lvextend shrinking a volume cuts off data
// the filesystem considers its own.
func TestVolumeExtensionOnlyUpwards(t *testing.T) {
	for _, bad := range []string{"10G", "-10G", "100%", "lots", "+10X"} {
		if _, err := LVExtendArguments("/dev/vg/lv", bad, true); err == nil {
			t.Errorf("accepted size %q", bad)
		}
	}
	arguments, err := LVExtendArguments("/dev/vg/lv", "+512M", true)
	if err != nil {
		t.Fatal(err)
	}
	command := strings.Join(arguments, " ")
	// A volume bigger than the filesystem gives not a byte of space, so the
	// resize goes together.
	if !strings.Contains(command, "--resizefs") {
		t.Errorf("command = %q", command)
	}
	if !strings.HasSuffix(command, "/dev/vg/lv") {
		t.Errorf("command = %q", command)
	}
}

func TestFormatAndWipeCheckArguments(t *testing.T) {
	if _, err := FormatArguments("/dev/sdb1", "btrfs", ""); err == nil {
		t.Error("accepted an unsupported filesystem")
	}
	if _, err := FormatArguments("sdb1", "ext4", ""); err == nil {
		t.Error("accepted a device without a path")
	}
	if _, err := FormatArguments("/dev/sdb1", "ext4", "bad label"); err == nil {
		t.Error("accepted a label with a space")
	}
	arguments, err := FormatArguments("/dev/sdb1", "ext4", "data")
	if err != nil {
		t.Fatal(err)
	}
	if strings.Join(arguments, " ") != MkfsExt4Path+" -q -L data /dev/sdb1" {
		t.Errorf("command = %v", arguments)
	}

	wipe, err := WipeArguments("/dev/sdb")
	if err != nil {
		t.Fatal(err)
	}
	// The signatures are wiped, not two terabytes with zeros: the latter
	// takes hours and is not what the operator asks for.
	if !strings.Contains(strings.Join(wipe, " "), "--all") {
		t.Errorf("command = %v", wipe)
	}
}

func TestFilesystemResizeDependsOnType(t *testing.T) {
	ext, err := FSResizeArguments("/dev/vg/lv", "ext4", "/data")
	if err != nil {
		t.Fatal(err)
	}
	if ext[len(ext)-1] != "/dev/vg/lv" {
		t.Errorf("ext4 = %v", ext)
	}
	// xfs_growfs takes the mount point, not the device.
	xfs, err := FSResizeArguments("/dev/vg/lv", "xfs", "/data")
	if err != nil {
		t.Fatal(err)
	}
	if xfs[len(xfs)-1] != "/data" {
		t.Errorf("xfs = %v", xfs)
	}
	if _, err := FSResizeArguments("/dev/vg/lv", "xfs", ""); err == nil {
		t.Error("accepted an xfs resize without a mount point")
	}
	if _, err := FSResizeArguments("/dev/vg/lv", "vfat", "/data"); err == nil {
		t.Error("accepted an unsupported filesystem")
	}
}

// The same volume has two names, and a hyphen in the group name is doubled
// in the mapper form. Comparing the strings drifts exactly where the
// operator looks.
func TestVolumeRecognisedByBothNames(t *testing.T) {
	volume := LogicalVolume{Name: "root", Group: "debian-13-vg", Path: "/dev/debian-13-vg/root"}

	for _, path := range []string{
		"/dev/debian-13-vg/root",
		"/dev/mapper/debian--13--vg-root",
	} {
		if !MatchesVolume(volume, path) {
			t.Errorf("the volume was not recognised by the path %q", path)
		}
	}
	for _, foreign := range []string{"", "/dev/sdb", "/dev/mapper/debian--13--vg-swap_1"} {
		if MatchesVolume(volume, foreign) {
			t.Errorf("a foreign path %q was recognised", foreign)
		}
	}
}
