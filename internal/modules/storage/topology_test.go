package storage

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// Output copied from a host of the test fleet.
const lsblkOutput = `{
 "blockdevices": [
  {"name":"sda","path":"/dev/sda","type":"disk","size":68719476736,"fstype":null,"label":null,
   "uuid":null,"partuuid":null,"mountpoints":[null],"model":"VBOX HARDDISK ","serial":"VB0808c8f2",
   "wwn":null,"rota":true,"ro":false,"pkname":null,"fssize":null,"fsused":null,"fsavail":null,
   "children":[
     {"name":"sda1","path":"/dev/sda1","type":"part","size":1023410176,"fstype":"ext4","label":null,
      "uuid":"c856d851-66da-4c31-a17a-b53a4afdd1f0","partuuid":"06901e8d-01","mountpoints":["/boot"],
      "rota":true,"ro":false,"pkname":"sda","fssize":988057600,"fsused":123404288,"fsavail":793923584},
     {"name":"sda5","path":"/dev/sda5","type":"part","size":67692920832,"fstype":"LVM2_member",
      "mountpoints":[null],"rota":true,"ro":false,"pkname":"sda",
      "children":[
        {"name":"debian--13--vg-root","path":"/dev/mapper/debian--13--vg-root","type":"lvm",
         "size":64470646784,"fstype":"ext4","uuid":"11111111-2222-3333-4444-555555555555",
         "mountpoints":["/"],"rota":true,"ro":false,"pkname":"sda5",
         "fssize":63256395776,"fsused":8571781120,"fsavail":51442851840}]}]}]}`

func TestTopologyFlattensTreeWithParentReference(t *testing.T) {
	devices, err := ParseDevices(lsblkOutput)
	if err != nil {
		t.Fatal(err)
	}
	if len(devices) != 4 {
		t.Fatalf("devices = %d", len(devices))
	}
	byPath := map[string]Device{}
	for _, device := range devices {
		byPath[device.Path] = device
	}

	if byPath["/dev/sda"].Type != TypeDisk || byPath["/dev/sda"].Parent != "" {
		t.Errorf("disk = %+v", byPath["/dev/sda"])
	}
	if byPath["/dev/sda1"].Parent != "/dev/sda" {
		t.Errorf("partition without a parent: %+v", byPath["/dev/sda1"])
	}
	// A logical volume sits on a partition, not on the disk: that is the
	// whole content of the topology when planning an extension.
	if byPath["/dev/mapper/debian--13--vg-root"].Parent != "/dev/sda5" {
		t.Errorf("volume = %+v", byPath["/dev/mapper/debian--13--vg-root"])
	}
	// Identification goes by UUID and serial, because /dev/sdX depends on
	// the detection order and after a reboot can point at a different disk.
	if byPath["/dev/sda1"].UUID == "" || byPath["/dev/sda"].Serial == "" {
		t.Errorf("no stable identifiers: %+v %+v", byPath["/dev/sda1"], byPath["/dev/sda"])
	}
	// The model comes with trailing spaces; left in place it would look
	// like two different values when compared with a plan.
	if byPath["/dev/sda"].Model != "VBOX HARDDISK" {
		t.Errorf("model = %q", byPath["/dev/sda"].Model)
	}
	// The filesystem size is at times smaller than the partition - that is
	// exactly the difference visible before a resize.
	root := byPath["/dev/mapper/debian--13--vg-root"]
	if root.FSSizeBytes == nil || *root.FSSizeBytes >= root.SizeBytes {
		t.Errorf("volume filesystem = %v of %d", root.FSSizeBytes, root.SizeBytes)
	}
	// A device without a filesystem must not pretend it has zero bytes
	// used.
	if byPath["/dev/sda"].FSUsedBytes != nil {
		t.Errorf("a disk without a filesystem got usage: %v", byPath["/dev/sda"].FSUsedBytes)
	}
	// A "null" mount point from lsblk is not a mount point.
	if len(byPath["/dev/sda"].Mountpoints) != 0 {
		t.Errorf("disk mounted: %v", byPath["/dev/sda"].Mountpoints)
	}
}

const vgsOutput = `{"report":[{"vg":[{"vg_name":"debian-13-vg","pv_count":"1","lv_count":"2","vg_size":"67691872256B","vg_free":"0B"}]}]}`
const lvsOutput = `{"report":[{"lv":[{"lv_name":"root","vg_name":"debian-13-vg","lv_size":"64470646784B","lv_path":"/dev/debian-13-vg/root"}]}]}`

func TestLVMReadsSizesInBytes(t *testing.T) {
	groups, err := ParseGroups(vgsOutput)
	if err != nil {
		t.Fatal(err)
	}
	if len(groups) != 1 || groups[0].SizeBytes != 67691872256 {
		t.Fatalf("groups = %+v", groups)
	}
	// A group without free space is a fact that decides about the
	// possibility of an extension - and is meant to be zero, not a missing
	// value.
	if groups[0].FreeBytes != 0 || groups[0].LVCount != 2 {
		t.Errorf("group = %+v", groups[0])
	}

	volumes, err := ParseVolumes(lvsOutput)
	if err != nil {
		t.Fatal(err)
	}
	if len(volumes) != 1 || volumes[0].Path != "/dev/debian-13-vg/root" {
		t.Errorf("volumes = %+v", volumes)
	}
}

const mountinfoOutput = `23 28 0:21 / /sys rw,nosuid,nodev,noexec,relatime shared:6 - sysfs sysfs rw
30 28 254:0 / / rw,relatime shared:1 - ext4 /dev/mapper/debian--13--vg-root rw,errors=remount-ro
36 30 8:1 / /boot rw,relatime shared:25 - ext4 /dev/sda1 rw
41 30 0:35 / /srv/flotestro ro,relatime shared:30 - vboxsf srv_flotestro ro
44 30 8:16 / /mnt/backup\040copies rw,relatime shared:33 - ext4 /dev/sdb1 rw`

const fstabContent = `# /etc/fstab
/dev/mapper/debian--13--vg-root /               ext4    errors=remount-ro 0       1
UUID=c856d851 /boot           ext4    defaults        0       2
# flotestro: backup copies
/dev/sdb1 /mnt/backup\040copies ext4 defaults 0 2
UUID=aaaa /mnt/archive ext4 defaults 0 2`

func TestMountsJoinKernelStateWithFstab(t *testing.T) {
	fromKernel := ParseMountinfo(mountinfoOutput)
	// Kernel mounts are not the host disk space; shown they would obscure
	// the picture.
	for _, mount := range fromKernel {
		if mount.FSType == "sysfs" {
			t.Errorf("system mount in the result: %+v", mount)
		}
	}

	merged := MergeMounts(fromKernel, ParseFstab(fstabContent))
	byTarget := map[string]Mount{}
	for _, mount := range merged {
		byTarget[mount.Target] = mount
	}

	if !byTarget["/"].Mounted || !byTarget["/"].InFstab {
		t.Errorf("root = %+v", byTarget["/"])
	}
	// A mount without an fstab entry vanishes after a reboot - and that is
	// the answer the operator comes here for.
	if byTarget["/srv/flotestro"].InFstab {
		t.Errorf("a mount outside fstab treated as an entry: %+v", byTarget["/srv/flotestro"])
	}
	// An fstab entry nobody mounted must be visible too.
	if !byTarget["/mnt/archive"].InFstab || byTarget["/mnt/archive"].Mounted {
		t.Errorf("unmounted entry = %+v", byTarget["/mnt/archive"])
	}
	// A path with a space is written in octal; without decoding it would
	// fall apart into two fields and not match the fstab entry.
	copies := byTarget["/mnt/backup copies"]
	if !copies.Mounted || !copies.InFstab || !copies.Managed {
		t.Errorf("mount with a space = %+v", copies)
	}
}

// The panel marker stands above the entry the panel created: an entry
// found on the host belongs to the host administrator.
func TestFstabEntriesDistinguishOwnership(t *testing.T) {
	entries := ParseFstab(fstabContent)
	if len(entries) != 4 {
		t.Fatalf("entries = %d", len(entries))
	}
	var managed int
	for _, entry := range entries {
		if entry.Managed {
			managed++
			if entry.Target != "/mnt/backup copies" {
				t.Errorf("the wrong entry treated as our own: %+v", entry)
			}
		}
	}
	if managed != 1 {
		t.Errorf("own entries = %d", managed)
	}
}

// The mount source must be a durable identifier or a path in /dev: the
// device name depends on the detection order.
func TestMountSourceAndTargetAreChecked(t *testing.T) {
	for _, bad := range []string{"", "sdb1", "//server/share", "UUID=$(reboot)", "/etc/passwd"} {
		if err := ValidateSource(bad); err == nil {
			t.Errorf("accepted source %q", bad)
		}
	}
	for _, good := range []string{"UUID=c856d851-66da-4c31-a17a-b53a4afdd1f0",
		"LABEL=backups", "/dev/sdb1", "/dev/mapper/vg-lv"} {
		if err := ValidateSource(good); err != nil {
			t.Errorf("rejected source %q: %v", good, err)
		}
	}

	// Shadowing a system directory cuts the host off from itself.
	for _, protected := range []string{"/", "/etc", "/usr", "/var/log", "/boot"} {
		if err := ValidateTarget(protected); err == nil {
			t.Errorf("accepted a mount on %q", protected)
		}
	}
	for _, bad := range []string{"mnt/data", "/mnt/../etc", "/mnt/data/"} {
		if err := ValidateTarget(bad); err == nil {
			t.Errorf("accepted target %q", bad)
		}
	}
	if err := ValidateTarget("/mnt/backup copies"); err != nil {
		t.Errorf("rejected a valid target: %v", err)
	}
}

// A path with a space written directly would fall apart into two fields,
// and the entry would point at an entirely different place.
func TestFstabLineWritesSpecialCharactersInOctal(t *testing.T) {
	line := FstabLine("/dev/sdb1", "/mnt/backup copies", "ext4", "")
	if !strings.Contains(line, `/mnt/backup\040copies`) {
		t.Errorf("line = %q", line)
	}
	// No options must not give an empty field: fstab then has five columns
	// instead of six and the entry becomes invalid.
	if !strings.Contains(line, "ext4 defaults 0 0") {
		t.Errorf("line without options = %q", line)
	}
}

func TestPanelEntryIsReplacedNotDuplicated(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "fstab")
	initial := "# /etc/fstab\nUUID=aaa / ext4 defaults 0 1\n"
	if err := os.WriteFile(path, []byte(initial), 0o644); err != nil {
		t.Fatal(err)
	}

	if err := WriteFstabEntry(path, "/dev/sdb1", "/mnt/data", "ext4", "defaults"); err != nil {
		t.Fatal(err)
	}
	if err := WriteFstabEntry(path, "LABEL=data", "/mnt/data", "xfs", "noatime"); err != nil {
		t.Fatal(err)
	}
	content, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	entries := ParseFstab(string(content))
	var data int
	for _, entry := range entries {
		if entry.Target == "/mnt/data" {
			data++
			if entry.Source != "LABEL=data" || entry.FSType != "xfs" || !entry.Managed {
				t.Errorf("entry after the change = %+v", entry)
			}
		}
	}
	if data != 1 {
		t.Errorf("entries for /mnt/data = %d", data)
	}
	// The host administrator entry stays untouched.
	if !strings.Contains(string(content), "UUID=aaa / ext4") {
		t.Errorf("a foreign entry was lost:\n%s", content)
	}

	if err := RemoveFstabEntry(path, "/mnt/data"); err != nil {
		t.Fatal(err)
	}
	content, _ = os.ReadFile(path)
	for _, entry := range ParseFstab(string(content)) {
		if entry.Target == "/mnt/data" {
			t.Errorf("the entry survived removal:\n%s", content)
		}
	}
}
