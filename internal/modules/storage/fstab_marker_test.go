package storage

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// The marker of the panel carries the target it belongs to, and the target
// used to be compared as a substring: "/mnt/data" then selected the marker of
// "/mnt/data-archive" and took its mount out of fstab with it. Nothing
// reported it, and the host kept working until the next reboot, because the
// panel reads /proc/mounts and not fstab.
func TestWritingOneEntryLeavesAnEntryWithTheSamePrefixAlone(t *testing.T) {
	path := filepath.Join(t.TempDir(), "fstab")
	before := strings.Join([]string{
		"UUID=aaa / ext4 defaults 0 1",
		PanelMarker + ": /mnt/data-archive",
		"/dev/sdb1 /mnt/data-archive ext4 defaults 0 2",
		PanelMarker + ": /mnt/data",
		"/dev/sdc1 /mnt/data ext4 defaults 0 2",
		"",
	}, "\n")
	if err := os.WriteFile(path, []byte(before), 0o644); err != nil {
		t.Fatal(err)
	}

	if err := WriteFstabEntry(path, "/dev/sdc1", "/mnt/data", "ext4", "defaults,noatime"); err != nil {
		t.Fatal(err)
	}
	after, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	text := string(after)

	if !strings.Contains(text, "/mnt/data-archive ext4") {
		t.Errorf("the entry for /mnt/data-archive was taken out by a write about /mnt/data:\n%s", text)
	}
	if !strings.Contains(text, PanelMarker+": /mnt/data-archive") {
		t.Errorf("the marker of /mnt/data-archive is gone:\n%s", text)
	}
	if !strings.Contains(text, "noatime") {
		t.Errorf("the entry for /mnt/data was not written:\n%s", text)
	}
	if strings.Count(text, PanelMarker+": /mnt/data\n") != 1 {
		t.Errorf("the entry for /mnt/data is not there exactly once:\n%s", text)
	}
}

// The same when the entry goes away: removing one must not remove the other.
func TestRemovingOneEntryLeavesAnEntryWithTheSamePrefixAlone(t *testing.T) {
	path := filepath.Join(t.TempDir(), "fstab")
	before := strings.Join([]string{
		PanelMarker + ": /mnt/data-archive",
		"/dev/sdb1 /mnt/data-archive ext4 defaults 0 2",
		PanelMarker + ": /mnt/data",
		"/dev/sdc1 /mnt/data ext4 defaults 0 2",
		"",
	}, "\n")
	if err := os.WriteFile(path, []byte(before), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := RemoveFstabEntry(path, "/mnt/data"); err != nil {
		t.Fatal(err)
	}
	after, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	text := string(after)
	if !strings.Contains(text, "/mnt/data-archive ext4") {
		t.Errorf("removing /mnt/data took /mnt/data-archive with it:\n%s", text)
	}
	if strings.Contains(text, "/dev/sdc1") {
		t.Errorf("the entry for /mnt/data is still there:\n%s", text)
	}
}

// A line that is not the panel's marker names no target of the panel.
func TestOnlyThePanelsOwnMarkerNamesATarget(t *testing.T) {
	for _, line := range []string{
		"# flotestro-backup: /mnt/data",
		"# something else: /mnt/data",
		"/dev/sdc1 /mnt/data ext4 defaults 0 2",
		"",
	} {
		if name, ok := markerTarget(line); ok {
			t.Errorf("the line %q was read as the panel's marker for %q", line, name)
		}
	}
	if name, ok := markerTarget(PanelMarker + ":  /mnt/data  "); !ok || name != "/mnt/data" {
		t.Errorf("markerTarget = %q, %v; want /mnt/data, true", name, ok)
	}
}
