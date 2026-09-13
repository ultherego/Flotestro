//go:build integration

package integration

import (
	"encoding/json"
	"net/http"
	"strings"
	"testing"
	"time"
)

type deviceView struct {
	Path        string   `json:"path"`
	Type        string   `json:"type"`
	SizeBytes   uint64   `json:"size_bytes"`
	FSType      string   `json:"fs_type"`
	UUID        string   `json:"uuid"`
	Parent      string   `json:"parent"`
	Mountpoints []string `json:"mountpoints"`
}

type mountView struct {
	Target            string  `json:"target"`
	Source            string  `json:"source"`
	FSType            string  `json:"fs_type"`
	InFstab           bool    `json:"in_fstab"`
	Mounted           bool    `json:"mounted"`
	Managed           bool    `json:"managed"`
	UsedPercent       *uint32 `json:"used_percent"`
	InodesUsedPercent *uint32 `json:"inodes_used_percent"`
}

type storageSnapshot struct {
	Devices []deviceView `json:"devices"`
	Mounts  []mountView  `json:"mounts"`
	Groups  []struct {
		Name      string `json:"name"`
		FreeBytes uint64 `json:"free_bytes"`
	} `json:"groups"`
	LVMUnavailableReason string `json:"lvm_unavailable_reason"`
	UnavailableReason    string `json:"unavailable_reason"`
}

const storageReason = "integration test of the storage module"

// TestTopologyHasStableIdentifiers checks the thing that decides the safety
// of every disk operation: a device is to be recognisable by UUID, not by
// /dev/sdX, which points at something else after a reboot.
func TestTopologyHasStableIdentifiers(t *testing.T) {
	h := newHarness(t)

	for _, family := range []string{"debian", "rhel"} {
		t.Run(family, func(t *testing.T) {
			host := h.hostByFamily(family)
			state := hostStorageSnapshot(t, h, host.ID)
			if state.UnavailableReason != "" {
				t.Fatalf("the topology was not read: %s", state.UnavailableReason)
			}
			if len(state.Devices) == 0 {
				t.Fatal("the host reported no device at all")
			}

			var withFilesystem, withParent int
			for _, device := range state.Devices {
				if device.FSType != "" && device.FSType != "swap" &&
					device.FSType != "LVM2_member" {
					withFilesystem++
					if device.UUID == "" {
						t.Errorf("filesystem without a UUID: %+v", device)
					}
				}
				if device.Parent != "" {
					withParent++
				}
			}
			if withFilesystem == 0 {
				t.Error("the host reported no filesystem at all")
			}
			// A topology without parent references is not a topology, only a
			// list - and in an extension plan the hierarchy is exactly what
			// counts.
			if withParent == 0 {
				t.Error("no device points at a parent")
			}
		})
	}
}

// TestMountsSeparateStateFromFstab checks the distinction the operator
// comes here for: what is mounted now and what survives a reboot.
func TestMountsSeparateStateFromFstab(t *testing.T) {
	h := newHarness(t)
	host := h.hostByFamily("debian")
	state := hostStorageSnapshot(t, h, host.ID)

	var root mountView
	var withoutEntry int
	for _, mount := range state.Mounts {
		if mount.Target == "/" {
			root = mount
		}
		if mount.Mounted && !mount.InFstab {
			withoutEntry++
		}
		// A mounted filesystem without a usage read would look empty; a
		// missing value is to be missing, not zero.
		if mount.Mounted && mount.UsedPercent != nil && *mount.UsedPercent > 100 {
			t.Errorf("usage out of range: %+v", mount)
		}
		if mount.InodesUsedPercent != nil && *mount.InodesUsedPercent > 100 {
			t.Errorf("inode usage out of range: %+v", mount)
		}
	}
	if !root.Mounted || !root.InFstab || root.UsedPercent == nil {
		t.Errorf("root = %+v", root)
	}
	// A host with containers and bind mounts always has mounts outside
	// fstab; if there were none, it would mean only the file is read.
	if withoutEntry == 0 {
		t.Error("the panel recognised no mount outside fstab")
	}
}

// TestMountOnASystemDirectoryIsRejected guards the boundary whose crossing
// cuts the host off from itself.
func TestMountOnASystemDirectoryIsRejected(t *testing.T) {
	h := newHarness(t)
	host := h.hostByFamily("debian")

	for _, tc := range []struct {
		change map[string]any
		why    string
	}{
		{map[string]any{"source": "UUID=aaaa", "target": "/etc", "fs_type": "ext4"}, "system directory"},
		{map[string]any{"source": "UUID=aaaa", "target": "/mnt/../etc", "fs_type": "ext4"}, "path climbing up"},
		{map[string]any{"source": "sdb1", "target": "/mnt/data", "fs_type": "ext4"}, "source without a path"},
		{map[string]any{"source": "UUID=aaaa", "target": "/mnt/data", "fs_type": "ext4",
			"options": "defaults;reboot"}, "options with a semicolon"},
	} {
		t.Run(tc.why, func(t *testing.T) {
			h.do(http.MethodPost, "/api/v1/hosts/"+host.ID+"/operations",
				map[string]any{"action": "mount.ensure", "reason": storageReason,
					"payload": map[string]any{"storage": tc.change}},
				nil, http.StatusBadRequest)
		})
	}
}

// TestFilesystemCheckRequiresUnmounting guards the rule whose breaking ends
// in data corruption: fsck on a mounted filesystem.
func TestFilesystemCheckRequiresUnmounting(t *testing.T) {
	h := newHarness(t)
	host := h.hostByFamily("debian")
	state := hostStorageSnapshot(t, h, host.ID)

	var mounted string
	for _, device := range state.Devices {
		if len(device.Mountpoints) > 0 && device.FSType != "" && device.FSType != "swap" {
			mounted = device.Path
			break
		}
	}
	if mounted == "" {
		t.Skip("the host has no mounted filesystem")
	}

	job, attempts := h.runOperation(host.ID, map[string]any{
		"action": "filesystem.check", "reason": storageReason,
		"payload": map[string]any{"storage": map[string]any{"device": mounted}},
	}, 2*time.Minute)
	if job.State == "succeeded" {
		t.Fatalf("the panel checked the mounted filesystem %s", mounted)
	}
	if !strings.Contains(lastMessage(attempts), "is mounted") {
		t.Errorf("refusal without a reason: %q", lastMessage(attempts))
	}
}

func hostStorageSnapshot(t *testing.T, h *harness, hostID string) storageSnapshot {
	t.Helper()
	var fragment inventoryFragment
	h.do(http.MethodGet, "/api/v1/hosts/"+hostID+"/inventory/storage", nil, &fragment, http.StatusOK)
	var state storageSnapshot
	if err := json.Unmarshal(fragment.Payload, &state); err != nil {
		t.Fatalf("storage snapshot: %v", err)
	}
	return state
}

// TestDestructiveOperationRequiresTwoPeople checks the boundary that tells
// formatting from every other operation: a mistake by one person with the
// right to approve costs data nobody will restore.
func TestDestructiveOperationRequiresTwoPeople(t *testing.T) {
	h := newHarness(t)
	host := h.hostByFamily("debian")

	// The target is chosen so that the host rejects the job anyway: the
	// test is about counting approvals, not about wiping data.
	job := h.createOperation(host.ID, map[string]any{
		"action": "disk.wipe", "reason": storageReason,
		"target_confirmation": host.Hostname,
		"payload": map[string]any{"storage": map[string]any{
			"device": "/dev/sdz", "expected_serial": "DEVICE-THAT-DOES-NOT-EXIST"}},
	})
	if job.RequiredApprovals != 2 {
		t.Fatalf("required approvals = %d", job.RequiredApprovals)
	}

	after := h.approve(job.ID, job.PayloadHash)
	if after.State != "awaiting_approval" || after.CollectedApprovals != 1 {
		t.Fatalf("after the first approval: state = %s, approvals = %d", after.State, after.CollectedApprovals)
	}
	// The same person clicking a second time is still one person.
	after = h.approve(job.ID, job.PayloadHash)
	if after.CollectedApprovals != 1 {
		t.Fatalf("the same person counted twice: %d", after.CollectedApprovals)
	}

	second := h.withToken(h.createPrincipal("second-person-storage",
		[]map[string]string{{"role": "platform_admin", "scope": "*"}}))
	after = second.approve(job.ID, job.PayloadHash)
	if after.State != "queued" || after.CollectedApprovals != 2 {
		t.Fatalf("after the second approval: state = %s, approvals = %d", after.State, after.CollectedApprovals)
	}

	// The job goes to the host and is to be rejected there: the device does
	// not exist.
	final := h.awaitTerminal(job.ID, 2*time.Minute)
	if final.State == "succeeded" {
		t.Error("the host carried out an operation on a device that does not exist")
	}
}

// TestDestructiveOperationChecksTheDeviceIdentity guards that formatting
// hits the disk the operator looked at. The /dev/sdX path points at
// something else after a reboot.
func TestDestructiveOperationChecksTheDeviceIdentity(t *testing.T) {
	h := newHarness(t)
	host := h.hostByFamily("debian")
	state := hostStorageSnapshot(t, h, host.ID)

	var empty deviceView
	for _, device := range state.Devices {
		if device.Type == "disk" && len(device.Mountpoints) == 0 {
			// A disk without mounted descendants: checked through the tree.
			busy := false
			for _, child := range state.Devices {
				if child.Parent == device.Path && len(child.Mountpoints) > 0 {
					busy = true
				}
			}
			if !busy {
				empty = device
				break
			}
		}
	}
	if empty.Path == "" {
		t.Skip("the host has no free disk")
	}

	// A wrong identity: the host is to refuse before doing anything.
	job := h.createOperation(host.ID, map[string]any{
		"action": "disk.wipe", "reason": storageReason,
		"target_confirmation": host.Hostname,
		"payload": map[string]any{"storage": map[string]any{
			"device": empty.Path, "expected_size_bytes": 1024}},
	})
	h.approve(job.ID, job.PayloadHash)
	second := h.withToken(h.createPrincipal("second-person-identity",
		[]map[string]string{{"role": "platform_admin", "scope": "*"}}))
	second.approve(job.ID, job.PayloadHash)

	final := h.awaitTerminal(job.ID, 2*time.Minute)
	if final.State == "succeeded" {
		t.Fatalf("the host wiped %s despite the mismatched size", empty.Path)
	}
	attempts := h.attempts(job.ID)
	if !strings.Contains(lastMessage(attempts), "bytes") {
		t.Errorf("the refusal does not explain the mismatch: %q", lastMessage(attempts))
	}
}

// TestDestructiveOperationRequiresAnIdentity checks that an order without
// any device identifier does not reach the host.
func TestDestructiveOperationRequiresAnIdentity(t *testing.T) {
	h := newHarness(t)
	host := h.hostByFamily("debian")

	h.do(http.MethodPost, "/api/v1/hosts/"+host.ID+"/operations",
		map[string]any{"action": "disk.wipe", "reason": storageReason,
			"target_confirmation": host.Hostname,
			"payload":             map[string]any{"storage": map[string]any{"device": "/dev/sdb"}}},
		nil, http.StatusBadRequest)

	// Without the hostname typed in, a destructive operation is not created
	// at all.
	h.do(http.MethodPost, "/api/v1/hosts/"+host.ID+"/operations",
		map[string]any{"action": "disk.wipe", "reason": storageReason,
			"payload": map[string]any{"storage": map[string]any{
				"device": "/dev/sdb", "expected_size_bytes": 2147483648}}},
		nil, http.StatusBadRequest)
}
