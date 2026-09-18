//go:build integration

package integration

import (
	"encoding/json"
	"net/http"
	"testing"
	"time"
)

/*
The layers above a bare disk: the software array and the volume manager.

What this file cannot do, and why. The task these tests belong to asked for
loop devices the test makes and removes itself. The panel has no operation
that runs an arbitrary command on a host - deliberately, it is a typed
operation system - and the integration harness speaks to the control plane
over HTTP and to nothing else. There is therefore no honest way from here
to create a loop device, build an array on it and tear it down again: it
would need a second channel into the lab that the product does not have,
and a test that opened one would be testing that channel.

So the lab hosts are read as they are, and every change is ordered against
a target the host must refuse. That is the half worth guarding anyway: what
these operations must never do is succeed on the wrong array, on the wrong
volume, or on a host that could not be asked. Not one of them touches a
device carrying a mounted filesystem - the orders below name devices that
do not exist on the lab hosts, and the plan refuses before any tool runs.
*/

type raidMemberView struct {
	Path                      string `json:"path"`
	Role                      string `json:"role"`
	ByID                      string `json:"by_id"`
	IdentityUnavailableReason string `json:"identity_unavailable_reason"`
}

type raidArrayView struct {
	Path                    string           `json:"path"`
	UUID                    string           `json:"uuid"`
	Level                   string           `json:"level"`
	State                   string           `json:"state"`
	RaidDevices             int              `json:"raid_devices"`
	ActiveDevices           int              `json:"active_devices"`
	FailedDevices           int              `json:"failed_devices"`
	Degraded                bool             `json:"degraded"`
	Redundant               bool             `json:"redundant"`
	SyncAction              string           `json:"sync_action"`
	SyncPercent             *float64         `json:"sync_percent"`
	Members                 []raidMemberView `json:"members"`
	DetailUnavailableReason string           `json:"detail_unavailable_reason"`
}

type layerSnapshot struct {
	Groups []struct {
		Name            string `json:"name"`
		UUID            string `json:"uuid"`
		FreeBytes       uint64 `json:"free_bytes"`
		ExtentSizeBytes uint64 `json:"extent_size_bytes"`
	} `json:"groups"`
	Volumes []struct {
		Name        string   `json:"name"`
		Group       string   `json:"group"`
		Path        string   `json:"path"`
		UUID        string   `json:"uuid"`
		Attributes  string   `json:"attributes"`
		Origin      string   `json:"origin"`
		DataPercent *float64 `json:"data_percent"`
	} `json:"volumes"`
	PhysicalVolumes []struct {
		Path  string `json:"path"`
		Group string `json:"group"`
	} `json:"physical_volumes"`
	Arrays                []raidArrayView `json:"arrays"`
	LVMUnavailableReason  string          `json:"lvm_unavailable_reason"`
	RAIDUnavailableReason string          `json:"raid_unavailable_reason"`
	UnavailableReason     string          `json:"unavailable_reason"`
}

const layerReason = "integration test of the storage layers"

func hostLayerSnapshot(t *testing.T, h *harness, hostID string) layerSnapshot {
	t.Helper()
	var fragment inventoryFragment
	h.do(http.MethodGet, "/api/v1/hosts/"+hostID+"/inventory/storage", nil, &fragment, http.StatusOK)
	var state layerSnapshot
	if err := json.Unmarshal(fragment.Payload, &state); err != nil {
		t.Fatalf("storage snapshot: %v", err)
	}
	return state
}

// TestSoftwareRAIDIsReadOrExplained guards the doctrine on the one module
// where an empty list is the easiest lie to tell: a host with no arrays
// and a host nobody could ask about must not look the same.
func TestSoftwareRAIDIsReadOrExplained(t *testing.T) {
	h := newHarness(t)
	for _, family := range []string{"debian", "rhel"} {
		t.Run(family, func(t *testing.T) {
			host := h.hostByFamily(family)
			state := hostLayerSnapshot(t, h, host.ID)
			if state.UnavailableReason != "" {
				t.Fatalf("the storage was not read at all: %s", state.UnavailableReason)
			}
			if len(state.Arrays) == 0 && state.RAIDUnavailableReason == "" {
				// The kernel has the md driver and no array is assembled.
				// That is a legitimate answer and the one the lab gives; it
				// is recorded here so a future empty list with no reason is
				// read as the answer it is rather than as a gap.
				t.Log("this host has software RAID support and no array assembled")
			}
			for _, array := range state.Arrays {
				if array.Path == "" {
					t.Errorf("an array without a path: %+v", array)
				}
				// An array with no UUID is an array no operation binds to,
				// and it has to say why rather than look bindable.
				if array.UUID == "" && array.DetailUnavailableReason == "" {
					t.Errorf("an array without a UUID and without a reason: %+v", array)
				}
				// A rebuild that is not running has no percentage; zero
				// would read as a rebuild standing still.
				if array.SyncAction == "" && array.SyncPercent != nil {
					t.Errorf("an idle array reports a rebuild: %+v", array)
				}
				if array.Degraded && array.FailedDevices == 0 && array.ActiveDevices >= array.RaidDevices {
					t.Errorf("an array called degraded with every slot filled: %+v", array)
				}
				for _, member := range array.Members {
					if member.Path != "" && member.ByID == "" && member.IdentityUnavailableReason == "" {
						t.Errorf("a member without an identity and without a reason: %+v", member)
					}
				}
			}
		})
	}
}

// TestVolumesCarryTheIdentityAnOrderBindsTo guards the other half: a group
// or a volume without a UUID is a group or a volume no order may name,
// and a snapshot is told apart from an ordinary volume.
func TestVolumesCarryTheIdentityAnOrderBindsTo(t *testing.T) {
	h := newHarness(t)
	host := h.hostByFamily("debian")
	state := hostLayerSnapshot(t, h, host.ID)
	if state.LVMUnavailableReason != "" {
		t.Skipf("this host has no LVM: %s", state.LVMUnavailableReason)
	}
	if len(state.Groups) == 0 {
		t.Skip("this host has LVM and no volume group")
	}
	for _, group := range state.Groups {
		if group.UUID == "" {
			t.Errorf("a volume group without a UUID: %+v", group)
		}
		// The extent size decides what a request for a size really gets:
		// LVM rounds up to whole extents.
		if group.ExtentSizeBytes == 0 {
			t.Errorf("a group without an extent size: %+v", group)
		}
	}
	for _, volume := range state.Volumes {
		if volume.UUID == "" {
			t.Errorf("a logical volume without a UUID: %+v", volume)
		}
		if volume.Attributes == "" {
			t.Errorf("a volume without lv_attr: %+v", volume)
		}
		// An ordinary volume has no copy-on-write space at all, so it has
		// no fill - not a fill of zero.
		snapshot := volume.Origin != "" || volume.Attributes[0] == 's' || volume.Attributes[0] == 'S'
		if !snapshot && volume.DataPercent != nil {
			t.Errorf("an ordinary volume reports a snapshot fill: %+v", volume)
		}
	}
	for _, physical := range state.PhysicalVolumes {
		if physical.Path == "" {
			t.Errorf("a physical volume without a path: %+v", physical)
		}
	}
}

// TestAnArrayOrderWithoutAnIdentityDoesNotReachTheHost guards the binding
// that makes these operations safe at all: an order that names an array by
// path or a member by path is not created.
func TestAnArrayOrderWithoutAnIdentityDoesNotReachTheHost(t *testing.T) {
	h := newHarness(t)
	host := h.hostByFamily("debian")

	for _, tc := range []struct {
		why     string
		payload map[string]any
	}{
		{"no array UUID", map[string]any{
			"array": "/dev/md0", "device": "/dev/sdz1",
			"expected_by_id": "/dev/disk/by-id/ata-DOES-NOT-EXIST"}},
		{"no member identity", map[string]any{
			"array": "/dev/md0", "device": "/dev/sdz1",
			"expected_array_uuid": "00000000:11111111:22222222:33333333"}},
		{"an array that is not an array", map[string]any{
			"array": "/dev/sda", "device": "/dev/sdz1",
			"expected_array_uuid": "00000000:11111111:22222222:33333333",
			"expected_by_id":      "/dev/disk/by-id/ata-DOES-NOT-EXIST"}},
	} {
		t.Run(tc.why, func(t *testing.T) {
			h.do(http.MethodPost, "/api/v1/hosts/"+host.ID+"/operations",
				map[string]any{"action": "raid.member.remove", "reason": layerReason,
					"payload": map[string]any{"storage": tc.payload}},
				nil, http.StatusBadRequest)
		})
	}
}

// TestAVolumeOrderWithoutAUUIDDoesNotReachTheHost is the same boundary for
// LVM: a group name is a label another group can carry after a rename.
func TestAVolumeOrderWithoutAUUIDDoesNotReachTheHost(t *testing.T) {
	h := newHarness(t)
	host := h.hostByFamily("debian")

	for _, tc := range []struct {
		why     string
		action  string
		payload map[string]any
	}{
		{"a volume created in a group named only by name", "lvm.volume.create",
			map[string]any{"group": "vg0", "volume": "logs", "size": "1G"}},
		{"a volume created with an increment instead of a size", "lvm.volume.create",
			map[string]any{"group": "vg0", "volume": "logs", "size": "+1G",
				"expected_group_uuid": "no-such-group"}},
		{"a snapshot of a volume named only by path", "lvm.snapshot.create",
			map[string]any{"device": "/dev/vg0/data", "volume": "before", "size": "1G"}},
		{"a snapshot dropped by path alone", "lvm.snapshot.remove",
			map[string]any{"device": "/dev/vg0/before"}},
		{"a disk taken into a group without its by-id link", "lvm.group.extend",
			map[string]any{"group": "vg0", "device": "/dev/sdz",
				"expected_group_uuid": "no-such-group"}},
	} {
		t.Run(tc.why, func(t *testing.T) {
			h.do(http.MethodPost, "/api/v1/hosts/"+host.ID+"/operations",
				map[string]any{"action": tc.action, "reason": layerReason,
					"payload": map[string]any{"storage": tc.payload}},
				nil, http.StatusBadRequest)
		})
	}
}

// TestDeletingAVolumeIsTreatedLikeAFormat guards that the destructive half
// of LVM gets the destructive treatment: the host name typed out and two
// people behind it.
func TestDeletingAVolumeIsTreatedLikeAFormat(t *testing.T) {
	h := newHarness(t)
	host := h.hostByFamily("debian")

	// Without the hostname typed in, the operation is not created at all.
	h.do(http.MethodPost, "/api/v1/hosts/"+host.ID+"/operations",
		map[string]any{"action": "lvm.volume.remove", "reason": layerReason,
			"payload": map[string]any{"storage": map[string]any{
				"device":               "/dev/vg-does-not-exist/data",
				"expected_volume_uuid": "no-such-volume",
				"expected_by_id":       "/dev/disk/by-id/dm-uuid-LVM-does-not-exist"}}},
		nil, http.StatusBadRequest)

	// The target names a group no host has, so the host refuses it anyway:
	// the test is about counting approvals, not about deleting data.
	job := h.createOperation(host.ID, map[string]any{
		"action": "lvm.volume.remove", "reason": layerReason,
		"target_confirmation": host.Hostname,
		"payload": map[string]any{"storage": map[string]any{
			"device":               "/dev/vg-does-not-exist/data",
			"expected_volume_uuid": "no-such-volume",
			"expected_by_id":       "/dev/disk/by-id/dm-uuid-LVM-does-not-exist"}},
	})
	if job.RequiredApprovals != 2 {
		t.Fatalf("required approvals = %d", job.RequiredApprovals)
	}
	h.approve(job.ID, job.PayloadHash)
	second := h.withToken(h.createPrincipal("second-person-volume",
		[]map[string]string{{"role": "platform_admin", "scope": "*"}}))
	after := second.approve(job.ID, job.PayloadHash)
	if after.State != "queued" {
		t.Fatalf("after two approvals: state = %s", after.State)
	}

	final := h.awaitTerminal(job.ID, 2*time.Minute)
	if final.State == "succeeded" {
		t.Fatal("the host deleted a volume in a group it does not have")
	}
	attempts := h.attempts(job.ID)
	if len(attempts) == 0 || attempts[len(attempts)-1].ErrorCode != "volume_unknown" {
		t.Errorf("refusal = %q, want volume_unknown", lastMessage(attempts))
	}
}

// TestTheHostRefusesAnArrayItDoesNotHave guards the far end of the same
// question: an order that passed the panel is still refused by the host,
// with a typed code, rather than succeeding on nothing.
func TestTheHostRefusesAnArrayItDoesNotHave(t *testing.T) {
	h := newHarness(t)
	host := h.hostByFamily("debian")

	job, attempts := h.runOperation(host.ID, map[string]any{
		"action": "raid.member.remove", "reason": layerReason,
		"payload": map[string]any{"storage": map[string]any{
			"array": "/dev/md127", "device": "/dev/sdz1",
			"expected_array_uuid": "00000000:11111111:22222222:33333333",
			"expected_by_id":      "/dev/disk/by-id/ata-DOES-NOT-EXIST"}},
	}, 2*time.Minute)
	if job.State == "succeeded" {
		t.Fatal("the host removed a member from an array it does not have")
	}
	if len(attempts) == 0 {
		t.Fatal("the job produced no attempt")
	}
	// A host with mdadm answers that it has no such array; a host without
	// the tool answers that it cannot manage arrays at all. Both are the
	// refusal this test is about - the order does not reach a disk - and
	// each says which of the two it is, which is the point of typing them.
	switch code := attempts[len(attempts)-1].ErrorCode; code {
	case "array_unknown", "unsupported":
	default:
		t.Errorf("refusal = %q (%s), want array_unknown or unsupported", code, lastMessage(attempts))
	}
}

// TestBuildingAnArrayIsRefusedByName guards the boundary the catalogue
// draws: the panel manages the members of an array that exists, and says
// so with its own code instead of looking like a module with a gap.
func TestBuildingAnArrayIsRefusedByName(t *testing.T) {
	h := newHarness(t)
	host := h.hostByFamily("debian")

	var refused struct {
		Code   string `json:"code"`
		Detail string `json:"detail"`
	}
	h.do(http.MethodPost, "/api/v1/hosts/"+host.ID+"/operations",
		map[string]any{"action": "storage.plan", "reason": layerReason,
			"payload": map[string]any{"storage": map[string]any{"plan": "raid_create"}}},
		&refused, http.StatusBadRequest)
	if refused.Code != "array_lifecycle_out_of_scope" {
		t.Errorf("refusal code = %q, want array_lifecycle_out_of_scope", refused.Code)
	}

	// The refusal is in the error catalogue with what to do next, so an
	// operator reading it is not left guessing whether it is a gap.
	var guide struct {
		Items []struct {
			Code    string `json:"code"`
			Meaning string `json:"meaning"`
			Action  string `json:"action"`
		} `json:"items"`
	}
	h.do(http.MethodGet, "/api/v1/errors", nil, &guide, http.StatusOK)
	wanted := map[string]bool{
		"array_lifecycle_out_of_scope": false, "array_unknown": false,
		"array_member_unknown": false, "array_redundancy_lost": false,
		"array_rebuilding": false, "volume_unknown": false,
		"volume_group_full": false, "snapshot_of_snapshot": false,
		"filesystem_errors_remain": false,
	}
	for _, item := range guide.Items {
		if _, named := wanted[item.Code]; !named {
			continue
		}
		if item.Meaning == "" || item.Action == "" {
			t.Errorf("the guide entry for %s says nothing", item.Code)
		}
		wanted[item.Code] = true
	}
	for code, found := range wanted {
		if !found {
			t.Errorf("the error catalogue does not describe %s", code)
		}
	}
}

// TestTheCatalogueDeclaresAVerifierForEveryLayerOperation guards the rule
// this whole task is about: no storage change is settled by the exit code
// of a tool.
func TestTheCatalogueDeclaresAVerifierForEveryLayerOperation(t *testing.T) {
	h := newHarness(t)
	var catalogue struct {
		Items []struct {
			Action          string `json:"action"`
			Mutating        bool   `json:"mutating"`
			Risk            string `json:"risk"`
			Verification    string `json:"verification"`
			CampaignReady   bool   `json:"campaign_ready"`
			CampaignRefusal string `json:"campaign_refusal"`
		} `json:"items"`
	}
	h.do(http.MethodGet, "/api/v1/actions", nil, &catalogue, http.StatusOK)

	layers := map[string]bool{
		"raid.member.fail": false, "raid.member.remove": false, "raid.member.add": false,
		"lvm.volume.create": false, "lvm.volume.remove": false, "lvm.group.extend": false,
		"lvm.snapshot.create": false, "lvm.snapshot.remove": false,
		// The two that used to settle on an exit code.
		"filesystem.check": false, "disk.wipe": false,
	}
	for _, item := range catalogue.Items {
		if _, named := layers[item.Action]; !named {
			continue
		}
		layers[item.Action] = true
		if !item.Mutating {
			t.Errorf("%s is listed as a read", item.Action)
		}
		if item.Verification == "" || item.Verification == "none" {
			t.Errorf("%s settles on nothing that is read back", item.Action)
		}
		// None of the layer operations has a fleet-wide version yet, and a
		// refusal without a reason reads as a missing feature.
		if !item.CampaignReady && item.CampaignRefusal == "" && item.Action != "disk.wipe" &&
			item.Action != "filesystem.check" {
			t.Errorf("%s is kept out of campaigns without saying why", item.Action)
		}
	}
	for action, found := range layers {
		if !found {
			t.Errorf("the catalogue does not list %s", action)
		}
	}
}
