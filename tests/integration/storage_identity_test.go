//go:build integration

package integration

import (
	"encoding/json"
	"net/http"
	"regexp"
	"strings"
	"testing"
	"time"
)

// identityDeviceView mirrors the identity fields of a device: what a
// destructive operation binds to, and why a device has none.
type identityDeviceView struct {
	Path                      string   `json:"path"`
	Type                      string   `json:"type"`
	ByID                      string   `json:"by_id"`
	WWN                       string   `json:"wwn"`
	Serial                    string   `json:"serial"`
	UUID                      string   `json:"uuid"`
	Parent                    string   `json:"parent"`
	Children                  []string `json:"children"`
	Holders                   []string `json:"holders"`
	Mountpoints               []string `json:"mountpoints"`
	RootDevice                bool     `json:"root_device"`
	HasMountedChildren        bool     `json:"has_mounted_children"`
	HasOpenHolders            bool     `json:"has_open_holders"`
	IdentityUnavailableReason string   `json:"identity_unavailable_reason"`
}

// devicePlanView mirrors the identity a device plan carries.
type devicePlanView struct {
	Operation   string `json:"operation"`
	Action      string `json:"action"`
	ByID        string `json:"by_id"`
	WWN         string `json:"wwn"`
	Serial      string `json:"serial"`
	RootDevice  bool   `json:"root_device"`
	Refusal     string `json:"refusal"`
	RefusalCode string `json:"refusal_code"`
	PlanHash    string `json:"plan_hash"`
}

const identityReason = "integration test of the storage identity"

var hexDigest = regexp.MustCompile(`^[0-9a-f]{64}$`)

// identityDevices reads the devices of a host with their identity.
func identityDevices(t *testing.T, h *harness, hostID string) []identityDeviceView {
	t.Helper()
	var fragment inventoryFragment
	h.do(http.MethodGet, "/api/v1/hosts/"+hostID+"/inventory/storage", nil, &fragment, http.StatusOK)
	var state struct {
		Devices           []identityDeviceView `json:"devices"`
		FstabRevision     string               `json:"fstab_revision"`
		UnavailableReason string               `json:"unavailable_reason"`
	}
	if err := json.Unmarshal(fragment.Payload, &state); err != nil {
		t.Fatalf("storage snapshot: %v", err)
	}
	if state.UnavailableReason != "" {
		t.Fatalf("the topology was not read: %s", state.UnavailableReason)
	}
	if !hexDigest.MatchString(state.FstabRevision) {
		t.Errorf("the snapshot carries no fstab revision: %q", state.FstabRevision)
	}
	return state.Devices
}

// systemDisk finds the disk that carries root: the one no operation may
// destroy, and the one every lab host has.
func systemDisk(t *testing.T, devices []identityDeviceView) identityDeviceView {
	t.Helper()
	for _, device := range devices {
		if device.Type == "disk" && device.RootDevice {
			return device
		}
	}
	t.Fatal("no disk carries the root filesystem")
	return identityDeviceView{}
}

// storagePlanDetail reads the plan out of the planning job.
func storagePlanDetail(t *testing.T, h *harness, jobID, kind string) json.RawMessage {
	t.Helper()
	var response struct {
		Items []struct {
			Detail struct {
				Kind string          `json:"kind"`
				Plan json.RawMessage `json:"plan"`
			} `json:"detail"`
		} `json:"items"`
	}
	h.get("/api/v1/jobs/"+jobID+"/attempts", &response)
	for i := len(response.Items) - 1; i >= 0; i-- {
		if response.Items[i].Detail.Kind == kind {
			return response.Items[i].Detail.Plan
		}
	}
	t.Fatalf("the job %s carries no %s", jobID, kind)
	return nil
}

// TestDevicesCarryAStableIdentity checks the thing every destructive
// operation binds to: a disk is named by its /dev/disk/by-id link, its
// serial or WWN, and the topology says what stands on it. A virtual disk
// in the lab has no WWN, but it has a serial and an ata- link - and a
// device that has none says why, rather than showing an empty cell.
func TestDevicesCarryAStableIdentity(t *testing.T) {
	h := newHarness(t)
	for _, family := range []string{"debian", "rhel"} {
		t.Run(family, func(t *testing.T) {
			host := h.hostByFamily(family)
			devices := identityDevices(t, h, host.ID)
			var disks int
			for _, device := range devices {
				if device.Type != "disk" {
					continue
				}
				disks++
				if device.ByID == "" {
					if device.IdentityUnavailableReason == "" {
						t.Errorf("%s has no by-id link and no reason", device.Path)
					}
					continue
				}
				if !strings.HasPrefix(device.ByID, "/dev/disk/by-id/") {
					t.Errorf("%s: by-id link outside the directory: %s", device.Path, device.ByID)
				}
				if device.WWN == "" && device.Serial == "" {
					t.Errorf("%s has a by-id link but neither a WWN nor a serial: %+v", device.Path, device)
				}
			}
			if disks == 0 {
				t.Fatal("the host reported no disk")
			}
			system := systemDisk(t, devices)
			if !system.HasMountedChildren || len(system.Children) == 0 {
				t.Errorf("the system disk does not know what stands on it: %+v", system)
			}
			if system.ByID == "" {
				t.Errorf("the system disk has no by-id link: %s", system.IdentityUnavailableReason)
			}
			// A partition that is a physical volume is held by the volume
			// group; the holder is what makes the disk in use even with
			// nothing mounted directly on it.
			for _, device := range devices {
				if device.Parent == system.Path && len(device.Holders) > 0 && !device.HasOpenHolders {
					t.Errorf("%s has holders but is not marked as held: %+v", device.Path, device)
				}
			}
		})
	}
}

// TestDestructivePlanOnTheRootDiskIsRefused checks the plan of a wipe
// against the system disk: the plan carries the identity of the disk and
// refuses with disk_in_use before anybody approves anything. A plan is a
// read; nothing on the host moves.
func TestDestructivePlanOnTheRootDiskIsRefused(t *testing.T) {
	h := newHarness(t)
	host := h.hostByFamily("debian")
	system := systemDisk(t, identityDevices(t, h, host.ID))

	job, attempts := h.runOperation(host.ID, map[string]any{
		"action": "storage.plan", "reason": identityReason,
		"payload": map[string]any{"storage": map[string]any{"device": system.Path, "plan": "wipe"}},
	}, 2*time.Minute)
	if job.State != "succeeded" {
		t.Fatalf("planning the wipe: state = %s, %s", job.State, lastMessage(attempts))
	}
	var plan devicePlanView
	if err := json.Unmarshal(storagePlanDetail(t, h, job.ID, "device_plan"), &plan); err != nil {
		t.Fatalf("device plan: %v", err)
	}
	if plan.Operation != "wipe" || plan.Action == "run" {
		t.Fatalf("the plan would wipe the system disk: %+v", plan)
	}
	if plan.ByID != system.ByID || plan.Serial != system.Serial {
		t.Errorf("the plan does not carry the identity of the disk: plan %+v, disk %+v", plan, system)
	}
	// A disk without a by-id link is refused for that first; one with a
	// link is refused for what stands on it.
	want := "disk_in_use"
	if system.ByID == "" {
		want = "stable_identity_required"
	}
	if plan.RefusalCode != want || !plan.RootDevice {
		t.Errorf("the refusal is not typed as %s: %+v", want, plan)
	}
	if plan.PlanHash == "" {
		t.Error("the plan has no fingerprint")
	}
}

// TestDestructiveOperationIsRefusedByIdentityBeforeAnythingRuns guards
// the two refusals of chapter 7.3 on a real host: a disk of the same size
// with another WWN is another disk (disk_changed), and the system disk is
// never wiped (disk_in_use). Both are checked by the host right before the
// change, after two people approved.
func TestDestructiveOperationIsRefusedByIdentityBeforeAnythingRuns(t *testing.T) {
	h := newHarness(t)
	host := h.hostByFamily("debian")
	system := systemDisk(t, identityDevices(t, h, host.ID))
	if system.ByID == "" {
		t.Skipf("the system disk has no by-id link: %s", system.IdentityUnavailableReason)
	}

	wipe := func(identity map[string]any) (jobView, []attemptView) {
		t.Helper()
		payload := map[string]any{"device": system.Path}
		for key, value := range identity {
			payload[key] = value
		}
		job := h.createOperation(host.ID, map[string]any{
			"action": "disk.wipe", "reason": identityReason,
			"target_confirmation": host.Hostname,
			"payload":             map[string]any{"storage": payload},
		})
		h.approve(job.ID, job.PayloadHash)
		second := h.withToken(h.createPrincipal("second-person-"+job.ID[:8],
			[]map[string]string{{"role": "platform_admin", "scope": "*"}}))
		second.approve(job.ID, job.PayloadHash)
		final := h.awaitTerminal(job.ID, 2*time.Minute)
		return final, h.attempts(job.ID)
	}

	// The right link, the wrong WWN: the size and the path match, and that
	// proves nothing.
	job, attempts := wipe(map[string]any{
		"expected_by_id": system.ByID, "expected_serial": system.Serial,
		"expected_wwn": "0x5000c500deadbeef",
	})
	if job.State == "succeeded" {
		t.Fatalf("the host wiped %s with a mismatched WWN", system.Path)
	}
	if code := attempts[len(attempts)-1].ErrorCode; code != "disk_changed" {
		t.Errorf("a disk with another WWN was refused as %s, want disk_changed: %s", code, lastMessage(attempts))
	}

	// The right identity, the system disk: refused for what stands on it.
	job, attempts = wipe(map[string]any{
		"expected_by_id": system.ByID, "expected_serial": system.Serial, "expected_wwn": system.WWN,
	})
	if job.State == "succeeded" {
		t.Fatalf("the host wiped its own system disk %s", system.Path)
	}
	if code := attempts[len(attempts)-1].ErrorCode; code != "disk_in_use" {
		t.Errorf("the system disk was refused as %s, want disk_in_use: %s", code, lastMessage(attempts))
	}

	// The system disk is still there with everything on it.
	if after := systemDisk(t, identityDevices(t, h, host.ID)); !after.HasMountedChildren {
		t.Errorf("the system disk lost what stood on it: %+v", after)
	}
}

// TestDestructiveOperationWithoutAStableIdentityIsRefused checks that an
// order naming the device by its serial and size alone does not reach the
// disk: the panel refuses it at the door, or the host refuses it with
// stable_identity_required - and either way nothing runs.
func TestDestructiveOperationWithoutAStableIdentityIsRefused(t *testing.T) {
	h := newHarness(t)
	host := h.hostByFamily("debian")
	system := systemDisk(t, identityDevices(t, h, host.ID))

	body := map[string]any{
		"action": "disk.wipe", "reason": identityReason,
		"target_confirmation": host.Hostname,
		"payload": map[string]any{"storage": map[string]any{
			"device": system.Path, "expected_serial": system.Serial, "expected_size_bytes": 1024}},
	}
	response, raw := h.request(http.MethodPost, "/api/v1/hosts/"+host.ID+"/operations", body, nil)
	switch response.StatusCode {
	case http.StatusBadRequest:
		// The panel does not create an order without a stable identity.
		return
	case http.StatusCreated:
	default:
		t.Fatalf("creating the order: status %d: %s", response.StatusCode, truncate(raw, 300))
	}
	var job jobView
	if err := json.Unmarshal(raw, &job); err != nil {
		t.Fatalf("the created order: %v", err)
	}
	h.approve(job.ID, job.PayloadHash)
	second := h.withToken(h.createPrincipal("second-person-"+job.ID[:8],
		[]map[string]string{{"role": "platform_admin", "scope": "*"}}))
	second.approve(job.ID, job.PayloadHash)
	final := h.awaitTerminal(job.ID, 2*time.Minute)
	attempts := h.attempts(job.ID)
	if final.State == "succeeded" {
		t.Fatalf("the host wiped %s on a serial and a size alone", system.Path)
	}
	if code := attempts[len(attempts)-1].ErrorCode; code != "stable_identity_required" {
		t.Errorf("refused as %s, want stable_identity_required: %s", code, lastMessage(attempts))
	}
}

// TestMountPlanCarriesTheFstabRevision checks that a mount plan is bound
// to the fstab it was computed against and to the state of the mount
// point: the fingerprint covers both, so an fstab edited after the plan
// makes the change stale. The plan is computed for a target that does not
// exist, so nothing is mounted.
func TestMountPlanCarriesTheFstabRevision(t *testing.T) {
	h := newHarness(t)
	host := h.hostByFamily("debian")
	var root identityDeviceView
	for _, device := range identityDevices(t, h, host.ID) {
		for _, point := range device.Mountpoints {
			if point == "/" {
				root = device
			}
		}
	}
	if root.UUID == "" {
		t.Skip("the root filesystem has no UUID")
	}

	target := "/mnt/flotestro-identity-" + root.UUID[:8]
	job, attempts := h.runOperation(host.ID, map[string]any{
		"action": "storage.plan", "reason": identityReason,
		"payload": map[string]any{"storage": map[string]any{
			"source": "UUID=" + root.UUID, "target": target, "fs_type": "ext4", "persist": true}},
	}, 2*time.Minute)
	if job.State != "succeeded" {
		t.Fatalf("planning the mount: state = %s, %s", job.State, lastMessage(attempts))
	}
	var plan struct {
		Action        string `json:"action"`
		SourceUUID    string `json:"source_uuid"`
		FstabRevision string `json:"fstab_revision"`
		TargetState   string `json:"target_state"`
		PlanHash      string `json:"plan_hash"`
		Refusal       string `json:"refusal"`
	}
	if err := json.Unmarshal(storagePlanDetail(t, h, job.ID, "mount_plan"), &plan); err != nil {
		t.Fatalf("mount plan: %v", err)
	}
	if plan.SourceUUID != root.UUID {
		t.Errorf("the plan does not name the source by UUID: %+v", plan)
	}
	if !hexDigest.MatchString(plan.FstabRevision) {
		t.Errorf("the plan carries no fstab revision: %+v", plan)
	}
	if plan.TargetState != "missing" {
		t.Errorf("the plan does not say the mount point is missing: %+v", plan)
	}
	if plan.PlanHash == "" {
		t.Errorf("the plan has no fingerprint: %+v", plan)
	}
	// A change sent with a fingerprint of another plan is stale: the host
	// compares before touching fstab. The target does not exist and nothing
	// is written.
	change, changeAttempts := h.runOperation(host.ID, map[string]any{
		"action": "mount.ensure", "reason": identityReason,
		"payload": map[string]any{"storage": map[string]any{
			"source": "UUID=" + root.UUID, "target": target, "fs_type": "ext4", "persist": true,
			"plan_hash": strings.Repeat("0", 64)}},
	}, 2*time.Minute)
	if change.State == "succeeded" {
		t.Fatalf("the host mounted %s on a stale plan", target)
	}
	if code := changeAttempts[len(changeAttempts)-1].ErrorCode; code != "stale_plan" {
		t.Errorf("a stale mount plan was refused as %s, want stale_plan: %s", code, lastMessage(changeAttempts))
	}
}
