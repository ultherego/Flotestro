//go:build integration

package integration

import (
	"encoding/json"
	"net/http"
	"testing"
	"time"
)

type inhibitorView struct {
	Who  string `json:"who"`
	Why  string `json:"why"`
	Mode string `json:"mode"`
}

type bootView struct {
	Index      int    `json:"index"`
	BootID     string `json:"boot_id"`
	FirstEntry string `json:"first_entry"`
}

type powerSnapshot struct {
	BootID            string          `json:"boot_id"`
	BootedAt          string          `json:"booted_at"`
	UptimeSeconds     *float64        `json:"uptime_seconds"`
	RunningKernel     string          `json:"running_kernel"`
	RebootRequired    *bool           `json:"reboot_required"`
	RebootReasons     []string        `json:"reboot_reasons"`
	Inhibitors        []inhibitorView `json:"inhibitors"`
	InhibitorsKnown   bool            `json:"inhibitors_known"`
	LastBoots         []bootView      `json:"last_boots"`
	UnavailableReason string          `json:"unavailable_reason"`
}

const powerReason = "integration test of the power module"

// TestPowerShowsTheHostBoot checks the facts every restart operation stands
// on: the boot identifier, the uptime and what holds a shutdown back.
func TestPowerShowsTheHostBoot(t *testing.T) {
	h := newHarness(t)

	for _, family := range []string{"debian", "rhel"} {
		t.Run(family, func(t *testing.T) {
			host := h.hostByFamily(family)
			state := hostPowerSnapshot(t, h, host.ID)
			if state.UnavailableReason != "" {
				t.Fatalf("the boot state was not read: %s", state.UnavailableReason)
			}
			if state.BootID == "" || state.BootedAt == "" {
				t.Errorf("the host did not report its boot: %+v", state.BootID)
			}
			// A host running for zero seconds does not exist: a missing read
			// is to be empty, not equal to zero.
			if state.UptimeSeconds == nil || *state.UptimeSeconds <= 0 {
				t.Errorf("uptime = %v", state.UptimeSeconds)
			}
			if state.RunningKernel == "" {
				t.Error("the host did not report the running kernel")
			}
			if state.RebootRequired == nil {
				t.Error("the need for a reboot is undetermined")
			}
			// No inhibitors and unread inhibitors are two different answers.
			if !state.InhibitorsKnown {
				t.Error("the shutdown inhibitors were not read")
			}
			if len(state.LastBoots) == 0 {
				t.Error("the host reported no boot from the journal at all")
			}
			// The current boot has index zero and the same identifier the
			// host gives as its boot_id.
			for _, boot := range state.LastBoots {
				if boot.Index != 0 {
					continue
				}
				if withoutDashes(boot.BootID) != withoutDashes(state.BootID) {
					t.Errorf("current boot = %q, host boot_id = %q", boot.BootID, state.BootID)
				}
			}
		})
	}
}

// TestShutdownRequiresAReasonAndTheTargetName guards the gates of an
// operation the panel cannot undo: nobody will power this host on remotely.
func TestShutdownRequiresAReasonAndTheTargetName(t *testing.T) {
	h := newHarness(t)
	host := h.hostByFamily("debian")

	// Without the target name: a click is not a sufficient decision.
	h.do(http.MethodPost, "/api/v1/hosts/"+host.ID+"/operations",
		map[string]any{"action": "system.shutdown", "reason": powerReason,
			"payload": map[string]any{"power": map[string]any{"reason": powerReason}}},
		nil, http.StatusBadRequest)

	// Without a reason in the payload: the audit trail is the only thing
	// that remains after this operation.
	h.do(http.MethodPost, "/api/v1/hosts/"+host.ID+"/operations",
		map[string]any{"action": "system.shutdown", "reason": powerReason,
			"target_confirmation": host.Hostname,
			"payload":             map[string]any{"power": map[string]any{"reason": "because"}}},
		nil, http.StatusBadRequest)

	// A mode outside the list does not reach the host.
	h.do(http.MethodPost, "/api/v1/hosts/"+host.ID+"/operations",
		map[string]any{"action": "system.shutdown", "reason": powerReason,
			"target_confirmation": host.Hostname,
			"payload": map[string]any{"power": map[string]any{
				"mode": "kexec", "reason": powerReason}}},
		nil, http.StatusBadRequest)
}

// TestIrreversibleOperationDoesNotRunInBulk guards the campaign boundary:
// the target name is the only gate of an operation with no way back, and a
// campaign has no single target to type in.
func TestIrreversibleOperationDoesNotRunInBulk(t *testing.T) {
	h := newHarness(t)
	host := h.hostByFamily("debian")

	for _, action := range []struct {
		kind    string
		payload map[string]any
	}{
		{"system.shutdown", map[string]any{"power": map[string]any{"reason": powerReason}}},
		{"disk.wipe", map[string]any{"storage": map[string]any{"device": "/dev/sdz"}}},
	} {
		t.Run(action.kind, func(t *testing.T) {
			h.do(http.MethodPost, "/api/v1/campaigns", map[string]any{
				"name": "irreversible operation attempt", "action": action.kind,
				"payload":  action.payload,
				"selector": map[string]any{"host_ids": []string{host.ID}},
			}, nil, http.StatusBadRequest)
		})
	}
}

// TestMaintenanceWindowSkipsCampaigns checks what the maintenance window
// exists for: a campaign is to skip a host somebody is working on.
func TestMaintenanceWindowSkipsCampaigns(t *testing.T) {
	h := newHarness(t)
	host := h.hostByFamily("debian")

	// A window without an end and a window without a reason are not
	// windows.
	h.do(http.MethodPost, "/api/v1/hosts/"+host.ID+"/maintenance",
		map[string]any{"reason": "disk replacement"}, nil, http.StatusBadRequest)
	h.do(http.MethodPost, "/api/v1/hosts/"+host.ID+"/maintenance",
		map[string]any{"duration_minutes": 30}, nil, http.StatusBadRequest)
	h.do(http.MethodPost, "/api/v1/hosts/"+host.ID+"/maintenance",
		map[string]any{"duration_minutes": 60 * 24 * 60, "reason": "disk replacement"},
		nil, http.StatusBadRequest)

	t.Cleanup(func() {
		h.do(http.MethodPost, "/api/v1/hosts/"+host.ID+"/maintenance",
			map[string]any{"clear": true}, nil, http.StatusOK)
	})

	var inWindow hostView
	h.do(http.MethodPost, "/api/v1/hosts/"+host.ID+"/maintenance",
		map[string]any{"duration_minutes": 30, "reason": powerReason}, &inWindow, http.StatusOK)
	if inWindow.Maintenance == nil {
		t.Fatal("the host does not report the window after it was opened")
	}
	if inWindow.Maintenance.Reason != powerReason || inWindow.Maintenance.SetBy == "" {
		t.Errorf("window = %+v", inWindow.Maintenance)
	}
	if !inWindow.Maintenance.Until.After(time.Now()) {
		t.Errorf("the window ends in the past: %v", inWindow.Maintenance.Until)
	}

	// A campaign covering only a host in a window has nothing to do.
	h.do(http.MethodPost, "/api/v1/campaigns", map[string]any{
		"name": "maintenance window attempt", "action": "unit.restart",
		"payload":  map[string]any{"unit": map[string]any{"unit": "cron.service"}},
		"selector": map[string]any{"host_ids": []string{host.ID}},
	}, nil, http.StatusBadRequest)

	// A closed window stops applying at once, together with its reason.
	var afterClosing hostView
	h.do(http.MethodPost, "/api/v1/hosts/"+host.ID+"/maintenance",
		map[string]any{"clear": true}, &afterClosing, http.StatusOK)
	if afterClosing.Maintenance != nil {
		t.Errorf("window after closing = %+v", afterClosing.Maintenance)
	}
}

// withoutDashes strips the dashes from a boot identifier. The journal writes
// it without them, /proc with them - it is the same identifier.
func withoutDashes(id string) string {
	result := make([]byte, 0, len(id))
	for i := 0; i < len(id); i++ {
		if id[i] != '-' {
			result = append(result, id[i])
		}
	}
	return string(result)
}

func hostPowerSnapshot(t *testing.T, h *harness, hostID string) powerSnapshot {
	t.Helper()
	var fragment inventoryFragment
	h.do(http.MethodGet, "/api/v1/hosts/"+hostID+"/inventory/power", nil, &fragment, http.StatusOK)
	var state powerSnapshot
	if err := json.Unmarshal(fragment.Payload, &state); err != nil {
		t.Fatalf("power snapshot: %v", err)
	}
	return state
}
