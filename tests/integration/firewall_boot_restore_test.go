//go:build integration

package integration

import (
	"encoding/json"
	"net/http"
	"testing"
	"time"

	"github.com/ultherego/flotestro/internal/modules/firewall"
	"github.com/ultherego/flotestro/internal/opspec"
)

const bootRestoreReason = "integration test of the restore of the panel's firewall table at boot"

// hostFirewallState reads the firewall snapshot of a host as the agent sent
// it. Nothing here changes a rule or a unit: the lab hosts really filter with
// nftables and the fleet reaches them through it.
func hostFirewallState(t *testing.T, h *harness, hostID string) firewall.Snapshot {
	t.Helper()
	h.runOperation(hostID, map[string]any{
		"action": "inventory.refresh", "reason": bootRestoreReason,
		"payload": map[string]any{"inventory": map[string]any{"modules": []string{"firewall"}}},
	}, 2*time.Minute)

	var fragment inventoryFragment
	h.do(http.MethodGet, "/api/v1/hosts/"+hostID+"/inventory/firewall", nil, &fragment, http.StatusOK)
	var state firewall.Snapshot
	if err := json.Unmarshal(fragment.Payload, &state); err != nil {
		t.Fatalf("firewall snapshot: %v", err)
	}
	return state
}

// TestThePanelsOwnTableIsRestoredAtBoot checks the one thing no boot file of a
// distribution carries. Before this unit existed, every rule the panel applied
// to an nftables host was gone after a restart while the host kept reporting
// itself as filtering with it.
func TestThePanelsOwnTableIsRestoredAtBoot(t *testing.T) {
	h := newHarness(t)

	checked := 0
	for _, host := range h.hosts() {
		if host.ConnectionState != "online" {
			continue
		}
		state := hostFirewallState(t, h, host.ID)
		// firewalld and ufw restore their own rules by construction, and the
		// restore is to leave such a host alone.
		if state.Adapter != firewall.AdapterNftables || state.UnavailableReason != "" {
			continue
		}
		checked++

		if state.Persistent == nil {
			t.Errorf("host %s: the agent does not say what restores its ruleset at boot",
				host.Hostname)
			continue
		}
		restore := state.Persistent.Restore
		if restore.Unit.LoadState != "loaded" {
			// This is the gap itself: an agent from before the unit existed, or a
			// host the package did not install it on.
			t.Errorf("host %s: no unit rebuilds the panel's own table after a reboot (%s: load %q, boot %q)",
				host.Hostname, firewall.BootRestoreUnitName, restore.Unit.LoadState, restore.Unit.BootState)
			continue
		}
		if restore.Unit.BootState != "enabled" {
			t.Errorf("host %s: %s is %q, so it rebuilds nothing at the next boot",
				host.Hostname, firewall.BootRestoreUnitName, restore.Unit.BootState)
		}
		if !restore.InForce() {
			t.Errorf("host %s: the panel's rules are not restored at boot: %s - %s",
				host.Hostname, restore.Reason, restore.Detail)
		}
		// A reason never travels without words, and never without a guide the
		// panel can show beside it.
		if restore.Reason != "" {
			if restore.Detail == "" {
				t.Errorf("host %s: the reason %q comes without a sentence", host.Hostname, restore.Reason)
			}
			if _, known := opspec.ErrorGuideFor(restore.Reason); !known {
				t.Errorf("host %s: the reason %q is in no error guide", host.Hostname, restore.Reason)
			}
		}

		// With the restore in force, the panel's own rules are answered for by
		// it, so no rule of its table is reported as lost at the next reboot.
		for _, entry := range state.Drift {
			if entry.Reason == firewall.DriftNftNotPersisted && entry.Table == firewall.FlotestroTable {
				t.Errorf("host %s: the panel's own rule %q is still reported as gone after a reboot",
					host.Hostname, entry.Rule)
			}
		}
	}
	if checked == 0 {
		t.Skip("no connected host holds its rules in nftables")
	}
}
