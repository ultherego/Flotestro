//go:build integration

package integration

import (
	"encoding/json"
	"net/http"
	"strings"
	"testing"
	"time"
)

// The reasons an nftables host reports about its own persistent state.
const (
	nftRuleNotPersisted  = "nft_rule_not_persisted"
	nftRuleNotLoaded     = "nft_rule_not_loaded"
	nftRuleNotComparable = "nft_rule_not_comparable"
	nftSourceUnreadable  = "nft_persistent_source_unreadable"
	nftSourceUnknown     = "nft_persistent_source_unknown"
	nftSourceInactive    = "nft_persistent_source_inactive"
)

// nftDriftView is one difference between the running ruleset and the file the
// host restores it from.
type nftDriftView struct {
	Reason string `json:"reason"`
	Rule   string `json:"rule"`
	RuleID string `json:"rule_id"`
	Family string `json:"family"`
	Table  string `json:"table"`
	Chain  string `json:"chain"`
	Detail string `json:"detail"`
}

// nftPersistenceView is what the host says restores its ruleset at boot.
type nftPersistenceView struct {
	Unit struct {
		Name      string   `json:"name"`
		LoadState string   `json:"load_state"`
		BootState string   `json:"boot_state"`
		Files     []string `json:"files"`
	} `json:"unit"`
	Files    []string `json:"files"`
	Compared bool     `json:"compared"`
	Reason   string   `json:"reason"`
	Detail   string   `json:"detail"`
}

type nftFirewallView struct {
	Adapter           string              `json:"adapter"`
	UnavailableReason string              `json:"unavailable_reason"`
	Persistent        *nftPersistenceView `json:"persistent"`
	Drift             []nftDriftView      `json:"drift"`
}

// nftSnapshotOf reads the firewall fragment of a host. It changes nothing: the
// lab's Debian and Ubuntu agents filter with nftables, and a test that touched
func nftSnapshotOf(t *testing.T, h *harness, hostID string) nftFirewallView {
	t.Helper()
	h.runOperation(hostID, map[string]any{
		"action": "inventory.refresh", "reason": firewallReason,
		"payload": map[string]any{"inventory": map[string]any{"modules": []string{"firewall"}}},
	}, 2*time.Minute)

	var fragment inventoryFragment
	h.do(http.MethodGet, "/api/v1/hosts/"+hostID+"/inventory/firewall", nil, &fragment, http.StatusOK)
	var state nftFirewallView
	if err := json.Unmarshal(fragment.Payload, &state); err != nil {
		t.Fatalf("firewall snapshot: %v", err)
	}
	return state
}

// nftPersistentReasons lists the codes the persistent comparison may report.
func nftPersistentReasons() map[string]bool {
	return map[string]bool{
		nftRuleNotPersisted: true, nftRuleNotLoaded: true, nftRuleNotComparable: true,
		nftSourceUnreadable: true, nftSourceUnknown: true, nftSourceInactive: true,
	}
}

// TestNftablesHostComparesItsPersistentState is the gap of chapter 14.4 on the
// nftables adapter: the snapshot used to be the running ruleset and nothing
func TestNftablesHostComparesItsPersistentState(t *testing.T) {
	h := newHarness(t)

	checked := 0
	for _, host := range h.hosts() {
		if host.ConnectionState != "online" {
			continue
		}
		capability := hostCapabilityOf(host, "firewall")
		if capability == nil || !capability.Available {
			continue
		}
		state := nftSnapshotOf(t, h, host.ID)
		if state.Adapter != "nftables" || state.UnavailableReason != "" {
			continue
		}
		checked++

		t.Run(host.Hostname, func(t *testing.T) {
			if state.Persistent == nil {
				t.Fatal("the host reports the running rules and nothing about what restores them at boot: " +
					"a rule gone after the next reboot reads as in force today")
			}
			persistent := *state.Persistent
			if persistent.Unit.Name == "" {
				t.Error("the host does not name the unit its ruleset would be restored by")
			}
			// Not compared is unknown, and unknown carries its reason; silence
			// here would be the pass the chapter refuses.
			if !persistent.Compared {
				if !nftPersistentReasons()[persistent.Reason] || persistent.Detail == "" {
					t.Fatalf("a comparison that did not happen without a typed reason: %+v", persistent)
				}
				if !nftDriftHas(state.Drift, persistent.Reason) {
					t.Errorf("the reason %q is not among the reported drift: %+v", persistent.Reason, state.Drift)
				}
				return
			}
			if len(persistent.Files) == 0 {
				t.Error("the comparison happened against no file at all")
			}
			// The path is the host's own: it is read from the unit, and the
			// distributions do not agree on it.
			for _, file := range persistent.Files {
				if !strings.HasPrefix(file, "/") {
					t.Errorf("the boot source is not an absolute path on the host: %q", file)
				}
			}
			for _, entry := range state.Drift {
				if entry.Reason == "" || entry.Detail == "" {
					t.Errorf("a difference without a reason or without a meaning: %+v", entry)
				}
			}
		})
	}
	if checked == 0 {
		t.Skip("no connected host holds its rules in nftables alone")
	}
}

// TestNftDriftReasonsHaveAdvice checks that every reason a host can report is
// a code the panel can explain: a code without advice is a dead end.
func TestNftDriftReasonsHaveAdvice(t *testing.T) {
	h := newHarness(t)

	var guide struct {
		Items []struct {
			Code    string `json:"code"`
			Meaning string `json:"meaning"`
			Action  string `json:"action"`
		} `json:"items"`
	}
	h.get("/api/v1/errors", &guide)

	explained := map[string]bool{}
	for _, item := range guide.Items {
		if item.Meaning != "" && item.Action != "" {
			explained[item.Code] = true
		}
	}
	for reason := range nftPersistentReasons() {
		if !explained[reason] {
			t.Errorf("the error guide does not explain %s", reason)
		}
	}
}

func nftDriftHas(drift []nftDriftView, reason string) bool {
	for _, entry := range drift {
		if entry.Reason == reason {
			return true
		}
	}
	return false
}
