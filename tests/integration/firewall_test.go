//go:build integration

package integration

import (
	"encoding/json"
	"net/http"
	"strings"
	"testing"
	"time"
)

type ruleView struct {
	Table   string  `json:"table"`
	Chain   string  `json:"chain"`
	Text    string  `json:"text"`
	Source  string  `json:"source"`
	Comment string  `json:"comment"`
	Packets *uint64 `json:"packets"`
}

type firewallSnapshot struct {
	Adapter string `json:"adapter"`
	Hash    string `json:"hash"`
	Tables  []struct {
		Name   string `json:"name"`
		Source string `json:"source"`
		Owner  string `json:"owner"`
	} `json:"tables"`
	Rules []ruleView `json:"rules"`
	Zones []struct {
		Name   string   `json:"name"`
		Active bool     `json:"active"`
		Ports  []string `json:"ports"`
	} `json:"zones"`
	Writable          bool   `json:"writable"`
	UnavailableReason string `json:"unavailable_reason"`
}

const firewallReason = "integration test of the firewall module"

// TestFirewallTellsForeignTablesApart checks the ownership boundary. The
// docker and firewalld tables are rewritten without the panel, so a rule in
// them is neither ours nor persistent - and the operator is to see that
// before starting to fix it.
func TestFirewallTellsForeignTablesApart(t *testing.T) {
	h := newHarness(t)

	for _, family := range []string{"debian", "rhel"} {
		t.Run(family, func(t *testing.T) {
			host := h.hostByFamily(family)
			state := hostFirewallSnapshot(t, h, host.ID)
			if state.UnavailableReason != "" {
				t.Fatalf("the firewall state was not read: %s", state.UnavailableReason)
			}
			if state.Adapter == "" || state.Hash == "" {
				t.Fatalf("adapter = %q, fingerprint = %q", state.Adapter, state.Hash)
			}
			var foreign int
			for _, table := range state.Tables {
				if table.Source == "foreign" {
					foreign++
					// A foreign table is to say whom it belongs to.
					if table.Owner == "" {
						t.Errorf("foreign table without an owner: %+v", table)
					}
				}
			}
			if foreign == 0 {
				t.Error("the host recognised no foreign table")
			}
		})
	}
}

// TestRuleCuttingOffThePanelIsRejected guards the one rule that must not be
// lost. Without the management channel the host stops answering and there
// is nothing to undo the change with.
func TestRuleCuttingOffThePanelIsRejected(t *testing.T) {
	h := newHarness(t)
	host := h.hostByFamily("debian")

	job, attempts := h.runOperation(host.ID, map[string]any{
		"action": "firewall.rule.ensure", "reason": firewallReason,
		"payload": map[string]any{"firewall": map[string]any{
			"rule_id": "panel-block-test", "chain": "input", "action": "drop",
			"protocol": "tcp", "ports": []string{"8000-9000"}, "rollback_seconds": 60}},
	}, 2*time.Minute)
	if job.State == "succeeded" {
		t.Fatal("the panel accepted a rule cutting itself off")
	}
	message := lastMessage(attempts)
	if !strings.Contains(message, "management channel") && !strings.Contains(message, "talks to the panel") {
		t.Errorf("refusal without a reason: %q", message)
	}
}

// TestPanelRuleLifecycle walks the whole path of a rule: creation,
// connectivity confirmation and removal. After the test the host is left
// without panel rules, as before it.
func TestPanelRuleLifecycle(t *testing.T) {
	h := newHarness(t)
	host := h.hostByFamily("debian")
	state := hostFirewallSnapshot(t, h, host.ID)
	if !state.Writable {
		t.Skip("the host does not allow changing the firewall")
	}
	const name = "lifecycle-test"

	t.Cleanup(func() {
		h.runOperation(host.ID, map[string]any{
			"action": "firewall.rule.remove", "reason": firewallReason,
			"payload": map[string]any{"firewall": map[string]any{
				"rule_id": name, "rollback_seconds": 60}},
		}, 2*time.Minute)
	})

	job, attempts := h.runOperation(host.ID, map[string]any{
		"action": "firewall.rule.ensure", "reason": firewallReason,
		"payload": map[string]any{"firewall": map[string]any{
			"rule_id": name, "chain": "input", "action": "drop",
			"protocol": "tcp", "ports": []string{"25"},
			"sources": []string{"10.10.0.0/16"}, "comment": "test",
			"rollback_seconds": 60, "expected_hash": state.Hash}},
	}, 3*time.Minute)
	if job.State != "succeeded" {
		t.Fatalf("creating the rule: state = %s, %s", job.State, lastMessage(attempts))
	}
	// A change without confirmed connectivity would leave an armed timer,
	// which would shortly undo a working change.
	if !strings.Contains(lastMessage(attempts), "the rollback was disarmed") {
		t.Errorf("change without a connectivity confirmation: %s", lastMessage(attempts))
	}

	after := panelRule(t, h, host.ID, name)
	if after.Table != "flotestro" || after.Chain != "input" {
		t.Errorf("the rule landed outside the panel table: %+v", after)
	}
	if !strings.Contains(after.Text, "tcp dport 25") || !strings.Contains(after.Text, "drop") {
		t.Errorf("rule text = %q", after.Text)
	}
	// The counter is part of the rule: without it there is no telling
	// whether anything went through it.
	if after.Packets == nil {
		t.Error("panel rule without a counter")
	}

	// The ruleset fingerprint changed together with the rule, so an order
	// against the old fingerprint is to be rejected.
	job, attempts = h.runOperation(host.ID, map[string]any{
		"action": "firewall.rule.ensure", "reason": firewallReason,
		"payload": map[string]any{"firewall": map[string]any{
			"rule_id": "stale-test", "chain": "input", "action": "drop",
			"protocol": "tcp", "ports": []string{"26"},
			"sources":          []string{"10.10.0.0/16"},
			"rollback_seconds": 60, "expected_hash": state.Hash}},
	}, 2*time.Minute)
	if job.State == "succeeded" {
		t.Errorf("a change against a stale ruleset was accepted: %s", lastMessage(attempts))
	}
}

// TestBadRuleDoesNotReachTheHost checks that a rule the host would not
// understand is rejected when ordered.
func TestBadRuleDoesNotReachTheHost(t *testing.T) {
	h := newHarness(t)
	host := h.hostByFamily("debian")

	cases := []struct {
		change map[string]any
		why    string
	}{
		{map[string]any{"rule_id": "Bad Name", "chain": "input", "action": "drop",
			"protocol": "tcp", "ports": []string{"25"}}, "name with whitespace"},
		{map[string]any{"rule_id": "test", "chain": "POSTROUTING", "action": "drop",
			"protocol": "tcp", "ports": []string{"25"}}, "foreign chain"},
		{map[string]any{"rule_id": "test", "chain": "input", "action": "log",
			"protocol": "tcp", "ports": []string{"25"}}, "unknown action"},
		{map[string]any{"rule_id": "test", "chain": "input", "action": "drop"},
			"rule without any match"},
		{map[string]any{"rule_id": "test", "chain": "input", "action": "drop",
			"protocol": "tcp", "ports": []string{"25"}, "comment": `x" accept #`},
			"comment with a quote"},
	}
	for _, tc := range cases {
		t.Run(tc.why, func(t *testing.T) {
			h.do(http.MethodPost, "/api/v1/hosts/"+host.ID+"/operations",
				map[string]any{"action": "firewall.rule.ensure", "reason": firewallReason,
					"payload": map[string]any{"firewall": tc.change}},
				nil, http.StatusBadRequest)
		})
	}
}

// TestFirewalldZonesAreASeparateModel checks that a host with firewalld
// describes access with zones, and that a zone operation is persistent and
// reloaded.
func TestFirewalldZonesAreASeparateModel(t *testing.T) {
	h := newHarness(t)
	host := h.hostByFamily("rhel")
	state := hostFirewallSnapshot(t, h, host.ID)
	if len(state.Zones) == 0 {
		t.Skip("the host has no firewalld")
	}

	var active string
	for _, zone := range state.Zones {
		if zone.Active {
			active = zone.Name
		}
	}
	if active == "" {
		t.Skip("the host has no active zone")
	}

	t.Cleanup(func() {
		h.runOperation(host.ID, map[string]any{
			"action": "firewall.zone.port", "reason": firewallReason,
			"payload": map[string]any{"firewall": map[string]any{
				"zone": active, "ports": []string{"9444"}, "protocol": "tcp", "enable": false}},
		}, 2*time.Minute)
	})

	job, attempts := h.runOperation(host.ID, map[string]any{
		"action": "firewall.zone.port", "reason": firewallReason,
		"payload": map[string]any{"firewall": map[string]any{
			"zone": active, "ports": []string{"9444"}, "protocol": "tcp", "enable": true}},
	}, 2*time.Minute)
	if job.State != "succeeded" {
		t.Fatalf("opening the port: state = %s, %s", job.State, lastMessage(attempts))
	}

	after := hostFirewallSnapshot(t, h, host.ID)
	open := false
	for _, zone := range after.Zones {
		if zone.Name != active {
			continue
		}
		for _, port := range zone.Ports {
			if port == "9444/tcp" {
				open = true
			}
		}
	}
	if !open {
		t.Errorf("the port did not appear in zone %s: %+v", active, after.Zones)
	}
}

func hostFirewallSnapshot(t *testing.T, h *harness, hostID string) firewallSnapshot {
	t.Helper()
	// A rule change is settled by the ruleset fingerprint, so the snapshot
	// must come from this moment, not from the last inventory cycle. The
	// previous test run leaves the host in a state other than the recorded
	// image and the plan bounces off precondition_failed.
	h.runOperation(hostID, map[string]any{
		"action": "inventory.refresh", "reason": firewallReason,
		"payload": map[string]any{"inventory": map[string]any{"modules": []string{"firewall"}}},
	}, 2*time.Minute)

	var fragment inventoryFragment
	h.do(http.MethodGet, "/api/v1/hosts/"+hostID+"/inventory/firewall", nil, &fragment, http.StatusOK)
	var state firewallSnapshot
	if err := json.Unmarshal(fragment.Payload, &state); err != nil {
		t.Fatalf("firewall snapshot: %v", err)
	}
	return state
}

// panelRule waits for a rule in the host inventory: the fragment write is
// asynchronous with respect to the job finishing.
func panelRule(t *testing.T, h *harness, hostID, name string) ruleView {
	t.Helper()
	deadline := time.Now().Add(60 * time.Second)
	for {
		for _, rule := range hostFirewallSnapshot(t, h, hostID).Rules {
			if rule.Source == "managed" && strings.Contains(rule.Comment, name) {
				return rule
			}
		}
		if time.Now().After(deadline) {
			t.Fatalf("rule %s did not appear in the host inventory", name)
		}
		time.Sleep(2 * time.Second)
	}
}
