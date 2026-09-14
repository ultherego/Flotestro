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
	// UFW is the header of "ufw status" where ufw is installed: whether it
	// holds the rules, and if not, what the panel does instead.
	UFW *struct {
		Active   bool   `json:"active"`
		Defaults string `json:"defaults"`
		Reason   string `json:"reason"`
	} `json:"ufw"`
	Writable          bool   `json:"writable"`
	ReadOnlyReason    string `json:"read_only_reason"`
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

// firewallPlanView is the plan a host computed for a rule, as the job
// result carries it.
type firewallPlanView struct {
	RuleID   string   `json:"rule_id"`
	Action   string   `json:"action"`
	Refusal  string   `json:"refusal"`
	Adapter  string   `json:"adapter"`
	Commands []string `json:"commands"`
	PlanHash string   `json:"plan_hash"`
}

// firewallPlan orders a plan of a rule change and reads what the host
// computed. A plan touches nothing on the host.
func firewallPlan(t *testing.T, h *harness, hostID string, rule map[string]any) firewallPlanView {
	t.Helper()
	job, attempts := h.runOperation(hostID, map[string]any{
		"action": "firewall.plan", "reason": firewallReason,
		"payload": map[string]any{"firewall": rule},
	}, 2*time.Minute)
	if job.State != "succeeded" {
		t.Fatalf("planning the rule: state = %s, %s", job.State, lastMessage(attempts))
	}
	var response struct {
		Items []struct {
			Detail struct {
				Kind string          `json:"kind"`
				Plan json.RawMessage `json:"plan"`
			} `json:"detail"`
		} `json:"items"`
	}
	h.get("/api/v1/jobs/"+job.ID+"/attempts", &response)
	for i := len(response.Items) - 1; i >= 0; i-- {
		if response.Items[i].Detail.Kind != "firewall_plan" {
			continue
		}
		var plan firewallPlanView
		if err := json.Unmarshal(response.Items[i].Detail.Plan, &plan); err != nil {
			t.Fatalf("firewall plan: %v", err)
		}
		return plan
	}
	t.Fatalf("the job %s carries no firewall plan", job.ID)
	return firewallPlanView{}
}

// hostCapabilityOf returns the named capability of a host, or nil.
func hostCapabilityOf(host hostView, name string) *hostCapability {
	for i := range host.Capabilities {
		if host.Capabilities[i].Name == name {
			return &host.Capabilities[i]
		}
	}
	return nil
}

// TestUFWHostKeepsOwnershipInComments finds the host with ufw installed -
// the Ubuntu host of the lab - and checks the adapter the way the doctrine
// wants it. An active ufw holds the rules: the plan lists the ufw commands
// the change will run, the rule goes in with the panel's marker in its
// comment, the change is confirmed by connectivity, and the rule comes out
// again by the same marker. An inactive ufw holds nothing: the host is
// then to say so and name what the panel writes through instead - or why
// nothing - and the lifecycle is skipped, because enabling ufw is the
// operator's decision, not the test's.
func TestUFWHostKeepsOwnershipInComments(t *testing.T) {
	h := newHarness(t)

	var host hostView
	var state firewallSnapshot
	found := false
	for _, candidate := range h.hosts() {
		if candidate.ConnectionState != "online" {
			continue
		}
		capability := hostCapabilityOf(candidate, "firewall")
		if capability == nil {
			continue
		}
		if !capability.Available {
			// A host with an inactive ufw and no nft has no firewall module to
			// read: the capability itself carries the reason, and the host tab
			// shows it instead of an empty rule list.
			if strings.Contains(capability.Reason, "ufw") {
				if !capability.ReadOnly || !strings.Contains(capability.Reason, "inactive") {
					t.Errorf("host %s: an inactive ufw without nft is not read-only with a reason: %+v",
						candidate.Hostname, capability)
				}
				t.Skipf("host %s: %s", candidate.Hostname, capability.Reason)
			}
			continue
		}
		snapshot := hostFirewallSnapshot(t, h, candidate.ID)
		if snapshot.UFW != nil {
			host, state, found = candidate, snapshot, true
			break
		}
	}
	if !found {
		t.Skip("no connected host has ufw installed")
	}

	capability := hostCapabilityOf(host, "firewall")
	if !state.UFW.Active {
		// An installed but inactive ufw holds nothing. The host says so next
		// to the adapter, and the adapter is the panel's own table - or, on
		// a host without nft, nothing, with the reason.
		if state.Adapter == "ufw" || capability.Features["ufw"] {
			t.Errorf("an inactive ufw was taken for the adapter: %q, features %v", state.Adapter, capability.Features)
		}
		if !strings.Contains(state.UFW.Reason, "inactive") {
			t.Errorf("an inactive ufw without a reason: %+v", state.UFW)
		}
		if state.Writable {
			if state.Adapter != "nftables" || state.ReadOnlyReason != "" {
				t.Errorf("a writable host with an inactive ufw: adapter %q, reason %q", state.Adapter, state.ReadOnlyReason)
			}
		} else if !strings.Contains(state.ReadOnlyReason, "ufw") || !strings.Contains(state.ReadOnlyReason, "inactive") {
			t.Errorf("a read-only host with an inactive ufw does not say why: %q", state.ReadOnlyReason)
		}
		t.Skipf("host %s: %s", host.Hostname, state.UFW.Reason)
	}

	if state.Adapter != "ufw" || !state.Writable || !capability.Features["ufw"] || !capability.Features["write"] {
		t.Fatalf("an active ufw is not the adapter: %q, writable %v, features %v",
			state.Adapter, state.Writable, capability.Features)
	}
	if state.UFW.Defaults == "" {
		t.Error("the default policy of ufw is missing: no rule list says what a packet meets when nothing matches")
	}

	const name = "ufw-lifecycle-test"
	const marker = "flotestro:" + name
	rule := map[string]any{
		"rule_id": name, "chain": "input", "action": "drop",
		"protocol": "tcp", "ports": []string{"25"},
		"sources": []string{"10.10.0.0/16"}, "comment": "test",
	}
	t.Cleanup(func() {
		h.runOperation(host.ID, map[string]any{
			"action": "firewall.rule.remove", "reason": firewallReason,
			"payload": map[string]any{"firewall": map[string]any{
				"rule_id": name, "rollback_seconds": 60}},
		}, 2*time.Minute)
	})

	// The plan names the adapter and lists the ufw commands as the operator
	// would type them: ufw is driven by its command line, and that is what
	// the operator consents to.
	plan := firewallPlan(t, h, host.ID, rule)
	if plan.Refusal != "" {
		t.Fatalf("the plan refused the rule: %s", plan.Refusal)
	}
	if plan.Adapter != "ufw" || plan.Action != "create" || len(plan.Commands) != 1 {
		t.Fatalf("plan = %+v", plan)
	}
	if !strings.HasPrefix(plan.Commands[0], "/usr/sbin/ufw ") || !strings.Contains(plan.Commands[0], "deny in") ||
		!strings.Contains(plan.Commands[0], "port 25") || !strings.Contains(plan.Commands[0], marker) {
		t.Errorf("plan command = %q", plan.Commands[0])
	}

	change := map[string]any{"rollback_seconds": 60, "expected_hash": state.Hash}
	for key, value := range rule {
		change[key] = value
	}
	job, attempts := h.runOperation(host.ID, map[string]any{
		"action": "firewall.rule.ensure", "reason": firewallReason,
		"payload": map[string]any{"firewall": change},
	}, 3*time.Minute)
	if job.State != "succeeded" {
		t.Fatalf("creating the rule: state = %s, %s", job.State, lastMessage(attempts))
	}
	if !strings.Contains(lastMessage(attempts), "the rollback was disarmed") {
		t.Errorf("change without a connectivity confirmation: %s", lastMessage(attempts))
	}

	// The rule is read back the way ufw would delete it, with the panel's
	// marker at the front of the comment: the marker is the only durable
	// sign of ownership, because ufw numbers shift with every deletion.
	after := panelRule(t, h, host.ID, name)
	if after.Table != "ufw" || after.Chain != "input" {
		t.Errorf("the rule landed outside ufw: %+v", after)
	}
	if !strings.HasPrefix(after.Comment, marker) {
		t.Errorf("the rule does not carry the marker %q: %+v", marker, after)
	}
	if !strings.Contains(after.Text, "port 25") || !strings.Contains(after.Text, "10.10.0.0/16") ||
		strings.Contains(after.Text, "comment") {
		t.Errorf("rule text = %q", after.Text)
	}

	// The removal plan lists the deletion by the same specification the
	// rule was added with, marker included.
	removal := firewallPlan(t, h, host.ID, map[string]any{"rule_id": name})
	if removal.Action != "remove" || len(removal.Commands) != 1 ||
		!strings.Contains(removal.Commands[0], " delete ") || !strings.Contains(removal.Commands[0], marker) {
		t.Errorf("removal plan = %+v", removal)
	}

	job, attempts = h.runOperation(host.ID, map[string]any{
		"action": "firewall.rule.remove", "reason": firewallReason,
		"payload": map[string]any{"firewall": map[string]any{
			"rule_id": name, "rollback_seconds": 60}},
	}, 3*time.Minute)
	if job.State != "succeeded" {
		t.Fatalf("removing the rule: state = %s, %s", job.State, lastMessage(attempts))
	}
	for _, entry := range hostFirewallSnapshot(t, h, host.ID).Rules {
		if strings.HasPrefix(entry.Comment, marker) {
			t.Errorf("the rule is still on the host after the removal: %+v", entry)
		}
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
