//go:build integration

package integration

import (
	"net/http"
	"slices"
	"strings"
	"testing"
	"time"
)

const ruleReason = "integration test of the directory access rules"

// ruleChange mirrors a directory change with the parts of the plan the
// rule tests read.
type ruleChange struct {
	ID          string `json:"id"`
	State       string `json:"state"`
	PayloadHash string `json:"payload_hash"`
	Plan        struct {
		Summary        string   `json:"summary"`
		Steps          []string `json:"steps"`
		ReachableHosts []string `json:"reachable_hosts"`
		AffectedUsers  []string `json:"affected_users"`
		Warnings       []string `json:"warnings"`
		Conflicts      []string `json:"conflicts"`
		Replaces       bool     `json:"replaces"`
	} `json:"plan"`
	ResultMessage string `json:"result_message"`
}

type directoryHostView struct {
	FQDN     string `json:"fqdn"`
	Enrolled bool   `json:"enrolled"`
}

type hbacRuleView struct {
	Name       string   `json:"name"`
	Enabled    bool     `json:"enabled"`
	UserGroups []string `json:"user_groups"`
	Hosts      []string `json:"hosts"`
	Services   []string `json:"services"`
}

type sudoRuleView struct {
	Name        string   `json:"name"`
	Enabled     bool     `json:"enabled"`
	UserGroups  []string `json:"user_groups"`
	Hosts       []string `json:"hosts"`
	Options     []string `json:"options"`
	AllCommands bool     `json:"all_commands"`
	Critical    bool     `json:"critical"`
}

// secondPerson returns a harness acting as a directory administrator other
// than the one who orders the change: a directory change is approved by a
// second person, whatever the environment.
func secondPerson(t *testing.T, h *harness) *harness {
	t.Helper()
	return h.withToken(h.createPrincipal(uniqueSubject("directory-approver"),
		[]map[string]string{{"role": "identity_admin", "scope": "*"}}))
}

// labDirectoryHost picks an enrolled host of the directory for a rule to
// name; a rule naming a host the directory does not know is a conflict.
func labDirectoryHost(t *testing.T, h *harness) string {
	t.Helper()
	var hosts struct {
		Items []directoryHostView `json:"items"`
	}
	h.get("/api/v1/identity/hosts", &hosts)
	for _, host := range hosts.Items {
		if host.Enrolled {
			return host.FQDN
		}
	}
	if len(hosts.Items) > 0 {
		return hosts.Items[0].FQDN
	}
	t.Skip("the directory has no host entries")
	return ""
}

// labDirectoryGroup picks a group of the directory for a rule to name.
func labDirectoryGroup(t *testing.T, h *harness) string {
	t.Helper()
	var groups struct {
		Items []struct {
			Name string `json:"name"`
		} `json:"items"`
	}
	h.get("/api/v1/identity/groups", &groups)
	for _, group := range groups.Items {
		if group.Name == "admins" {
			return group.Name
		}
	}
	if len(groups.Items) > 0 {
		return groups.Items[0].Name
	}
	t.Skip("the directory has no groups")
	return ""
}

// awaitDirectoryChange waits for the executor to finish the change.
func awaitDirectoryChange(t *testing.T, h *harness, id string, timeout time.Duration) ruleChange {
	t.Helper()
	deadline := time.Now().Add(timeout)
	for {
		var change ruleChange
		h.get("/api/v1/identity/changes/"+id, &change)
		switch change.State {
		case "succeeded", "partially_applied", "failed", "canceled":
			return change
		}
		if time.Now().After(deadline) {
			t.Fatalf("the change %s is still %s after %s", id, change.State, timeout)
		}
		time.Sleep(2 * time.Second)
	}
}

// approveAndRun approves a change as the second person and waits for the
// executor. A change of access needs a reason at approval time as well.
func approveAndRun(t *testing.T, h, approver *harness, change ruleChange) ruleChange {
	t.Helper()
	approver.do(http.MethodPost, "/api/v1/identity/changes/"+change.ID+"/approve",
		map[string]any{"payload_hash": change.PayloadHash, "reason": ruleReason}, nil, http.StatusOK)
	return awaitDirectoryChange(t, h, change.ID, 90*time.Second)
}

// removeRule orders and approves the removal of a test rule. It is used
// both as the second half of a test and as the cleanup after a failure, so
// it reports nothing when the rule is already gone.
func removeRule(t *testing.T, h, approver *harness, action, family, name string) {
	t.Helper()
	var change ruleChange
	h.do(http.MethodPost, "/api/v1/identity/changes", map[string]any{
		"action": action, "reason": ruleReason,
		"payload": map[string]any{family: map[string]any{"name": name}},
	}, &change, http.StatusCreated)
	if len(change.Plan.Conflicts) > 0 {
		// The directory has no such rule: nothing to remove.
		h.do(http.MethodPost, "/api/v1/identity/changes/"+change.ID+"/cancel",
			map[string]any{"reason": "nothing to remove"}, nil, 0)
		return
	}
	approveAndRun(t, h, approver, change)
}

// TestDirectoryHBACRuleGoesThroughPlanApprovalAndExecution walks the whole
// path of a managed access rule: the plan with its impact, the approval by a
// second person with a reason, the execution, the rule as the directory
// holds it, and its removal.
func TestDirectoryHBACRuleGoesThroughPlanApprovalAndExecution(t *testing.T) {
	h := newHarness(t)
	if !directoryAvailable(t, h) {
		t.Skip("this installation has no directory connection")
	}
	approver := secondPerson(t, h)
	host := labDirectoryHost(t, h)
	group := labDirectoryGroup(t, h)
	name := "flotestro-test-hbac"
	t.Cleanup(func() { removeRule(t, h, approver, "identity.hbac.rule.remove", "hbac_rule", name) })

	// Without a reason the order is refused before anything is planned.
	h.do(http.MethodPost, "/api/v1/identity/changes", map[string]any{
		"action": "identity.hbac.rule.ensure",
		"payload": map[string]any{"hbac_rule": map[string]any{
			"name": name, "enabled": true, "user_groups": []string{group},
			"hosts": []string{host}, "services": []string{"sshd"},
		}},
	}, nil, http.StatusBadRequest)

	var change ruleChange
	h.do(http.MethodPost, "/api/v1/identity/changes", map[string]any{
		"action": "identity.hbac.rule.ensure", "reason": ruleReason,
		"payload": map[string]any{"hbac_rule": map[string]any{
			"name": name, "description": "created by the integration tests", "enabled": true,
			"user_groups": []string{group}, "hosts": []string{host}, "services": []string{"sshd"},
		}},
	}, &change, http.StatusCreated)
	if len(change.Plan.Conflicts) > 0 {
		t.Fatalf("the plan has conflicts: %v", change.Plan.Conflicts)
	}
	if change.State != "awaiting_approval" {
		t.Fatalf("a rule change was planned as %s", change.State)
	}
	// The impact names the host the rule reaches.
	if !slices.Contains(change.Plan.ReachableHosts, host) {
		t.Fatalf("the plan does not list %s among the reachable hosts: %v", host, change.Plan.ReachableHosts)
	}

	// The person who ordered the change does not approve it.
	h.do(http.MethodPost, "/api/v1/identity/changes/"+change.ID+"/approve",
		map[string]any{"payload_hash": change.PayloadHash, "reason": ruleReason}, nil, http.StatusForbidden)

	final := approveAndRun(t, h, approver, change)
	if final.State != "succeeded" {
		t.Fatalf("the change finished as %s: %s", final.State, final.ResultMessage)
	}

	var rules struct {
		Items []hbacRuleView `json:"items"`
	}
	h.get("/api/v1/identity/hbac-rules", &rules)
	index := slices.IndexFunc(rules.Items, func(rule hbacRuleView) bool { return rule.Name == name })
	if index < 0 {
		t.Fatalf("the directory does not list the rule %s", name)
	}
	rule := rules.Items[index]
	if !rule.Enabled || !slices.Contains(rule.Hosts, host) || !slices.Contains(rule.UserGroups, group) ||
		!slices.Contains(rule.Services, "sshd") {
		t.Fatalf("the rule as the directory holds it: %+v", rule)
	}

	// Ensuring the rule again with a member less shows the diff and applies it.
	h.do(http.MethodPost, "/api/v1/identity/changes", map[string]any{
		"action": "identity.hbac.rule.ensure", "reason": ruleReason,
		"payload": map[string]any{"hbac_rule": map[string]any{
			"name": name, "description": "created by the integration tests", "enabled": false,
			"user_groups": []string{group}, "services": []string{"sshd"},
		}},
	}, &change, http.StatusCreated)
	if !change.Plan.Replaces {
		t.Fatalf("the plan does not say the rule exists: %+v", change.Plan)
	}
	steps := strings.Join(change.Plan.Steps, "\n")
	if !strings.Contains(steps, "removing hosts: "+host) || !strings.Contains(steps, "disabling the rule") {
		t.Fatalf("the plan does not carry the diff:\n%s", steps)
	}
	if final := approveAndRun(t, h, approver, change); final.State != "succeeded" {
		t.Fatalf("the second change finished as %s: %s", final.State, final.ResultMessage)
	}
	h.get("/api/v1/identity/hbac-rules", &rules)
	index = slices.IndexFunc(rules.Items, func(rule hbacRuleView) bool { return rule.Name == name })
	if index < 0 || rules.Items[index].Enabled || len(rules.Items[index].Hosts) != 0 {
		t.Fatalf("the rule after the second change: %+v", rules.Items)
	}

	// The removal, ordered and approved the same way.
	removeRule(t, h, approver, "identity.hbac.rule.remove", "hbac_rule", name)
	h.get("/api/v1/identity/hbac-rules", &rules)
	if slices.ContainsFunc(rules.Items, func(rule hbacRuleView) bool { return rule.Name == name }) {
		t.Fatalf("the rule %s is still in the directory after its removal", name)
	}
}

// TestDirectorySudoRuleWarnsAboutRootWithoutAPassword checks that the
// dangerous shape is named in the plan one warning at a time and that the
// directory marks the resulting rule as critical.
func TestDirectorySudoRuleWarnsAboutRootWithoutAPassword(t *testing.T) {
	h := newHarness(t)
	if !directoryAvailable(t, h) {
		t.Skip("this installation has no directory connection")
	}
	approver := secondPerson(t, h)
	host := labDirectoryHost(t, h)
	group := labDirectoryGroup(t, h)
	name := "flotestro-test-sudo"
	t.Cleanup(func() { removeRule(t, h, approver, "identity.sudo.rule.remove", "sudo_rule", name) })

	var change ruleChange
	h.do(http.MethodPost, "/api/v1/identity/changes", map[string]any{
		"action": "identity.sudo.rule.ensure", "reason": ruleReason,
		"payload": map[string]any{"sudo_rule": map[string]any{
			"name": name, "enabled": true, "user_groups": []string{group}, "hosts": []string{host},
			"all_commands": true, "options": []string{"!authenticate"},
		}},
	}, &change, http.StatusCreated)
	if len(change.Plan.Conflicts) > 0 {
		t.Fatalf("the plan has conflicts: %v", change.Plan.Conflicts)
	}
	warnings := strings.Join(change.Plan.Warnings, "\n")
	for _, want := range []string{"!authenticate", "every command"} {
		if !strings.Contains(warnings, want) {
			t.Errorf("the plan does not warn about %q:\n%s", want, warnings)
		}
	}

	final := approveAndRun(t, h, approver, change)
	if final.State != "succeeded" {
		t.Fatalf("the change finished as %s: %s", final.State, final.ResultMessage)
	}

	var rules struct {
		Items []sudoRuleView `json:"items"`
	}
	h.get("/api/v1/identity/sudo-rules", &rules)
	index := slices.IndexFunc(rules.Items, func(rule sudoRuleView) bool { return rule.Name == name })
	if index < 0 {
		t.Fatalf("the directory does not list the rule %s", name)
	}
	rule := rules.Items[index]
	if !rule.Enabled || !rule.AllCommands || !rule.Critical || !slices.Contains(rule.Options, "!authenticate") ||
		!slices.Contains(rule.Hosts, host) {
		t.Fatalf("the rule as the directory holds it: %+v", rule)
	}

	removeRule(t, h, approver, "identity.sudo.rule.remove", "sudo_rule", name)
	h.get("/api/v1/identity/sudo-rules", &rules)
	if slices.ContainsFunc(rules.Items, func(rule sudoRuleView) bool { return rule.Name == name }) {
		t.Fatalf("the rule %s is still in the directory after its removal", name)
	}
}

// TestDirectoryRuleValidationRefusesBadMaterial guards the boundary: a rule
// the directory would reject falls out when ordered, not after approval.
func TestDirectoryRuleValidationRefusesBadMaterial(t *testing.T) {
	h := newHarness(t)
	if !directoryAvailable(t, h) {
		t.Skip("this installation has no directory connection")
	}
	bad := map[string]map[string]any{
		"a name with a space": {
			"action": "identity.hbac.rule.ensure",
			"payload": map[string]any{"hbac_rule": map[string]any{"name": "bad name", "enabled": false}},
		},
		"an enabled rule without hosts": {
			"action": "identity.hbac.rule.ensure",
			"payload": map[string]any{"hbac_rule": map[string]any{
				"name": "flotestro-test-empty", "enabled": true, "user_groups": []string{"admins"},
				"services": []string{"sshd"},
			}},
		},
		"a sudo option nobody knows": {
			"action": "identity.sudo.rule.ensure",
			"payload": map[string]any{"sudo_rule": map[string]any{
				"name": "flotestro-test-option", "enabled": true, "all_users": true, "all_hosts": true,
				"all_commands": true, "options": []string{"nopassword"},
			}},
		},
		"a simulation ordered as a change": {
			"action": "identity.hbac.test", "payload": map[string]any{},
		},
	}
	for name, body := range bad {
		t.Run(name, func(t *testing.T) {
			body["reason"] = ruleReason
			h.do(http.MethodPost, "/api/v1/identity/changes", body, nil, http.StatusBadRequest)
		})
	}
}

// TestAccessSimulationAnswersForALabHost asks the directory for its verdict
// on the administrator and a lab host.
func TestAccessSimulationAnswersForALabHost(t *testing.T) {
	h := newHarness(t)
	if !directoryAvailable(t, h) {
		t.Skip("this installation has no directory connection")
	}
	host := labDirectoryHost(t, h)

	var result struct {
		User       string   `json:"user"`
		Host       string   `json:"host"`
		Service    string   `json:"service"`
		Allowed    bool     `json:"allowed"`
		Matched    []string `json:"matched"`
		NotMatched []string `json:"not_matched"`
	}
	h.do(http.MethodPost, "/api/v1/identity/access/simulate",
		map[string]any{"user": "admin", "host": host, "service": "sshd"}, &result, http.StatusOK)
	if result.User != "admin" || result.Host != host || result.Service != "sshd" {
		t.Fatalf("the simulation answered for %+v", result)
	}
	// The verdict has to agree with the rules the directory evaluated:
	// allowed means at least one rule matched.
	if result.Allowed != (len(result.Matched) > 0) {
		t.Fatalf("the verdict %v does not agree with the matched rules %v", result.Allowed, result.Matched)
	}
	if result.Matched == nil || result.NotMatched == nil {
		t.Fatalf("the lists of rules are absent instead of empty: %+v", result)
	}

	// A name that cannot be an account never reaches the directory.
	h.do(http.MethodPost, "/api/v1/identity/access/simulate",
		map[string]any{"user": "admin; drop", "host": host}, nil, http.StatusBadRequest)
}

// TestHostEffectiveAccessIsAProjectionOrHonestlyUnknown reads the effective
// access of a fleet host. A host the directory knows gets its groups and
// rules; one it does not know is reported as unknown, never as "no access".
func TestHostEffectiveAccessIsAProjectionOrHonestlyUnknown(t *testing.T) {
	h := newHarness(t)
	if !directoryAvailable(t, h) {
		t.Skip("this installation has no directory connection")
	}
	hosts := h.hosts()
	if len(hosts) == 0 {
		t.Skip("the fleet has no hosts")
	}

	var known int
	for _, host := range hosts {
		var access struct {
			Hostname   string   `json:"hostname"`
			Known      bool     `json:"known"`
			Detail     string   `json:"detail"`
			FQDN       string   `json:"fqdn"`
			HostGroups []string `json:"host_groups"`
			HBACRules  []struct {
				Name string   `json:"name"`
				Via  []string `json:"via"`
			} `json:"hbac_rules"`
			SudoRules []struct {
				Name string `json:"name"`
			} `json:"sudo_rules"`
		}
		h.get("/api/v1/hosts/"+host.ID+"/access", &access)
		if access.HostGroups == nil || access.HBACRules == nil || access.SudoRules == nil {
			t.Fatalf("%s: the lists are absent instead of empty: %+v", host.Hostname, access)
		}
		if !access.Known {
			if access.Detail == "" {
				t.Fatalf("%s: unknown without saying why", host.Hostname)
			}
			continue
		}
		known++
		if access.FQDN == "" {
			t.Fatalf("%s: known without a directory name", host.Hostname)
		}
		for _, rule := range access.HBACRules {
			if len(rule.Via) == 0 {
				t.Fatalf("%s: the rule %s reaches the host without saying how", host.Hostname, rule.Name)
			}
		}
	}
	if known == 0 {
		t.Log("no fleet host has an entry in the directory; the projection was checked as unknown only")
	}
}
