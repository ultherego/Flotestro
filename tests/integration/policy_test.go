//go:build integration

package integration

import (
	"encoding/json"
	"net/http"
	"testing"
	"time"
)

// The desired-state policies against the lab: the panel judges the hosts
// from their inventory, and the only change a policy sets in motion is a
// campaign that waits for approval.

type policyView struct {
	ID              string           `json:"id"`
	Name            string           `json:"name"`
	Version         int              `json:"version"`
	RemediationMode string           `json:"remediation_mode"`
	Draft           bool             `json:"draft"`
	Counts          map[string]int   `json:"counts"`
	Rules           []map[string]any `json:"rules"`
}

type policyResultView struct {
	HostID    string `json:"host_id"`
	Hostname  string `json:"hostname"`
	RuleIndex int    `json:"rule_index"`
	Verdict   string `json:"verdict"`
	Reason    string `json:"reason"`
	Version   int    `json:"version"`
}

type policyOutcomeView struct {
	Version     int            `json:"version"`
	Hosts       int            `json:"hosts"`
	Counts      map[string]int `json:"counts"`
	CampaignID  string         `json:"campaign_id"`
	Remediation string         `json:"remediation"`
}

// createPolicy records a draft over the debian family with the rules and
// the mode given, and removes it at the end of the test.
func (h *harness) createPolicy(t *testing.T, name, mode string, rules []map[string]any) policyView {
	t.Helper()
	var created policyView
	h.do(http.MethodPost, "/api/v1/policies", map[string]any{
		"name":             name,
		"description":      "integration test",
		"selector":         map[string]any{"os_family": "debian"},
		"rules":            rules,
		"remediation_mode": mode,
	}, &created, http.StatusCreated)
	t.Cleanup(func() {
		h.do(http.MethodDelete, "/api/v1/policies/"+created.ID, nil, nil, http.StatusNoContent)
	})
	return created
}

func (h *harness) publishPolicy(t *testing.T, id string) policyView {
	t.Helper()
	var published policyView
	h.do(http.MethodPost, "/api/v1/policies/"+id+"/publish",
		map[string]any{"reason": "integration test"}, &published, http.StatusOK)
	if published.Version == 0 {
		t.Fatalf("the publication did not bump the version: %+v", published)
	}
	return published
}

func (h *harness) evaluatePolicy(t *testing.T, id string) policyOutcomeView {
	t.Helper()
	var outcome policyOutcomeView
	h.do(http.MethodPost, "/api/v1/policies/"+id+"/evaluate", nil, &outcome, http.StatusOK)
	return outcome
}

func (h *harness) policyResults(t *testing.T, id string) []policyResultView {
	t.Helper()
	var page struct {
		Items []policyResultView `json:"items"`
		Total int                `json:"total"`
	}
	h.get("/api/v1/policies/"+id+"/results?limit=500", &page)
	return page.Items
}

// problemCode reads the stable code of a refusal.
func problemCode(t *testing.T, body []byte) string {
	t.Helper()
	var problem struct {
		Code string `json:"code"`
	}
	if err := json.Unmarshal(body, &problem); err != nil {
		t.Fatalf("the refusal does not decode: %v; body: %s", err, body)
	}
	return problem.Code
}

// connectedDebianHosts lists the connected hosts of the debian family by
// identifier: the ones a fresh inventory can be expected from.
func (h *harness) connectedDebianHosts(t *testing.T) map[string]hostView {
	t.Helper()
	online := map[string]hostView{}
	for _, host := range h.hosts() {
		if host.OSFamily == "debian" && host.ConnectionState == "online" {
			online[host.ID] = host
		}
	}
	if len(online) == 0 {
		t.Skip("no connected host of the debian family")
	}
	return online
}

// TestPolicyJudgesAUnitOverTheDebianFamily publishes a policy that wants
// cron enabled and running on every debian host and checks that the
// evaluation reads the unit listing and finds every connected host
// compliant.
func TestPolicyJudgesAUnitOverTheDebianFamily(t *testing.T) {
	h := newHarness(t)
	online := h.connectedDebianHosts(t)

	// The unit rule judges the full listing the panel holds; the listing
	// is a read the panel orders, so the test orders it first.
	for _, host := range online {
		job, _ := h.runOperation(host.ID, map[string]any{
			"action":  "unit.status",
			"payload": map[string]any{"unit_status": map[string]any{"all": true}},
		}, 90*time.Second)
		if job.State != "succeeded" {
			t.Fatalf("%s: the unit listing ended %s (%s)", host.Hostname, job.State, job.ResultErrorCode)
		}
	}

	policy := h.createPolicy(t, uniqueSubject("cron-running"), "report", []map[string]any{
		{"kind": "unit_state", "unit": "cron.service", "enabled": true, "active": true},
	})
	if policy.Version != 0 || policy.Draft {
		t.Fatalf("a fresh draft is version %d, draft %v", policy.Version, policy.Draft)
	}
	published := h.publishPolicy(t, policy.ID)
	if published.Version != 1 {
		t.Fatalf("version = %d, want 1", published.Version)
	}

	outcome := h.evaluatePolicy(t, policy.ID)
	if outcome.Hosts < len(online) {
		t.Fatalf("the evaluation covered %d hosts, the family has at least %d online", outcome.Hosts, len(online))
	}
	for _, result := range h.policyResults(t, policy.ID) {
		if _, ok := online[result.HostID]; !ok {
			continue
		}
		if result.Verdict != "compliant" {
			t.Errorf("%s: verdict %s (%s), want compliant", result.Hostname, result.Verdict, result.Reason)
		}
		if result.Version != 1 {
			t.Errorf("%s: judged by version %d", result.Hostname, result.Version)
		}
	}

	// The host page reads the same verdicts.
	for id, host := range online {
		var page struct {
			Items []policyResultView `json:"items"`
		}
		h.get("/api/v1/hosts/"+id+"/policies", &page)
		found := false
		for _, result := range page.Items {
			if result.RuleIndex == 0 && result.Verdict == "compliant" {
				found = true
			}
		}
		if !found {
			t.Errorf("%s: the host page does not show the verdict: %+v", host.Hostname, page.Items)
		}
		break
	}
}

// packageDriftPolicy publishes a policy that wants a package nobody ships
// and evaluates it; the caller reads the consequences of its mode. The
// judgement rests on the panel's copy of the package list, which the
// vulnerability cycle fetches - without it the verdict is an error, not a
// drift, and the test says so rather than pretending.
func packageDriftPolicy(t *testing.T, h *harness, mode string) (policyView, policyOutcomeView, map[string]hostView) {
	t.Helper()
	online := h.connectedDebianHosts(t)
	policy := h.createPolicy(t, uniqueSubject("pkg-"+mode), mode, []map[string]any{
		{"kind": "package_installed", "name": "nonexistent-pkg-xyz"},
	})
	h.publishPolicy(t, policy.ID)
	outcome := h.evaluatePolicy(t, policy.ID)
	for _, result := range h.policyResults(t, policy.ID) {
		host, ok := online[result.HostID]
		if !ok {
			continue
		}
		if result.Verdict == "error" {
			t.Skipf("%s: the package copy is not usable (%s); the vulnerability cycle has not fetched it", host.Hostname, result.Reason)
		}
		if result.Verdict != "drift" {
			t.Fatalf("%s: verdict %s (%s), want drift", host.Hostname, result.Verdict, result.Reason)
		}
	}
	return policy, outcome, online
}

// TestPolicyInReportModeRecordsDriftAndOrdersNothing checks the first
// mode: the drift is on the table, and no campaign.
func TestPolicyInReportModeRecordsDriftAndOrdersNothing(t *testing.T) {
	h := newHarness(t)
	policy, outcome, online := packageDriftPolicy(t, h, "report")
	if outcome.CampaignID != "" {
		t.Fatalf("report mode ordered campaign %s", outcome.CampaignID)
	}
	if outcome.Counts["drift"] < len(online) {
		t.Fatalf("drift on %d hosts, at least %d are online: %+v", outcome.Counts["drift"], len(online), outcome.Counts)
	}
	var campaigns struct {
		Items []map[string]any `json:"items"`
	}
	h.get("/api/v1/policies/"+policy.ID+"/campaigns", &campaigns)
	if len(campaigns.Items) != 0 {
		t.Fatalf("report mode has campaigns: %+v", campaigns.Items)
	}
	var read policyView
	h.get("/api/v1/policies/"+policy.ID, &read)
	if read.Counts["drift"] != outcome.Counts["drift"] {
		t.Fatalf("the policy counts %d drifted hosts, the evaluation %d", read.Counts["drift"], outcome.Counts["drift"])
	}
}

// TestPolicyInCampaignModeOrdersOneCampaignAwaitingApproval checks the
// second mode: one campaign for the drift set, linked to the policy, one
// target per drifted host, waiting for a consent nobody gave yet - and no
// second campaign for the same drift.
func TestPolicyInCampaignModeOrdersOneCampaignAwaitingApproval(t *testing.T) {
	h := newHarness(t)
	policy, outcome, online := packageDriftPolicy(t, h, "campaign")
	if outcome.CampaignID == "" {
		t.Fatalf("campaign mode ordered nothing: %s", outcome.Remediation)
	}
	t.Cleanup(func() {
		h.do(http.MethodPost, "/api/v1/campaigns/"+outcome.CampaignID+"/cancel",
			map[string]any{"reason": "end of the test"}, nil, http.StatusOK)
	})

	var campaign struct {
		campaignView
		PolicyID      string `json:"policy_id"`
		PolicyVersion int    `json:"policy_version"`
		ActionType    string `json:"action_type"`
	}
	h.get("/api/v1/campaigns/"+outcome.CampaignID, &campaign)
	if campaign.State != "awaiting_approval" {
		t.Fatalf("the campaign is %s, want awaiting_approval", campaign.State)
	}
	if campaign.PolicyID != policy.ID || campaign.PolicyVersion != 1 {
		t.Fatalf("the campaign links to %s v%d, want %s v1", campaign.PolicyID, campaign.PolicyVersion, policy.ID)
	}
	if campaign.ActionType != "security.remediate" {
		t.Fatalf("the campaign runs %s, want the remediation composite", campaign.ActionType)
	}
	if campaign.ApprovedBy != "" {
		t.Fatalf("campaign mode approved the campaign by itself: %s", campaign.ApprovedBy)
	}

	targets := h.campaignTargets(outcome.CampaignID)
	seen := map[string]int{}
	for _, target := range targets {
		seen[target.HostID]++
	}
	for id, host := range online {
		if seen[id] != 1 {
			t.Errorf("%s has %d targets, want one", host.Hostname, seen[id])
		}
	}

	// The same drift again is the same campaign, not a second one.
	again := h.evaluatePolicy(t, policy.ID)
	if again.CampaignID != outcome.CampaignID {
		t.Fatalf("a second evaluation ordered campaign %q, the first %q", again.CampaignID, outcome.CampaignID)
	}
	var campaigns struct {
		Items []map[string]any `json:"items"`
	}
	h.get("/api/v1/policies/"+policy.ID+"/campaigns", &campaigns)
	if len(campaigns.Items) != 1 {
		t.Fatalf("the policy lists %d campaigns, want one", len(campaigns.Items))
	}
}

// TestPolicyRefusesARuleKindItDoesNotJudge checks that a kind this panel
// does not know is refused by name, at the draft and at the publication.
func TestPolicyRefusesARuleKindItDoesNotJudge(t *testing.T) {
	h := newHarness(t)
	response, body := h.request(http.MethodPost, "/api/v1/policies", map[string]any{
		"name":     uniqueSubject("unsupported"),
		"selector": map[string]any{"os_family": "debian"},
		"rules":    []map[string]any{{"kind": "timer_present", "unit": "apt-daily.timer"}},
	}, nil)
	if response.StatusCode != http.StatusBadRequest {
		t.Fatalf("an unsupported kind answered %d; body: %s", response.StatusCode, body)
	}
	if code := problemCode(t, body); code != "unsupported_rule" {
		t.Fatalf("code = %s, want unsupported_rule", code)
	}

	// A draft without rules is accepted and refused at the publication.
	policy := h.createPolicy(t, uniqueSubject("empty"), "report", nil)
	response, body = h.request(http.MethodPost, "/api/v1/policies/"+policy.ID+"/publish",
		map[string]any{"reason": "integration test"}, nil)
	if response.StatusCode != http.StatusBadRequest || problemCode(t, body) != "no_rules" {
		t.Fatalf("an empty policy published: %d %s", response.StatusCode, body)
	}
}

// TestAutomaticRemediationNeedsItsOwnPermission checks that the approver
// - who publishes policies - cannot publish one that changes hosts
// without a second look, and that the platform administrator can.
func TestAutomaticRemediationNeedsItsOwnPermission(t *testing.T) {
	h := newHarness(t)
	h.connectedDebianHosts(t)

	policy := h.createPolicy(t, uniqueSubject("automatic"), "automatic", []map[string]any{
		{"kind": "sysctl", "key": "net.ipv4.ip_forward", "value": "0"},
	})
	approver := h.withToken(h.createPrincipal(uniqueSubject("approver"), []map[string]string{
		{"role": "approver", "site": "*", "environment": "*"},
	}))
	response, body := approver.request(http.MethodPost, "/api/v1/policies/"+policy.ID+"/publish",
		map[string]any{"reason": "integration test"}, nil)
	if response.StatusCode != http.StatusForbidden {
		t.Fatalf("the approver published an automatic policy: %d %s", response.StatusCode, body)
	}
	if code := problemCode(t, body); code != "permission_denied" {
		t.Fatalf("code = %s, want permission_denied", code)
	}

	// The refusal left the draft where it was.
	var read policyView
	h.get("/api/v1/policies/"+policy.ID, &read)
	if read.Version != 0 {
		t.Fatalf("the refused publication bumped the version to %d", read.Version)
	}

	// An approval-bound rule in an automatic policy is refused before the
	// permission is even asked: a removal is approved with what really
	// goes, and a publication cannot show that.
	bound := h.createPolicy(t, uniqueSubject("bound"), "automatic", []map[string]any{
		{"kind": "package_absent", "name": "telnetd"},
	})
	response, body = h.request(http.MethodPost, "/api/v1/policies/"+bound.ID+"/publish",
		map[string]any{"reason": "integration test"}, nil)
	if response.StatusCode != http.StatusBadRequest || problemCode(t, body) != "approval_bound_rule" {
		t.Fatalf("a removal published automatically: %d %s", response.StatusCode, body)
	}
}

// TestPolicyWriteHonoursTheEntityTag checks the conditional write: a stale
// tag is refused with the current one, a fresh tag goes through.
func TestPolicyWriteHonoursTheEntityTag(t *testing.T) {
	h := newHarness(t)
	policy := h.createPolicy(t, uniqueSubject("etag"), "report", []map[string]any{
		{"kind": "sysctl", "key": "net.ipv4.ip_forward", "value": "0"},
	})
	response, body := h.request(http.MethodGet, "/api/v1/policies/"+policy.ID, nil, nil)
	if response.StatusCode != http.StatusOK {
		t.Fatalf("GET the policy: %d %s", response.StatusCode, body)
	}
	fresh := response.Header.Get("ETag")
	if fresh == "" {
		t.Fatal("the policy read carries no ETag")
	}
	update := map[string]any{
		"name": policy.Name, "selector": map[string]any{"os_family": "debian"},
		"rules":            []map[string]any{{"kind": "sysctl", "key": "net.ipv4.ip_forward", "value": "1"}},
		"remediation_mode": "report",
	}
	response, body = h.request(http.MethodPut, "/api/v1/policies/"+policy.ID, update,
		map[string]string{"If-Match": `W/"0000000000000000"`})
	if response.StatusCode != http.StatusPreconditionFailed {
		t.Fatalf("a stale If-Match answered %d; body: %s", response.StatusCode, body)
	}
	if got := response.Header.Get("ETag"); got != fresh {
		t.Errorf("the refusal names ETag %q, the read gave %q", got, fresh)
	}
	response, body = h.request(http.MethodPut, "/api/v1/policies/"+policy.ID, update,
		map[string]string{"If-Match": fresh})
	if response.StatusCode != http.StatusOK {
		t.Fatalf("the fresh If-Match answered %d; body: %s", response.StatusCode, body)
	}
}
