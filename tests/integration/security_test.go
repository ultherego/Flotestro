//go:build integration

package integration

import (
	"encoding/json"
	"net/http"
	"strings"
	"testing"
	"time"
)

type listenerView struct {
	Protocol string `json:"protocol"`
	Port     int    `json:"port"`
	Reach    string `json:"reach"`
}

type securitySnapshot struct {
	MAC struct {
		System         string `json:"system"`
		Mode           string `json:"mode"`
		ConfiguredMode string `json:"configured_mode"`
		Reason         string `json:"reason"`
	} `json:"mac"`
	Audit struct {
		Present         bool  `json:"present"`
		Active          *bool `json:"active"`
		RulesLoaded     *int  `json:"rules_loaded"`
		RulesConfigured *int  `json:"rules_configured"`
	} `json:"audit"`
	FIPSEnabled       *bool             `json:"fips_enabled"`
	SecureBoot        *bool             `json:"secure_boot"`
	SecureBootReason  string            `json:"secure_boot_reason"`
	Listening         []listenerView    `json:"listening"`
	ListeningKnown    bool              `json:"listening_known"`
	OwnersKnown       bool              `json:"owners_known"`
	Missing           map[string]string `json:"missing"`
	UnavailableReason string            `json:"unavailable_reason"`
}

type remediationView struct {
	Action  string          `json:"action"`
	Payload json.RawMessage `json:"payload"`
	Note    string          `json:"note"`
}

type findingView struct {
	CheckID      string           `json:"check_id"`
	CheckVersion int              `json:"check_version"`
	Title        string           `json:"title"`
	Severity     string           `json:"severity"`
	Rationale    string           `json:"rationale"`
	Applicable   bool             `json:"applicable"`
	Passed       bool             `json:"passed"`
	Unknown      bool             `json:"unknown"`
	ReasonCode   string           `json:"reason_code"`
	Expected     string           `json:"expected"`
	Observed     string           `json:"observed"`
	Module       string           `json:"module"`
	Revision     string           `json:"revision"`
	Remediation  *remediationView `json:"remediation"`
}

type reportView struct {
	Findings        []findingView  `json:"findings"`
	PlanHash        string         `json:"plan_hash"`
	PlanHashVersion int            `json:"plan_hash_version"`
	GeneratedAt     time.Time      `json:"generated_at"`
	Counts          map[string]int `json:"counts"`
}

type planStepView struct {
	Position       int    `json:"position"`
	CheckID        string `json:"check_id"`
	CheckVersion   int    `json:"check_version"`
	ActionType     string `json:"action_type"`
	LockClass      string `json:"lock_class"`
	RequiresReboot bool   `json:"requires_reboot"`
	JobID          string `json:"job_id"`
	State          string `json:"state"`
	Reason         string `json:"reason"`
}

type remediationPlanView struct {
	ID              string         `json:"id"`
	HostID          string         `json:"host_id"`
	PlanHash        string         `json:"plan_hash"`
	PlanHashVersion int            `json:"plan_hash_version"`
	StopOnFailure   bool           `json:"stop_on_failure"`
	State           string         `json:"state"`
	Steps           []planStepView `json:"steps"`
}

type planResponse struct {
	Plan    remediationPlanView `json:"plan"`
	Skipped map[string]string   `json:"skipped"`
}

const securityReason = "integration test of the security module"

// TestSecurityStateComesFromTheHost checks the facts all the findings stand
// on: MAC, audit, the boot mode and what the host exposes outside.
func TestSecurityStateComesFromTheHost(t *testing.T) {
	h := newHarness(t)

	for _, family := range []string{"debian", "rhel"} {
		t.Run(family, func(t *testing.T) {
			host := h.hostByFamily(family)
			state := hostSecuritySnapshot(t, h, host.ID)
			if state.UnavailableReason != "" {
				t.Fatalf("the security state was not read: %s", state.UnavailableReason)
			}
			// A host without MAC is to say why, not stay quiet.
			if state.MAC.System == "" && state.MAC.Reason == "" {
				t.Error("no MAC system without a reason")
			}
			if state.MAC.System != "" && state.MAC.Mode == "" {
				t.Errorf("MAC system without a mode: %+v", state.MAC)
			}
			if !state.ListeningKnown {
				t.Error("the listening sockets were not read")
			}
			if len(state.Listening) == 0 {
				t.Error("the host reported no socket at all, yet at least the agent listens somewhere")
			}
			// The reach is a classification, not a conclusion about visibility from the
			// internet: that cannot be seen from the address alone.
			classes := map[string]bool{"loopback": true, "host-network": true, "all-interfaces": true}
			for _, socket := range state.Listening {
				if !classes[socket.Reach] {
					t.Errorf("socket %s/%d has the reach %q", socket.Protocol, socket.Port, socket.Reach)
				}
			}
			// A fact that could not be gathered carries a reason - not a
			// default value.
			for name, reason := range state.Missing {
				if reason == "" {
					t.Errorf("missing fact %s without a reason", name)
				}
			}
			// Loaded rules and configured rules are two questions.
			if state.Audit.Present && state.Audit.Active != nil && *state.Audit.Active {
				if state.Audit.RulesLoaded == nil || state.Audit.RulesConfigured == nil {
					t.Errorf("a running audit without rule counters: %+v", state.Audit)
				}
			}
			// An undetermined state carries a reason: the secure boot question on a
			// host without EFI has no answer and it is not made up.
			if state.SecureBoot == nil && state.SecureBootReason == "" {
				t.Error("undetermined secure boot without a reason")
			}
			if !state.Audit.Present && state.Audit.Active != nil {
				t.Errorf("a host without audit reports its state: %+v", state.Audit)
			}
		})
	}
}

// TestFindingsAreRepeatable checks the contract of the compliance report.
func TestFindingsAreRepeatable(t *testing.T) {
	h := newHarness(t)
	host := h.hostByFamily("debian")

	report := securityReport(t, h, host.ID)
	if len(report.Findings) == 0 {
		t.Fatal("report without findings")
	}
	if report.PlanHash == "" {
		t.Error("report without a plan fingerprint")
	}
	// The canonical form of the fingerprint is versioned: a change in the
	// computation rules is to invalidate approved plans explicitly, not quietly.
	if report.PlanHashVersion == 0 {
		t.Error("report without the fingerprint canonicalisation version")
	}

	for _, finding := range report.Findings {
		if finding.CheckID == "" || finding.CheckVersion == 0 {
			t.Errorf("finding without a check version: %+v", finding)
		}
		if finding.Expected == "" || finding.Observed == "" || finding.Rationale == "" {
			t.Errorf("%s without an expectation, an observation or a rationale", finding.CheckID)
		}
		// A passed finding carries no remediation plan: fixing a correct
		// state is an invitation to a change without a reason.
		if (finding.Passed || finding.Unknown || !finding.Applicable) && finding.Remediation != nil {
			t.Errorf("%s needs no action, yet carries a remediation", finding.CheckID)
		}
		// An undetermined state and "not applicable" carry a reason code: without it
		// the operator does not know whether to wait, fix or grant permissions.
		if (finding.Unknown || !finding.Applicable) && finding.ReasonCode == "" {
			t.Errorf("%s without a result and without a reason code", finding.CheckID)
		}
		if finding.Applicable && !finding.Unknown && finding.ReasonCode != "" {
			t.Errorf("%s has a result and a reason code at once: %q", finding.CheckID, finding.ReasonCode)
		}
		// A finding computed from a module points at the revision of the
		// read it came from - without it the result cannot be repeated.
		if finding.Module != "" && !finding.Unknown && finding.Revision == "" {
			t.Errorf("%s without a read revision", finding.CheckID)
		}
	}

	// The same host state gives the same plan fingerprint.
	repeated := securityReport(t, h, host.ID)
	if repeated.PlanHash != report.PlanHash {
		t.Error("the plan fingerprint changed between two reads of the same state")
	}
}

// TestNotApplicableCheckIsNotAFailure guards the assessment boundary: a host
// without a given component does not fail its check and does not quietly pass
// it.
func TestNotApplicableCheckIsNotAFailure(t *testing.T) {
	h := newHarness(t)

	for _, family := range []string{"debian", "rhel"} {
		t.Run(family, func(t *testing.T) {
			host := h.hostByFamily(family)
			state := hostSecuritySnapshot(t, h, host.ID)
			report := securityReport(t, h, host.ID)

			persistence := findFinding(t, report, "mac.persistent")
			hasSELinux := state.MAC.System == "selinux"
			if persistence.Applicable != hasSELinux {
				t.Errorf("SELinux check: applicable=%v with the MAC system %q",
					persistence.Applicable, state.MAC.System)
			}
			if !persistence.Applicable && (persistence.Passed || persistence.Unknown) {
				t.Errorf("not applicable mixed with a result: %+v", persistence)
			}

			// A host without the audit daemon does not fail the check of its
			// rules.
			rules := findFinding(t, report, "audit.rules-loaded")
			if !state.Audit.Present && rules.Applicable {
				t.Errorf("the rules check applies to a host without audit: %+v", rules)
			}

			// The summary counts not applicable separately.
			if report.Counts["not_applicable"] == 0 && !hasSELinux {
				t.Errorf("summary without the not applicable state: %v", report.Counts)
			}
		})
	}
}

// TestRemediationRequiresAPlanAndAChoice guards the rule from the document:
// there is no "fix everything" button, and the plan binds the order to the
// state the operator looked at.
func TestRemediationRequiresAPlanAndAChoice(t *testing.T) {
	h := newHarness(t)
	host := h.hostByFamily("debian")
	report := securityReport(t, h, host.ID)

	// A plan from before a state change cannot be carried out.
	h.do(http.MethodPost, "/api/v1/hosts/"+host.ID+"/security/remediation",
		map[string]any{"plan_hash": "0000", "check_ids": []string{"kernel.rp-filter"},
			"reason": securityReason}, nil, http.StatusConflict)

	// An empty list does not mean "everything".
	h.do(http.MethodPost, "/api/v1/hosts/"+host.ID+"/security/remediation",
		map[string]any{"plan_hash": report.PlanHash, "check_ids": []string{}, "reason": securityReason},
		nil, http.StatusBadRequest)

	// A check outside the plan does not exist.
	h.do(http.MethodPost, "/api/v1/hosts/"+host.ID+"/security/remediation",
		map[string]any{"plan_hash": report.PlanHash, "check_ids": []string{"no.such.check"},
			"reason": securityReason}, nil, http.StatusBadRequest)

	// A finding without a remediation operation creates no job - and says
	// why.
	var withoutOperation string
	for _, finding := range report.Findings {
		if !finding.Passed && !finding.Unknown &&
			(finding.Remediation == nil || finding.Remediation.Action == "") {
			withoutOperation = finding.CheckID
			break
		}
	}
	if withoutOperation == "" {
		t.Skip("this host has no finding without a remediation operation")
	}
	// A finding without an operation creates no plan at all: there is
	// nothing to make it from.
	h.do(http.MethodPost, "/api/v1/hosts/"+host.ID+"/security/remediation",
		map[string]any{"plan_hash": report.PlanHash, "check_ids": []string{withoutOperation},
			"reason": securityReason}, nil, http.StatusBadRequest)
}

// TestRemediationCreatesAModuleJob checks that remediation is not a separate
// mechanism: it is an ordinary job of the module responsible for the given
// thing.
func TestRemediationCreatesAModuleJob(t *testing.T) {
	h := newHarness(t)
	host := h.hostByFamily("debian")
	report := securityReport(t, h, host.ID)

	var toFix findingView
	for _, finding := range report.Findings {
		if !finding.Passed && !finding.Unknown &&
			finding.Remediation != nil && finding.Remediation.Action != "" {
			toFix = finding
			break
		}
	}
	if toFix.CheckID == "" {
		t.Skip("this host has no finding with a remediation operation")
	}

	var response planResponse
	h.do(http.MethodPost, "/api/v1/hosts/"+host.ID+"/security/remediation",
		map[string]any{"plan_hash": report.PlanHash, "check_ids": []string{toFix.CheckID},
			"reason": securityReason}, &response, http.StatusCreated)
	plan := response.Plan
	t.Cleanup(func() {
		// A plan left in progress would block the next runs of this test.
		h.do(http.MethodPost,
			"/api/v1/hosts/"+host.ID+"/security/remediation/"+plan.ID+"/stop", nil, nil, 0)
	})

	if plan.State != "running" || len(plan.Steps) != 1 {
		t.Fatalf("plan = %+v", plan)
	}
	step := plan.Steps[0]
	if step.ActionType != toFix.Remediation.Action {
		t.Errorf("operation = %q, the plan said %q", step.ActionType, toFix.Remediation.Action)
	}
	if step.Position != 1 || step.CheckVersion != toFix.CheckVersion {
		t.Errorf("step = %+v", step)
	}
	if !plan.StopOnFailure {
		t.Error("the plan does not stop after a failure")
	}
	if plan.PlanHash != report.PlanHash || plan.PlanHashVersion != report.PlanHashVersion {
		t.Errorf("the plan is not bound to the findings: %+v", plan)
	}

	// A second plan on the same host cannot run in parallel: the steps of
	// one assume a state the other changes underneath them.
	h.do(http.MethodPost, "/api/v1/hosts/"+host.ID+"/security/remediation",
		map[string]any{"plan_hash": report.PlanHash, "check_ids": []string{toFix.CheckID},
			"reason": securityReason}, nil, http.StatusConflict)

	// Stopping closes the plan and leaves no steps in limbo.
	var stopped remediationPlanView
	h.do(http.MethodPost, "/api/v1/hosts/"+host.ID+"/security/remediation/"+plan.ID+"/stop",
		nil, &stopped, http.StatusOK)
	if stopped.State != "stopped" {
		t.Errorf("plan after stopping = %q", stopped.State)
	}
	for _, step := range stopped.Steps {
		if step.State == "pending" {
			t.Errorf("step %s stayed pending after the plan was stopped", step.CheckID)
		}
	}
}

func findFinding(t *testing.T, report reportView, id string) findingView {
	t.Helper()
	for _, finding := range report.Findings {
		if finding.CheckID == id {
			return finding
		}
	}
	t.Fatalf("the report has no finding %s", id)
	return findingView{}
}

// TestSwitchingMACHasBoundaries guards what the panel does not do: it does
// not disable SELinux and does not pretend a host has it when it does not.
func TestSwitchingMACHasBoundaries(t *testing.T) {
	h := newHarness(t)

	// Disabling does not reach the host: the order validation rejects it.
	rhel := h.hostByFamily("rhel")
	h.do(http.MethodPost, "/api/v1/hosts/"+rhel.ID+"/operations",
		map[string]any{"action": "selinux.mode.set", "reason": securityReason,
			"payload": map[string]any{"security": map[string]any{"mode": "disabled"}}},
		nil, http.StatusBadRequest)

	// A host without SELinux refuses when ordered, not after delivery.
	debian := h.hostByFamily("debian")
	if hasCapability(debian, "security.mac") {
		t.Skip("this host has SELinux, so it will not check the refusal for a missing capability")
	}
	h.do(http.MethodPost, "/api/v1/hosts/"+debian.ID+"/operations",
		map[string]any{"action": "selinux.mode.set", "reason": securityReason,
			"payload": map[string]any{"security": map[string]any{"mode": "permissive"}}},
		nil, http.StatusConflict)
}

func hasCapability(host hostView, name string) bool {
	for _, capability := range host.Capabilities {
		if capability.Name == name {
			return capability.Available
		}
	}
	return false
}

func hostSecuritySnapshot(t *testing.T, h *harness, hostID string) securitySnapshot {
	t.Helper()
	var fragment inventoryFragment
	h.do(http.MethodGet, "/api/v1/hosts/"+hostID+"/inventory/security", nil, &fragment, http.StatusOK)
	var state securitySnapshot
	if err := json.Unmarshal(fragment.Payload, &state); err != nil {
		t.Fatalf("security snapshot: %v", err)
	}
	return state
}

func securityReport(t *testing.T, h *harness, hostID string) reportView {
	t.Helper()
	var report reportView
	h.do(http.MethodGet, "/api/v1/hosts/"+hostID+"/security", nil, &report, http.StatusOK)
	return report
}

type fleetCheckView struct {
	CheckID string `json:"check_id"`
	Failed  int    `json:"failed"`
	Fixable int    `json:"fixable"`
	Hosts   []struct {
		HostID   string `json:"host_id"`
		Hostname string `json:"hostname"`
		Action   string `json:"action"`
	} `json:"hosts"`
}

type remediationGroupView struct {
	PlanHash string         `json:"plan_hash"`
	Count    int            `json:"count"`
	Changes  []string       `json:"changes"`
	Steps    []planStepView `json:"steps"`
	Hosts    []struct {
		HostID   string `json:"host_id"`
		Hostname string `json:"hostname"`
	} `json:"hosts"`
}

type remediationPreviewView struct {
	CheckIDs []string               `json:"check_ids"`
	Hosts    int                    `json:"hosts"`
	Eligible int                    `json:"eligible"`
	Groups   []remediationGroupView `json:"groups"`
	Excluded []struct {
		HostID  string `json:"host_id"`
		Reason  string `json:"reason"`
		Message string `json:"message"`
	} `json:"excluded"`
}

type remediationOrderView struct {
	Campaign campaignView           `json:"campaign"`
	Groups   []remediationGroupView `json:"groups"`
}

// fixableCheck picks a check the lab has fixable findings for, together with
// the hosts that carry them.
func fixableCheck(t *testing.T, h *harness) (fleetCheckView, []string) {
	t.Helper()
	var fleet struct {
		Checks []fleetCheckView `json:"checks"`
	}
	h.get("/api/v1/security", &fleet)
	var chosen fleetCheckView
	for _, check := range fleet.Checks {
		if check.Fixable == 0 {
			continue
		}
		if chosen.CheckID == "" || check.CheckID == "ssh.password-auth" {
			chosen = check
		}
	}
	if chosen.CheckID == "" {
		t.Skip("no check has a fixable finding in this lab")
	}
	var hostIDs []string
	for _, host := range chosen.Hosts {
		if host.Action != "" {
			hostIDs = append(hostIDs, host.HostID)
		}
	}
	if len(hostIDs) == 0 {
		t.Skipf("the check %s has fixable findings but lists no host with an operation", chosen.CheckID)
	}
	return chosen, hostIDs
}

// TestFleetRemediationGroupsPlansAndBindsTheApproval checks the fleet form of
// remediation: chosen checks on chosen hosts, every host with its own plan,
// hosts with the same steps in one group, and one campaign whose approval
func TestFleetRemediationGroupsPlansAndBindsTheApproval(t *testing.T) {
	h := newHarness(t)
	check, hostIDs := fixableCheck(t, h)
	selector := map[string]any{"host_ids": hostIDs}

	// There is no fix-all: neither an empty check list nor an empty host
	// selection is "everything", and a check that does not exist is a refusal
	// rather than a silent no-op on the fleet.
	h.do(http.MethodPost, "/api/v1/security/remediation/preview",
		map[string]any{"check_ids": []string{}, "selector": selector}, nil, http.StatusBadRequest)
	h.do(http.MethodPost, "/api/v1/security/remediation/preview",
		map[string]any{"check_ids": []string{check.CheckID}, "selector": map[string]any{}}, nil, http.StatusBadRequest)
	h.do(http.MethodPost, "/api/v1/security/remediation/preview",
		map[string]any{"check_ids": []string{"no.such.check"}, "selector": selector}, nil, http.StatusBadRequest)

	var preview remediationPreviewView
	h.do(http.MethodPost, "/api/v1/security/remediation/preview",
		map[string]any{"check_ids": []string{check.CheckID}, "selector": selector}, &preview, http.StatusOK)
	if preview.Hosts != len(hostIDs) {
		t.Errorf("the preview describes %d hosts, %d were named", preview.Hosts, len(hostIDs))
	}
	if preview.Eligible == 0 || len(preview.Groups) == 0 {
		t.Fatalf("no host got a plan: %+v", preview)
	}
	// Every host with the finding gets the same step, so the plans form one
	// group; the group's hosts add up to the eligible count.
	covered := 0
	for _, group := range preview.Groups {
		if len(group.Steps) != 1 || group.Steps[0].CheckID != check.CheckID {
			t.Errorf("group %s has the steps %+v", group.PlanHash[:8], group.Steps)
		}
		if group.Count != len(group.Hosts) {
			t.Errorf("group %s counts %d hosts and lists %d", group.PlanHash[:8], group.Count, len(group.Hosts))
		}
		covered += group.Count
	}
	if covered != preview.Eligible {
		t.Errorf("the groups cover %d hosts, %d are eligible", covered, preview.Eligible)
	}
	if len(preview.Groups) != 1 {
		t.Errorf("one declarative step on every host split into %d groups", len(preview.Groups))
	}
	for _, excluded := range preview.Excluded {
		if excluded.Reason == "" || excluded.Message == "" {
			t.Errorf("host %s was left out without a reason", excluded.HostID)
		}
	}

	// The composite permission: an operator may write the sshd configuration and
	// create campaigns, but does not hold the remediation permission - so the
	// order is refused as a whole, naming the missing one, and nothing comes into
	host := h.hostByFamily("debian")
	operator := h.withToken(h.createPrincipal(uniqueSubject("remediation-operator"), []map[string]string{
		{"role": "operator", "site": host.Site, "environment": host.Environment},
	}))
	operator.do(http.MethodPost, "/api/v1/security/remediation/preview",
		map[string]any{"check_ids": []string{check.CheckID}, "selector": selector}, nil, http.StatusOK)
	var refusal struct {
		Code   string `json:"code"`
		Detail string `json:"detail"`
	}
	operator.do(http.MethodPost, "/api/v1/security/remediation",
		map[string]any{"check_ids": []string{check.CheckID}, "selector": selector, "reason": securityReason},
		&refusal, http.StatusForbidden)
	if refusal.Code != "permission_denied" || !strings.Contains(refusal.Detail, "security.remediate") {
		t.Errorf("the operator's refusal = %+v; expected the missing remediation permission named", refusal)
	}

	// The order: a campaign that waits for one approval over the plans.
	var order remediationOrderView
	h.do(http.MethodPost, "/api/v1/security/remediation",
		map[string]any{
			"check_ids": []string{check.CheckID}, "selector": selector, "reason": securityReason,
			"canary_size": 1, "wave_size": 5, "max_concurrent": 2,
		}, &order, http.StatusCreated)
	campaign := order.Campaign
	t.Cleanup(func() {
		// The campaign is never approved here; cancelling leaves the lab as
		// it was and the queue empty for the next run.
		h.do(http.MethodPost, "/api/v1/campaigns/"+campaign.ID+"/cancel",
			map[string]any{"reason": "end of the test"}, nil, 0)
	})
	if campaign.State != "awaiting_approval" {
		t.Fatalf("the campaign is %s, not awaiting approval", campaign.State)
	}
	if campaign.ApprovalFingerprint == "" || campaign.PlanSetHash == "" {
		t.Fatalf("the campaign has no fingerprint over its plans: %+v", campaign)
	}
	if campaign.CanarySize != 1 || campaign.WaveSize != 5 || !campaign.RequiresApproval {
		t.Errorf("the rollout was not recorded as ordered: %+v", campaign)
	}
	if campaign.OfflinePolicy != "wait_until_deadline" {
		t.Errorf("offline policy = %q, expected the operation's wait_until_deadline", campaign.OfflinePolicy)
	}

	// The plan set is the one the preview showed: the same groups with the same
	// digests, one plan per eligible host, every plan a remediation plan.
	var plans struct {
		Items []struct {
			PlanHash string   `json:"plan_hash"`
			Count    int      `json:"count"`
			Hosts    []string `json:"hosts"`
			Plan     struct {
				Kind string `json:"kind"`
				Plan struct {
					Changes []string       `json:"changes"`
					Steps   []planStepView `json:"steps"`
				} `json:"plan"`
			} `json:"plan"`
		} `json:"items"`
		Hosts       int    `json:"hosts"`
		PlanSetHash string `json:"plan_set_hash"`
	}
	h.get("/api/v1/campaigns/"+campaign.ID+"/plans", &plans)
	if plans.Hosts != preview.Eligible || plans.PlanSetHash != campaign.PlanSetHash {
		t.Errorf("the campaign holds %d plans under %s; the preview had %d eligible hosts",
			plans.Hosts, plans.PlanSetHash, preview.Eligible)
	}
	if len(plans.Items) != len(order.Groups) || len(order.Groups) != len(preview.Groups) {
		t.Errorf("the plan groups: %d recorded, %d in the answer, %d in the preview",
			len(plans.Items), len(order.Groups), len(preview.Groups))
	}
	for _, item := range plans.Items {
		if item.Plan.Kind != "security_remediation" || len(item.Plan.Plan.Steps) != 1 {
			t.Errorf("the recorded plan %s is %+v", item.PlanHash[:8], item.Plan)
		}
		found := false
		for _, group := range preview.Groups {
			if group.PlanHash == item.PlanHash && group.Count == item.Count {
				found = true
			}
		}
		if !found {
			t.Errorf("the recorded group %s (%d hosts) was not in the preview", item.PlanHash[:8], item.Count)
		}
	}
	targets := h.campaignTargets(campaign.ID)
	if len(targets) != preview.Hosts {
		t.Errorf("the snapshot has %d targets, the preview named %d hosts", len(targets), preview.Hosts)
	}
	for _, target := range targets {
		if target.State != "pending" && target.State != "ineligible" && target.State != "skipped" {
			t.Errorf("target %s is %s before any approval", target.Hostname, target.State)
		}
	}

	// The consent covers the plans: the same hosts with a different check set are
	// a different set of plans, and the approval fingerprint moves with it.
	second := []string{check.CheckID}
	var fleet struct {
		Checks []fleetCheckView `json:"checks"`
	}
	h.get("/api/v1/security", &fleet)
	named := map[string]bool{}
	for _, id := range hostIDs {
		named[id] = true
	}
	shared := false
	for _, other := range fleet.Checks {
		if other.CheckID == check.CheckID || other.Fixable == 0 {
			continue
		}
		for _, candidate := range other.Hosts {
			if named[candidate.HostID] && candidate.Action != "" {
				shared = true
			}
		}
		if shared {
			second = append(second, other.CheckID)
			break
		}
	}
	if len(second) == 1 {
		second = append(second, "kernel.rp-filter")
		if check.CheckID == "kernel.rp-filter" {
			second[1] = "kernel.syncookies"
		}
	}
	var recomputed remediationOrderView
	h.do(http.MethodPost, "/api/v1/security/remediation",
		map[string]any{"check_ids": second, "selector": selector, "reason": securityReason},
		&recomputed, http.StatusCreated)
	t.Cleanup(func() {
		h.do(http.MethodPost, "/api/v1/campaigns/"+recomputed.Campaign.ID+"/cancel",
			map[string]any{"reason": "end of the test"}, nil, 0)
	})
	if recomputed.Campaign.ApprovalFingerprint == campaign.ApprovalFingerprint {
		t.Error("a different check set kept the approval fingerprint")
	}
	if shared && recomputed.Campaign.PlanSetHash == campaign.PlanSetHash {
		t.Errorf("a second check with findings on the same hosts kept the plan set digest %s", campaign.PlanSetHash)
	}
	if recomputed.Campaign.State != "awaiting_approval" {
		t.Errorf("the recomputed campaign is %s", recomputed.Campaign.State)
	}
}
