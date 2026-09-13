//go:build integration

package integration

import (
	"encoding/json"
	"net/http"
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
			// The reach is a classification, not a conclusion about
			// visibility from the internet: that cannot be seen from the
			// address alone.
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
			// An undetermined state carries a reason: the secure boot
			// question on a host without EFI has no answer and it is not
			// made up.
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
	// computation rules is to invalidate approved plans explicitly, not
	// quietly.
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
		// An undetermined state and "not applicable" carry a reason code:
		// without it the operator does not know whether to wait, fix or
		// grant permissions.
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

// TestNotApplicableCheckIsNotAFailure guards the assessment boundary: a
// host without a given component does not fail its check and does not
// quietly pass it.
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

// TestRemediationCreatesAModuleJob checks that remediation is not a
// separate mechanism: it is an ordinary job of the module responsible for
// the given thing.
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
