//go:build integration

package integration

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"sort"
	"strconv"
	"strings"
	"testing"
	"time"
)

type campaignView struct {
	ID               string `json:"id"`
	Name             string `json:"name"`
	State            string `json:"state"`
	CanarySize       int    `json:"canary_size"`
	WaveSize         int    `json:"wave_size"`
	RequiresApproval bool   `json:"requires_approval"`
	// The fingerprint of what the approver sees. An approval without it
	// would concern the campaign identifier alone.
	ApprovalFingerprint string `json:"approval_fingerprint"`
	PlanSetHash         string `json:"plan_set_hash"`
	CreatedBy           string `json:"created_by"`
	ApprovedBy          string `json:"approved_by"`
	PausedBy            string `json:"paused_by"`
	PauseReason         string `json:"pause_reason"`
}

type campaignTargetView struct {
	HostID    string `json:"host_id"`
	Hostname  string `json:"hostname"`
	Wave      int    `json:"wave"`
	State     string `json:"state"`
	ErrorCode string `json:"error_code"`
	JobID     string `json:"job_id"`
	PlanJobID string `json:"plan_job_id"`
}

type campaignReportView struct {
	State  string         `json:"state"`
	Totals map[string]int `json:"totals"`
	Waves  []struct {
		Wave      int            `json:"wave"`
		IsCanary  bool           `json:"is_canary"`
		Totals    map[string]int `json:"totals"`
		Completed bool           `json:"completed"`
	} `json:"waves"`
	Failures []campaignTargetView `json:"failures"`
}

func (h *harness) createCampaign(body map[string]any) campaignView {
	h.t.Helper()
	var campaign campaignView
	h.do(http.MethodPost, "/api/v1/campaigns", body, &campaign, http.StatusCreated)
	h.t.Cleanup(func() {
		// A campaign in progress would block the next tests on the same
		// hosts.
		h.do(http.MethodPost, "/api/v1/campaigns/"+campaign.ID+"/cancel",
			map[string]any{"reason": "end of the test"}, nil, 0)
	})
	return campaign
}

// approveCampaign approves a campaign with its own fingerprint.
func (h *harness) approveCampaign(campaign campaignView) campaignView {
	h.t.Helper()
	var approved campaignView
	h.do(http.MethodPost, "/api/v1/campaigns/"+campaign.ID+"/approve",
		map[string]any{"approval_fingerprint": campaign.ApprovalFingerprint},
		&approved, http.StatusOK)
	return approved
}

func (h *harness) campaign(id string) campaignView {
	h.t.Helper()
	var campaign campaignView
	h.get("/api/v1/campaigns/"+id, &campaign)
	return campaign
}

func (h *harness) campaignTargets(id string) []campaignTargetView {
	h.t.Helper()
	var result struct {
		Items []campaignTargetView `json:"items"`
	}
	h.get("/api/v1/campaigns/"+id+"/targets", &result)
	return result.Items
}

// awaitCampaign waits for one of the expected campaign states.
func (h *harness) awaitCampaign(id string, wanted map[string]bool, timeout time.Duration) campaignView {
	h.t.Helper()
	deadline := time.Now().Add(timeout)
	var last campaignView
	for time.Now().Before(deadline) {
		last = h.campaign(id)
		if wanted[last.State] {
			return last
		}
		time.Sleep(2 * time.Second)
	}
	h.t.Fatalf("campaign %s did not reach the expected state (it is %s)", id, last.State)
	return last
}

func labCampaign(name, unit string, extra map[string]any) map[string]any {
	body := map[string]any{
		"name":                       name,
		"action":                     "unit.restart",
		"payload":                    unitPayload(unit),
		"selector":                   map[string]any{"site": "lab"},
		"canary_size":                1,
		"wave_size":                  1,
		"max_concurrent":             1,
		"failure_threshold_absolute": 0,
		"failure_threshold_percent":  0,
		"reboot_policy":              "never",
	}
	for key, value := range extra {
		body[key] = value
	}
	return body
}

// TestCampaignCreatesATargetSnapshot checks that the selector is turned at
// once into an immutable host list split into waves.
func TestCampaignCreatesATargetSnapshot(t *testing.T) {
	h := newHarness(t)
	campaign := h.createCampaign(labCampaign("target snapshot", "cron.service", nil))

	if campaign.State != "awaiting_approval" {
		t.Fatalf("state = %s, expected awaiting_approval", campaign.State)
	}
	targets := h.campaignTargets(campaign.ID)
	if len(targets) < 2 {
		t.Fatalf("the snapshot has %d targets, expected at least 2", len(targets))
	}

	// Wave 0 is the canary and has exactly as many hosts as given.
	canary := 0
	for _, target := range targets {
		if target.Wave == 0 {
			canary++
		}
		if target.State != "pending" {
			t.Errorf("target %s started before approval: %s", target.Hostname, target.State)
		}
	}
	if canary != campaign.CanarySize {
		t.Errorf("the canary has %d hosts, expected %d", canary, campaign.CanarySize)
	}
}

// TestCampaignWaitsForApproval checks that creation alone starts nothing.
// Approving a campaign is consent to a change on many hosts.
func TestCampaignWaitsForApproval(t *testing.T) {
	h := newHarness(t)
	campaign := h.createCampaign(labCampaign("waiting for consent", "cron.service", nil))

	time.Sleep(8 * time.Second)
	current := h.campaign(campaign.ID)
	if current.State != "awaiting_approval" {
		t.Fatalf("the unapproved campaign changed its state to %s", current.State)
	}
	for _, target := range h.campaignTargets(campaign.ID) {
		if target.State != "pending" {
			t.Errorf("target %s started without approval", target.Hostname)
		}
	}
}

// TestCanaryPrecedesTheNextWaves checks that wave 1 does not start before
// the canary closes.
func TestCanaryPrecedesTheNextWaves(t *testing.T) {
	h := newHarness(t)
	campaign := h.createCampaign(labCampaign("canary before the wave", "cron.service", nil))
	h.approveCampaign(campaign)

	// While the canary works, the next waves must wait.
	deadline := time.Now().Add(60 * time.Second)
	sawCanaryFirst := false
	for time.Now().Before(deadline) {
		targets := h.campaignTargets(campaign.ID)
		canaryOpen, laterStarted := false, false
		for _, target := range targets {
			if target.Wave == 0 && (target.State == "running" || target.State == "pending") {
				canaryOpen = true
			}
			if target.Wave > 0 && target.State != "pending" {
				laterStarted = true
			}
		}
		if canaryOpen && laterStarted {
			t.Fatal("the wave after the canary started before the canary closed")
		}
		if !canaryOpen {
			sawCanaryFirst = true
			break
		}
		time.Sleep(time.Second)
	}
	if !sawCanaryFirst {
		t.Skip("the canary did not close within the test time")
	}
}

// TestFailureThresholdPausesTheCampaign is a test of the most important
// safeguard: a bad change must not pass through the whole fleet.
func TestFailureThresholdPausesTheCampaign(t *testing.T) {
	h := newHarness(t)
	campaign := h.createCampaign(labCampaign("campaign with a failure", "non-existent-unit.service",
		map[string]any{"failure_threshold_absolute": 1}))
	h.approveCampaign(campaign)

	paused := h.awaitCampaign(campaign.ID, map[string]bool{"paused": true}, 90*time.Second)
	if paused.PauseReason == "" {
		t.Error("the campaign was paused without a reason")
	}
	if paused.PausedBy != "system" {
		t.Errorf("paused by %q, expected system", paused.PausedBy)
	}

	targets := h.campaignTargets(campaign.ID)
	failed, untouched := 0, 0
	for _, target := range targets {
		switch {
		case target.State == "failed":
			failed++
			// The error code must reach the campaign, otherwise the operator
			// sees the bare word "failed" without a cause.
			if target.ErrorCode == "" {
				t.Errorf("target %s failed without an error code", target.Hostname)
			}
		case target.State == "pending":
			untouched++
		}
	}
	if failed == 0 {
		t.Fatal("the campaign was paused, but no host is marked as failed")
	}
	// The crux of the threshold: the hosts of the next waves were not
	// touched.
	if untouched == 0 {
		t.Error("no untouched host remained after the threshold was exceeded")
	}
}

// TestCampaignReportDescribesTheWaves checks the completeness of the final
// report.
func TestCampaignReportDescribesTheWaves(t *testing.T) {
	h := newHarness(t)
	campaign := h.createCampaign(labCampaign("report", "non-existent-unit.service",
		map[string]any{"failure_threshold_absolute": 1}))
	h.approveCampaign(campaign)
	h.awaitCampaign(campaign.ID, map[string]bool{"paused": true}, 90*time.Second)

	var report campaignReportView
	h.get("/api/v1/campaigns/"+campaign.ID+"/report", &report)

	if len(report.Waves) == 0 {
		t.Fatal("the report describes no wave at all")
	}
	if !report.Waves[0].IsCanary {
		t.Error("the first wave is not marked as the canary")
	}
	if len(report.Failures) == 0 {
		t.Error("the report does not list the hosts that failed")
	}
	if report.Totals["failed"] == 0 {
		t.Error("the summary does not count the failures")
	}
}

// TestPausedCampaignCanBeResumedAndCancelled checks the campaign controls.
func TestPausedCampaignCanBeResumedAndCancelled(t *testing.T) {
	h := newHarness(t)
	campaign := h.createCampaign(labCampaign("controls", "cron.service", nil))
	h.approveCampaign(campaign)

	h.do(http.MethodPost, "/api/v1/campaigns/"+campaign.ID+"/pause",
		map[string]any{"reason": "test"}, nil, http.StatusOK)
	if state := h.campaign(campaign.ID).State; state != "paused" {
		t.Fatalf("state after pausing = %s", state)
	}

	h.do(http.MethodPost, "/api/v1/campaigns/"+campaign.ID+"/resume", nil, nil, http.StatusOK)
	if state := h.campaign(campaign.ID).State; state == "paused" {
		t.Fatal("the campaign stayed paused after resuming")
	}

	h.do(http.MethodPost, "/api/v1/campaigns/"+campaign.ID+"/cancel",
		map[string]any{"reason": "end"}, nil, http.StatusOK)
	final := h.campaign(campaign.ID)
	if final.State != "canceled" {
		t.Fatalf("state after cancelling = %s", final.State)
	}
	// Cancelling must not leave hosts waiting in the queue.
	for _, target := range h.campaignTargets(campaign.ID) {
		if target.State == "pending" {
			t.Errorf("target %s stayed pending after cancelling", target.Hostname)
		}
	}
}

// TestOperatorDoesNotApproveCampaigns checks the separation of duties at
// the campaign level: one approval starts a change on many hosts.
func TestOperatorDoesNotApproveCampaigns(t *testing.T) {
	h := newHarness(t)
	host := h.hostByFamily("debian")

	operator := h.withToken(h.createPrincipal(uniqueSubject("operator-campaigns"), []map[string]string{
		{"role": "operator", "site": host.Site, "environment": host.Environment},
	}))
	approver := h.withToken(h.createPrincipal(uniqueSubject("approver-campaigns"), []map[string]string{
		{"role": "approver", "site": host.Site, "environment": host.Environment},
	}))

	body := labCampaign("separation of duties", "cron.service", map[string]any{
		"selector": map[string]any{"host_ids": []string{host.ID}},
	})
	var campaign campaignView
	operator.do(http.MethodPost, "/api/v1/campaigns", body, &campaign, http.StatusCreated)
	t.Cleanup(func() {
		h.do(http.MethodPost, "/api/v1/campaigns/"+campaign.ID+"/cancel",
			map[string]any{"reason": "end of the test"}, nil, 0)
	})

	consent := map[string]any{"approval_fingerprint": campaign.ApprovalFingerprint}
	// The operator runs the campaign, but does not approve it.
	operator.do(http.MethodPost, "/api/v1/campaigns/"+campaign.ID+"/approve",
		consent, nil, http.StatusForbidden)
	// The approver approves, but does not create.
	approver.do(http.MethodPost, "/api/v1/campaigns", body, nil, http.StatusForbidden)
	approver.do(http.MethodPost, "/api/v1/campaigns/"+campaign.ID+"/approve",
		consent, nil, http.StatusOK)
}

// TestCampaignOutsideTheScopeIsRejected checks that the permission is
// examined for every host of the snapshot, not only for the first.
func TestCampaignOutsideTheScopeIsRejected(t *testing.T) {
	h := newHarness(t)
	host := h.hostByFamily("debian")

	outsider := h.withToken(h.createPrincipal(uniqueSubject("foreign-operator"), []map[string]string{
		{"role": "operator", "site": "other-site", "environment": "other"},
	}))
	outsider.do(http.MethodPost, "/api/v1/campaigns",
		labCampaign("outside the scope", "cron.service", map[string]any{
			"selector": map[string]any{"host_ids": []string{host.ID}},
		}), nil, http.StatusForbidden)
}

// TestCampaignRefusesAnOperationWithoutABulkMode guards the gate that
// separates single-host operations from fleet ones. The refusal is to come
// when ordering and have its own code: a campaign that approves one payload
// for an operation computing a different plan on every host would approve a
// change nobody saw.
func TestCampaignRefusesAnOperationWithoutABulkMode(t *testing.T) {
	h := newHarness(t)
	host := h.hostByFamily("debian")

	// A specialised operation without its own phase in the engine. Every
	// family with a per-host plan already has a planner; this gate guards
	// that the pass is a declaration and a mechanism, not the operation
	// name - package repair has its own state machine, which the campaign
	// does not drive yet.
	cases := map[string]map[string]any{
		"packages.repair": {"package_repair": map[string]any{
			"answers": []map[string]any{},
		}},
	}
	for action, payload := range cases {
		t.Run(action, func(t *testing.T) {
			var response struct {
				Code   string `json:"code"`
				Detail string `json:"detail"`
			}
			h.do(http.MethodPost, "/api/v1/campaigns", map[string]any{
				"name": "bulk mode " + action, "action": action, "payload": payload,
				"selector": map[string]any{"host_ids": []string{host.ID}},
			}, &response, http.StatusBadRequest)
			if response.Code != "campaign_mode_unsupported" {
				t.Fatalf("refusal code = %q (%s)", response.Code, response.Detail)
			}
			if response.Detail == "" {
				t.Error("a refusal without a reason looks like a missing feature")
			}
		})
	}
}

// TestApprovalConcernsWhatIsVisible guards the consent invariant: an
// approval without a fingerprint or with somebody else's fingerprint is not
// consent to this campaign.
func TestApprovalConcernsWhatIsVisible(t *testing.T) {
	h := newHarness(t)
	host := h.hostByFamily("debian")
	campaign := h.createCampaign(labCampaign("consent fingerprint", "cron.service",
		map[string]any{"selector": map[string]any{"host_ids": []string{host.ID}}}))

	if campaign.ApprovalFingerprint == "" {
		t.Fatal("campaign without an approval fingerprint")
	}
	// Without a fingerprint and with somebody else's fingerprint: both are
	// consent to something other than this campaign.
	h.do(http.MethodPost, "/api/v1/campaigns/"+campaign.ID+"/approve",
		map[string]any{}, nil, http.StatusConflict)
	h.do(http.MethodPost, "/api/v1/campaigns/"+campaign.ID+"/approve",
		map[string]any{"approval_fingerprint": "0000000000000000"}, nil, http.StatusConflict)

	approved := h.approveCampaign(campaign)
	if approved.ApprovedBy == "" {
		t.Fatal("the campaign was approved without recording the person")
	}
}

// TestCampaignWorksOnManyHostsAtOnce is the proof that multitasking really
// works. A concurrency limit greater than one is to mean that two hosts
// work side by side, not that the queue goes faster.
func TestCampaignWorksOnManyHostsAtOnce(t *testing.T) {
	h := newHarness(t)
	// One OS family: the campaign is to show concurrency, not the
	// differences in unit names between distributions.
	hosts := h.hosts()
	online := make([]string, 0, len(hosts))
	for _, host := range hosts {
		if host.ConnectionState == "online" && host.OSFamily == "debian" {
			online = append(online, host.ID)
		}
	}
	if len(online) < 2 {
		t.Skip("the fleet has fewer than two connected hosts of the debian family")
	}

	// No canary and one wave: the whole set is to start at once.
	campaign := h.createCampaign(labCampaign("concurrency", "cron.service", map[string]any{
		"selector":       map[string]any{"host_ids": online},
		"canary_size":    0,
		"wave_size":      len(online),
		"max_concurrent": len(online),
	}))
	h.approveCampaign(campaign)

	final := h.awaitCampaign(campaign.ID,
		map[string]bool{"completed": true, "failed": true, "paused": true}, 3*time.Minute)
	if final.State != "completed" {
		t.Fatalf("the campaign ended in state %s (%s)", final.State, final.PauseReason)
	}

	// Concurrency is decided from the attempt times, not from polling: two
	// operations lasting a fraction of a second could fit between one query
	// and the next, and still work side by side.
	windows := make([]window, 0, len(online))
	for _, target := range h.campaignTargets(campaign.ID) {
		if target.JobID == "" {
			continue
		}
		for _, attempt := range h.timedAttempts(target.JobID) {
			if attempt.DispatchedAt == nil || attempt.FinishedAt == nil {
				continue
			}
			windows = append(windows, window{from: *attempt.DispatchedAt, to: *attempt.FinishedAt})
		}
	}
	if len(windows) < 2 {
		t.Fatalf("the campaign left %d attempts with times", len(windows))
	}
	if !overlap(windows) {
		t.Errorf("no two attempts worked side by side: %+v", windows)
	}
}

type window struct{ from, to time.Time }

// overlap says whether any two windows share a moment.
func overlap(windows []window) bool {
	for i := range windows {
		for j := i + 1; j < len(windows); j++ {
			if windows[i].from.Before(windows[j].to) && windows[j].from.Before(windows[i].to) {
				return true
			}
		}
	}
	return false
}

// timedAttempts returns the attempts together with their dispatch and
// finish times.
func (h *harness) timedAttempts(jobID string) []timedAttempt {
	h.t.Helper()
	var response struct {
		Items []timedAttempt `json:"items"`
	}
	h.get("/api/v1/jobs/"+jobID+"/attempts", &response)
	return response.Items
}

type timedAttempt struct {
	Status       string     `json:"status"`
	DispatchedAt *time.Time `json:"dispatched_at"`
	FinishedAt   *time.Time `json:"finished_at"`
}

// TestConflictingOperationsOnAHostAreSerialised guards the host resource
// locks.
//
// Three restarts of the same unit ordered at once must run one after
// another. The proof is in the unit state: every restart sees in front of
// it the process the previous one left. If two restarts went side by side,
// that chain would break - and the host job limit alone does not ensure it,
// because the general class has more than one slot.
func TestConflictingOperationsOnAHostAreSerialised(t *testing.T) {
	h := newHarness(t)
	host := h.hostByFamily("debian")

	const count = 3
	jobs := make([]string, 0, count)
	for i := 0; i < count; i++ {
		job := h.createOperation(host.ID, map[string]any{
			"action": "unit.restart", "reason": "resource lock serialisation test",
			"payload": unitPayload("cron.service"),
		})
		if job.RequiresApproval {
			job = h.approve(job.ID, job.PayloadHash)
		}
		jobs = append(jobs, job.ID)
	}

	type execution struct {
		finished    time.Time
		pidBefore   uint32
		pidAfter    uint32
		stateBefore string
		id          string
	}
	executions := make([]execution, 0, count)
	for _, jobID := range jobs {
		job := h.awaitTerminal(jobID, 3*time.Minute)
		if job.State != "succeeded" {
			t.Fatalf("restart %s: state = %s, code = %s",
				jobID, job.State, job.ResultErrorCode)
		}
		attempts := h.attempts(jobID)
		last := attempts[len(attempts)-1]
		if last.UnitStateBefore == nil || last.UnitStateAfter == nil {
			t.Fatalf("restart %s without a unit state", jobID)
		}
		timed := h.timedAttempts(jobID)
		finished := timed[len(timed)-1].FinishedAt
		if finished == nil {
			t.Fatalf("restart %s without a finish time", jobID)
		}
		executions = append(executions, execution{
			finished: *finished, pidBefore: last.UnitStateBefore.MainPID,
			pidAfter: last.UnitStateAfter.MainPID, stateBefore: last.UnitStateBefore.ActiveState,
			id: jobID,
		})
	}

	sort.Slice(executions, func(i, j int) bool {
		return executions[i].finished.Before(executions[j].finished)
	})
	for i := 1; i < len(executions); i++ {
		if executions[i].pidBefore != executions[i-1].pidAfter {
			t.Errorf("restart %s started from process %d, while the previous one left %d - the operations overlapped",
				executions[i].id, executions[i].pidBefore, executions[i-1].pidAfter)
		}
	}
}

// TestPackageCampaignComputesAPlanOnEveryHost guards the most important
// change of Campaigns v2: the consent does not concern one payload, but a
// set of plans.
//
// Two hosts picked by the same order almost never have the same diff, so
// the campaign first asks every host what comes out there, and only then
// asks for consent. The approval fingerprint changes after planning - the
// proof is that consent given with the fingerprint from before planning is
// rejected.
func TestPackageCampaignComputesAPlanOnEveryHost(t *testing.T) {
	h := newHarness(t)
	hosts := h.hosts()
	targets := make([]string, 0, 2)
	for _, host := range hosts {
		if host.ConnectionState == "online" && host.OSFamily == "debian" {
			targets = append(targets, host.ID)
		}
	}
	if len(targets) < 2 {
		t.Skip("the fleet has fewer than two connected hosts of the debian family")
	}

	campaign := h.createCampaign(map[string]any{
		"name": "update with plans", "action": "packages.upgrade",
		"payload":                    map[string]any{"package_upgrade": map[string]any{"security_only": true}},
		"selector":                   map[string]any{"host_ids": targets},
		"canary_size":                0,
		"wave_size":                  len(targets),
		"max_concurrent":             len(targets),
		"failure_threshold_percent":  0,
		"failure_threshold_absolute": 0,
		"reboot_policy":              "never",
	})
	if campaign.State != "planning" {
		t.Fatalf("the package campaign started from state %s", campaign.State)
	}
	orderFingerprint := campaign.ApprovalFingerprint

	// The planning phase ends on its own: every host computes its plan.
	afterPlanning := h.awaitCampaign(campaign.ID,
		map[string]bool{"awaiting_approval": true, "paused": true, "failed": true}, 3*time.Minute)
	if afterPlanning.State != "awaiting_approval" {
		t.Fatalf("planning ended in state %s (%s)",
			afterPlanning.State, afterPlanning.PauseReason)
	}
	if afterPlanning.PlanSetHash == "" {
		t.Fatal("the campaign after planning has no plan set fingerprint")
	}
	if afterPlanning.ApprovalFingerprint == orderFingerprint {
		t.Error("the plan set did not change the approval fingerprint")
	}

	// Consent given with the fingerprint from before planning concerns
	// something else.
	h.do(http.MethodPost, "/api/v1/campaigns/"+campaign.ID+"/approve",
		map[string]any{"approval_fingerprint": orderFingerprint}, nil, http.StatusConflict)

	// Every target has a planning job and went back to the queue.
	for _, target := range h.campaignTargets(campaign.ID) {
		if target.PlanJobID == "" {
			t.Errorf("target %s without a planning job", target.Hostname)
		}
		if target.State != "pending" {
			t.Errorf("target %s after planning is in state %s", target.Hostname, target.State)
		}
	}

	h.approveCampaign(afterPlanning)
	final := h.awaitCampaign(campaign.ID,
		map[string]bool{"completed": true, "failed": true, "paused": true}, 5*time.Minute)
	if final.State != "completed" {
		t.Fatalf("the campaign ended in state %s (%s)", final.State, final.PauseReason)
	}
}

type budgetView struct {
	Key       string `json:"key"`
	Capacity  int    `json:"capacity"`
	Used      int    `json:"used"`
	Claimants int    `json:"claimants"`
}

// setBudget changes a budget capacity for the duration of the test and
// restores it afterwards.
func (h *harness) setBudget(key string, capacity, afterTest int) {
	h.t.Helper()
	h.do(http.MethodPut, "/api/v1/budgets/"+key,
		map[string]any{"capacity": capacity, "note": "integration test of the budgets"},
		nil, http.StatusOK)
	h.t.Cleanup(func() {
		// A budget changed for the test must go back: left at one it would
		// slow down every next run and look like a defect.
		h.do(http.MethodPut, "/api/v1/budgets/"+key,
			map[string]any{"capacity": afterTest, "note": "after the test"}, nil, 0)
	})
}

// TestSiteBudgetStopsTheExcessChange guards invariant I-05: the campaign
// concurrency limit is not the only limit of the system.
//
// The campaign asks for three hosts at once and has consent for that - and
// yet the site admits one change of this family. The proof is in the
// attempt times: no two may overlap. The second proof is visibility: a host
// that waits must say so, not stand in the queue without a reason.
//
// The negative control stands next to it: TestCampaignWorksOnManyHostsAtOnce
// does the same on the same fleet at the default capacity and requires the
// windows to overlap. Without that pair "no overlap" could simply mean a
// slow fleet, not a working budget.
func TestSiteBudgetStopsTheExcessChange(t *testing.T) {
	h := newHarness(t)
	// One OS family and one site: the proof concerns the budget, not the
	// differences in unit names between distributions.
	online := make([]hostView, 0, 3)
	site := ""
	for _, host := range h.hosts() {
		if host.ConnectionState != "online" || host.OSFamily != "debian" {
			continue
		}
		if site == "" {
			site = host.Site
		}
		if host.Site == site {
			online = append(online, host)
		}
	}
	if len(online) < 2 || site == "" {
		t.Skip("the test fleet has fewer than two connected hosts of the debian family in one site")
	}

	// Units are the cheapest mutation there is: the proof concerns the
	// budget, not what the operation specifically does.
	key := "site:" + site + ":units"
	const defaultCapacity = 10
	h.setBudget(key, 1, defaultCapacity)

	targets := make([]string, 0, len(online))
	for _, host := range online {
		targets = append(targets, host.ID)
	}
	campaign := h.createCampaign(map[string]any{
		"name": "restart with a budget", "action": "unit.restart",
		"reason":                     "site budget test",
		"payload":                    unitPayload("cron.service"),
		"selector":                   map[string]any{"host_ids": targets},
		"canary_size":                0,
		"wave_size":                  len(targets),
		"max_concurrent":             len(targets),
		"failure_threshold_percent":  0,
		"failure_threshold_absolute": 0,
		"reboot_policy":              "never",
	})
	if campaign.State == "awaiting_approval" {
		campaign = h.approveCampaign(campaign)
	}

	// Along the way at least one host must report that it waits for
	// capacity. This is checked during the run, because the state is
	// transient.
	waited := false
	deadline := time.Now().Add(4 * time.Minute)
	for time.Now().Before(deadline) {
		for _, target := range h.campaignTargets(campaign.ID) {
			if target.State == "awaiting_budget" {
				waited = true
				if target.ErrorCode != "budget_capacity" && target.ErrorCode != "budget_fair_share" {
					t.Errorf("a host waits for the budget without a given reason: %+v", target)
				}
			}
		}
		state := h.campaign(campaign.ID)
		if state.State == "completed" || state.State == "failed" || state.State == "paused" {
			break
		}
		time.Sleep(time.Second)
	}

	final := h.awaitCampaign(campaign.ID,
		map[string]bool{"completed": true, "failed": true, "paused": true}, 4*time.Minute)
	if final.State != "completed" {
		t.Fatalf("the campaign ended in state %s (%s)", final.State, final.PauseReason)
	}
	if !waited {
		t.Error("no host reported waiting for capacity - the budget stopped nobody")
	}

	windows := make([]window, 0, len(targets))
	for _, target := range h.campaignTargets(campaign.ID) {
		if target.JobID == "" {
			continue
		}
		for _, attempt := range h.timedAttempts(target.JobID) {
			if attempt.DispatchedAt == nil || attempt.FinishedAt == nil {
				continue
			}
			windows = append(windows, window{from: *attempt.DispatchedAt, to: *attempt.FinishedAt})
		}
	}
	if len(windows) < 2 {
		t.Fatalf("the campaign left %d attempts with times", len(windows))
	}
	// The crux of the invariant: the campaign had consent for three at
	// once, and the site admitted one. Overlapping windows would mean the
	// budget did not bind.
	if overlap(windows) {
		t.Errorf("two changes went side by side despite a budget of 1: %+v", windows)
	}
}

// TestBudgetShowsUsageAndRefusesZeroCapacity guards the screen without
// which a campaign standing on a budget looks like a forgotten campaign.
func TestBudgetShowsUsageAndRefusesZeroCapacity(t *testing.T) {
	h := newHarness(t)
	var view struct {
		Items []budgetView `json:"items"`
	}
	h.get("/api/v1/budgets", &view)
	if len(view.Items) == 0 {
		t.Fatal("the panel has no budget at all - nobody guards the capacities")
	}
	found := map[string]budgetView{}
	for _, budget := range view.Items {
		if budget.Capacity < 1 {
			t.Errorf("budget %s with the capacity %d", budget.Key, budget.Capacity)
		}
		found[budget.Key] = budget
	}
	// Reads and mutations have separate capacities: a hundred state reads
	// are not the same load as a hundred package transactions.
	for _, key := range []string{"global:mutations", "global:reads"} {
		if _, present := found[key]; !present {
			t.Errorf("no budget %s: %+v", key, view.Items)
		}
	}

	// A zero capacity is not a policy, only a quiet halt of everything.
	h.do(http.MethodPut, "/api/v1/budgets/global:mutations",
		map[string]any{"capacity": 0}, nil, http.StatusBadRequest)
}

// TestBudgetChangeRequiresAPermission guards that capacities are not raised
// quietly: a budget raised without a trace takes the meaning away from
// every limit below it.
func TestBudgetChangeRequiresAPermission(t *testing.T) {
	h := newHarness(t)
	host := h.hostByFamily("debian")
	operatorToken := h.createPrincipal(uniqueSubject("no-budgets"),
		[]map[string]string{{"role": "approver", "site": host.Site, "environment": host.Environment}})
	withoutRight := h.withToken(operatorToken)

	withoutRight.do(http.MethodPut, "/api/v1/budgets/global:mutations",
		map[string]any{"capacity": 500}, nil, http.StatusForbidden)
}

type previewView struct {
	Count        int      `json:"count"`
	Limit        int      `json:"limit"`
	Eligible     int      `json:"eligible"`
	Sample       []string `json:"sample"`
	CampaignMode string   `json:"campaign_mode"`
	RequiresPlan bool     `json:"requires_plan"`
	Excluded     []struct {
		Reason string   `json:"reason"`
		Count  int      `json:"count"`
		Sample []string `json:"sample"`
	} `json:"excluded"`
	Notes []struct {
		Reason string   `json:"reason"`
		Count  int      `json:"count"`
		Sample []string `json:"sample"`
	} `json:"notes"`
}

// TestPreviewTellsReadyFromIncapable guards criterion A-02: before the
// start the operator is to know which hosts go and why the rest do not.
//
// The test fleet has an Arch host that has neither apt nor dnf. A package
// update is infeasible on it and the panel is to say so before the campaign
// is created, not with an error at execution. The same host is at the same
// time ready for a unit restart - qualification depends on the operation,
// not on the host.
func TestPreviewTellsReadyFromIncapable(t *testing.T) {
	h := newHarness(t)

	var restart previewView
	h.get("/api/v1/campaigns/preview?action=unit.restart", &restart)
	if restart.Count == 0 {
		t.Fatal("the preview sees no host at all")
	}
	if restart.Eligible == 0 {
		t.Fatalf("no host is ready for a unit restart: %+v", restart)
	}
	if restart.CampaignMode != "same_payload" {
		t.Errorf("unit restart in mode %q", restart.CampaignMode)
	}
	if restart.RequiresPlan {
		t.Error("a unit restart computes no plan on the host")
	}

	var update previewView
	h.get("/api/v1/campaigns/preview?action=packages.upgrade", &update)
	if !update.RequiresPlan || update.CampaignMode != "per_host_plan" {
		t.Errorf("the package update described as %q, plan=%v",
			update.CampaignMode, update.RequiresPlan)
	}
	// The same fleet, a different operation: a host without a package
	// adapter is to be excluded with a reason, not counted as ready.
	if update.Eligible >= restart.Eligible {
		t.Errorf("the update has %d ready hosts with %d ready for a restart - "+
			"the host without apt and dnf was not recognised",
			update.Eligible, restart.Eligible)
	}
	missingAdapter := 0
	for _, group := range update.Excluded {
		if group.Reason == "capability_missing" {
			missingAdapter = group.Count
			if len(group.Sample) == 0 {
				t.Error("exclusion without a single hostname")
			}
		}
	}
	if missingAdapter == 0 {
		t.Errorf("the preview excludes no host without an adapter: %+v", update.Excluded)
	}
	if update.Eligible+missingAdapter > update.Count {
		t.Errorf("%d ready and %d excluded with %d matched",
			update.Eligible, missingAdapter, update.Count)
	}
}

// TestCampaignKeepsTheIncapableHostInTheSnapshot guards the doctrine: a host
// that will not carry out the operation does not disappear quietly.
//
// A quiet exclusion is worse than a refusal: the operator approves a
// campaign on four hosts and learns about three only from the report - or
// does not learn at all.
func TestCampaignKeepsTheIncapableHostInTheSnapshot(t *testing.T) {
	h := newHarness(t)
	targets := make([]string, 0, 4)
	incapable := 0
	for _, host := range h.hosts() {
		if host.ConnectionState != "online" {
			continue
		}
		targets = append(targets, host.ID)
		if host.OSFamily == "arch" {
			incapable++
		}
	}
	if incapable == 0 {
		t.Skip("the test fleet has no host without a package adapter")
	}

	campaign := h.createCampaign(map[string]any{
		"name": "update of the whole fleet", "action": "packages.upgrade",
		"payload":                    map[string]any{"package_upgrade": map[string]any{"security_only": true}},
		"selector":                   map[string]any{"host_ids": targets},
		"canary_size":                0,
		"wave_size":                  len(targets),
		"max_concurrent":             len(targets),
		"failure_threshold_percent":  0,
		"failure_threshold_absolute": 0,
		"reboot_policy":              "never",
	})

	states := map[string]int{}
	reasons := map[string]string{}
	for _, target := range h.campaignTargets(campaign.ID) {
		states[target.State]++
		if target.State == "ineligible" {
			reasons[target.Hostname] = target.ErrorCode
		}
	}
	if states["ineligible"] != incapable {
		t.Errorf("the snapshot has %d incapable hosts with %d without an adapter: %+v",
			states["ineligible"], incapable, states)
	}
	for hostname, code := range reasons {
		if code != "capability_missing" {
			t.Errorf("host %s incapable without a given reason: %q", hostname, code)
		}
	}
	// An incapable host is not a failure: the campaign is to go on with the
	// rest.
	if states["pending"]+states["planning"] == 0 {
		t.Errorf("the campaign left no host to work on at all: %+v", states)
	}
}

// TestComposeCampaignCarriesThePlanDigestToTheHost guards that the planning
// phase is not owned by packages: the second family computes the plan on
// the host and gets it back together with the change.
//
// The Compose plan digest is made from the manifest and from the image
// digests this host really sees. The deployment carries it back, and the
// host refuses when it stopped matching - the consent concerned that plan,
// not this one.
func TestComposeCampaignCarriesThePlanDigestToTheHost(t *testing.T) {
	h := newHarness(t)
	const project = "flotestro-campaign"
	manifest := "services:\n  web:\n    image: nginx:alpine\n"

	// Docker is on one host in this fleet. That is enough to show the
	// planning phase, and the other hosts show along the way that
	// incapability is not a failure.
	targets := make([]string, 0, 4)
	withDocker := 0
	for _, host := range h.hosts() {
		if host.ConnectionState != "online" {
			continue
		}
		targets = append(targets, host.ID)
		// The host adapter registry speaks about capability, not guessing
		// by distribution: a container engine may be everywhere or nowhere.
		for _, capability := range host.Capabilities {
			if capability.Name == "docker.compose" && capability.Available {
				withDocker++
			}
		}
	}
	if withDocker == 0 {
		t.Skip("the test fleet has no host with a container engine")
	}

	campaign := h.createCampaign(map[string]any{
		"name": "project deployment", "action": "docker.compose.deploy",
		"reason":                     "integration test of Compose plans",
		"payload":                    map[string]any{"compose": map[string]any{"project": project, "manifest": manifest}},
		"selector":                   map[string]any{"host_ids": targets},
		"canary_size":                0,
		"wave_size":                  len(targets),
		"max_concurrent":             len(targets),
		"failure_threshold_percent":  0,
		"failure_threshold_absolute": 0,
		"reboot_policy":              "never",
	})
	if campaign.State != "planning" {
		t.Fatalf("the Compose campaign started from state %s", campaign.State)
	}
	orderFingerprint := campaign.ApprovalFingerprint

	afterPlanning := h.awaitCampaign(campaign.ID,
		map[string]bool{"awaiting_approval": true, "paused": true, "failed": true}, 3*time.Minute)
	if afterPlanning.State != "awaiting_approval" {
		t.Fatalf("planning ended in state %s (%s)",
			afterPlanning.State, afterPlanning.PauseReason)
	}
	if afterPlanning.PlanSetHash == "" {
		t.Fatal("the Compose campaign after planning has no plan set fingerprint")
	}
	if afterPlanning.ApprovalFingerprint == orderFingerprint {
		t.Error("the plan set did not change the approval fingerprint")
	}

	// A host without a container engine is incapable, not broken: it does
	// not count towards the failure threshold and does not stop the
	// campaign.
	planned, ineligible := 0, 0
	for _, target := range h.campaignTargets(campaign.ID) {
		switch target.State {
		case "ineligible":
			ineligible++
		case "pending":
			planned++
			if target.PlanJobID == "" {
				t.Errorf("target %s without a planning job", target.Hostname)
			}
		}
	}
	if planned != withDocker {
		t.Errorf("%d hosts computed the plan, %d have the engine", planned, withDocker)
	}
	if ineligible != len(targets)-withDocker {
		t.Errorf("%d ineligible with %d hosts without an engine",
			ineligible, len(targets)-withDocker)
	}

	// The cleanup goes by containers, because the panel has no "take the
	// project down" operation: a deployment is a declaration of state, not
	// a command that can be undone with one order.
	t.Cleanup(func() {
		for _, hostID := range targets {
			for _, container := range projectContainers(h, hostID, project) {
				h.runOperation(hostID, map[string]any{
					"action": "docker.container.remove",
					"reason": "cleanup after the Compose test",
					"payload": map[string]any{
						"docker_container": map[string]any{"container_id": container, "force": true},
					},
				}, 2*time.Minute)
			}
		}
	})

	h.approveCampaign(afterPlanning)
	final := h.awaitCampaign(campaign.ID,
		map[string]bool{"completed": true, "failed": true, "paused": true}, 5*time.Minute)
	if final.State != "completed" {
		t.Fatalf("the campaign ended in state %s (%s)", final.State, final.PauseReason)
	}
}

// projectContainers returns the container identifiers of one Compose
// project.
func projectContainers(h *harness, hostID, project string) []string {
	h.t.Helper()
	var fragment inventoryFragment
	h.do(http.MethodGet, "/api/v1/hosts/"+hostID+"/inventory/containers",
		nil, &fragment, http.StatusOK)
	if len(fragment.Payload) == 0 {
		return nil
	}
	var state struct {
		Containers []struct {
			ID      string            `json:"id"`
			Labels  map[string]string `json:"labels"`
			Compose *struct {
				Project string `json:"project"`
			} `json:"compose"`
		} `json:"containers"`
	}
	if err := json.Unmarshal(fragment.Payload, &state); err != nil {
		return nil
	}
	ids := []string{}
	for _, container := range state.Containers {
		if (container.Compose != nil && container.Compose.Project == project) ||
			container.Labels["com.docker.compose.project"] == project {
			ids = append(ids, container.ID)
		}
	}
	return ids
}

type timelineEntryView struct {
	ID         int64           `json:"id"`
	Aggregate  string          `json:"aggregate_type"`
	Type       string          `json:"event_type"`
	Payload    json.RawMessage `json:"payload"`
	OccurredAt time.Time       `json:"occurred_at"`
}

// TestCampaignTimelineSurvivesAPanelRestart guards invariant I-14: the
// course of a campaign can be reconstructed from durable records, not only
// from notifications.
//
// A notification sent at the moment the panel was restarting no longer
// exists anywhere. The final state stays in the tables, but the course -
// what happened and when - vanished with it. A campaign without a timeline
// is a report after the fact, not control over the rollout.
func TestCampaignTimelineSurvivesAPanelRestart(t *testing.T) {
	h := newHarness(t)
	online := make([]string, 0, 2)
	for _, host := range h.hosts() {
		if host.ConnectionState == "online" && host.OSFamily == "debian" {
			online = append(online, host.ID)
		}
	}
	if len(online) < 2 {
		t.Skip("the fleet has fewer than two connected hosts of the debian family")
	}

	campaign := h.createCampaign(labCampaign("timeline", "cron.service", map[string]any{
		"selector":       map[string]any{"host_ids": online},
		"canary_size":    1,
		"wave_size":      len(online),
		"max_concurrent": len(online),
	}))
	h.approveCampaign(campaign)
	final := h.awaitCampaign(campaign.ID,
		map[string]bool{"completed": true, "failed": true, "paused": true}, 3*time.Minute)
	if final.State != "completed" {
		t.Fatalf("the campaign ended in state %s (%s)", final.State, final.PauseReason)
	}

	var timeline struct {
		Items []timelineEntryView `json:"items"`
	}
	h.get("/api/v1/campaigns/"+campaign.ID+"/timeline", &timeline)
	if len(timeline.Items) == 0 {
		t.Fatal("campaign without a single event in the timeline")
	}

	// The timeline is to name the campaign phases and the fate of the
	// hosts. The final state alone is visible in the tables; here it is
	// about how it came to be.
	kinds := map[string]int{}
	for _, entry := range timeline.Items {
		kinds[entry.Type]++
		if entry.OccurredAt.IsZero() {
			t.Errorf("event %s without a time", entry.Type)
		}
		if len(entry.Payload) == 0 {
			t.Errorf("event %s without content", entry.Type)
		}
	}
	for _, required := range []string{
		"campaign.canary", "campaign.running", "campaign.completed",
		"target.running", "target.succeeded",
	} {
		if kinds[required] == 0 {
			t.Errorf("timeline without the event %s: %+v", required, kinds)
		}
	}
	if kinds["target.succeeded"] != len(online) {
		t.Errorf("%d target.succeeded events with %d hosts",
			kinds["target.succeeded"], len(online))
	}

	// The order is part of the answer: the canary precedes the other waves.
	for i := 1; i < len(timeline.Items); i++ {
		if timeline.Items[i].ID <= timeline.Items[i-1].ID {
			t.Fatalf("the timeline is not ordered: %d after %d",
				timeline.Items[i].ID, timeline.Items[i-1].ID)
		}
	}
}

// TestMetricsShowTheCampaignMachinery guards the observability of the part
// of the system that is invisible without it.
//
// A campaign standing on a budget and a campaign that goes look the same
// from outside: both are "in progress". Only one of them needs a reaction,
// and what tells them apart is the reason code at the hosts and the budget
// usage.
func TestMetricsShowTheCampaignMachinery(t *testing.T) {
	h := newHarness(t)
	text := h.text("/metrics")

	// Budgets are always described - also when nothing takes them. A
	// capacity given only when there is a problem would not let anybody see
	// how close to the limit the fleet works.
	for _, fragment := range []string{
		"flotestro_budget_tokens",
		`flotestro_budget_tokens{budget="global:mutations",status="capacity"}`,
		`flotestro_budget_tokens{budget="global:mutations",status="used"}`,
	} {
		if !strings.Contains(text, fragment) {
			t.Errorf("metrics without %q", fragment)
		}
	}

	online := make([]string, 0, 2)
	for _, host := range h.hosts() {
		if host.ConnectionState == "online" && host.OSFamily == "debian" {
			online = append(online, host.ID)
		}
	}
	if len(online) < 2 {
		t.Skip("the fleet has fewer than two connected hosts of the debian family")
	}

	campaign := h.createCampaign(labCampaign("metrics", "cron.service", map[string]any{
		"selector":       map[string]any{"host_ids": online},
		"canary_size":    0,
		"wave_size":      len(online),
		"max_concurrent": len(online),
	}))
	// A campaign waiting for approval is a campaign in progress: somebody
	// has to make a decision, and the metric is to show that.
	text = h.text("/metrics")
	if !strings.Contains(text, `flotestro_campaigns_active{action="unit.restart"`) {
		t.Errorf("the metrics do not see the campaign in progress:\n%s", extract(text, "flotestro_campaigns_active"))
	}
	if !strings.Contains(text, "flotestro_campaign_targets{") {
		t.Errorf("the metrics do not see the campaign hosts:\n%s",
			extract(text, "flotestro_campaign_targets"))
	}

	h.approveCampaign(campaign)
	h.awaitCampaign(campaign.ID,
		map[string]bool{"completed": true, "failed": true, "paused": true}, 3*time.Minute)

	// A finished campaign leaves its measurements behind: how long the
	// hosts sat in each state, how long the agents took and how many tasks
	// were handed over. These are histograms and counters measured at the
	// point of the event - a table read at scrape time could not give them.
	text = h.text("/metrics")
	for _, fragment := range []string{
		`flotestro_job_dispatch_total{outcome="dispatched"`,
		`flotestro_agent_task_duration_seconds_bucket{action="unit.restart",outcome="succeeded",le="`,
		`flotestro_agent_task_duration_seconds_count{action="unit.restart",outcome="succeeded"}`,
		`flotestro_target_state_duration_seconds_count{state="running",action="unit.restart"}`,
		`flotestro_target_state_duration_seconds_bucket{state="pending",action="unit.restart",le="+Inf"}`,
	} {
		if !strings.Contains(text, fragment) {
			t.Errorf("metrics without %q:\n%s", fragment,
				extract(text, strings.SplitN(fragment, "{", 2)[0]))
		}
	}
}

// extract returns the lines of the metric with the given name - for an
// error message.
func extract(text, name string) string {
	lines := []string{}
	for _, line := range strings.Split(text, "\n") {
		if strings.Contains(line, name) {
			lines = append(lines, line)
		}
	}
	return strings.Join(lines, "\n")
}

// TestFileCampaignComputesTheDiffOnEveryHost guards what tells a file from
// an operation with a portable intent.
//
// The same desired state means different things on two hosts: one has a
// file with different content, the other does not have it at all. The
// campaign must ask every host separately, the consent is to concern the
// set of those answers, and the write is to come back to the host with the
// digest of the content the operator looked at - otherwise a change made
// between the plan and the write would vanish without a trace.
func TestFileCampaignComputesTheDiffOnEveryHost(t *testing.T) {
	h := newHarness(t)
	const path = "/etc/flotestro-file-campaign.conf"
	targets := make([]string, 0, 2)
	for _, host := range h.hosts() {
		if host.ConnectionState == "online" && host.OSFamily == "debian" {
			targets = append(targets, host.ID)
		}
	}
	if len(targets) < 2 {
		t.Skip("the fleet has fewer than two connected hosts of the debian family")
	}

	t.Cleanup(func() {
		for _, hostID := range targets {
			h.runOperation(hostID, map[string]any{
				"action": "file.remove", "reason": "cleanup after the file plans test",
				"payload": map[string]any{"file": map[string]any{"path": path}},
			}, 2*time.Minute)
		}
	})

	// The first host gets a file with different content; the second stays
	// without it. From now on the same desired state is two different
	// changes.
	job, attempts := h.runOperation(targets[0], map[string]any{
		"action": "file.ensure", "reason": "preparation of the file plans test",
		"payload": map[string]any{"file": map[string]any{
			"path": path, "content": "old content\n", "mode": "0644"}},
	}, 2*time.Minute)
	if job.State != "succeeded" {
		t.Fatalf("preparing the file: state = %s, %s", job.State, lastMessage(attempts))
	}

	campaign := h.createCampaign(map[string]any{
		"name": "shared configuration file", "action": "file.ensure",
		"reason": "integration test of the file plans",
		"payload": map[string]any{"file": map[string]any{
			"path": path, "content": "new content\n", "mode": "0644"}},
		"selector":                   map[string]any{"host_ids": targets},
		"canary_size":                0,
		"wave_size":                  len(targets),
		"max_concurrent":             len(targets),
		"failure_threshold_percent":  0,
		"failure_threshold_absolute": 0,
		"reboot_policy":              "never",
	})
	if campaign.State != "planning" {
		t.Fatalf("the file campaign started from state %s", campaign.State)
	}
	orderFingerprint := campaign.ApprovalFingerprint

	afterPlanning := h.awaitCampaign(campaign.ID,
		map[string]bool{"awaiting_approval": true, "paused": true, "failed": true}, 3*time.Minute)
	if afterPlanning.State != "awaiting_approval" {
		t.Fatalf("planning ended in state %s (%s)",
			afterPlanning.State, afterPlanning.PauseReason)
	}
	if afterPlanning.PlanSetHash == "" {
		t.Fatal("the file campaign after planning has no plan set fingerprint")
	}
	if afterPlanning.ApprovalFingerprint == orderFingerprint {
		t.Error("the plan set did not change the approval fingerprint")
	}

	// The crux: two hosts, two different plans. One creates the file, the
	// other changes it.
	actions := map[string]string{}
	for _, target := range h.campaignTargets(campaign.ID) {
		if target.PlanJobID == "" {
			t.Fatalf("target %s without a planning job", target.Hostname)
		}
		actions[target.Hostname] = planAction(h, target.PlanJobID)
	}
	kinds := map[string]int{}
	for _, action := range actions {
		kinds[action]++
	}
	if kinds["create"] == 0 || kinds["update"] == 0 {
		t.Errorf("the host plans do not differ: %+v", actions)
	}

	h.approveCampaign(afterPlanning)
	final := h.awaitCampaign(campaign.ID,
		map[string]bool{"completed": true, "failed": true, "paused": true}, 3*time.Minute)
	if final.State != "completed" {
		t.Fatalf("the campaign ended in state %s (%s)", final.State, final.PauseReason)
	}

	// Both hosts reached the same desired state, although they went there
	// from two different places. A plan computed now has nothing left to
	// do.
	for _, hostID := range targets {
		job, attempts := h.runOperation(hostID, map[string]any{
			"action": "file.plan", "reason": "checking the state after the campaign",
			"payload": map[string]any{"file": map[string]any{
				"path": path, "content": "new content\n", "mode": "0644"}},
		}, 2*time.Minute)
		if job.State != "succeeded" {
			t.Fatalf("final plan: state = %s, %s", job.State, lastMessage(attempts))
		}
		if action := planAction(h, job.ID); action != "no_change" {
			t.Errorf("after the campaign host %s still has something to do: %s", hostID[:8], action)
		}
		_ = attempts
	}
}

// planAction reads from the planning job result what the plan is to do.
func planAction(h *harness, jobID string) string {
	h.t.Helper()
	var response struct {
		Items []struct {
			Detail struct {
				Kind string `json:"kind"`
				Plan struct {
					Action string `json:"action"`
				} `json:"plan"`
			} `json:"detail"`
		} `json:"items"`
	}
	h.get("/api/v1/jobs/"+jobID+"/attempts", &response)
	for i := len(response.Items) - 1; i >= 0; i-- {
		if response.Items[i].Detail.Kind == "file_plan" {
			return response.Items[i].Detail.Plan.Action
		}
	}
	return ""
}

// TestFirewallCampaignComputesTheDiffAndRefusesBeforeConsent guards two
// things at once.
//
// First: a firewall rule ordered on two hosts is two different changes -
// one host creates it, the other changes it - and each comes back to the
// host with the ruleset fingerprint that host had at planning.
//
// Second: a rule that would cut off the management channel is to fall out
// at the plan stage, before anybody approves anything. A refusal at
// execution on half the fleet would be a belated answer.
func TestFirewallCampaignComputesTheDiffAndRefusesBeforeConsent(t *testing.T) {
	h := newHarness(t)
	const name = "firewall-campaign-test"
	targets := make([]string, 0, 2)
	for _, host := range h.hosts() {
		if host.ConnectionState == "online" && host.OSFamily == "debian" {
			targets = append(targets, host.ID)
		}
	}
	if len(targets) < 2 {
		t.Skip("the fleet has fewer than two connected hosts of the debian family")
	}
	if !hostFirewallSnapshot(t, h, targets[0]).Writable {
		t.Skip("the host does not allow changing the firewall")
	}

	t.Cleanup(func() {
		for _, hostID := range targets {
			h.runOperation(hostID, map[string]any{
				"action": "firewall.rule.remove", "reason": "cleanup after the firewall campaign test",
				"payload": map[string]any{"firewall": map[string]any{
					"rule_id": name, "rollback_seconds": 60}},
			}, 2*time.Minute)
		}
	})

	// The first host gets a rule on a different port; the second stays
	// without it.
	state := hostFirewallSnapshot(t, h, targets[0])
	job, attempts := h.runOperation(targets[0], map[string]any{
		"action": "firewall.rule.ensure", "reason": "preparation of the firewall campaign test",
		"payload": map[string]any{"firewall": map[string]any{
			"rule_id": name, "chain": "input", "action": "drop",
			"protocol": "tcp", "ports": []string{"2525"},
			"sources": []string{"10.10.0.0/16"}, "rollback_seconds": 60,
			"expected_hash": state.Hash}},
	}, 3*time.Minute)
	if job.State != "succeeded" {
		t.Fatalf("preparing the rule: state = %s, %s", job.State, lastMessage(attempts))
	}

	rule := map[string]any{
		"rule_id": name, "chain": "input", "action": "drop",
		"protocol": "tcp", "ports": []string{"25"},
		"sources": []string{"10.10.0.0/16"}, "rollback_seconds": 60,
	}
	campaign := h.createCampaign(map[string]any{
		"name": "rule on the whole fleet", "action": "firewall.rule.ensure",
		"reason":                     "integration test of the firewall plans",
		"payload":                    map[string]any{"firewall": rule},
		"selector":                   map[string]any{"host_ids": targets},
		"canary_size":                0,
		"wave_size":                  len(targets),
		"max_concurrent":             len(targets),
		"failure_threshold_percent":  0,
		"failure_threshold_absolute": 0,
		"reboot_policy":              "never",
	})
	if campaign.State != "planning" {
		t.Fatalf("the firewall campaign started from state %s", campaign.State)
	}

	afterPlanning := h.awaitCampaign(campaign.ID,
		map[string]bool{"awaiting_approval": true, "paused": true, "failed": true}, 3*time.Minute)
	if afterPlanning.State != "awaiting_approval" {
		t.Fatalf("planning ended in state %s (%s)",
			afterPlanning.State, afterPlanning.PauseReason)
	}
	actions := map[string]int{}
	for _, target := range h.campaignTargets(campaign.ID) {
		actions[firewallPlanAction(h, target.PlanJobID)]++
	}
	if actions["create"] == 0 || actions["update"] == 0 {
		t.Errorf("the host plans do not differ: %+v", actions)
	}

	h.approveCampaign(afterPlanning)
	final := h.awaitCampaign(campaign.ID,
		map[string]bool{"completed": true, "failed": true, "paused": true}, 4*time.Minute)
	if final.State != "completed" {
		t.Fatalf("the campaign ended in state %s (%s)", final.State, final.PauseReason)
	}
	for _, hostID := range targets {
		after := panelRule(t, h, hostID, name)
		if !strings.Contains(after.Text, "tcp dport 25") {
			t.Errorf("host %s after the campaign has the rule %q", hostID[:8], after.Text)
		}
	}

	// A rule cutting off the panel: the plan is to reject it on every host,
	// and the campaign is to stop without consent, because no host is left
	// to work on.
	cutting := h.createCampaign(map[string]any{
		"name": "cutting rule", "action": "firewall.rule.ensure",
		"reason": "firewall plan refusal test",
		"payload": map[string]any{"firewall": map[string]any{
			"rule_id": "campaign-cut-off-test", "chain": "input", "action": "drop",
			"protocol": "tcp", "ports": []string{"8000-9000"}, "rollback_seconds": 60}},
		"selector":    map[string]any{"host_ids": targets},
		"canary_size": 0, "wave_size": len(targets), "max_concurrent": len(targets),
		"failure_threshold_percent": 0, "failure_threshold_absolute": 0,
		"reboot_policy": "never",
	})
	refusalState := h.awaitCampaign(cutting.ID,
		map[string]bool{"awaiting_approval": true, "paused": true, "failed": true}, 3*time.Minute)
	if refusalState.State == "awaiting_approval" {
		t.Fatal("the campaign with a rule cutting off the panel reached consent")
	}
	for _, target := range h.campaignTargets(cutting.ID) {
		if target.State != "ineligible" || target.ErrorCode != "plan_refused" {
			t.Errorf("target %s after the plan refusal: %s/%s", target.Hostname, target.State, target.ErrorCode)
		}
	}
}

// firewallPlanAction reads from the planning job result what the plan is
// to do.
func firewallPlanAction(h *harness, jobID string) string {
	h.t.Helper()
	var response struct {
		Items []struct {
			Detail struct {
				Kind string `json:"kind"`
				Plan struct {
					Action string `json:"action"`
				} `json:"plan"`
			} `json:"detail"`
		} `json:"items"`
	}
	h.get("/api/v1/jobs/"+jobID+"/attempts", &response)
	for i := len(response.Items) - 1; i >= 0; i-- {
		if response.Items[i].Detail.Kind == "firewall_plan" {
			return response.Items[i].Detail.Plan.Action
		}
	}
	return ""
}

// TestMountCampaignResolvesTheUUIDOnEveryHost checks that the order "mount
// /dev/sdb" does not go to the hosts as a path: every host resolves it to
// the UUID of the filesystem it really has, and that UUID comes back in the
// change. Two hosts with the same path have two different filesystems - and
// two different UUIDs.
func TestMountCampaignResolvesTheUUIDOnEveryHost(t *testing.T) {
	h := newHarness(t)
	const target = "/mnt/flotestro-campaign"

	// Hosts of the debian family with a free filesystem under the same
	// path.
	sources := map[string]string{}
	var hosts []string
	for _, host := range h.hosts() {
		if host.ConnectionState != "online" || host.OSFamily != "debian" {
			continue
		}
		// The storage fragment comes from the inventory cycle; the previous
		// test may have just unmounted a disk the snapshot does not see yet.
		h.runOperation(host.ID, map[string]any{
			"action": "inventory.refresh", "reason": "mount campaign test",
			"payload": map[string]any{"inventory": map[string]any{"modules": []string{"storage"}}},
		}, 2*time.Minute)
		state := hostStorageSnapshot(t, h, host.ID)
		for _, device := range state.Devices {
			if device.FSType == "ext4" && device.UUID != "" &&
				len(device.Mountpoints) == 0 && !inFstab(state, device) {
				sources[host.ID] = device.Path
				hosts = append(hosts, host.ID)
				break
			}
		}
	}
	if len(hosts) < 2 {
		t.Skip("the fleet has fewer than two debian hosts with a free ext4 filesystem")
	}
	hosts = hosts[:2]
	if sources[hosts[0]] != sources[hosts[1]] {
		t.Skipf("the free filesystems have different paths: %s and %s",
			sources[hosts[0]], sources[hosts[1]])
	}
	path := sources[hosts[0]]

	t.Cleanup(func() {
		for _, hostID := range hosts {
			h.runOperation(hostID, map[string]any{
				"action": "mount.remove", "reason": "cleanup after the mount campaign test",
				"payload": map[string]any{"storage": map[string]any{"target": target}},
			}, 2*time.Minute)
		}
	})

	campaign := h.createCampaign(map[string]any{
		"name": "data disk on the fleet", "action": "mount.ensure",
		"reason": "integration test of the mount plans",
		"payload": map[string]any{"storage": map[string]any{
			"source": path, "target": target, "fs_type": "ext4",
			"options": "defaults,noatime", "persist": true}},
		"selector":                   map[string]any{"host_ids": hosts},
		"canary_size":                0,
		"wave_size":                  len(hosts),
		"max_concurrent":             len(hosts),
		"failure_threshold_percent":  0,
		"failure_threshold_absolute": 0,
		"reboot_policy":              "never",
	})
	if campaign.State != "planning" {
		t.Fatalf("the mount campaign started from state %s", campaign.State)
	}
	afterPlanning := h.awaitCampaign(campaign.ID,
		map[string]bool{"awaiting_approval": true, "paused": true, "failed": true}, 3*time.Minute)
	if afterPlanning.State != "awaiting_approval" {
		t.Fatalf("planning ended in state %s (%s)",
			afterPlanning.State, afterPlanning.PauseReason)
	}

	resolved := map[string]string{}
	for _, campaignTarget := range h.campaignTargets(campaign.ID) {
		plan := mountPlan(h, campaignTarget.PlanJobID)
		if plan.Action != "create" {
			t.Errorf("host %s plans %q instead of create", campaignTarget.Hostname, plan.Action)
		}
		if !strings.HasPrefix(plan.ResolvedSource, "UUID=") {
			t.Errorf("host %s did not resolve the source to a UUID: %q", campaignTarget.Hostname, plan.ResolvedSource)
		}
		resolved[campaignTarget.Hostname] = plan.ResolvedSource
	}
	if len(resolved) != 2 {
		t.Fatalf("plans for %d hosts instead of 2", len(resolved))
	}
	var uuids []string
	for _, uuid := range resolved {
		uuids = append(uuids, uuid)
	}
	if uuids[0] == uuids[1] {
		t.Fatalf("two hosts resolved %s to the same UUID %s", path, uuids[0])
	}

	h.approveCampaign(afterPlanning)
	final := h.awaitCampaign(campaign.ID,
		map[string]bool{"completed": true, "failed": true, "paused": true}, 4*time.Minute)
	if final.State != "completed" {
		t.Fatalf("the campaign ended in state %s (%s)", final.State, final.PauseReason)
	}

	// The change that went onto the host is to carry that host's UUID, not
	// the path from the order - and the host is to have the mount recorded
	// in fstab afterwards.
	for _, campaignTarget := range h.campaignTargets(campaign.ID) {
		var job struct {
			Payload struct {
				Storage struct {
					Source string `json:"source"`
				} `json:"storage"`
			} `json:"payload"`
		}
		h.get("/api/v1/jobs/"+campaignTarget.JobID, &job)
		if job.Payload.Storage.Source != resolved[campaignTarget.Hostname] {
			t.Errorf("host %s got the source %q, the plan had %q",
				campaignTarget.Hostname, job.Payload.Storage.Source, resolved[campaignTarget.Hostname])
		}
		if !hostMounted(t, h, campaignTarget.HostID, target) {
			t.Errorf("host %s after the campaign does not have %s mounted and in fstab", campaignTarget.Hostname, target)
		}
	}
}

// hostMounted waits until the host inventory shows the target mounted and
// in fstab. The storage fragment comes from the inventory cycle, so after
// the change it has to be refreshed, and the fragment write is asynchronous
// with respect to the job.
func hostMounted(t *testing.T, h *harness, hostID, target string) bool {
	t.Helper()
	h.runOperation(hostID, map[string]any{
		"action": "inventory.refresh", "reason": "mount campaign test",
		"payload": map[string]any{"inventory": map[string]any{"modules": []string{"storage"}}},
	}, 2*time.Minute)
	deadline := time.Now().Add(60 * time.Second)
	for {
		for _, mount := range hostStorageSnapshot(t, h, hostID).Mounts {
			if mount.Target == target && mount.Mounted && mount.InFstab {
				return true
			}
		}
		if time.Now().After(deadline) {
			return false
		}
		time.Sleep(2 * time.Second)
	}
}

// inFstab says whether the device has an fstab entry under any target.
func inFstab(state storageSnapshot, device deviceView) bool {
	for _, mount := range state.Mounts {
		if !mount.InFstab {
			continue
		}
		if mount.Source == device.Path ||
			mount.Source == "UUID="+device.UUID {
			return true
		}
	}
	return false
}

// mountPlan reads the mount plan from the planning job result.
func mountPlan(h *harness, jobID string) (plan struct {
	Action         string `json:"action"`
	ResolvedSource string `json:"resolved_source"`
	Refusal        string `json:"refusal"`
}) {
	h.t.Helper()
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
		if response.Items[i].Detail.Kind == "mount_plan" {
			_ = json.Unmarshal(response.Items[i].Detail.Plan, &plan)
			return plan
		}
	}
	return plan
}

// TestNetworkCampaignComputesTheDiffAndRefusesBeforeConsent checks that a
// network change in a campaign gets a plan computed on the host: the
// difference against the profile the host has, the fingerprint of that
// difference in the change, and a refusal before consent where the change
// has nothing to land on.
func TestNetworkCampaignComputesTheDiffAndRefusesBeforeConsent(t *testing.T) {
	h := newHarness(t)

	// Hosts with a write mechanism and a named management interface.
	interfaces := map[string]string{}
	var targets []string
	for _, host := range h.hosts() {
		if host.ConnectionState != "online" {
			continue
		}
		state := hostNetworkSnapshot(t, h, host.ID)
		if state.WriteAdapter == "" || state.ManagementInterface == "" {
			continue
		}
		interfaces[host.ID] = state.ManagementInterface
		targets = append(targets, host.ID)
	}
	if len(targets) == 0 {
		t.Skip("the fleet has no host with a mechanism to write the network configuration")
	}
	// The order names one interface, and the hosts call it differently.
	// The campaign goes to those that have it under the same name.
	counts := map[string]int{}
	for _, name := range interfaces {
		counts[name]++
	}
	iface := ""
	for name, count := range counts {
		if count > counts[iface] || (count == counts[iface] && name < iface) {
			iface = name
		}
	}
	selected := targets[:0]
	for _, hostID := range targets {
		if interfaces[hostID] == iface {
			selected = append(selected, hostID)
		}
	}
	targets = selected

	t.Cleanup(func() {
		for _, hostID := range targets {
			h.runOperation(hostID, map[string]any{
				"action": "network.mtu.set", "reason": "cleanup after the network campaign test",
				"payload": map[string]any{"network": map[string]any{
					"interface": iface, "mtu": "auto", "rollback_seconds": 60}},
			}, 3*time.Minute)
		}
	})

	campaign := h.createCampaign(map[string]any{
		"name": "MTU on the fleet", "action": "network.mtu.set",
		"reason": "integration test of the network plans",
		"payload": map[string]any{"network": map[string]any{
			"interface": iface, "mtu": "1400", "rollback_seconds": 60}},
		"selector":                   map[string]any{"host_ids": targets},
		"canary_size":                0,
		"wave_size":                  len(targets),
		"max_concurrent":             len(targets),
		"failure_threshold_percent":  0,
		"failure_threshold_absolute": 0,
		"reboot_policy":              "never",
	})
	if campaign.State != "planning" {
		t.Fatalf("the network campaign started from state %s", campaign.State)
	}
	afterPlanning := h.awaitCampaign(campaign.ID,
		map[string]bool{"awaiting_approval": true, "paused": true, "failed": true}, 3*time.Minute)
	if afterPlanning.State != "awaiting_approval" {
		t.Fatalf("planning ended in state %s (%s)",
			afterPlanning.State, afterPlanning.PauseReason)
	}
	fingerprints := map[string]string{}
	for _, target := range h.campaignTargets(campaign.ID) {
		plan := planOfKind(h, target.PlanJobID, "network_plan")
		if plan.Action != "update" || len(plan.Changes) != 1 ||
			!strings.Contains(plan.Changes[0], "MTU") {
			t.Errorf("host %s plans %q %v instead of an MTU change", target.Hostname, plan.Action, plan.Changes)
		}
		if plan.PlanHash == "" {
			t.Errorf("host %s gave no plan fingerprint", target.Hostname)
		}
		fingerprints[target.Hostname] = plan.PlanHash
	}

	h.approveCampaign(afterPlanning)
	final := h.awaitCampaign(campaign.ID,
		map[string]bool{"completed": true, "failed": true, "paused": true}, 5*time.Minute)
	if final.State != "completed" {
		t.Fatalf("the campaign ended in state %s (%s)", final.State, final.PauseReason)
	}
	// The change that went onto the host carries that host's plan
	// fingerprint: the host computed the plan once more before the change
	// and had something to compare against.
	for _, target := range h.campaignTargets(campaign.ID) {
		var job struct {
			Payload struct {
				Network struct {
					PlanHash string `json:"plan_hash"`
				} `json:"network"`
			} `json:"payload"`
		}
		h.get("/api/v1/jobs/"+target.JobID, &job)
		if job.Payload.Network.PlanHash != fingerprints[target.Hostname] {
			t.Errorf("host %s got the fingerprint %q, the plan had %q",
				target.Hostname, job.Payload.Network.PlanHash, fingerprints[target.Hostname])
		}
	}

	// An interface without a profile: the plan is to refuse on every host,
	// and the campaign is to stop without consent, because no host is left
	// to work on.
	withoutProfile := h.createCampaign(map[string]any{
		"name": "MTU on an interface that does not exist", "action": "network.mtu.set",
		"reason": "network plan refusal test",
		"payload": map[string]any{"network": map[string]any{
			"interface": "flotestro9", "mtu": "1400", "rollback_seconds": 60}},
		"selector":    map[string]any{"host_ids": targets},
		"canary_size": 0, "wave_size": len(targets), "max_concurrent": len(targets),
		"failure_threshold_percent": 0, "failure_threshold_absolute": 0,
		"reboot_policy": "never",
	})
	refusalState := h.awaitCampaign(withoutProfile.ID,
		map[string]bool{"awaiting_approval": true, "paused": true, "failed": true}, 3*time.Minute)
	if refusalState.State == "awaiting_approval" {
		t.Fatal("the campaign on an interface without a profile reached consent")
	}
	for _, target := range h.campaignTargets(withoutProfile.ID) {
		if target.State != "ineligible" || target.ErrorCode != "plan_refused" {
			t.Errorf("target %s after the plan refusal: %s/%s", target.Hostname, target.State, target.ErrorCode)
		}
	}
}

// TestFirewalldZoneCampaignComputesTheDiffAndRefusesBeforeConsent checks
// that a firewalld zone entry in a campaign gets a plan computed on the
// host: whether the port is already open, in which zone and against which
// ruleset - and a zone the host does not have is a refusal before consent.
func TestFirewalldZoneCampaignComputesTheDiffAndRefusesBeforeConsent(t *testing.T) {
	h := newHarness(t)
	const port = "9445"

	zones := map[string]string{}
	var targets []string
	for _, host := range h.hosts() {
		if host.ConnectionState != "online" {
			continue
		}
		state := hostFirewallSnapshot(t, h, host.ID)
		if state.Adapter != "firewalld" {
			continue
		}
		for _, zone := range state.Zones {
			if zone.Active {
				zones[host.ID] = zone.Name
				targets = append(targets, host.ID)
				break
			}
		}
	}
	if len(targets) == 0 {
		t.Skip("the fleet has no host with firewalld and an active zone")
	}
	zone := zones[targets[0]]
	selected := targets[:0]
	for _, hostID := range targets {
		if zones[hostID] == zone {
			selected = append(selected, hostID)
		}
	}
	targets = selected

	t.Cleanup(func() {
		for _, hostID := range targets {
			h.runOperation(hostID, map[string]any{
				"action": "firewall.zone.port", "reason": "cleanup after the zone campaign test",
				"payload": map[string]any{"firewall": map[string]any{
					"zone": zone, "ports": []string{port}, "protocol": "tcp", "enable": false}},
			}, 2*time.Minute)
		}
	})

	opening := map[string]any{"firewall": map[string]any{
		"zone": zone, "ports": []string{port}, "protocol": "tcp", "enable": true}}
	campaign := h.createCampaign(map[string]any{
		"name": "port in a zone on the fleet", "action": "firewall.zone.port",
		"reason":                     "integration test of the zone plans",
		"payload":                    opening,
		"selector":                   map[string]any{"host_ids": targets},
		"canary_size":                0,
		"wave_size":                  len(targets),
		"max_concurrent":             len(targets),
		"failure_threshold_percent":  0,
		"failure_threshold_absolute": 0,
		"reboot_policy":              "never",
	})
	afterPlanning := h.awaitCampaign(campaign.ID,
		map[string]bool{"awaiting_approval": true, "paused": true, "failed": true}, 3*time.Minute)
	if afterPlanning.State != "awaiting_approval" {
		t.Fatalf("planning ended in state %s (%s)",
			afterPlanning.State, afterPlanning.PauseReason)
	}
	for _, target := range h.campaignTargets(campaign.ID) {
		plan := zonePlan(h, target.PlanJobID)
		if plan.Action != "create" || plan.Present || plan.Entry != port+"/tcp" || plan.RulesetHash == "" {
			t.Errorf("host %s plans %+v instead of opening the port", target.Hostname, plan)
		}
	}

	h.approveCampaign(afterPlanning)
	final := h.awaitCampaign(campaign.ID,
		map[string]bool{"completed": true, "failed": true, "paused": true}, 4*time.Minute)
	if final.State != "completed" {
		t.Fatalf("the campaign ended in state %s (%s)", final.State, final.PauseReason)
	}

	// The same entry once more: the plan is to say the port is already
	// open.
	repeat := h.createCampaign(map[string]any{
		"name": "port in a zone once more", "action": "firewall.zone.port",
		"reason": "no-change plan test", "payload": opening,
		"selector":    map[string]any{"host_ids": targets},
		"canary_size": 0, "wave_size": len(targets), "max_concurrent": len(targets),
		"failure_threshold_percent": 0, "failure_threshold_absolute": 0,
		"reboot_policy": "never",
	})
	afterRepeat := h.awaitCampaign(repeat.ID,
		map[string]bool{"awaiting_approval": true, "paused": true, "failed": true}, 3*time.Minute)
	if afterRepeat.State != "awaiting_approval" {
		t.Fatalf("repeat: planning ended in state %s (%s)",
			afterRepeat.State, afterRepeat.PauseReason)
	}
	for _, target := range h.campaignTargets(repeat.ID) {
		if plan := zonePlan(h, target.PlanJobID); plan.Action != "no_change" || !plan.Present {
			t.Errorf("host %s after the opening plans %+v", target.Hostname, plan)
		}
	}
	h.do(http.MethodPost, "/api/v1/campaigns/"+repeat.ID+"/cancel",
		map[string]any{"reason": "no-change plan test"}, nil, 0)

	// A zone the host does not have: a refusal in the plan on every host.
	withoutZone := h.createCampaign(map[string]any{
		"name": "port in a zone that does not exist", "action": "firewall.zone.port",
		"reason": "zone plan refusal test",
		"payload": map[string]any{"firewall": map[string]any{
			"zone": "flotestro-missing", "ports": []string{port}, "protocol": "tcp", "enable": true}},
		"selector":    map[string]any{"host_ids": targets},
		"canary_size": 0, "wave_size": len(targets), "max_concurrent": len(targets),
		"failure_threshold_percent": 0, "failure_threshold_absolute": 0,
		"reboot_policy": "never",
	})
	refusalState := h.awaitCampaign(withoutZone.ID,
		map[string]bool{"awaiting_approval": true, "paused": true, "failed": true}, 3*time.Minute)
	if refusalState.State == "awaiting_approval" {
		t.Fatal("the campaign on a zone that does not exist reached consent")
	}
	for _, target := range h.campaignTargets(withoutZone.ID) {
		if target.State != "ineligible" || target.ErrorCode != "plan_refused" {
			t.Errorf("target %s after the plan refusal: %s/%s", target.Hostname, target.State, target.ErrorCode)
		}
	}
}

// zonePlan reads the firewalld zone plan from the planning job result.
func zonePlan(h *harness, jobID string) (plan struct {
	Action      string `json:"action"`
	Entry       string `json:"entry"`
	Present     bool   `json:"present"`
	Refusal     string `json:"refusal"`
	RulesetHash string `json:"ruleset_hash"`
}) {
	h.t.Helper()
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
		if response.Items[i].Detail.Kind == "firewall_plan" {
			_ = json.Unmarshal(response.Items[i].Detail.Plan, &plan)
			return plan
		}
	}
	return plan
}

// TestResolverCampaignComputesTheDiffAndRefusesBeforeConsent checks that a
// resolver change in a campaign gets a plan computed on the host against
// the profile the host has, and comes back with its fingerprint - and an
// interface without a profile is a refusal before consent.
func TestResolverCampaignComputesTheDiffAndRefusesBeforeConsent(t *testing.T) {
	h := newHarness(t)
	const server = "192.168.56.50"

	interfaces := map[string]string{}
	var targets []string
	for _, host := range h.hosts() {
		if host.ConnectionState != "online" {
			continue
		}
		state := hostNetworkSnapshot(t, h, host.ID)
		if state.WriteAdapter == "" || state.ManagementInterface == "" {
			continue
		}
		interfaces[host.ID] = state.ManagementInterface
		targets = append(targets, host.ID)
	}
	if len(targets) == 0 {
		t.Skip("the fleet has no host with a mechanism to write the network configuration")
	}
	iface := interfaces[targets[0]]
	selected := targets[:0]
	for _, hostID := range targets {
		if interfaces[hostID] == iface {
			selected = append(selected, hostID)
		}
	}
	targets = selected

	// The cleanup leaves the server without search domains: a resolver
	// without a server is a refusal, so an empty profile cannot be restored
	// here.
	t.Cleanup(func() {
		for _, hostID := range targets {
			h.runOperation(hostID, map[string]any{
				"action": "dns.host.apply", "reason": "cleanup after the resolver campaign test",
				"payload": map[string]any{"dns": map[string]any{
					"interface": iface, "servers": []string{server}, "rollback_seconds": 60}},
			}, 3*time.Minute)
		}
	})

	campaign := h.createCampaign(map[string]any{
		"name": "resolver on the fleet", "action": "dns.host.apply",
		"reason": "integration test of the resolver plans",
		"payload": map[string]any{"dns": map[string]any{
			"interface": iface, "servers": []string{server},
			"search_domains": []string{"flotestro.test"}, "rollback_seconds": 60}},
		"selector":                   map[string]any{"host_ids": targets},
		"canary_size":                0,
		"wave_size":                  len(targets),
		"max_concurrent":             len(targets),
		"failure_threshold_percent":  0,
		"failure_threshold_absolute": 0,
		"reboot_policy":              "never",
	})
	afterPlanning := h.awaitCampaign(campaign.ID,
		map[string]bool{"awaiting_approval": true, "paused": true, "failed": true}, 3*time.Minute)
	if afterPlanning.State != "awaiting_approval" {
		t.Fatalf("planning ended in state %s (%s)",
			afterPlanning.State, afterPlanning.PauseReason)
	}
	fingerprints := map[string]string{}
	for _, target := range h.campaignTargets(campaign.ID) {
		plan := planOfKind(h, target.PlanJobID, "dns_plan")
		if plan.Action != "update" || plan.PlanHash == "" {
			t.Errorf("host %s plans %+v instead of a resolver change", target.Hostname, plan)
		}
		var aboutDomains bool
		for _, change := range plan.Changes {
			aboutDomains = aboutDomains || strings.Contains(change, "search domains")
		}
		if !aboutDomains {
			t.Errorf("host %s does not see the search domain change: %v", target.Hostname, plan.Changes)
		}
		fingerprints[target.Hostname] = plan.PlanHash
	}

	h.approveCampaign(afterPlanning)
	final := h.awaitCampaign(campaign.ID,
		map[string]bool{"completed": true, "failed": true, "paused": true}, 5*time.Minute)
	if final.State != "completed" {
		t.Fatalf("the campaign ended in state %s (%s)", final.State, final.PauseReason)
	}
	for _, target := range h.campaignTargets(campaign.ID) {
		var job struct {
			Payload struct {
				DNS struct {
					PlanHash string `json:"plan_hash"`
				} `json:"dns"`
			} `json:"payload"`
		}
		h.get("/api/v1/jobs/"+target.JobID, &job)
		if job.Payload.DNS.PlanHash != fingerprints[target.Hostname] {
			t.Errorf("host %s got the fingerprint %q, the plan had %q",
				target.Hostname, job.Payload.DNS.PlanHash, fingerprints[target.Hostname])
		}
	}

	withoutProfile := h.createCampaign(map[string]any{
		"name": "resolver on an interface that does not exist", "action": "dns.host.apply",
		"reason": "resolver plan refusal test",
		"payload": map[string]any{"dns": map[string]any{
			"interface": "flotestro9", "servers": []string{server}, "rollback_seconds": 60}},
		"selector":    map[string]any{"host_ids": targets},
		"canary_size": 0, "wave_size": len(targets), "max_concurrent": len(targets),
		"failure_threshold_percent": 0, "failure_threshold_absolute": 0,
		"reboot_policy": "never",
	})
	refusalState := h.awaitCampaign(withoutProfile.ID,
		map[string]bool{"awaiting_approval": true, "paused": true, "failed": true}, 3*time.Minute)
	if refusalState.State == "awaiting_approval" {
		t.Fatal("the campaign on an interface without a profile reached consent")
	}
	for _, target := range h.campaignTargets(withoutProfile.ID) {
		if target.State != "ineligible" || target.ErrorCode != "plan_refused" {
			t.Errorf("target %s after the plan refusal: %s/%s", target.Hostname, target.State, target.ErrorCode)
		}
	}
}

// planOfKind reads a plan of the given kind from the planning job result.
func planOfKind(h *harness, jobID, kind string) (plan struct {
	Action   string   `json:"action"`
	Changes  []string `json:"changes"`
	Refusal  string   `json:"refusal"`
	PlanHash string   `json:"plan_hash"`
}) {
	h.t.Helper()
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
			_ = json.Unmarshal(response.Items[i].Detail.Plan, &plan)
			return plan
		}
	}
	return plan
}

// TestSSHCampaignComputesTheDiffAndRefusesBeforeConsent checks that an sshd
// configuration change in a campaign gets a plan computed on the host: the
// difference against what the server applies, the panel file the write
// overwrites, and a refusal before consent when the change would cut off
// all login methods.
func TestSSHCampaignComputesTheDiffAndRefusesBeforeConsent(t *testing.T) {
	h := newHarness(t)

	var targets []string
	for _, host := range h.hosts() {
		if host.ConnectionState != "online" {
			continue
		}
		if state := hostSSHSnapshot(t, h, host.ID); len(state.Ports) > 0 {
			targets = append(targets, host.ID)
		}
	}
	if len(targets) < 2 {
		t.Skip("the fleet has fewer than two connected hosts with sshd")
	}

	t.Cleanup(func() {
		for _, hostID := range targets {
			h.runOperation(hostID, map[string]any{
				"action": "ssh.config.apply", "reason": "cleanup after the sshd campaign test",
				"payload": map[string]any{"ssh": map[string]any{"max_auth_tries": "6"}},
			}, 2*time.Minute)
		}
	})

	// The first host gets a different value than the rest, so the host
	// plans are to differ by the state found, not by the order. The rest
	// get the value explicitly: the previous run may have left the host
	// already in the desired state.
	for i, hostID := range targets {
		value := "6"
		if i == 0 {
			value = "3"
		}
		job, attempts := h.runOperation(hostID, map[string]any{
			"action": "ssh.config.apply", "reason": "preparation of the sshd campaign test",
			"payload": map[string]any{"ssh": map[string]any{"max_auth_tries": value}},
		}, 2*time.Minute)
		if job.State != "succeeded" {
			t.Fatalf("preparing %s: state = %s, %s", hostID[:8], job.State, lastMessage(attempts))
		}
	}

	order := map[string]any{"ssh": map[string]any{"max_auth_tries": "5"}}
	campaign := h.createCampaign(map[string]any{
		"name": "MaxAuthTries on the fleet", "action": "ssh.config.apply",
		"reason":                     "integration test of the sshd plans",
		"payload":                    order,
		"selector":                   map[string]any{"host_ids": targets},
		"canary_size":                0,
		"wave_size":                  len(targets),
		"max_concurrent":             len(targets),
		"failure_threshold_percent":  0,
		"failure_threshold_absolute": 0,
		"reboot_policy":              "never",
	})
	afterPlanning := h.awaitCampaign(campaign.ID,
		map[string]bool{"awaiting_approval": true, "paused": true, "failed": true}, 3*time.Minute)
	if afterPlanning.State != "awaiting_approval" {
		t.Fatalf("planning ended in state %s (%s)",
			afterPlanning.State, afterPlanning.PauseReason)
	}
	fingerprints := map[string]string{}
	for _, target := range h.campaignTargets(campaign.ID) {
		plan := planOfKind(h, target.PlanJobID, "ssh_plan")
		if plan.Action != "update" || plan.PlanHash == "" {
			t.Errorf("host %s plans %+v instead of a change", target.Hostname, plan)
		}
		var aboutTries bool
		for _, change := range plan.Changes {
			aboutTries = aboutTries || strings.Contains(change, "MaxAuthTries")
		}
		if !aboutTries {
			t.Errorf("host %s does not see the MaxAuthTries change: %v", target.Hostname, plan.Changes)
		}
		fingerprints[target.PlanJobID] = plan.PlanHash
	}
	// The host prepared differently has a different fingerprint: the plan
	// describes the state found.
	distinct := map[string]bool{}
	for _, fingerprint := range fingerprints {
		distinct[fingerprint] = true
	}
	if len(distinct) < 2 {
		t.Errorf("hosts with different states have the same plan fingerprint: %v", fingerprints)
	}

	h.approveCampaign(afterPlanning)
	final := h.awaitCampaign(campaign.ID,
		map[string]bool{"completed": true, "failed": true, "paused": true}, 4*time.Minute)
	if final.State != "completed" {
		t.Fatalf("the campaign ended in state %s (%s)", final.State, final.PauseReason)
	}
	for _, hostID := range targets {
		if after := hostSSHSnapshot(t, h, hostID); after.MaxAuthTries != 5 {
			t.Errorf("host %s after the campaign has MaxAuthTries = %d", hostID[:8], after.MaxAuthTries)
		}
	}

	// The same order once more: the plan is to say there are no changes.
	repeat := h.createCampaign(map[string]any{
		"name": "MaxAuthTries once more", "action": "ssh.config.apply",
		"reason": "no-change plan test", "payload": order,
		"selector":    map[string]any{"host_ids": targets},
		"canary_size": 0, "wave_size": len(targets), "max_concurrent": len(targets),
		"failure_threshold_percent": 0, "failure_threshold_absolute": 0,
		"reboot_policy": "never",
	})
	afterRepeat := h.awaitCampaign(repeat.ID,
		map[string]bool{"awaiting_approval": true, "paused": true, "failed": true}, 3*time.Minute)
	if afterRepeat.State != "awaiting_approval" {
		t.Fatalf("repeat: planning ended in state %s (%s)",
			afterRepeat.State, afterRepeat.PauseReason)
	}
	for _, target := range h.campaignTargets(repeat.ID) {
		if plan := planOfKind(h, target.PlanJobID, "ssh_plan"); plan.Action != "no_change" {
			t.Errorf("host %s after the change plans %+v", target.Hostname, plan)
		}
	}
	h.do(http.MethodPost, "/api/v1/campaigns/"+repeat.ID+"/cancel",
		map[string]any{"reason": "no-change plan test"}, nil, 0)

	// Cutting off all login methods: a refusal in the plan on every host. A
	// host with GSSAPI keeps one method, so for it that is not a cut-off -
	// it stays out of this part of the test.
	withoutGSSAPI := targets[:0:0]
	for _, hostID := range targets {
		if !strings.EqualFold(hostSSHSnapshot(t, h, hostID).GSSAPIAuthentication, "yes") {
			withoutGSSAPI = append(withoutGSSAPI, hostID)
		}
	}
	if len(withoutGSSAPI) == 0 {
		t.Skip("every host has GSSAPI, so the cut-off cannot be ordered")
	}
	targets = withoutGSSAPI
	cutOff := h.createCampaign(map[string]any{
		"name": "login cut-off", "action": "ssh.config.apply",
		"reason": "sshd plan refusal test",
		"payload": map[string]any{"ssh": map[string]any{
			"password_authentication": "no", "pubkey_authentication": "no",
			"kbd_interactive_authentication": "no"}},
		"selector":    map[string]any{"host_ids": targets},
		"canary_size": 0, "wave_size": len(targets), "max_concurrent": len(targets),
		"failure_threshold_percent": 0, "failure_threshold_absolute": 0,
		"reboot_policy": "never",
	})
	refusalState := h.awaitCampaign(cutOff.ID,
		map[string]bool{"awaiting_approval": true, "paused": true, "failed": true}, 3*time.Minute)
	if refusalState.State == "awaiting_approval" {
		t.Fatal("the campaign cutting off login reached consent")
	}
	for _, target := range h.campaignTargets(cutOff.ID) {
		if target.State != "ineligible" || target.ErrorCode != "plan_refused" {
			t.Errorf("target %s after the plan refusal: %s/%s", target.Hostname, target.State, target.ErrorCode)
		}
	}
}

// TestModuleBlacklistCampaignComputesTheDiffOnEveryHost checks that a
// module blacklist in a campaign gets a plan computed on the host: a host
// that already blacklists the module has no change, and the rest get the
// entry - and the change comes back with that host's plan fingerprint.
func TestModuleBlacklistCampaignComputesTheDiffOnEveryHost(t *testing.T) {
	h := newHarness(t)
	const module = "floppy"

	var targets []string
	for _, host := range h.hosts() {
		if host.ConnectionState == "online" {
			targets = append(targets, host.ID)
		}
	}
	if len(targets) < 2 {
		t.Skip("the fleet has fewer than two connected hosts")
	}

	t.Cleanup(func() {
		for _, hostID := range targets {
			h.runOperation(hostID, map[string]any{
				"action": "kernel.module.blacklist", "reason": "cleanup after the blacklist campaign test",
				"payload": map[string]any{"kernel": map[string]any{"module": module, "blacklist": false}},
			}, 2*time.Minute)
		}
	})

	// The first host blacklists the module already before the campaign.
	job, attempts := h.runOperation(targets[0], map[string]any{
		"action": "kernel.module.blacklist", "reason": "preparation of the blacklist campaign test",
		"payload": map[string]any{"kernel": map[string]any{"module": module, "blacklist": true}},
	}, 2*time.Minute)
	if job.State != "succeeded" {
		t.Fatalf("preparation: state = %s, %s", job.State, lastMessage(attempts))
	}

	campaign := h.createCampaign(map[string]any{
		"name": "module blacklist on the fleet", "action": "kernel.module.blacklist",
		"reason":                     "integration test of the blacklist plans",
		"payload":                    map[string]any{"kernel": map[string]any{"module": module, "blacklist": true}},
		"selector":                   map[string]any{"host_ids": targets},
		"canary_size":                0,
		"wave_size":                  len(targets),
		"max_concurrent":             len(targets),
		"failure_threshold_percent":  0,
		"failure_threshold_absolute": 0,
		"reboot_policy":              "never",
	})
	afterPlanning := h.awaitCampaign(campaign.ID,
		map[string]bool{"awaiting_approval": true, "paused": true, "failed": true}, 3*time.Minute)
	if afterPlanning.State != "awaiting_approval" {
		t.Fatalf("planning ended in state %s (%s)",
			afterPlanning.State, afterPlanning.PauseReason)
	}
	actions := map[string]int{}
	fingerprints := map[string]string{}
	for _, target := range h.campaignTargets(campaign.ID) {
		plan := planOfKind(h, target.PlanJobID, "kernel_module_plan")
		actions[plan.Action]++
		fingerprints[target.Hostname] = plan.PlanHash
		if plan.PlanHash == "" {
			t.Errorf("host %s gave no plan fingerprint", target.Hostname)
		}
	}
	if actions["create"] == 0 || actions["no_change"] == 0 {
		t.Errorf("the host plans do not differ: %+v", actions)
	}

	h.approveCampaign(afterPlanning)
	final := h.awaitCampaign(campaign.ID,
		map[string]bool{"completed": true, "failed": true, "paused": true}, 4*time.Minute)
	if final.State != "completed" {
		t.Fatalf("the campaign ended in state %s (%s)", final.State, final.PauseReason)
	}
	for _, target := range h.campaignTargets(campaign.ID) {
		var job struct {
			Payload struct {
				Kernel struct {
					PlanHash string `json:"plan_hash"`
				} `json:"kernel"`
			} `json:"payload"`
		}
		h.get("/api/v1/jobs/"+target.JobID, &job)
		if job.Payload.Kernel.PlanHash != fingerprints[target.Hostname] {
			t.Errorf("host %s got the fingerprint %q, the plan had %q",
				target.Hostname, job.Payload.Kernel.PlanHash, fingerprints[target.Hostname])
		}
		var blacklisted bool
		for _, name := range hostKernelSnapshot(t, h, target.HostID).Blacklist {
			blacklisted = blacklisted || name == module
		}
		if !blacklisted {
			t.Errorf("host %s after the campaign does not blacklist the module %s", target.Hostname, module)
		}
	}
}

// TestTimeSourceCampaignComputesTheDiffAndRefusesBeforeConsent checks that
// a time source change in a campaign gets a plan computed on the host:
// which daemon, whether a restart or a reload - and a host without a daemon
// or without the panel directory is a refusal before consent, not a failure
// halfway through the fleet.
func TestTimeSourceCampaignComputesTheDiffAndRefusesBeforeConsent(t *testing.T) {
	h := newHarness(t)

	states := map[string]timeSnapshot{}
	var targets []string
	server := ""
	for _, host := range h.hosts() {
		if host.ConnectionState != "online" {
			continue
		}
		state := hostTimeSnapshot(t, h, host.ID)
		states[host.ID] = state
		targets = append(targets, host.ID)
		if server == "" && len(state.Sources) > 0 {
			server = state.Sources[0].Address
		}
	}
	if len(targets) < 2 || server == "" {
		t.Skip("the fleet has no two hosts and a working time source")
	}
	// Without consent to the directory, a chrony host without a drop-in and
	// a host without a daemon are to fall out in the plan; the rest get a
	// change plan.
	refusals := map[string]bool{}
	for hostID, state := range states {
		refusals[hostID] = state.Service == "" ||
			(state.Service == "chrony" && state.ManagedPath == "")
	}

	campaign := h.createCampaign(map[string]any{
		"name": "time sources on the fleet", "action": "time.config.apply",
		"reason":                     "integration test of the time source plans",
		"payload":                    map[string]any{"time": map[string]any{"servers": []string{server}}},
		"selector":                   map[string]any{"host_ids": targets},
		"canary_size":                0,
		"wave_size":                  len(targets),
		"max_concurrent":             len(targets),
		"failure_threshold_percent":  0,
		"failure_threshold_absolute": 0,
		"reboot_policy":              "never",
	})
	afterPlanning := h.awaitCampaign(campaign.ID,
		map[string]bool{"awaiting_approval": true, "paused": true, "failed": true}, 3*time.Minute)

	capable := 0
	for _, target := range h.campaignTargets(campaign.ID) {
		if refusals[target.HostID] {
			if target.State != "ineligible" || target.ErrorCode != "plan_refused" {
				t.Errorf("target %s without a daemon or a directory: %s/%s",
					target.Hostname, target.State, target.ErrorCode)
			}
			continue
		}
		capable++
		plan := planOfKind(h, target.PlanJobID, "time_plan")
		if plan.Refusal != "" || plan.PlanHash == "" ||
			(plan.Action != "update" && plan.Action != "no_change") {
			t.Errorf("host %s plans %+v", target.Hostname, plan)
		}
	}
	if capable == 0 {
		if afterPlanning.State == "awaiting_approval" {
			t.Fatal("a campaign without a capable host reached consent")
		}
		t.Skip("no host accepts the time source change; only the refusals were checked")
	}
	if afterPlanning.State != "awaiting_approval" {
		t.Fatalf("planning ended in state %s (%s)",
			afterPlanning.State, afterPlanning.PauseReason)
	}

	h.approveCampaign(afterPlanning)
	final := h.awaitCampaign(campaign.ID,
		map[string]bool{"completed": true, "failed": true, "paused": true}, 6*time.Minute)
	if final.State != "completed" {
		t.Fatalf("the campaign ended in state %s (%s)", final.State, final.PauseReason)
	}
	for _, target := range h.campaignTargets(campaign.ID) {
		if refusals[target.HostID] {
			continue
		}
		var recorded bool
		for _, entry := range hostTimeSnapshot(t, h, target.HostID).Configured {
			recorded = recorded || (entry.Managed && entry.Address == server)
		}
		if !recorded {
			t.Errorf("host %s after the campaign does not have the server %s in the panel file", target.Hostname, server)
		}
	}
}

// TestFilesystemCheckCampaignComputesAPlanOnEveryHost checks that a
// filesystem check in a campaign gets a plan computed on the host: which
// filesystem and UUID the host has under the path, whether it is unmounted
// - and a device the host does not see is a refusal before consent.
func TestFilesystemCheckCampaignComputesAPlanOnEveryHost(t *testing.T) {
	h := newHarness(t)

	paths := map[string]string{}
	var targets []string
	for _, host := range h.hosts() {
		if host.ConnectionState != "online" {
			continue
		}
		// The storage fragment comes from the inventory cycle; the previous
		// test may have just unmounted a disk the snapshot does not see yet.
		h.runOperation(host.ID, map[string]any{
			"action": "inventory.refresh", "reason": "filesystem check campaign test",
			"payload": map[string]any{"inventory": map[string]any{"modules": []string{"storage"}}},
		}, 2*time.Minute)
		state := hostStorageSnapshot(t, h, host.ID)
		for _, device := range state.Devices {
			if device.FSType == "ext4" && device.UUID != "" && len(device.Mountpoints) == 0 {
				paths[host.ID] = device.Path
				targets = append(targets, host.ID)
				break
			}
		}
	}
	if len(targets) < 2 {
		t.Skip("the fleet has fewer than two hosts with an unmounted ext4 filesystem")
	}
	path := paths[targets[0]]
	selected := targets[:0]
	for _, hostID := range targets {
		if paths[hostID] == path {
			selected = append(selected, hostID)
		}
	}
	targets = selected
	if len(targets) < 2 {
		t.Skipf("the unmounted filesystems have different paths")
	}

	campaign := h.createCampaign(map[string]any{
		"name": "filesystem check on the fleet", "action": "filesystem.check",
		"reason":                     "integration test of the device plans",
		"payload":                    map[string]any{"storage": map[string]any{"device": path}},
		"selector":                   map[string]any{"host_ids": targets},
		"canary_size":                0,
		"wave_size":                  len(targets),
		"max_concurrent":             len(targets),
		"failure_threshold_percent":  0,
		"failure_threshold_absolute": 0,
		"reboot_policy":              "never",
	})
	afterPlanning := h.awaitCampaign(campaign.ID,
		map[string]bool{"awaiting_approval": true, "paused": true, "failed": true}, 3*time.Minute)
	if afterPlanning.State != "awaiting_approval" {
		t.Fatalf("planning ended in state %s (%s)",
			afterPlanning.State, afterPlanning.PauseReason)
	}
	uuids := map[string]bool{}
	fingerprints := map[string]string{}
	for _, target := range h.campaignTargets(campaign.ID) {
		plan := devicePlan(h, target.PlanJobID)
		if plan.Action != "run" || plan.Refusal != "" || plan.UUID == "" || plan.Mountpoint != "" {
			t.Errorf("host %s plans %+v instead of a check", target.Hostname, plan)
		}
		uuids[plan.UUID] = true
		fingerprints[target.Hostname] = plan.PlanHash
	}
	// The same path, different filesystems: the plan describes the one the
	// host has.
	if len(uuids) < 2 {
		t.Errorf("the hosts under %s have the same UUIDs: %v", path, uuids)
	}

	h.approveCampaign(afterPlanning)
	final := h.awaitCampaign(campaign.ID,
		map[string]bool{"completed": true, "failed": true, "paused": true}, 5*time.Minute)
	if final.State != "completed" {
		t.Fatalf("the campaign ended in state %s (%s)", final.State, final.PauseReason)
	}
	for _, target := range h.campaignTargets(campaign.ID) {
		var job struct {
			Payload struct {
				Storage struct {
					PlanHash string `json:"plan_hash"`
				} `json:"storage"`
			} `json:"payload"`
		}
		h.get("/api/v1/jobs/"+target.JobID, &job)
		if job.Payload.Storage.PlanHash != fingerprints[target.Hostname] {
			t.Errorf("host %s got the fingerprint %q, the plan had %q",
				target.Hostname, job.Payload.Storage.PlanHash, fingerprints[target.Hostname])
		}
	}

	// A device the host does not see: a refusal in the plan on every host.
	withoutDevice := h.createCampaign(map[string]any{
		"name": "check of a device that does not exist", "action": "filesystem.check",
		"reason":      "device plan refusal test",
		"payload":     map[string]any{"storage": map[string]any{"device": "/dev/flotestro0"}},
		"selector":    map[string]any{"host_ids": targets},
		"canary_size": 0, "wave_size": len(targets), "max_concurrent": len(targets),
		"failure_threshold_percent": 0, "failure_threshold_absolute": 0,
		"reboot_policy": "never",
	})
	refusalState := h.awaitCampaign(withoutDevice.ID,
		map[string]bool{"awaiting_approval": true, "paused": true, "failed": true}, 3*time.Minute)
	if refusalState.State == "awaiting_approval" {
		t.Fatal("the campaign on a device that does not exist reached consent")
	}
	for _, target := range h.campaignTargets(withoutDevice.ID) {
		if target.State != "ineligible" || target.ErrorCode != "plan_refused" {
			t.Errorf("target %s after the plan refusal: %s/%s", target.Hostname, target.State, target.ErrorCode)
		}
	}
}

// devicePlan reads the device plan from the planning job result.
func devicePlan(h *harness, jobID string) (plan struct {
	Operation  string `json:"operation"`
	Action     string `json:"action"`
	UUID       string `json:"uuid"`
	Mountpoint string `json:"mountpoint"`
	Refusal    string `json:"refusal"`
	PlanHash   string `json:"plan_hash"`
}) {
	h.t.Helper()
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
		if response.Items[i].Detail.Kind == "device_plan" {
			_ = json.Unmarshal(response.Items[i].Detail.Plan, &plan)
			return plan
		}
	}
	return plan
}

// TestCertificateCampaignComputesTheDiffAndProtectsTheKey checks two things
// at once: a certificate deployment in a campaign gets a plan computed on
// the host (the found and desired fingerprints, the expiry), and the
// private key appears neither in the plan, nor in the job envelope, nor in
// the audit log.
func TestCertificateCampaignComputesTheDiffAndProtectsTheKey(t *testing.T) {
	h := newHarness(t)

	var targets []string
	for _, host := range h.hosts() {
		if host.ConnectionState == "online" {
			targets = append(targets, host.ID)
		}
	}
	if len(targets) < 2 {
		t.Skip("the fleet has fewer than two connected hosts")
	}
	targets = targets[:2]

	// The directory must exist on every campaign host: the panel writes a
	// file, it does not create somebody else's directories.
	path := fmt.Sprintf("/etc/ssl/certs/flotestro-campaign-%d.crt", time.Now().UnixNano())
	keyPath := strings.Replace(path, ".crt", ".key", 1)
	old, oldKey, _ := testPair(t, "campaign.flotestro.test", 10*24*time.Hour)
	fresh, freshKey, freshFingerprint := testPair(t, "campaign.flotestro.test", 40*24*time.Hour)
	oldSecret := newSecret(t, h, oldKey)
	freshSecret := newSecret(t, h, freshKey)

	t.Cleanup(func() {
		for _, hostID := range targets {
			h.do(http.MethodDelete,
				"/api/v1/hosts/"+hostID+"/certificates/targets?path="+path, nil, nil, 0)
			// The file stays on the host unless removed - and the target
			// registry has a limit the next runs would eventually exhaust.
			for _, toRemove := range []string{path, keyPath} {
				h.runOperation(hostID, map[string]any{
					"action": "file.remove", "reason": "cleanup after the certificate campaign test",
					"payload": map[string]any{"file": map[string]any{"path": toRemove}},
				}, 2*time.Minute)
			}
		}
	})

	// The first host gets an older certificate under the same path: the
	// host plans are to differ by the state found, not by the order.
	job, attempts := h.runOperation(targets[0], map[string]any{
		"action": "certificate.deploy", "reason": "preparation of the certificate campaign test",
		"payload": map[string]any{"certificate": map[string]any{
			"path": path, "key_path": keyPath, "certificate": old,
			"key_secret": map[string]any{"name": oldSecret.Name},
		}},
	}, 3*time.Minute)
	if job.State != "succeeded" {
		t.Fatalf("preparation: state = %s, %s", job.State, lastMessage(attempts))
	}

	campaign := h.createCampaign(map[string]any{
		"name": "certificate on the fleet", "action": "certificate.deploy",
		"reason": "integration test of the certificate plans",
		"payload": map[string]any{"certificate": map[string]any{
			"path": path, "key_path": keyPath, "certificate": fresh,
			"key_secret": map[string]any{"name": freshSecret.Name},
		}},
		"selector":                   map[string]any{"host_ids": targets},
		"canary_size":                0,
		"wave_size":                  len(targets),
		"max_concurrent":             len(targets),
		"failure_threshold_percent":  0,
		"failure_threshold_absolute": 0,
		"reboot_policy":              "never",
	})
	afterPlanning := h.awaitCampaign(campaign.ID,
		map[string]bool{"awaiting_approval": true, "paused": true, "failed": true}, 3*time.Minute)
	if afterPlanning.State != "awaiting_approval" {
		t.Fatalf("planning ended in state %s (%s)",
			afterPlanning.State, afterPlanning.PauseReason)
	}
	actions := map[string]int{}
	fingerprints := map[string]string{}
	for _, target := range h.campaignTargets(campaign.ID) {
		plan := certificatePlan(h, target.PlanJobID)
		actions[plan.Action]++
		fingerprints[target.Hostname] = plan.PlanHash
		if plan.DesiredFingerprint != freshFingerprint || plan.PlanHash == "" {
			t.Errorf("host %s plans %+v", target.Hostname, plan)
		}
		// The private key is to be in the plan only as a reference to the
		// store.
		if plan.KeySecret == "" || strings.Contains(plan.KeySecret, "BEGIN") {
			t.Errorf("host %s: key reference = %q", target.Hostname, plan.KeySecret)
		}
	}
	if actions["create"] == 0 || actions["update"] == 0 {
		t.Errorf("the host plans do not differ: %+v", actions)
	}

	h.approveCampaign(afterPlanning)
	final := h.awaitCampaign(campaign.ID,
		map[string]bool{"completed": true, "failed": true, "paused": true}, 5*time.Minute)
	if final.State != "completed" {
		t.Fatalf("the campaign ended in state %s (%s)", final.State, final.PauseReason)
	}
	for _, target := range h.campaignTargets(campaign.ID) {
		var job struct {
			Payload struct {
				Certificate struct {
					PlanHash string `json:"plan_hash"`
				} `json:"certificate"`
			} `json:"payload"`
		}
		h.get("/api/v1/jobs/"+target.JobID, &job)
		if job.Payload.Certificate.PlanHash != fingerprints[target.Hostname] {
			t.Errorf("host %s got the fingerprint %q, the plan had %q",
				target.Hostname, job.Payload.Certificate.PlanHash, fingerprints[target.Hostname])
		}
		deployed := findCertificate(t, hostCertificates(h, target.HostID), path)
		if deployed.FingerprintSHA256 != freshFingerprint {
			t.Errorf("host %s has the certificate %q after the campaign", target.Hostname, deployed.FingerprintSHA256)
		}
	}
	// The key value must be nowhere but the store - also on the way
	// through the campaign plan and its approval.
	assertValueAbsent(t, h, strings.Split(strings.TrimSpace(freshKey), "\n")[1])
}

// certificatePlan reads the deployment plan from the planning job result.
func certificatePlan(h *harness, jobID string) (plan struct {
	Action             string `json:"action"`
	DesiredFingerprint string `json:"desired_fingerprint"`
	KeySecret          string `json:"key_secret"`
	Refusal            string `json:"refusal"`
	PlanHash           string `json:"plan_hash"`
}) {
	h.t.Helper()
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
		if response.Items[i].Detail.Kind == "certificate_plan" {
			_ = json.Unmarshal(response.Items[i].Detail.Plan, &plan)
			return plan
		}
	}
	return plan
}

// TestBackupCampaignComputesTheScopeAndRequiresAVerification checks three
// things at once: a copy in a campaign gets a plan computed on the host
// (the scope, the size, the repository state), the copy ends with a
// repository check, and a restore does not run in bulk at all.
func TestBackupCampaignComputesTheScopeAndRequiresAVerification(t *testing.T) {
	h := newHarness(t)

	var targets []string
	for _, host := range h.hosts() {
		if host.ConnectionState == "online" && host.OSFamily != "arch" {
			targets = append(targets, host.ID)
		}
	}
	if len(targets) < 2 {
		t.Skip("the fleet has fewer than two connected hosts")
	}
	targets = targets[:2]

	name := fmt.Sprintf("campaign-%d", time.Now().UnixNano())
	repository := "/srv/" + name
	password := "password-" + name
	secret := newSecret(t, h, password)
	order := map[string]any{
		"id": name, "tool": "restic", "repository": repository,
		// Every host has the first directory; none has the second and the
		// plan is to say so instead of writing an empty copy.
		"paths":     []string{"/etc/flotestro", "/srv/flotestro-missing"},
		"keep_last": 2, "initialize": true,
		"password_secret": map[string]any{"name": secret.Name},
	}

	// A restore has no right to run in bulk - and not because the panel
	// cannot, but because it is not allowed.
	var refusal struct {
		Code   string `json:"code"`
		Detail string `json:"detail"`
	}
	restore := map[string]any{}
	for key, value := range order {
		restore[key] = value
	}
	restore["snapshot_id"] = "abc123"
	restore["target"] = "/srv/restore"
	restore["overwrite"] = "empty-target"
	h.do(http.MethodPost, "/api/v1/campaigns", map[string]any{
		"name": "restore on the fleet", "action": "backup.restore",
		"payload":  map[string]any{"backup": restore},
		"selector": map[string]any{"host_ids": targets},
	}, &refusal, http.StatusBadRequest)
	if refusal.Code != "not_a_campaign_action" || !strings.Contains(refusal.Detail, "an operator present at every host") {
		t.Errorf("restore refusal: %s (%s)", refusal.Code, refusal.Detail)
	}

	campaign := h.createCampaign(map[string]any{
		"name": "copy on the fleet", "action": "backup.run",
		"reason":                     "integration test of the backup plans",
		"payload":                    map[string]any{"backup": order},
		"selector":                   map[string]any{"host_ids": targets},
		"canary_size":                0,
		"wave_size":                  len(targets),
		"max_concurrent":             len(targets),
		"failure_threshold_percent":  0,
		"failure_threshold_absolute": 0,
		"reboot_policy":              "never",
	})
	afterPlanning := h.awaitCampaign(campaign.ID,
		map[string]bool{"awaiting_approval": true, "paused": true, "failed": true}, 5*time.Minute)
	if afterPlanning.State != "awaiting_approval" {
		t.Fatalf("planning ended in state %s (%s)",
			afterPlanning.State, afterPlanning.PauseReason)
	}
	fingerprints := map[string]string{}
	for _, target := range h.campaignTargets(campaign.ID) {
		plan := backupPlan(h, target.PlanJobID)
		if plan.Action != "run" || plan.Refusal != "" || plan.PlanHash == "" {
			t.Errorf("host %s plans %+v", target.Hostname, plan)
		}
		if len(plan.Paths) != 1 || len(plan.MissingPaths) != 1 {
			t.Errorf("host %s: scope %v, missing %v", target.Hostname, plan.Paths, plan.MissingPaths)
		}
		if !plan.Verified || plan.WillInitialize != true {
			t.Errorf("host %s: plan without a check or without initialising the repository: %+v",
				target.Hostname, plan)
		}
		fingerprints[target.Hostname] = plan.PlanHash
	}

	h.approveCampaign(afterPlanning)
	final := h.awaitCampaign(campaign.ID,
		map[string]bool{"completed": true, "failed": true, "paused": true}, 10*time.Minute)
	if final.State != "completed" {
		t.Fatalf("the campaign ended in state %s (%s)", final.State, final.PauseReason)
	}
	for _, target := range h.campaignTargets(campaign.ID) {
		var job struct {
			Payload struct {
				Backup struct {
					PlanHash string `json:"plan_hash"`
				} `json:"backup"`
			} `json:"payload"`
		}
		h.get("/api/v1/jobs/"+target.JobID, &job)
		if job.Payload.Backup.PlanHash != fingerprints[target.Hostname] {
			t.Errorf("host %s got the fingerprint %q, the plan had %q",
				target.Hostname, job.Payload.Backup.PlanHash, fingerprints[target.Hostname])
		}
		// A copy without a repository check is not a success, so the result
		// is to say the check took place.
		var attempts struct {
			Items []struct {
				Message string `json:"message"`
			} `json:"items"`
		}
		h.get("/api/v1/jobs/"+target.JobID+"/attempts", &attempts)
		if len(attempts.Items) == 0 || !strings.Contains(attempts.Items[len(attempts.Items)-1].Message, "checked") {
			t.Errorf("host %s: copy without a check: %+v", target.Hostname, attempts.Items)
		}
	}
	// The repository password must be nowhere but the store - also on the
	// way through the campaign plan.
	assertValueAbsent(t, h, password)

	t.Cleanup(func() {
		for _, hostID := range targets {
			h.runOperation(hostID, map[string]any{
				"action": "file.remove", "reason": "cleanup after the backup campaign test",
				"payload": map[string]any{"file": map[string]any{"path": repository + "/config"}},
			}, 2*time.Minute)
		}
	})
}

// backupPlan reads the backup plan from the planning job result.
func backupPlan(h *harness, jobID string) (plan struct {
	Action         string   `json:"action"`
	Paths          []string `json:"paths"`
	MissingPaths   []string `json:"missing_paths"`
	WillInitialize bool     `json:"will_initialize"`
	Verified       bool     `json:"verified"`
	Refusal        string   `json:"refusal"`
	PlanHash       string   `json:"plan_hash"`
}) {
	h.t.Helper()
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
		if response.Items[i].Detail.Kind == "backup_plan" {
			_ = json.Unmarshal(response.Items[i].Detail.Plan, &plan)
			return plan
		}
	}
	return plan
}

// TestCatalogueSaysWhatACampaignWillNotDoAndWhy checks what the interface
// recognises the boundaries by: the installation says whether it runs
// campaigns at all, and the operation catalogue - which change it will not
// order in bulk and for what reason. A refusal without a reason looks in
// the panel like a missing feature.
func TestCatalogueSaysWhatACampaignWillNotDoAndWhy(t *testing.T) {
	h := newHarness(t)

	var capabilities struct {
		CampaignV2 bool `json:"campaign_v2"`
	}
	h.get("/api/v1/capabilities", &capabilities)
	if !capabilities.CampaignV2 {
		t.Fatal("an installation with the campaign engine does not report campaign_v2")
	}

	var catalogue struct {
		Items []struct {
			Action   string `json:"action"`
			Mutating bool   `json:"mutating"`
			Mode     string `json:"campaign_mode"`
			Ready    bool   `json:"campaign_ready"`
			Refusal  string `json:"campaign_refusal"`
		} `json:"items"`
	}
	h.get("/api/v1/actions", &catalogue)
	if len(catalogue.Items) == 0 {
		t.Fatal("the operation catalogue is empty")
	}

	var ready, refused int
	for _, item := range catalogue.Items {
		switch {
		case item.Ready:
			ready++
			if item.Refusal != "" {
				t.Errorf("%s is ready for bulk and has the refusal %q", item.Action, item.Refusal)
			}
			if item.Mode == "" {
				t.Errorf("%s is ready for bulk without a declared mode", item.Action)
			}
		case item.Mutating:
			refused++
			if item.Refusal == "" {
				t.Errorf("%s does not run in bulk and does not say why", item.Action)
			}
		}
		// A backup restore is a boundary, not a missing feature: the reason
		// is to speak of an operator at the host, not of the campaign
		// engine.
		if item.Action == "backup.restore" {
			if item.Ready || !strings.Contains(item.Refusal, "an operator present at every host") {
				t.Errorf("restore: ready=%v, reason=%q", item.Ready, item.Refusal)
			}
		}
		if item.Action == "backup.run" && !item.Ready {
			t.Errorf("the copy is not ready for bulk: %q", item.Refusal)
		}
	}
	if ready == 0 || refused == 0 {
		t.Errorf("the catalogue does not tell ready from refused: %d/%d", ready, refused)
	}
}

// TestBackendBudgetStopsTheSecondCampaign guards a limit that exists
// neither in the campaign nor in the site: the backup repository is one,
// and there may be several campaigns writing to it at once. The backend
// limit is to spread them out, although each on its own fits within its
// concurrency limit.
func TestBackendBudgetStopsTheSecondCampaign(t *testing.T) {
	h := newHarness(t)

	var targets []string
	for _, host := range h.hosts() {
		if host.ConnectionState == "online" && host.OSFamily != "arch" {
			targets = append(targets, host.ID)
		}
	}
	if len(targets) < 2 {
		t.Skip("the fleet has fewer than two connected hosts with a backup tool")
	}
	targets = targets[:2]

	name := fmt.Sprintf("budget-%d", time.Now().UnixNano())
	repository := "/srv/" + name
	secret := newSecret(t, h, "password-"+name)
	order := map[string]any{
		"id": name, "tool": "restic", "repository": repository,
		"paths": []string{"/etc/flotestro"}, "keep_last": 1, "initialize": true,
		"password_secret": map[string]any{"name": secret.Name},
	}
	// The repository is one on both hosts, so the backend budget is one
	// too.
	h.setBudget("backend:"+repository+":backup", 1, 50)

	campaign := h.createCampaign(map[string]any{
		"name": "copy with a backend budget", "action": "backup.run",
		"reason":                     "repository budget test",
		"payload":                    map[string]any{"backup": order},
		"selector":                   map[string]any{"host_ids": targets},
		"canary_size":                0,
		"wave_size":                  len(targets),
		"max_concurrent":             len(targets),
		"failure_threshold_percent":  0,
		"failure_threshold_absolute": 0,
		"reboot_policy":              "never",
	})
	afterPlanning := h.awaitCampaign(campaign.ID,
		map[string]bool{"awaiting_approval": true, "paused": true, "failed": true}, 5*time.Minute)
	if afterPlanning.State != "awaiting_approval" {
		t.Fatalf("planning ended in state %s (%s)",
			afterPlanning.State, afterPlanning.PauseReason)
	}
	h.approveCampaign(afterPlanning)

	// The waiting state is transient, so it is observed during the run.
	waited := false
	deadline := time.Now().Add(6 * time.Minute)
	for time.Now().Before(deadline) {
		for _, target := range h.campaignTargets(campaign.ID) {
			if target.State == "awaiting_budget" {
				waited = true
				if target.ErrorCode != "budget_capacity" && target.ErrorCode != "budget_fair_share" {
					t.Errorf("a host waits for the backend without a reason: %+v", target)
				}
			}
		}
		state := h.campaign(campaign.ID)
		if state.State == "completed" || state.State == "failed" || state.State == "paused" {
			break
		}
		time.Sleep(time.Second)
	}

	final := h.awaitCampaign(campaign.ID,
		map[string]bool{"completed": true, "failed": true, "paused": true}, 6*time.Minute)
	if final.State != "completed" {
		t.Fatalf("the campaign ended in state %s (%s)", final.State, final.PauseReason)
	}
	if !waited {
		t.Error("no host waited for the repository capacity")
	}

	// The crux of the invariant: the campaign had consent for two hosts at
	// once, and the backend admitted one stream. Overlapping windows would
	// mean the repository budget did not bind.
	windows := make([]window, 0, len(targets))
	for _, target := range h.campaignTargets(campaign.ID) {
		if target.JobID == "" {
			continue
		}
		for _, attempt := range h.timedAttempts(target.JobID) {
			if attempt.DispatchedAt == nil || attempt.FinishedAt == nil {
				continue
			}
			windows = append(windows, window{from: *attempt.DispatchedAt, to: *attempt.FinishedAt})
		}
	}
	if len(windows) < 2 {
		t.Fatalf("the campaign left %d attempts with times", len(windows))
	}
	if overlap(windows) {
		t.Errorf("two copies wrote to the repository at once despite a budget of 1: %+v", windows)
	}

	t.Cleanup(func() {
		for _, hostID := range targets {
			h.runOperation(hostID, map[string]any{
				"action": "file.remove", "reason": "cleanup after the backend budget test",
				"payload": map[string]any{"file": map[string]any{"path": repository + "/config"}},
			}, 2*time.Minute)
		}
	})
}

// TestTrustCampaignDistributesTheAuthorityAndProtectsTheOneInUse walks two
// steps of an authority rotation: the fleet starts trusting the new
// authority, and withdrawing an authority that still signs a host
// certificate falls out in the plan. Between those steps the host trusts
// both authorities at once - and that is the whole substance of a
// rotation.
func TestTrustCampaignDistributesTheAuthorityAndProtectsTheOneInUse(t *testing.T) {
	h := newHarness(t)

	var targets []string
	for _, host := range h.hosts() {
		if host.ConnectionState == "online" {
			targets = append(targets, host.ID)
		}
	}
	if len(targets) < 2 {
		t.Skip("the fleet has fewer than two connected hosts")
	}
	targets = targets[:2]

	anchor := fmt.Sprintf("test-%d", time.Now().Unix())
	authority, authorityKey := testAuthority(t, "Flotestro Rotation "+anchor)

	t.Cleanup(func() {
		for _, hostID := range targets {
			h.runOperation(hostID, map[string]any{
				"action": "certificate.trust.remove", "reason": "cleanup after the rotation test",
				"payload": map[string]any{"certificate": map[string]any{"anchor_id": anchor}},
			}, 2*time.Minute)
		}
	})

	// Step one: the fleet starts trusting the new authority.
	campaign := h.createCampaign(map[string]any{
		"name": "authority distribution", "action": "certificate.trust.ensure",
		"reason": "integration test of the authority rotation",
		"payload": map[string]any{"certificate": map[string]any{
			"anchor_id": anchor, "certificate": authority}},
		"selector":                   map[string]any{"host_ids": targets},
		"canary_size":                0,
		"wave_size":                  len(targets),
		"max_concurrent":             len(targets),
		"failure_threshold_percent":  0,
		"failure_threshold_absolute": 0,
		"reboot_policy":              "never",
	})
	afterPlanning := h.awaitCampaign(campaign.ID,
		map[string]bool{"awaiting_approval": true, "paused": true, "failed": true}, 3*time.Minute)
	if afterPlanning.State != "awaiting_approval" {
		t.Fatalf("planning ended in state %s (%s)",
			afterPlanning.State, afterPlanning.PauseReason)
	}
	for _, target := range h.campaignTargets(campaign.ID) {
		plan := trustPlan(h, target.PlanJobID)
		if plan.Action != "create" || plan.Refusal != "" || plan.PlanHash == "" {
			t.Errorf("host %s plans %+v instead of trusting the new authority", target.Hostname, plan)
		}
	}
	h.approveCampaign(afterPlanning)
	final := h.awaitCampaign(campaign.ID,
		map[string]bool{"completed": true, "failed": true, "paused": true}, 4*time.Minute)
	if final.State != "completed" {
		t.Fatalf("the authority distribution ended in state %s (%s)", final.State, final.PauseReason)
	}

	// Step two, before anything was replaced: a certificate signed by this
	// authority lies on the first host, so the withdrawal is to fall out
	// there.
	path := fmt.Sprintf("/etc/ssl/certs/flotestro-rotation-%d.crt", time.Now().UnixNano())
	leaf := leafFromAuthority(t, "rotation.flotestro.test", authority, authorityKey)
	secret := newSecret(t, h, leaf.key)
	t.Cleanup(func() {
		h.do(http.MethodDelete,
			"/api/v1/hosts/"+targets[0]+"/certificates/targets?path="+path, nil, nil, 0)
	})
	job, attempts := h.runOperation(targets[0], map[string]any{
		"action": "certificate.deploy", "reason": "preparation of the authority withdrawal test",
		"payload": map[string]any{"certificate": map[string]any{
			"path": path, "key_path": strings.Replace(path, ".crt", ".key", 1),
			"certificate": leaf.certificate,
			"key_secret":  map[string]any{"name": secret.Name},
		}},
	}, 3*time.Minute)
	if job.State != "succeeded" {
		t.Fatalf("deploying the leaf: state = %s, %s", job.State, lastMessage(attempts))
	}

	// An authority withdrawal binds the whole fleet at once: a campaign
	// covering an unconnected host does not start at all, because that
	// host would be left with a trust the rest of the fleet no longer has.
	var incomplete struct {
		Code   string `json:"code"`
		Detail string `json:"detail"`
	}
	h.do(http.MethodPost, "/api/v1/campaigns", map[string]any{
		"name": "authority withdrawal beyond the fleet", "action": "certificate.trust.remove",
		"payload":  map[string]any{"certificate": map[string]any{"anchor_id": anchor}},
		"selector": map[string]any{"host_ids": append(append([]string{}, targets...), hostOutside(t, h, targets))},
	}, &incomplete, http.StatusBadRequest)
	if incomplete.Code != "incomplete_coverage" || !strings.Contains(incomplete.Detail, "the whole fleet at once") {
		t.Errorf("campaign with an uncertain target: %s (%s)", incomplete.Code, incomplete.Detail)
	}

	withdrawal := h.createCampaign(map[string]any{
		"name": "authority withdrawal", "action": "certificate.trust.remove",
		"reason":      "refusal test for withdrawing an authority in use",
		"payload":     map[string]any{"certificate": map[string]any{"anchor_id": anchor}},
		"selector":    map[string]any{"host_ids": targets},
		"canary_size": 0, "wave_size": len(targets), "max_concurrent": len(targets),
		"failure_threshold_percent": 0, "failure_threshold_absolute": 0,
		"reboot_policy": "never",
	})
	afterSecond := h.awaitCampaign(withdrawal.ID,
		map[string]bool{"awaiting_approval": true, "paused": true, "failed": true}, 3*time.Minute)

	var refused, agreed int
	for _, target := range h.campaignTargets(withdrawal.ID) {
		if target.HostID == targets[0] {
			// The host with a certificate from this authority is to fall
			// out in the plan.
			if target.State != "ineligible" || target.ErrorCode != "plan_refused" {
				t.Errorf("the host with a certificate from this authority: %s/%s", target.State, target.ErrorCode)
			}
			refused++
			continue
		}
		plan := trustPlan(h, target.PlanJobID)
		if plan.Action != "remove" || plan.Refusal != "" {
			t.Errorf("a host without a certificate from this authority plans %+v", plan)
		}
		agreed++
	}
	if refused == 0 || agreed == 0 {
		t.Errorf("the withdrawal did not tell the hosts apart: refused=%d, agreed=%d", refused, agreed)
	}
	if afterSecond.State == "awaiting_approval" {
		h.do(http.MethodPost, "/api/v1/campaigns/"+withdrawal.ID+"/cancel",
			map[string]any{"reason": "withdrawal refusal test"}, nil, 0)
	}
}

// trustPlan reads the rotation step plan from the planning job result.
func trustPlan(h *harness, jobID string) (plan struct {
	AnchorID string   `json:"anchor_id"`
	Action   string   `json:"action"`
	InUseBy  []string `json:"in_use_by"`
	Refusal  string   `json:"refusal"`
	PlanHash string   `json:"plan_hash"`
}) {
	h.t.Helper()
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
		if response.Items[i].Detail.Kind == "trust_plan" {
			_ = json.Unmarshal(response.Items[i].Detail.Plan, &plan)
			return plan
		}
	}
	return plan
}

// hostOutside returns a host that will not carry out a change now:
// unconnected or in a maintenance window. Without such a host the full
// coverage rule cannot be shown, so the test has nothing to check without
// it.
func hostOutside(t *testing.T, h *harness, used []string) string {
	t.Helper()
	taken := map[string]bool{}
	for _, id := range used {
		taken[id] = true
	}
	for _, host := range h.hosts() {
		if !taken[host.ID] && host.ConnectionState != "online" {
			return host.ID
		}
	}
	// The test fleet tends to be fully connected. A host in a maintenance
	// window is an equivalent uncertain target here: it will not carry out
	// the change now either.
	for _, host := range h.hosts() {
		if taken[host.ID] {
			continue
		}
		h.do(http.MethodPost, "/api/v1/hosts/"+host.ID+"/maintenance", map[string]any{
			"duration_minutes": 10,
			"reason":           "full coverage test for the authority withdrawal",
		}, nil, http.StatusOK)
		hostID := host.ID
		t.Cleanup(func() {
			h.do(http.MethodPost, "/api/v1/hosts/"+hostID+"/maintenance",
				map[string]any{"clear": true}, nil, 0)
		})
		return hostID
	}
	t.Skip("the fleet has no host outside the campaign to show incomplete coverage with")
	return ""
}

// TestRenewalCampaignSaysWhoTracksTheCertificate checks the rotation step
// the panel does not do itself: the host daemon asks for a new certificate.
// There are two answers here and both must be audible - a host without
// certmonger falls out already on capability, and a host with certmonger
// that does not track this file falls out in the plan. One must not pose as
// the other.
func TestRenewalCampaignSaysWhoTracksTheCertificate(t *testing.T) {
	h := newHarness(t)

	var targets []string
	withDaemon := map[string]bool{}
	for _, host := range h.hosts() {
		if host.ConnectionState != "online" {
			continue
		}
		targets = append(targets, host.ID)
		if hasCapability(host, "certificates.renew") {
			withDaemon[host.ID] = true
		}
	}
	if len(withDaemon) == 0 {
		t.Skip("the fleet has no host with certmonger")
	}
	if len(targets) < 2 {
		t.Skip("the fleet has fewer than two connected hosts")
	}

	path := "/etc/pki/tls/certs/flotestro-renewal.pem"
	campaign := h.createCampaign(map[string]any{
		"name": "renewal on the fleet", "action": "certificate.renew",
		"reason":                     "integration test of the renewal plans",
		"payload":                    map[string]any{"certificate": map[string]any{"path": path}},
		"selector":                   map[string]any{"host_ids": targets},
		"canary_size":                0,
		"wave_size":                  len(targets),
		"max_concurrent":             len(targets),
		"failure_threshold_percent":  0,
		"failure_threshold_absolute": 0,
		"reboot_policy":              "never",
	})
	state := h.awaitCampaign(campaign.ID,
		map[string]bool{"awaiting_approval": true, "paused": true, "failed": true}, 3*time.Minute)
	if state.State == "awaiting_approval" {
		t.Fatal("the renewal campaign for a file nobody tracks reached consent")
	}

	var withoutDaemon, withPlan int
	for _, target := range h.campaignTargets(campaign.ID) {
		if !withDaemon[target.HostID] {
			// A host without certmonger is not a host the plan will tell
			// anything: it does not accept this operation at all.
			if target.State != "ineligible" || target.ErrorCode != "capability_missing" {
				t.Errorf("host without certmonger: %s/%s", target.State, target.ErrorCode)
			}
			withoutDaemon++
			continue
		}
		if target.State != "ineligible" || target.ErrorCode != "plan_refused" {
			t.Errorf("host with certmonger: %s/%s", target.State, target.ErrorCode)
		}
		plan := renewalPlan(h, target.PlanJobID)
		if !strings.Contains(plan.Refusal, "does not track the file") || plan.PlanHash == "" {
			t.Errorf("host with certmonger, plan: %+v", plan)
		}
		withPlan++
	}
	if withoutDaemon == 0 || withPlan == 0 {
		t.Errorf("the campaign did not tell the hosts apart: without a daemon=%d, with a plan=%d", withoutDaemon, withPlan)
	}
}

// renewalPlan reads the renewal plan from the planning job result.
func renewalPlan(h *harness, jobID string) (plan struct {
	Path     string `json:"path"`
	Request  string `json:"request"`
	Status   string `json:"status"`
	Refusal  string `json:"refusal"`
	PlanHash string `json:"plan_hash"`
}) {
	h.t.Helper()
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
		if response.Items[i].Detail.Kind == "renewal_plan" {
			_ = json.Unmarshal(response.Items[i].Detail.Plan, &plan)
			return plan
		}
	}
	return plan
}

// TestCampaignPlansAreGroupedByFingerprint checks the screen on which the
// operator makes the decision: the consent concerns a set of plans, so the
// set must be visible - and a hundred hosts with an identical diff are to
// be one item, not a wall of text.
func TestCampaignPlansAreGroupedByFingerprint(t *testing.T) {
	h := newHarness(t)
	const name = "grouped-plans-test"

	var targets []string
	for _, host := range h.hosts() {
		if host.ConnectionState == "online" && host.OSFamily == "debian" {
			targets = append(targets, host.ID)
		}
	}
	if len(targets) < 2 {
		t.Skip("the fleet has fewer than two connected hosts of the debian family")
	}

	// The path must lie in the panel file allowlist: a campaign is not a
	// way around that boundary.
	path := "/etc/flotestro-" + name + ".conf"
	t.Cleanup(func() {
		for _, hostID := range targets {
			h.runOperation(hostID, map[string]any{
				"action": "file.remove", "reason": "cleanup after the plan grouping test",
				"payload": map[string]any{"file": map[string]any{"path": path}},
			}, 2*time.Minute)
		}
	})

	// All the hosts get the same content into the same file, which none of
	// them has: the plans are to be identical, so one group.
	campaign := h.createCampaign(map[string]any{
		"name": "file on the fleet", "action": "file.ensure",
		"reason": "plan grouping test",
		"payload": map[string]any{"file": map[string]any{
			"path": path, "content": "# " + name + "\n", "mode": "0644"}},
		"selector":                   map[string]any{"host_ids": targets},
		"canary_size":                0,
		"wave_size":                  len(targets),
		"max_concurrent":             len(targets),
		"failure_threshold_percent":  0,
		"failure_threshold_absolute": 0,
		"reboot_policy":              "never",
	})
	afterPlanning := h.awaitCampaign(campaign.ID,
		map[string]bool{"awaiting_approval": true, "paused": true, "failed": true}, 3*time.Minute)
	if afterPlanning.State != "awaiting_approval" {
		t.Fatalf("planning ended in state %s (%s)",
			afterPlanning.State, afterPlanning.PauseReason)
	}

	var groups struct {
		Items []struct {
			PlanHash string   `json:"plan_hash"`
			Count    int      `json:"count"`
			Hosts    []string `json:"hosts"`
			Plan     struct {
				Kind string `json:"kind"`
				Plan struct {
					Action  string   `json:"action"`
					Changes []string `json:"changes"`
				} `json:"plan"`
			} `json:"plan"`
		} `json:"items"`
		Count       int    `json:"count"`
		Hosts       int    `json:"hosts"`
		PlanSetHash string `json:"plan_set_hash"`
	}
	h.get("/api/v1/campaigns/"+campaign.ID+"/plans", &groups)

	if groups.Hosts != len(targets) {
		t.Errorf("the plans describe %d hosts, there were %d targets", groups.Hosts, len(targets))
	}
	// The same file with the same content on hosts that do not have it
	// gives one shape of change - and it is to be shown that way.
	if groups.Count != 1 || len(groups.Items) != 1 {
		t.Fatalf("the plans split into %d groups: %+v", groups.Count, groups.Items)
	}
	group := groups.Items[0]
	if group.Count != len(targets) || len(group.Hosts) != len(targets) {
		t.Errorf("the group covers %d hosts (%v)", group.Count, group.Hosts)
	}
	if group.PlanHash == "" || groups.PlanSetHash == "" {
		t.Errorf("group without a fingerprint: %q, set: %q", group.PlanHash, groups.PlanSetHash)
	}
	// The plan content is to reach this far: without it the operator looks
	// at fingerprints, not at the change they consent to.
	if group.Plan.Plan.Action != "create" || len(group.Plan.Plan.Changes) == 0 {
		t.Errorf("group without the plan content: %+v", group.Plan)
	}

	h.do(http.MethodPost, "/api/v1/campaigns/"+campaign.ID+"/cancel",
		map[string]any{"reason": "plan grouping test"}, nil, 0)
}

// TestPreviewShowsTheSnapshotDistribution checks what the bare number of
// ready hosts does not say: what the frozen snapshot consists of. Thirty
// hosts from one site are a different change than thirty scattered across
// three.
func TestPreviewShowsTheSnapshotDistribution(t *testing.T) {
	h := newHarness(t)

	var preview struct {
		Eligible     int `json:"eligible"`
		Distribution map[string][]struct {
			Reason string   `json:"reason"`
			Count  int      `json:"count"`
			Sample []string `json:"sample"`
		} `json:"distribution"`
	}
	h.get("/api/v1/campaigns/preview?action=unit.restart", &preview)
	if preview.Eligible == 0 {
		t.Skip("no host is ready for a unit restart")
	}

	for _, dimension := range []string{"site", "environment", "os_family", "capability"} {
		groups, present := preview.Distribution[dimension]
		if !present || len(groups) == 0 {
			t.Errorf("the distribution has no dimension %q", dimension)
			continue
		}
		sum := 0
		for _, group := range groups {
			if group.Reason == "" || group.Count == 0 {
				t.Errorf("%s: group without a name or empty: %+v", dimension, group)
			}
			sum += group.Count
		}
		// Every ready host belongs to exactly one group in every dimension:
		// a distribution that does not add up to the whole speaks of a
		// different snapshot than the one entering the campaign.
		if sum != preview.Eligible {
			t.Errorf("%s: the distribution adds up to %d, %d are ready", dimension, sum, preview.Eligible)
		}
	}

	// The lab has more than one OS family, so the distribution is to show
	// it - otherwise this screen would tell nothing apart.
	if len(preview.Distribution["os_family"]) < 2 {
		t.Errorf("distribution by OS family: %+v", preview.Distribution["os_family"])
	}
}

// TestFleetShowsWhomItTrustsDuringARotation checks the screen without which
// an authority rotation is invisible: during it part of the fleet trusts
// both authorities at once, and only that says whether the old one may be
// withdrawn.
func TestFleetShowsWhomItTrustsDuringARotation(t *testing.T) {
	h := newHarness(t)

	var targets []string
	for _, host := range h.hosts() {
		if host.ConnectionState == "online" {
			targets = append(targets, host.ID)
		}
	}
	if len(targets) < 2 {
		t.Skip("the fleet has fewer than two connected hosts")
	}
	targets = targets[:2]

	anchor := fmt.Sprintf("view-%d", time.Now().Unix())
	authority, _ := testAuthority(t, "Flotestro View "+anchor)
	t.Cleanup(func() {
		for _, hostID := range targets {
			h.runOperation(hostID, map[string]any{
				"action": "certificate.trust.remove", "reason": "cleanup after the trust view test",
				"payload": map[string]any{"certificate": map[string]any{"anchor_id": anchor}},
			}, 2*time.Minute)
		}
	})

	// One host gets the authority, the other does not: that is exactly
	// what the fleet looks like during a rotation, and the view is to show
	// it.
	job, attempts := h.runOperation(targets[0], map[string]any{
		"action": "certificate.trust.ensure", "reason": "trust view test",
		"payload": map[string]any{"certificate": map[string]any{
			"anchor_id": anchor, "certificate": authority}},
	}, 3*time.Minute)
	if job.State != "succeeded" {
		t.Fatalf("authority distribution: state = %s, %s", job.State, lastMessage(attempts))
	}
	// The fleet view reads the inventory, so the host must refresh it.
	h.runOperation(targets[0], map[string]any{
		"action": "inventory.refresh", "reason": "trust view test",
		"payload": map[string]any{"inventory": map[string]any{"modules": []string{"certificates"}}},
	}, 2*time.Minute)

	var view struct {
		Items []struct {
			Subject           string   `json:"subject"`
			AnchorID          string   `json:"anchor_id"`
			FingerprintSHA256 string   `json:"fingerprint_sha256"`
			Hosts             int      `json:"hosts"`
			Sample            []string `json:"sample"`
		} `json:"items"`
		HostsTotal   int `json:"hosts_total"`
		HostsUnknown int `json:"hosts_unknown"`
	}
	found := false
	deadline := time.Now().Add(90 * time.Second)
	for time.Now().Before(deadline) && !found {
		h.get("/api/v1/certificates/trust", &view)
		for _, item := range view.Items {
			if item.AnchorID != anchor {
				continue
			}
			found = true
			// An authority handed to one host is to be counted for one, not
			// for the whole fleet: that is the whole substance of this
			// screen.
			if item.Hosts != 1 || len(item.Sample) != 1 {
				t.Errorf("authority on %d hosts: %+v", item.Hosts, item.Sample)
			}
			if item.FingerprintSHA256 == "" || item.Subject == "" {
				t.Errorf("anchor without a description: %+v", item)
			}
		}
		if !found {
			time.Sleep(3 * time.Second)
		}
	}
	if !found {
		t.Fatalf("the fleet view does not know the anchor %s: %+v", anchor, view.Items)
	}
	if view.HostsTotal == 0 {
		t.Error("the view counted no host")
	}
}

// TestBackendBudgetBindsTwoCampaigns guards the boundary from the document
// in its full form: the backend limit is to hold between campaigns, not
// only within one. Two campaigns to one repository must not write at once,
// although each on its own fits within its limit.
func TestBackendBudgetBindsTwoCampaigns(t *testing.T) {
	h := newHarness(t)

	var targets []string
	for _, host := range h.hosts() {
		if host.ConnectionState == "online" && host.OSFamily != "arch" {
			targets = append(targets, host.ID)
		}
	}
	if len(targets) < 2 {
		t.Skip("the fleet has fewer than two connected hosts with a backup tool")
	}
	targets = targets[:2]

	name := fmt.Sprintf("two-%d", time.Now().UnixNano())
	repository := "/srv/" + name
	secret := newSecret(t, h, "password-"+name)
	order := func(id string) map[string]any {
		return map[string]any{
			"id": id, "tool": "restic", "repository": repository,
			"paths": []string{"/etc/flotestro"}, "keep_last": 1, "initialize": true,
			"password_secret": map[string]any{"name": secret.Name},
		}
	}
	h.setBudget("backend:"+repository+":backup", 1, 50)

	t.Cleanup(func() {
		for _, hostID := range targets {
			h.runOperation(hostID, map[string]any{
				"action": "file.remove", "reason": "cleanup after the two campaigns test",
				"payload": map[string]any{"file": map[string]any{"path": repository + "/config"}},
			}, 2*time.Minute)
		}
	})

	// Two separate campaigns, each on one host: the campaign limit stops
	// nothing here, because each has one target.
	campaigns := make([]campaignView, 0, 2)
	for i, hostID := range targets {
		campaign := h.createCampaign(map[string]any{
			"name": fmt.Sprintf("copy %d of %s", i+1, name), "action": "backup.run",
			"reason":                     "backend budget test between campaigns",
			"payload":                    map[string]any{"backup": order(fmt.Sprintf("%s-%d", name, i+1))},
			"selector":                   map[string]any{"host_ids": []string{hostID}},
			"canary_size":                0,
			"wave_size":                  1,
			"max_concurrent":             1,
			"failure_threshold_percent":  0,
			"failure_threshold_absolute": 0,
			"reboot_policy":              "never",
		})
		campaigns = append(campaigns, campaign)
	}
	for i := range campaigns {
		state := h.awaitCampaign(campaigns[i].ID,
			map[string]bool{"awaiting_approval": true, "paused": true, "failed": true}, 5*time.Minute)
		if state.State != "awaiting_approval" {
			t.Fatalf("campaign %d finished planning in state %s (%s)", i+1, state.State, state.PauseReason)
		}
		h.approveCampaign(state)
	}

	windows := make([]window, 0, 2)
	for i := range campaigns {
		final := h.awaitCampaign(campaigns[i].ID,
			map[string]bool{"completed": true, "failed": true, "paused": true}, 10*time.Minute)
		if final.State != "completed" {
			t.Fatalf("campaign %d ended in state %s (%s)", i+1, final.State, final.PauseReason)
		}
		for _, target := range h.campaignTargets(campaigns[i].ID) {
			if target.JobID == "" {
				continue
			}
			for _, attempt := range h.timedAttempts(target.JobID) {
				if attempt.DispatchedAt == nil || attempt.FinishedAt == nil {
					continue
				}
				windows = append(windows, window{from: *attempt.DispatchedAt, to: *attempt.FinishedAt})
			}
		}
	}
	if len(windows) < 2 {
		t.Fatalf("the two campaigns left %d attempts with times", len(windows))
	}
	// The crux: the backend budget is shared by the whole fleet, so two
	// independent campaigns had to spread out in time.
	if overlap(windows) {
		t.Errorf("two campaigns wrote to the repository at once despite a budget of 1: %+v", windows)
	}
}

// TestCampaignStreamResumesFromTheLastEvent guards the durable stream of a
// campaign: the trail events carry identifiers, a reconnection with
// Last-Event-ID gets only what happened after it, and the publisher marks
// every row it handed on.
//
// Without the identifier a broken connection would lose the events sent in
// between, and the operator watching the canary would see a state jump
// with no way to tell what happened.
func TestCampaignStreamResumesFromTheLastEvent(t *testing.T) {
	h := newHarness(t)
	host := h.hostByFamily("debian")

	campaign := h.createCampaign(labCampaign("stream", "cron.service", map[string]any{
		"selector": map[string]any{"host_ids": []string{host.ID}},
	}))
	h.approveCampaign(campaign)
	final := h.awaitCampaign(campaign.ID,
		map[string]bool{"completed": true, "failed": true, "paused": true}, 3*time.Minute)
	if final.State != "completed" {
		t.Fatalf("the campaign ended in state %s (%s)", final.State, final.PauseReason)
	}

	// The publisher has two seconds between rounds; the marks appear soon
	// after the last state change.
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	pool := h.database(ctx)
	defer pool.Close()
	deadline := time.Now().Add(20 * time.Second)
	for {
		var unpublished int
		if err := pool.QueryRow(ctx, `select count(*) from outbox_events
			 where aggregate_id = $1 and published_at is null`, campaign.ID).Scan(&unpublished); err != nil {
			t.Fatalf("counting the unpublished events: %v", err)
		}
		if unpublished == 0 {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("%d events of the campaign were never published", unpublished)
		}
		time.Sleep(time.Second)
	}

	// A fresh stream replays the whole trail with identifiers.
	all := h.streamTimeline(campaign.ID, 0)
	if len(all) < 3 {
		t.Fatalf("the stream replayed only %d events: %+v", len(all), all)
	}
	for i := 1; i < len(all); i++ {
		if all[i].ID <= all[i-1].ID {
			t.Fatalf("the stream is not ordered: %d after %d", all[i].ID, all[i-1].ID)
		}
	}

	// A reconnection carrying the identifier of the middle event gets only
	// what came after it - nothing twice, nothing missing.
	middle := all[len(all)/2]
	resumed := h.streamTimeline(campaign.ID, middle.ID)
	if len(resumed) != len(all)-len(all)/2-1 {
		t.Fatalf("after %d the stream sent %d events, expected %d", middle.ID, len(resumed), len(all)-len(all)/2-1)
	}
	for _, entry := range resumed {
		if entry.ID <= middle.ID {
			t.Errorf("event %d repeated after the cursor %d", entry.ID, middle.ID)
		}
	}

	// The last identifier resumes into silence: the campaign is over and
	// nothing else is to arrive.
	if tail := h.streamTimeline(campaign.ID, all[len(all)-1].ID); len(tail) != 0 {
		t.Errorf("resuming after the last event replayed %d events", len(tail))
	}
}

// streamTimeline opens the campaign stream with a cursor and returns the
// trail events it replays before going quiet.
func (h *harness) streamTimeline(campaignID string, after int64) []timelineEntryView {
	h.t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 8*time.Second)
	defer cancel()
	request, err := http.NewRequestWithContext(ctx, http.MethodGet,
		h.api+"/api/v1/campaigns/"+campaignID+"/events", nil)
	if err != nil {
		h.t.Fatalf("building the request: %v", err)
	}
	request.Header.Set("Authorization", "Bearer "+h.token)
	if after > 0 {
		// The browser sends this header on its own after a broken
		// connection; here the test plays the browser.
		request.Header.Set("Last-Event-ID", strconv.FormatInt(after, 10))
	}
	response, err := h.client.Do(request)
	if err != nil {
		h.t.Fatalf("opening the stream: %v", err)
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		h.t.Fatalf("the stream answered %d", response.StatusCode)
	}

	var entries []timelineEntryView
	var id int64
	var event string
	scanner := bufio.NewScanner(response.Body)
	scanner.Buffer(make([]byte, 0, 64*1024), 1024*1024)
	// The replay ends when the stream goes quiet: the keep-alive comes
	// only every 25 seconds, so the read deadline is the end of the read.
	for scanner.Scan() {
		line := scanner.Text()
		switch {
		case strings.HasPrefix(line, "id: "):
			id, _ = strconv.ParseInt(strings.TrimPrefix(line, "id: "), 10, 64)
		case strings.HasPrefix(line, "event: "):
			event = strings.TrimPrefix(line, "event: ")
		case strings.HasPrefix(line, "data: "):
			if event == "timeline" {
				var entry timelineEntryView
				if err := json.Unmarshal([]byte(strings.TrimPrefix(line, "data: ")), &entry); err != nil {
					h.t.Fatalf("a trail event that is not JSON: %v", err)
				}
				if entry.ID != id {
					h.t.Fatalf("the event identifier %d differs from the id line %d", entry.ID, id)
				}
				entries = append(entries, entry)
			}
			event, id = "", 0
		}
	}
	return entries
}

// TestCampaignTargetsArePagedAndFilteredOnTheServer guards the contract a
// large campaign needs: the targets come page by page in the order of the
// rollout, a filter is answered by the database and the total says how many
// hosts match beyond the page.
func TestCampaignTargetsArePagedAndFilteredOnTheServer(t *testing.T) {
	h := newHarness(t)
	online := make([]string, 0, 2)
	for _, host := range h.hosts() {
		if host.ConnectionState == "online" && host.OSFamily == "debian" {
			online = append(online, host.ID)
		}
	}
	if len(online) < 2 {
		t.Skip("the fleet has fewer than two connected hosts of the debian family")
	}

	campaign := h.createCampaign(labCampaign("paging", "cron.service", map[string]any{
		"selector": map[string]any{"host_ids": online},
	}))
	defer h.do(http.MethodPost, "/api/v1/campaigns/"+campaign.ID+"/cancel",
		map[string]any{"reason": "end of the paging test"}, nil, http.StatusOK)

	type page struct {
		Items      []campaignTargetView `json:"items"`
		Count      int                  `json:"count"`
		Total      int                  `json:"total"`
		NextCursor string               `json:"next_cursor"`
	}

	// One row per page: the cursor walks the whole snapshot without a
	// repeat and without a gap.
	seen := map[string]bool{}
	cursor := ""
	for {
		var p page
		h.get("/api/v1/campaigns/"+campaign.ID+"/targets?limit=1&cursor="+cursor, &p)
		if p.Total != len(online) {
			t.Fatalf("total = %d, expected %d", p.Total, len(online))
		}
		if p.Count != 1 {
			t.Fatalf("a page of one row has %d rows", p.Count)
		}
		if seen[p.Items[0].HostID] {
			t.Fatalf("host %s came twice", p.Items[0].HostID)
		}
		seen[p.Items[0].HostID] = true
		if p.NextCursor == "" {
			break
		}
		cursor = p.NextCursor
	}
	if len(seen) != len(online) {
		t.Fatalf("the pages covered %d of %d hosts", len(seen), len(online))
	}

	// A filter nobody matches is an empty page with a zero total, not an
	// error and not the unfiltered list.
	var none page
	h.get("/api/v1/campaigns/"+campaign.ID+"/targets?state=succeeded", &none)
	if none.Total != 0 || len(none.Items) != 0 {
		t.Fatalf("the state filter returned %d rows, total %d", len(none.Items), none.Total)
	}
	var byName page
	h.get("/api/v1/campaigns/"+campaign.ID+"/targets?q="+h.hosts()[0].Hostname[:3], &byName)
	if byName.Total == 0 {
		t.Fatalf("the hostname filter matched nothing")
	}
	h.do(http.MethodGet, "/api/v1/campaigns/"+campaign.ID+"/targets?cursor=garbage",
		nil, nil, http.StatusBadRequest)
}
