//go:build integration

package integration

// The states of a campaign and of its hosts that the campaigns document names
// and the engine did not have until now.

import (
	"context"
	"net/http"
	"strings"
	"testing"
	"time"
)

// awaitTargetState waits until the campaign's only host is in one of the
// wanted states, and returns it.
func awaitTargetState(t *testing.T, h *harness, campaignID, hostID string, wanted map[string]bool,
	timeout time.Duration) campaignTargetView {
	t.Helper()
	deadline := time.Now().Add(timeout)
	var last campaignTargetView
	for time.Now().Before(deadline) {
		for _, target := range h.campaignTargets(campaignID) {
			if target.HostID != hostID {
				continue
			}
			last = target
			if wanted[target.State] {
				return target
			}
		}
		time.Sleep(2 * time.Second)
	}
	t.Fatalf("the host %s of campaign %s did not reach the expected state (it is %s: %s %s)",
		hostID[:8], campaignID, last.State, last.ErrorCode, last.Message)
	return last
}

// campaignReport reads the report of a campaign.
func campaignReport(h *harness, campaignID string) campaignReportView {
	h.t.Helper()
	var report campaignReportView
	h.get("/api/v1/campaigns/"+campaignID+"/report", &report)
	return report
}

// fileCampaign orders a file.
func fileCampaign(name, path, content string, hostIDs []string) map[string]any {
	return map[string]any{
		"name": name, "action": "file.ensure",
		"reason": "integration test of the campaign states",
		"payload": map[string]any{"file": map[string]any{
			"path": path, "content": content, "mode": "0644"}},
		"selector":                   map[string]any{"host_ids": hostIDs},
		"canary_size":                0,
		"wave_size":                  len(hostIDs),
		"max_concurrent":             len(hostIDs),
		"failure_threshold_percent":  0,
		"failure_threshold_absolute": 0,
		"reboot_policy":              "never",
	}
}

// TestAHostAlreadyInTheDesiredStateEndsNoChange: a file the host already holds
// with the same content gives a plan with nothing to do.
func TestAHostAlreadyInTheDesiredStateEndsNoChange(t *testing.T) {
	h := newHarness(t)
	host := h.hostByFamily("debian")
	const path = "/etc/flotestro-no-change-campaign.conf"
	const content = "already here\n"

	t.Cleanup(func() {
		h.runOperation(host.ID, map[string]any{
			"action": "file.remove", "reason": "cleanup after the no-change test",
			"payload": map[string]any{"file": map[string]any{"path": path}},
		}, 2*time.Minute)
	})
	prepared, attempts := h.runOperation(host.ID, map[string]any{
		"action": "file.ensure", "reason": "preparation of the no-change test",
		"payload": map[string]any{"file": map[string]any{
			"path": path, "content": content, "mode": "0644"}},
	}, 2*time.Minute)
	if prepared.State != "succeeded" {
		t.Fatalf("preparing the file: state = %s, %s", prepared.State, lastMessage(attempts))
	}

	campaign := h.createCampaign(fileCampaign("file already in place", path, content, []string{host.ID}))
	if campaign.State != "planning" {
		t.Fatalf("the file campaign started from state %s", campaign.State)
	}
	final := h.awaitCampaign(campaign.ID,
		map[string]bool{"completed": true, "completed_with_issues": true, "failed": true,
			"plan_failed": true, "paused": true, "awaiting_approval": true}, 3*time.Minute)
	if final.State != "completed" {
		t.Fatalf("the campaign ended in state %s (%s)", final.State, final.PauseReason)
	}
	if final.ApprovedBy != "" {
		t.Errorf("a campaign with nothing to change was approved by %s", final.ApprovedBy)
	}

	targets := h.campaignTargets(campaign.ID)
	if len(targets) != 1 {
		t.Fatalf("the campaign has %d targets, expected one", len(targets))
	}
	target := targets[0]
	if target.State != "no_change" {
		t.Fatalf("the host ended %s (%s: %s), expected no_change", target.State, target.ErrorCode, target.Message)
	}
	if target.ErrorCode != "" {
		t.Errorf("a host that needed no change carries the error code %q", target.ErrorCode)
	}
	// No task ran the change: the plan was the whole of the host's part.
	if target.JobID != "" {
		t.Errorf("a host that needed no change got the task %s", target.JobID)
	}
	if target.PlanJobID == "" {
		t.Error("the host has no plan task, so nothing could have said there was nothing to change")
	} else if action := planAction(h, target.PlanJobID); action != "no_change" {
		t.Errorf("the plan of the host says %q, expected no_change", action)
	}

	report := campaignReport(h, campaign.ID)
	if report.State != "completed" {
		t.Errorf("the report says the campaign is %s, expected completed", report.State)
	}
	if report.Totals["no_change"] != 1 {
		t.Errorf("the report counts no_change: %d, expected 1 (totals: %v)", report.Totals["no_change"], report.Totals)
	}
	if report.Totals["succeeded"] != 0 {
		t.Errorf("the report counts the unchanged host among the succeeded: %v", report.Totals)
	}
	// The steps say the same: the plan ran to its answer, and the change
	// was skipped for that reason.
	steps := h.campaignSteps(campaign.ID, "?host_id="+host.ID)
	byKey := map[string]campaignStepView{}
	for _, step := range steps.Items {
		byKey[step.StepKey] = step
	}
	if plan := byKey["plan"]; plan.State != "succeeded" {
		t.Errorf("the plan step is %s, expected succeeded", plan.State)
	}
	if execute := byKey["execute"]; execute.State != "skipped" || !strings.Contains(execute.Reason, "nothing to change") {
		t.Errorf("the execute step is %s (%q), expected skipped for want of a change", execute.State, execute.Reason)
	}
	// Nothing changed, so there is nothing a compensation could run on.
	var record struct {
		ChangedHosts int `json:"changed_hosts"`
	}
	h.get("/api/v1/campaigns/"+campaign.ID, &record)
	if record.ChangedHosts != 0 {
		t.Errorf("the campaign counts %d changed hosts, expected none", record.ChangedHosts)
	}
}

// TestAFailureUnderTheThresholdEndsCompletedWithIssues: a restart of cron.
func TestAFailureUnderTheThresholdEndsCompletedWithIssues(t *testing.T) {
	h := newHarness(t)
	var withCron, withoutCron *hostView
	for _, host := range h.hosts() {
		if host.ConnectionState != "online" {
			continue
		}
		host := host
		switch {
		case host.OSFamily == "debian" && withCron == nil:
			withCron = &host
		case host.OSFamily != "debian" && withoutCron == nil:
			withoutCron = &host
		}
	}
	if withCron == nil || withoutCron == nil {
		t.Skip("the fleet needs a connected debian host and a connected host of another family")
	}

	campaign := h.createCampaign(labCampaign("restart with one failure", "cron.service", map[string]any{
		"selector":                   map[string]any{"host_ids": []string{withCron.ID, withoutCron.ID}},
		"canary_size":                0,
		"wave_size":                  2,
		"max_concurrent":             2,
		"failure_threshold_percent":  0,
		"failure_threshold_absolute": 2,
	}))
	h.approveCampaign(campaign)
	final := h.awaitCampaign(campaign.ID,
		map[string]bool{"completed": true, "completed_with_issues": true, "failed": true, "paused": true},
		3*time.Minute)
	if final.State != "completed_with_issues" {
		t.Fatalf("the campaign ended in state %s (%s), expected completed_with_issues", final.State, final.PauseReason)
	}

	states := map[string]string{}
	for _, target := range h.campaignTargets(campaign.ID) {
		states[target.HostID] = target.State
	}
	if states[withCron.ID] != "succeeded" {
		t.Errorf("the host with cron ended %s, expected succeeded", states[withCron.ID])
	}
	if states[withoutCron.ID] != "failed" {
		t.Errorf("the host without cron ended %s, expected failed", states[withoutCron.ID])
	}
	report := campaignReport(h, campaign.ID)
	if report.State != "completed_with_issues" {
		t.Errorf("the report says %s, expected completed_with_issues", report.State)
	}
	if report.Totals["succeeded"] != 1 || report.Totals["failed"] != 1 {
		t.Errorf("the report totals are %v, expected one succeeded and one failed", report.Totals)
	}
	if len(report.Failures) != 1 || report.Failures[0].HostID != withoutCron.ID {
		t.Errorf("the report does not name the failed host: %+v", report.Failures)
	}
}

// TestACancelDrainsTheHostUnderWay: a run of a schedule entry holds the units
// lock of the host, so the campaign's restart of cron.
func TestACancelDrainsTheHostUnderWay(t *testing.T) {
	h := newHarness(t)
	ctx := context.Background()
	pool := h.database(ctx)
	host := h.hostByFamily("debian")
	const id = "campaign-states-lock-holder"

	t.Cleanup(func() {
		h.createOperation(host.ID, map[string]any{
			"action": "schedule.remove", "reason": scheduleReason,
			"payload": map[string]any{"schedule": map[string]any{"id": id}},
		})
	})
	entry, attempts := h.runOperation(host.ID, map[string]any{
		"action": "schedule.ensure", "reason": scheduleReason,
		"payload": map[string]any{"schedule": map[string]any{
			"id":         id,
			"expression": "0 5 * * *",
			"command":    []string{"/bin/sleep", "45"},
			"user":       "root",
			"enabled":    false,
		}},
	}, 90*time.Second)
	if entry.State != "succeeded" {
		t.Fatalf("creating the entry: state = %s, %s", entry.State, lastMessage(attempts))
	}
	holder := h.createOperation(host.ID, map[string]any{
		"action": "schedule.run_now", "reason": scheduleReason,
		"payload": map[string]any{"schedule": map[string]any{"id": id}},
	})
	t.Cleanup(func() { h.cancelJob(holder.ID) })
	if holder.RequiresApproval {
		h.approve(holder.ID, holder.PayloadHash)
	}
	awaitRow(ctx, t, pool, holder.ID, 30*time.Second, func(row ackRow) bool { return row.State == "running" })

	campaign := h.createCampaign(labCampaign("cancel while a host waits for a lock", "cron.service", map[string]any{
		"selector":       map[string]any{"host_ids": []string{host.ID}},
		"canary_size":    0,
		"wave_size":      1,
		"max_concurrent": 1,
	}))
	h.approveCampaign(campaign)

	// The host's task reaches the agent and waits behind the run: the
	// target says so, and names what it waits on.
	waiting := awaitTargetState(t, h, campaign.ID, host.ID,
		map[string]bool{"awaiting_lock": true, "running": true, "succeeded": true, "failed": true}, 90*time.Second)
	if waiting.State != "awaiting_lock" {
		t.Fatalf("the host is %s while the lock is held, expected awaiting_lock (%s: %s)",
			waiting.State, waiting.ErrorCode, waiting.Message)
	}
	var blocker string
	if err := pool.QueryRow(ctx, `select blocker from campaign_targets where campaign_id = $1 and host_id = $2`,
		campaign.ID, host.ID).Scan(&blocker); err != nil {
		t.Fatalf("reading the blocker: %v", err)
	}
	if !strings.Contains(blocker, "schedule.run_now") {
		t.Errorf("the blocker does not name the run holding the lock: %q", blocker)
	}

	var canceled campaignView
	h.do(http.MethodPost, "/api/v1/campaigns/"+campaign.ID+"/cancel",
		map[string]any{"reason": "the operator changed their mind"}, &canceled, http.StatusOK)
	if canceled.State != "canceling" {
		t.Fatalf("the cancel of a campaign with a host under way answered %s, expected canceling", canceled.State)
	}
	// A second cancel has nothing to cancel.
	h.do(http.MethodPost, "/api/v1/campaigns/"+campaign.ID+"/cancel",
		map[string]any{"reason": "again"}, nil, http.StatusConflict)

	// The run ends with its sleep, the restart takes the lock and succeeds, and
	// only then is the campaign canceled.
	final := h.awaitCampaign(campaign.ID, map[string]bool{"canceled": true}, 2*time.Minute)
	if final.State != "canceled" {
		t.Fatalf("the campaign ended %s, expected canceled", final.State)
	}
	target := awaitTargetState(t, h, campaign.ID, host.ID,
		map[string]bool{"succeeded": true, "failed": true, "unknown": true, "canceled": true}, 30*time.Second)
	if target.State != "canceled" {
		t.Errorf("the host under way ended %s (%s: %s); a cancel of a task not yet started ends the host canceled",
			target.State, target.ErrorCode, target.Message)
	}
	report := campaignReport(h, campaign.ID)
	if report.State != "canceled" {
		t.Errorf("the report says %s, expected canceled", report.State)
	}
	if report.Totals["canceled"] != 1 {
		t.Errorf("the report of the canceled campaign does not count the host taken back: %v", report.Totals)
	}
	if run := h.awaitTerminal(holder.ID, 60*time.Second); run.State != "succeeded" {
		t.Errorf("the run that held the lock ended as %s (%s)", run.State, run.ResultErrorCode)
	}
}

// TestAPlanRefusedEverywhereEndsPlanFailed: a file outside the allowlist is
// refused by every host at planning.
func TestAPlanRefusedEverywhereEndsPlanFailed(t *testing.T) {
	h := newHarness(t)
	host := h.hostByFamily("debian")
	// Outside the built-in allowlist and outside the paths the panel itself
	// refuses: the refusal has to come from the host's plan.
	const path = "/usr/local/etc/flotestro-outside-the-allowlist.conf"

	campaign := h.createCampaign(fileCampaign("file outside the allowlist", path, "never written\n", []string{host.ID}))
	if campaign.State != "planning" {
		t.Fatalf("the file campaign started from state %s", campaign.State)
	}
	final := h.awaitCampaign(campaign.ID,
		map[string]bool{"plan_failed": true, "paused": true, "failed": true, "completed": true,
			"awaiting_approval": true}, 3*time.Minute)
	if final.State != "plan_failed" {
		t.Fatalf("the campaign ended in state %s (%s), expected plan_failed", final.State, final.PauseReason)
	}
	if !strings.Contains(final.PauseReason, "no host computed a plan") {
		t.Errorf("the reason does not say that no host planned: %q", final.PauseReason)
	}
	targets := h.campaignTargets(campaign.ID)
	if len(targets) != 1 || targets[0].State != "failed" {
		t.Fatalf("the host ended %+v, expected failed at planning", targets)
	}
	if targets[0].ErrorCode == "" {
		t.Error("the host failed its plan without an error code")
	}
	report := campaignReport(h, campaign.ID)
	if report.State != "plan_failed" {
		t.Errorf("the report says %s, expected plan_failed", report.State)
	}
	if report.Totals["failed"] != 1 {
		t.Errorf("the report totals are %v, expected one failed host", report.Totals)
	}
	// A campaign that ended cannot be resumed or canceled.
	h.do(http.MethodPost, "/api/v1/campaigns/"+campaign.ID+"/resume", nil, nil, http.StatusConflict)
	h.do(http.MethodPost, "/api/v1/campaigns/"+campaign.ID+"/cancel",
		map[string]any{"reason": "too late"}, nil, http.StatusConflict)
}
