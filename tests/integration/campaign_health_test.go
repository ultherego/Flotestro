//go:build integration

package integration

import (
	"context"
	"net/http"
	"strings"
	"testing"
	"time"
)

// healthTargetView is a target with the task of its verification, which
// the shared view does not carry.
type healthTargetView struct {
	HostID      string `json:"host_id"`
	Hostname    string `json:"hostname"`
	Wave        int    `json:"wave"`
	State       string `json:"state"`
	ErrorCode   string `json:"error_code"`
	Message     string `json:"message"`
	JobID       string `json:"job_id"`
	HealthJobID string `json:"health_job_id"`
}

func (h *harness) healthTargets(id string) []healthTargetView {
	h.t.Helper()
	var result struct {
		Items []healthTargetView `json:"items"`
	}
	h.get("/api/v1/campaigns/"+id+"/targets", &result)
	return result.Items
}

// stepOf finds one step of a host on the campaign's strip.
func (h *harness) stepOf(campaignID, hostID, key string) campaignStepView {
	h.t.Helper()
	steps := h.campaignSteps(campaignID, "?host_id="+hostID)
	for _, step := range steps.Items {
		if step.StepKey == key {
			return step
		}
	}
	h.t.Fatalf("no %s step for host %s in %+v", key, hostID, steps.Items)
	return campaignStepView{}
}

// onlineDebianHosts returns the connected hosts of the debian family, the
// ones that have a cron.service to restart and to check.
func (h *harness) onlineDebianHosts() []hostView {
	h.t.Helper()
	var online []hostView
	for _, host := range h.hosts() {
		if host.OSFamily == "debian" && host.ConnectionState == "online" {
			online = append(online, host)
		}
	}
	return online
}

// healthCampaign is a cron restart with the given units verified after the
// change, on the given hosts, with no reboot in it.
func healthCampaign(name string, hostIDs []string, units []string) map[string]any {
	return map[string]any{
		"name":                       name,
		"action":                     "unit.restart",
		"payload":                    unitPayload("cron.service"),
		"selector":                   map[string]any{"host_ids": hostIDs},
		"canary_size":                1,
		"wave_size":                  1,
		"max_concurrent":             1,
		"failure_threshold_percent":  20,
		"failure_threshold_absolute": 0,
		"reboot_policy":              "never",
		"health_check_units":         units,
	}
}

// TestCampaignVerifiesUnitsWithoutAReboot guards the health check of a
// campaign that reboots nothing: the units named in the order are verified
// right after the change, with a unit.
func TestCampaignVerifiesUnitsWithoutAReboot(t *testing.T) {
	h := newHarness(t)
	host := h.hostByFamily("debian")

	campaign := h.createCampaign(healthCampaign("health check without a reboot",
		[]string{host.ID}, []string{"cron.service"}))
	h.approveCampaign(campaign)
	final := h.awaitCampaign(campaign.ID,
		map[string]bool{"completed": true, "failed": true, "paused": true}, 3*time.Minute)
	if final.State != "completed" {
		t.Fatalf("the campaign ended in state %s (%s)", final.State, final.PauseReason)
	}

	targets := h.healthTargets(campaign.ID)
	if len(targets) != 1 {
		t.Fatalf("the campaign has %d targets, expected one", len(targets))
	}
	target := targets[0]
	if target.State != "succeeded" {
		t.Fatalf("the target ended %s/%s: %s", target.State, target.ErrorCode, target.Message)
	}
	if target.HealthJobID == "" {
		t.Fatal("the target carries no health check task: the units were never verified")
	}
	// The verification is a read of the units, separate from the change.
	health := h.job(target.HealthJobID)
	if health.ActionType != "unit.status" || health.State != "succeeded" {
		t.Errorf("the health task is %s in state %s, expected a succeeded unit.status", health.ActionType, health.State)
	}
	if health.ID == target.JobID {
		t.Error("the health check reused the task of the change")
	}

	// The strip: the change ran, the reboot was a decision of the policy,
	// the verification followed the change directly.
	verify := h.stepOf(campaign.ID, host.ID, "verify")
	if verify.State != "succeeded" {
		t.Errorf("the verify step is %s (%s), expected succeeded", verify.State, verify.Reason)
	}
	if verify.JobID != target.HealthJobID {
		t.Errorf("the verify step names task %q, the target %q", verify.JobID, target.HealthJobID)
	}
	if verify.DependsOn != "execute" {
		t.Errorf("the verify step followed %q, expected execute", verify.DependsOn)
	}
	reboot := h.stepOf(campaign.ID, host.ID, "reboot")
	if reboot.State != "skipped" || !strings.Contains(reboot.Reason, "never") {
		t.Errorf("the reboot step is %s (%s), expected skipped by the policy", reboot.State, reboot.Reason)
	}
}

// TestACanaryHealthFailureStopsTheNextWave guards the mandatory scenario
// "canary health check negative, wave two stopped": a canary whose change
// succeeded but whose units are not up afterwards fails with
func TestACanaryHealthFailureStopsTheNextWave(t *testing.T) {
	h := newHarness(t)
	online := h.onlineDebianHosts()
	if len(online) < 2 {
		t.Skip("the fleet has fewer than two connected hosts of the debian family")
	}
	hostIDs := make([]string, 0, len(online))
	for _, host := range online {
		hostIDs = append(hostIDs, host.ID)
	}

	campaign := h.createCampaign(healthCampaign("canary health failure",
		hostIDs, []string{"no-such-unit-for-flotestro.service"}))
	h.approveCampaign(campaign)
	paused := h.awaitCampaign(campaign.ID,
		map[string]bool{"paused": true, "completed": true, "failed": true}, 3*time.Minute)
	if paused.State != "paused" {
		t.Fatalf("the campaign ended %s instead of pausing after the canary", paused.State)
	}
	if paused.PausedBy != "system" || paused.PauseReason == "" {
		t.Errorf("paused by %q with reason %q, expected the system with a reason", paused.PausedBy, paused.PauseReason)
	}

	var canary healthTargetView
	for _, target := range h.healthTargets(campaign.ID) {
		if target.Wave == 0 {
			canary = target
			continue
		}
		// The crux of the scenario: nothing beyond the canary was started.
		if target.State != "pending" {
			t.Errorf("host %s of wave %d is %s: the next wave started after a failed canary",
				target.Hostname, target.Wave, target.State)
		}
	}
	if canary.HostID == "" {
		t.Fatal("the campaign has no canary target")
	}
	if canary.State != "failed" || canary.ErrorCode != "health_check_failed" {
		t.Fatalf("the canary ended %s/%s, expected failed/health_check_failed: %s",
			canary.State, canary.ErrorCode, canary.Message)
	}
	// The agent's finding travels in the message: which unit was not up.
	if !strings.Contains(canary.Message, "no-such-unit-for-flotestro.service") {
		t.Errorf("the message does not name the unit that failed the check: %s", canary.Message)
	}
	// The change itself succeeded; only the verification did not.
	change := h.job(canary.JobID)
	if change.State != "succeeded" {
		t.Errorf("the change of the canary is %s, expected succeeded: the failure is to come from the check", change.State)
	}
	verify := h.stepOf(campaign.ID, canary.HostID, "verify")
	if verify.State != "failed" || verify.Reason == "" {
		t.Errorf("the verify step is %s (%q), expected failed with a reason", verify.State, verify.Reason)
	}
	if execute := h.stepOf(campaign.ID, canary.HostID, "execute"); execute.State != "succeeded" {
		t.Errorf("the execute step is %s, expected succeeded", execute.State)
	}
}

// TestAHostStillRebootingWhenTheWindowClosesIsFailedAndPausesTheCampaign
// guards the mandatory scenario "the host does not come back within the
// maintenance window".
func TestAHostStillRebootingWhenTheWindowClosesIsFailedAndPausesTheCampaign(t *testing.T) {
	h := newHarness(t)
	online := h.onlineDebianHosts()
	if len(online) < 2 {
		t.Skip("the fleet has fewer than two connected hosts of the debian family")
	}
	canary, next := online[0], online[1]
	if canary.BootID == "" {
		t.Skipf("host %s reports no boot ID", canary.Hostname)
	}

	windowStart := time.Now().Add(-time.Hour).UTC()
	windowEnd := time.Now().Add(time.Hour).UTC()
	campaign := h.createCampaign(map[string]any{
		"name":                       "window closed mid-reboot",
		"action":                     "unit.restart",
		"payload":                    unitPayload("cron.service"),
		"selector":                   map[string]any{"host_ids": []string{canary.ID, next.ID}},
		"canary_size":                1,
		"wave_size":                  1,
		"max_concurrent":             1,
		"failure_threshold_percent":  0,
		"failure_threshold_absolute": 0,
		"reboot_policy":              "always",
		"maintenance_start":          windowStart.Format(time.RFC3339),
		"maintenance_end":            windowEnd.Format(time.RFC3339),
	})

	// The campaign is not approved: it is moved straight into the state the
	// scenario is about, with the canary away since three minutes before the
	// window ended a second ago.
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	pool := h.database(ctx)
	if _, err := pool.Exec(ctx, `
		update campaign_targets
		   set state = 'rebooting', boot_id_before = $3, message = 'a reboot was scheduled',
		       started_at = now() - interval '4 minutes', state_since = now() - interval '3 minutes'
		 where campaign_id = $1 and host_id = $2`, campaign.ID, canary.ID, canary.BootID); err != nil {
		t.Fatalf("putting the canary mid-reboot: %v", err)
	}
	if _, err := pool.Exec(ctx, `
		update campaigns
		   set state = 'running', started_at = now() - interval '4 minutes',
		       maintenance_end = now() - interval '1 second', updated_at = now()
		 where id = $1`, campaign.ID); err != nil {
		t.Fatalf("closing the window on the campaign: %v", err)
	}

	paused := h.awaitCampaign(campaign.ID,
		map[string]bool{"paused": true, "completed": true, "failed": true}, time.Minute)
	if paused.State != "paused" {
		t.Fatalf("the campaign ended %s instead of pausing (%s)", paused.State, paused.PauseReason)
	}
	if !strings.HasPrefix(paused.PauseReason, "maintenance_window_closed_mid_reboot") {
		t.Errorf("pause reason = %q, expected maintenance_window_closed_mid_reboot", paused.PauseReason)
	}
	if paused.PausedBy != "system" {
		t.Errorf("paused by %q, expected system", paused.PausedBy)
	}

	for _, target := range h.healthTargets(campaign.ID) {
		switch target.HostID {
		case canary.ID:
			if target.State != "failed" || target.ErrorCode != "reboot_window_closed" {
				t.Errorf("the canary ended %s/%s, expected failed/reboot_window_closed: %s",
					target.State, target.ErrorCode, target.Message)
			}
			// The message names the window end and how long the host has
			// been away - the two facts the operator judges the host by.
			if !strings.Contains(target.Message, "window ended at") || !strings.Contains(target.Message, "away for") {
				t.Errorf("the message does not name the window end and the absence: %s", target.Message)
			}
		case next.ID:
			if target.State != "pending" {
				t.Errorf("the host of the next wave is %s: the campaign went on after the window closed", target.State)
			}
		}
	}
	// The reboot step of the canary is closed with the verdict, so the
	// strip says why the host never came back into the campaign.
	reboot := h.stepOf(campaign.ID, canary.ID, "reboot")
	if reboot.State != "failed" || !strings.Contains(reboot.Reason, "reboot_window_closed") {
		t.Errorf("the reboot step is %s (%q), expected failed with reboot_window_closed", reboot.State, reboot.Reason)
	}
}

// TestTheRebootTimeoutIsPartOfTheOrder guards the field on the API: the bound
// is recorded and read back, the default applies when the order says nothing,
// and a value outside the bounds is refused with a reason rather than rounded.
func TestTheRebootTimeoutIsPartOfTheOrder(t *testing.T) {
	h := newHarness(t)
	host := h.hostByFamily("debian")

	var withTimeout struct {
		ID                   string `json:"id"`
		RebootTimeoutSeconds int    `json:"reboot_timeout_seconds"`
		ApprovalFingerprint  string `json:"approval_fingerprint"`
	}
	body := healthCampaign("reboot timeout", []string{host.ID}, nil)
	body["reboot_timeout_seconds"] = 1800
	h.do(http.MethodPost, "/api/v1/campaigns", body, &withTimeout, http.StatusCreated)
	t.Cleanup(func() {
		h.do(http.MethodPost, "/api/v1/campaigns/"+withTimeout.ID+"/cancel",
			map[string]any{"reason": "end of the test"}, nil, 0)
	})
	if withTimeout.RebootTimeoutSeconds != 1800 {
		t.Errorf("the campaign records a reboot timeout of %d, expected 1800", withTimeout.RebootTimeoutSeconds)
	}

	var byDefault struct {
		ID                   string `json:"id"`
		RebootTimeoutSeconds int    `json:"reboot_timeout_seconds"`
		ApprovalFingerprint  string `json:"approval_fingerprint"`
	}
	h.do(http.MethodPost, "/api/v1/campaigns", healthCampaign("reboot timeout by default", []string{host.ID}, nil),
		&byDefault, http.StatusCreated)
	t.Cleanup(func() {
		h.do(http.MethodPost, "/api/v1/campaigns/"+byDefault.ID+"/cancel",
			map[string]any{"reason": "end of the test"}, nil, 0)
	})
	if byDefault.RebootTimeoutSeconds != 900 {
		t.Errorf("a campaign that said nothing waits %d seconds, expected the default 900", byDefault.RebootTimeoutSeconds)
	}
	// The bound is part of what the approver consents to.
	if byDefault.ApprovalFingerprint == withTimeout.ApprovalFingerprint {
		t.Error("the reboot timeout did not change the approval fingerprint")
	}

	for _, seconds := range []int{30, 7201, -5} {
		refused := healthCampaign("reboot timeout out of bounds", []string{host.ID}, nil)
		refused["reboot_timeout_seconds"] = seconds
		h.do(http.MethodPost, "/api/v1/campaigns", refused, nil, http.StatusBadRequest)
	}
}
