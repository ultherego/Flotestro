//go:build integration

package integration

import (
	"context"
	"net/http"
	"testing"
	"time"
)

// cancelJobView is a job as the cancel protocol tests read it: the state, and
// the record of the cancel - when it was asked of the host, when the host
// answered, and what it answered.
type cancelJobView struct {
	ID                string     `json:"id"`
	State             string     `json:"state"`
	ResultStatus      string     `json:"result_status"`
	ResultErrorCode   string     `json:"result_error_code"`
	CancelRequestedAt *time.Time `json:"cancel_requested_at"`
	CancelAckAt       *time.Time `json:"cancel_ack_at"`
	CancelOutcome     string     `json:"cancel_outcome"`
	CancelPhase       string     `json:"cancel_phase"`
}

func (h *harness) cancelJobView(jobID string) cancelJobView {
	h.t.Helper()
	var job cancelJobView
	h.get("/api/v1/jobs/"+jobID, &job)
	return job
}

// awaitCancelState waits until the job is in one of the wanted states, without
// failing on a terminal state: the cancel protocol ends jobs, and a test of it
// wants to see which end.
func (h *harness) awaitCancelState(jobID string, timeout time.Duration, states ...string) cancelJobView {
	h.t.Helper()
	wanted := map[string]bool{}
	for _, state := range states {
		wanted[state] = true
	}
	deadline := time.Now().Add(timeout)
	var last cancelJobView
	for time.Now().Before(deadline) {
		last = h.cancelJobView(jobID)
		if wanted[last.State] {
			return last
		}
		time.Sleep(500 * time.Millisecond)
	}
	h.t.Fatalf("job %s did not reach %v within %s (state: %s, outcome: %q)",
		jobID, states, timeout, last.State, last.CancelOutcome)
	return last
}

// TestACancelOfARunningPreviewIsAcknowledgedAsInterrupted is the cancel
// protocol on a live host: a cancel of a task the host holds does not write
// "canceled" on its own.
func TestACancelOfARunningPreviewIsAcknowledgedAsInterrupted(t *testing.T) {
	h := newHarness(t)
	ctx := context.Background()
	pool := h.database(ctx)
	host := h.hostByFamily("debian")

	job := followingJournal(t, h, host.ID, "", 60)
	h.awaitJobState(job.ID, 30*time.Second, "running")

	h.do(http.MethodPost, "/api/v1/jobs/"+job.ID+"/cancel",
		map[string]any{"reason": "canceled while the host was on it"}, nil, http.StatusOK)

	// The request is on the trail the instance holding the session reads it from,
	// in the same transaction as the state that says it is pending.
	var requests int
	if err := pool.QueryRow(ctx, `
		select count(*) from outbox_events
		 where aggregate_type = 'job' and aggregate_id = $1::uuid and event_type = 'job.cancel_requested'`,
		job.ID).Scan(&requests); err != nil {
		t.Fatalf("reading the trail: %v", err)
	}
	if requests != 1 {
		t.Errorf("the trail carries %d cancel requests for the job, expected 1", requests)
	}

	canceled := h.awaitCancelState(job.ID, 45*time.Second, "canceled", "succeeded", "failed")
	if canceled.State != "canceled" {
		t.Fatalf("the job is %s after the cancel (outcome %q, code %q), expected canceled",
			canceled.State, canceled.CancelOutcome, canceled.ResultErrorCode)
	}
	if canceled.CancelRequestedAt == nil {
		t.Error("the job does not record when the cancel was asked of the host")
	}
	if canceled.CancelAckAt == nil || canceled.CancelOutcome != "interrupted" {
		t.Errorf("the job was canceled without the host's answer: ack at %v, outcome %q",
			canceled.CancelAckAt, canceled.CancelOutcome)
	}
	if canceled.CancelPhase == "" {
		t.Error("the acknowledgement does not say what the host was doing")
	}
	// The answer is on the trail, and the capacity went back with the
	// settlement rather than with the request.
	var acks int
	if err := pool.QueryRow(ctx, `
		select count(*) from audit_events
		 where action = 'job.cancel_ack' and target_id = $1 and detail->>'outcome' = 'interrupted'`,
		job.ID).Scan(&acks); err != nil {
		t.Fatalf("reading the audit trail: %v", err)
	}
	if acks == 0 {
		t.Error("the acknowledgement of the host is not on the audit trail")
	}
	var held int
	if err := pool.QueryRow(ctx, `select count(*) from budget_leases where owner = $1`, "job:"+job.ID).Scan(&held); err != nil {
		t.Fatalf("reading the budget leases: %v", err)
	}
	if held != 0 {
		t.Errorf("the canceled job still holds %d budget leases", held)
	}

	// The host's own result of the interrupted preview arrives after the
	// acknowledgement and changes nothing: the job stays canceled.
	after := h.awaitCancelState(job.ID, 10*time.Second, "canceled")
	if after.State != "canceled" {
		t.Fatalf("the late result moved the job to %s", after.State)
	}
}

// TestACancelOfAQueuedTaskNeverAsksAHost guards the other path of the
// protocol: a task still in the panel's queue - here on a synthetic host that
// never connected - is canceled at once.
func TestACancelOfAQueuedTaskNeverAsksAHost(t *testing.T) {
	h := newHarness(t)
	ctx := context.Background()
	pool := h.database(ctx)
	host := h.enrollSyntheticHost(t)
	// The host never connected, so it announced no adapter; the order is judged
	// at the door against the registry, and a systemd adapter of an agent that
	// will never answer is what lets the task into the queue.
	if _, err := pool.Exec(ctx, `
		insert into host_capability_registry (host_id, name, version, available, features)
		values ($1::uuid, 'systemd', 1, true, '{}'::jsonb)
		on conflict (host_id, name) do update set available = true`,
		host.ID); err != nil {
		t.Fatalf("giving the synthetic host a systemd adapter: %v", err)
	}

	job := h.createOperation(host.ID, map[string]any{
		"action":  "unit.restart",
		"payload": unitPayload("cron.service"),
	})
	if job.RequiresApproval {
		job = h.approve(job.ID, job.PayloadHash)
	}
	if state := h.job(job.ID).State; state != "queued" {
		t.Fatalf("the task of the offline host is %s, expected queued", state)
	}

	var canceled cancelJobView
	h.do(http.MethodPost, "/api/v1/jobs/"+job.ID+"/cancel",
		map[string]any{"reason": "the host will not come back"}, &canceled, http.StatusOK)
	if canceled.State != "canceled" {
		t.Fatalf("the queued task is %s after the cancel, expected canceled at once", canceled.State)
	}
	if canceled.CancelRequestedAt != nil || canceled.CancelOutcome != "" {
		t.Errorf("a cancel in the queue was recorded as a request to a host: requested at %v, outcome %q",
			canceled.CancelRequestedAt, canceled.CancelOutcome)
	}
	var requests int
	if err := pool.QueryRow(ctx, `
		select count(*) from outbox_events
		 where aggregate_type = 'job' and aggregate_id = $1::uuid and event_type = 'job.cancel_requested'`,
		job.ID).Scan(&requests); err != nil {
		t.Fatalf("reading the trail: %v", err)
	}
	if requests != 0 {
		t.Errorf("the trail carries %d cancel requests for a task no host ever held", requests)
	}
	// A second cancel finds nothing to cancel.
	h.do(http.MethodPost, "/api/v1/jobs/"+job.ID+"/cancel",
		map[string]any{"reason": "again"}, nil, http.StatusConflict)
}

// TestAnOfflineCanaryHoldsTheWaveUntilItIsSkipped is the barrier of the
// document: a canary that was not connected when its turn came stays queued
// offline, and no wave opens over it until somebody skips it with a reason.
func TestAnOfflineCanaryHoldsTheWaveUntilItIsSkipped(t *testing.T) {
	h := newHarness(t)
	offline := h.enrollSyntheticHost(t)
	live := h.hostByFamily("debian")

	campaign := h.createCampaign(labCampaign("offline canary barrier", "cron.service", map[string]any{
		"selector":         map[string]any{"host_ids": []string{offline.ID, live.ID}},
		"canary_size":      1,
		"wave_size":        1,
		"offline_policy":   "wait_until_deadline",
		"deadline_minutes": 60,
	}))
	if campaign.State == "awaiting_approval" {
		campaign = h.approveCampaign(campaign)
	}

	// The canary enters the offline queue; the wave behind it must not
	// start while it waits.
	queued := false
	for deadline := time.Now().Add(45 * time.Second); time.Now().Before(deadline) && !queued; {
		for _, target := range h.campaignTargets(campaign.ID) {
			if target.HostID == offline.ID && target.State == "queued_offline" {
				queued = true
			}
		}
		if !queued {
			time.Sleep(2 * time.Second)
		}
	}
	if !queued {
		t.Fatalf("the canary never entered the offline queue: %+v", h.campaignTargets(campaign.ID))
	}
	for deadline := time.Now().Add(20 * time.Second); time.Now().Before(deadline); {
		for _, target := range h.campaignTargets(campaign.ID) {
			if target.HostID == live.ID && (target.State != "pending" || target.JobID != "") {
				t.Fatalf("the wave opened over an offline canary: host %s stands %s with task %q",
					target.Hostname, target.State, target.JobID)
			}
		}
		time.Sleep(2 * time.Second)
	}

	// The skip is a decision with a reason; without one it is refused,
	// and a host under way or in the queue cannot be skipped.
	var refusal struct {
		Code string `json:"code"`
	}
	h.do(http.MethodPost, "/api/v1/campaigns/"+campaign.ID+"/targets/"+offline.ID+"/skip",
		map[string]any{"reason": ""}, &refusal, http.StatusBadRequest)
	if refusal.Code != "reason_required" {
		t.Errorf("a skip without a reason was refused with %q, expected reason_required", refusal.Code)
	}
	h.do(http.MethodPost, "/api/v1/campaigns/"+campaign.ID+"/targets/"+live.ID+"/skip",
		map[string]any{"reason": "the wave host is not offline"}, &refusal, http.StatusConflict)
	if refusal.Code != "skip_not_allowed" {
		t.Errorf("a skip of a pending host was refused with %q, expected skip_not_allowed", refusal.Code)
	}

	var skipped campaignTargetView
	h.do(http.MethodPost, "/api/v1/campaigns/"+campaign.ID+"/targets/"+offline.ID+"/skip",
		map[string]any{"reason": "the canary machine is in the repair shop"}, &skipped, http.StatusOK)
	if skipped.State != "skipped" || skipped.ErrorCode != "skipped_by_operator" {
		t.Fatalf("the canary stands %s/%s after the skip, expected skipped/skipped_by_operator",
			skipped.State, skipped.ErrorCode)
	}

	// The barrier is open: the first wave starts.
	started := false
	for deadline := time.Now().Add(60 * time.Second); time.Now().Before(deadline) && !started; {
		for _, target := range h.campaignTargets(campaign.ID) {
			if target.HostID == live.ID && target.State != "pending" {
				started = true
			}
		}
		if !started {
			time.Sleep(2 * time.Second)
		}
	}
	if !started {
		t.Fatalf("the wave did not open after the canary was skipped: %+v", h.campaignTargets(campaign.ID))
	}
	final := h.awaitCampaign(campaign.ID,
		map[string]bool{"completed": true, "completed_with_issues": true, "failed": true, "paused": true}, 2*time.Minute)
	if final.State != "completed" {
		t.Errorf("the campaign ended %s (%s); a skipped canary is not a failure", final.State, final.PauseReason)
	}
	for _, target := range h.campaignTargets(campaign.ID) {
		if target.HostID == offline.ID && (target.State != "skipped" || target.Message == "") {
			t.Errorf("the skipped canary stands %s without its reason: %q", target.State, target.Message)
		}
	}
}
