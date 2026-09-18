//go:build integration

package integration

import (
	"context"
	"net/http"
	"testing"
	"time"
)

// casTargetView is a campaign target as the compare-and-swap tests read
// it: the identifier is the owner of the host's budget lease, and the
// revision is what a client will send back as If-Match.
type casTargetView struct {
	ID        string `json:"id"`
	HostID    string `json:"host_id"`
	Hostname  string `json:"hostname"`
	State     string `json:"state"`
	JobID     string `json:"job_id"`
	Revision  int64  `json:"revision"`
	ErrorCode string `json:"error_code"`
}

// casCampaignView is the campaign as the compare-and-swap tests read it.
type casCampaignView struct {
	ID          string `json:"id"`
	State       string `json:"state"`
	Revision    int64  `json:"revision"`
	PausedBy    string `json:"paused_by"`
	PauseReason string `json:"pause_reason"`
}

func (h *harness) casCampaign(campaignID string) casCampaignView {
	h.t.Helper()
	var campaign casCampaignView
	h.get("/api/v1/campaigns/"+campaignID, &campaign)
	return campaign
}

func (h *harness) casTargets(campaignID string) []casTargetView {
	h.t.Helper()
	var result struct {
		Items []casTargetView `json:"items"`
	}
	h.get("/api/v1/campaigns/"+campaignID+"/targets", &result)
	return result.Items
}

// underWay says whether the host carries a task of the campaign.
func underWay(state string) bool {
	switch state {
	case "dispatched", "awaiting_lock", "running", "rebooting", "verifying":
		return true
	default:
		return false
	}
}

func settledTarget(state string) bool {
	switch state {
	case "succeeded", "no_change", "failed", "unknown", "skipped", "canceled", "ineligible", "excluded":
		return true
	default:
		return false
	}
}

// TestPauseKeepsTheRunningHostAndStartsNoNewOne is the document's CAM-02:
// a pause ordered while a host carries its task either finds the task
// already created - and then follows it to its end, with the budget lease
// renewed meanwhile - or finds no task, and none comes into being after
// the pause. The campaign is pausing while the host works and paused once
// it settled; no host of the next wave gets a task in between.
func TestPauseKeepsTheRunningHostAndStartsNoNewOne(t *testing.T) {
	h := newHarness(t)
	online := 0
	for _, host := range h.hosts() {
		if host.ConnectionState == "online" && host.Site == "lab" {
			online++
		}
	}
	if online < 2 {
		t.Skip("the test fleet has fewer than two connected hosts in the lab site")
	}
	campaign := h.createCampaign(labCampaign("pause between claim and create", "cron.service", nil))
	if campaign.State == "awaiting_approval" {
		campaign = h.approveCampaign(campaign)
	}
	if h.casCampaign(campaign.ID).Revision == 0 {
		t.Error("the campaign record carries no revision")
	}

	// The first host of the campaign takes its task within a tick or two.
	// The pause is ordered the moment a host is seen carrying one.
	var inFlight *casTargetView
	deadline := time.Now().Add(90 * time.Second)
	for time.Now().Before(deadline) && inFlight == nil {
		for _, target := range h.casTargets(campaign.ID) {
			if underWay(target.State) {
				copied := target
				inFlight = &copied
				break
			}
		}
		if inFlight == nil {
			time.Sleep(200 * time.Millisecond)
		}
	}
	if inFlight == nil {
		t.Skip("no host was seen carrying a task within the test time")
	}
	if inFlight.Revision == 0 {
		t.Error("the target record carries no revision")
	}

	var paused campaignView
	h.do(http.MethodPost, "/api/v1/campaigns/"+campaign.ID+"/pause",
		map[string]any{"reason": "CAM-02"}, &paused, http.StatusOK)
	if paused.State != "pausing" && paused.State != "paused" {
		t.Fatalf("the campaign is %s after the pause, expected pausing or paused", paused.State)
	}
	// Every task that exists now was created before the pause; the set
	// must not grow while the campaign pauses and after it is paused.
	withTask := map[string]string{}
	for _, target := range h.casTargets(campaign.ID) {
		if target.JobID != "" {
			withTask[target.ID] = target.JobID
		}
	}

	// While the campaign is pausing, the host under way keeps its budget
	// lease: the orchestrator renews it, and the lease is not left to
	// expire under a host halfway through its work.
	ctx := context.Background()
	pool := h.database(ctx)
	sawPausing := false
	for time.Now().Before(deadline) {
		state := h.campaign(campaign.ID)
		if state.State == "paused" {
			break
		}
		if state.State != "pausing" {
			t.Fatalf("the campaign is %s while it pauses", state.State)
		}
		sawPausing = true
		var live int
		if err := pool.QueryRow(ctx, `
			select count(*) from budget_leases where owner = $1 and lease_until > now()`,
			inFlight.ID).Scan(&live); err != nil {
			t.Fatalf("reading the budget leases: %v", err)
		}
		var current string
		for _, target := range h.casTargets(campaign.ID) {
			if target.ID == inFlight.ID {
				current = target.State
			}
			if target.JobID != "" && withTask[target.ID] == "" {
				t.Fatalf("host %s got the task %s after the pause", target.Hostname, target.JobID)
			}
		}
		if underWay(current) && live == 0 {
			t.Errorf("the host %s carries its task while the campaign pauses and holds no live budget lease",
				inFlight.Hostname)
		}
		time.Sleep(500 * time.Millisecond)
	}
	final := h.awaitCampaign(campaign.ID, map[string]bool{"paused": true}, 60*time.Second)
	if final.PausedBy == "" || final.PauseReason != "CAM-02" {
		t.Errorf("the paused campaign lost the author or the reason of the pause: %+v", final)
	}
	if !sawPausing {
		t.Log("the host settled before the campaign was read as pausing; the pause went straight to paused")
	}

	for _, target := range h.casTargets(campaign.ID) {
		if target.JobID != "" && withTask[target.ID] != target.JobID {
			t.Errorf("host %s carries the task %s, which was created after the pause", target.Hostname, target.JobID)
		}
		if target.ID == inFlight.ID && !settledTarget(target.State) {
			t.Errorf("the host %s under way at the pause stands %s after the campaign was paused; its result was not followed",
				target.Hostname, target.State)
		}
		if withTask[target.ID] == "" && underWay(target.State) {
			t.Errorf("host %s without a task stands %s after the pause", target.Hostname, target.State)
		}
	}
	// A paused campaign holds no tokens of a host that settled.
	var held int
	if err := pool.QueryRow(ctx, `select count(*) from budget_leases where owner = $1`, inFlight.ID).Scan(&held); err != nil {
		t.Fatalf("reading the budget leases: %v", err)
	}
	if held != 0 {
		t.Errorf("the settled host %s still holds %d budget leases", inFlight.Hostname, held)
	}

	// The resume opens the queue again; the cleanup cancels the rest.
	h.do(http.MethodPost, "/api/v1/campaigns/"+campaign.ID+"/resume", nil, nil, http.StatusOK)
}

// TestCancelTakesBackTheQueuedTaskOfAnOfflineHost guards the cancel of a
// campaign whose host went offline right after its task was created: the
// task sits in the panel's queue, and a cancel takes it back in the same
// transaction that cancels the campaign, so a host that comes online an
// hour later does not carry out a change of a campaign that no longer
// exists. The host stands in for a clone that enrolled and never spoke
// again: it is marked online for the dispatch and offline before the
// cancel, the way a session that opened and broke would leave it.
func TestCancelTakesBackTheQueuedTaskOfAnOfflineHost(t *testing.T) {
	h := newHarness(t)
	ctx := context.Background()
	pool := h.database(ctx)
	host := h.enrollSyntheticHost(t)

	if _, err := pool.Exec(ctx, `update hosts set connection_state = 'online' where id = $1::uuid`, host.ID); err != nil {
		t.Fatalf("marking the synthetic host online: %v", err)
	}
	campaign := h.createCampaign(map[string]any{
		"name": "cancel with an offline host", "action": "unit.restart",
		"reason":                     "cancel of a queued task",
		"payload":                    unitPayload("cron.service"),
		"selector":                   map[string]any{"host_ids": []string{host.ID}},
		"canary_size":                0,
		"wave_size":                  1,
		"max_concurrent":             1,
		"failure_threshold_percent":  0,
		"failure_threshold_absolute": 0,
		"reboot_policy":              "never",
	})
	if campaign.State == "awaiting_approval" {
		campaign = h.approveCampaign(campaign)
	}

	// The task is created and stays queued: nobody delivers it to a host
	// without a session.
	var target casTargetView
	deadline := time.Now().Add(60 * time.Second)
	for time.Now().Before(deadline) && target.JobID == "" {
		// The host is held online until its turn comes: nothing here keeps
		// a session open, and a sweep that finds none would take the row
		// back to offline while the campaign is still deciding.
		if _, err := pool.Exec(ctx,
			`update hosts set connection_state = 'online' where id = $1::uuid`, host.ID); err != nil {
			t.Fatalf("keeping the synthetic host online: %v", err)
		}
		for _, candidate := range h.casTargets(campaign.ID) {
			if candidate.HostID == host.ID && candidate.JobID != "" {
				target = candidate
			}
		}
		if target.JobID == "" {
			time.Sleep(500 * time.Millisecond)
		}
	}
	if target.JobID == "" {
		targets := h.casTargets(campaign.ID)
		t.Fatalf("no task was created for the synthetic host within the test time: %+v", targets)
	}
	if target.State != "dispatched" {
		t.Fatalf("the host stands %s with a queued task, expected dispatched", target.State)
	}
	if job := h.job(target.JobID); job.State != "queued" {
		t.Fatalf("the task of the host is %s, expected queued", job.State)
	}

	// The host goes offline with its task still in the queue.
	if _, err := pool.Exec(ctx, `update hosts set connection_state = 'offline' where id = $1::uuid`, host.ID); err != nil {
		t.Fatalf("marking the synthetic host offline: %v", err)
	}
	var canceled campaignView
	h.do(http.MethodPost, "/api/v1/campaigns/"+campaign.ID+"/cancel",
		map[string]any{"reason": "the host is gone"}, &canceled, http.StatusOK)
	if canceled.State != "canceled" {
		t.Fatalf("the campaign is %s after the cancel, expected canceled: nothing was left in flight", canceled.State)
	}

	if job := h.job(target.JobID); job.State != "canceled" {
		t.Errorf("the queued task of the offline host is %s after the cancel, expected canceled", job.State)
	}
	var queued int
	if err := pool.QueryRow(ctx, `
		select count(*) from jobs
		 where campaign_id = $1::uuid and state in ('planned', 'awaiting_approval', 'queued')`,
		campaign.ID).Scan(&queued); err != nil {
		t.Fatalf("counting the queued tasks of the campaign: %v", err)
	}
	if queued != 0 {
		t.Errorf("%d tasks of the canceled campaign are still queued", queued)
	}
	for _, after := range h.casTargets(campaign.ID) {
		if after.HostID != host.ID {
			continue
		}
		if after.State != "canceled" {
			t.Errorf("the host stands %s after the cancel, expected canceled", after.State)
		}
		if after.Revision <= target.Revision {
			t.Errorf("the revision of the target did not move with the cancel: %d then, %d now",
				target.Revision, after.Revision)
		}
	}
	// The host's tokens went back with the cancel, not with the lease.
	var held int
	if err := pool.QueryRow(ctx, `select count(*) from budget_leases where owner = $1`, target.ID).Scan(&held); err != nil {
		t.Fatalf("reading the budget leases: %v", err)
	}
	if held != 0 {
		t.Errorf("the canceled host still holds %d budget leases", held)
	}
}
