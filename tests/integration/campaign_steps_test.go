//go:build integration

package integration

import (
	"context"
	"net/http"
	"testing"
	"time"
)

type campaignStepView struct {
	ID        string `json:"id"`
	TargetID  string `json:"target_id"`
	HostID    string `json:"host_id"`
	Hostname  string `json:"hostname"`
	StepKey   string `json:"step_key"`
	DependsOn string `json:"depends_on"`
	PlanHash  string `json:"plan_hash"`
	State     string `json:"state"`
	JobID     string `json:"job_id"`
	Attempts  int    `json:"attempts"`
	Reason    string `json:"reason"`
}

type campaignStepsView struct {
	Items      []campaignStepView `json:"items"`
	Count      int                `json:"count"`
	NextCursor string             `json:"next_cursor"`
	StepOrder  []string           `json:"step_order"`
}

func (h *harness) campaignSteps(id, query string) campaignStepsView {
	h.t.Helper()
	var result campaignStepsView
	h.get("/api/v1/campaigns/"+id+"/steps"+query, &result)
	return result
}

// TestCampaignRecordsAStepPerTargetPhase guards the step ledger of a
// target: every executable step of a host is its own durable row with its
// task, its attempts and - where it did not run - the reason.
//
// A file campaign is the cheapest planned change the lab has: the host
// computes a plan, the change runs under that plan's digest, the reboot
// policy says never. That gives a plan step and an execute step that
// succeeded with their tasks, a reboot step skipped with the policy as the
// reason, and no verification at all - the host never reached it. The
// unique index closes the door on a second row for the same step of the
// same target under the same plan, nulls included.
func TestCampaignRecordsAStepPerTargetPhase(t *testing.T) {
	h := newHarness(t)
	host := h.hostByFamily("debian")
	const path = "/etc/flotestro-step-ledger.conf"
	t.Cleanup(func() {
		h.runOperation(host.ID, map[string]any{
			"action": "file.remove", "reason": "cleanup after the step ledger test",
			"payload": map[string]any{"file": map[string]any{"path": path}},
		}, 2*time.Minute)
	})

	campaign := h.createCampaign(map[string]any{
		"name": "step ledger", "action": "file.ensure",
		"reason": "integration test of the campaign steps",
		"payload": map[string]any{"file": map[string]any{
			"path": path, "content": "step ledger\n", "mode": "0644"}},
		"selector":                   map[string]any{"host_ids": []string{host.ID}},
		"canary_size":                0,
		"wave_size":                  1,
		"max_concurrent":             1,
		"failure_threshold_percent":  0,
		"failure_threshold_absolute": 0,
		"reboot_policy":              "never",
	})
	if campaign.State != "planning" {
		t.Fatalf("the file campaign started from state %s", campaign.State)
	}
	afterPlanning := h.awaitCampaign(campaign.ID,
		map[string]bool{"awaiting_approval": true, "paused": true, "failed": true}, 3*time.Minute)
	if afterPlanning.State != "awaiting_approval" {
		t.Fatalf("planning ended in state %s (%s)", afterPlanning.State, afterPlanning.PauseReason)
	}

	// After planning the plan step is closed and nothing else exists yet:
	// the change has not been ordered, so it has no row rather than a
	// pending one - nothing was decided about it.
	planned := h.campaignSteps(campaign.ID, "")
	if len(planned.Items) != 1 || planned.Items[0].StepKey != "plan" || planned.Items[0].State != "succeeded" {
		t.Fatalf("after planning the steps are %+v, expected one succeeded plan step", planned.Items)
	}
	if planned.Items[0].JobID == "" || planned.Items[0].Attempts != 1 {
		t.Errorf("the plan step has no task or a wrong attempt count: %+v", planned.Items[0])
	}
	if len(planned.StepOrder) == 0 || planned.StepOrder[0] != "plan" {
		t.Errorf("the answer does not carry the step order: %v", planned.StepOrder)
	}

	h.approveCampaign(afterPlanning)
	final := h.awaitCampaign(campaign.ID,
		map[string]bool{"completed": true, "failed": true, "paused": true}, 3*time.Minute)
	if final.State != "completed" {
		t.Fatalf("the campaign ended in state %s (%s)", final.State, final.PauseReason)
	}
	targets := h.campaignTargets(campaign.ID)
	if len(targets) != 1 || targets[0].State != "succeeded" {
		t.Fatalf("the target ended as %+v", targets)
	}

	// The ledger of the finished host, filtered on the host: the plan and
	// the change succeeded with their tasks, the reboot was skipped by the
	// policy and says so, the verification was never reached.
	steps := h.campaignSteps(campaign.ID, "?host_id="+host.ID)
	byKey := map[string]campaignStepView{}
	for _, step := range steps.Items {
		if step.HostID != host.ID {
			t.Errorf("the host filter let through a step of %s", step.HostID)
		}
		byKey[step.StepKey] = step
	}
	for _, key := range []string{"plan", "execute"} {
		step, present := byKey[key]
		if !present {
			t.Fatalf("no %s step in %+v", key, steps.Items)
		}
		if step.State != "succeeded" {
			t.Errorf("the %s step ended %s (%s)", key, step.State, step.Reason)
		}
		if step.JobID == "" {
			t.Errorf("the %s step has no task", key)
		}
	}
	if byKey["execute"].JobID != targets[0].JobID || byKey["plan"].JobID != targets[0].PlanJobID {
		t.Errorf("the steps name other tasks than the target: %+v against %+v", byKey, targets[0])
	}
	if byKey["execute"].DependsOn != "plan" {
		t.Errorf("the change does not follow the plan: depends_on = %q", byKey["execute"].DependsOn)
	}
	if byKey["execute"].PlanHash == "" {
		t.Error("the change does not name the plan it ran under")
	}
	if byKey["plan"].PlanHash != "" {
		t.Errorf("the plan step names a plan it ran under: %s", byKey["plan"].PlanHash)
	}
	reboot, present := byKey["reboot"]
	if !present || reboot.State != "skipped" || reboot.Reason == "" {
		t.Errorf("the reboot the policy never asked for is %+v, expected skipped with a reason", reboot)
	}
	if _, present := byKey["verify"]; present {
		t.Errorf("a verification the host never reached has a row: %+v", byKey["verify"])
	}
	// The order of the strip is the order the steps ran in.
	if len(steps.Items) < 3 || steps.Items[0].StepKey != "plan" || steps.Items[1].StepKey != "execute" || steps.Items[2].StepKey != "reboot" {
		t.Errorf("the steps are not in dependency order: %+v", steps.Items)
	}
	if steps.NextCursor != "" {
		t.Errorf("a single host has a next page: %q", steps.NextCursor)
	}

	// The unique index: one step of one kind per target and plan. A second
	// execute under the same plan is refused, and so is a second plan step
	// - the plan runs under no digest, and nulls count as equal there.
	ctx := context.Background()
	pool := h.database(ctx)
	execute := byKey["execute"]
	if _, err := pool.Exec(ctx, `
		insert into campaign_steps (campaign_id, target_id, host_id, step_key, plan_hash, state)
		values ($1, $2, $3, 'execute', $4, 'pending')`,
		campaign.ID, execute.TargetID, host.ID, execute.PlanHash); err == nil {
		t.Error("a second execute step under the same plan was accepted")
	}
	if _, err := pool.Exec(ctx, `
		insert into campaign_steps (campaign_id, target_id, host_id, step_key, state)
		values ($1, $2, $3, 'plan', 'pending')`,
		campaign.ID, execute.TargetID, host.ID); err == nil {
		t.Error("a second plan step without a plan digest was accepted")
	}
	// A step that did not run has to say why; the table refuses one that
	// does not.
	if _, err := pool.Exec(ctx, `
		insert into campaign_steps (campaign_id, target_id, host_id, step_key, state)
		values ($1, $2, $3, 'compensate', 'skipped')`,
		campaign.ID, execute.TargetID, host.ID); err == nil {
		t.Error("a skipped step without a reason was accepted")
		_, _ = pool.Exec(ctx, `delete from campaign_steps where target_id = $1 and step_key = 'compensate'`, execute.TargetID)
	}
}

// TestCampaignStepsFollowTheCampaignPermission guards the door: the steps
// are read with the same right as the campaign, and a stranger to the
// scope gets the same refusal as for the campaign itself.
func TestCampaignStepsFollowTheCampaignPermission(t *testing.T) {
	h := newHarness(t)
	host := h.hostByFamily("debian")
	campaign := h.createCampaign(labCampaign("steps behind the door", "cron.service", map[string]any{
		"selector": map[string]any{"host_ids": []string{host.ID}},
	}))
	stranger := h.withToken(h.createPrincipal(uniqueSubject("viewer-elsewhere"), []map[string]string{
		{"role": "viewer", "site": "nowhere", "environment": "nowhere"},
	}))
	stranger.do(http.MethodGet, "/api/v1/campaigns/"+campaign.ID+"/steps", nil, nil, http.StatusForbidden)
	// A campaign that has not started has no steps yet, and says so with an
	// empty list rather than an error.
	steps := h.campaignSteps(campaign.ID, "")
	if steps.Count != 0 || len(steps.Items) != 0 {
		t.Errorf("an unstarted campaign has steps: %+v", steps.Items)
	}
}
