//go:build integration

package integration

import (
	"net/http"
	"strings"
	"testing"
	"time"
)

// compensationView is the campaign as the link between an original and its
// compensation shows on it: the compensating side names the original, the
// original lists what was ordered to undo it and counts the hosts a
type compensationView struct {
	ID                      string `json:"id"`
	Name                    string `json:"name"`
	State                   string `json:"state"`
	ApprovalFingerprint     string `json:"approval_fingerprint"`
	PauseReason             string `json:"pause_reason"`
	CompensatesCampaignID   string `json:"compensates_campaign_id"`
	CompensatesCampaignName string `json:"compensates_campaign_name"`
	CompensatedBy           []struct {
		ID    string `json:"id"`
		Name  string `json:"name"`
		State string `json:"state"`
	} `json:"compensated_by"`
	ChangedHosts int `json:"changed_hosts"`
}

func (h *harness) compensationLinks(id string) compensationView {
	h.t.Helper()
	var view compensationView
	h.get("/api/v1/campaigns/"+id, &view)
	return view
}

// runFileCampaign orders a one-host file campaign, waits for its plan,
// approves it and waits for its end.
func (h *harness) runFileCampaign(body map[string]any) campaignView {
	h.t.Helper()
	campaign := h.createCampaign(body)
	if campaign.State != "planning" {
		h.t.Fatalf("the file campaign %s started from state %s", campaign.Name, campaign.State)
	}
	planned := h.awaitCampaign(campaign.ID,
		map[string]bool{"awaiting_approval": true, "paused": true, "failed": true, "plan_failed": true, "completed": true}, 3*time.Minute)
	if planned.State != "awaiting_approval" {
		h.t.Fatalf("planning of %s ended in state %s (%s)", campaign.Name, planned.State, planned.PauseReason)
	}
	// Nothing landed yet.
	if view := h.compensationLinks(campaign.ID); view.ChangedHosts != 0 {
		h.t.Errorf("the campaign %s counts %d changed hosts before it ran", campaign.Name, view.ChangedHosts)
	}
	h.approveCampaign(planned)
	final := h.awaitCampaign(campaign.ID,
		map[string]bool{"completed": true, "failed": true, "paused": true}, 3*time.Minute)
	if final.State != "completed" {
		h.t.Fatalf("the campaign %s ended in state %s (%s)", campaign.Name, final.State, final.PauseReason)
	}
	return final
}

// TestACompensatingCampaignLinksToTheOriginalAndMarksItsTargets guards the
// link between a campaign and the campaign that undoes it.
func TestACompensatingCampaignLinksToTheOriginalAndMarksItsTargets(t *testing.T) {
	h := newHarness(t)
	host := h.hostByFamily("debian")
	const path = "/etc/flotestro-compensation.conf"
	t.Cleanup(func() {
		h.runOperation(host.ID, map[string]any{
			"action": "file.remove", "reason": "cleanup after the compensation test",
			"payload": map[string]any{"file": map[string]any{"path": path}},
		}, 2*time.Minute)
	})

	// The version to go back to has to exist before the change: a rollback
	// names a version from the history, and a file written once has one.
	job, attempts := h.runOperation(host.ID, map[string]any{
		"action": "file.ensure", "reason": "the version before the rollout",
		"payload": map[string]any{"file": map[string]any{
			"path": path, "content": "before = 1\n", "mode": "0644"}},
	}, 2*time.Minute)
	if job.State != "succeeded" {
		t.Fatalf("the first write ended %s: %s", job.State, lastMessage(attempts))
	}
	before := managedFile(t, h, host.ID, path).DesiredSHA256

	original := h.runFileCampaign(map[string]any{
		"name": "rollout to compensate", "action": "file.ensure",
		"reason": "integration test of the campaign compensation",
		"payload": map[string]any{"file": map[string]any{
			"path": path, "content": "after = 2\n", "mode": "0644"}},
		"selector":                   map[string]any{"host_ids": []string{host.ID}},
		"canary_size":                0,
		"wave_size":                  1,
		"max_concurrent":             1,
		"failure_threshold_percent":  0,
		"failure_threshold_absolute": 0,
		"reboot_policy":              "never",
	})
	originalTargets := h.campaignTargets(original.ID)
	if len(originalTargets) != 1 || originalTargets[0].State != "succeeded" {
		t.Fatalf("the original's target ended as %+v", originalTargets)
	}
	originalTarget := originalTargets[0]
	var originalReport campaignReportView
	h.get("/api/v1/campaigns/"+original.ID+"/report", &originalReport)
	// Settled, the original counts the host it changed: the number the
	// campaign page offers to compensate, before any rollback is ordered.
	if view := h.compensationLinks(original.ID); view.ChangedHosts != 1 || len(view.CompensatedBy) != 0 {
		t.Errorf("the settled original counts %d changed hosts and %d compensations, expected 1 and none",
			view.ChangedHosts, len(view.CompensatedBy))
	}

	rollback := map[string]any{"file": map[string]any{
		"path": path, "version_sha256": before, "mode": "0644"}}
	rollout := map[string]any{
		"canary_size": 0, "wave_size": 1, "max_concurrent": 1,
		"failure_threshold_percent": 0, "failure_threshold_absolute": 0,
		"reboot_policy": "never",
	}
	order := func(name, action string, payload map[string]any, extra map[string]any) map[string]any {
		body := map[string]any{
			"name": name, "action": action, "payload": payload,
			"reason":                  "integration test of the campaign compensation",
			"selector":                map[string]any{},
			"compensates_campaign_id": original.ID,
		}
		for key, value := range rollout {
			body[key] = value
		}
		for key, value := range extra {
			body[key] = value
		}
		return body
	}
	var refusal struct {
		Code   string `json:"code"`
		Detail string `json:"detail"`
	}

	// A host the original did not change has nothing to compensate; the
	// refusal names it, by hostname where there is one.
	var stranger *hostView
	for _, other := range h.hosts() {
		if other.ID != host.ID && other.ConnectionState == "online" {
			candidate := other
			stranger = &candidate
			break
		}
	}
	if stranger != nil {
		h.do(http.MethodPost, "/api/v1/campaigns", order("rollback of a stranger", "file.rollback", rollback,
			map[string]any{"selector": map[string]any{"host_ids": []string{host.ID, stranger.ID}}}),
			&refusal, http.StatusBadRequest)
		if refusal.Code != "compensation_target_unchanged" || !strings.Contains(refusal.Detail, stranger.Hostname) {
			t.Errorf("a host the original did not change was refused with %s (%s)", refusal.Code, refusal.Detail)
		}
	}
	// An operation that is not the declared reverse is not a compensation,
	// whatever the name says.
	h.do(http.MethodPost, "/api/v1/campaigns", order("restart called a rollback", "unit.restart",
		unitPayload("cron.service"), nil), &refusal, http.StatusBadRequest)
	if refusal.Code != "not_reverse_operation" || !strings.Contains(refusal.Detail, "file.rollback") {
		t.Errorf("a restart as a compensation was refused with %s (%s)", refusal.Code, refusal.Detail)
	}
	// An original that does not exist, and one that is not settled.
	h.do(http.MethodPost, "/api/v1/campaigns", order("rollback of nothing", "file.rollback", rollback,
		map[string]any{"compensates_campaign_id": "00000000-0000-0000-0000-000000000000"}),
		&refusal, http.StatusBadRequest)
	if refusal.Code != "compensated_campaign_not_found" {
		t.Errorf("a missing original was refused with %s (%s)", refusal.Code, refusal.Detail)
	}
	pending := h.createCampaign(labCampaign("still awaiting approval", "cron.service", map[string]any{
		"selector": map[string]any{"host_ids": []string{host.ID}},
	}))
	h.do(http.MethodPost, "/api/v1/campaigns", order("rollback of a pending campaign", "unit.stop",
		unitPayload("cron.service"), map[string]any{"compensates_campaign_id": pending.ID}),
		&refusal, http.StatusBadRequest)
	if refusal.Code != "compensated_campaign_not_settled" {
		t.Errorf("an unsettled original was refused with %s (%s)", refusal.Code, refusal.Detail)
	}
	if view := h.compensationLinks(pending.ID); view.ChangedHosts != 0 {
		t.Errorf("the pending campaign counts %d changed hosts", view.ChangedHosts)
	}

	// The preview of the compensation names the original and the hosts it
	// changed, so the wizard shows both before anything is created.
	var preview struct {
		Count       int `json:"count"`
		Compensates struct {
			ID      string `json:"id"`
			Name    string `json:"name"`
			Changed int    `json:"changed"`
		} `json:"compensates"`
	}
	h.get("/api/v1/campaigns/preview?action=file.rollback&compensates="+original.ID, &preview)
	if preview.Count != 1 || preview.Compensates.ID != original.ID || preview.Compensates.Changed != 1 {
		t.Errorf("the preview of the compensation says %+v", preview)
	}

	// The way through: an empty selector takes the hosts the original
	// changed, and the rollback runs on them.
	compensating := h.runFileCampaign(order("rollback of the rollout", "file.rollback", rollback, nil))
	after := managedFile(t, h, host.ID, path)
	if after.DesiredSHA256 != before || after.Drift {
		t.Errorf("the file after the compensation = %+v, expected the version %s", after, before[:12])
	}

	// The link, both ways. The original's record was never rewritten: its
	// side of the link is read from the compensating campaign.
	links := h.compensationLinks(compensating.ID)
	if links.CompensatesCampaignID != original.ID || links.CompensatesCampaignName != original.Name {
		t.Errorf("the compensating campaign names %q (%s), expected %q (%s)",
			links.CompensatesCampaignName, links.CompensatesCampaignID, original.Name, original.ID)
	}
	originalLinks := h.compensationLinks(original.ID)
	if len(originalLinks.CompensatedBy) != 1 || originalLinks.CompensatedBy[0].ID != compensating.ID ||
		originalLinks.CompensatedBy[0].State != "completed" {
		t.Errorf("the original is compensated by %+v, expected %s", originalLinks.CompensatedBy, compensating.ID)
	}
	if originalLinks.CompensatesCampaignID != "" {
		t.Errorf("the original compensates %s", originalLinks.CompensatesCampaignID)
	}
	if originalLinks.ApprovalFingerprint != original.ApprovalFingerprint {
		t.Error("the original's approval fingerprint changed with the compensation")
	}
	// The count is what the original changed, not what is left to undo: a second
	// compensation is still the operator's decision, and the compensating
	// campaign counts its own change the same way.
	if originalLinks.ChangedHosts != 1 || links.ChangedHosts != 1 {
		t.Errorf("after the compensation the original counts %d changed hosts and the compensation %d, expected 1 and 1",
			originalLinks.ChangedHosts, links.ChangedHosts)
	}

	// The original's target: the same state, the same outcome, and a compensate
	// step carried by the compensating campaign's task under the compensating
	// campaign's plan.
	targets := h.campaignTargets(original.ID)
	if len(targets) != 1 || targets[0].State != originalTarget.State ||
		targets[0].ErrorCode != originalTarget.ErrorCode || targets[0].Message != originalTarget.Message ||
		targets[0].JobID != originalTarget.JobID {
		t.Errorf("the original's target was rewritten: %+v, was %+v", targets, originalTarget)
	}
	var reportAfter campaignReportView
	h.get("/api/v1/campaigns/"+original.ID+"/report", &reportAfter)
	if reportAfter.State != originalReport.State || reportAfter.Totals["succeeded"] != originalReport.Totals["succeeded"] {
		t.Errorf("the original's report changed: %+v, was %+v", reportAfter, originalReport)
	}
	compensatingTargets := h.campaignTargets(compensating.ID)
	if len(compensatingTargets) != 1 || compensatingTargets[0].State != "succeeded" {
		t.Fatalf("the compensating target ended as %+v", compensatingTargets)
	}
	compensatingSteps := h.campaignSteps(compensating.ID, "?host_id="+host.ID)
	var reverseChange campaignStepView
	for _, step := range compensatingSteps.Items {
		if step.StepKey == "execute" {
			reverseChange = step
		}
	}
	if reverseChange.State != "succeeded" || reverseChange.JobID == "" {
		t.Fatalf("the compensating campaign's change step is %+v", reverseChange)
	}
	// The compensating campaign's own strip has no compensate step: it is
	// the compensation, not the compensated.
	for _, step := range compensatingSteps.Items {
		if step.StepKey == "compensate" {
			t.Errorf("the compensating campaign carries a compensate step of its own: %+v", step)
		}
	}

	steps := h.campaignSteps(original.ID, "?host_id="+host.ID)
	var compensate *campaignStepView
	for _, step := range steps.Items {
		if step.StepKey == "compensate" {
			found := step
			compensate = &found
		}
	}
	if compensate == nil {
		t.Fatalf("the original's target has no compensate step: %+v", steps.Items)
	}
	if compensate.State != "succeeded" || compensate.Attempts != 1 {
		t.Errorf("the compensate step is %s after %d attempts (%s)", compensate.State, compensate.Attempts, compensate.Reason)
	}
	if compensate.JobID != reverseChange.JobID || compensate.PlanHash != reverseChange.PlanHash {
		t.Errorf("the compensate step names task %s under plan %s; the reverse change ran as %s under %s",
			compensate.JobID, compensate.PlanHash, reverseChange.JobID, reverseChange.PlanHash)
	}
	if compensate.DependsOn != "execute" {
		t.Errorf("the compensate step follows %q, expected the change", compensate.DependsOn)
	}
	if !strings.Contains(compensate.Reason, compensating.ID) {
		t.Errorf("the compensate step does not name the compensating campaign: %q", compensate.Reason)
	}
	// The strip ends with the compensation: the change came first.
	if last := steps.Items[len(steps.Items)-1]; last.StepKey != "compensate" {
		t.Errorf("the strip of the compensated host ends with %s, expected the compensation", last.StepKey)
	}

	// A second compensation of a campaign already compensated is still a decision
	// for the operator, not for the panel: the rules allow it, and the link lists
	// both.
	h.get("/api/v1/campaigns/preview?action=file.rollback&compensates="+original.ID, &preview)
	if preview.Compensates.Changed != 1 {
		t.Errorf("after the compensation the original changed %d hosts, expected still 1", preview.Compensates.Changed)
	}
}

// TestACompensationIsReadThroughTheOriginalsDoor guards the scope: the
// original is read with the same right as reading it directly, so an
// identifier alone cannot be used to learn about a campaign elsewhere.
func TestACompensationIsReadThroughTheOriginalsDoor(t *testing.T) {
	h := newHarness(t)
	host := h.hostByFamily("debian")
	original := h.createCampaign(labCampaign("behind the door", "cron.service", map[string]any{
		"selector": map[string]any{"host_ids": []string{host.ID}},
	}))
	stranger := h.withToken(h.createPrincipal(uniqueSubject("operator-elsewhere"), []map[string]string{
		{"role": "operator", "site": "nowhere", "environment": "nowhere"},
	}))
	stranger.do(http.MethodPost, "/api/v1/campaigns", map[string]any{
		"name": "rollback from elsewhere", "action": "unit.stop", "payload": unitPayload("cron.service"),
		"selector": map[string]any{"site": "nowhere"}, "compensates_campaign_id": original.ID,
	}, nil, http.StatusForbidden)
}
