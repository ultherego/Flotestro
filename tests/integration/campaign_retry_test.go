//go:build integration

package integration

import (
	"net/http"
	"net/url"
	"sort"
	"strings"
	"testing"
	"time"
)

// retryView is the campaign record with the retry links: what this
// campaign retries, and what was ordered to retry it.
type retryView struct {
	ID                  string `json:"id"`
	Name                string `json:"name"`
	State               string `json:"state"`
	ActionType          string `json:"action_type"`
	ApprovalFingerprint string `json:"approval_fingerprint"`
	CanarySize          int    `json:"canary_size"`
	WaveSize            int    `json:"wave_size"`
	MaxConcurrent       int    `json:"max_concurrent"`
	RetriesCampaignID   string `json:"retries_campaign_id"`
	RetriesCampaignName string `json:"retries_campaign_name"`
	RetriedBy           []struct {
		ID    string `json:"id"`
		Name  string `json:"name"`
		State string `json:"state"`
	} `json:"retried_by"`
}

func (h *harness) retryLinks(id string) retryView {
	h.t.Helper()
	var view retryView
	h.get("/api/v1/campaigns/"+id, &view)
	return view
}

// TestARetryRunsTheFailedHostsAgainUnderANewApproval guards the retry of a
// finished campaign.
func TestARetryRunsTheFailedHostsAgainUnderANewApproval(t *testing.T) {
	h := newHarness(t)
	campaign := h.createCampaign(labCampaign("retry source", "non-existent-unit.service",
		map[string]any{"failure_threshold_absolute": 1}))
	h.approveCampaign(campaign)
	h.awaitCampaign(campaign.ID, map[string]bool{"paused": true}, 90*time.Second)

	retry := map[string]any{"reason": "the unit is installed now; run the failed hosts again"}
	var refusal struct {
		Code   string `json:"code"`
		Detail string `json:"detail"`
	}
	// A paused campaign can be resumed; its failed hosts are not final.
	h.do(http.MethodPost, "/api/v1/campaigns/"+campaign.ID+"/retry", retry, &refusal, http.StatusConflict)
	if refusal.Code != "campaign_not_finished" || !strings.Contains(refusal.Detail, "paused") {
		t.Errorf("a retry of a paused campaign was refused with %s (%s)", refusal.Code, refusal.Detail)
	}
	// A retry is a decision, and the record says why.
	h.do(http.MethodPost, "/api/v1/campaigns/"+campaign.ID+"/retry", map[string]any{"reason": "again"},
		&refusal, http.StatusBadRequest)
	if refusal.Code != "reason_required" {
		t.Errorf("a retry without a reason was refused with %s (%s)", refusal.Code, refusal.Detail)
	}

	h.do(http.MethodPost, "/api/v1/campaigns/"+campaign.ID+"/cancel",
		map[string]any{"reason": "the rest is not to run"}, nil, http.StatusOK)
	h.awaitCampaign(campaign.ID, map[string]bool{"canceled": true}, 60*time.Second)
	failed := []string{}
	for _, target := range h.campaignTargets(campaign.ID) {
		if target.State == "failed" {
			failed = append(failed, target.HostID)
		}
	}
	if len(failed) == 0 {
		t.Fatal("no host of the campaign failed; there is nothing to retry")
	}

	var retried campaignView
	h.do(http.MethodPost, "/api/v1/campaigns/"+campaign.ID+"/retry", retry, &retried, http.StatusCreated)
	t.Cleanup(func() {
		h.do(http.MethodPost, "/api/v1/campaigns/"+retried.ID+"/cancel",
			map[string]any{"reason": "end of the test"}, nil, 0)
	})
	if retried.State != "awaiting_approval" {
		t.Errorf("the retry started in state %s, expected its own approval", retried.State)
	}
	if retried.Name != "retry source (retry)" {
		t.Errorf("the retry is named %q", retried.Name)
	}
	if retried.ApprovalFingerprint == campaign.ApprovalFingerprint {
		t.Error("the retry carries the original's fingerprint; the consent would cover a different campaign")
	}

	// Exactly the hosts that failed, and nothing else.
	got := []string{}
	for _, target := range h.campaignTargets(retried.ID) {
		got = append(got, target.HostID)
		if target.State != "pending" {
			t.Errorf("the retry's host %s starts %s", target.Hostname, target.State)
		}
	}
	sort.Strings(got)
	sort.Strings(failed)
	if strings.Join(got, ",") != strings.Join(failed, ",") {
		t.Errorf("the retry targets %v, expected the failed hosts %v", got, failed)
	}

	// The same order: operation and rollout as the original had them.
	view := h.retryLinks(retried.ID)
	if view.ActionType != "unit.restart" || view.CanarySize != campaign.CanarySize || view.WaveSize != campaign.WaveSize {
		t.Errorf("the retry carries a different order: %s %d/%d", view.ActionType, view.CanarySize, view.WaveSize)
	}
	// The link both ways: the retry names the original, the original
	// lists the retry, and the original's own record stays as it was.
	if view.RetriesCampaignID != campaign.ID || view.RetriesCampaignName != campaign.Name {
		t.Errorf("the retry names %s (%s) as what it retries", view.RetriesCampaignID, view.RetriesCampaignName)
	}
	original := h.retryLinks(campaign.ID)
	if original.RetriesCampaignID != "" {
		t.Errorf("the original was rewritten as a retry of %s", original.RetriesCampaignID)
	}
	if len(original.RetriedBy) != 1 || original.RetriedBy[0].ID != retried.ID || original.RetriedBy[0].State != "awaiting_approval" {
		t.Errorf("the original lists %v as its retries", original.RetriedBy)
	}

	// The retry waits for its approval; it is not finished either.
	h.do(http.MethodPost, "/api/v1/campaigns/"+retried.ID+"/retry", retry, &refusal, http.StatusConflict)
	if refusal.Code != "campaign_not_finished" {
		t.Errorf("a retry of an unapproved campaign was refused with %s (%s)", refusal.Code, refusal.Detail)
	}
	// Canceled before it ran, the retry has no failed host: nothing to
	// retry, with unknown hosts asked for or not.
	h.do(http.MethodPost, "/api/v1/campaigns/"+retried.ID+"/cancel",
		map[string]any{"reason": "nothing ran"}, nil, http.StatusOK)
	h.do(http.MethodPost, "/api/v1/campaigns/"+retried.ID+"/retry", retry, &refusal, http.StatusConflict)
	if refusal.Code != "nothing_to_retry" {
		t.Errorf("a retry of a clean campaign was refused with %s (%s)", refusal.Code, refusal.Detail)
	}
	h.do(http.MethodPost, "/api/v1/campaigns/"+retried.ID+"/retry",
		map[string]any{"reason": retry["reason"], "include_unknown": true}, &refusal, http.StatusConflict)
	if refusal.Code != "nothing_to_retry" {
		t.Errorf("a retry with unknown hosts of a clean campaign was refused with %s (%s)", refusal.Code, refusal.Detail)
	}
}

// TestCampaignListFiltersAndCountsProgress guards the list: state, operation,
// requester and time filter on the server, and every row carries its tally.
func TestCampaignListFiltersAndCountsProgress(t *testing.T) {
	h := newHarness(t)
	campaign := h.createCampaign(labCampaign("listed and counted", "cron.service", nil))

	var page struct {
		Items []struct {
			ID        string `json:"id"`
			State     string `json:"state"`
			CreatedBy string `json:"created_by"`
			Progress  *struct {
				Total     int `json:"total"`
				Succeeded int `json:"succeeded"`
				Failed    int `json:"failed"`
				Unknown   int `json:"unknown"`
				Skipped   int `json:"skipped"`
				Pending   int `json:"pending"`
			} `json:"progress"`
		} `json:"items"`
		Count  int `json:"count"`
		Total  int `json:"total"`
		Limit  int `json:"limit"`
		Offset int `json:"offset"`
	}
	since := time.Now().Add(-time.Hour).UTC().Format(time.RFC3339)
	h.get("/api/v1/campaigns?state=awaiting_approval&action=unit.restart&requester="+url.QueryEscape(campaign.CreatedBy)+
		"&since="+url.QueryEscape(since)+"&limit=5", &page)
	if page.Limit != 5 || page.Offset != 0 || page.Total < 1 || page.Count > 5 {
		t.Errorf("the page says limit %d offset %d total %d count %d", page.Limit, page.Offset, page.Total, page.Count)
	}
	found := false
	for _, item := range page.Items {
		if item.State != "awaiting_approval" || item.CreatedBy != campaign.CreatedBy {
			t.Errorf("the filter let through %s by %s", item.State, item.CreatedBy)
		}
		if item.Progress == nil {
			t.Errorf("the row %s carries no progress", item.ID)
			continue
		}
		if item.ID == campaign.ID {
			found = true
			targets := h.campaignTargets(campaign.ID)
			if item.Progress.Total != len(targets) || item.Progress.Pending != len(targets) {
				t.Errorf("the fresh campaign counts %+v over %d targets", *item.Progress, len(targets))
			}
		}
	}
	if !found && page.Total <= 5 {
		t.Error("the campaign just ordered is missing from its own page")
	}
	// A filter that matches nothing answers with an empty page, not an
	// error; a malformed timestamp is refused with its code.
	h.get("/api/v1/campaigns?action=no.such.operation", &page)
	if page.Total != 0 || len(page.Items) != 0 {
		t.Errorf("an unknown operation lists %d campaigns", page.Total)
	}
	var refusal struct {
		Code string `json:"code"`
	}
	h.do(http.MethodGet, "/api/v1/campaigns?since=yesterday", nil, &refusal, http.StatusBadRequest)
	if refusal.Code != "invalid_since" {
		t.Errorf("a malformed since was refused with %s", refusal.Code)
	}
	// The second page starts where the first ended.
	h.get("/api/v1/campaigns?limit=1&offset=1", &page)
	if page.Offset != 1 || page.Limit != 1 || len(page.Items) > 1 {
		t.Errorf("the offset page says limit %d offset %d with %d rows", page.Limit, page.Offset, len(page.Items))
	}
}
