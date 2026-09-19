//go:build integration

package integration

import (
	"net/http"
	"net/url"
	"strings"
	"testing"
	"time"
)

// TestHostnameCampaignSplitsTheMappingPerHost checks a rename in bulk as the
// system chapter describes it: the order carries a map of host to new name,
// the panel splits it into one plan per host, and a host the map does not name
func TestHostnameCampaignSplitsTheMappingPerHost(t *testing.T) {
	h := newHarness(t)
	online := h.onlineDebianHosts()
	if len(online) < 2 {
		t.Skip("the fleet has fewer than two connected hosts of the debian family")
	}
	first, second := online[0], online[1]
	targets := []string{first.ID, second.ID}

	// The preview lists every ready host by identifier: the mapping names
	// hosts by it, so the wizard needs the list before the order.
	query := url.Values{"action": {"system.hostname.set"}, "site": {first.Site}}
	var preview struct {
		CampaignMode string `json:"campaign_mode"`
		RequiresPlan bool   `json:"requires_plan"`
		Hosts        []struct {
			ID       string `json:"id"`
			Hostname string `json:"hostname"`
		} `json:"hosts"`
	}
	h.get("/api/v1/campaigns/preview?"+query.Encode(), &preview)
	if preview.CampaignMode != "per_host_plan" || !preview.RequiresPlan {
		t.Errorf("the preview says mode=%q requires_plan=%v; a rename is a per-host plan split from the order",
			preview.CampaignMode, preview.RequiresPlan)
	}
	listed := map[string]string{}
	for _, host := range preview.Hosts {
		listed[host.ID] = host.Hostname
	}
	for _, host := range []hostView{first, second} {
		if listed[host.ID] != host.Hostname {
			t.Errorf("the preview lists %s as %q, the host is %q", host.ID, listed[host.ID], host.Hostname)
		}
	}

	order := func(name string, mapping map[string]string) map[string]any {
		return map[string]any{
			"name": name, "action": "system.hostname.set",
			"reason":                     "integration test of a rename in bulk: every host keeps its name",
			"payload":                    map[string]any{"hostname": map[string]any{"mapping": mapping}},
			"selector":                   map[string]any{"host_ids": targets},
			"canary_size":                0,
			"wave_size":                  len(targets),
			"max_concurrent":             len(targets),
			"failure_threshold_percent":  0,
			"failure_threshold_absolute": 0,
			"reboot_policy":              "never",
		}
	}

	// An order without a mapping is refused before any host is resolved: there is
	// no shared name, and a name in the shared part would be the one name every
	// host must not get.
	for name, payload := range map[string]map[string]any{
		"no mapping":     {"hostname": map[string]any{"hostname": "shared.flotestro.test"}},
		"duplicate name": {"hostname": map[string]any{"mapping": map[string]string{first.ID: "twin.flotestro.test", second.ID: "twin.flotestro.test"}}},
		"invalid name":   {"hostname": map[string]any{"mapping": map[string]string{first.ID: "not a name!"}}},
	} {
		t.Run(name, func(t *testing.T) {
			var problem struct {
				Code   string `json:"code"`
				Detail string `json:"detail"`
			}
			body := order("refused rename: "+name, nil)
			body["payload"] = payload
			h.do(http.MethodPost, "/api/v1/campaigns", body, &problem, http.StatusBadRequest)
			if problem.Code != "invalid_mapping" {
				t.Errorf("code = %q (%s), expected invalid_mapping", problem.Code, problem.Detail)
			}
		})
	}

	// A mapping that names one host only: the other settles as ineligible at
	// planning, with the code the wizard shows before the order, and the named
	// host gets a plan that carries its own name.
	partial := h.createCampaign(order("rename with a host left out", map[string]string{first.ID: first.Hostname}))
	if partial.State != "planning" {
		t.Fatalf("the rename campaign started from state %s; the mapping is split at planning", partial.State)
	}
	afterPartial := h.awaitCampaign(partial.ID,
		map[string]bool{"awaiting_approval": true, "queued": true, "running": true, "completed": true, "failed": true, "paused": true},
		2*time.Minute)
	for _, target := range h.campaignTargets(partial.ID) {
		switch target.HostID {
		case second.ID:
			if target.State != "ineligible" || target.ErrorCode != "no_hostname_for_host" {
				t.Errorf("the host left out of the mapping is %s/%s, expected ineligible/no_hostname_for_host",
					target.State, target.ErrorCode)
			}
		case first.ID:
			if target.State == "ineligible" || target.State == "failed" {
				t.Errorf("the named host is %s (%s: %s)", target.State, target.ErrorCode, target.Message)
			}
			if target.PlanJobID != "" {
				t.Errorf("the named host got a planning task %s; the plan comes with the order, not from the host", target.PlanJobID)
			}
		}
	}
	assertPlansCarryOwnNames(t, h, partial.ID, map[string]string{first.Hostname: first.Hostname})
	if afterPartial.State == "awaiting_approval" || afterPartial.State == "queued" || afterPartial.State == "running" {
		h.do(http.MethodPost, "/api/v1/campaigns/"+partial.ID+"/cancel",
			map[string]any{"reason": "the partial mapping was the point of the test"}, nil, 0)
	}

	// The whole mapping: every host is named with the name it has, the set
	// of names goes for approval, and every host carries out its no-op.
	full := h.createCampaign(order("rename to the same names", map[string]string{
		first.ID: first.Hostname, second.ID: second.Hostname,
	}))
	afterPlanning := h.awaitCampaign(full.ID,
		map[string]bool{"awaiting_approval": true, "queued": true, "running": true, "completed": true, "failed": true, "paused": true},
		2*time.Minute)
	if afterPlanning.State == "failed" || afterPlanning.State == "paused" {
		t.Fatalf("planning ended in state %s (%s)", afterPlanning.State, afterPlanning.PauseReason)
	}
	if afterPlanning.PlanSetHash == "" {
		t.Error("the campaign after planning has no plan set fingerprint; the consent covers the set of names")
	}
	assertPlansCarryOwnNames(t, h, full.ID, map[string]string{
		first.Hostname: first.Hostname, second.Hostname: second.Hostname,
	})
	if afterPlanning.State == "awaiting_approval" {
		// Consent given with the fingerprint from before the split concerns
		// something else.
		if afterPlanning.ApprovalFingerprint == full.ApprovalFingerprint {
			t.Error("the set of names did not change the approval fingerprint")
		}
		h.do(http.MethodPost, "/api/v1/campaigns/"+full.ID+"/approve",
			map[string]any{"approval_fingerprint": full.ApprovalFingerprint, "reason": "stale fingerprint"},
			nil, http.StatusConflict)
		h.approveCampaign(afterPlanning)
	}
	final := h.awaitCampaign(full.ID, map[string]bool{"completed": true, "failed": true, "paused": true}, 5*time.Minute)
	if final.State != "completed" {
		t.Fatalf("the rename campaign ended in state %s (%s)", final.State, final.PauseReason)
	}
	for _, target := range h.campaignTargets(full.ID) {
		if target.State != "succeeded" && target.State != "no_change" {
			t.Errorf("%s ended as %s (%s: %s)", target.Hostname, target.State, target.ErrorCode, target.Message)
		}
	}
	// Nothing was renamed: the fleet answers to the same names.
	for _, before := range []hostView{first, second} {
		if after := h.hostByName(before.Hostname); after.ID != before.ID {
			t.Errorf("%s is no longer the host %s after the no-op rename", before.Hostname, before.ID)
		}
	}
}

// assertPlansCarryOwnNames reads the plan set of a rename campaign and checks
// that every named host's plan carries that host's own name, from the order -
// and no other host's.
func assertPlansCarryOwnNames(t *testing.T, h *harness, campaignID string, wanted map[string]string) {
	t.Helper()
	var groups struct {
		Items []struct {
			PlanHash string   `json:"plan_hash"`
			Hosts    []string `json:"hosts"`
			Plan     struct {
				Plan struct {
					Hostname string `json:"hostname"`
					Source   string `json:"source"`
				} `json:"plan"`
			} `json:"plan"`
		} `json:"items"`
		Hosts int `json:"hosts"`
	}
	h.get("/api/v1/campaigns/"+campaignID+"/plans", &groups)
	if groups.Hosts != len(wanted) {
		t.Errorf("the plan set covers %d hosts, %d were named", groups.Hosts, len(wanted))
	}
	seen := map[string]bool{}
	for _, group := range groups.Items {
		// Two hosts with two names never share a plan: the digest is of
		// the name, so a group is one host.
		if len(group.Hosts) != 1 {
			t.Errorf("the plan %s covers %d hosts (%s); a rename plan is one host's name", group.PlanHash, len(group.Hosts), strings.Join(group.Hosts, ", "))
			continue
		}
		host := group.Hosts[0]
		if group.Plan.Plan.Source != "order" {
			t.Errorf("the plan of %s comes from %q, expected the order", host, group.Plan.Plan.Source)
		}
		if group.Plan.Plan.Hostname != wanted[host] {
			t.Errorf("the plan of %s carries the name %q, the order gave it %q", host, group.Plan.Plan.Hostname, wanted[host])
		}
		seen[host] = true
	}
	for host := range wanted {
		if !seen[host] {
			t.Errorf("%s has no plan in the set", host)
		}
	}
}
