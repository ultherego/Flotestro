//go:build integration

package integration

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"testing"
	"time"
)

// The scope of an identity is a boundary of every list, preview and order, not
// only of a direct read: the operator of one site must not count, preview,
// list or revoke what lives in another.

// scopeReason is the reason the tests give for what they create.
const scopeReason = "scope boundary integration test"

// enrollSyntheticHostAt brings a machine that does not exist into the fleet at
// the given placement.
func (h *harness) enrollSyntheticHostAt(t *testing.T, site, environment string) hostView {
	t.Helper()
	var order struct {
		Token string `json:"token"`
	}
	h.do(http.MethodPost, "/api/v1/enrollment-requests", map[string]any{
		"description": "synthetic host of " + site, "site": site, "environment": environment,
	}, &order, http.StatusCreated)
	return h.enrollSyntheticHostWithToken(t, order.Token)
}

// labOperator is an operator bound to the lab site and the test
// environment alone - the placement of every lab host.
func (h *harness) labOperator(t *testing.T, prefix string) *harness {
	t.Helper()
	return h.withToken(h.createPrincipal(uniqueSubject(prefix), []map[string]string{
		{"role": "operator", "site": "lab", "environment": "test"},
	}))
}

// targetsProblem is the refusal of an explicit host list: the code and the
// reason per host.
type targetsProblem struct {
	Code    string `json:"code"`
	Targets []struct {
		HostID string `json:"host_id"`
		Reason string `json:"reason"`
	} `json:"targets"`
}

func (p targetsProblem) reasonOf(hostID string) string {
	for _, target := range p.Targets {
		if target.HostID == hostID {
			return target.Reason
		}
	}
	return ""
}

// TestCampaignPreviewAndOrderShareTheCallersScope guards the invariant of the
// RBAC chapter: for the same caller and selector the preview counts what the
// order would carry.
func TestCampaignPreviewAndOrderShareTheCallersScope(t *testing.T) {
	h := newHarness(t)
	labHost := h.hostByFamily("debian")
	elsewhere := h.enrollSyntheticHostAt(t, "elsewhere", "test")
	operator := h.labOperator(t, "operator-lab-scope")

	type preview struct {
		Count  int      `json:"count"`
		Sample []string `json:"sample"`
	}
	// A preview of the whole fleet: the administrator counts the host
	// elsewhere, the operator does not - the scope is part of the query.
	var admin, scoped preview
	h.get("/api/v1/campaigns/preview", &admin)
	operator.get("/api/v1/campaigns/preview", &scoped)
	if admin.Count <= scoped.Count {
		t.Fatalf("the administrator counts %d hosts and the lab operator %d; the host elsewhere should make the difference",
			admin.Count, scoped.Count)
	}
	for _, name := range scoped.Sample {
		if name == elsewhere.Hostname {
			t.Fatalf("the sample of the lab operator names the host elsewhere: %v", scoped.Sample)
		}
	}
	// The same with an operation: the eligibility is judged on the
	// narrowed set, so the count stays the operator's.
	var withAction preview
	operator.get("/api/v1/campaigns/preview?action=unit.restart", &withAction)
	if withAction.Count != scoped.Count {
		t.Errorf("the preview with an operation counts %d, without %d; the same resolver should answer both",
			withAction.Count, scoped.Count)
	}

	// An explicit list naming the host elsewhere is refused with its reason, in
	// the preview and in the order alike, and the lab host on the same list is
	// not the reason.
	query := url.Values{}
	query.Add("host_id", labHost.ID)
	query.Add("host_id", elsewhere.ID)
	query.Set("action", "unit.restart")
	var refusal targetsProblem
	operator.do(http.MethodGet, "/api/v1/campaigns/preview?"+query.Encode(), nil, &refusal,
		http.StatusUnprocessableEntity)
	if refusal.Code != "targets_invalid" || refusal.reasonOf(elsewhere.ID) != "out_of_scope" ||
		refusal.reasonOf(labHost.ID) != "" {
		t.Fatalf("the preview of a list with a host elsewhere answered %+v", refusal)
	}
	refusal = targetsProblem{}
	operator.do(http.MethodPost, "/api/v1/campaigns", labCampaign("list with a host elsewhere", "cron.service",
		map[string]any{"selector": map[string]any{"host_ids": []string{labHost.ID, elsewhere.ID}}}),
		&refusal, http.StatusUnprocessableEntity)
	if refusal.Code != "targets_invalid" || refusal.reasonOf(elsewhere.ID) != "out_of_scope" {
		t.Fatalf("the order of a list with a host elsewhere answered %+v", refusal)
	}

	// An identifier that is no host, and a host both listed and excluded,
	// are named the same way.
	unknown := "00000000-0000-4000-8000-000000000001"
	refusal = targetsProblem{}
	h.do(http.MethodPost, "/api/v1/campaigns", labCampaign("list with a stranger", "cron.service",
		map[string]any{"selector": map[string]any{
			"host_ids": []string{labHost.ID, unknown}, "exclude": []string{labHost.ID},
			"exclude_reason": "listed and excluded at once",
		}}), &refusal, http.StatusUnprocessableEntity)
	if refusal.reasonOf(unknown) != "unknown_host" || refusal.reasonOf(labHost.ID) != "excluded_and_listed" {
		t.Fatalf("the order of a list with a stranger and a contradiction answered %+v", refusal)
	}

	// The administrator previews and orders the same list: both hosts are
	// in scope, so the list resolves in full.
	var full preview
	h.get("/api/v1/campaigns/preview?"+query.Encode(), &full)
	if full.Count != 2 {
		t.Fatalf("the administrator's preview of two hosts counts %d", full.Count)
	}
	campaign := h.createCampaign(labCampaign("both sites", "cron.service",
		map[string]any{"selector": map[string]any{"host_ids": []string{labHost.ID, elsewhere.ID}}}))
	if targets := h.campaignTargets(campaign.ID); len(targets) != 2 {
		t.Fatalf("the snapshot of the administrator's order has %d hosts, expected 2", len(targets))
	}
}

// TestEnrollmentOrdersStayWithinTheCallersScope guards the enrollment chapter
// of the RBAC document: a site-scoped operator sees only their site's orders.
func TestEnrollmentOrdersStayWithinTheCallersScope(t *testing.T) {
	h := newHarness(t)
	operator := h.labOperator(t, "operator-lab-enrollment")

	var lab, elsewhere orderView
	h.do(http.MethodPost, "/api/v1/enrollment-requests", map[string]any{
		"description": "order of the lab", "site": "lab", "environment": "test", "ttl_minutes": 15,
	}, &lab, http.StatusCreated)
	h.do(http.MethodPost, "/api/v1/enrollment-requests", map[string]any{
		"description": "order elsewhere", "site": "elsewhere", "environment": "test", "ttl_minutes": 15,
	}, &elsewhere, http.StatusCreated)
	t.Cleanup(func() {
		h.do(http.MethodPost, "/api/v1/enrollment-requests/"+lab.ID+"/revoke", nil, nil, 0)
		h.do(http.MethodPost, "/api/v1/enrollment-requests/"+elsewhere.ID+"/revoke", nil, nil, 0)
	})

	type page struct {
		Items      []orderView `json:"items"`
		NextCursor string      `json:"next_cursor"`
	}
	listed := func(p page, id string) bool {
		for _, item := range p.Items {
			if item.ID == id {
				return true
			}
		}
		return false
	}
	var scoped page
	operator.get("/api/v1/enrollment-requests?status=pending", &scoped)
	if !listed(scoped, lab.ID) || listed(scoped, elsewhere.ID) {
		t.Fatalf("the lab operator lists the lab order %v and the order elsewhere %v",
			listed(scoped, lab.ID), listed(scoped, elsewhere.ID))
	}
	for _, item := range scoped.Items {
		if item.Site != "lab" {
			t.Fatalf("the lab operator's list carries an order of site %q", item.Site)
		}
	}
	// The placement filter is a filter, not a way around the scope.
	var asked page
	operator.get("/api/v1/enrollment-requests?site=elsewhere", &asked)
	if len(asked.Items) != 0 {
		t.Fatalf("the lab operator asked for the orders elsewhere and got %d", len(asked.Items))
	}
	// The administrator sees both, and the page is keyed: one order per
	// page walks the list without a row twice.
	var admin page
	h.get("/api/v1/enrollment-requests?status=pending", &admin)
	if !listed(admin, lab.ID) || !listed(admin, elsewhere.ID) {
		t.Fatalf("the administrator does not list both orders: lab %v, elsewhere %v",
			listed(admin, lab.ID), listed(admin, elsewhere.ID))
	}
	seen := map[string]bool{}
	cursor := ""
	for pages := 0; pages < 1000; pages++ {
		var one page
		h.get("/api/v1/enrollment-requests?status=pending&limit=1&cursor="+url.QueryEscape(cursor), &one)
		if len(one.Items) > 1 {
			t.Fatalf("a page of one carries %d orders", len(one.Items))
		}
		for _, item := range one.Items {
			if seen[item.ID] {
				t.Fatalf("the order %s appeared on two pages", item.ID)
			}
			seen[item.ID] = true
		}
		if one.NextCursor == "" {
			break
		}
		cursor = one.NextCursor
	}
	if !seen[lab.ID] || !seen[elsewhere.ID] {
		t.Fatalf("walking the pages missed an order: lab %v, elsewhere %v", seen[lab.ID], seen[elsewhere.ID])
	}
	h.do(http.MethodGet, "/api/v1/enrollment-requests?cursor=not-a-cursor", nil, nil, http.StatusBadRequest)
	h.do(http.MethodGet, "/api/v1/enrollment-requests?status=dancing", nil, nil, http.StatusBadRequest)

	// The revoke is judged where the machine was to live.
	operator.do(http.MethodPost, "/api/v1/enrollment-requests/"+elsewhere.ID+"/revoke", nil, nil, http.StatusForbidden)
	var still orderView
	h.get("/api/v1/enrollment-requests/"+elsewhere.ID, &still)
	if still.Status != "pending" {
		t.Fatalf("the refused revoke changed the order elsewhere to %s", still.Status)
	}
	operator.do(http.MethodPost, "/api/v1/enrollment-requests/"+lab.ID+"/revoke", nil, nil, http.StatusNoContent)
	var revoked orderView
	h.get("/api/v1/enrollment-requests/"+lab.ID, &revoked)
	if revoked.Status != "revoked" {
		t.Fatalf("the lab operator's revoke left the lab order %s", revoked.Status)
	}
}

// TestNotificationChannelsAreVisibleInTheirScope guards the notification part
// of the RBAC chapter: a channel filtered to a site is the business of that
// site's operators, and a fleet-wide one is not theirs to see.
func TestNotificationChannelsAreVisibleInTheirScope(t *testing.T) {
	h := newHarness(t)
	operator := h.labOperator(t, "operator-lab-notifications")
	stamp := time.Now().UnixNano()

	fleetWide := createChannel(h, map[string]any{
		"name": fmt.Sprintf("scope-fleet-%d", stamp), "kind": "slack_webhook",
		"config": map[string]any{"url": "http://127.0.0.1:1/services/T0/B0/fleet-token"},
		"events": []string{"alert.fired"}, "reason": scopeReason,
	})
	labOnly := createChannel(h, map[string]any{
		"name": fmt.Sprintf("scope-lab-%d", stamp), "kind": "slack_webhook",
		"config": map[string]any{"url": "http://127.0.0.1:1/services/T0/B0/lab-token"},
		"events": []string{"alert.fired"}, "filter": map[string]any{"site": "lab", "environment": "test"},
		"reason": scopeReason,
	})
	elsewhereOnly := createChannel(h, map[string]any{
		"name": fmt.Sprintf("scope-elsewhere-%d", stamp), "kind": "webhook",
		"config": map[string]any{"url": "http://127.0.0.1:1/", "secret": "scope-signing-secret"},
		"events": []string{"alert.fired"}, "filter": map[string]any{"site": "elsewhere", "environment": "test"},
		"reason": scopeReason,
	})

	// The address left the store as "set", on the create answer and on
	// every read after it; the signing secret of the webhook the same way.
	for _, channel := range []channelView{fleetWide, labOnly} {
		var config map[string]any
		if err := json.Unmarshal(channel.Config, &config); err != nil {
			t.Fatal(err)
		}
		if address, present := config["url"]; present && address != "" {
			t.Fatalf("the address of the incoming webhook %s came back: %s", channel.Name, channel.Config)
		}
		if config["url_set"] != true {
			t.Fatalf("the channel %s does not say its address is set: %s", channel.Name, channel.Config)
		}
	}

	var list struct {
		Items []channelView `json:"items"`
	}
	operator.get("/api/v1/notifications/channels", &list)
	visible := map[string]bool{}
	for _, item := range list.Items {
		visible[item.ID] = true
	}
	if !visible[labOnly.ID] || visible[fleetWide.ID] || visible[elsewhereOnly.ID] {
		t.Fatalf("the lab operator sees lab %v, fleet-wide %v, elsewhere %v; expected the lab channel alone",
			visible[labOnly.ID], visible[fleetWide.ID], visible[elsewhereOnly.ID])
	}
	operator.do(http.MethodGet, "/api/v1/notifications/channels/"+labOnly.ID, nil, nil, http.StatusOK)
	operator.do(http.MethodGet, "/api/v1/notifications/channels/"+fleetWide.ID, nil, nil, http.StatusForbidden)
	operator.do(http.MethodGet, "/api/v1/notifications/channels/"+elsewhereOnly.ID, nil, nil, http.StatusForbidden)

	// An edit that does not retype the address keeps it: the channel still
	// says the address is set, and a channel without one is refused.
	var edited channelView
	h.do(http.MethodPut, "/api/v1/notifications/channels/"+labOnly.ID, map[string]any{
		"name": labOnly.Name, "kind": "slack_webhook", "config": map[string]any{"url_set": true},
		"events": []string{"alert.fired", "alert.resolved"},
		"filter": map[string]any{"site": "lab", "environment": "test"}, "enabled": true, "reason": scopeReason,
	}, &edited, http.StatusOK)
	var config map[string]any
	if err := json.Unmarshal(edited.Config, &config); err != nil {
		t.Fatal(err)
	}
	if config["url_set"] != true || len(edited.Events) != 2 {
		t.Fatalf("the edit without the address did not keep it: %s events %v", edited.Config, edited.Events)
	}
	h.do(http.MethodPost, "/api/v1/notifications/channels", map[string]any{
		"name": fmt.Sprintf("scope-empty-%d", stamp), "kind": "slack_webhook",
		"config": map[string]any{"url_set": true}, "events": []string{"alert.fired"}, "reason": scopeReason,
	}, nil, http.StatusBadRequest)
}
