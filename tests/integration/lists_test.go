//go:build integration

package integration

import (
	"net/url"
	"testing"
	"time"
)

// listedHost is the part of a host the list tests look at.
type listedHost struct {
	ID                string `json:"id"`
	Hostname          string `json:"hostname"`
	ManagementAddress string `json:"management_address"`
	ConnectionState   string `json:"connection_state"`
}

// hostPage mirrors one page of the host list.
type hostPage struct {
	Items      []listedHost `json:"items"`
	Count      int          `json:"count"`
	Total      int          `json:"total"`
	NextCursor string       `json:"next_cursor"`
}

// TestHostSearchFindsAHostByFragmentAndAddress checks that the search runs
// in the database: a fragment of the name and the management address both
// find the lab host, and the total says how many hosts match rather than
// how many fit on the page.
func TestHostSearchFindsAHostByFragmentAndAddress(t *testing.T) {
	h := newHarness(t)
	var fleet hostPage
	h.get("/api/v1/hosts", &fleet)
	if len(fleet.Items) == 0 {
		t.Fatal("the fleet is empty")
	}
	host := fleet.Items[0]
	if fleet.Total < len(fleet.Items) {
		t.Errorf("total = %d, fewer than the %d hosts on the page", fleet.Total, len(fleet.Items))
	}

	// The middle of the name, in the other case: the search is a
	// case-insensitive "contains", not a prefix match.
	fragment := host.Hostname
	if len(fragment) > 3 {
		fragment = fragment[1 : len(fragment)-1]
	}
	fragment = swapCase(fragment)
	var byName hostPage
	h.get("/api/v1/hosts?q="+url.QueryEscape(fragment), &byName)
	if !containsHost(byName.Items, host.ID) {
		t.Errorf("the search for %q did not find %s among %d hosts", fragment, host.Hostname, len(byName.Items))
	}

	// The address the panel talks to the host through. A host that has not
	// connected yet has none, and there is nothing to search for then.
	if host.ManagementAddress != "" {
		var byAddress hostPage
		h.get("/api/v1/hosts?q="+url.QueryEscape(host.ManagementAddress), &byAddress)
		if !containsHost(byAddress.Items, host.ID) {
			t.Errorf("the search for the address %s did not find %s", host.ManagementAddress, host.Hostname)
		}
	}

	var none hostPage
	h.get("/api/v1/hosts?q=no-such-host-anywhere-in-the-lab", &none)
	if none.Total != 0 || len(none.Items) != 0 {
		t.Errorf("a search for nothing found %d hosts (total %d)", len(none.Items), none.Total)
	}
}

// TestHostListPagesWithTheCursor walks the fleet one host per page and
// checks that the pages neither overlap nor skip: together they are the
// whole list, in the same order.
func TestHostListPagesWithTheCursor(t *testing.T) {
	h := newHarness(t)
	var whole hostPage
	h.get("/api/v1/hosts?limit=500", &whole)
	if len(whole.Items) < 2 {
		t.Skipf("the fleet has %d hosts; paging needs at least 2", len(whole.Items))
	}

	var walked []listedHost
	cursor := ""
	for pages := 0; pages <= len(whole.Items); pages++ {
		var page hostPage
		h.get("/api/v1/hosts?limit=1&cursor="+url.QueryEscape(cursor), &page)
		if page.Count != len(page.Items) {
			t.Errorf("count = %d for %d items", page.Count, len(page.Items))
		}
		if page.Total != whole.Total {
			t.Errorf("total = %d on a page, %d on the whole list", page.Total, whole.Total)
		}
		walked = append(walked, page.Items...)
		if page.NextCursor == "" {
			break
		}
		cursor = page.NextCursor
	}
	if len(walked) != len(whole.Items) {
		t.Fatalf("the pages gave %d hosts, the whole list %d", len(walked), len(whole.Items))
	}
	for i := range whole.Items {
		if walked[i].ID != whole.Items[i].ID {
			t.Errorf("page %d holds %s, the whole list %s", i, walked[i].Hostname, whole.Items[i].Hostname)
		}
	}

	h.do("GET", "/api/v1/hosts?cursor=not-a-cursor", nil, nil, 400)
}

// jobPage mirrors one page of the task list.
type jobPage struct {
	Items      []jobView `json:"items"`
	Count      int       `json:"count"`
	NextCursor string    `json:"next_cursor"`
}

// TestJobListFiltersByActionAndPages orders two reads and checks that the
// list narrowed to that operation holds only such tasks, newest first, and
// pages by the cursor without repeating a task.
func TestJobListFiltersByActionAndPages(t *testing.T) {
	h := newHarness(t)
	host := h.hostByFamily("debian")

	payload := map[string]any{
		"journal": map[string]any{"unit": "cron.service", "lines": 3},
	}
	first := h.createOperation(host.ID, map[string]any{"action": "journal.read", "payload": payload})
	second := h.createOperation(host.ID, map[string]any{"action": "journal.read", "payload": payload})
	// The list is asked for the tasks of this test only, so that the noise
	// of the other tests on the same host does not decide the answer.
	since := time.Now().Add(-time.Minute).UTC().Format(time.RFC3339)
	query := "/api/v1/jobs?action=journal.read&host_id=" + host.ID + "&since=" + url.QueryEscape(since)

	var page jobPage
	h.get(query+"&limit=1", &page)
	if len(page.Items) != 1 {
		t.Fatalf("the first page holds %d tasks, expected 1", len(page.Items))
	}
	if page.Items[0].ActionType != "journal.read" {
		t.Errorf("the filter let through %s", page.Items[0].ActionType)
	}
	if page.Items[0].ID != second.ID {
		t.Errorf("the newest task is %s, expected the second read %s", page.Items[0].ID, second.ID)
	}
	if page.NextCursor == "" {
		t.Fatal("the first page has no next cursor although a second task exists")
	}

	var next jobPage
	h.get(query+"&limit=1&cursor="+url.QueryEscape(page.NextCursor), &next)
	if len(next.Items) != 1 || next.Items[0].ID != first.ID {
		t.Errorf("the second page holds %+v, expected the first read %s", next.Items, first.ID)
	}
	for _, job := range next.Items {
		if job.ActionType != "journal.read" {
			t.Errorf("the filter let through %s", job.ActionType)
		}
	}

	var other jobPage
	h.get("/api/v1/jobs?action=unit.restart&host_id="+host.ID+"&since="+url.QueryEscape(since), &other)
	for _, job := range other.Items {
		if job.ID == first.ID || job.ID == second.ID {
			t.Errorf("a read appeared in the list of restarts")
		}
	}

	h.do("GET", "/api/v1/jobs?since=yesterday", nil, nil, 400)
	h.do("GET", "/api/v1/jobs?campaign_id=not-an-id", nil, nil, 400)
	h.awaitTerminal(first.ID, 60*time.Second)
	h.awaitTerminal(second.ID, 60*time.Second)
}

// auditPage mirrors one page of the trail.
type auditPage struct {
	Items []struct {
		ID         int64          `json:"id"`
		OccurredAt time.Time      `json:"occurred_at"`
		Action     string         `json:"action"`
		Outcome    string         `json:"outcome"`
		ActorID    string         `json:"actor_id"`
		TargetID   string         `json:"target_id"`
		RequestID  string         `json:"request_id"`
		Detail     map[string]any `json:"detail"`
	} `json:"items"`
	NextCursor string `json:"next_cursor"`
}

// TestAuditListFiltersByAction checks that the trail narrowed to one action
// holds only that action, that ordering a task leaves a fresh event in it
// and that the pages follow the cursor.
func TestAuditListFiltersByAction(t *testing.T) {
	h := newHarness(t)
	host := h.hostByFamily("debian")
	job := h.createOperation(host.ID, map[string]any{
		"action":  "journal.read",
		"payload": map[string]any{"journal": map[string]any{"unit": "cron.service", "lines": 3}},
	})

	var page auditPage
	h.get("/api/v1/audit?action=job.create&outcome=success&limit=5", &page)
	if len(page.Items) == 0 {
		t.Fatal("no job.create event although a task was just ordered")
	}
	for _, event := range page.Items {
		if event.Action != "job.create" || event.Outcome != "success" {
			t.Errorf("the filter let through %s/%s", event.Action, event.Outcome)
		}
	}

	if page.NextCursor != "" {
		var next auditPage
		h.get("/api/v1/audit?action=job.create&outcome=success&limit=5&cursor="+url.QueryEscape(page.NextCursor), &next)
		// The key is the time and then the identifier: the second page is
		// strictly before the last row of the first one.
		last := page.Items[len(page.Items)-1]
		for _, event := range next.Items {
			if event.OccurredAt.After(last.OccurredAt) ||
				(event.OccurredAt.Equal(last.OccurredAt) && event.ID >= last.ID) {
				t.Errorf("event %d of the second page is not older than the first page", event.ID)
			}
		}
	}

	h.do("GET", "/api/v1/audit?cursor=not-a-cursor", nil, nil, 400)
	h.do("GET", "/api/v1/audit?until=tomorrow", nil, nil, 400)
	h.awaitTerminal(job.ID, 60*time.Second)
}

// TestFleetSummaryCarriesAttentionCounters checks that the dashboard
// counters are numbers computed on the server. A counter the panel cannot
// answer is allowed to be missing; one that is present has to be a
// non-negative number and agree with the size of the fleet.
func TestFleetSummaryCarriesAttentionCounters(t *testing.T) {
	h := newHarness(t)
	var summary struct {
		Hosts                     int    `json:"hosts"`
		RebootRequired            int    `json:"reboot_required"`
		WithFailedUnits           int    `json:"with_failed_units"`
		QuarantinedHosts          int    `json:"quarantined_hosts"`
		PackageDatabaseBroken     int    `json:"package_database_broken"`
		InMaintenance             int    `json:"in_maintenance"`
		FailedJobs24h             *int   `json:"failed_jobs_24h"`
		PendingEnrollmentRequests *int   `json:"pending_enrollment_requests"`
		AgentsBehindLatest        *int   `json:"agents_behind_latest"`
		LatestAgentVersion        string `json:"latest_agent_version"`
		AgentCertificatesExpiring *int   `json:"agent_certificates_expiring"`
		DegradedRelays            *int   `json:"degraded_relays"`
	}
	h.get("/api/v1/fleet/summary", &summary)

	// These three are computed for every view: the tasks, the orders and
	// the certificates are all known to the database.
	for name, value := range map[string]*int{
		"failed_jobs_24h":             summary.FailedJobs24h,
		"pending_enrollment_requests": summary.PendingEnrollmentRequests,
		"agent_certificates_expiring": summary.AgentCertificatesExpiring,
	} {
		if value == nil {
			t.Errorf("the summary lacks %s", name)
		} else if *value < 0 {
			t.Errorf("%s = %d, a negative count", name, *value)
		}
	}
	// The enrolled lab hosts report a version, so the fleet has a newest one
	// and nobody is behind it or ahead of it beyond the fleet's size.
	if summary.AgentsBehindLatest == nil {
		t.Error("no agent version counter although the lab agents report one")
	} else if *summary.AgentsBehindLatest > summary.Hosts || summary.LatestAgentVersion == "" {
		t.Errorf("agents behind latest = %d of %d, latest %q", *summary.AgentsBehindLatest, summary.Hosts, summary.LatestAgentVersion)
	}
	if summary.AgentCertificatesExpiring != nil && *summary.AgentCertificatesExpiring > summary.Hosts {
		t.Errorf("%d certificates expiring on %d hosts", *summary.AgentCertificatesExpiring, summary.Hosts)
	}
	// The global test identity sees the relays of every site.
	if summary.DegradedRelays == nil {
		t.Error("the global view lacks the relay counter")
	}
	for name, value := range map[string]int{
		"reboot_required": summary.RebootRequired, "with_failed_units": summary.WithFailedUnits,
		"quarantined_hosts": summary.QuarantinedHosts, "package_database_broken": summary.PackageDatabaseBroken,
		"in_maintenance": summary.InMaintenance,
	} {
		if value < 0 || value > summary.Hosts {
			t.Errorf("%s = %d on a fleet of %d", name, value, summary.Hosts)
		}
	}
}

func containsHost(items []listedHost, id string) bool {
	for _, item := range items {
		if item.ID == id {
			return true
		}
	}
	return false
}

// swapCase flips the case of every letter, so that a search for the result
// proves the match is case-insensitive.
func swapCase(value string) string {
	out := []rune(value)
	for i, r := range out {
		switch {
		case r >= 'a' && r <= 'z':
			out[i] = r - 'a' + 'A'
		case r >= 'A' && r <= 'Z':
			out[i] = r - 'A' + 'a'
		}
	}
	return string(out)
}
