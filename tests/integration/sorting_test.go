//go:build integration

package integration

import (
	"net/http"
	"net/url"
	"testing"
	"time"
)

// sortedHost is the part of a host the sort tests read.
type sortedHost struct {
	ID       string `json:"id"`
	Hostname string `json:"hostname"`
	Site     string `json:"site"`
}

type sortedHostPage struct {
	Items      []sortedHost `json:"items"`
	Total      int          `json:"total"`
	NextCursor string       `json:"next_cursor"`
}

// walkHosts reads the whole list one page at a time under the given query,
// following the cursor, and returns every row in the order the pages gave
// them.
func walkHosts(t *testing.T, h *harness, query url.Values, fleet int) []sortedHost {
	t.Helper()
	var walked []sortedHost
	cursor := ""
	for pages := 0; pages <= fleet+1; pages++ {
		q := url.Values{}
		for key, values := range query {
			q[key] = values
		}
		if cursor != "" {
			q.Set("cursor", cursor)
		}
		var page sortedHostPage
		h.get("/api/v1/hosts?"+q.Encode(), &page)
		walked = append(walked, page.Items...)
		if page.NextCursor == "" {
			return walked
		}
		cursor = page.NextCursor
	}
	t.Fatalf("the cursor of %s never ran dry after %d pages", query.Encode(), fleet+2)
	return nil
}

// TestHostListSortsAndPagesUnderASort checks the order the list can be asked
// for: sorted by hostname the rows come in the database's order, turned round
// under :desc, and the pages of a sorted list neither repeat a host nor skip
func TestHostListSortsAndPagesUnderASort(t *testing.T) {
	h := newHarness(t)
	var whole sortedHostPage
	h.get("/api/v1/hosts?limit=500", &whole)
	if len(whole.Items) < 2 {
		t.Skipf("the fleet has %d hosts; sorting needs at least 2", len(whole.Items))
	}

	// The default order is the hostname ascending, and asking for it by
	// name gives the same list.
	var byName sortedHostPage
	h.get("/api/v1/hosts?sort=hostname&limit=500", &byName)
	if len(byName.Items) != len(whole.Items) {
		t.Fatalf("sorted by hostname the list has %d hosts, unsorted %d", len(byName.Items), len(whole.Items))
	}
	for i := range whole.Items {
		if byName.Items[i].ID != whole.Items[i].ID {
			t.Errorf("row %d is %s sorted by hostname, %s unsorted", i, byName.Items[i].Hostname, whole.Items[i].Hostname)
		}
	}

	// Descending is the same list read from the other end.
	var reversed sortedHostPage
	h.get("/api/v1/hosts?sort=hostname:desc&limit=500", &reversed)
	if len(reversed.Items) != len(whole.Items) {
		t.Fatalf("sorted by hostname:desc the list has %d hosts, unsorted %d", len(reversed.Items), len(whole.Items))
	}
	for i := range whole.Items {
		mirror := whole.Items[len(whole.Items)-1-i]
		if reversed.Items[i].ID != mirror.ID {
			t.Errorf("row %d is %s descending, expected %s", i, reversed.Items[i].Hostname, mirror.Hostname)
		}
	}

	// The pages of a sorted list: one host per page, every page under the
	// same sort, and the pages together are the unpaged sorted list.
	for _, sort := range []string{"hostname:desc", "site", "site:desc", "pending_updates:desc", "agent_version"} {
		var unpaged sortedHostPage
		h.get("/api/v1/hosts?sort="+url.QueryEscape(sort)+"&limit=500", &unpaged)
		walked := walkHosts(t, h, url.Values{"sort": {sort}, "limit": {"1"}}, whole.Total)
		if len(walked) != whole.Total {
			t.Errorf("sort=%s: the pages gave %d hosts, the fleet has %d", sort, len(walked), whole.Total)
		}
		seen := map[string]bool{}
		for i, host := range walked {
			if seen[host.ID] {
				t.Errorf("sort=%s: %s appears on two pages", sort, host.Hostname)
			}
			seen[host.ID] = true
			if i < len(unpaged.Items) && unpaged.Items[i].ID != host.ID {
				t.Errorf("sort=%s: page %d holds %s, the unpaged list %s", sort, i, host.Hostname, unpaged.Items[i].Hostname)
			}
		}
		for _, host := range whole.Items {
			if !seen[host.ID] {
				t.Errorf("sort=%s: the pages skipped %s", sort, host.Hostname)
			}
		}
	}

	// A cursor is issued under an order and refused under another: the key it
	// carries is a name, and a page sorted by site cannot start after a name.
	var first sortedHostPage
	h.get("/api/v1/hosts?sort=hostname&limit=1", &first)
	if first.NextCursor == "" {
		t.Fatal("a page of one host out of at least two has no next cursor")
	}
	var problem struct {
		Code   string `json:"code"`
		Detail string `json:"detail"`
	}
	h.do(http.MethodGet, "/api/v1/hosts?sort=site&cursor="+url.QueryEscape(first.NextCursor), nil, &problem, http.StatusBadRequest)
	if problem.Code != "invalid_cursor" {
		t.Errorf("a cursor of another order was answered with %q (%s), expected invalid_cursor", problem.Code, problem.Detail)
	}

	// A column the list has not got, or a direction that is neither way,
	// is the request's fault and is named as such.
	for _, query := range []string{"sort=colour", "sort=hostname:sideways", "sort=machine_id"} {
		h.do(http.MethodGet, "/api/v1/hosts?"+query, nil, &problem, http.StatusBadRequest)
		if problem.Code != "invalid_sort" {
			t.Errorf("%s was answered with %q (%s), expected invalid_sort", query, problem.Code, problem.Detail)
		}
	}
	// The export takes the same order as the list.
	h.do(http.MethodGet, "/api/v1/hosts?sort=colour&format=csv", nil, &problem, http.StatusBadRequest)
	if problem.Code != "invalid_sort" {
		t.Errorf("an export sorted by nothing was answered with %q, expected invalid_sort", problem.Code)
	}
}

// TestJobListSortsByCreationTime orders two reads and checks that the list
// asked for oldest first gives the first read before the second, page by page,
// while the default stays newest first; a sort by a column the list has not
func TestJobListSortsByCreationTime(t *testing.T) {
	h := newHarness(t)
	host := h.hostByFamily("debian")

	payload := map[string]any{
		"journal": map[string]any{"unit": "cron.service", "lines": 3},
	}
	// The bound is taken right before the first order: an earlier read of
	// the same kind on the host, left by another test, would come first.
	since := time.Now().Add(-2 * time.Second).UTC().Format(time.RFC3339)
	first := h.createOperation(host.ID, map[string]any{"action": "journal.read", "payload": payload})
	second := h.createOperation(host.ID, map[string]any{"action": "journal.read", "payload": payload})
	query := "/api/v1/jobs?action=journal.read&host_id=" + host.ID + "&since=" + url.QueryEscape(since)

	var oldest jobPage
	h.get(query+"&sort=created_at:asc&limit=1", &oldest)
	if len(oldest.Items) != 1 || oldest.Items[0].ID != first.ID {
		t.Fatalf("oldest first, the first page holds %+v, expected the first read %s", oldest.Items, first.ID)
	}
	if oldest.NextCursor == "" {
		t.Fatal("the first page has no next cursor although a second read exists")
	}
	var next jobPage
	h.get(query+"&sort=created_at:asc&limit=1&cursor="+url.QueryEscape(oldest.NextCursor), &next)
	if len(next.Items) != 1 || next.Items[0].ID != second.ID {
		t.Errorf("oldest first, the second page holds %+v, expected the second read %s", next.Items, second.ID)
	}

	var newest jobPage
	h.get(query+"&limit=1", &newest)
	if len(newest.Items) != 1 || newest.Items[0].ID != second.ID {
		t.Errorf("by default the first page holds %+v, expected the second read %s", newest.Items, second.ID)
	}

	// The other columns are accepted; the cursor of one order is refused
	// under another, and a column the list has not got is refused.
	for _, sort := range []string{"state", "action_type:desc", "hostname", "finished_at:desc"} {
		var page jobPage
		h.get(query+"&sort="+url.QueryEscape(sort), &page)
		if len(page.Items) != 2 {
			t.Errorf("sort=%s lists %d jobs, expected the two reads", sort, len(page.Items))
		}
	}
	var problem struct {
		Code   string `json:"code"`
		Detail string `json:"detail"`
	}
	h.do(http.MethodGet, query+"&sort=state&cursor="+url.QueryEscape(oldest.NextCursor), nil, &problem, http.StatusBadRequest)
	if problem.Code != "invalid_cursor" {
		t.Errorf("a cursor of another order was answered with %q (%s), expected invalid_cursor", problem.Code, problem.Detail)
	}
	for _, sort := range []string{"payload", "created_at:up"} {
		h.do(http.MethodGet, "/api/v1/jobs?sort="+url.QueryEscape(sort), nil, &problem, http.StatusBadRequest)
		if problem.Code != "invalid_sort" {
			t.Errorf("sort=%s was answered with %q (%s), expected invalid_sort", sort, problem.Code, problem.Detail)
		}
	}
	h.awaitTerminal(first.ID, 60*time.Second)
	h.awaitTerminal(second.ID, 60*time.Second)
}
