//go:build integration

package integration

import (
	"net/http"
	"net/url"
	"testing"
)

// TestJobListFiltersByFanOutAndHost orders a read fan-out over the connected
// hosts and checks that the job list narrows to it: the fan-out filter keeps
// exactly its jobs, the host filter keeps the jobs of that host alone, and the
func TestJobListFiltersByFanOutAndHost(t *testing.T) {
	h := newHarness(t)
	online := onlineHosts(t, h)

	var created readView
	h.do(http.MethodPost, "/api/v1/reads", map[string]any{
		"action":   "process.list",
		"payload":  map[string]any{"process_list": map[string]any{"sort_by": "rss", "limit": 5}},
		"selector": map[string]any{"host_ids": hostIDs(online)},
		"reason":   "integration test: jobs the list filters must find",
	}, &created, http.StatusCreated)
	if created.ID == "" || len(created.Hosts) != len(online) {
		t.Fatalf("the fan-out came back as %+v", created)
	}
	jobOfHost := map[string]string{}
	for _, host := range created.Hosts {
		jobOfHost[host.HostID] = host.JobID
	}

	list := func(query url.Values) []jobView {
		t.Helper()
		var page struct {
			Items []jobView `json:"items"`
		}
		h.get("/api/v1/jobs?"+query.Encode(), &page)
		return page.Items
	}

	// The fan-out filter keeps its jobs and nothing else: every job of the
	// list is one the fan-out named, and every named job is on the list.
	byFanOut := list(url.Values{"fanout_id": {created.ID}})
	if len(byFanOut) != len(online) {
		t.Fatalf("the list filtered on the fan-out has %d jobs, expected %d", len(byFanOut), len(online))
	}
	for _, job := range byFanOut {
		if jobOfHost[job.HostID] != job.ID {
			t.Errorf("job %s of host %s is on the fan-out list but not in the fan-out", job.ID, job.HostID)
		}
	}

	// The host filter keeps the jobs of that host alone, the fan-out's
	// among them; a filter on both narrows to that single job.
	host := online[0]
	byHost := list(url.Values{"host_id": {host.ID}})
	found := false
	for _, job := range byHost {
		if job.HostID != host.ID {
			t.Errorf("job %s of host %s is on the list of host %s", job.ID, job.HostID, host.ID)
		}
		if job.ID == jobOfHost[host.ID] {
			found = true
		}
	}
	if !found {
		t.Errorf("the list of host %s does not carry the fan-out's job %s", host.Hostname, jobOfHost[host.ID])
	}
	both := list(url.Values{"host_id": {host.ID}, "fanout_id": {created.ID}})
	if len(both) != 1 || both[0].ID != jobOfHost[host.ID] {
		t.Errorf("the list filtered on the host and the fan-out is %+v, expected the one job %s", both, jobOfHost[host.ID])
	}

	// The hostname filter takes the beginning of the name; a full name is
	// a prefix of itself, so the fan-out's job on the host is on the list.
	byName := list(url.Values{"hostname": {host.Hostname}, "fanout_id": {created.ID}})
	if len(byName) == 0 {
		t.Errorf("the list filtered on the name %s and the fan-out is empty", host.Hostname)
	}
	for _, job := range byName {
		if job.HostID != host.ID && !sharesPrefix(online, job.HostID, host.Hostname) {
			t.Errorf("job %s of host %s is on the list of the name %s", job.ID, job.HostID, host.Hostname)
		}
	}
	if len(host.Hostname) > 1 {
		short := list(url.Values{"hostname": {host.Hostname[:1]}, "fanout_id": {created.ID}})
		if len(short) < len(byName) {
			t.Errorf("a shorter prefix %q keeps %d jobs, fewer than the full name's %d", host.Hostname[:1], len(short), len(byName))
		}
	}

	// An identifier that is not one is a wrong request, not a server fault,
	// and the answer says which filter is wrong.
	var problem struct {
		Code   string `json:"code"`
		Detail string `json:"detail"`
	}
	h.do(http.MethodGet, "/api/v1/jobs?host_id=not-a-host", nil, &problem, http.StatusBadRequest)
	if problem.Code != "invalid_filter" {
		t.Errorf("a malformed host_id was answered with %q (%s), expected invalid_filter", problem.Code, problem.Detail)
	}
	h.do(http.MethodGet, "/api/v1/jobs?hostname=%20", nil, &problem, http.StatusBadRequest)
	if problem.Code != "invalid_filter" {
		t.Errorf("a malformed hostname was answered with %q (%s), expected invalid_filter", problem.Code, problem.Detail)
	}
}

// sharesPrefix says whether the host with the identifier is one of the listed
// hosts and its name begins with the prefix: two lab hosts may be named alike,
// and the name filter keeps both by design.
func sharesPrefix(hosts []hostView, hostID, prefix string) bool {
	for _, host := range hosts {
		if host.ID == hostID && len(host.Hostname) >= len(prefix) && host.Hostname[:len(prefix)] == prefix {
			return true
		}
	}
	return false
}
