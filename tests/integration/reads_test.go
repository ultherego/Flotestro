//go:build integration

package integration

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"testing"
	"time"
)

// readView mirrors the answer of the reads endpoint: the fan-out, its hosts
// and the merged result.
type readView struct {
	ID        string `json:"id"`
	Action    string `json:"action"`
	CreatedBy string `json:"created_by"`
	HostCount int    `json:"host_count"`
	Kind      string `json:"kind"`
	Counts    struct {
		Queued    int `json:"queued"`
		Running   int `json:"running"`
		Succeeded int `json:"succeeded"`
		Failed    int `json:"failed"`
	} `json:"counts"`
	Hosts []struct {
		JobID     string          `json:"job_id"`
		HostID    string          `json:"host_id"`
		Hostname  string          `json:"hostname"`
		State     string          `json:"state"`
		ErrorCode string          `json:"error_code"`
		Message   string          `json:"message"`
		Lines     []string        `json:"lines"`
		Snapshot  json.RawMessage `json:"snapshot"`
		Detail    json.RawMessage `json:"detail"`
	} `json:"hosts"`
	Timeline []struct {
		HostID   string `json:"host_id"`
		Hostname string `json:"hostname"`
		At       string `json:"at"`
		Line     string `json:"line"`
	} `json:"timeline"`
	Untimed []struct {
		HostID string   `json:"host_id"`
		Lines  []string `json:"lines"`
	} `json:"untimed"`
}

// onlineHosts returns the connected hosts of the lab, or skips the test
// when fewer than two are up: a fan-out of one host is a single read.
func onlineHosts(t *testing.T, h *harness) []hostView {
	t.Helper()
	var online []hostView
	for _, host := range h.hosts() {
		if host.ConnectionState == "online" {
			online = append(online, host)
		}
	}
	if len(online) < 2 {
		t.Skipf("only %d hosts are connected; a fan-out needs at least two", len(online))
	}
	return online
}

// awaitRead waits until every host of the fan-out has answered.
func awaitRead(t *testing.T, h *harness, id string, timeout time.Duration) readView {
	t.Helper()
	deadline := time.Now().Add(timeout)
	var view readView
	var finished time.Time
	for time.Now().Before(deadline) {
		view = readView{}
		h.get("/api/v1/reads/"+id, &view)
		if view.Counts.Queued+view.Counts.Running == 0 && len(view.Hosts) > 0 {
			if finished.IsZero() {
				finished = time.Now()
			}
			// A read whose answer is neither a snapshot nor a detail has
			// nothing more to wait for; the rest gets a grace period.
			if snapshotsLanded(view) || time.Since(finished) > 15*time.Second {
				return view
			}
		}
		time.Sleep(time.Second)
	}
	t.Fatalf("the fan-out %s did not finish within %s: %+v", id, timeout, view.Counts)
	return view
}

// snapshotsLanded says whether every host that succeeded has its snapshot
// in the view. The result of the job and the inventory fragment it
// refreshed travel separately, and the fragment can land a moment after
// the result: a view read in that moment is finished but not yet whole.
func snapshotsLanded(view readView) bool {
	for _, host := range view.Hosts {
		if host.State == "succeeded" && len(host.Snapshot) == 0 && len(host.Detail) == 0 && len(host.Lines) == 0 {
			return false
		}
	}
	return true
}

// hostIDs lists the identifiers of the hosts.
func hostIDs(hosts []hostView) []string {
	ids := make([]string, 0, len(hosts))
	for _, host := range hosts {
		ids = append(ids, host.ID)
	}
	return ids
}

// TestProcessListFanOut orders a process snapshot on every connected lab
// host at once and reads the per-host results side by side.
func TestProcessListFanOut(t *testing.T) {
	h := newHarness(t)
	online := onlineHosts(t, h)

	var created readView
	h.do(http.MethodPost, "/api/v1/reads", map[string]any{
		"action":   "process.list",
		"payload":  map[string]any{"process_list": map[string]any{"sort_by": "rss", "limit": 20}},
		"selector": map[string]any{"host_ids": hostIDs(online)},
		"reason":   "integration test: a process snapshot of the lab",
	}, &created, http.StatusCreated)

	if created.ID == "" || created.Action != "process.list" || created.Kind != "structured" {
		t.Fatalf("the fan-out came back as %+v", created)
	}
	if created.HostCount != len(online) || len(created.Hosts) != len(online) {
		t.Fatalf("the fan-out covers %d hosts with %d jobs; %d were named",
			created.HostCount, len(created.Hosts), len(online))
	}
	// One ordinary job per host, none of them waiting for approval: a read
	// needs none.
	for _, host := range created.Hosts {
		job := h.job(host.JobID)
		if job.RequiresApproval || job.State == "awaiting_approval" {
			t.Errorf("the job of %s waits for approval; a read needs none", host.Hostname)
		}
		if job.HostID != host.HostID {
			t.Errorf("the job of %s belongs to host %s", host.Hostname, job.HostID)
		}
	}

	view := awaitRead(t, h, created.ID, 90*time.Second)
	if view.Counts.Succeeded != len(online) {
		t.Fatalf("%d of %d hosts succeeded: %+v", view.Counts.Succeeded, len(online), view.Hosts)
	}
	for _, host := range view.Hosts {
		if host.State != "succeeded" {
			t.Errorf("host %s ended in state %s (%s: %s)", host.Hostname, host.State, host.ErrorCode, host.Message)
			continue
		}
		// The snapshot lands in the inventory, and the fan-out reads it back
		// from there for every host: the result stands side by side.
		var snapshot struct {
			Processes []struct {
				PID  int    `json:"pid"`
				Name string `json:"name"`
			} `json:"processes"`
		}
		if len(host.Snapshot) == 0 {
			t.Errorf("host %s answered without a process snapshot", host.Hostname)
			continue
		}
		if err := json.Unmarshal(host.Snapshot, &snapshot); err != nil {
			t.Errorf("the snapshot of %s is not a process list: %v", host.Hostname, err)
			continue
		}
		if len(snapshot.Processes) == 0 {
			t.Errorf("the snapshot of %s lists no processes", host.Hostname)
		}
	}

	// The jobs list filters on the fan-out, and the operator's list carries
	// the fan-out with its counts.
	var jobs struct {
		Items []jobView `json:"items"`
	}
	h.get("/api/v1/jobs?fanout_id="+created.ID, &jobs)
	if len(jobs.Items) != len(online) {
		t.Errorf("the job list filtered on the fan-out has %d jobs, expected %d", len(jobs.Items), len(online))
	}
	var listed struct {
		Items []readView `json:"items"`
	}
	h.get("/api/v1/reads", &listed)
	found := false
	for _, item := range listed.Items {
		if item.ID == created.ID {
			found = true
			if item.Counts.Succeeded != len(online) {
				t.Errorf("the list counts %d succeeded hosts, expected %d", item.Counts.Succeeded, len(online))
			}
		}
	}
	if !found {
		t.Error("the operator's list does not carry the fan-out")
	}
}

// TestJournalFanOutMergesTimeline reads a few journal lines on every
// connected host and checks the merged timeline: every line names its
// host, and the lines with a timestamp stand in order.
func TestJournalFanOutMergesTimeline(t *testing.T) {
	h := newHarness(t)
	online := onlineHosts(t, h)

	var created readView
	h.do(http.MethodPost, "/api/v1/reads", map[string]any{
		"action":   "journal.read",
		"payload":  map[string]any{"journal": map[string]any{"lines": 5}},
		"selector": map[string]any{"host_ids": hostIDs(online)},
		"reason":   "integration test: the last lines of every journal",
	}, &created, http.StatusCreated)
	if created.Kind != "timeline" {
		t.Fatalf("a journal read merges as %q, expected a timeline", created.Kind)
	}

	view := awaitRead(t, h, created.ID, 90*time.Second)
	if view.Counts.Succeeded != len(online) {
		t.Fatalf("%d of %d hosts succeeded: %+v", view.Counts.Succeeded, len(online), view.Hosts)
	}
	byID := map[string]string{}
	for _, host := range online {
		byID[host.ID] = host.Hostname
	}
	// Every host brought at most five lines - six with the header an older
	// journalctl prints - and the merge carries them all: on the timeline
	// when the line names a moment, under its host when not.
	total := 0
	for _, host := range view.Hosts {
		if len(host.Lines) == 0 || len(host.Lines) > 6 {
			t.Errorf("host %s brought %d lines, expected 1-5", host.Hostname, len(host.Lines))
		}
		total += len(host.Lines)
	}
	merged := len(view.Timeline)
	for _, group := range view.Untimed {
		merged += len(group.Lines)
	}
	if merged != total {
		t.Errorf("the merge carries %d lines, the hosts brought %d", merged, total)
	}
	if len(view.Timeline) == 0 {
		t.Fatal("no journal line carried a timestamp; journalctl writes short-iso lines")
	}
	// Every timeline line names the host it came from, and the moments do
	// not go backwards.
	var previous time.Time
	seen := map[string]bool{}
	for i, line := range view.Timeline {
		if byID[line.HostID] == "" || line.Hostname != byID[line.HostID] {
			t.Errorf("line %d names host %q (%s), which is not in the lab", i, line.Hostname, line.HostID)
		}
		seen[line.HostID] = true
		at, err := time.Parse(time.RFC3339Nano, line.At)
		if err != nil {
			t.Errorf("line %d carries the moment %q: %v", i, line.At, err)
			continue
		}
		if at.Before(previous) {
			t.Errorf("line %d (%s) stands before line %d (%s)", i, at, i-1, previous)
		}
		previous = at
		if !strings.Contains(line.Line, at.Format("2006-01-02T15:04:05")) {
			t.Errorf("line %d does not start with its moment: %q", i, line.Line)
		}
	}
	if len(seen) < 2 {
		t.Errorf("the timeline carries lines of %d hosts; at least two answered", len(seen))
	}
}

// TestFanOutRefusesMutations checks that a change is not a read: a fan-out
// of a mutating operation is refused with the reason, whoever asks.
func TestFanOutRefusesMutations(t *testing.T) {
	h := newHarness(t)
	online := onlineHosts(t, h)

	var problem struct {
		Code   string `json:"code"`
		Detail string `json:"detail"`
	}
	h.do(http.MethodPost, "/api/v1/reads", map[string]any{
		"action":   "unit.restart",
		"payload":  unitPayload("cron.service"),
		"selector": map[string]any{"host_ids": hostIDs(online)},
	}, &problem, http.StatusBadRequest)
	if problem.Code != "not_a_fanout_action" {
		t.Errorf("a mutation fanned out: code = %q (%s)", problem.Code, problem.Detail)
	}

	// A live view of the journal is a read, and still one host at a time.
	h.do(http.MethodPost, "/api/v1/reads", map[string]any{
		"action":   "journal.follow",
		"payload":  map[string]any{"journal": map[string]any{"lines": 5, "follow_seconds": 30}},
		"selector": map[string]any{"host_ids": hostIDs(online)},
	}, &problem, http.StatusBadRequest)
	if problem.Code != "not_a_fanout_action" {
		t.Errorf("a journal follow fanned out: code = %q (%s)", problem.Code, problem.Detail)
	}
}

// TestFanOutRefusesTooManyHosts checks the ceiling of a read: an order
// naming more hosts than the process list fans out to is refused as a
// list, before any of the hosts is looked up - so the identifiers need not
// exist.
func TestFanOutRefusesTooManyHosts(t *testing.T) {
	h := newHarness(t)

	// The catalogue names the ceiling; the order exceeds it by one.
	var catalogue struct {
		Items []struct {
			Action      string `json:"action"`
			FanOutLimit int    `json:"fanout_limit"`
			Mutating    bool   `json:"mutating"`
		} `json:"items"`
	}
	h.get("/api/v1/actions", &catalogue)
	limit := 0
	for _, item := range catalogue.Items {
		if item.Action == "process.list" {
			limit = item.FanOutLimit
		}
		if item.Mutating && item.FanOutLimit != 0 {
			t.Errorf("the catalogue lets %s fan out", item.Action)
		}
	}
	if limit != 10 {
		t.Fatalf("the catalogue gives process.list a fan-out limit of %d, expected 10", limit)
	}

	ids := make([]string, 0, limit+1)
	for i := 0; i <= limit; i++ {
		ids = append(ids, fmt.Sprintf("00000000-0000-4000-8000-%012d", i))
	}
	var problem struct {
		Code   string `json:"code"`
		Detail string `json:"detail"`
	}
	h.do(http.MethodPost, "/api/v1/reads", map[string]any{
		"action":   "process.list",
		"payload":  map[string]any{"process_list": map[string]any{"limit": 20}},
		"selector": map[string]any{"host_ids": ids},
	}, &problem, http.StatusBadRequest)
	if problem.Code != "fanout_too_broad" {
		t.Errorf("an order of %d hosts passed: code = %q (%s)", len(ids), problem.Code, problem.Detail)
	}

	// An empty selector is a read of the whole fleet, which is never the
	// intent.
	h.do(http.MethodPost, "/api/v1/reads", map[string]any{
		"action":   "process.list",
		"payload":  map[string]any{"process_list": map[string]any{"limit": 20}},
		"selector": map[string]any{},
	}, &problem, http.StatusBadRequest)
	if problem.Code != "selector_required" {
		t.Errorf("an empty selector passed: code = %q (%s)", problem.Code, problem.Detail)
	}
}
