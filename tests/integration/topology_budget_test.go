//go:build integration

package integration

import (
	"context"
	"encoding/json"
	"net/http"
	"testing"
	"time"
)

// hostTopologyView is the part of a host the topology test reads: where
// the operator placed it.
type hostTopologyView struct {
	ID            string `json:"id"`
	FailureDomain string `json:"failure_domain"`
}

// placeInFailureDomain records the failure domain of a host through the API
// and takes it away again after the test: a lab host left in a rack would
// carry the rack's budget into every later run.
func (h *harness) placeInFailureDomain(hostID, domain string) hostTopologyView {
	h.t.Helper()
	response, body := h.request(http.MethodPut, "/api/v1/hosts/"+hostID+"/failure-domain",
		map[string]any{"failure_domain": domain, "reason": "integration test of the topology budgets"}, nil)
	if response.StatusCode != http.StatusOK {
		h.t.Fatalf("placing host %s in %q answered %d; body: %s", hostID, domain, response.StatusCode, body)
	}
	var host hostTopologyView
	if err := json.Unmarshal(body, &host); err != nil {
		h.t.Fatalf("the host does not decode: %v", err)
	}
	h.t.Cleanup(func() {
		h.do(http.MethodPut, "/api/v1/hosts/"+hostID+"/failure-domain",
			map[string]any{"failure_domain": "", "reason": "after the test"}, nil, 0)
	})
	return host
}

// TestFailureDomainBudgetHoldsTheSecondChange guards the topology budget: two
// hosts in one rack share the rack's token, so the second change waits.
func TestFailureDomainBudgetHoldsTheSecondChange(t *testing.T) {
	h := newHarness(t)
	ctx := context.Background()
	pool := h.database(ctx)

	online := make([]hostView, 0, 2)
	for _, host := range h.hosts() {
		if host.ConnectionState == "online" && host.OSFamily == "debian" {
			online = append(online, host)
		}
	}
	if len(online) < 2 {
		t.Skip("the test fleet has fewer than two connected hosts of the debian family")
	}
	first, second := online[0], online[1]

	// The placement is a fact of the host from the moment it is written,
	// and the host says so.
	const domain = "rack-1"
	for _, host := range []hostView{first, second} {
		placed := h.placeInFailureDomain(host.ID, domain)
		if placed.FailureDomain != domain {
			t.Fatalf("host %s shows failure domain %q after the write", host.ID, placed.FailureDomain)
		}
	}
	var read hostTopologyView
	h.get("/api/v1/hosts/"+first.ID, &read)
	if read.FailureDomain != domain {
		t.Fatalf("the host read shows failure domain %q", read.FailureDomain)
	}

	// The exact key is written so the proof does not lean on the seeded
	// default; the row goes away afterwards and the default applies again.
	const key = "domain:" + domain + ":units"
	h.do(http.MethodPut, "/api/v1/budgets/"+key,
		map[string]any{"capacity": 1, "note": "integration test of the topology budgets"}, nil, http.StatusOK)
	t.Cleanup(func() {
		_, _ = pool.Exec(ctx, `delete from budget_limits where key = $1`, key)
	})

	// The stand-in for a change under way in the rack: one token, and the
	// test holds it.
	const holder = "integration-test:topology-budget"
	if _, err := pool.Exec(ctx, `
		insert into budget_leases (key, owner, claimant, weight, lease_until)
		values ($1, $2, 'integration-test', 1, now() + interval '3 minutes')
		on conflict (key, owner) do update set lease_until = excluded.lease_until`,
		key, holder); err != nil {
		t.Fatalf("holding the token: %v", err)
	}
	t.Cleanup(func() {
		_, _ = pool.Exec(ctx, `delete from budget_leases where owner = $1`, holder)
	})

	order := func(host hostView) jobView {
		job := h.createOperation(host.ID, map[string]any{
			"action": "unit.restart", "payload": unitPayload("cron.service"),
		})
		if job.RequiresApproval {
			job = h.approve(job.ID, job.PayloadHash)
		}
		return job
	}
	one := order(first)
	two := order(second)

	// Both stand in the queue and both name the rack's budget: the site
	// has room for ten unit changes, the rack for one.
	want := "awaiting_budget:" + key
	for _, job := range []jobView{one, two} {
		deadline := time.Now().Add(30 * time.Second)
		var seen waitingJobView
		for time.Now().Before(deadline) {
			seen = h.waitingJob(job.ID)
			if seen.WaitReason == want {
				break
			}
			time.Sleep(200 * time.Millisecond)
		}
		if seen.State != "queued" || seen.WaitReason != want {
			t.Fatalf("job %s in a held rack: state %s, wait_reason %q; want queued with %q",
				job.ID, seen.State, seen.WaitReason, want)
		}
	}
	if held := h.budgetState(key); held.WaitingJobs != 2 {
		t.Errorf("the rack's budget counts %d waiting jobs while two stand in the queue", held.WaitingJobs)
	}

	// The token goes back. One token, two jobs: the second must not start before
	// the first has finished, and while one runs the other still names the rack.
	if _, err := pool.Exec(ctx, `delete from budget_leases where owner = $1`, holder); err != nil {
		t.Fatalf("giving the token back: %v", err)
	}
	deadline := time.Now().Add(3 * time.Minute)
	for time.Now().Before(deadline) {
		later := h.waitingJob(two.ID)
		earlier := h.waitingJob(one.ID)
		if terminal(earlier.State) {
			break
		}
		if later.State != "queued" {
			t.Fatalf("the second job is %s while the first is still %s: one token admitted two changes in the rack",
				later.State, earlier.State)
		}
		if later.WaitReason != want {
			t.Fatalf("the second job waits without naming the rack: %q", later.WaitReason)
		}
		time.Sleep(200 * time.Millisecond)
	}

	for _, job := range []jobView{one, two} {
		final := h.awaitTerminal(job.ID, 2*time.Minute)
		if final.State != "succeeded" {
			t.Errorf("job %s ended as %s (%s)", job.ID, final.State, final.ResultErrorCode)
		}
	}

	var windows []window
	for _, job := range []jobView{one, two} {
		for _, attempt := range h.timedAttempts(job.ID) {
			if attempt.DispatchedAt != nil && attempt.FinishedAt != nil {
				windows = append(windows, window{from: *attempt.DispatchedAt, to: *attempt.FinishedAt})
			}
		}
	}
	if len(windows) != 2 {
		t.Fatalf("the two jobs left %d attempts with times", len(windows))
	}
	if overlap(windows) {
		t.Errorf("two changes went side by side in one rack despite a budget of 1: %+v", windows)
	}

	// A host taken out of the rack asks for no rack at all: the cleanup
	// restores the fleet, and this is what the restore means.
	h.do(http.MethodPut, "/api/v1/hosts/"+first.ID+"/failure-domain",
		map[string]any{"failure_domain": "", "reason": "out of the rack"}, nil, http.StatusOK)
	// A fresh variable: the cleared field is absent from the answer, and
	// a decode into the earlier one would keep the rack in it.
	var cleared struct {
		FailureDomain string `json:"failure_domain"`
	}
	h.get("/api/v1/hosts/"+first.ID, &cleared)
	if cleared.FailureDomain != "" {
		t.Errorf("the host still shows failure domain %q after it was cleared", cleared.FailureDomain)
	}
}
