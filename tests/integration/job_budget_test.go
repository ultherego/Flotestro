//go:build integration

package integration

import (
	"context"
	"testing"
	"time"
)

// waitingJobView is the part of a job the budget test reads: whether it
// still stands in the queue and what it says it waits for.
type waitingJobView struct {
	ID         string `json:"id"`
	State      string `json:"state"`
	WaitReason string `json:"wait_reason"`
}

func (h *harness) waitingJob(jobID string) waitingJobView {
	h.t.Helper()
	var job waitingJobView
	h.get("/api/v1/jobs/"+jobID, &job)
	return job
}

// TestJobWaitsForTheMutationBudget guards the rule that a budget is
// admission for every change, not only for a campaign: a restart ordered
// by hand asks for the fleet's mutation token like a campaign target does,
// says which budget holds it while it waits, and starts once the token is
// free - while a state read walks past the mutation budget untouched.
//
// The token is held first by the test itself, through the table the
// budgets live in: the proof is about the wait, and a wait that depends on
// winning a race against a restart that takes a second would prove
// nothing on a fast fleet.
func TestJobWaitsForTheMutationBudget(t *testing.T) {
	h := newHarness(t)
	ctx := context.Background()
	pool := h.database(ctx)

	// Two connected hosts of one family: the proof concerns the budget, not
	// the names of units on different distributions.
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

	const key = "global:mutations"
	const defaultCapacity = 50
	h.setBudget(key, 1, defaultCapacity)

	// The stand-in for a change under way somewhere else in the fleet: one
	// token, and the test holds it.
	const holder = "integration-test:job-budget"
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

	// Both stand in the queue and both say why. The reason appears on the
	// scheduler's next pass, not at once.
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
			t.Fatalf("job %s on a held budget: state %s, wait_reason %q; want queued with %q",
				job.ID, seen.State, seen.WaitReason, want)
		}
	}

	// A read is not a mutation: the held token does not hold it.
	read, attempts := h.runOperation(first.ID, map[string]any{
		"action":  "unit.status",
		"payload": map[string]any{"unit_status": map[string]any{"units": []string{"cron.service"}}},
	}, 90*time.Second)
	if read.State != "succeeded" {
		t.Fatalf("a read was held with the mutations: state %s, %s", read.State, lastMessage(attempts))
	}
	for _, job := range []jobView{one, two} {
		if seen := h.waitingJob(job.ID); seen.State != "queued" {
			t.Fatalf("job %s moved while the token was held: state %s", job.ID, seen.State)
		}
	}

	// The token goes back. One token, two jobs: the second must not start
	// before the first has finished. The second job is read before the
	// first on purpose - the first finishing between the two reads then
	// shows as a finished first, never as a second that jumped the queue.
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
			t.Fatalf("the second job is %s while the first is still %s: one token admitted two changes",
				later.State, earlier.State)
		}
		if later.WaitReason != want {
			t.Fatalf("the second job waits without a reason: %q", later.WaitReason)
		}
		time.Sleep(200 * time.Millisecond)
	}

	for _, job := range []jobView{one, two} {
		final := h.awaitTerminal(job.ID, 2*time.Minute)
		if final.State != "succeeded" {
			t.Errorf("job %s ended as %s (%s)", job.ID, final.State, final.ResultErrorCode)
		}
		// A job that ran no longer says it waits.
		if seen := h.waitingJob(job.ID); seen.WaitReason != "" {
			t.Errorf("job %s finished and still says %q", job.ID, seen.WaitReason)
		}
	}

	// The second proof is in the times: with one token, no two attempts
	// may share a moment.
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
		t.Errorf("two changes went side by side despite a budget of 1: %+v", windows)
	}

	// The budget screen counts the jobs it holds while it holds them; after
	// the run it holds none.
	var view struct {
		Items []struct {
			Key         string `json:"key"`
			WaitingJobs int    `json:"waiting_jobs"`
		} `json:"items"`
	}
	h.get("/api/v1/budgets", &view)
	for _, budget := range view.Items {
		if budget.Key == key && budget.WaitingJobs != 0 {
			t.Errorf("the budget still counts %d waiting jobs after the run", budget.WaitingJobs)
		}
	}
}

func terminal(state string) bool {
	switch state {
	case "succeeded", "failed", "timed_out", "canceled", "expired":
		return true
	}
	return false
}
