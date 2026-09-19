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

// TestJobWaitsForTheMutationBudget guards the rule that a budget is admission
// for every change, not only for a campaign: a restart ordered by hand asks
// for the fleet's mutation token like a campaign target does, says which
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

	// The budget screen says who holds the token and who waits for it while it is
	// held: the stand-in as a holder the panel cannot place, two jobs in the
	// queue.
	held := h.budgetState(key)
	if held.WaitingJobs != 2 {
		t.Errorf("the budget counts %d waiting jobs while two stand in the queue", held.WaitingJobs)
	}
	if !holds(held, holder) {
		t.Errorf("the budget does not list the held token among its holders: %+v", held.Holders)
	}
	if held.ByClass["unknown"] < 1 {
		t.Errorf("a stand-in's token is not counted as unknown: %v", held.ByClass)
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

	// The token goes back. One token, two jobs: the second must not start before
	// the first has finished.
	if _, err := pool.Exec(ctx, `delete from budget_leases where owner = $1`, holder); err != nil {
		t.Fatalf("giving the token back: %v", err)
	}
	// While the first job holds the token, the budget names it as the holder by
	// its job id and still counts the second in the queue.
	shown := false
	deadline := time.Now().Add(3 * time.Minute)
	for time.Now().Before(deadline) {
		later := h.waitingJob(two.ID)
		earlier := h.waitingJob(one.ID)
		if terminal(earlier.State) {
			break
		}
		if !shown && earlier.State != "queued" && later.State == "queued" {
			running := h.budgetState(key)
			if !holds(running, "job:"+one.ID) {
				t.Errorf("the budget does not list the running job among its holders: %+v", running.Holders)
			}
			if running.WaitingJobs != 1 {
				t.Errorf("the budget counts %d waiting jobs while one runs and one waits", running.WaitingJobs)
			}
			if running.ByClass["interactive"] < 1 {
				t.Errorf("an operator's job is not counted as interactive: %v", running.ByClass)
			}
			shown = true
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
	if after := h.budgetState(key); after.WaitingJobs != 0 {
		t.Errorf("the budget still counts %d waiting jobs after the run", after.WaitingJobs)
	}
}

// budgetStateView is the part of a budget row the tests read: the numbers
// and who is behind them.
type budgetStateView struct {
	Key            string         `json:"key"`
	Capacity       int            `json:"capacity"`
	Used           int            `json:"used"`
	WaitingJobs    int            `json:"waiting_jobs"`
	WaitingTargets int            `json:"waiting_targets"`
	ByClass        map[string]int `json:"by_class"`
	Holders        []struct {
		Owner    string `json:"owner"`
		Claimant string `json:"claimant"`
		Class    string `json:"class"`
		Tokens   int    `json:"tokens"`
	} `json:"holders"`
}

// budgetState reads one row of the budget screen. A key the screen does
// not show fails the test: the test configured it, so it has to be there.
func (h *harness) budgetState(key string) budgetStateView {
	h.t.Helper()
	var view struct {
		Items []budgetStateView `json:"items"`
	}
	h.get("/api/v1/budgets", &view)
	for _, budget := range view.Items {
		if budget.Key == key {
			return budget
		}
	}
	h.t.Fatalf("the budget screen shows no row for %s", key)
	return budgetStateView{}
}

// holds says whether the row lists the owner among its holders.
func holds(budget budgetStateView, owner string) bool {
	for _, holder := range budget.Holders {
		if holder.Owner == owner {
			return true
		}
	}
	return false
}

func terminal(state string) bool {
	switch state {
	case "succeeded", "failed", "timed_out", "canceled", "expired":
		return true
	}
	return false
}
