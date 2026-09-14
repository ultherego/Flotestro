//go:build integration

package integration

// The acknowledgement of a task. Until the agent answered a delivery, the
// panel knew a delivered task only by its result: an attempt was silent
// between the hand-over and the end, a host queued behind a busy lock
// looked like a lost one, and an envelope sent into a dead stream waited
// out the whole five-minute lease before it was sent again.
//
// What the product promises now, as read from the code:
//
//   - The agent answers a delivery in stages of TaskProgress (agent.proto):
//     "accepted" before it queues for the resources of the host, "started"
//     once it holds them and the operation is starting, and "awaiting_lock"
//     with the blocker while it waits (internal/agent/tasks.go run).
//   - The panel stamps accepted_at on the attempt and moves the job from
//     dispatched to running on "started", with started_at
//     (internal/jobs/store.go AcceptAttempt, MarkRunning). A wait for a
//     lock is the job's wait_reason, awaiting_lock:<blocker>, until the
//     start clears it (SetLockWait).
//   - The lease of a delivered attempt is the short dispatch lease
//     (internal/jobs DispatchLease, a minute) until the acceptance moves
//     it out to the execution lease.

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
)

// ackRow is what the tests read straight from the tables: the API view of
// an attempt carries the times, but the wait reason of a job and the lease
// are what the tests are about, and both are read from the same place.
type ackRow struct {
	State        string
	WaitReason   string
	LeaseExpires *time.Time
	DispatchedAt *time.Time
	AcceptedAt   *time.Time
	StartedAt    *time.Time
}

// latestAttempt reads the job together with its newest attempt.
func latestAttempt(ctx context.Context, t *testing.T, pool *pgxpool.Pool, jobID string) ackRow {
	t.Helper()
	var row ackRow
	if err := pool.QueryRow(ctx, `
		select j.state, j.wait_reason,
		       a.lease_expires_at, a.dispatched_at, a.accepted_at, a.started_at
		  from jobs j
		  left join job_attempts a on a.job_id = j.id
		 where j.id = $1
		 order by a.attempt_number desc nulls last
		 limit 1`, jobID).Scan(&row.State, &row.WaitReason,
		&row.LeaseExpires, &row.DispatchedAt, &row.AcceptedAt, &row.StartedAt); err != nil {
		t.Fatalf("reading the job %s with its attempt: %v", jobID, err)
	}
	return row
}

// awaitRow polls the job until the condition holds or the bound passes.
func awaitRow(ctx context.Context, t *testing.T, pool *pgxpool.Pool, jobID string,
	bound time.Duration, holds func(ackRow) bool) ackRow {
	t.Helper()
	deadline := time.Now().Add(bound)
	var row ackRow
	for {
		row = latestAttempt(ctx, t, pool, jobID)
		if holds(row) {
			return row
		}
		switch row.State {
		case "succeeded", "failed", "timed_out", "canceled", "expired":
			t.Fatalf("the job %s ended as %s (wait_reason=%q) before the condition held", jobID, row.State, row.WaitReason)
		}
		if time.Now().After(deadline) {
			t.Fatalf("the job %s did not meet the condition within %s: %+v", jobID, bound, row)
		}
		time.Sleep(500 * time.Millisecond)
	}
}

// TestADeliveredTaskIsAcknowledgedAndRunsWithinSeconds: a preview of the
// journal is accepted and started by the agent within seconds of the
// hand-over, so the job shows running - not dispatched - while the host
// works, with the acceptance and the start on the attempt, and the lease
// out at the execution length rather than the dispatch length.
func TestADeliveredTaskIsAcknowledgedAndRunsWithinSeconds(t *testing.T) {
	h := newHarness(t)
	ctx := context.Background()
	pool := h.database(ctx)
	host := h.hostByFamily("debian")

	const followSeconds = 20
	job := followingJournal(t, h, host.ID, silentUnit, followSeconds)
	handedOver := time.Now()

	running := awaitRow(ctx, t, pool, job.ID, 10*time.Second, func(row ackRow) bool {
		return row.State == "running"
	})
	t.Logf("job %s running %s after the hand-over", job.ID, time.Since(handedOver).Round(time.Millisecond))
	if running.AcceptedAt == nil {
		t.Error("the running job has no acceptance on its attempt")
	}
	if running.StartedAt == nil {
		t.Error("the running job has no start on its attempt")
	}
	if running.AcceptedAt != nil && running.StartedAt != nil && running.StartedAt.Before(*running.AcceptedAt) {
		t.Errorf("the start %s precedes the acceptance %s", running.StartedAt, running.AcceptedAt)
	}
	if running.DispatchedAt != nil && running.AcceptedAt != nil &&
		running.AcceptedAt.Sub(*running.DispatchedAt) > 10*time.Second {
		t.Errorf("the acceptance took %s after the hand-over", running.AcceptedAt.Sub(*running.DispatchedAt))
	}
	if running.WaitReason != "" {
		t.Errorf("a read that took no resource waits on %q", running.WaitReason)
	}
	// The acceptance moved the lease out past the dispatch lease: a minute
	// from the hand-over would be the short one, five minutes the long one.
	if running.LeaseExpires == nil || running.LeaseExpires.Sub(*running.DispatchedAt) < 2*time.Minute {
		t.Errorf("the lease of an accepted attempt is still the dispatch lease: expires %v, dispatched %v",
			running.LeaseExpires, running.DispatchedAt)
	}

	final := h.awaitTerminal(job.ID, followSeconds*time.Second+time.Minute)
	if final.State != "succeeded" {
		t.Fatalf("the job ended as %s (%s: %s)", final.State, final.ResultErrorCode, final.ResultMessage)
	}
	views := h.attempts(job.ID)
	if len(views) != 1 {
		t.Errorf("a task acknowledged within its dispatch lease opened %d attempts, expected one", len(views))
	}
	text := h.text("/metrics")
	if !strings.Contains(text, `flotestro_task_ack_seconds_count{action="journal.follow"}`) {
		t.Errorf("the metrics do not count the acknowledgement:\n%s", extract(text, "flotestro_task_ack_seconds"))
	}
}

// TestATaskWaitingForALockSaysSoAndThenRuns: a run of a schedule entry
// holds the units lock of the host for as long as its command runs, and a
// unit restart ordered meanwhile needs the same lock. The restart is
// accepted, waits, and the job says on what - awaiting_lock and the
// blocker - until the run ends; then it starts, the reason is gone, and
// it succeeds on the attempt it was delivered on.
func TestATaskWaitingForALockSaysSoAndThenRuns(t *testing.T) {
	h := newHarness(t)
	ctx := context.Background()
	pool := h.database(ctx)
	host := h.hostByFamily("debian")
	const id = "task-ack-lock-test"

	t.Cleanup(func() {
		h.createOperation(host.ID, map[string]any{
			"action": "schedule.remove", "reason": scheduleReason,
			"payload": map[string]any{"schedule": map[string]any{"id": id}},
		})
	})
	entry, attempts := h.runOperation(host.ID, map[string]any{
		"action": "schedule.ensure", "reason": scheduleReason,
		"payload": map[string]any{"schedule": map[string]any{
			"id":         id,
			"expression": "0 5 * * *",
			"command":    []string{"/bin/sleep", "25"},
			"user":       "root",
			"enabled":    false,
		}},
	}, 90*time.Second)
	if entry.State != "succeeded" {
		t.Fatalf("creating the entry: state = %s, %s", entry.State, lastMessage(attempts))
	}

	// The holder: the run waits for its command, so the units lock is held
	// for the whole sleep.
	holder := h.createOperation(host.ID, map[string]any{
		"action": "schedule.run_now", "reason": scheduleReason,
		"payload": map[string]any{"schedule": map[string]any{"id": id}},
	})
	t.Cleanup(func() { h.cancelJob(holder.ID) })
	if holder.RequiresApproval {
		h.approve(holder.ID, holder.PayloadHash)
	}
	awaitRow(ctx, t, pool, holder.ID, 30*time.Second, func(row ackRow) bool { return row.State == "running" })

	waiter := h.createOperation(host.ID, map[string]any{
		"action":  "unit.restart",
		"payload": unitPayload("cron.service"),
	})
	t.Cleanup(func() { h.cancelJob(waiter.ID) })
	if waiter.RequiresApproval {
		h.approve(waiter.ID, waiter.PayloadHash)
	}

	waiting := awaitRow(ctx, t, pool, waiter.ID, 30*time.Second, func(row ackRow) bool {
		return strings.HasPrefix(row.WaitReason, "awaiting_lock:")
	})
	t.Logf("the restart waits: %q", waiting.WaitReason)
	if waiting.State != "dispatched" {
		t.Errorf("a task waiting for a lock is %s, expected dispatched", waiting.State)
	}
	if waiting.AcceptedAt == nil {
		t.Error("a task waiting for a lock was not accepted first")
	}
	if waiting.StartedAt != nil {
		t.Error("a task waiting for a lock reports a start")
	}
	if !strings.Contains(waiting.WaitReason, "units held by task "+holderAttempt(ctx, t, pool, holder.ID)) ||
		!strings.Contains(waiting.WaitReason, "schedule.run_now") {
		t.Errorf("the reason does not name the holder: %q", waiting.WaitReason)
	}

	// The run ends with the sleep; the restart takes the lock, starts, and
	// its reason goes away with the start.
	started := awaitRow(ctx, t, pool, waiter.ID, 60*time.Second, func(row ackRow) bool {
		return row.State == "running" || row.State == "succeeded"
	})
	if started.WaitReason != "" {
		t.Errorf("the reason survived the start: %q", started.WaitReason)
	}
	if started.StartedAt == nil {
		t.Error("the started task has no start on its attempt")
	}
	final := h.awaitTerminal(waiter.ID, 60*time.Second)
	if final.State != "succeeded" {
		t.Fatalf("the restart ended as %s (%s: %s)", final.State, final.ResultErrorCode, final.ResultMessage)
	}
	if views := h.attempts(waiter.ID); len(views) != 1 {
		t.Errorf("the waiting task opened %d attempts, expected one: its reports kept the lease alive", len(views))
	}
	if run := h.awaitTerminal(holder.ID, 60*time.Second); run.State != "succeeded" {
		t.Errorf("the run that held the lock ended as %s (%s)", run.State, run.ResultErrorCode)
	}

	text := h.text("/metrics")
	if !strings.Contains(text, `flotestro_resource_lock_wait_seconds_count{action="unit.restart"}`) {
		t.Errorf("the metrics do not count the wait for the lock:\n%s", extract(text, "flotestro_resource_lock_wait_seconds"))
	}
}

// holderAttempt is the attempt identifier of a job as the agent knows it:
// the blocker names the task by the attempt, since that is what the
// envelope carries.
func holderAttempt(ctx context.Context, t *testing.T, pool *pgxpool.Pool, jobID string) string {
	t.Helper()
	var attemptID string
	if err := pool.QueryRow(ctx, `
		select id from job_attempts where job_id = $1 order by attempt_number desc limit 1`,
		jobID).Scan(&attemptID); err != nil {
		t.Fatalf("reading the attempt of %s: %v", jobID, err)
	}
	return attemptID
}
