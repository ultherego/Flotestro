//go:build integration

package integration

// An operation that outlasts the lease of its attempt. The lease is five
// minutes (cmd/control-plane/main.

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
)

// leaseLength is the attempt lease of the panel. The tests do not read it
// from anywhere: the point is that a five-minute lease is outlasted.
const leaseLength = 5 * time.Minute

// silentUnit is a unit nothing logs under, so that a preview filtered by it
// carries no lines and the attempt has nothing but its own liveness to show.
const silentUnit = "flotestro-nothing-logs-here.service"

// attemptRow is what the tests read straight from job_attempts: the API
// view has no lease column, and the lease is what the tests are about.
type attemptRow struct {
	Number       int
	Status       string
	Replayed     bool
	LeaseExpires *time.Time
	DispatchedAt *time.Time
	FinishedAt   *time.Time
	CreatedAt    time.Time
}

func attemptRows(ctx context.Context, t *testing.T, pool *pgxpool.Pool, jobID string) []attemptRow {
	t.Helper()
	rows, err := pool.Query(ctx, `
		select attempt_number, coalesce(status, ''), replayed,
		       lease_expires_at, dispatched_at, finished_at, created_at
		  from job_attempts
		 where job_id = $1
		 order by attempt_number`, jobID)
	if err != nil {
		t.Fatalf("reading the attempts of %s: %v", jobID, err)
	}
	defer rows.Close()
	var attempts []attemptRow
	for rows.Next() {
		var row attemptRow
		if err := rows.Scan(&row.Number, &row.Status, &row.Replayed,
			&row.LeaseExpires, &row.DispatchedAt, &row.FinishedAt, &row.CreatedAt); err != nil {
			t.Fatalf("scanning an attempt of %s: %v", jobID, err)
		}
		attempts = append(attempts, row)
	}
	if err := rows.Err(); err != nil {
		t.Fatalf("reading the attempts of %s: %v", jobID, err)
	}
	return attempts
}

// followingJournal orders a preview of the given unit (empty means the whole
// journal) that keeps the agent busy for the given number of seconds, and
// waits for the hand-over.
func followingJournal(t *testing.T, h *harness, hostID, unit string, seconds int) jobView {
	t.Helper()
	journal := map[string]any{"lines": 3, "follow_seconds": seconds}
	if unit != "" {
		journal["unit"] = unit
	}
	job := h.createOperation(hostID, map[string]any{
		"action":  "journal.follow",
		"payload": map[string]any{"journal": journal},
	})
	t.Cleanup(func() { h.cancelJob(job.ID) })
	if job.RequiresApproval {
		h.approve(job.ID, job.PayloadHash)
	}
	return h.awaitJobState(job.ID, 60*time.Second, "dispatched", "running")
}

// assertStillOpen fails the test the moment the job reaches a terminal state
// before the operation on the host could have ended.
func assertStillOpen(t *testing.T, job jobView) {
	t.Helper()
	switch job.State {
	case "succeeded", "failed", "timed_out", "canceled", "expired":
		t.Fatalf("the job ended as %s (%s: %s) while the host was still on it",
			job.State, job.ResultErrorCode, job.ResultMessage)
	}
}

// TestAnOperationOutlastingItsLeaseIsNotFailed lets a silent preview run past
// the lease.
func TestAnOperationOutlastingItsLeaseIsNotFailed(t *testing.T) {
	t.Parallel()
	h := newHarness(t)
	ctx := context.Background()
	pool := h.database(ctx)
	host := h.hostByFamily("debian")

	const followSeconds = 400
	job := followingJournal(t, h, host.ID, silentUnit, followSeconds)
	dispatched := time.Now()
	t.Logf("job %s handed over to %s at %s", job.ID, host.Hostname, dispatched.Format(time.RFC3339))

	// Up to the lease nothing is expected but an open job on one attempt.
	for time.Since(dispatched) < leaseLength {
		assertStillOpen(t, h.job(job.ID))
		time.Sleep(5 * time.Second)
	}

	// After the lease: the reclaim (a housekeeping pass, every 30 s) and the
	// redelivery (a dispatch pass) open a second attempt.
	var attempts []attemptRow
	for {
		assertStillOpen(t, h.job(job.ID))
		attempts = attemptRows(ctx, t, pool, job.ID)
		if len(attempts) >= 2 {
			break
		}
		if time.Since(dispatched) > leaseLength+80*time.Second {
			t.Fatalf("the lease was not reclaimed and redelivered within 80 s of running out; attempts: %+v", attempts)
		}
		time.Sleep(5 * time.Second)
	}
	first, second := attempts[0], attempts[len(attempts)-1]
	if first.Status != "lease_expired" || first.FinishedAt == nil {
		t.Errorf("the first attempt was not given up by the scheduler: status=%q finished=%v", first.Status, first.FinishedAt)
	}
	if second.Status != "" || second.FinishedAt != nil {
		t.Errorf("the redelivered attempt is already closed: status=%q finished=%v", second.Status, second.FinishedAt)
	}

	// Minute six: the redelivery reached the agent, and the job is neither failed
	// nor on its way to a second reclaim - the in-progress answer renewed the
	// lease of the redelivered attempt, which is still alive.
	for time.Since(dispatched) < 6*time.Minute {
		assertStillOpen(t, h.job(job.ID))
		time.Sleep(5 * time.Second)
	}
	atSix := h.job(job.ID)
	assertStillOpen(t, atSix)
	if atSix.State != "dispatched" && atSix.State != "running" {
		t.Errorf("at minute six the job is %s, expected it handed over", atSix.State)
	}
	attempts = attemptRows(ctx, t, pool, job.ID)
	second = attempts[len(attempts)-1]
	if second.FinishedAt != nil || second.Status != "" {
		t.Errorf("at minute six the redelivered attempt is closed: status=%q", second.Status)
	}
	if second.LeaseExpires == nil || !second.LeaseExpires.After(time.Now()) {
		t.Errorf("at minute six the redelivered attempt holds no live lease: %v", second.LeaseExpires)
	}

	// The preview ends at 400 s.
	final := h.awaitTerminal(job.ID, followSeconds*time.Second+2*time.Minute-time.Since(dispatched))
	if final.State != "succeeded" {
		t.Fatalf("the job ended as %s (%s: %s)", final.State, final.ResultErrorCode, final.ResultMessage)
	}
	if !strings.Contains(final.ResultMessage, "the preview ended") {
		t.Errorf("the result is not the preview summary: %q", final.ResultMessage)
	}
	// The copy of the result for the redelivered attempt follows the
	// original on the same stream; a moment for it to land.
	time.Sleep(3 * time.Second)
	// How many leases an operation outlasts depends on how loaded the fleet is,
	// so the count is not the property: the work is done once, and every
	// redelivery of it is closed by the result rather than failed.
	attempts = attemptRows(ctx, t, pool, job.ID)
	if len(attempts) < 2 {
		t.Fatalf("expected the operation to outlast its lease, got %d attempt(s): %+v",
			len(attempts), attempts)
	}
	first = attempts[0]
	if first.Status != "succeeded" || first.Replayed || first.FinishedAt == nil {
		t.Errorf("the first attempt did the work and has to carry its result: status=%q replayed=%v", first.Status, first.Replayed)
	}
	for _, attempt := range attempts[1:] {
		switch attempt.Status {
		case "superseded_by_result", "lease_expired":
		default:
			t.Errorf("a redelivered attempt ended as %q; the result of the first closes it",
				attempt.Status)
		}
		if attempt.FinishedAt == nil || attempt.LeaseExpires != nil {
			t.Errorf("the redelivered attempt %d still holds a lease: finished=%v lease=%v",
				attempt.Number, attempt.FinishedAt, attempt.LeaseExpires)
		}
	}
	if last := attempts[len(attempts)-1]; last.Status != "superseded_by_result" {
		t.Errorf("the last attempt ended as %q, not closed by the result", last.Status)
	}
	views := h.attempts(job.ID)
	if len(views) != len(attempts) || views[len(views)-1].Status != "superseded_by_result" {
		t.Errorf("the API shows the attempts as %+v", views)
	}
}

// TestAReportingAttemptKeepsItsLease is the other half: a preview of the whole
// journal on a host that keeps logging - the test restarts a unit on it every
// half minute - sends lines the whole time, and every line is a sign of life.
func TestAReportingAttemptKeepsItsLease(t *testing.T) {
	t.Parallel()
	h := newHarness(t)
	ctx := context.Background()
	pool := h.database(ctx)
	host := h.hostByFamily("rhel")

	const followSeconds = 400
	job := followingJournal(t, h, host.ID, "", followSeconds)
	dispatched := time.Now()
	t.Logf("job %s handed over to %s at %s", job.ID, host.Hostname, dispatched.Format(time.RFC3339))

	// The lines: systemd logs the stop and the start of the unit, and the agent
	// logs the task, and the preview forwards both.
	for time.Since(dispatched) < 6*time.Minute {
		assertStillOpen(t, h.job(job.ID))
		restart, _ := h.runOperation(host.ID, map[string]any{
			"action":  "unit.restart",
			"payload": unitPayload("crond.service"),
		}, 60*time.Second)
		if restart.State != "succeeded" {
			t.Fatalf("the restart that feeds the journal ended as %s (%s)", restart.State, restart.ResultErrorCode)
		}
		time.Sleep(30 * time.Second)
	}

	// Minute six: one attempt, still open, its lease later than the one the
	// delivery gave it by more than a housekeeping pass - the renewals moved it,
	// and the scheduler had nothing to reclaim.
	atSix := h.job(job.ID)
	assertStillOpen(t, atSix)
	attempts := attemptRows(ctx, t, pool, job.ID)
	if len(attempts) != 1 {
		t.Fatalf("the attempt was reclaimed although it kept reporting: %+v", attempts)
	}
	only := attempts[0]
	if only.FinishedAt != nil || only.Status != "" || only.DispatchedAt == nil {
		t.Fatalf("the attempt is not open and handed over: %+v", only)
	}
	if only.LeaseExpires == nil || !only.LeaseExpires.After(only.DispatchedAt.Add(leaseLength+30*time.Second)) {
		t.Errorf("the lease was not renewed by the reports: expires %v, handed over %v", only.LeaseExpires, only.DispatchedAt)
	}
	if !only.LeaseExpires.After(time.Now()) {
		t.Errorf("at minute six the attempt holds no live lease: %v", only.LeaseExpires)
	}

	final := h.awaitTerminal(job.ID, followSeconds*time.Second+2*time.Minute-time.Since(dispatched))
	if final.State != "succeeded" {
		t.Fatalf("the job ended as %s (%s: %s)", final.State, final.ResultErrorCode, final.ResultMessage)
	}
	if !strings.Contains(final.ResultMessage, "the preview ended") {
		t.Errorf("the result is not the preview summary: %q", final.ResultMessage)
	}
	attempts = attemptRows(ctx, t, pool, job.ID)
	if len(attempts) != 1 || attempts[0].Status != "succeeded" || attempts[0].Replayed {
		t.Errorf("the job did not end on the attempt it started on: %+v", attempts)
	}
}
