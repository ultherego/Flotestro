//go:build integration

package integration

import (
	"context"
	"errors"
	"sort"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/ultherego/flotestro/internal/jobs"
)

// The session fence in one scene: two sessions claim the same host one after
// the other, and only the later claim may settle the host's job.
func TestOnlyNewestSessionMayCommit(t *testing.T) {
	h := newHarness(t)
	ctx := context.Background()
	pool := h.database(ctx)
	store := jobs.NewStore(pool)
	host := h.enrollSyntheticHost(t)

	jobID := stageDispatchedJob(t, h, host.ID)
	attemptID := lastAttemptID(t, h, jobID)

	sessionA, sessionB := uuid.NewString(), uuid.NewString()
	instanceA, instanceB := uuid.NewString(), uuid.NewString()
	tokenA, err := store.ClaimSession(ctx, host.ID, sessionA, instanceA, jobs.OwnerLeaseTTL)
	if err != nil {
		t.Fatalf("the first claim: %v", err)
	}
	tokenB, err := store.ClaimSession(ctx, host.ID, sessionB, instanceB, jobs.OwnerLeaseTTL)
	if err != nil {
		t.Fatalf("the second claim: %v", err)
	}
	if tokenB <= tokenA {
		t.Fatalf("the later claim got token %d, the earlier %d; the token must grow", tokenB, tokenA)
	}

	// The superseded session cannot renew, either: the row is somebody
	// else's now, and it learns so with the same code.
	if err := store.RenewOwnership(ctx, host.ID, sessionA, instanceA, tokenA, jobs.OwnerLeaseTTL); !errors.Is(err, jobs.ErrStaleFence) {
		t.Fatalf("the superseded session renewed its ownership: %v", err)
	}
	if err := store.RenewOwnership(ctx, host.ID, sessionB, instanceB, tokenB, jobs.OwnerLeaseTTL); err != nil {
		t.Fatalf("the owner did not renew: %v", err)
	}

	result := jobs.Result{Status: "succeeded", Message: "settled by the session fence test"}
	accepted, err := store.RecordResult(ctx, jobID, attemptID, result, jobs.StateSucceeded,
		jobs.Fence{SessionID: sessionA, Token: tokenA})
	if !errors.Is(err, jobs.ErrStaleFence) {
		t.Fatalf("the result under the superseded token was not refused: accepted=%v err=%v", accepted, err)
	}
	if state := jobStateOf(t, h, jobID); state != "dispatched" {
		t.Fatalf("the refused result moved the job to %s", state)
	}

	accepted, err = store.RecordResult(ctx, jobID, attemptID, result, jobs.StateSucceeded,
		jobs.Fence{SessionID: sessionB, Token: tokenB})
	if err != nil || !accepted {
		t.Fatalf("the owner's result was not applied: accepted=%v err=%v", accepted, err)
	}
	if state := jobStateOf(t, h, jobID); state != "succeeded" {
		t.Fatalf("the job is %s after the owner's result", state)
	}

	// Exactly one terminal transition: a second result from the owner is answered
	// by the state of the job, not by the fence, and changes nothing; the
	// superseded session gets the same refusal as before.
	accepted, err = store.RecordResult(ctx, jobID, attemptID, jobs.Result{Status: "failed"},
		jobs.StateFailed, jobs.Fence{SessionID: sessionB, Token: tokenB})
	if err != nil || accepted {
		t.Fatalf("a second result settled the job again: accepted=%v err=%v", accepted, err)
	}
	if _, err := store.RecordResult(ctx, jobID, attemptID, jobs.Result{Status: "failed"},
		jobs.StateFailed, jobs.Fence{SessionID: sessionA, Token: tokenA}); err != nil {
		// A settled job answers by its state before the fence is asked: the trail
		// keeps a late result as not applied rather than as a refused write.
		t.Fatalf("a late result on a settled job was answered by the fence, not by the state: %v", err)
	}
	var status, message string
	var finished *time.Time
	if err := pool.QueryRow(ctx, `
		select coalesce(status, ''), coalesce(message, ''), finished_at
		  from job_attempts where id = $1::uuid`, attemptID).Scan(&status, &message, &finished); err != nil {
		t.Fatalf("reading the attempt: %v", err)
	}
	if status != "succeeded" || message != result.Message || finished == nil {
		t.Fatalf("the attempt does not carry the owner's result alone: status=%q message=%q finished=%v",
			status, message, finished)
	}

	// A released owner owns nothing, keeps its token, and the superseded
	// session releases nothing.
	if err := store.ReleaseOwnership(ctx, host.ID, sessionA, tokenA); !errors.Is(err, jobs.ErrStaleFence) {
		t.Fatalf("the superseded session released the host: %v", err)
	}
	if err := store.ReleaseOwnership(ctx, host.ID, sessionB, tokenB); err != nil {
		t.Fatalf("the owner did not release the host: %v", err)
	}
	owner, err := store.OwnerOf(ctx, host.ID)
	if err != nil {
		t.Fatalf("reading the owner: %v", err)
	}
	if owner.Live(time.Now()) || owner.Token != tokenB {
		t.Fatalf("after the release the row reads %+v", owner)
	}
}

// A hundred sessions claim one host at the same moment and every one of them
// gets a token of its own: the tokens are unique, contiguous, and a claim made
// after them all gets a higher one.
func TestAHundredClaimsGiveRisingTokens(t *testing.T) {
	h := newHarness(t)
	ctx := context.Background()
	store := jobs.NewStore(h.database(ctx))
	host := h.enrollSyntheticHost(t)

	const claims = 100
	tokens := make([]uint64, claims)
	failures := make([]error, claims)
	var wg sync.WaitGroup
	for i := 0; i < claims; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			tokens[i], failures[i] = store.ClaimSession(ctx, host.ID, uuid.NewString(), uuid.NewString(),
				jobs.OwnerLeaseTTL)
		}(i)
	}
	wg.Wait()
	for i, err := range failures {
		if err != nil {
			t.Fatalf("claim %d failed: %v", i, err)
		}
	}
	sort.Slice(tokens, func(i, j int) bool { return tokens[i] < tokens[j] })
	for i := 1; i < claims; i++ {
		if tokens[i] != tokens[i-1]+1 {
			t.Fatalf("the tokens are not unique and contiguous around %d: %v", i, tokens)
		}
	}
	if tokens[0] != 1 {
		t.Fatalf("the first claim of a fresh host got token %d, expected 1", tokens[0])
	}
	later, err := store.ClaimSession(ctx, host.ID, uuid.NewString(), uuid.NewString(), jobs.OwnerLeaseTTL)
	if err != nil {
		t.Fatalf("the claim after the storm: %v", err)
	}
	if later != tokens[claims-1]+1 {
		t.Fatalf("the claim after the storm got token %d, expected %d", later, tokens[claims-1]+1)
	}
}

// A host with a lease that ran out has no owner for the scheduler, and the
// sweep forgets the session while the token stays: a write under the old token
// is refused after the sweep as it was before.
func TestAnExpiredOwnerIsForgottenButNotItsToken(t *testing.T) {
	h := newHarness(t)
	ctx := context.Background()
	pool := h.database(ctx)
	store := jobs.NewStore(pool)
	host := h.enrollSyntheticHost(t)

	session, instance := uuid.NewString(), uuid.NewString()
	token, err := store.ClaimSession(ctx, host.ID, session, instance, time.Millisecond)
	if err != nil {
		t.Fatalf("the claim: %v", err)
	}
	time.Sleep(50 * time.Millisecond)
	owner, err := store.OwnerOf(ctx, host.ID)
	if err != nil {
		t.Fatalf("reading the owner: %v", err)
	}
	if owner.Live(time.Now()) {
		t.Fatalf("a lease that ran out still reads as live: %+v", owner)
	}
	if _, err := store.SweepExpiredOwners(ctx); err != nil {
		t.Fatalf("the sweep: %v", err)
	}
	after, err := store.OwnerOf(ctx, host.ID)
	if err != nil {
		t.Fatalf("reading the owner after the sweep: %v", err)
	}
	if after.SessionID != "" || after.Token != token {
		t.Fatalf("the sweep left %+v; expected no session and token %d", after, token)
	}
	if err := store.RenewOwnership(ctx, host.ID, session, instance, token, jobs.OwnerLeaseTTL); !errors.Is(err, jobs.ErrStaleFence) {
		t.Fatalf("the swept session renewed its ownership: %v", err)
	}
}

// stageDispatchedJob writes a job of the host as the scheduler leaves it after
// a delivery - dispatched, with an open attempt - without a session to deliver
// it over.
func stageDispatchedJob(t *testing.T, h *harness, hostID string) string {
	t.Helper()
	ctx := context.Background()
	pool := h.database(ctx)
	jobID, attemptID := uuid.NewString(), uuid.NewString()
	if _, err := pool.Exec(ctx, `
		insert into jobs (id, host_id, action_type, payload, payload_hash, idempotency_key,
		                  state, expires_at, created_by)
		values ($1::uuid, $2::uuid, 'unit.restart', '{"unit": {"name": "cron.service"}}'::jsonb,
		        '\x00'::bytea, $3, 'dispatched', now() + interval '1 hour', 'session-fence-test')`,
		jobID, hostID, "session-fence-"+jobID); err != nil {
		t.Fatalf("staging the job: %v", err)
	}
	if _, err := pool.Exec(ctx, `
		insert into job_attempts (id, job_id, attempt_number, lease_owner, lease_expires_at,
		                          gateway_id, dispatched_at)
		values ($1::uuid, $2::uuid, 1, 'session-fence-test', now() + interval '1 hour',
		        'session-fence-test', now())`,
		attemptID, jobID); err != nil {
		t.Fatalf("staging the attempt: %v", err)
	}
	t.Cleanup(func() {
		_, _ = pool.Exec(context.Background(), `delete from jobs where id = $1::uuid`, jobID)
	})
	return jobID
}

// lastAttemptID reads the newest attempt of a job.
func lastAttemptID(t *testing.T, h *harness, jobID string) string {
	t.Helper()
	ctx := context.Background()
	var attemptID string
	if err := h.database(ctx).QueryRow(ctx, `
		select id::text from job_attempts where job_id = $1::uuid
		order by attempt_number desc limit 1`, jobID).Scan(&attemptID); err != nil {
		t.Fatalf("reading the attempt: %v", err)
	}
	return attemptID
}

// jobStateOf reads the state of a job straight from the table.
func jobStateOf(t *testing.T, h *harness, jobID string) string {
	t.Helper()
	ctx := context.Background()
	var state string
	if err := h.database(ctx).QueryRow(ctx, `select state from jobs where id = $1::uuid`, jobID).
		Scan(&state); err != nil {
		t.Fatalf("reading the job: %v", err)
	}
	return state
}
