//go:build integration

package integration

import (
	"context"
	"testing"

	"github.com/google/uuid"

	"github.com/ultherego/flotestro/internal/jobs"
)

// A host that answers a cancel with "not interruptible" puts the job back to
// running, and the operator may cancel it again. That second request used to
// be recorded and never delivered: the relay sends only the jobs with no
// answer yet, and the first answer was still on the row. The panel then waited
// out the operation's timeout and failed the job as an outcome nobody knows,
// without ever having asked the host.
func TestASecondCancelOfAJobReachesTheHost(t *testing.T) {
	h := newHarness(t)
	ctx := context.Background()
	pool := h.database(ctx)
	store := jobs.NewStore(pool)
	host := h.enrollSyntheticHost(t)

	jobID := stageDispatchedJob(t, h, host.ID)
	sessionID := stageOpenSession(t, h, host.ID)
	token, err := store.ClaimSession(ctx, host.ID, sessionID, uuid.NewString(), jobs.OwnerLeaseTTL)
	if err != nil {
		t.Fatalf("the claim: %v", err)
	}
	fence := jobs.Fence{SessionID: sessionID, Token: token}

	if _, err := pool.Exec(ctx, `update jobs set state = 'running' where id = $1::uuid`, jobID); err != nil {
		t.Fatalf("running the job: %v", err)
	}

	cancelOnce := func() uint64 {
		t.Helper()
		tx, err := pool.Begin(ctx)
		if err != nil {
			t.Fatalf("the transaction: %v", err)
		}
		defer func() { _ = tx.Rollback(ctx) }()
		if _, err := store.Cancel(ctx, tx, jobID, "integration", "the cancel revision test"); err != nil {
			t.Fatalf("the cancel: %v", err)
		}
		if err := tx.Commit(ctx); err != nil {
			t.Fatalf("committing the cancel: %v", err)
		}
		return store.OutstandingCancelRevision(ctx, jobID)
	}

	first := cancelOnce()
	if first == 0 {
		t.Fatal("the first cancel request has no revision")
	}
	if !pendingForHost(t, h, host.ID, jobID) {
		t.Fatal("the first cancel request was not offered to the host")
	}

	// The host cannot interrupt this one, so the job goes back to running.
	if _, err := store.RecordCancelAck(ctx, jobID, first,
		jobs.CancelOutcomeNotInterruptible, "applying", fence); err != nil {
		t.Fatalf("the first answer: %v", err)
	}
	if pendingForHost(t, h, host.ID, jobID) {
		t.Fatal("an answered cancel request is still offered to the host")
	}

	// The operator cancels again. This is where the request used to vanish.
	second := cancelOnce()
	if second <= first {
		t.Fatalf("the second request has revision %d, the first %d", second, first)
	}
	if !pendingForHost(t, h, host.ID, jobID) {
		t.Fatal("the second cancel request never reached the host")
	}

	// An answer naming the request that was replaced settles nothing.
	if _, err := store.RecordCancelAck(ctx, jobID, first,
		jobs.CancelOutcomeNotStarted, "", fence); err == nil {
		t.Error("an answer to the replaced request was accepted")
	}
	if !pendingForHost(t, h, host.ID, jobID) {
		t.Error("a stale answer took the outstanding request away")
	}

	// A session that no longer owns the host may not settle the job either.
	other := stageOpenSession(t, h, host.ID)
	if _, err := store.ClaimSession(ctx, host.ID, other, uuid.NewString(), jobs.OwnerLeaseTTL); err != nil {
		t.Fatalf("the second claim: %v", err)
	}
	if _, err := store.RecordCancelAck(ctx, jobID, second,
		jobs.CancelOutcomeNotStarted, "", fence); err == nil {
		t.Error("a superseded session settled the cancel")
	}
}

// pendingForHost says whether the relay would carry a cancel request for the
// job to its host right now.
func pendingForHost(t *testing.T, h *harness, hostID, jobID string) bool {
	t.Helper()
	store := jobs.NewStore(h.database(context.Background()))
	pending, err := store.PendingCancels(context.Background(), []string{hostID})
	if err != nil {
		t.Fatalf("reading the pending cancels: %v", err)
	}
	for _, request := range pending {
		if request.JobID == jobID {
			return true
		}
	}
	return false
}
