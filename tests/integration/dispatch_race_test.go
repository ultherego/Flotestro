//go:build integration

package integration

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/ultherego/flotestro/internal/jobs"
)

// The envelope leaves the panel before the delivery is written down, and a
// cancel arriving in that window used to settle the job outright: the panel
// said "canceled" about a change the host was already carrying out. The
// delivery is now recorded against the state the job is actually in.
func TestAJobSettledWhileItsTaskWasOnTheWireSaysTheOutcomeIsUnknown(t *testing.T) {
	h := newHarness(t)
	ctx := context.Background()
	pool := h.database(ctx)
	store := jobs.NewStore(pool)
	host := h.enrollSyntheticHost(t)

	jobID := stageDispatchedJob(t, h, host.ID)
	attemptID := lastAttemptID(t, h, jobID)
	sessionID := stageOpenSession(t, h, host.ID)
	token, err := store.ClaimSession(ctx, host.ID, sessionID, uuid.NewString(), jobs.OwnerLeaseTTL)
	if err != nil {
		t.Fatalf("the claim: %v", err)
	}
	fence := jobs.Fence{SessionID: sessionID, Token: token}

	// The job is leased: the scheduler is about to send it.
	if _, err := pool.Exec(ctx, `update jobs set state = 'leased' where id = $1::uuid`, jobID); err != nil {
		t.Fatalf("leasing the job: %v", err)
	}
	// The envelope goes out here. Before the delivery is recorded, the job is
	// settled - the cancel of a leased job does exactly this.
	if _, err := pool.Exec(ctx, `
		update jobs set state = 'canceled', canceled_at = now(), finished_at = now()
		 where id = $1::uuid`, jobID); err != nil {
		t.Fatalf("settling the job: %v", err)
	}

	err = store.MarkDispatchedWithLease(ctx, jobID, attemptID, fence, 30*time.Second)
	if !errors.Is(err, jobs.ErrDispatchLost) {
		t.Fatalf("the delivery of a settled job was recorded as ordinary: %v", err)
	}
	var status, message *string
	if err := pool.QueryRow(ctx,
		`select result_status, result_message from jobs where id = $1::uuid`, jobID).
		Scan(&status, &message); err != nil {
		t.Fatal(err)
	}
	if status == nil || *status != jobs.ResultStatusUnknown {
		t.Errorf("the settled job reads as %v, not as an unknown outcome", status)
	}
	if message == nil || *message == "" {
		t.Error("the job says nothing about the task that had already left")
	}

	// A job that simply moved forward - a quick agent acknowledged the task
	// before the delivery was written - is the ordinary case and stays one.
	quick := stageDispatchedJob(t, h, host.ID)
	quickAttempt := lastAttemptID(t, h, quick)
	if _, err := pool.Exec(ctx, `update jobs set state = 'running' where id = $1::uuid`, quick); err != nil {
		t.Fatalf("moving the job forward: %v", err)
	}
	if err := store.MarkDispatchedWithLease(ctx, quick, quickAttempt, fence, 30*time.Second); err != nil {
		t.Errorf("the delivery of a job the agent had already taken was refused: %v", err)
	}
	if state := jobStateOf(t, h, quick); state != "running" {
		t.Errorf("the delivery moved a running job to %s", state)
	}
}

// stageOpenSession gives the host an open session row, which is what a
// delivery is recorded over.
func stageOpenSession(t *testing.T, h *harness, hostID string) string {
	t.Helper()
	ctx := context.Background()
	pool := h.database(ctx)
	sessionID := uuid.NewString()
	if _, err := pool.Exec(ctx, `
		insert into agent_sessions
			(id, host_id, gateway_id, cert_fingerprint, remote_addr, agent_version, boot_id, epoch,
			 last_heartbeat_at)
		values ($1::uuid, $2::uuid, 'dispatch-race-test', '\x01'::bytea, '203.0.113.9', 'test',
		        'dispatch-race', (select coalesce(max(epoch), 0) + 1 from agent_sessions where host_id = $2::uuid),
		        now())`, sessionID, hostID); err != nil {
		t.Fatalf("staging the session: %v", err)
	}
	t.Cleanup(func() {
		_, _ = pool.Exec(context.Background(), `delete from agent_sessions where id = $1::uuid`, sessionID)
	})
	return sessionID
}
