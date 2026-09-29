//go:build integration

package integration

// The measured gap: a task whose result could not be sent was never sent
// again, and the job stayed running for ever with the change made on the host.
// The panel will not redeliver a task it believes is leased, so the answer has
// to come back from the host - on the session after the one that broke.

import (
	"context"
	"testing"
	"time"

	"github.com/google/uuid"

	agentv1 "github.com/ultherego/flotestro/internal/genproto/flotestro/agent/v1"
)

// awaitResultAck waits for the panel's answer to a task result.
func (s *syntheticSession) awaitResultAck(limit time.Duration) *agentv1.TaskResultAck {
	deadline := time.After(limit)
	for {
		select {
		case message, ok := <-s.server:
			if !ok {
				return nil
			}
			if ack := message.GetTaskResultAck(); ack != nil {
				return ack
			}
		case <-deadline:
			return nil
		}
	}
}

// TestAResultOfferedOnTheNextSessionSettlesTheJobExactlyOnce takes a task,
// drops the session the way a relay restart drops it, and answers on the next
// one. The panel has to take an answer for an attempt it still believes is
// running, settle the job once, and say so to the host.
func TestAResultOfferedOnTheNextSessionSettlesTheJobExactlyOnce(t *testing.T) {
	h := newHarness(t)
	ctx := context.Background()
	gateway := envOr("FLOTESTRO_TEST_GATEWAY", defaultGateway)
	host, identity := h.enrollSyntheticHostWithIdentity(t)
	pool := h.database(ctx)
	if _, err := pool.Exec(ctx, `
		insert into host_capability_registry (host_id, name, version, available, features)
		values ($1::uuid, 'systemd', 1, true, '{}'::jsonb)
		on conflict (host_id, name) do update set available = true`, host.ID); err != nil {
		t.Fatalf("giving the synthetic host a systemd adapter: %v", err)
	}

	session, err := openSyntheticSession(ctx, gateway, identity, uuid.NewString())
	if err != nil {
		t.Fatalf("the synthetic host did not open a session: %v", err)
	}
	defer session.close()

	job := h.createOperation(host.ID, map[string]any{
		"action": "unit.restart", "reason": "an answer that could not be sent",
		"payload": unitPayload("cron.service"),
	})
	if job.RequiresApproval {
		job = h.approve(job.ID, job.PayloadHash)
	}
	t.Cleanup(func() { h.cancelJob(job.ID) })

	task := session.awaitTask(90 * time.Second)
	if task == nil {
		t.Fatalf("the task did not reach the host; the job is %s", h.job(job.ID).State)
	}
	// The host performed the change and the session went away before the answer
	// left - which is what a relay restart looks like from here.
	session.close()

	again, err := openSyntheticSession(ctx, gateway, identity, uuid.NewString())
	if err != nil {
		t.Fatalf("the host did not come back: %v", err)
	}
	defer again.close()
	result := &agentv1.TaskResult{
		TaskId:         task.GetTaskId(),
		IdempotencyKey: task.GetIdempotencyKey(),
		Status:         agentv1.TaskResult_STATUS_SUCCEEDED,
		Message:        "the unit was restarted",
		Verification:   restartVerification(),
	}
	if err := again.stream.Send(&agentv1.AgentMessage{
		Payload: &agentv1.AgentMessage_TaskResult{TaskResult: result},
	}); err != nil {
		t.Fatalf("the spooled result was not offered on the new session: %v", err)
	}

	// The panel's word is what frees the host's copy, so it has to arrive.
	ack := again.awaitResultAck(90 * time.Second)
	if ack == nil {
		t.Fatal("the panel never said what became of the result; the host would offer it for ever")
	}
	if ack.GetTaskId() != task.GetTaskId() {
		t.Fatalf("the acknowledgement names the attempt %q, not %q", ack.GetTaskId(), task.GetTaskId())
	}
	if ack.GetStatus() != agentv1.TaskResultAck_STATUS_SETTLED {
		t.Fatalf("the answer offered on the next session was not taken: %s %s",
			ack.GetStatus(), ack.GetReasonCode())
	}

	settled := h.awaitTerminal(job.ID, 2*time.Minute)
	if settled.State != "succeeded" {
		t.Fatalf("the answer from the next session did not settle the job: %s %s %s",
			settled.State, settled.ResultErrorCode, settled.ResultMessage)
	}
	// Exactly once: the panel must not have handed the task out a second time
	// behind the host's back and written two attempts for one change.
	if attempts := h.attempts(job.ID); len(attempts) != 1 {
		t.Errorf("the job carries %d attempts after one delivery and one answer", len(attempts))
	}

	// And a second offer of the same answer - the host had not been told the
	// first time - changes nothing and is refused rather than taken late.
	if err := again.stream.Send(&agentv1.AgentMessage{
		Payload: &agentv1.AgentMessage_TaskResult{TaskResult: result},
	}); err != nil {
		t.Fatalf("the second offer was not sent: %v", err)
	}
	second := again.awaitResultAck(60 * time.Second)
	if second == nil {
		t.Fatal("the panel said nothing about the second offer")
	}
	if second.GetStatus() == agentv1.TaskResultAck_STATUS_UNSPECIFIED {
		t.Fatalf("the second offer got no disposition: %+v", second)
	}
	if attempts := h.attempts(job.ID); len(attempts) != 1 {
		t.Errorf("the second offer wrote a second attempt: %d", len(attempts))
	}
}
