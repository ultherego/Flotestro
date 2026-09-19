//go:build integration

package integration

import (
	"context"
	"crypto/tls"
	"net"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"

	agentv1 "github.com/ultherego/flotestro/internal/genproto/flotestro/agent/v1"
)

// The readiness criterion of the security document: a relay restarted in the
// middle of the work loses no result.

// TestARelayRestartLosesNoResult restarts the relay through the panel while a
// host connected through it holds a task, and asserts the result still settles
// the job exactly once.
func TestARelayRestartLosesNoResult(t *testing.T) {
	h := newHarness(t)
	ctx := context.Background()
	relayURL := envOr("FLOTESTRO_TEST_RELAY", defaultRelay)
	address := strings.TrimPrefix(relayURL, "https://")
	if conn, err := net.DialTimeout("tcp", address, 3*time.Second); err != nil {
		t.Skipf("the lab relay at %s does not answer: %v", address, err)
	} else {
		_ = conn.Close()
	}
	// The machine the relay runs on takes the order to restart it; without it the
	// test would need a shell on that host, which the product does not give
	// anybody.
	relayHost := h.hostByName(relayHostName(t, h))
	host, identity := h.enrollSyntheticHostWithIdentity(t)
	pool := h.database(ctx)
	if _, err := pool.Exec(ctx, `
		insert into host_capability_registry (host_id, name, version, available, features)
		values ($1::uuid, 'systemd', 1, true, '{}'::jsonb)
		on conflict (host_id, name) do update set available = true`, host.ID); err != nil {
		t.Fatalf("giving the synthetic host a systemd adapter: %v", err)
	}

	session, err := openRelayedAgent(ctx, relayURL, identity)
	if err != nil {
		t.Fatalf("the synthetic host did not open a session through the relay: %v", err)
	}
	defer session.close()

	job := h.createOperation(host.ID, map[string]any{
		"action": "unit.restart", "reason": "a result carried across a relay restart",
		"payload": unitPayload("cron.service"),
	})
	if job.RequiresApproval {
		job = h.approve(job.ID, job.PayloadHash)
	}
	t.Cleanup(func() { h.cancelJob(job.ID) })

	task := session.awaitTask(90 * time.Second)
	if task == nil {
		t.Fatalf("the task did not reach the host through the relay; the job is %s", h.job(job.ID).State)
	}

	// The relay goes down and comes back while the host holds the task.
	restart := h.createOperation(relayHost.ID, map[string]any{
		"action": "unit.restart", "reason": "restarting the relay while a task is in flight",
		"payload": unitPayload("flotestro-relay.service"),
	})
	if restart.RequiresApproval {
		restart = h.approve(restart.ID, restart.PayloadHash)
	}
	if final := h.awaitTerminal(restart.ID, 3*time.Minute); final.State != "succeeded" {
		t.Fatalf("the relay was not restarted: %s %s", final.State, final.ResultMessage)
	}

	// The host answers.
	session.close()
	// A relay that has just been restarted is not listening the instant the job
	// that restarted it reports success: the unit is started, the process opens
	// its listener a moment later, and a real agent retries exactly like this.
	var again *syntheticSession
	deadline := time.Now().Add(90 * time.Second)
	for {
		var err error
		again, err = openRelayedAgent(ctx, relayURL, identity)
		if err == nil {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("the host did not come back through the restarted relay: %v", err)
		}
		time.Sleep(2 * time.Second)
	}
	defer again.close()
	if err := again.stream.Send(&agentv1.AgentMessage{
		Payload: &agentv1.AgentMessage_TaskResult{TaskResult: &agentv1.TaskResult{
			TaskId:         task.GetTaskId(),
			IdempotencyKey: task.GetIdempotencyKey(),
			Status:         agentv1.TaskResult_STATUS_SUCCEEDED,
			Message:        "the unit was restarted",
		}},
	}); err != nil {
		t.Fatalf("the result was not sent through the relay: %v", err)
	}

	settled := h.awaitTerminal(job.ID, 2*time.Minute)
	if settled.State != "succeeded" {
		t.Fatalf("the result did not settle the job across the relay restart: %s %s %s",
			settled.State, settled.ResultErrorCode, settled.ResultMessage)
	}
	// Exactly once: a resend after a reconnect must not write a second attempt,
	// and the relay's redelivery must not be recorded as a replay on the host.
	attempts := h.attempts(job.ID)
	if len(attempts) != 1 {
		t.Errorf("the job carries %d attempts after one delivery and one answer", len(attempts))
	}
	if view := h.hostRefusal(host.ID); view != nil {
		t.Errorf("the host carries a refusal after the restart: %+v", view)
	}
}

// relayHostName finds the machine the relay runs on: the one whose hostname
// the laboratory gave it.
func relayHostName(t *testing.T, h *harness) string {
	t.Helper()
	name := envOr("FLOTESTRO_TEST_RELAY_HOST", "agent-ubuntu")
	for _, host := range h.hosts() {
		if host.Hostname == name {
			return name
		}
	}
	t.Skipf("the fleet has no host named %s to restart the relay on", name)
	return ""
}

// openRelayedAgent opens a session at the relay with the host's own
// certificate.
func openRelayedAgent(ctx context.Context, relayURL string, identity tls.Certificate) (*syntheticSession, error) {
	return openSyntheticSession(ctx, relayURL, identity, uuid.NewString())
}
