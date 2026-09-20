//go:build integration

package integration

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"net/http"
	"os"
	"strings"
	"testing"
	"time"

	"connectrpc.com/connect"
	"github.com/google/uuid"
	"golang.org/x/net/http2"

	agentv1 "github.com/ultherego/flotestro/internal/genproto/flotestro/agent/v1"
	"github.com/ultherego/flotestro/internal/genproto/flotestro/agent/v1/agentv1connect"
)

// The verification of a change on a live fleet: only a state the host showed
// after the change may end a job succeeded.

const verifyReason = "integration test of the verification of a change"

// verifiedAttemptView is an attempt with the reading the host made of itself
// after the change.
type verifiedAttemptView struct {
	Number       int    `json:"attempt_number"`
	Status       string `json:"status"`
	ErrorCode    string `json:"error_code"`
	Message      string `json:"message"`
	Verification *struct {
		Verifier string `json:"verifier"`
		Verified bool   `json:"verified"`
		Expected string `json:"expected"`
		Observed string `json:"observed"`
		Reason   string `json:"reason"`
	} `json:"verification"`
}

// verifiedAttempts reads the attempts of a job with their verifications.
func verifiedAttempts(h *harness, jobID string) []verifiedAttemptView {
	h.t.Helper()
	var result struct {
		Items []verifiedAttemptView `json:"items"`
	}
	h.get("/api/v1/jobs/"+jobID+"/attempts", &result)
	return result.Items
}

// lastVerifiedAttempt returns the attempt that settled the job.
func lastVerifiedAttempt(t *testing.T, h *harness, jobID string) verifiedAttemptView {
	t.Helper()
	attempts := verifiedAttempts(h, jobID)
	if len(attempts) == 0 {
		t.Fatalf("job %s has no attempt at all", jobID)
	}
	return attempts[len(attempts)-1]
}

// TestAChangeTheHostDoesNotShowEndsUnverified drives the case chapter 1 calls
// false success: the tool reports that it did the work, the host does not hold
// the state that was ordered, and the job used to say succeeded.
func TestAChangeTheHostDoesNotShowEndsUnverified(t *testing.T) {
	h := newHarness(t)
	host := h.hostByName("agent-debian")

	t.Cleanup(func() {
		h.runOperation(host.ID, map[string]any{
			"action": "sysctl.ensure", "reason": verifyReason,
			"payload": map[string]any{"kernel": map[string]any{
				"settings": map[string]string{"vm.nr_hugepages": "0"}}},
		}, 2*time.Minute)
	})

	job, _ := h.runOperation(host.ID, map[string]any{
		"action": "sysctl.ensure", "reason": verifyReason,
		"payload": map[string]any{"kernel": map[string]any{
			"settings": map[string]string{"vm.nr_hugepages": "1048576"}}},
	}, 5*time.Minute)

	if job.State == "succeeded" {
		t.Fatalf("the host does not hold the setting and the job says succeeded: %+v", job)
	}
	if job.ResultErrorCode != "applied_unverified" {
		t.Fatalf("error code = %q, expected applied_unverified (%s)", job.ResultErrorCode, job.ResultMessage)
	}

	// The observation is on the attempt, in full: an operator must be able to
	// read which verifier looked, what it wanted and what it found without
	// opening the host.
	attempt := lastVerifiedAttempt(t, h, job.ID)
	if attempt.Verification == nil {
		t.Fatal("the attempt carries no verification at all")
	}
	if attempt.Verification.Verified {
		t.Errorf("the verification says the state was observed: %+v", *attempt.Verification)
	}
	if attempt.Verification.Verifier != "sysctl" {
		t.Errorf("verifier = %q, expected sysctl", attempt.Verification.Verifier)
	}
	if !strings.Contains(attempt.Verification.Expected, "vm.nr_hugepages") ||
		attempt.Verification.Observed == "" {
		t.Errorf("the observation names neither the setting nor a value: %+v", *attempt.Verification)
	}
	// The contract rolls this operation back, and the reason has to say so:
	// the operator must know whether the host still carries the change.
	if !strings.Contains(attempt.Verification.Reason, "back") {
		t.Errorf("the reason does not say what happened to the change: %q", attempt.Verification.Reason)
	}
}

// TestARestartOfAMaskedUnitIsNeverASuccess is the unit half of the same rule,
// in the one shape the lab can produce honestly: a masked unit cannot be
// started, and the job fails with a code instead of reporting a restart.
func TestARestartOfAMaskedUnitIsNeverASuccess(t *testing.T) {
	h := newHarness(t)
	host := h.hostByName("agent-debian")
	const unit = "cron.service"

	mask, _ := h.runOperation(host.ID, map[string]any{
		"action": "unit.mask.set", "reason": verifyReason,
		"payload": map[string]any{"unit_toggle": map[string]any{"unit": unit, "enabled": true}},
	}, 2*time.Minute)
	if mask.State != "succeeded" {
		t.Fatalf("masking %s ended %s: %s", unit, mask.State, mask.ResultMessage)
	}
	t.Cleanup(func() {
		h.runOperation(host.ID, map[string]any{
			"action": "unit.mask.set", "reason": verifyReason,
			"payload": map[string]any{"unit_toggle": map[string]any{"unit": unit, "enabled": false}},
		}, 2*time.Minute)
		h.runOperation(host.ID, map[string]any{
			"action": "unit.start", "reason": verifyReason,
			"payload": unitPayload(unit),
		}, 2*time.Minute)
	})

	restart, _ := h.runOperation(host.ID, map[string]any{
		"action": "unit.restart", "reason": verifyReason, "payload": unitPayload(unit),
	}, 2*time.Minute)
	if restart.State == "succeeded" {
		t.Fatalf("a masked unit was restarted according to the panel: %+v", restart)
	}
	if restart.ResultErrorCode == "" {
		t.Error("the failure of the restart carries no code")
	}
}

// TestARestartSettlesOnTheReturnOfTheHost drives the second gap: the job of a
// restart used to end succeeded on the exit code of the scheduling, which is
// the same exit code a host that never comes back produces.
func TestARestartSettlesOnTheReturnOfTheHost(t *testing.T) {
	// The machines of this laboratory do not come back from a restart they order
	// themselves: VirtualBox leaves the guest stopped, and the workstation brings
	// it back with vagrant.
	if os.Getenv("FLOTESTRO_TEST_REBOOT") == "" {
		t.Skip("set FLOTESTRO_TEST_REBOOT=1 on a fleet whose hosts come back from a restart on their own")
	}
	h := newHarness(t)
	host := h.hostByName("agent-debian")
	if host.BootID == "" {
		t.Skip("the host reports no boot identifier; there would be nothing to compare")
	}
	bootBefore := host.BootID

	job := h.createOperation(host.ID, map[string]any{
		"action": "system.reboot", "reason": verifyReason,
		"payload": map[string]any{"reboot": map[string]any{
			"delay_seconds": 5, "reason": "Flotestro: " + verifyReason,
		}},
	})
	if job.RequiresApproval {
		job = h.approve(job.ID, job.PayloadHash)
	}

	// The whole point of the operation: while the host is away the job is open.
	deadline := time.Now().Add(6 * time.Minute)
	var settled jobView
	for settled.ID == "" && time.Now().Before(deadline) {
		current := h.job(job.ID)
		switch current.State {
		case "succeeded":
			if bootIDOf(h, host.ID) == bootBefore {
				t.Fatalf("the restart was settled succeeded while the host was still on boot %s", bootBefore)
			}
			settled = current
		case "failed", "timed_out", "canceled", "expired":
			t.Fatalf("the restart ended %s/%s: %s", current.State,
				current.ResultErrorCode, current.ResultMessage)
		default:
			time.Sleep(3 * time.Second)
		}
	}
	if settled.ID == "" {
		t.Fatalf("the restart of %s did not settle; the host is on boot %s",
			host.Hostname, bootIDOf(h, host.ID))
	}

	bootAfter := bootIDOf(h, host.ID)
	if bootAfter == "" || bootAfter == bootBefore {
		t.Fatalf("boot identifier after the restart = %q, before = %q", bootAfter, bootBefore)
	}
	if !strings.Contains(settled.ResultMessage, bootAfter) {
		t.Errorf("the result does not name the boot the host came back on: %q", settled.ResultMessage)
	}

	attempt := lastVerifiedAttempt(t, h, job.ID)
	if attempt.Verification == nil {
		t.Fatal("the settled restart carries no verification")
	}
	if attempt.Verification.Verifier != "reboot" || !attempt.Verification.Verified {
		t.Errorf("verification of the restart = %+v", *attempt.Verification)
	}
	if attempt.Verification.Observed != bootAfter ||
		!strings.Contains(attempt.Verification.Expected, bootBefore) {
		t.Errorf("the observation does not name both boots: %+v", *attempt.Verification)
	}

	// The host is back for the rest of the suite before this test ends.
	h.awaitConnection(host.ID, 5*time.Minute)
}

// bootIDOf reads the boot identifier the panel has for a host now.
func bootIDOf(h *harness, hostID string) string {
	h.t.Helper()
	for _, host := range h.hosts() {
		if host.ID == hostID {
			return host.BootID
		}
	}
	return ""
}

// TestACopyBoundToAForeignPlanIsRefused drives the third gap: the plan of a
// copy binds the copy.
func TestACopyBoundToAForeignPlanIsRefused(t *testing.T) {
	h := newHarness(t)
	host := hostWithRestic(t, h)
	stamp := time.Now().UnixNano()
	name := fmt.Sprintf("integration-stale-%d", stamp%100000)
	repository := fmt.Sprintf("/srv/flotestro-stale-%d", stamp%100000)
	secret := newSecret(t, h, fmt.Sprintf("repository-password-%d", stamp))

	h.do(http.MethodPost, "/api/v1/hosts/"+host.ID+"/backups", map[string]any{
		"name": name, "tool": "restic", "repository": repository,
		"paths": []string{"/etc/flotestro"}, "keep_last": 2,
		"initialize": true, "password_secret": secret.Name,
	}, nil, http.StatusOK)
	t.Cleanup(func() {
		h.do(http.MethodDelete, "/api/v1/hosts/"+host.ID+"/backups?name="+name, nil, nil, 0)
	})

	// A digest of a plan this host never computed: the shape is right and
	// the content describes nothing that is here.
	foreign := strings.Repeat("a1", 32)
	job, attempts := h.runOperation(host.ID, map[string]any{
		"action": "backup.run", "reason": verifyReason,
		"payload": map[string]any{"backup": map[string]any{
			"id": name, "tool": "restic", "repository": repository,
			"paths": []string{"/etc/flotestro"}, "keep_last": 2, "initialize": true,
			"password_secret": map[string]any{"name": secret.Name},
			"plan_hash":       foreign,
		}},
	}, 10*time.Minute)

	if job.State == "succeeded" {
		t.Fatalf("a copy ran on a plan this host never computed: %+v", job)
	}
	if job.ResultErrorCode != "stale_plan" {
		t.Fatalf("error code = %q, expected stale_plan: %s", job.ResultErrorCode, lastMessage(attempts))
	}
	// The refusal happens before anything is written: the repository the
	// order names is not created by a refused copy.
	report := hostBackups(h, host.ID)
	for _, definition := range report.Definitions {
		if definition.Name == name && definition.Snapshots != nil && *definition.Snapshots > 0 {
			t.Errorf("the refused copy left %d snapshot(s) behind", *definition.Snapshots)
		}
	}
}

// TestARestartWaitsForAnotherBootIdentifier proves the panel's half of the
// settlement without restarting anything: a synthetic host takes the order,
// its session ends the way a machine going down ends one, and the job settles
// only when the host comes back on another boot.
func TestARestartWaitsForAnotherBootIdentifier(t *testing.T) {
	h := newHarness(t)
	ctx := context.Background()
	pool := h.database(ctx)
	host, identity := h.enrollSyntheticHostWithIdentity(t)
	gateway := envOr("FLOTESTRO_TEST_GATEWAY", defaultGateway)

	// The host announces the adapter the operation needs and a boot it is
	// on, the way an agent does at its first session.
	if _, err := pool.Exec(ctx, `
		insert into host_capability_registry (host_id, name, version, available, features)
		values ($1::uuid, 'systemd', 1, true, '{}'::jsonb)
		on conflict (host_id, name) do update set available = true`, host.ID); err != nil {
		t.Fatalf("giving the synthetic host a systemd adapter: %v", err)
	}
	bootBefore := uuid.NewString()
	session, err := openSyntheticSession(ctx, gateway, identity, bootBefore)
	if err != nil {
		t.Fatalf("the synthetic host did not open its first session: %v", err)
	}

	job := h.createOperation(host.ID, map[string]any{
		"action": "system.reboot", "reason": verifyReason,
		"payload": map[string]any{"reboot": map[string]any{
			"delay_seconds": 5, "reason": "Flotestro: " + verifyReason,
		}},
	})
	if job.RequiresApproval {
		job = h.approve(job.ID, job.PayloadHash)
	}
	t.Cleanup(func() { h.cancelJob(job.ID) })

	// The task reaches the host, which answers nothing: a machine that
	// goes down does not report the restart it is carrying out.
	if task := session.awaitTask(60 * time.Second); task == nil {
		t.Fatalf("the restart did not reach the host; the job is %s", h.job(job.ID).State)
	}
	session.close()

	// The host is away: no session, and nothing settles the job. A
	// success here would be the false success this whole chapter is about.
	time.Sleep(20 * time.Second)
	if state := h.job(job.ID).State; state == "succeeded" {
		t.Fatalf("the restart was settled succeeded while the host was away on boot %s", bootBefore)
	}

	// The host comes back on another boot: that, and only that, settles it.
	back, err := openSyntheticSession(ctx, gateway, identity, uuid.NewString())
	if err != nil {
		t.Fatalf("the returning host did not open a session: %v", err)
	}
	defer back.close()
	deadline := time.Now().Add(90 * time.Second)
	current := h.job(job.ID)
	for current.State != "succeeded" && time.Now().Before(deadline) {
		time.Sleep(2 * time.Second)
		current = h.job(job.ID)
	}
	if current.State != "succeeded" {
		t.Fatalf("the restart did not settle on the host's return: %s/%s %s",
			current.State, current.ResultErrorCode, current.ResultMessage)
	}
	attempt := lastVerifiedAttempt(t, h, job.ID)
	if attempt.Verification == nil || attempt.Verification.Verifier != "reboot" || !attempt.Verification.Verified {
		t.Fatalf("the settled restart carries no verification of the return: %+v", attempt.Verification)
	}
}

// syntheticSession is a host that connects and listens: the test drives
// what it answers, which for a restart is nothing at all.
type syntheticSession struct {
	stream *connect.BidiStreamForClient[agentv1.AgentMessage, agentv1.ServerMessage]
	cancel context.CancelFunc
	server chan *agentv1.ServerMessage
}

// awaitTask waits for the next task the panel sends down the session.
func (s *syntheticSession) awaitTask(limit time.Duration) *agentv1.TaskEnvelope {
	deadline := time.After(limit)
	for {
		select {
		case message, ok := <-s.server:
			if !ok {
				return nil
			}
			if task := message.GetTask(); task != nil {
				return task
			}
		case <-deadline:
			return nil
		}
	}
}

// close ends the session the way a machine going down ends one.
func (s *syntheticSession) close() {
	_ = s.stream.CloseRequest()
	_ = s.stream.CloseResponse()
	s.cancel()
}

// openSyntheticSession opens a session with the identity and the boot
// identifier given and keeps it open, reading what the panel sends.
func openSyntheticSession(ctx context.Context, gateway string,
	identity tls.Certificate, bootID string) (*syntheticSession, error) {
	ctx, cancel := context.WithCancel(ctx)
	client := agentv1connect.NewAgentServiceClient(&http.Client{
		Transport: &http2.Transport{
			TLSClientConfig: &tls.Config{
				Certificates: []tls.Certificate{identity},
				RootCAs:      testTrustPool(),
				MinVersion:   tls.VersionTLS13,
			},
		},
	}, gateway, connect.WithGRPC())
	stream := client.Connect(ctx)
	if err := stream.Send(&agentv1.AgentMessage{
		Payload: &agentv1.AgentMessage_Hello{Hello: &agentv1.Hello{
			AgentVersion: "test", BootId: bootID,
			Capabilities: &agentv1.Capabilities{Registry: []*agentv1.Capability{
				{Name: "systemd", Version: 1, Available: true},
			}},
		}},
	}); err != nil {
		cancel()
		return nil, err
	}
	first, err := stream.Receive()
	if err != nil {
		cancel()
		return nil, err
	}
	if first.GetSessionConfig() == nil {
		cancel()
		return nil, errors.New("the server answered Hello with something other than the session configuration")
	}
	session := &syntheticSession{stream: stream, cancel: cancel, server: make(chan *agentv1.ServerMessage, 16)}
	go func() {
		defer close(session.server)
		for {
			message, err := stream.Receive()
			if err != nil {
				return
			}
			select {
			case session.server <- message:
			default:
			}
		}
	}()
	return session, nil
}
