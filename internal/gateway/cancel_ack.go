package gateway

import (
	"context"
	"encoding/hex"
	"errors"
	"fmt"
	"strings"
	"sync"
	"time"

	"github.com/ultherego/flotestro/internal/audit"
	"github.com/ultherego/flotestro/internal/events"
	agentv1 "github.com/ultherego/flotestro/internal/genproto/flotestro/agent/v1"
	"github.com/ultherego/flotestro/internal/jobs"
)

// The cancel protocol on the gateway side.
//
// A cancel of a task the host holds is a request the panel records on the
// job (jobs.Store.Cancel) and a question the agent answers (CancelAck in
// agent.proto). Two things happen here. The request reaches the host: the
// instance holding the host's session reads the open requests of its own
// hosts and sends each as a CancelTask - on the trail's notification, so
// a request goes out within a round trip, and on a tick, so a request
// made while the notification was lost or the session was elsewhere goes
// out anyway. And the answer settles the job: the acknowledgement names
// the attempt, the attempt names the job, and the store moves the job by
// what the host said. A request nobody answers within the operation's
// timeout is settled by the sweep as unknown.

// cancelOutcomeName translates the protocol's outcome into the word the
// store keeps: the enum name in lower case.
func cancelOutcomeName(outcome agentv1.CancelAck_Outcome) string {
	return strings.ToLower(outcome.String())
}

// recordCancelAck settles a cancel request by the agent's answer. Called
// from the message switch of the session for AgentMessage_CancelAck.
//
// The attempt must belong to the host that answers: a host that learned
// another host's attempt identifier must not cancel that host's job. The
// hash of the result the agent observed - with already_done - goes on the
// trail: the panel keeps the parsed result, not the encoding, so the
// hash is a fact for the record rather than something to compare here.
func (s *AgentService) recordCancelAck(ctx context.Context, session *Session, ack *agentv1.CancelAck) error {
	hostID := session.HostID
	attemptID := ack.GetTaskId()
	jobID, action, _, err := s.jobs.AttemptOwner(ctx, attemptID, hostID)
	if err != nil {
		if errors.Is(err, jobs.ErrNotFound) {
			s.audit.Record(ctx, audit.Event{
				ActorType: audit.ActorAgent, ActorID: hostID,
				Action: "security.attempt_mismatch", TargetType: "host", TargetID: hostID,
				Outcome: audit.OutcomeDenied,
				Detail: map[string]any{
					"attempt_id": attemptID, "message": "cancel_ack",
					"outcome": cancelOutcomeName(ack.GetOutcome()),
				},
			})
		}
		return fmt.Errorf("a cancel acknowledgement for the unknown attempt %s: %w", attemptID, err)
	}
	outcome := cancelOutcomeName(ack.GetOutcome())
	settlement, err := s.jobs.RecordCancelAck(ctx, jobID, outcome, ack.GetPhase())
	if err != nil {
		return fmt.Errorf("recording the cancel acknowledgement of job %s: %w", jobID, err)
	}

	detail := map[string]any{
		"attempt_id": attemptID, "action_type": action, "host_id": hostID,
		"outcome": outcome, "phase": ack.GetPhase(),
		"previous_state": string(settlement.Previous), "state": string(settlement.State),
	}
	if hash := ack.GetObservedResultHash(); len(hash) > 0 {
		detail["observed_result_hash"] = hex.EncodeToString(hash)
	}
	s.audit.Record(ctx, audit.Event{
		ActorType: audit.ActorAgent, ActorID: hostID,
		Action: "job.cancel_ack", TargetType: "job", TargetID: jobID,
		Outcome: audit.OutcomeSuccess, Detail: detail,
	})
	s.log.Info("the host answered the cancel of a task",
		"host_id", hostID, "job_id", jobID, "attempt_id", attemptID,
		"outcome", outcome, "phase", ack.GetPhase(),
		"previous_state", settlement.Previous, "state", settlement.State)
	return nil
}

// cancelResendInterval is how long the relay waits before sending an
// unanswered request to the same attempt again. A request is answered
// within a round trip; one still open after this long was sent into a
// stream that died, or to an agent from before the protocol, which never
// answers and is settled by the sweep.
const cancelResendInterval = 30 * time.Second

// cancelRelayInterval is the tick of the relay: how long a request waits
// at most when the trail's notification did not reach this instance.
const cancelRelayInterval = 5 * time.Second

// cancelSends remembers, per attempt, when the relay last sent the
// request, so a tick does not send the same request every five seconds.
// An answered request leaves the pending list and is never looked up
// again; the entry is bounded away, not cleaned.
type cancelSends struct {
	mu   sync.Mutex
	sent map[string]time.Time
}

// maxRememberedCancelSends bounds the memory: a session may die between
// the send and the answer, and a map that only grows would be a slow leak.
const maxRememberedCancelSends = 4096

func (c *cancelSends) due(attemptID string, now time.Time) bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.sent == nil {
		c.sent = map[string]time.Time{}
	}
	if last, known := c.sent[attemptID]; known && now.Sub(last) < cancelResendInterval {
		return false
	}
	if len(c.sent) >= maxRememberedCancelSends {
		c.sent = map[string]time.Time{}
	}
	c.sent[attemptID] = now
	return true
}

func (c *cancelSends) forget(attemptID string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	delete(c.sent, attemptID)
}

// cancelRelay is the relay of one instance: the service it sends through
// and the sends it remembers. It is a value of its own rather than a
// field of the service so that it is created where it runs.
type cancelRelay struct {
	service *AgentService
	sends   cancelSends
}

// RunCancelRelay delivers the open cancel requests of the hosts connected
// to this instance and settles the requests nobody answered. It runs
// until the context ends; one goroutine per instance.
func (s *AgentService) RunCancelRelay(ctx context.Context) {
	relay := &cancelRelay{service: s}
	ticker := time.NewTicker(cancelRelayInterval)
	defer ticker.Stop()

	// The trail's notification wakes the relay the moment a request is
	// recorded; without the bus the tick alone carries the requests.
	var wakes <-chan events.Event
	if s.events != nil {
		var unsubscribe func()
		wakes, unsubscribe = s.events.Subscribe(func(event events.Event) bool {
			return event.Outbox != nil && event.Outbox.Type == jobs.EventCancelRequested
		})
		defer unsubscribe()
	}
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			relay.send(ctx)
			s.settleCancelTimeouts(ctx)
		case <-wakes:
			relay.send(ctx)
		}
	}
}

// send delivers the open requests of the connected hosts. It returns how
// many went out.
func (r *cancelRelay) send(ctx context.Context) int {
	s := r.service
	connected := s.registry.ConnectedHosts()
	if len(connected) == 0 {
		return 0
	}
	pending, err := s.jobs.PendingCancels(ctx, connected)
	if err != nil {
		s.log.Error("the open cancel requests were not read", "err", err)
		return 0
	}
	now := time.Now()
	sent := 0
	for _, request := range pending {
		if request.AttemptID == "" || !r.sends.due(request.AttemptID, now) {
			continue
		}
		message := &agentv1.ServerMessage{
			Payload: &agentv1.ServerMessage_CancelTask{
				CancelTask: cancelTaskOf(request),
			},
		}
		if _, err := s.registry.Dispatch(request.HostID, message, 5*time.Second); err != nil {
			// The host left between the listing and the send: the next
			// instance to hold it sends, and the send is tried again here
			// on the next tick should it come back.
			r.sends.forget(request.AttemptID)
			s.log.Debug("the cancel request was not sent",
				"job_id", request.JobID, "host_id", request.HostID, "err", err)
			continue
		}
		sent++
		s.log.Info("the cancel request was sent to the host",
			"job_id", request.JobID, "host_id", request.HostID, "attempt_id", request.AttemptID,
			"deadline", request.Deadline.UTC().Format(time.RFC3339))
	}
	return sent
}

// cancelTaskOf is the message the request goes out as: the attempt the
// agent knows the task by, the reason for its log, the revision the
// answer is read against and the deadline after which the panel stops
// waiting.
func cancelTaskOf(request jobs.CancelRequest) *agentv1.CancelTask {
	reason := request.Reason
	if reason == "" {
		reason = "operation cancelled from the panel"
	}
	return &agentv1.CancelTask{
		TaskId:          request.AttemptID,
		Reason:          reason,
		RequestRevision: request.Revision,
		DeadlineUnix:    request.Deadline.Unix(),
	}
}

// settleCancelTimeouts ends the requests nobody answered in time and puts
// each on the trail: the outcome on the host is unknown, and the operator
// reads it off the host.
func (s *AgentService) settleCancelTimeouts(ctx context.Context) {
	settled, err := s.jobs.SettleCancelTimeouts(ctx)
	if err != nil {
		s.log.Error("the unanswered cancel requests were not settled", "err", err)
		return
	}
	for _, jobID := range settled {
		s.audit.Record(ctx, audit.Event{
			ActorType: audit.ActorSystem, ActorID: "gateway:" + s.gatewayID,
			Action: "job.cancel_timeout", TargetType: "job", TargetID: jobID,
			Outcome: audit.OutcomeFailure,
			Detail: map[string]any{
				"error_code": jobs.CancelAckTimeoutCode,
				"reason":     "the host did not acknowledge the cancel within the operation's timeout",
			},
		})
		s.log.Warn("a cancel request got no answer within the operation's timeout; the outcome on the host is unknown",
			"job_id", jobID)
	}
}
