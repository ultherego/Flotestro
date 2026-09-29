package agent

// How the answer of a finished task reaches the panel, and what happens to it
// when it cannot.

import (
	"log/slog"
	"time"

	agentv1 "github.com/ultherego/flotestro/internal/genproto/flotestro/agent/v1"
)

// resultDelivery carries the answers of the tasks to the panel and keeps the
// ones the panel has not taken.
type resultDelivery struct {
	// spool holds what the panel has not answered. Nil means a host with no
	// state directory - the simulator, a test - and then a lost session loses
	// the answer, as it always did.
	spool *ResultSpool
	send  func(*agentv1.AgentMessage) error
	log   *slog.Logger
	// acknowledged says this panel answers every result with a TaskResultAck.
	// Against a panel that does not, the successful send is the whole of the
	// confirmation there is, and holding the answer back past it would only
	// deliver it a second time at the next session.
	acknowledged bool
}

// deliver writes the answer down and sends it. A send that fails leaves the
// answer in the spool, where the next session that works finds it.
func (d *resultDelivery) deliver(result *agentv1.TaskResult) {
	// The copy on disk comes before the send, always: the task is already
	// carried out on the host, and a session that breaks between the change and
	// the answer is the case this exists for.
	if d.spool != nil {
		if err := d.spool.Enqueue(result); err != nil {
			d.log.Error("the result was not kept for a resend; a broken session now loses it",
				"task_id", result.GetTaskId(), "err", err)
		}
	}
	if err := d.send(&agentv1.AgentMessage{
		Payload: &agentv1.AgentMessage_TaskResult{TaskResult: result},
	}); err != nil {
		if d.spool != nil {
			d.log.Error("the result of the task was not sent back; it is offered again at the next session",
				"task_id", result.GetTaskId(), "err", err)
		} else {
			d.log.Error("the result of the task was not sent back", "task_id", result.GetTaskId(), "err", err)
		}
		return
	}
	if d.spool != nil && !d.acknowledged {
		d.spool.Forget(result.GetTaskId())
	}
}

// offer sends the answers the panel never took, oldest first and before this
// session's own work. It stops at the first send that fails: the session is
// gone, and what is left waits for the next one.
func (d *resultDelivery) offer(now time.Time) {
	if d.spool == nil {
		return
	}
	pending := d.spool.Pending(now)
	if len(pending) == 0 {
		return
	}
	d.log.Info("the results the panel never took go out before this session's work",
		"results", len(pending))
	for _, result := range pending {
		d.log.Info("a result the panel never took is offered again",
			"task_id", result.GetTaskId(), "status", result.GetStatus(),
			"error_code", result.GetErrorCode())
		if err := d.send(&agentv1.AgentMessage{
			Payload: &agentv1.AgentMessage_TaskResult{TaskResult: result},
		}); err != nil {
			d.log.Warn("the spooled result was not sent either; it waits for the next session",
				"task_id", result.GetTaskId(), "err", err)
			return
		}
		if !d.acknowledged {
			d.spool.Forget(result.GetTaskId())
		}
	}
}

// acknowledge frees what the panel answered. Every answer frees the copy: a
// settlement because the panel holds it, a duplicate because it already did,
// and a refusal because it never will.
func (d *resultDelivery) acknowledge(ack *agentv1.TaskResultAck) {
	if d.spool == nil || ack == nil || ack.GetTaskId() == "" {
		return
	}
	switch ack.GetStatus() {
	case agentv1.TaskResultAck_STATUS_REJECTED_STALE:
		// The work was done on the host and the panel will never record it. The
		// operator reads this line and nothing else, so it says the whole of it.
		d.log.Error("the panel refused the result for good and it is given up",
			"task_id", ack.GetTaskId(), "reason_code", ack.GetReasonCode(),
			"consequence", "the task was carried out on this host and the panel does not record it")
	case agentv1.TaskResultAck_STATUS_DUPLICATE:
		d.log.Info("the panel already held this result", "task_id", ack.GetTaskId())
	default:
		d.log.Debug("the panel took the result", "task_id", ack.GetTaskId())
	}
	d.spool.Acknowledge(ack)
}
