package agent

// How the answer of a finished task reaches the panel, and what happens to it
// when it cannot.

import (
	"context"
	"log/slog"
	"sync"
	"time"

	agentv1 "github.com/ultherego/flotestro/internal/genproto/flotestro/agent/v1"
)

// resultRetryInterval is how long an answer the panel has not acknowledged
// waits before the same session offers it again. Long enough that an
// acknowledgement in flight is not raced, short enough that an answer nobody
// took does not wait for the session to break.
const resultRetryInterval = 2 * time.Minute

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
	// retryEvery is how often this session offers again what the panel has not
	// answered; zero is resultRetryInterval, and a test sets it shorter.
	retryEvery time.Duration

	// offering is held by the one offer that is running, so a wake-up while one
	// is under way does not start a second.
	offering sync.Mutex

	mu sync.Mutex
	// sent is when this session last put each answer on the wire. An answer
	// waiting for its acknowledgement is not sent again until the retry
	// interval has passed, and a session that has just begun has sent nothing,
	// so it offers everything the spool holds.
	sent map[string]time.Time
}

// watch offers what the panel has not taken for as long as this session lives:
// at once when an answer is written down, and every retry interval for the
// ones whose send did not get through.
//
// Without it the only trigger was the start of a session. A task started in a
// session that broke finishes in its own goroutine, writes its answer to the
// spool of the process - which the live session shares - and its send goes to
// the stream that is already gone. The live session had offered minutes
// earlier and nothing looked again, so the answer waited for the next session,
// which on a healthy agent is hours or days away. The panel held the job
// leased over work that was finished.
func (d *resultDelivery) watch(ctx context.Context) {
	if d.spool == nil {
		return
	}
	every := d.retryEvery
	if every <= 0 {
		every = resultRetryInterval
	}
	ticker := time.NewTicker(every)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-d.spool.Spooled():
		case <-ticker.C:
		}
		d.offer(time.Now())
	}
}

// due says whether this session may put an answer on the wire now: it has not
// sent it, or it sent it long enough ago that the acknowledgement is not
// simply still on its way.
func (d *resultDelivery) due(taskID string, now time.Time) bool {
	every := d.retryEvery
	if every <= 0 {
		every = resultRetryInterval
	}
	d.mu.Lock()
	defer d.mu.Unlock()
	at, known := d.sent[taskID]
	return !known || now.Sub(at) >= every
}

// noteSent records that this session has the answer on the wire.
func (d *resultDelivery) noteSent(taskID string, now time.Time) {
	d.mu.Lock()
	defer d.mu.Unlock()
	if d.sent == nil {
		d.sent = map[string]time.Time{}
	}
	d.sent[taskID] = now
}

// forgetSent drops what this session remembers about an answer that is settled.
func (d *resultDelivery) forgetSent(taskID string) {
	d.mu.Lock()
	defer d.mu.Unlock()
	delete(d.sent, taskID)
}

// deliver writes the answer down and sends it. A send that fails leaves the
// answer in the spool, where the next session that works finds it.
func (d *resultDelivery) deliver(result *agentv1.TaskResult) {
	// The copy on disk comes before the send, always: the task is already
	// carried out on the host, and a session that breaks between the change and
	// the answer is the case this exists for.
	if d.spool != nil {
		// This delivery is about to send it, so the watch that the write below
		// wakes does not send it as well.
		d.noteSent(result.GetTaskId(), time.Now())
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
	// One offer at a time: a wake-up in the middle of one would send the same
	// answers twice.
	if !d.offering.TryLock() {
		return
	}
	defer d.offering.Unlock()

	owed := make([]*agentv1.TaskResult, 0, 4)
	for _, result := range d.spool.Pending(now) {
		if d.due(result.GetTaskId(), now) {
			owed = append(owed, result)
		}
	}
	if len(owed) == 0 {
		return
	}
	d.log.Info("the results the panel never took go out before this session's work",
		"results", len(owed))
	for _, result := range owed {
		d.log.Info("a result the panel never took is offered again",
			"task_id", result.GetTaskId(), "status", result.GetStatus(),
			"error_code", result.GetErrorCode())
		d.noteSent(result.GetTaskId(), now)
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
	d.forgetSent(ack.GetTaskId())
	d.spool.Acknowledge(ack)
}
