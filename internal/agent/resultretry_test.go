package agent

// The trigger that looks for the answers the panel has not taken: a session
// offers them when it begins, and keeps looking while it lives.

import (
	"context"
	"errors"
	"testing"
	"time"

	agentv1 "github.com/ultherego/flotestro/internal/genproto/flotestro/agent/v1"
)

// watchedPanel is a far end that records what it was sent on a channel, so a
// test can wait for a send made by a goroutine.
type watchedPanel struct {
	sent   chan string
	broken bool
}

func (p *watchedPanel) send(msg *agentv1.AgentMessage) error {
	result := msg.GetTaskResult()
	if result == nil {
		return nil
	}
	if p.broken {
		return errors.New("the session is gone")
	}
	p.sent <- result.GetTaskId()
	return nil
}

// A task that started in the session that broke finishes while the next
// session is already running: its answer reaches the spool after that session
// offered, and the session that can send it has to look again. Nothing did, so
// the answer waited for the session after that - hours on a healthy agent -
// while the panel held the job leased over work that was finished.
func TestAnAnswerSpooledAfterTheOfferGoesOutOnTheSessionThatIsLive(t *testing.T) {
	spool := openResultSpool(t, t.TempDir(), ResultSpoolSize, ResultSpoolBytes)

	live := &watchedPanel{sent: make(chan string, 4)}
	session := &resultDelivery{
		spool: spool, send: live.send, log: quietLog(), acknowledged: true,
		// Long enough that only the signal of the spool can satisfy this test.
		retryEvery: time.Hour,
	}
	// The session begins: nothing is owed yet.
	session.offer(time.Now())
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go session.watch(ctx)

	// The task of the previous session finishes now. Its answer goes to the
	// spool of the process and its send to a stream that is gone.
	broken := &resultDelivery{
		spool: spool, send: (&watchedPanel{broken: true}).send,
		log: quietLog(), acknowledged: true,
	}
	broken.deliver(finishedTask("attempt-late"))

	select {
	case taskID := <-live.sent:
		if taskID != "attempt-late" {
			t.Fatalf("the live session sent %q", taskID)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("the answer spooled by the broken session was never offered on the live one")
	}

	// And once: the acknowledgement settles it, and the session does not keep
	// sending what the panel has answered.
	session.acknowledge(&agentv1.TaskResultAck{
		TaskId: "attempt-late", Status: agentv1.TaskResultAck_STATUS_SETTLED,
	})
	session.offer(time.Now())
	select {
	case taskID := <-live.sent:
		t.Fatalf("the settled answer %q was sent again", taskID)
	case <-time.After(100 * time.Millisecond):
	}
}

// An answer whose acknowledgement may still be on its way is not sent a second
// time: the wake-up of the spool is not a reason to deliver twice.
func TestAnAnswerWaitingForItsAcknowledgementIsNotSentAgain(t *testing.T) {
	spool := openResultSpool(t, t.TempDir(), ResultSpoolSize, ResultSpoolBytes)
	panel := &watchedPanel{sent: make(chan string, 4)}
	session := &resultDelivery{
		spool: spool, send: panel.send, log: quietLog(), acknowledged: true,
		retryEvery: time.Hour,
	}

	session.deliver(finishedTask("attempt-waiting"))
	if taskID := <-panel.sent; taskID != "attempt-waiting" {
		t.Fatalf("the session sent %q", taskID)
	}
	session.offer(time.Now())
	select {
	case taskID := <-panel.sent:
		t.Fatalf("the answer %q went out twice while its acknowledgement was in flight", taskID)
	case <-time.After(100 * time.Millisecond):
	}
}
