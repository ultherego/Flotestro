package agent

// A result is not lost: a task whose answer could not be sent goes out at the
// next session that works, and the panel's word - not the send - is what frees
// the copy on disk.

import (
	"errors"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"testing"
	"time"

	agentv1 "github.com/ultherego/flotestro/internal/genproto/flotestro/agent/v1"
)

// fakePanel stands in for the far end of the session: it counts the results it
// was given and answers them the way the panel does.
type fakePanel struct {
	// received are the attempts whose result arrived, in order.
	received []string
	// refuse makes every send fail, which is a session that broke between the
	// change on the host and the answer.
	refuse bool
	answer agentv1.TaskResultAck_Status
	// answered is set when the panel is to answer at all; a panel that does not
	// acknowledge results leaves it false.
	answered bool
	delivery *resultDelivery
}

func (p *fakePanel) send(msg *agentv1.AgentMessage) error {
	result := msg.GetTaskResult()
	if result == nil {
		return nil
	}
	if p.refuse {
		return errors.New("the session is gone")
	}
	p.received = append(p.received, result.GetTaskId())
	if p.answered {
		p.delivery.acknowledge(&agentv1.TaskResultAck{
			TaskId:         result.GetTaskId(),
			IdempotencyKey: result.GetIdempotencyKey(),
			Status:         p.answer,
		})
	}
	return nil
}

// session builds one session of the agent over the spool given.
func (p *fakePanel) session(t *testing.T, spool *ResultSpool, acknowledged bool) *resultDelivery {
	t.Helper()
	p.answered = acknowledged
	delivery := &resultDelivery{spool: spool, send: p.send, log: quietLog(), acknowledged: acknowledged}
	p.delivery = delivery
	return delivery
}

func openResultSpool(t *testing.T, dir string, limit int, maxSize int64) *ResultSpool {
	t.Helper()
	spool, err := OpenResultSpool(dir, limit, maxSize, ResultSpoolTTL, quietLog())
	if err != nil {
		t.Fatalf("the result spool did not open: %v", err)
	}
	return spool
}

func finishedTask(taskID string) *agentv1.TaskResult {
	return &agentv1.TaskResult{
		TaskId:         taskID,
		IdempotencyKey: "job:" + taskID,
		Status:         agentv1.TaskResult_STATUS_SUCCEEDED,
		Message:        "the unit was restarted",
	}
}

// TestAResultThatCouldNotBeSentGoesOutAtTheNextSession is the whole point: the
// host did the work, the session broke before the answer left, and the job
// must not stay running for ever because of it.
func TestAResultThatCouldNotBeSentGoesOutAtTheNextSession(t *testing.T) {
	dir := t.TempDir()
	panel := &fakePanel{answer: agentv1.TaskResultAck_STATUS_SETTLED}

	// The session that broke: the task finished and the answer went nowhere.
	spool := openResultSpool(t, dir, ResultSpoolSize, ResultSpoolBytes)
	panel.refuse = true
	panel.session(t, spool, true).deliver(finishedTask("attempt-1"))
	if len(panel.received) != 0 {
		t.Fatalf("the broken session delivered %v", panel.received)
	}
	if spool.Len() != 1 {
		t.Fatalf("the undelivered result was not kept; the spool holds %d", spool.Len())
	}

	// The next session, three seconds later, works.
	panel.refuse = false
	second := panel.session(t, spool, true)
	second.offer(time.Now())
	if len(panel.received) != 1 || panel.received[0] != "attempt-1" {
		t.Fatalf("the next session offered %v, expected the one answer", panel.received)
	}
	if spool.Len() != 0 {
		t.Fatalf("the acknowledged result did not leave the spool; %d remain", spool.Len())
	}

	// Exactly once: a third session has nothing left to say about that attempt.
	panel.session(t, spool, true).offer(time.Now())
	if len(panel.received) != 1 {
		t.Fatalf("the settled result was offered again: %v", panel.received)
	}
}

// TestASpooledResultOutlivesTheProcessThatProducedIt covers the reboot in the
// middle: the answer is on disk before it is sent, so a new process finds it.
func TestASpooledResultOutlivesTheProcessThatProducedIt(t *testing.T) {
	dir := t.TempDir()
	panel := &fakePanel{answer: agentv1.TaskResultAck_STATUS_SETTLED, refuse: true}
	first := openResultSpool(t, dir, ResultSpoolSize, ResultSpoolBytes)
	panel.session(t, first, true).deliver(finishedTask("attempt-2"))

	// A new process of the agent over the same state directory.
	panel.refuse = false
	second := openResultSpool(t, dir, ResultSpoolSize, ResultSpoolBytes)
	if second.Len() != 1 {
		t.Fatalf("the new process found %d spooled results, expected one", second.Len())
	}
	delivery := panel.session(t, second, true)
	delivery.offer(time.Now())
	if len(panel.received) != 1 || panel.received[0] != "attempt-2" {
		t.Fatalf("the returning process offered %v", panel.received)
	}
	pending := second.Pending(time.Now())
	if len(pending) != 0 {
		t.Fatalf("%d results still wait after the panel took the answer", len(pending))
	}
}

// TestAResultThePanelRefusesAsStaleIsNotOfferedAgain: a job cancelled or taken
// over meanwhile will never take this answer, and the host must not knock for
// ever. The refusal is final and says so.
func TestAResultThePanelRefusesAsStaleIsNotOfferedAgain(t *testing.T) {
	dir := t.TempDir()
	panel := &fakePanel{answer: agentv1.TaskResultAck_STATUS_REJECTED_STALE, refuse: true}
	spool := openResultSpool(t, dir, ResultSpoolSize, ResultSpoolBytes)
	panel.session(t, spool, true).deliver(finishedTask("attempt-3"))

	panel.refuse = false
	panel.session(t, spool, true).offer(time.Now())
	if len(panel.received) != 1 {
		t.Fatalf("the refused result was offered %d times in one session", len(panel.received))
	}
	if spool.Len() != 0 {
		t.Fatalf("the refused result stayed in the spool; %d remain", spool.Len())
	}
	for session := 0; session < 3; session++ {
		panel.session(t, spool, true).offer(time.Now())
	}
	if len(panel.received) != 1 {
		t.Fatalf("the refused result came back: %v", panel.received)
	}
	if left, err := os.ReadDir(filepath.Join(dir, resultSpoolDirName)); err != nil {
		t.Fatal(err)
	} else if len(left) != 0 {
		t.Fatalf("the spool directory still holds %d files", len(left))
	}
}

// TestAResultNobodyTookIsGivenUpWhenItIsTooOld bounds the other way: a host cut
// off for longer than the idempotency journal remembers the operation has
// nothing left to settle, and it says so rather than offering for ever.
func TestAResultNobodyTookIsGivenUpWhenItIsTooOld(t *testing.T) {
	dir := t.TempDir()
	spool, err := OpenResultSpool(dir, ResultSpoolSize, ResultSpoolBytes, time.Hour, quietLog())
	if err != nil {
		t.Fatal(err)
	}
	if err := spool.Enqueue(finishedTask("attempt-4")); err != nil {
		t.Fatal(err)
	}
	if pending := spool.Pending(time.Now()); len(pending) != 1 {
		t.Fatalf("a fresh result was given up straight away: %d", len(pending))
	}
	if pending := spool.Pending(time.Now().Add(2 * time.Hour)); len(pending) != 0 {
		t.Fatalf("%d results outlived the bound", len(pending))
	}
	if spool.Len() != 0 || spool.Bytes() != 0 {
		t.Fatalf("the spool still accounts for %d results and %d bytes", spool.Len(), spool.Bytes())
	}
	// And it is gone from disk, not only from the list.
	left, err := os.ReadDir(filepath.Join(dir, resultSpoolDirName))
	if err != nil {
		t.Fatal(err)
	}
	if len(left) != 0 {
		t.Fatalf("the spool directory still holds %d files", len(left))
	}
}

// TestTheSpoolGivesUpTheOldestAnswerWhenItIsFull: an outage must not fill the
// state directory of the host.
func TestTheSpoolGivesUpTheOldestAnswerWhenItIsFull(t *testing.T) {
	spool := openResultSpool(t, t.TempDir(), 3, ResultSpoolBytes)
	for _, id := range []string{"a", "b", "c", "d"} {
		if err := spool.Enqueue(finishedTask(id)); err != nil {
			t.Fatal(err)
		}
	}
	pending := spool.Pending(time.Now())
	if len(pending) != 3 {
		t.Fatalf("the spool holds %d results over a bound of 3", len(pending))
	}
	if pending[0].GetTaskId() != "b" || pending[2].GetTaskId() != "d" {
		t.Fatalf("the spool did not give up the oldest: %s..%s",
			pending[0].GetTaskId(), pending[2].GetTaskId())
	}
}

// TestASecondAnswerForTheSameAttemptReplacesTheFirst: the agent offers a
// result again on every session, and a spool keyed by the attempt must hold
// one copy of it, not one per offer.
func TestASecondAnswerForTheSameAttemptReplacesTheFirst(t *testing.T) {
	spool := openResultSpool(t, t.TempDir(), ResultSpoolSize, ResultSpoolBytes)
	for range 3 {
		if err := spool.Enqueue(finishedTask("attempt-5")); err != nil {
			t.Fatal(err)
		}
	}
	if spool.Len() != 1 {
		t.Fatalf("the spool holds %d copies of one answer", spool.Len())
	}
}

// TestAPanelThatDoesNotAcknowledgeResultsFreesThemOnTheSend keeps the promise
// that a panel and an agent one release apart work together: against a panel
// that says nothing about a result, the send is the whole confirmation there
// is, and holding the answer back would deliver it twice at every session.
func TestAPanelThatDoesNotAcknowledgeResultsFreesThemOnTheSend(t *testing.T) {
	spool := openResultSpool(t, t.TempDir(), ResultSpoolSize, ResultSpoolBytes)
	panel := &fakePanel{}
	panel.session(t, spool, false).deliver(finishedTask("attempt-6"))
	if len(panel.received) != 1 {
		t.Fatalf("the result was delivered %d times", len(panel.received))
	}
	if spool.Len() != 0 {
		t.Fatalf("the sent result waits for an answer that will never come; %d remain", spool.Len())
	}
}

// TestAnAttemptIdentifierThatIsNotOneIsNotWrittenToDisk: the file name of a
// spooled answer comes from the panel, and a path must not.
func TestAnAttemptIdentifierThatIsNotOneIsNotWrittenToDisk(t *testing.T) {
	dir := t.TempDir()
	spool := openResultSpool(t, dir, ResultSpoolSize, ResultSpoolBytes)
	for _, bad := range []string{"", "../../etc/passwd", "a/b", "a b"} {
		if err := spool.Enqueue(finishedTask(bad)); err == nil {
			t.Fatalf("the spool took the attempt %q", bad)
		}
	}
	if spool.Len() != 0 {
		t.Fatalf("the spool holds %d refused results", spool.Len())
	}
}

// A task started in one session finishes in a goroutine that holds that
// session's spool, and the next session used to open its own: the directory is
// read once, at the open, so the file the old goroutine wrote was invisible
// until the agent restarted - and the time-to-live could take it first. The
// panel meanwhile held the job leased over a host where the change had already
// been made, which is the one case this spool exists for (audit of 6c38561,
// TR-05).
func TestEverySessionOfAProcessSharesOneResultSpool(t *testing.T) {
	dir := t.TempDir()
	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	resetProcessResultSpool()
	t.Cleanup(resetProcessResultSpool)

	first, err := ProcessResultSpool(dir, 10, 1<<20, time.Hour, log)
	if err != nil {
		t.Fatal(err)
	}
	// The session that follows asks for the spool of the process and is given
	// the same object, not a second reading of the directory.
	second, err := ProcessResultSpool(dir, 10, 1<<20, time.Hour, log)
	if err != nil {
		t.Fatal(err)
	}
	if first != second {
		t.Fatal("two sessions of one process hold two spools over one directory")
	}

	// A result written through the first - which is what a task of the previous
	// session does - is offered by the second.
	if err := first.Enqueue(&agentv1.TaskResult{TaskId: "task-after-the-reconnect"}); err != nil {
		t.Fatal(err)
	}
	pending := second.Pending(time.Now())
	if len(pending) != 1 || pending[0].GetTaskId() != "task-after-the-reconnect" {
		t.Fatalf("the session that followed offers %d results: %+v", len(pending), pending)
	}
}
