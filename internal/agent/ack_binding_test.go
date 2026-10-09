package agent

import (
	"strings"
	"testing"

	agentv1 "github.com/ultherego/flotestro/internal/genproto/flotestro/agent/v1"
)

// The spool is the only durable copy of work already carried out on the host,
// and the attempt identifier alone used to free it. So an acknowledgement that
// named a task deleted whatever was spooled under it - the answer of another
// attempt of the same operation, one replayed from an earlier session, or one
// from anybody who can put a frame into the session. The relay terminates TLS,
// so "anybody in the session" is not only the panel.
//
// The panel echoes the key the host performed the operation under. These hold
// the spool to comparing the two.
func TestAnAcknowledgementOfAnotherOperationFreesNothing(t *testing.T) {
	spool := openResultSpool(t, t.TempDir(), ResultSpoolSize, ResultSpoolBytes)
	result := &agentv1.TaskResult{TaskId: "attempt-1", IdempotencyKey: "operation-a"}
	if err := spool.Enqueue(result); err != nil {
		t.Fatalf("the result was not spooled: %v", err)
	}
	if spool.Len() != 1 {
		t.Fatalf("the spool holds %d answers before the acknowledgement", spool.Len())
	}

	// The same attempt, another operation: this is the shape of a replay. The
	// return value is deliberately not read here - this assertion is about what
	// the spool still holds, so it stands against the version of this method
	// that answered nothing and freed the answer anyway.
	spool.Acknowledge(&agentv1.TaskResultAck{
		TaskId:         "attempt-1",
		IdempotencyKey: "operation-b",
		Status:         agentv1.TaskResultAck_STATUS_SETTLED,
	})
	if spool.Len() != 1 {
		t.Fatal("the answer was freed by an acknowledgement about another operation")
	}

	// The real one frees it.
	if err := spool.Acknowledge(&agentv1.TaskResultAck{
		TaskId:         "attempt-1",
		IdempotencyKey: "operation-a",
		Status:         agentv1.TaskResultAck_STATUS_SETTLED,
	}); err != nil {
		t.Fatalf("the acknowledgement of the answer held was refused: %v", err)
	}
	if spool.Len() != 0 {
		t.Error("the answer stayed spooled after it was acknowledged")
	}
}

// The refusal says which operation was held and which was named, because an
// operator reading it has to be able to tell a replay from a mismatch of its
// own making.
func TestTheRefusalNamesBothOperations(t *testing.T) {
	spool := openResultSpool(t, t.TempDir(), ResultSpoolSize, ResultSpoolBytes)
	if err := spool.Enqueue(&agentv1.TaskResult{
		TaskId: "attempt-1", IdempotencyKey: "operation-a"}); err != nil {
		t.Fatal(err)
	}
	err := spool.Acknowledge(&agentv1.TaskResultAck{
		TaskId: "attempt-1", IdempotencyKey: "operation-b"})
	if err == nil {
		t.Fatal("an acknowledgement naming another operation was accepted")
	}
	for _, want := range []string{"attempt-1", "operation-a", "operation-b"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("the refusal does not say %q: %v", want, err)
		}
	}
}

// Freeing nothing is not a refusal: a panel that acknowledges nothing has the
// answer freed by the send, and a second acknowledgement arrives after the
// first already freed it. Neither may be reported as a frame to distrust.
func TestAnAcknowledgementOfNothingIsNotARefusal(t *testing.T) {
	spool := openResultSpool(t, t.TempDir(), ResultSpoolSize, ResultSpoolBytes)
	if err := spool.Acknowledge(&agentv1.TaskResultAck{
		TaskId: "an attempt nothing is held for", IdempotencyKey: "operation-a",
	}); err != nil {
		t.Errorf("an acknowledgement of an empty spool was reported as a refusal: %v", err)
	}
}

// A half with no key cannot be told apart this way, and refusing there would
// strand every answer of a host whose spool predates this: the comparison is
// made when both sides carry a key, and the attempt identifier is all there is
// otherwise.
func TestAnAcknowledgementWithoutAKeyStillFreesTheAnswer(t *testing.T) {
	for _, c := range []struct {
		name     string
		spooled  string
		acked    string
		expected int
	}{
		{"neither carries one", "", "", 0},
		{"the answer has none", "", "operation-a", 0},
		{"the acknowledgement has none", "operation-a", "", 0},
	} {
		t.Run(c.name, func(t *testing.T) {
			spool := openResultSpool(t, t.TempDir(), ResultSpoolSize, ResultSpoolBytes)
			if err := spool.Enqueue(&agentv1.TaskResult{
				TaskId: "attempt-1", IdempotencyKey: c.spooled}); err != nil {
				t.Fatal(err)
			}
			if err := spool.Acknowledge(&agentv1.TaskResultAck{
				TaskId: "attempt-1", IdempotencyKey: c.acked}); err != nil {
				t.Fatalf("the acknowledgement was refused: %v", err)
			}
			if spool.Len() != c.expected {
				t.Errorf("the spool holds %d answers, want %d", spool.Len(), c.expected)
			}
		})
	}
}

// What the spool knows has to survive a restart, because the answer it guards
// does: the key is read back from the file the agent wrote.
func TestTheKeyOfASpooledAnswerSurvivesARestart(t *testing.T) {
	dir := t.TempDir()
	spool := openResultSpool(t, dir, ResultSpoolSize, ResultSpoolBytes)
	if err := spool.Enqueue(&agentv1.TaskResult{
		TaskId: "attempt-1", IdempotencyKey: "operation-a"}); err != nil {
		t.Fatal(err)
	}
	reopened := openResultSpool(t, dir, ResultSpoolSize, ResultSpoolBytes)
	if reopened.Len() != 1 {
		t.Fatalf("the reopened spool holds %d answers", reopened.Len())
	}
	if err := reopened.Acknowledge(&agentv1.TaskResultAck{
		TaskId: "attempt-1", IdempotencyKey: "operation-b"}); err == nil {
		t.Error("after a restart the spool no longer knows which operation its answer is about")
	}
}
