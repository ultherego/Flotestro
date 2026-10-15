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

// An answer spooled without a key cannot be told apart by one, and refusing
// there would strand every answer of a host whose spool predates the key: the
// attempt identifier is all there is for those.
//
// An answer that carries one is a different case, and it changed on 11.10.
// The comparison used to be made only when *both* sides carried a key, which
// made an absent key on the acknowledgement a way past it - and the field is
// filled by the relay. The panel does not have that excuse: it echoes
// result.GetIdempotencyKey() unconditionally (agent_service.go:822), so an
// acknowledgement with no key, for an answer that has one, is not an older
// half. It is a field somebody took out. The spool is the only durable copy
// of work already carried out on the host, so it is refused.
func TestWhatAnAcknowledgementWithoutAKeyFreesAndWhatItDoesNot(t *testing.T) {
	for _, c := range []struct {
		name     string
		spooled  string
		acked    string
		expected int
		refused  bool
		why      string
	}{
		{
			name: "neither carries one", spooled: "", acked: "", expected: 0,
			why: "an older half on both sides; the attempt identifier is all there is",
		},
		{
			name: "the answer has none", spooled: "", acked: "operation-a", expected: 0,
			why: "nothing to compare the panel's key against",
		},
		{
			name: "the acknowledgement has none", spooled: "operation-a", acked: "",
			expected: 1, refused: true,
			why: "the panel echoes the key of the answer; an empty one came from somewhere else",
		},
	} {
		t.Run(c.name, func(t *testing.T) {
			spool := openResultSpool(t, t.TempDir(), ResultSpoolSize, ResultSpoolBytes)
			if err := spool.Enqueue(&agentv1.TaskResult{
				TaskId: "attempt-1", IdempotencyKey: c.spooled}); err != nil {
				t.Fatal(err)
			}
			err := spool.Acknowledge(&agentv1.TaskResultAck{
				TaskId: "attempt-1", IdempotencyKey: c.acked})
			switch {
			case c.refused && err == nil:
				t.Errorf("the acknowledgement was taken and it should have been refused: %s", c.why)
			case !c.refused && err != nil:
				t.Errorf("the acknowledgement was refused (%v) and it should have been taken: %s", err, c.why)
			}
			if spool.Len() != c.expected {
				t.Errorf("the spool holds %d answers, want %d: %s", spool.Len(), c.expected, c.why)
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

// A status this agent does not know does not free the result.
//
// The switch over the acknowledgement's status used to choose a log line and
// nothing else: every answer, STATUS_UNSPECIFIED included, fell through to the
// release. The zero value of that enum is also what a field nobody set looks
// like, so "the panel said nothing about what it did with this" read as "the
// panel took it". Keeping the copy costs a duplicate delivery, which the
// idempotency key makes harmless; releasing it costs work already carried out
// on the host.
func TestAnAcknowledgementWithAStatusTheAgentDoesNotKnowFreesNothing(t *testing.T) {
	for _, status := range []agentv1.TaskResultAck_Status{
		agentv1.TaskResultAck_STATUS_UNSPECIFIED,
		// A status from a newer panel: refusing it keeps the answer, which is
		// the safe direction for a protocol that may grow.
		agentv1.TaskResultAck_Status(99),
	} {
		t.Run(status.String(), func(t *testing.T) {
			spool := openResultSpool(t, t.TempDir(), ResultSpoolSize, ResultSpoolBytes)
			panel := &fakePanel{}
			delivery := panel.session(t, spool, true)
			result := &agentv1.TaskResult{TaskId: "attempt-1", IdempotencyKey: "operation-a"}
			if err := spool.Enqueue(result); err != nil {
				t.Fatalf("the result was not spooled: %v", err)
			}

			delivery.acknowledge(&agentv1.TaskResultAck{
				TaskId:         "attempt-1",
				IdempotencyKey: "operation-a",
				Status:         status,
			})
			if spool.Len() != 1 {
				t.Fatalf("the answer was freed by an acknowledgement of status %s", status)
			}

			// And the one it does know still frees it, so this is a narrowing
			// and not a spool that has stopped answering.
			delivery.acknowledge(&agentv1.TaskResultAck{
				TaskId:         "attempt-1",
				IdempotencyKey: "operation-a",
				Status:         agentv1.TaskResultAck_STATUS_SETTLED,
			})
			if spool.Len() != 0 {
				t.Error("a settled acknowledgement did not free the answer")
			}
		})
	}
}
