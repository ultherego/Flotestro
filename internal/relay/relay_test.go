package relay

import (
	"testing"
	"time"

	agentv1 "github.com/ultherego/flotestro/internal/genproto/flotestro/agent/v1"
	"google.golang.org/protobuf/types/known/timestamppb"
)

// heartbeat builds a message recognisable by its timestamp: here it serves
// only to check whose message came back in whose session.
func heartbeat(mark int64) *agentv1.AgentMessage {
	return &agentv1.AgentMessage{
		Payload: &agentv1.AgentMessage_Heartbeat{
			Heartbeat: &agentv1.Heartbeat{SentAt: timestamppb.New(time.Unix(mark, 0))},
		},
	}
}

// TestTheBufferHasALimit guards the requirement of the document: the buffer of
// a relay is bounded. A relay in a cut-off site must not grow until the disk
// is exhausted, because that takes from the site what works locally as well.
func TestTheBufferHasALimit(t *testing.T) {
	buffer := NewBuffer(200)

	accepted := 0
	for i := 0; i < 100; i++ {
		if err := buffer.Add("host-1", heartbeat(1)); err != nil {
			break
		}
		accepted++
	}
	if accepted == 0 {
		t.Fatal("the buffer accepted not a single message")
	}

	state := buffer.Stats()
	if state.Bytes > state.MaxBytes {
		t.Errorf("the buffer exceeded the limit: %d > %d", state.Bytes, state.MaxBytes)
	}
	if err := buffer.Add("host-1", heartbeat(1)); err == nil {
		t.Error("a full buffer accepted another message")
	}
	// The drop has to be counted: a silent loss of results looks to the panel
	// like jobs that are still running.
	if buffer.Stats().Dropped == 0 {
		t.Error("the drop was not recorded")
	}
}

// TestTheBufferSendsBackInTheSessionOfTheHost checks that the messages come
// back to the right session. The centre binds a stream to one identity, so the
// result of one host must not go in the session of another.
func TestTheBufferSendsBackInTheSessionOfTheHost(t *testing.T) {
	buffer := NewBuffer(1 << 20)
	for _, entry := range []struct {
		host string
		mark int64
	}{{"host-1", 1}, {"host-2", 2}, {"host-1", 3}} {
		if err := buffer.Add(entry.host, heartbeat(entry.mark)); err != nil {
			t.Fatal(err)
		}
	}

	taken := 0
	for {
		message, ok := buffer.TakeFor("host-1")
		if !ok {
			break
		}
		if mark := message.GetHeartbeat().GetSentAt().AsTime().Unix(); mark == 2 {
			t.Error("a message of another host appeared in the session of host-1")
		}
		buffer.CommitFor("host-1")
		taken++
	}
	if taken != 2 {
		t.Errorf("%d messages of host-1 were sent back, expected 2", taken)
	}
	// The message of the second host waits for its own session.
	if state := buffer.Stats(); state.Messages != 1 {
		t.Errorf("%d messages were left in the buffer, expected 1", state.Messages)
	}
}

// TestAMessageDisappearsOnlyAfterItIsSent guards the order: a peek does not
// remove a message, because a broken link halfway would mean a lost result.
func TestAMessageDisappearsOnlyAfterItIsSent(t *testing.T) {
	buffer := NewBuffer(1 << 20)
	if err := buffer.Add("host-1", heartbeat(1)); err != nil {
		t.Fatal(err)
	}
	if _, ok := buffer.TakeFor("host-1"); !ok {
		t.Fatal("there is no message in the buffer")
	}
	if buffer.Stats().Messages != 1 {
		t.Error("the peek removed the message before the send was confirmed")
	}
	buffer.CommitFor("host-1")
	if buffer.Stats().Messages != 0 {
		t.Error("a confirmed message stayed in the buffer")
	}
}

// TestAJobAfterItsTTLIsNotForwarded answers the requirement from the document:
// the relay buffers results but does not carry a job out after its TTL.
// Forwarding an expired job is ordering work nobody is asking for any more -
// and the host would carry it out, because it does not know it waited on a
// shelf.
func TestAJobAfterItsTTLIsNotForwarded(t *testing.T) {
	overdue := &agentv1.TaskEnvelope{
		TaskId:    "job-1",
		ExpiresAt: timestamppb.New(time.Now().Add(-time.Minute)),
	}
	if !expired(overdue) {
		t.Error("a job past its deadline was not recognised")
	}

	valid := &agentv1.TaskEnvelope{
		TaskId:    "job-2",
		ExpiresAt: timestamppb.New(time.Now().Add(10 * time.Minute)),
	}
	if expired(valid) {
		t.Error("a valid job was treated as expired")
	}

	// A job without a deadline is not expired: a missing deadline is a missing
	// requirement rather than a deadline in the past.
	if expired(&agentv1.TaskEnvelope{TaskId: "job-3"}) {
		t.Error("a job without a deadline was skipped")
	}
}
