package relay

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"testing"
	"time"

	agentv1 "github.com/ultherego/flotestro/internal/genproto/flotestro/agent/v1"
	"github.com/ultherego/flotestro/internal/relay/spool"
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

// signed attaches an envelope of the given session and sequence, as a host
// behind a relay does.
func signed(message *agentv1.AgentMessage, session string, sequence uint64) *agentv1.AgentMessage {
	message.Envelope = &agentv1.RelayedEnvelope{
		SchemaVersion: 2, HostId: "host-1", SessionId: session, Sequence: sequence,
	}
	return message
}

// newTestRelay assembles a relay over a temporary spool. It connects to
// nothing: the tests below drive the spool through the relay's own methods.
func newTestRelay(t *testing.T, options spool.Options) *Relay {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	relay, err := New(Options{
		UpstreamURL: "https://centre.invalid:8443",
		Identity:    tls.Certificate{PrivateKey: key},
		TrustPool:   x509.NewCertPool(),
		SpoolDir:    t.TempDir(),
		Spool:       options,
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = relay.Close() })
	return relay
}

// TestARelayWithoutASpoolDoesNotComeUp guards the fail-closed start: a
// relay that cannot keep what it takes must not take it.
func TestARelayWithoutASpoolDoesNotComeUp(t *testing.T) {
	if _, err := New(Options{UpstreamURL: "https://centre.invalid:8443"}); err == nil {
		t.Fatal("a relay without a spool directory came up")
	}
}

// TestTheSpoolHasALimit guards the requirement of the document: the spool of a
// relay is bounded.
func TestTheSpoolHasALimit(t *testing.T) {
	relay := newTestRelay(t, spool.Options{MaxBytes: 2000, CriticalReserveBytes: 500})

	accepted := 0
	for i := uint64(1); i <= 100; i++ {
		if relay.keep("host-1", signed(heartbeat(1), "session-a", i)) == nil {
			break
		}
		accepted++
	}
	if accepted == 0 || accepted == 100 {
		t.Fatalf("%d messages were accepted under a limit of 2000 bytes", accepted)
	}
	_, state, _ := relay.Stats()
	if state.Bytes > state.MaxBytes {
		t.Errorf("the spool exceeded the limit: %d > %d", state.Bytes, state.MaxBytes)
	}
	// The drop has to be counted: a silent loss of results looks to the panel
	// like jobs that are still running.
	if state.Dropped == 0 {
		t.Error("the drop was not recorded")
	}
	if !state.Critical {
		t.Error("a spool that refused a control message does not say it is critical")
	}
}

// TestTheSpoolSendsBackInTheSessionOfTheHost checks that the messages come
// back to the right session.
func TestTheSpoolSendsBackInTheSessionOfTheHost(t *testing.T) {
	relay := newTestRelay(t, spool.Options{})
	for _, entry := range []struct {
		host    string
		session string
		mark    int64
	}{{"host-1", "a", 1}, {"host-2", "b", 2}, {"host-1", "a", 3}} {
		if relay.keep(entry.host, signed(heartbeat(entry.mark), entry.session, uint64(entry.mark))) == nil {
			t.Fatal("the message was refused")
		}
	}

	records, err := relay.spool.Next("host-1", 0)
	if err != nil {
		t.Fatal(err)
	}
	if len(records) != 2 {
		t.Fatalf("%d messages of host-1 are due, expected 2", len(records))
	}
	for _, record := range records {
		message, err := record.Message()
		if err != nil {
			t.Fatal(err)
		}
		if mark := message.GetHeartbeat().GetSentAt().AsTime().Unix(); mark == 2 {
			t.Error("a message of another host appeared in the session of host-1")
		}
	}
	// The message of the second host waits for its own session.
	if hosts := relay.spool.Hosts(); len(hosts) != 2 {
		t.Errorf("the spool names %v, expected both hosts", hosts)
	}
}

// TestAMessageDisappearsOnlyOnTheAcknowledgement guards the order of the
// document: a record leaves the spool on the application acknowledgement of
// the panel, not on a send.
func TestAMessageDisappearsOnlyOnTheAcknowledgement(t *testing.T) {
	relay := newTestRelay(t, spool.Options{})
	record := relay.keep("host-1", signed(heartbeat(1), "session-a", 4))
	if record == nil {
		t.Fatal("the message was refused")
	}
	if _, err := relay.spool.Next("host-1", 0); err != nil {
		t.Fatal(err)
	}
	if _, state, _ := relay.Stats(); state.Messages != 1 || state.Inflight != 1 {
		t.Errorf("after the send the spool holds %d messages with %d in flight, expected 1 and 1",
			state.Messages, state.Inflight)
	}
	// An acknowledgement of another sequence changes nothing.
	relay.acknowledge("host-1", &agentv1.MessageAck{HostId: "host-1", SessionId: "session-a", Sequence: 3})
	if _, state, _ := relay.Stats(); state.Messages != 1 {
		t.Error("an acknowledgement of another sequence removed the record")
	}
	// One naming another host is ignored: the session is bound to one
	// identity.
	relay.acknowledge("host-1", &agentv1.MessageAck{HostId: "host-2", SessionId: "session-a", Sequence: 4})
	if _, state, _ := relay.Stats(); state.Messages != 1 {
		t.Error("an acknowledgement naming another host removed the record")
	}
	relay.acknowledge("host-1", &agentv1.MessageAck{HostId: "host-1", SessionId: "session-a", Sequence: 4})
	if _, state, _ := relay.Stats(); state.Messages != 0 {
		t.Error("the acknowledged message stayed in the spool")
	}
}

// TestAJobAfterItsTTLIsNotForwarded answers the requirement from the document:
// the relay buffers results but does not carry a job out after its TTL.
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

// TestHelloIsNeverSpooled guards that a session's opening is not carried into
// another session: the centre rejects a stream that starts otherwise, and a
// Hello from the spool would close the stream it was sent on.
func TestHelloIsNeverSpooled(t *testing.T) {
	relay := newTestRelay(t, spool.Options{})
	hello := &agentv1.AgentMessage{Payload: &agentv1.AgentMessage_Hello{Hello: &agentv1.Hello{AgentVersion: "test"}}}
	if relay.keep("host-1", signed(hello, "session-a", 1)) != nil {
		t.Fatal("a Hello was written to the spool")
	}
}

// TestTheUpstreamStateIsNamed guards the words of the heartbeat.
func TestTheUpstreamStateIsNamed(t *testing.T) {
	relay := newTestRelay(t, spool.Options{})
	if state := relay.UpstreamState(); state != UpstreamReconnecting {
		t.Fatalf("a relay that never reached the centre reports %q", state)
	}
	relay.keep("host-1", signed(heartbeat(1), "session-a", 1))
	if state := relay.UpstreamState(); state != UpstreamBuffering {
		t.Fatalf("a relay with a spooled message and no link reports %q", state)
	}
	relay.upstream.Store(true)
	if state := relay.UpstreamState(); state != UpstreamConnected {
		t.Fatalf("a relay with a link reports %q", state)
	}
	if relay.InstanceID() == "" {
		t.Fatal("the relay has no instance identifier")
	}
}
