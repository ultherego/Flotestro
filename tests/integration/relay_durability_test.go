//go:build integration

package integration

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"io"
	"log/slog"
	"net"
	"net/http"
	"sync"
	"testing"
	"time"

	"connectrpc.com/connect"
	"github.com/google/uuid"
	"golang.org/x/net/http2"

	agentv1 "github.com/ultherego/flotestro/internal/genproto/flotestro/agent/v1"
	"github.com/ultherego/flotestro/internal/genproto/flotestro/agent/v1/agentv1connect"
	"github.com/ultherego/flotestro/internal/pki"
	"github.com/ultherego/flotestro/internal/relay"
	"github.com/ultherego/flotestro/internal/relay/spool"
)

// Chapter 16 of the containerisation document: a record leaves the spool when
// the panel says it committed, signed envelope or not, and on nothing else.

// playedCentre is the panel as the relay sees it: it takes the messages and
// acknowledges them only when the test lets it.
type playedCentre struct {
	agentv1connect.UnimplementedAgentServiceHandler

	mu          sync.Mutex
	results     []*agentv1.AgentMessage
	acknowledge bool
	named       bool
	arrived     chan *agentv1.AgentMessage
}

func newPlayedCentre() *playedCentre {
	return &playedCentre{arrived: make(chan *agentv1.AgentMessage, 16)}
}

// answers settles whether the centre acknowledges what it consumes and whether
// it names the record; a centre of the previous release does neither.
func (c *playedCentre) answers(acknowledge, named bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.acknowledge, c.named = acknowledge, named
}

func (c *playedCentre) policy() (bool, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.acknowledge, c.named
}

// delivered lists the job results the centre consumed, in order.
func (c *playedCentre) delivered() []*agentv1.AgentMessage {
	c.mu.Lock()
	defer c.mu.Unlock()
	return append([]*agentv1.AgentMessage(nil), c.results...)
}

func (c *playedCentre) Ping(context.Context,
	*connect.Request[agentv1.PingRequest]) (*connect.Response[agentv1.PingResponse], error) {
	return connect.NewResponse(&agentv1.PingResponse{}), nil
}

func (c *playedCentre) Connect(_ context.Context,
	stream *connect.BidiStream[agentv1.AgentMessage, agentv1.ServerMessage]) error {
	hostID := stream.RequestHeader().Get("Flotestro-Relay-Host")
	for {
		message, err := stream.Receive()
		if err != nil {
			return nil
		}
		if message.GetTaskResult() == nil {
			continue
		}
		c.mu.Lock()
		c.results = append(c.results, message)
		c.mu.Unlock()
		select {
		case c.arrived <- message:
		default:
		}
		acknowledge, named := c.policy()
		if !acknowledge {
			// The panel died between the write to the socket and the commit.
			continue
		}
		ack := &agentv1.MessageAck{HostId: hostID}
		if named {
			ack.RelayMessageId = message.GetRelayMessageId()
		}
		if err := stream.Send(&agentv1.ServerMessage{
			Payload: &agentv1.ServerMessage_MessageAck{MessageAck: ack},
		}); err != nil {
			return nil
		}
	}
}

// awaitResult waits for the next job result the centre consumes.
func (c *playedCentre) awaitResult(t *testing.T, limit time.Duration) *agentv1.AgentMessage {
	t.Helper()
	select {
	case message := <-c.arrived:
		return message
	case <-time.After(limit):
		t.Fatalf("no job result reached the centre within %s", limit)
		return nil
	}
}

// fleet is the certificate authority of a site played in this process: it
// issues the centre's listener, the relay and the host.
type fleet struct {
	ca   *pki.CA
	pool *x509.CertPool
}

func newFleet(t *testing.T) *fleet {
	t.Helper()
	ca, err := pki.Init(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(ca.PEM) {
		t.Fatal("the certificate of the authority was not taken into the trust pool")
	}
	return &fleet{ca: ca, pool: pool}
}

// listener issues a server certificate for the loopback and returns the TLS
// configuration of a listener that demands a certificate of the fleet.
func (f *fleet) listener(t *testing.T) *tls.Config {
	t.Helper()
	certPEM, keyPEM, err := f.ca.IssueServerCert(nil, []net.IP{net.ParseIP("127.0.0.1")})
	if err != nil {
		t.Fatal(err)
	}
	pair, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		t.Fatal(err)
	}
	return &tls.Config{
		Certificates: []tls.Certificate{pair},
		ClientAuth:   tls.RequireAndVerifyClientCert,
		ClientCAs:    f.pool,
		MinVersion:   tls.VersionTLS13,
		NextProtos:   []string{"h2"},
	}
}

// identity issues the certificate of a relay or of a host.
func (f *fleet) identity(t *testing.T, kind, id string) tls.Certificate {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	// No network names on either identity: the listeners of this test carry a
	// server certificate of their own, and a relay may not hold a loopback name.
	csr := relayCSR(t, key, id, nil)
	var issued *pki.IssuedCert
	if kind == "relay" {
		issued, err = f.ca.SignRelayCSR(csr, id)
	} else {
		issued, err = f.ca.SignAgentCSR(csr, id)
	}
	if err != nil {
		t.Fatal(err)
	}
	pair, _ := tlsPair(t, key, issued.PEM)
	return pair
}

// centreHandler mounts the played centre where a panel serves it.
func centreHandler(centre *playedCentre) http.Handler {
	mux := http.NewServeMux()
	path, handler := agentv1connect.NewAgentServiceHandler(centre)
	mux.Handle(path, handler)
	return mux
}

// serveTLS starts a listener of the fleet and returns its address.
func serveTLS(t *testing.T, config *tls.Config, handler http.Handler) string {
	t.Helper()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	server := &http.Server{Handler: handler, TLSConfig: config}
	go func() { _ = server.ServeTLS(listener, "", "") }()
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = server.Shutdown(ctx)
	})
	return "https://" + listener.Addr().String()
}

// hostSession opens the session of a host towards the relay, the way an agent
// of the previous release does it: without the identity envelope.
func hostSession(t *testing.T, address string, identity tls.Certificate,
	pool *x509.CertPool) (*connect.BidiStreamForClient[agentv1.AgentMessage, agentv1.ServerMessage], func()) {
	t.Helper()
	client := agentv1connect.NewAgentServiceClient(&http.Client{Transport: &http2.Transport{
		TLSClientConfig: &tls.Config{
			Certificates: []tls.Certificate{identity},
			RootCAs:      pool,
			MinVersion:   tls.VersionTLS13,
		},
	}}, address, connect.WithGRPC())
	ctx, cancel := context.WithCancel(context.Background())
	stream := client.Connect(ctx)
	if err := stream.Send(&agentv1.AgentMessage{
		Payload: &agentv1.AgentMessage_Hello{Hello: &agentv1.Hello{AgentVersion: "0.53.0"}},
	}); err != nil {
		cancel()
		t.Fatalf("the host did not open its session through the relay: %v", err)
	}
	return stream, func() {
		_ = stream.CloseRequest()
		_ = stream.CloseResponse()
		cancel()
	}
}

// siteRelay assembles a relay over the given spool directory.
func siteRelay(t *testing.T, f *fleet, relayID, centre, dir string, options spool.Options) (*relay.Relay, string) {
	t.Helper()
	site, err := relay.New(relay.Options{
		UpstreamURL: centre,
		Identity:    f.identity(t, "relay", relayID),
		TrustPool:   f.pool,
		SpoolDir:    dir,
		Spool:       options,
		Log:         slog.New(slog.NewTextHandler(io.Discard, nil)),
	})
	if err != nil {
		t.Fatal(err)
	}
	address := serveTLS(t, f.listener(t), relay.WithClientCertificate(site.Handler()))
	return site, address
}

// jobResult is the message of an agent that does not sign the envelope: the
// ordinary state of a fleet in the middle of an upgrade.
func jobResult(taskID string) *agentv1.AgentMessage {
	return &agentv1.AgentMessage{Payload: &agentv1.AgentMessage_TaskResult{
		TaskResult: &agentv1.TaskResult{
			TaskId: taskID, IdempotencyKey: taskID,
			Status: agentv1.TaskResult_STATUS_SUCCEEDED, Message: "the unit was restarted",
		},
	}}
}

// TestAResultWithoutAnEnvelopeSurvivesAPanelThatNeverCommitted is the gap: the
// write to the socket used to free the record, so a restart lost the result.
func TestAResultWithoutAnEnvelopeSurvivesAPanelThatNeverCommitted(t *testing.T) {
	f := newFleet(t)
	hostID := uuid.NewString()
	centre := newPlayedCentre()
	centre.answers(false, false)
	address := serveTLS(t, f.listener(t), centreHandler(centre))
	dir := t.TempDir()
	// Long enough that nothing is given up on while the test runs: the bounded
	// wait of an old panel has a test of its own.
	options := spool.Options{Site: "lab", AckTimeout: 30 * time.Second}

	site, relayAddress := siteRelay(t, f, uuid.NewString(), address, dir, options)
	identity := f.identity(t, "host", hostID)
	stream, closeStream := hostSession(t, relayAddress, identity, f.pool)
	if err := stream.Send(jobResult("job-1")); err != nil {
		t.Fatalf("the result was not sent through the relay: %v", err)
	}
	first := centre.awaitResult(t, 20*time.Second)
	if first.GetRelayMessageId() == "" {
		t.Fatal("the relay forwarded a spooled message without the identifier the panel acknowledges it under")
	}
	if first.GetEnvelope() != nil {
		t.Fatal("the played agent signed an envelope; the gap is about the message that has none")
	}
	closeStream()
	if err := site.Close(); err != nil {
		t.Fatal(err)
	}

	// The relay restarts. What the panel did not confirm is still on the disk.
	waiting, err := spool.Open(dir, options)
	if err != nil {
		t.Fatal(err)
	}
	if items := waiting.Stats().Items; items != 1 {
		t.Fatalf("%d records survived the restart, expected the unacknowledged result", items)
	}
	if err := waiting.Close(); err != nil {
		t.Fatal(err)
	}

	// The panel is back and says what it consumed.
	centre.answers(true, true)
	again, relayAgain := siteRelay(t, f, uuid.NewString(), address, dir, options)
	t.Cleanup(func() { _ = again.Close() })
	stream, closeStream = hostSession(t, relayAgain, identity, f.pool)
	defer closeStream()
	second := centre.awaitResult(t, 20*time.Second)
	if second.GetTaskResult().GetTaskId() != "job-1" {
		t.Fatalf("the redelivered result names %q", second.GetTaskResult().GetTaskId())
	}
	if second.GetRelayMessageId() != first.GetRelayMessageId() {
		t.Errorf("the redelivery carries %q, the first delivery carried %q: the panel cannot tell they are one message",
			second.GetRelayMessageId(), first.GetRelayMessageId())
	}

	// The acknowledgement empties the spool, and nothing is carried a third
	// time: a redelivery is what an unconfirmed message earns, not a habit.
	deadline := time.Now().Add(20 * time.Second)
	for {
		_, state, _ := again.Stats()
		if state.Messages == 0 {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("%d records stayed in the spool after the acknowledgement", state.Messages)
		}
		time.Sleep(100 * time.Millisecond)
	}
	if err := stream.Send(&agentv1.AgentMessage{
		Payload: &agentv1.AgentMessage_Heartbeat{Heartbeat: &agentv1.Heartbeat{}},
	}); err != nil {
		t.Fatalf("the session did not survive the acknowledgement: %v", err)
	}
	time.Sleep(2 * time.Second)
	if delivered := centre.delivered(); len(delivered) != 2 {
		t.Errorf("the result reached the centre %d times, expected the delivery and one redelivery", len(delivered))
	}
}

// TestAPanelThatCannotNameARecordIsWaitedOutNotWaitedOn guards N-1: the relay
// must not fill its spool with records a previous release will never free.
func TestAPanelThatCannotNameARecordIsWaitedOutNotWaitedOn(t *testing.T) {
	f := newFleet(t)
	centre := newPlayedCentre()
	// A panel of the previous release: it consumes the message and says nothing
	// about it, because a message without an envelope has no sequence to name.
	centre.answers(false, false)
	address := serveTLS(t, f.listener(t), centreHandler(centre))
	options := spool.Options{Site: "lab", AckTimeout: 500 * time.Millisecond}

	site, relayAddress := siteRelay(t, f, uuid.NewString(), address, t.TempDir(), options)
	t.Cleanup(func() { _ = site.Close() })
	stream, closeStream := hostSession(t, relayAddress, f.identity(t, "host", uuid.NewString()), f.pool)
	defer closeStream()
	if err := stream.Send(jobResult("job-2")); err != nil {
		t.Fatalf("the result was not sent through the relay: %v", err)
	}
	centre.awaitResult(t, 20*time.Second)

	// The wait is four delivery attempts long; after it the record goes out the
	// way it did before the acknowledgement existed.
	deadline := time.Now().Add(30 * time.Second)
	for {
		_, state, _ := site.Stats()
		if state.Messages == 0 {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("%d records wait for an acknowledgement this panel cannot send", state.Messages)
		}
		time.Sleep(100 * time.Millisecond)
	}
	if err := stream.Send(&agentv1.AgentMessage{
		Payload: &agentv1.AgentMessage_Heartbeat{Heartbeat: &agentv1.Heartbeat{}},
	}); err != nil {
		t.Fatalf("the session of the host did not survive the fallback: %v", err)
	}
}
