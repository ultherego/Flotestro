package relay

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"sync"
	"sync/atomic"
	"time"

	"connectrpc.com/connect"
	"golang.org/x/net/http2"

	"github.com/google/uuid"

	"github.com/ultherego/flotestro/internal/endpoints"
	agentv1 "github.com/ultherego/flotestro/internal/genproto/flotestro/agent/v1"
	"github.com/ultherego/flotestro/internal/genproto/flotestro/agent/v1/agentv1connect"
	"github.com/ultherego/flotestro/internal/pki"
	"github.com/ultherego/flotestro/internal/relay/spool"
)

// The headers the relay attests a host's session with.
const (
	hostHeader            = "Flotestro-Relay-Host"
	hostFingerprintHeader = "Flotestro-Relay-Host-Fingerprint"
	hostSerialHeader      = "Flotestro-Relay-Host-Serial"
	hostCertificateHeader = "Flotestro-Relay-Host-Certificate"
)

// attestHost names the host and the certificate it presented on a call
// forwarded to the centre.
func attestHost(headers http.Header, hostID string, cert *x509.Certificate) {
	headers.Set(hostHeader, hostID)
	headers.Set(hostFingerprintHeader, hex.EncodeToString(pki.Fingerprint(cert)))
	if cert.SerialNumber != nil {
		headers.Set(hostSerialHeader, cert.SerialNumber.String())
	}
	headers.Set(hostCertificateHeader, base64.StdEncoding.EncodeToString(cert.Raw))
}

// Options describe the relay of a site.
type Options struct {
	// UpstreamURL is the address of the agent gateway in the centre.
	UpstreamURL string
	// UpstreamURLs are the remaining gateways in order of priority.
	UpstreamURLs []string
	// EnrollmentURL enables mediation in the registration of hosts.
	EnrollmentURL string
	// Identity is the identity of the relay towards the centre.
	Identity tls.Certificate
	// TrustPool verifies both the centre and the certificates of the agents:
	// one CA of the fleet covers both sides.
	TrustPool *x509.CertPool
	// SpoolDir is the directory of the durable spool: the messages of the agents
	// the centre has not yet confirmed it consumed.
	SpoolDir string
	// Spool bounds the spool and its classes. Site is the site of the
	// relay, named on every record.
	Spool spool.Options
	Log   *slog.Logger
}

// Relay mediates between the agents of a site and the centre.
type Relay struct {
	options Options
	client_ atomic.Pointer[centreClient]
	// gateways drives the choice of the gateway of the centre together with
	// the backoff and the class of an error.
	gateways *endpoints.Manager
	// current is the address of the gateway the relay speaks to now. It
	// changes on a switch, so it cannot be kept in options.
	current atomic.Pointer[string]
	spool   *spool.Spool
	// instanceID names this process of the relay: a fresh identifier at
	// every start, so that the panel reads a restart off its change.
	instanceID string
	log        *slog.Logger

	mu sync.RWMutex
	// sessions hold the cancel functions.
	sessions map[string]context.CancelFunc
	upstream atomic.Bool
	identity atomic.Pointer[relayMaterial]
}

// New assembles the relay.
func New(options Options) (*Relay, error) {
	log := options.Log
	if log == nil {
		log = slog.Default()
	}
	addresses := options.UpstreamURLs
	if len(addresses) == 0 {
		addresses = []string{options.UpstreamURL}
	}
	if options.SpoolDir == "" {
		return nil, errors.New("the relay needs a spool directory")
	}
	store, err := spool.Open(options.SpoolDir, options.Spool)
	if err != nil {
		return nil, fmt.Errorf("the spool of the relay: %w", err)
	}
	relay := &Relay{
		options: options, log: log,
		gateways:   endpoints.New(addresses, endpoints.MinBackoff, endpoints.MaxBackoff),
		spool:      store,
		instanceID: uuid.NewString(),
		sessions:   map[string]context.CancelFunc{},
	}
	first := addresses[0]
	relay.current.Store(&first)
	relay.identity.Store(&relayMaterial{
		cert: options.Identity, trust: options.TrustPool,
	})
	relay.client_.Store(&centreClient{
		client: clientToCentre(first, options.Identity, options.TrustPool),
	})
	if stats := store.Stats(); stats.Items > 0 {
		log.Info("the spool holds messages from before the start; they go out with the sessions of their hosts",
			"items", stats.Items, "bytes", stats.BytesUsed, "hosts", len(store.Hosts()))
	}
	return relay, nil
}

// Close flushes and closes the spool.
func (r *Relay) Close() error { return r.spool.Close() }

// InstanceID names this process of the relay.
func (r *Relay) InstanceID() string { return r.instanceID }

// relayMaterial holds the current certificate of the relay towards the
// centre.
type relayMaterial struct {
	cert  tls.Certificate
	trust *x509.CertPool
}

// centreClient wraps the client so that it can be swapped as a whole.
// atomic.Pointer requires a concrete type, and the client is an interface.
type centreClient struct {
	client agentv1connect.AgentServiceClient
}

// clientToCentre assembles the client of the agent service in the centre.
func clientToCentre(address string, identity tls.Certificate,
	trust *x509.CertPool) agentv1connect.AgentServiceClient {
	return agentv1connect.NewAgentServiceClient(
		&http.Client{Transport: &http2.Transport{
			TLSClientConfig: &tls.Config{
				Certificates: []tls.Certificate{identity},
				RootCAs:      trust,
				MinVersion:   tls.VersionTLS13,
			},
			// A broken WAN link does not show up as a send error: the data fit in the
			// buffer of the kernel and TCP retransmits them for more than a dozen
			// minutes.
			ReadIdleTimeout: 15 * time.Second,
			PingTimeout:     10 * time.Second,
		}},
		address,
		connect.WithGRPC(),
	)
}

// RefreshIdentity swaps the certificate the relay presents itself to the
// centre with.
func (r *Relay) RefreshIdentity(identity tls.Certificate, trust *x509.CertPool) {
	r.identity.Store(&relayMaterial{cert: identity, trust: trust})
	r.client_.Store(&centreClient{
		client: clientToCentre(*r.current.Load(), identity, trust),
	})
}

// switchGateway points the relay at another gateway of the centre.
func (r *Relay) switchGateway(address string) {
	material := r.identity.Load()
	r.current.Store(&address)
	r.client_.Store(&centreClient{
		client: clientToCentre(address, material.cert, material.trust),
	})
}

// Gateway returns the address of the centre the relay speaks to now.
func (r *Relay) Gateway() string { return *r.current.Load() }

// centre returns the current client of the agent service.
func (r *Relay) centre() agentv1connect.AgentServiceClient {
	return r.client_.Load().client
}

// Handler serves the connections of the agents. The relay exposes the same
// contract as the centre, so the agent needs no other client for it.
func (r *Relay) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.Handle(agentv1connect.NewAgentServiceHandler(r))
	// The registration of a host goes over the same port: a host in an isolated
	// site knows the address of the relay alone.
	if r.options.EnrollmentURL != "" {
		mux.Handle(r.EnrollmentHandler())
	}
	return mux
}

// RenewCertificate forwards the renewal of a certificate to the centre.
func (r *Relay) RenewCertificate(ctx context.Context,
	req *connect.Request[agentv1.RenewCertificateRequest],
) (*connect.Response[agentv1.RenewCertificateResponse], error) {
	cert, ok := clientCertificate(ctx)
	if !ok {
		return nil, connect.NewError(connect.CodeUnauthenticated, errors.New("no client certificate"))
	}
	hostID, err := pki.HostIDFromCert(cert)
	if err != nil {
		return nil, connect.NewError(connect.CodeUnauthenticated, err)
	}

	forwarded := connect.NewRequest(req.Msg)
	attestHost(forwarded.Header(), hostID, cert)
	response, err := r.centre().RenewCertificate(ctx, forwarded)
	if err != nil {
		// The renewal has to reach the centre; the buffer does not help here,
		// because the agent waits for an answer.
		return nil, err
	}
	return connect.NewResponse(response.Msg), nil
}

// RequestIdentityChallenge forwards the request for a renewal challenge to the
// centre, the way the renewal itself goes: the centre binds the challenge to
// the host the relay names and to this relay, and the host signs it into the
func (r *Relay) RequestIdentityChallenge(ctx context.Context,
	req *connect.Request[agentv1.IdentityChallengeRequest],
) (*connect.Response[agentv1.IdentityChallengeResponse], error) {
	cert, ok := clientCertificate(ctx)
	if !ok {
		return nil, connect.NewError(connect.CodeUnauthenticated, errors.New("no client certificate"))
	}
	hostID, err := pki.HostIDFromCert(cert)
	if err != nil {
		return nil, connect.NewError(connect.CodeUnauthenticated, err)
	}

	forwarded := connect.NewRequest(req.Msg)
	attestHost(forwarded.Header(), hostID, cert)
	response, err := r.centre().RequestIdentityChallenge(ctx, forwarded)
	if err != nil {
		return nil, err
	}
	return connect.NewResponse(response.Msg), nil
}

// FetchSecret forwards the fetch of a secret to the centre.
func (r *Relay) FetchSecret(ctx context.Context,
	req *connect.Request[agentv1.FetchSecretRequest],
) (*connect.Response[agentv1.FetchSecretResponse], error) {
	cert, ok := clientCertificate(ctx)
	if !ok {
		return nil, connect.NewError(connect.CodeUnauthenticated, errors.New("no client certificate"))
	}
	hostID, err := pki.HostIDFromCert(cert)
	if err != nil {
		return nil, connect.NewError(connect.CodeUnauthenticated, err)
	}

	forwarded := connect.NewRequest(req.Msg)
	attestHost(forwarded.Header(), hostID, cert)
	response, err := r.centre().FetchSecret(ctx, forwarded)
	if err != nil {
		return nil, err
	}
	return connect.NewResponse(response.Msg), nil
}

// Ping forwards a connectivity probe to the centre.
func (r *Relay) Ping(ctx context.Context,
	req *connect.Request[agentv1.PingRequest],
) (*connect.Response[agentv1.PingResponse], error) {
	// A client certificate is required here as well.
	if _, ok := clientCertificate(ctx); !ok {
		return nil, connect.NewError(connect.CodeUnauthenticated,
			errors.New("no client certificate"))
	}
	response, err := r.centre().Ping(ctx, connect.NewRequest(req.Msg))
	if err != nil {
		return nil, err
	}
	return connect.NewResponse(response.Msg), nil
}

// Connect forwards the session of an agent to the centre.
func (r *Relay) Connect(ctx context.Context,
	stream *connect.BidiStream[agentv1.AgentMessage, agentv1.ServerMessage]) error {
	cert, ok := clientCertificate(ctx)
	if !ok {
		return connect.NewError(connect.CodeUnauthenticated, errors.New("no client certificate"))
	}
	hostID, err := pki.HostIDFromCert(cert)
	if err != nil {
		return connect.NewError(connect.CodeUnauthenticated, err)
	}
	// A spool in its reserve while the centre is out of reach takes no new
	// session: the session would only bring what the spool cannot keep, and the
	// records already there are worth more than a session that resumes on its
	if !r.upstream.Load() && r.spool.Critical() {
		r.log.Warn("a session was refused: the spool is in its reserve and the centre is out of reach",
			"host_id", hostID)
		return connect.NewError(connect.CodeResourceExhausted,
			errors.New("relay_spool_critical: the spool of the relay is full"))
	}

	sessionCtx, cancel := context.WithCancel(ctx)
	defer cancel()
	r.trackSession(hostID, cancel)
	defer r.trackSession(hostID, nil)
	// Whatever the session sent and did not see acknowledged goes out
	// again in the next one, at once rather than after the timeout.
	defer r.spool.Unsend(hostID)

	upstream := r.centre().Connect(sessionCtx)
	attestHost(upstream.RequestHeader(), hostID, cert)
	defer func() {
		_ = upstream.CloseRequest()
		_ = upstream.CloseResponse()
	}()

	// A broken link is recognised on the receiving side.
	lost := make(chan struct{})
	var once sync.Once
	go func() {
		err := r.pumpDown(ctx, hostID, stream, upstream)
		r.upstream.Store(false)
		once.Do(func() { close(lost) })
		if err != nil && ctx.Err() == nil {
			r.log.Warn("the connection to the centre broke, switching to the spool",
				"host_id", hostID, "err", err)
		}
	}()

	r.upstream.Store(true)

	// The reception from the agent goes in a goroutine of its own so that the
	// loop can react to the cancellation of the session.
	received := make(chan *agentv1.AgentMessage)
	errors_ := make(chan error, 1)
	go func() {
		for {
			message, err := stream.Receive()
			if err != nil {
				errors_ <- err
				return
			}
			select {
			case received <- message:
			case <-sessionCtx.Done():
				return
			}
		}
	}()

	// The resend of what the panel did not acknowledge in time runs on a tick of
	// the session: the records come back as due from the spool once the timeout
	// passed, and the same session sends them again.
	resend := time.NewTicker(r.ackTimeout() / 2)
	defer resend.Stop()

	// A session starts with Hello; only after it may what waits in the spool
	// be sent - the centre rejects a stream that starts otherwise.
	first := true
	for {
		var message *agentv1.AgentMessage
		select {
		case <-sessionCtx.Done():
			// The session resumes on its own: the agent connects again within
			// seconds.
			return nil
		case err := <-errors_:
			return err
		case <-resend.C:
			select {
			case <-lost:
			default:
				if !first {
					r.flush(hostID, upstream, &once, lost)
				}
			}
			continue
		case message = <-received:
		}

		select {
		case <-lost:
			// The centre is unreachable: the message waits in the spool instead of
			// being lost.
			r.keep(hostID, message)
		default:
			if r.forward(hostID, message, upstream, &once, lost) && first {
				first = false
				r.flush(hostID, upstream, &once, lost)
			}
		}
	}
}

// ackTimeout is the acknowledgement timeout of the spool.
func (r *Relay) ackTimeout() time.Duration {
	if r.options.Spool.AckTimeout > 0 {
		return r.options.Spool.AckTimeout
	}
	return spool.DefaultAckTimeout
}

// forward sends a live message up: through the spool first for a durable
// class, straight for the rest.
func (r *Relay) forward(hostID string, message *agentv1.AgentMessage,
	upstream *connect.BidiStreamForClient[agentv1.AgentMessage, agentv1.ServerMessage],
	once *sync.Once, lost chan struct{}) bool {
	var record *spool.Record
	if message.GetHello() == nil && spool.Durable(spool.Classify(message)) {
		record = r.keep(hostID, message)
	}
	if err := upstream.Send(message); err != nil {
		r.upstream.Store(false)
		once.Do(func() { close(lost) })
		if record == nil {
			r.keep(hostID, message)
		}
		return false
	}
	if record != nil {
		r.spool.MarkSent(record.ID)
		if record.Sequence == 0 {
			// A message of an agent from before the envelope has no sequence for the
			// panel to acknowledge; the send is its confirmation, as it was before the
			// spool.
			_ = r.spool.Delete(record.ID)
		}
	}
	return true
}

// keep writes a message to the spool by the policy of its class and says which
// record it became; nil when the class refused it.
func (r *Relay) keep(hostID string, message *agentv1.AgentMessage) *spool.Record {
	if message.GetHello() != nil {
		// Hello opens a session and is never carried into another one.
		return nil
	}
	record, err := spool.FromMessage(r.options.Spool.Site, hostID, message, time.Now())
	if err != nil {
		r.log.Error("the message could not be encoded for the spool", "host_id", hostID, "err", err)
		return nil
	}
	if err := r.spool.Append(record); err != nil {
		switch {
		case errors.Is(err, spool.ErrExhausted):
			r.log.Warn("the spool refused a message of a light class; the stream is cut with resource_exhausted",
				"host_id", hostID, "stream", record.Stream, "err", err, "state", r.spool.Stats())
		case errors.Is(err, spool.ErrCritical):
			r.log.Error("the spool is full; a message of a durable class was dropped",
				"host_id", hostID, "stream", record.Stream, "err", err, "state", r.spool.Stats())
		default:
			r.log.Error("the spool did not take a message", "host_id", hostID, "stream", record.Stream, "err", err)
		}
		return nil
	}
	return record
}

// flush sends the records of the host that are due: what waited through an
// outage, what a previous session sent without an acknowledgement, and what
// the timeout brought back.
func (r *Relay) flush(hostID string,
	upstream *connect.BidiStreamForClient[agentv1.AgentMessage, agentv1.ServerMessage],
	once *sync.Once, lost chan struct{}) {
	sent := 0
	for {
		records, err := r.spool.Next(hostID, 0)
		if err != nil {
			r.log.Error("the spool could not be read", "host_id", hostID, "err", err)
			return
		}
		if len(records) == 0 {
			break
		}
		for _, record := range records {
			message, err := record.Message()
			if err != nil {
				// A record the relay cannot decode cannot be delivered; it
				// is removed so that it does not stand before the rest.
				r.log.Error("a spooled message could not be decoded and was dropped",
					"host_id", hostID, "record", record.ID, "err", err)
				_ = r.spool.Delete(record.ID)
				continue
			}
			if err := upstream.Send(message); err != nil {
				r.upstream.Store(false)
				once.Do(func() { close(lost) })
				r.spool.Unsend(hostID)
				r.log.Warn("the spool was not sent back", "host_id", hostID, "err", err)
				return
			}
			if record.Sequence == 0 {
				_ = r.spool.Delete(record.ID)
			}
			sent++
		}
	}
	if sent > 0 {
		r.log.Info("the spooled messages were sent", "host_id", hostID, "messages", sent)
	}
}

// pumpDown forwards the jobs from the centre to the agent. A job whose TTL has
// run out is not forwarded.
func (r *Relay) pumpDown(ctx context.Context, hostID string,
	to *connect.BidiStream[agentv1.AgentMessage, agentv1.ServerMessage],
	from *connect.BidiStreamForClient[agentv1.AgentMessage, agentv1.ServerMessage]) error {
	for {
		message, err := from.Receive()
		if err != nil {
			return err
		}
		if ack := message.GetMessageAck(); ack != nil {
			r.acknowledge(hostID, ack)
			continue
		}
		if task := message.GetTask(); task != nil && expired(task) {
			r.log.Warn("the job was skipped after its TTL ran out",
				"host_id", hostID, "task_id", task.GetTaskId(),
				"expires_at", task.GetExpiresAt().AsTime().Format(time.RFC3339))
			continue
		}
		if err := to.Send(message); err != nil {
			return err
		}
	}
}

// acknowledge deletes the record the panel consumed.
func (r *Relay) acknowledge(hostID string, ack *agentv1.MessageAck) {
	if ack.GetHostId() != "" && ack.GetHostId() != hostID {
		r.log.Warn("an acknowledgement named another host than the session's and was ignored",
			"host_id", hostID, "named", ack.GetHostId())
		return
	}
	found, err := r.spool.Ack(hostID, ack.GetSessionId(), ack.GetSequence())
	if err != nil {
		r.log.Error("the acknowledged record was not deleted", "host_id", hostID,
			"session_id", ack.GetSessionId(), "sequence", ack.GetSequence(), "err", err)
		return
	}
	if !found {
		// A message forwarded live without the spool - a sample, a log
		// line - or one deleted already: nothing to do, and nothing wrong.
		r.log.Debug("an acknowledgement found no record", "host_id", hostID,
			"session_id", ack.GetSessionId(), "sequence", ack.GetSequence())
	}
}

func expired(task *agentv1.TaskEnvelope) bool {
	expires := task.GetExpiresAt()
	if expires == nil {
		return false
	}
	return time.Now().After(expires.AsTime())
}

func (r *Relay) trackSession(hostID string, cancel context.CancelFunc) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if cancel != nil {
		r.sessions[hostID] = cancel
		return
	}
	delete(r.sessions, hostID)
}

// resetSessions ends the sessions of the agents once the link is back. The
// agent connects again within seconds and works live at once.
func (r *Relay) resetSessions() int {
	r.mu.Lock()
	defer r.mu.Unlock()
	for _, cancel := range r.sessions {
		cancel()
	}
	return len(r.sessions)
}

// Stats describes the fill of the spool for the heartbeat, the state file and
// the diagnostics.
type Stats struct {
	Messages int
	Bytes    int
	MaxBytes int
	Dropped  int
	// DiskBytes is what the segment files take on disk.
	DiskBytes int
	// Inflight counts the records sent and not yet acknowledged.
	Inflight int
	// Expired counts the records cut for their age.
	Expired int
	// Critical says the spool is in its reserve for control and results.
	Critical bool
}

// SpoolError returns the last failure of the spool to reach the disk, nil
// while it writes.
func (r *Relay) SpoolError() error { return r.spool.FlushError() }

// Stats describes the state of the relay for the metrics and the diagnostics.
func (r *Relay) Stats() (sessions int, buffer_ Stats, upstreamOK bool) {
	r.mu.RLock()
	sessions = len(r.sessions)
	r.mu.RUnlock()
	state := r.spool.Stats()
	return sessions, Stats{
		Messages: state.Items, Bytes: int(state.BytesUsed), MaxBytes: int(state.BytesLimit),
		Dropped: int(state.DroppedTotal), DiskBytes: int(state.DiskBytes),
		Inflight: state.Inflight, Expired: int(state.ExpiredTotal), Critical: state.Critical,
	}, r.upstream.Load()
}

// The states of the link as the heartbeat names them.
const (
	UpstreamConnected    = "connected"
	UpstreamBuffering    = "buffering"
	UpstreamReconnecting = "reconnecting"
)

// UpstreamState names how the relay sees its link to the centre: connected
// while it forwards live, buffering while the spool holds what the link cannot
// carry, reconnecting while the link is down and the spool is empty.
func (r *Relay) UpstreamState() string {
	if r.upstream.Load() {
		return UpstreamConnected
	}
	if r.spool.Stats().Items > 0 {
		return UpstreamBuffering
	}
	return UpstreamReconnecting
}

// WatchUpstream probes the connectivity with the centre while the relay works
// in the spool mode.
func (r *Relay) WatchUpstream(ctx context.Context, interval time.Duration) {
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			if r.upstream.Load() {
				continue
			}
			// The choice of a gateway belongs to the manager: it watches over the order
			// of the priorities and the windows of the retries.
			gateway, err_ := r.gateways.Choose(time.Now())
			if err_ != nil || gateway == nil {
				continue
			}
			if gateway.URL != r.Gateway() {
				r.switchGateway(gateway.URL)
			}
			probeCtx, cancelProbe := context.WithTimeout(ctx, 10*time.Second)
			_, err := r.centre().Ping(probeCtx, connect.NewRequest(&agentv1.PingRequest{}))
			cancelProbe()
			if err != nil {
				r.gateways.Error(gateway.URL, endpoints.Classify(err), time.Now())
				continue
			}
			r.gateways.Success(gateway.URL, time.Now())
			r.upstream.Store(true)
			r.log.Info("the connectivity with the centre was confirmed", "gateway", gateway.URL)
			// The sessions working in the spool mode are ended: the agent connects
			// again within seconds and we then send its records in the same session,
			// which starts with Hello.
			if ended := r.resetSessions(); ended > 0 {
				r.log.Info("the connectivity with the centre is back, the sessions will resume",
					"sessions", ended, "spooled", r.spool.Stats().Items)
			}
		}
	}
}

// certKey carries the certificate of the agent from the TLS layer into the
// handling of the stream.
type certKey struct{}

// WithClientCertificate carries the client certificate into the context of the
// request.
func WithClientCertificate(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ctx := r.Context()
		if r.TLS != nil && len(r.TLS.PeerCertificates) > 0 {
			ctx = context.WithValue(ctx, certKey{}, r.TLS.PeerCertificates[0])
		}
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

func clientCertificate(ctx context.Context) (*x509.Certificate, bool) {
	cert, ok := ctx.Value(certKey{}).(*x509.Certificate)
	return cert, ok
}
