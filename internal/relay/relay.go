package relay

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"log/slog"
	"net/http"
	"sync"
	"sync/atomic"
	"time"

	"connectrpc.com/connect"
	"golang.org/x/net/http2"

	"github.com/ultherego/flotestro/internal/endpoints"
	agentv1 "github.com/ultherego/flotestro/internal/genproto/flotestro/agent/v1"
	"github.com/ultherego/flotestro/internal/genproto/flotestro/agent/v1/agentv1connect"
	"github.com/ultherego/flotestro/internal/pki"
)

// hostHeader carries the identity of the host attested by the relay. The name
// has to match the gateway: it is the only place where the panel learns whose
// traffic goes through the relay.
const hostHeader = "Flotestro-Relay-Host"

// Options describe the relay of a site.
type Options struct {
	// UpstreamURL is the address of the agent gateway in the centre.
	UpstreamURL string
	// UpstreamURLs are the remaining gateways in order of priority. The relay
	// keeps one connection upwards, but a failure of a gateway must not cut a
	// whole site off until somebody looks into the configuration.
	UpstreamURLs []string
	// EnrollmentURL enables mediation in the registration of hosts. Empty
	// means the relay does not handle it: a site that sees the centre needs no
	// intermediary for a one-time act.
	EnrollmentURL string
	// Identity is the identity of the relay towards the centre.
	Identity tls.Certificate
	// TrustPool verifies both the centre and the certificates of the agents:
	// one CA of the fleet covers both sides.
	TrustPool *x509.CertPool
	// BufferBytes limits the memory given to the results waiting for the link
	// to come back.
	BufferBytes int
	Log         *slog.Logger
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
	buffer  *Buffer
	log     *slog.Logger

	mu sync.RWMutex
	// sessions hold the cancel functions. Once the link is back, a session
	// working in the buffering mode is ended so that the agent connects anew
	// and returns to live forwarding; otherwise it would stay in that mode to
	// the end of its life even though the centre answers again.
	sessions map[string]context.CancelFunc
	upstream atomic.Bool
	identity atomic.Pointer[relayMaterial]
}

func New(options Options) *Relay {
	log := options.Log
	if log == nil {
		log = slog.Default()
	}
	addresses := options.UpstreamURLs
	if len(addresses) == 0 {
		addresses = []string{options.UpstreamURL}
	}
	relay := &Relay{
		options: options, log: log,
		gateways: endpoints.New(addresses, endpoints.MinBackoff, endpoints.MaxBackoff),
		buffer:   NewBuffer(options.BufferBytes),
		sessions: map[string]context.CancelFunc{},
	}
	first := addresses[0]
	relay.current.Store(&first)
	relay.identity.Store(&relayMaterial{
		cert: options.Identity, trust: options.TrustPool,
	})
	relay.client_.Store(&centreClient{
		client: clientToCentre(first, options.Identity, options.TrustPool),
	})
	return relay
}

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
			// A broken WAN link does not show up as a send error: the data fit
			// in the buffer of the kernel and TCP retransmits them for more
			// than a dozen minutes. Without active probing the relay would
			// consider everything working for that time and would not start
			// buffering.
			ReadIdleTimeout: 15 * time.Second,
			PingTimeout:     10 * time.Second,
		}},
		address,
		connect.WithGRPC(),
	)
}

// RefreshIdentity swaps the certificate the relay presents itself to the
// centre with.
//
// After a renewal the old certificate is still valid but stops being the one
// the panel recognises the relay by. New connections to the centre have to go
// with the new one; running streams live to their natural end, so the agents
// do not lose their sessions because of the renewal alone.
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
// contract as the centre, so the agent does not know and does not have to know
// that it speaks through a relay.
func (r *Relay) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.Handle(agentv1connect.NewAgentServiceHandler(r))
	// The registration of a host goes over the same port: a host in an
	// isolated site knows the address of the relay alone. Without a client
	// certificate only that one service goes through - the rest read the
	// identity from the handshake and refuse without it.
	if r.options.EnrollmentURL != "" {
		mux.Handle(r.EnrollmentHandler())
	}
	return mux
}

// RenewCertificate forwards the renewal of a certificate to the centre.
//
// The relay signs nothing itself: the CA of the fleet stays in the centre and
// the relay only mediates. The certificate of the agent is verified here in
// the TLS handshake, so the identity of the requester is known and attached
// just as in a session.
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
	forwarded.Header().Set(hostHeader, hostID)
	response, err := r.centre().RenewCertificate(ctx, forwarded)
	if err != nil {
		// The renewal has to reach the centre; the buffer does not help here,
		// because the agent waits for an answer. It will try again on its own
		// schedule.
		return nil, err
	}
	return connect.NewResponse(response.Msg), nil
}

// FetchSecret forwards the fetch of a secret to the centre.
//
// The relay neither stores nor looks at the value: it forwards the call
// together with the identity of the host, and the centre decides on the
// release on the basis of the lease. A buffer makes no sense here - the host
// waits for an answer and the lease is short.
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
	forwarded.Header().Set(hostHeader, hostID)
	response, err := r.centre().FetchSecret(ctx, forwarded)
	if err != nil {
		return nil, err
	}
	return connect.NewResponse(response.Msg), nil
}

// Ping forwards a connectivity probe to the centre. The relay does not answer
// on its own: the question concerns the path to the centre rather than whether
// the relay works.
func (r *Relay) Ping(ctx context.Context,
	req *connect.Request[agentv1.PingRequest],
) (*connect.Response[agentv1.PingResponse], error) {
	// A client certificate is required here as well. The listener of the relay
	// lets connections without a certificate in, because a host before its
	// registration has nothing to present itself with - but a connectivity
	// probe is not part of the registration and must not be a free way of
	// checking whether the centre is alive.
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
//
// The identity of the host comes from the certificate of the agent verified in
// the TLS handshake on the side of the relay and is attached to the connection
// upwards. The relay does not look into the content of the jobs; its role ends
// at forwarding and buffering.
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

	sessionCtx, cancel := context.WithCancel(ctx)
	defer cancel()
	r.trackSession(hostID, cancel)
	defer r.trackSession(hostID, nil)

	upstream := r.centre().Connect(sessionCtx)
	upstream.RequestHeader().Set(hostHeader, hostID)
	defer func() {
		_ = upstream.CloseRequest()
		_ = upstream.CloseResponse()
	}()

	// A broken link is recognised on the receiving side. Sending will not show
	// it: the data go into the HTTP/2 queue and into the buffer of the kernel,
	// so Send succeeds long after the centre stopped answering.
	lost := make(chan struct{})
	var once sync.Once
	go func() {
		err := r.pumpDown(ctx, hostID, stream, upstream)
		r.upstream.Store(false)
		once.Do(func() { close(lost) })
		if err != nil && ctx.Err() == nil {
			r.log.Warn("the connection to the centre broke, switching to buffering",
				"host_id", hostID, "err", err)
		}
	}()

	r.upstream.Store(true)

	// The reception from the agent goes in a goroutine of its own so that the
	// loop can react to the cancellation of the session. Receive blocks on the
	// context of the request and does not see our cancellation: without this a
	// session switched to buffering would stay in that mode for good even
	// though the centre answers again.
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

	// A session starts with Hello; only after it may what waited in the buffer
	// be sent back - the centre rejects a stream that starts otherwise.
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
		case message = <-received:
		}

		select {
		case <-lost:
			// The centre is unreachable: the message waits in the buffer
			// instead of being lost. A lost result looks to the panel like a
			// job that is still running and blocks the host for the TTL.
			r.bufferMessage(hostID, message)
		default:
			if sendErr := upstream.Send(message); sendErr != nil {
				r.upstream.Store(false)
				once.Do(func() { close(lost) })
				r.bufferMessage(hostID, message)
				continue
			}
			if first {
				first = false
				r.flushBuffer(hostID, upstream)
			}
		}
	}
}

// buffer_ sets a message aside and reports an overflow. A full buffer is an
// operational event: from that moment the site loses results.
func (r *Relay) bufferMessage(hostID string, message *agentv1.AgentMessage) {
	if err := r.buffer.Add(hostID, message); err != nil {
		r.log.Error("the buffer of the relay is full, the result was dropped",
			"host_id", hostID, "err", err, "state", r.buffer.Stats())
	}
}

// pumpDown forwards the jobs from the centre to the agent.
//
// A job whose TTL has run out is not forwarded. The document says it outright:
// the relay buffers results but does not carry a job out after its TTL - and
// forwarding an expired job is exactly ordering work nobody is asking for any
// more.
func (r *Relay) pumpDown(ctx context.Context, hostID string,
	to *connect.BidiStream[agentv1.AgentMessage, agentv1.ServerMessage],
	from *connect.BidiStreamForClient[agentv1.AgentMessage, agentv1.ServerMessage]) error {
	for {
		message, err := from.Receive()
		if err != nil {
			return err
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

// Stats describes the state of the relay for the metrics and the diagnostics.
func (r *Relay) Stats() (sessions int, buffer_ Stats, upstreamOK bool) {
	r.mu.RLock()
	sessions = len(r.sessions)
	r.mu.RUnlock()
	return sessions, r.buffer.Stats(), r.upstream.Load()
}

// WatchUpstream probes the connectivity with the centre while the relay works
// in the buffering mode.
//
// The probe goes as a separate call without side effects. An earlier version
// checked the link by sending the buffered messages over a separate stream -
// and lost them, because the session of an agent starts with Hello and a
// stream without Hello is rejected by the centre. The buffer is to protect the
// results rather than lose them.
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
			// The choice of a gateway belongs to the manager: it watches over
			// the order of the priorities and the windows of the retries. The
			// relay tries the one that is ready rather than each in turn on
			// every tick.
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
			// The sessions working in the buffering mode are ended: the agent
			// connects again within seconds and we then send its buffer back
			// in the same session, which starts with Hello.
			if ended := r.resetSessions(); ended > 0 {
				r.log.Info("the connectivity with the centre is back, the sessions will resume",
					"sessions", ended, "buffer", r.buffer.Stats().Messages)
			}
		}
	}
}

// certKey carries the certificate of the agent from the TLS layer into the
// handling of the stream.
type certKey struct{}

// WithClientCertificate carries the client certificate into the context of
// the request. The contract carries no identity: it comes from the TLS
// handshake alone.
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

// flushBuffer sends the buffered messages of a host back in its live session.
// A message disappears from the buffer only after it has been sent, so a break
// halfway means another attempt rather than a lost result.
func (r *Relay) flushBuffer(hostID string,
	upstream *connect.BidiStreamForClient[agentv1.AgentMessage, agentv1.ServerMessage]) {
	sent := 0
	for {
		message, ok := r.buffer.TakeFor(hostID)
		if !ok {
			break
		}
		if err := upstream.Send(message); err != nil {
			r.log.Warn("the buffer was not sent back", "host_id", hostID, "err", err)
			return
		}
		r.buffer.CommitFor(hostID)
		sent++
	}
	if sent > 0 {
		r.log.Info("the buffered messages were sent back", "host_id", hostID, "messages", sent)
	}
}
