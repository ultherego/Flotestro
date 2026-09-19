package gateway

import (
	"errors"
	"sync"
	"sync/atomic"
	"time"

	agentv1 "github.com/ultherego/flotestro/internal/genproto/flotestro/agent/v1"
	"github.com/ultherego/flotestro/internal/jobs"
)

// ErrNotConnected means the host has no active session on this gateway.
var ErrNotConnected = errors.New("the host has no active session")

// ErrSendTimeout means the session does not keep up with receiving messages.
var ErrSendTimeout = errors.New("the session did not accept the message within the given time")

// Session describes an active connection of an agent served by this gateway.
type Session struct {
	ID           string
	HostID       string
	AgentVersion string
	BootID       string
	RemoteAddr   string
	StartedAt    time.Time
	// RelayID is empty for a direct connection.
	RelayID string
	// RelayIdentity says how the host was identified through the relay: attested,
	// when the relay named the certificate the host presented and the gateway
	// checked it, or weak, when the relay named the host alone.
	RelayIdentity string
	// HelperCapabilitySupported says the agent forwards a signed capability to
	// its root helper, and HelperCapabilityMode is what the helper does with one
	// - observe, prefer, enforce, or empty for a helper that has not said.
	HelperCapabilitySupported bool
	HelperCapabilityMode      string
	// Epoch grows within a host and settles which session is the right one.
	Epoch int64
	// FenceToken is the token the session got when it claimed the host in
	// host_session_owners, and OwnerInstanceID names the control-plane process
	// that claimed it.
	FenceToken      uint64
	OwnerInstanceID string

	// outbound is the only path of sending to the agent. A stream is not safe
	// for concurrent Sends, so only one goroutine writes to it.
	outbound chan *agentv1.ServerMessage
	// closed ends the session on the initiative of the panel.
	closed chan struct{}
	once   sync.Once
	reason atomic.Pointer[string]
	// finalReady carries the agent's answer to the final task to whoever drives
	// the decommission handshake.
	finalReady chan *agentv1.FinalReady
	// finished closes when the stream of the session has ended for good.
	finished     chan struct{}
	finishedOnce sync.Once
}

// NewSession creates a session with a buffer of outgoing messages.
func NewSession(id, hostID, agentVersion, bootID, remoteAddr string, buffer int) *Session {
	if buffer <= 0 {
		buffer = 16
	}
	return &Session{
		ID: id, HostID: hostID, AgentVersion: agentVersion, BootID: bootID,
		RemoteAddr: remoteAddr, StartedAt: time.Now(),
		outbound:   make(chan *agentv1.ServerMessage, buffer),
		closed:     make(chan struct{}),
		finalReady: make(chan *agentv1.FinalReady, 1),
		finished:   make(chan struct{}),
	}
}

// Fence is what the writes made on this session carry: its identifier
// and the token of its claim on the host.
func (s *Session) Fence() jobs.Fence {
	return jobs.Fence{SessionID: s.ID, Token: s.FenceToken}
}

// AcceptFinalReady hands the agent's answer to the handshake. A second
// answer, or one nobody asked for, is dropped: the handshake reads one.
func (s *Session) AcceptFinalReady(ready *agentv1.FinalReady) bool {
	select {
	case s.finalReady <- ready:
		return true
	default:
		return false
	}
}

// FinalReady is the channel the handshake reads the agent's answer from.
func (s *Session) FinalReady() <-chan *agentv1.FinalReady { return s.finalReady }

// Finish marks the end of the stream. Idempotent.
func (s *Session) Finish() { s.finishedOnce.Do(func() { close(s.finished) }) }

// Finished is the channel that closes when the stream has ended.
func (s *Session) Finished() <-chan struct{} { return s.finished }

// End closes the session on the initiative of the panel. Idempotent: a
// quarantine issued twice must not topple the gateway.
func (s *Session) End(reason string) {
	s.once.Do(func() {
		s.reason.Store(&reason)
		close(s.closed)
	})
}

// Closed is the channel that closes together with the session.
func (s *Session) Closed() <-chan struct{} { return s.closed }

// CloseReason says why the panel ended the session.
func (s *Session) CloseReason() string {
	if reason := s.reason.Load(); reason != nil {
		return *reason
	}
	return ""
}

// Outbound returns the channel of the messages to send to the agent.
func (s *Session) Outbound() <-chan *agentv1.ServerMessage { return s.outbound }

// Send queues a message to the agent. The block is bounded in time so that a
// slow agent does not stop the scheduler.
func (s *Session) Send(message *agentv1.ServerMessage, timeout time.Duration) error {
	timer := time.NewTimer(timeout)
	defer timer.Stop()
	select {
	case s.outbound <- message:
		return nil
	case <-timer.C:
		return ErrSendTimeout
	}
}

// EndSession ends the session of a host if one is running.
func (r *Registry) EndSession(hostID, reason string) bool {
	r.mu.RLock()
	session, ok := r.sessions[hostID]
	r.mu.RUnlock()
	if !ok {
		return false
	}
	session.End(reason)
	return true
}

// Registry is the short-lived registry of the active sessions.
type Registry struct {
	mu       sync.RWMutex
	sessions map[string]*Session
}

func NewRegistry() *Registry {
	return &Registry{sessions: make(map[string]*Session)}
}

func (r *Registry) Add(session *Session) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.sessions[session.HostID] = session
}

// Remove deletes a session only when it still belongs to the given identifier.
func (r *Registry) Remove(hostID, sessionID string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if current, ok := r.sessions[hostID]; ok && current.ID == sessionID {
		delete(r.sessions, hostID)
	}
}

func (r *Registry) Get(hostID string) (*Session, bool) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	session, ok := r.sessions[hostID]
	return session, ok
}

// Dispatch sends a message to a host if it is connected to this gateway.
func (r *Registry) Dispatch(hostID string, message *agentv1.ServerMessage, timeout time.Duration) (string, error) {
	session, ok := r.Get(hostID)
	if !ok {
		return "", ErrNotConnected
	}
	if err := session.Send(message, timeout); err != nil {
		return session.ID, err
	}
	return session.ID, nil
}

// ConnectedHosts returns the identifiers of the hosts with an active session.
func (r *Registry) ConnectedHosts() []string {
	r.mu.RLock()
	defer r.mu.RUnlock()
	hosts := make([]string, 0, len(r.sessions))
	for hostID := range r.sessions {
		hosts = append(hosts, hostID)
	}
	return hosts
}

// RelaySessions counts the sessions attested by the named relay.
func (r *Registry) RelaySessions(relayID string) int {
	if relayID == "" {
		return 0
	}
	r.mu.RLock()
	defer r.mu.RUnlock()
	var count int
	for _, session := range r.sessions {
		if session.RelayID == relayID {
			count++
		}
	}
	return count
}

func (r *Registry) Count() int {
	r.mu.RLock()
	defer r.mu.RUnlock()
	return len(r.sessions)
}

// SessionIDs returns the identifiers of the sessions kept by this instance. It
// serves to close the rows of sessions that no longer exist.
func (r *Registry) SessionIDs() []string {
	r.mu.RLock()
	defer r.mu.RUnlock()
	ids := make([]string, 0, len(r.sessions))
	for _, session := range r.sessions {
		ids = append(ids, session.ID)
	}
	return ids
}
