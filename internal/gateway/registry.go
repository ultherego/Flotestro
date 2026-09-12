package gateway

import (
	"errors"
	"sync"
	"sync/atomic"
	"time"

	agentv1 "github.com/ultherego/flotestro/internal/genproto/flotestro/agent/v1"
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
	// RelayID is empty for a direct connection. The panel has to be able to
	// say which relay attested the identity of a host: these are two different
	// grounds of trust rather than a detail of the route.
	RelayID string
	// Epoch grows within a host and settles which session is the right one.
	// Two gateways do not see each other; they see a shared database, so the
	// number comes from it and it points at the winner.
	Epoch int64

	// outbound is the only path of sending to the agent. A stream is not safe
	// for concurrent Sends, so only one goroutine writes to it.
	outbound chan *agentv1.ServerMessage
	// closed ends the session on the initiative of the panel. A quarantine
	// checked only at the next connection does not cut off a host that is
	// being taken over right now - and that is the moment when cutting it off
	// matters.
	closed chan struct{}
	once   sync.Once
	reason atomic.Pointer[string]
}

// NewSession creates a session with a buffer of outgoing messages.
func NewSession(id, hostID, agentVersion, bootID, remoteAddr string, buffer int) *Session {
	if buffer <= 0 {
		buffer = 16
	}
	return &Session{
		ID: id, HostID: hostID, AgentVersion: agentVersion, BootID: bootID,
		RemoteAddr: remoteAddr, StartedAt: time.Now(),
		outbound: make(chan *agentv1.ServerMessage, buffer),
		closed:   make(chan struct{}),
	}
}

// End closes the session on the initiative of the panel.
//
// Idempotent: a quarantine issued twice must not topple the gateway.
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
//
// It returns whether there was anything to end: a host offline at the moment
// of a quarantine is not an error but a host that will not come back anyway -
// the condition at the connection will not let it in.
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

// Registry is the short-lived registry of the active sessions. It is the only
// state kept in the memory of the gateway; PostgreSQL remains the source of
// truth.
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

// Remove deletes a session only when it still belongs to the given
// identifier. Thanks to that closing an old session does not delete a newer
// one that has already replaced it after a reconnect.
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
//
// The relay compares this number with its own: a divergence means a session
// that hangs on one side, and that cannot be seen from either side alone.
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
