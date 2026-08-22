package gateway

import (
	"errors"
	"sync"
	"time"

	agentv1 "github.com/ultherego/flotestro/internal/genproto/flotestro/agent/v1"
)

// ErrNotConnected oznacza, ze host nie ma aktywnej sesji na tym gatewayu.
var ErrNotConnected = errors.New("host nie ma aktywnej sesji")

// ErrSendTimeout oznacza, ze sesja nie nadaza odbierac wiadomosci.
var ErrSendTimeout = errors.New("sesja nie przyjela wiadomosci w zadanym czasie")

// Session opisuje aktywne polaczenie agenta obslugiwane przez ten gateway.
type Session struct {
	ID           string
	HostID       string
	AgentVersion string
	BootID       string
	RemoteAddr   string
	StartedAt    time.Time

	// outbound jest jedyna droga wysylki do agenta. Stream nie jest bezpieczny
	// dla rownoleglych Send, wiec pisze do niego wylacznie jedna goroutine.
	outbound chan *agentv1.ServerMessage
}

// NewSession tworzy sesje z buforem wiadomosci wychodzacych.
func NewSession(id, hostID, agentVersion, bootID, remoteAddr string, buffer int) *Session {
	if buffer <= 0 {
		buffer = 16
	}
	return &Session{
		ID: id, HostID: hostID, AgentVersion: agentVersion, BootID: bootID,
		RemoteAddr: remoteAddr, StartedAt: time.Now(),
		outbound: make(chan *agentv1.ServerMessage, buffer),
	}
}

// Outbound zwraca kanal wiadomosci do wyslania do agenta.
func (s *Session) Outbound() <-chan *agentv1.ServerMessage { return s.outbound }

// Send kolejkuje wiadomosc do agenta. Blokada jest ograniczona czasowo, zeby
// wolny agent nie zatrzymal schedulera.
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

// Registry jest krotkotrwalym rejestrem aktywnych sesji. Jest to jedyny stan
// trzymany w pamieci gatewaya; zrodlem prawdy pozostaje PostgreSQL.
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

// Remove usuwa sesje tylko wtedy, gdy nadal nalezy do podanego identyfikatora.
// Dzieki temu zamkniecie starej sesji nie kasuje nowszej, ktora zdazyla ja
// zastapic po reconnekcie.
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

// Dispatch wysyla wiadomosc do hosta, jesli jest polaczony z tym gatewayem.
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

// ConnectedHosts zwraca identyfikatory hostow z aktywna sesja.
func (r *Registry) ConnectedHosts() []string {
	r.mu.RLock()
	defer r.mu.RUnlock()
	hosts := make([]string, 0, len(r.sessions))
	for hostID := range r.sessions {
		hosts = append(hosts, hostID)
	}
	return hosts
}

func (r *Registry) Count() int {
	r.mu.RLock()
	defer r.mu.RUnlock()
	return len(r.sessions)
}
