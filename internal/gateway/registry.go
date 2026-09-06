package gateway

import (
	"errors"
	"sync"
	"sync/atomic"
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
	// RelayID jest pusty przy polaczeniu bezposrednim. Panel musi umiec
	// powiedziec, ktory relay poswiadczyl tozsamosc hosta: to dwie rozne
	// podstawy zaufania, a nie szczegol trasy.
	RelayID string
	// Epoka rosnie w obrebie hosta i rozstrzyga, ktora sesja jest wlasciwa.
	// Dwie bramy nie widza siebie nawzajem; widza wspolna baze, wiec to
	// z niej pochodzi numer i to on wskazuje zwyciezce.
	Epoka int64

	// outbound jest jedyna droga wysylki do agenta. Stream nie jest bezpieczny
	// dla rownoleglych Send, wiec pisze do niego wylacznie jedna goroutine.
	outbound chan *agentv1.ServerMessage
	// zamkniecie konczy sesje z inicjatywy panelu. Kwarantanna sprawdzana
	// dopiero przy nastepnym polaczeniu nie odcina hosta, ktory wlasnie jest
	// przejety - a to jest ta chwila, w ktorej odciecie ma znaczenie.
	zamkniecie chan struct{}
	raz        sync.Once
	powod      atomic.Pointer[string]
}

// NewSession tworzy sesje z buforem wiadomosci wychodzacych.
func NewSession(id, hostID, agentVersion, bootID, remoteAddr string, buffer int) *Session {
	if buffer <= 0 {
		buffer = 16
	}
	return &Session{
		ID: id, HostID: hostID, AgentVersion: agentVersion, BootID: bootID,
		RemoteAddr: remoteAddr, StartedAt: time.Now(),
		outbound:   make(chan *agentv1.ServerMessage, buffer),
		zamkniecie: make(chan struct{}),
	}
}

// Zakoncz zamyka sesje z inicjatywy panelu.
//
// Idempotentne: kwarantanna wydana dwa razy nie moze wywrocic gatewaya.
func (s *Session) Zakoncz(powod string) {
	s.raz.Do(func() {
		s.powod.Store(&powod)
		close(s.zamkniecie)
	})
}

// Zamknieta jest kanalem, ktory zamyka sie razem z sesja.
func (s *Session) Zamknieta() <-chan struct{} { return s.zamkniecie }

// PowodZamkniecia mowi, dlaczego panel zakonczyl sesje.
func (s *Session) PowodZamkniecia() string {
	if powod := s.powod.Load(); powod != nil {
		return *powod
	}
	return ""
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

// ZakonczSesje konczy sesje hosta, jesli jakas trwa.
//
// Zwraca, czy bylo co konczyc: host offline w chwili kwarantanny nie jest
// bledem, tylko hostem, ktory i tak nie wroci - warunek przy polaczeniu go
// nie wpusci.
func (r *Registry) ZakonczSesje(hostID, powod string) bool {
	r.mu.RLock()
	session, ok := r.sessions[hostID]
	r.mu.RUnlock()
	if !ok {
		return false
	}
	session.Zakoncz(powod)
	return true
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

// SesjeRelaya liczy sesje poswiadczone przez wskazany relay.
//
// Relay porownuje te liczbe ze swoja: rozjazd oznacza sesje, ktora zawisla po
// jednej stronie, a tego nie widac z zadnej strony osobno.
func (r *Registry) SesjeRelaya(relayID string) int {
	if relayID == "" {
		return 0
	}
	r.mu.RLock()
	defer r.mu.RUnlock()
	var ile int
	for _, session := range r.sessions {
		if session.RelayID == relayID {
			ile++
		}
	}
	return ile
}

func (r *Registry) Count() int {
	r.mu.RLock()
	defer r.mu.RUnlock()
	return len(r.sessions)
}

// SessionIDs zwraca identyfikatory sesji utrzymywanych przez te instancje.
// Sluzy zamykaniu wpisow po sesjach, ktore juz nie istnieja.
func (r *Registry) SessionIDs() []string {
	r.mu.RLock()
	defer r.mu.RUnlock()
	ids := make([]string, 0, len(r.sessions))
	for _, session := range r.sessions {
		ids = append(ids, session.ID)
	}
	return ids
}
