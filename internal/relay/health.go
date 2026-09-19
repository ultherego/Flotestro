package relay

import (
	"encoding/json"
	"errors"
	"net"
	"net/http"
	"strconv"
	"sync"
	"sync/atomic"
	"time"
)

// This file answers the question a container runtime asks about a relay, and
// it answers it twice, because the two answers are not the same question.

// The paths of the two answers.
const (
	HealthPathLive  = "/healthz"
	HealthPathAlias = "/livez"
	HealthPathReady = "/readyz"
)

// The codes a health answer names.
const (
	// HealthListenerUnavailable is the listener of the agents gone or refusing
	// every connection: this process is the wedged one, and a restart is the
	// answer.
	HealthListenerUnavailable = "relay_listener_unavailable"
	// HealthUpstreamUnreachable is the link to the centre: the relay
	// buffers instead of forwarding. It is not a reason to restart.
	HealthUpstreamUnreachable = "relay_upstream_unreachable"
	// HealthSpoolCritical is the spool in its reserve: new sessions are
	// refused before an existing record is lost.
	HealthSpoolCritical = "relay_spool_critical"
	// HealthSpoolUnwritable is the spool that cannot reach the disk: the batched
	// sync of the light classes failed, so what the relay takes now is not what
	// it holds after a power failure.
	HealthSpoolUnwritable = "relay_spool_unwritable"
	// HealthCertificateExpired is the identity of the relay past its end: the
	// centre and the agents refuse it, and the renewal has to succeed before the
	// relay carries anything again.
	HealthCertificateExpired = "relay_certificate_expired"
	// HealthCertificateUnknown is an identity without an end date. Unknown
	// is not valid: the relay says so rather than reporting ready.
	HealthCertificateUnknown = "relay_certificate_unknown"
)

// The names of the readiness checks, in the order they are answered.
const (
	CheckListener    = "listener"
	CheckUpstream    = "upstream"
	CheckSpool       = "spool"
	CheckCertificate = "certificate"
)

// HealthOptions assemble the health of a relay out of what the process
// already holds.
type HealthOptions struct {
	// Relay is the relay being asked about.
	Relay *Relay
	// Listener watches the listener of the agents; nil means the liveness
	// answer speaks for the process alone.
	Listener *ListenerState
	// Identity returns the identity the relay presents now.
	Identity func() Identity
	// Version is the release of the binary, for the operator reading the
	// answer of a container.
	Version string
	// ListenerGrace is how long the listener may fail to accept before
	// liveness calls the process wedged. Zero means the default.
	ListenerGrace time.Duration
	Now           func() time.Time
}

// DefaultListenerGrace is how long accepts may fail in a row before the
// liveness answer turns.
const DefaultListenerGrace = 30 * time.Second

// Health serves the liveness and readiness of a relay.
type Health struct {
	options   HealthOptions
	startedAt time.Time
}

// NewHealth builds the health of a relay.
func NewHealth(options HealthOptions) *Health {
	if options.Now == nil {
		options.Now = time.Now
	}
	if options.ListenerGrace <= 0 {
		options.ListenerGrace = DefaultListenerGrace
	}
	return &Health{options: options, startedAt: options.Now()}
}

// Handler serves the two answers. Nothing else is served here: the listener
// carries no identity, so it answers the two questions and refuses the rest.
func (h *Health) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET "+HealthPathLive, h.serveLiveness)
	mux.HandleFunc("GET "+HealthPathAlias, h.serveLiveness)
	mux.HandleFunc("GET "+HealthPathReady, h.serveReadiness)
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		writeHealth(w, http.StatusNotFound, map[string]string{
			"status": "unknown_path",
			"detail": "the health listener of the relay answers " + HealthPathLive +
				" and " + HealthPathReady + " only",
		})
	})
	return mux
}

// LivenessReport is the answer to "is this process alive".
type LivenessReport struct {
	// Status is alive or wedged. The words are the answer; the status
	// code carries the same thing for a check that reads nothing.
	Status string `json:"status"`
	// Code names what is wrong, empty while the relay is alive.
	Code   string `json:"code,omitempty"`
	Detail string `json:"detail,omitempty"`
	// Upstream is reported and never judged here: an operator reading a liveness
	// answer during an outage has to see that the relay knows the link is down
	// and stayed alive anyway.
	Upstream      string `json:"upstream"`
	RelayID       string `json:"relay_id,omitempty"`
	InstanceID    string `json:"instance_id"`
	Version       string `json:"version,omitempty"`
	UptimeSeconds int64  `json:"uptime_seconds"`
	Accepted      uint64 `json:"accepted_connections"`
}

// HealthCheck is one readiness question and its answer.
type HealthCheck struct {
	Name   string `json:"name"`
	OK     bool   `json:"ok"`
	Code   string `json:"code,omitempty"`
	Detail string `json:"detail"`
}

// ReadinessReport is the answer to "can this relay carry work now".
type ReadinessReport struct {
	Status string        `json:"status"`
	Checks []HealthCheck `json:"checks"`
	// Reasons are the codes of the checks that are false, in the order
	// they were asked: what a runtime logs when it has room for one line.
	Reasons []string `json:"reasons,omitempty"`
	// SafeToRestart is the condition of the containerisation document for
	// restarting a relay without losing anything: the link is up, nothing waits
	// in the spool and nothing was dropped since the start.
	SafeToRestart bool   `json:"safe_to_restart"`
	Upstream      string `json:"upstream"`
	Gateway       string `json:"gateway,omitempty"`
	SpooledItems  int    `json:"spooled_items"`
	SpooledBytes  int    `json:"spooled_bytes"`
	SpoolMaxBytes int    `json:"spool_max_bytes"`
	SpoolDropped  int    `json:"spool_dropped_total"`
	Sessions      int    `json:"sessions"`
	RelayID       string `json:"relay_id,omitempty"`
	InstanceID    string `json:"instance_id"`
	// CertificateNotAfter is when the identity of the relay ends, in
	// RFC 3339; empty when the relay holds no end date.
	CertificateNotAfter string `json:"certificate_not_after,omitempty"`
}

// Liveness answers whether the process works.
func (h *Health) Liveness() LivenessReport {
	report := LivenessReport{
		Status:        "alive",
		Version:       h.options.Version,
		UptimeSeconds: int64(h.options.Now().Sub(h.startedAt) / time.Second),
	}
	if h.options.Relay != nil {
		report.InstanceID = h.options.Relay.InstanceID()
		report.Upstream = h.options.Relay.UpstreamState()
	}
	if h.options.Identity != nil {
		report.RelayID = h.options.Identity().RelayID
	}
	check := h.listenerCheck()
	report.Accepted = h.accepted()
	if !check.OK {
		report.Status = "wedged"
		report.Code = check.Code
		report.Detail = check.Detail
	}
	return report
}

// Readiness answers whether the relay can carry work right now and names
// every question whose answer is no.
func (h *Health) Readiness() ReadinessReport {
	report := ReadinessReport{Status: "ready"}
	checks := []HealthCheck{h.listenerCheck()}
	if h.options.Relay != nil {
		sessions, stats, upstreamOK := h.options.Relay.Stats()
		report.InstanceID = h.options.Relay.InstanceID()
		report.Upstream = h.options.Relay.UpstreamState()
		report.Gateway = h.options.Relay.Gateway()
		report.Sessions = sessions
		report.SpooledItems = stats.Messages
		report.SpooledBytes = stats.Bytes
		report.SpoolMaxBytes = stats.MaxBytes
		report.SpoolDropped = stats.Dropped
		// The condition of the document, word for word: the link is up, the spool is
		// empty and nothing was dropped.
		report.SafeToRestart = upstreamOK && stats.Messages == 0 && stats.Dropped == 0
		checks = append(checks, upstreamCheck(upstreamOK, report.Upstream, stats),
			spoolCheck(stats, h.options.Relay.SpoolError()))
	}
	if h.options.Identity != nil {
		identity := h.options.Identity()
		if !identity.NotAfter.IsZero() {
			report.CertificateNotAfter = identity.NotAfter.UTC().Format(time.RFC3339)
		}
		checks = append(checks, certificateCheck(identity, h.options.Now()))
	}
	report.Checks = checks
	for _, check := range checks {
		if !check.OK {
			report.Status = "not_ready"
			report.Reasons = append(report.Reasons, check.Code)
		}
	}
	return report
}

// listenerCheck says whether the listener of the agents still accepts.
func (h *Health) listenerCheck() HealthCheck {
	if h.options.Listener == nil {
		return HealthCheck{Name: CheckListener, OK: true,
			Detail: "the process serves; the listener of the agents is not watched"}
	}
	state := h.options.Listener.State(h.options.Now(), h.options.ListenerGrace)
	if state.Closed {
		return HealthCheck{Name: CheckListener, Code: HealthListenerUnavailable,
			Detail: "the listener of the agents is closed: " + state.Detail}
	}
	if state.Failing {
		return HealthCheck{Name: CheckListener, Code: HealthListenerUnavailable,
			Detail: "the listener of the agents has refused every connection for " +
				state.FailingFor.Truncate(time.Second).String() + ": " + state.Detail}
	}
	return HealthCheck{Name: CheckListener, OK: true,
		Detail: "the listener of the agents accepts connections"}
}

// accepted is the number of connections the listener took, zero when
// nobody watches it.
func (h *Health) accepted() uint64 {
	if h.options.Listener == nil {
		return 0
	}
	return h.options.Listener.Accepted()
}

// upstreamCheck says whether the relay forwards live.
func upstreamCheck(upstreamOK bool, state string, stats Stats) HealthCheck {
	if upstreamOK {
		return HealthCheck{Name: CheckUpstream, OK: true,
			Detail: "the session to the centre is established"}
	}
	detail := "the relay does not reach the centre (" + state + ")"
	if stats.Messages > 0 {
		detail += " and holds " + strconv.Itoa(stats.Messages) + " messages in its spool"
	}
	return HealthCheck{Name: CheckUpstream, Code: HealthUpstreamUnreachable, Detail: detail}
}

// spoolCheck says whether the spool can still take what the site
// produces: room inside its bound, and a disk that takes the writes.
func spoolCheck(stats Stats, syncErr error) HealthCheck {
	if syncErr != nil {
		return HealthCheck{Name: CheckSpool, Code: HealthSpoolUnwritable,
			Detail: "the spool does not reach the disk: " + syncErr.Error()}
	}
	if stats.Critical {
		return HealthCheck{Name: CheckSpool, Code: HealthSpoolCritical,
			Detail: "the spool is in its reserve (" + strconv.Itoa(stats.Bytes) + " of " +
				strconv.Itoa(stats.MaxBytes) + " bytes) and new sessions are refused"}
	}
	return HealthCheck{Name: CheckSpool, OK: true,
		Detail: "the spool holds " + strconv.Itoa(stats.Messages) + " messages in " +
			strconv.Itoa(stats.Bytes) + " of " + strconv.Itoa(stats.MaxBytes) + " bytes"}
}

// certificateCheck says whether the identity the relay presents is still
// valid.
func certificateCheck(identity Identity, now time.Time) HealthCheck {
	if identity.NotAfter.IsZero() {
		return HealthCheck{Name: CheckCertificate, Code: HealthCertificateUnknown,
			Detail: "the relay holds no end date for its certificate"}
	}
	if !now.Before(identity.NotAfter) {
		return HealthCheck{Name: CheckCertificate, Code: HealthCertificateExpired,
			Detail: "the certificate of the relay ended at " +
				identity.NotAfter.UTC().Format(time.RFC3339)}
	}
	return HealthCheck{Name: CheckCertificate, OK: true,
		Detail: "the certificate of the relay is valid until " +
			identity.NotAfter.UTC().Format(time.RFC3339)}
}

// serveLiveness answers the liveness question.
func (h *Health) serveLiveness(w http.ResponseWriter, r *http.Request) {
	report := h.Liveness()
	status := http.StatusOK
	if report.Status != "alive" {
		status = http.StatusServiceUnavailable
	}
	writeHealth(w, status, report)
}

// serveReadiness answers the readiness question.
func (h *Health) serveReadiness(w http.ResponseWriter, r *http.Request) {
	report := h.Readiness()
	status := http.StatusOK
	if report.Status != "ready" {
		status = http.StatusServiceUnavailable
	}
	writeHealth(w, status, report)
}

// writeHealth writes the answer as JSON. A health answer is never
// cached: a cached "ready" is the one answer that costs.
func writeHealth(w http.ResponseWriter, status int, body any) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(body)
}

// ListenerState watches the listener of the agents so that the liveness answer
// can speak about the listener rather than about the process around it.
type ListenerState struct {
	inner    net.Listener
	accepted atomic.Uint64
	closed   atomic.Bool

	mu sync.Mutex
	// failingSince is when the run of failed accepts began, zero while
	// the listener takes connections.
	failingSince time.Time
	lastErr      error
}

// WatchListener wraps a listener so that its accepts are observable.
func WatchListener(inner net.Listener) *ListenerState {
	return &ListenerState{inner: inner}
}

// Accept takes a connection and notes what happened.
func (l *ListenerState) Accept() (net.Conn, error) {
	conn, err := l.inner.Accept()
	now := time.Now()
	l.mu.Lock()
	defer l.mu.Unlock()
	if err != nil {
		l.lastErr = err
		if l.failingSince.IsZero() {
			l.failingSince = now
		}
		if errors.Is(err, net.ErrClosed) {
			l.closed.Store(true)
		}
		return nil, err
	}
	l.failingSince = time.Time{}
	l.lastErr = nil
	l.accepted.Add(1)
	return conn, nil
}

// Close closes the listener and marks it closed: from then on liveness
// says the relay is no longer serving its site.
func (l *ListenerState) Close() error {
	l.closed.Store(true)
	return l.inner.Close()
}

// Addr is the address the listener stands on.
func (l *ListenerState) Addr() net.Addr { return l.inner.Addr() }

// Accepted is how many connections the listener took since the start.
func (l *ListenerState) Accepted() uint64 { return l.accepted.Load() }

// ListenerPicture is what the liveness answer reads off the listener.
type ListenerPicture struct {
	Closed  bool
	Failing bool
	// FailingFor is how long the accepts have been failing in a row.
	FailingFor time.Duration
	Detail     string
}

// State describes the listener now.
func (l *ListenerState) State(now time.Time, grace time.Duration) ListenerPicture {
	l.mu.Lock()
	defer l.mu.Unlock()
	picture := ListenerPicture{Closed: l.closed.Load(), Detail: "the listener accepts"}
	if l.lastErr != nil {
		picture.Detail = l.lastErr.Error()
	}
	if !l.failingSince.IsZero() {
		picture.FailingFor = now.Sub(l.failingSince)
		picture.Failing = picture.FailingFor >= grace
	}
	return picture
}
