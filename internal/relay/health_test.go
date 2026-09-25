package relay

import (
	"encoding/json"
	"errors"
	"net"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/ultherego/flotestro/internal/relay/spool"
)

// ask sends one request to the health handler and gives back the status
// and the decoded answer.
func ask(t *testing.T, health *Health, path string, into any) int {
	t.Helper()
	recorder := httptest.NewRecorder()
	health.Handler().ServeHTTP(recorder, httptest.NewRequest(http.MethodGet, path, nil))
	if into != nil {
		if err := json.Unmarshal(recorder.Body.Bytes(), into); err != nil {
			t.Fatalf("the answer of %s did not decode: %v (%s)", path, err, recorder.Body.String())
		}
	}
	return recorder.Code
}

// validIdentity is a relay whose certificate ends well after the tests.
func validIdentity() Identity {
	return Identity{RelayID: "relay-1", NotAfter: time.Now().Add(72 * time.Hour)}
}

// named says whether the readiness answer carried the code.
func named(report ReadinessReport, code string) bool {
	for _, reason := range report.Reasons {
		if reason == code {
			return true
		}
	}
	return false
}

// TestLivenessSurvivesAnOutageOfTheCentre is the whole point of two answers
// instead of one.
func TestLivenessSurvivesAnOutageOfTheCentre(t *testing.T) {
	relay := newTestRelay(t, spool.Options{})
	// The link is down and the spool holds what the site produced
	// meanwhile: the state of a relay in an outage.
	relay.upstream.Store(false)
	if record, _ := relay.keep("host-1", signed(heartbeat(1), "session-a", 1)); record == nil {
		t.Fatal("the spool did not take the message of the outage")
	}
	health := NewHealth(HealthOptions{Relay: relay, Identity: validIdentity})

	var live LivenessReport
	if status := ask(t, health, HealthPathLive, &live); status != http.StatusOK {
		t.Fatalf("liveness during an outage answered %d, and a runtime would restart the "+
			"one process that holds the results of the site", status)
	}
	if live.Status != "alive" {
		t.Fatalf("liveness = %+v", live)
	}
	if live.Upstream != UpstreamBuffering {
		t.Fatalf("liveness did not say the relay is buffering: %+v", live)
	}

	var ready ReadinessReport
	if status := ask(t, health, HealthPathReady, &ready); status != http.StatusServiceUnavailable {
		t.Fatalf("readiness during an outage answered %d, expected 503", status)
	}
	if !named(ready, HealthUpstreamUnreachable) {
		t.Fatalf("readiness did not name the link: %+v", ready)
	}
	if ready.SafeToRestart {
		t.Fatalf("a relay holding a spool called itself safe to restart: %+v", ready)
	}
}

// TestReadinessIsTrueOnlyWhenTheRelayCanCarryWork guards the positive answer:
// the link is up, the spool is inside its bound and the certificate is valid.
func TestReadinessIsTrueOnlyWhenTheRelayCanCarryWork(t *testing.T) {
	relay := newTestRelay(t, spool.Options{})
	relay.upstream.Store(true)
	health := NewHealth(HealthOptions{Relay: relay, Identity: validIdentity})

	var ready ReadinessReport
	if status := ask(t, health, HealthPathReady, &ready); status != http.StatusOK {
		t.Fatalf("a working relay answered readiness %d: %+v", status, ready)
	}
	if ready.Status != "ready" || len(ready.Reasons) != 0 {
		t.Fatalf("readiness = %+v", ready)
	}
	if !ready.SafeToRestart {
		t.Fatalf("an empty spool on a live link is safe to restart: %+v", ready)
	}
	if len(ready.Checks) != 4 {
		t.Fatalf("readiness answered %d checks, expected the listener, the link, the spool "+
			"and the certificate: %+v", len(ready.Checks), ready.Checks)
	}
}

// TestReadinessNamesTheSpoolAndTheCertificate guards the requirement that a
// readiness answer says which of its questions is false rather than only that
// something is.
func TestReadinessNamesTheSpoolAndTheCertificate(t *testing.T) {
	// A spool whose reserve begins almost at once: one record puts it in its
	// reserve, which is the state in which the relay refuses new sessions.
	relay := newTestRelay(t, spool.Options{MaxBytes: 4096, CriticalReserveBytes: 4000})
	relay.upstream.Store(true)
	if record, _ := relay.keep("host-1", signed(heartbeat(1), "session-a", 1)); record == nil {
		t.Fatal("the spool did not take the message")
	}
	expired := func() Identity {
		return Identity{RelayID: "relay-1", NotAfter: time.Now().Add(-time.Hour)}
	}
	health := NewHealth(HealthOptions{Relay: relay, Identity: expired})

	var ready ReadinessReport
	if status := ask(t, health, HealthPathReady, &ready); status != http.StatusServiceUnavailable {
		t.Fatalf("a full spool and an expired certificate answered %d", status)
	}
	if !named(ready, HealthSpoolCritical) || !named(ready, HealthCertificateExpired) {
		t.Fatalf("readiness named %v, expected the spool and the certificate", ready.Reasons)
	}
	// The link is up, so nothing about it is named: a readiness answer that
	// blamed the link here would send the operator to the WAN while the disk is
	// what is full.
	if named(ready, HealthUpstreamUnreachable) {
		t.Fatalf("readiness blamed the link although it is up: %+v", ready)
	}
}

// TestAnIdentityWithoutAnEndIsNotReady guards the doctrine: unknown is never
// zero.
func TestAnIdentityWithoutAnEndIsNotReady(t *testing.T) {
	relay := newTestRelay(t, spool.Options{})
	relay.upstream.Store(true)
	health := NewHealth(HealthOptions{Relay: relay,
		Identity: func() Identity { return Identity{RelayID: "relay-1"} }})

	var ready ReadinessReport
	if status := ask(t, health, HealthPathReady, &ready); status != http.StatusServiceUnavailable {
		t.Fatalf("an identity without an end answered %d", status)
	}
	if !named(ready, HealthCertificateUnknown) {
		t.Fatalf("readiness named %v", ready.Reasons)
	}
}

// TestASpoolThatCannotWriteIsNotReady guards the property behind the durable
// spool: a relay whose disk stopped taking the writes must not keep collecting
// the results of the site as though it held them.
func TestASpoolThatCannotWriteIsNotReady(t *testing.T) {
	check := spoolCheck(Stats{Messages: 2, Bytes: 400, MaxBytes: 4096},
		errors.New("sync /var/lib/flotestro-relay/spool/segment-1.log: input/output error"))
	if check.OK || check.Code != HealthSpoolUnwritable {
		t.Fatalf("the spool check of a disk that stopped taking writes = %+v", check)
	}
	// A spool inside its bound and writing is the one that reports ready.
	if check := spoolCheck(Stats{Messages: 2, Bytes: 400, MaxBytes: 4096}, nil); !check.OK {
		t.Fatalf("a working spool = %+v", check)
	}
}

// failingListener is a listener that accepts nothing: the shape of a
// relay out of file descriptors.
type failingListener struct{ err error }

func (f failingListener) Accept() (net.Conn, error) { return nil, f.err }
func (f failingListener) Close() error              { return nil }
func (f failingListener) Addr() net.Addr            { return &net.TCPAddr{Port: 8453} }

// TestLivenessTurnsWhenTheListenerStopsAccepting guards the other half of the
// liveness answer.
func TestLivenessTurnsWhenTheListenerStopsAccepting(t *testing.T) {
	relay := newTestRelay(t, spool.Options{})
	relay.upstream.Store(true)
	watched := WatchListener(failingListener{err: errors.New("too many open files")})
	later := time.Now().Add(time.Hour)
	health := NewHealth(HealthOptions{Relay: relay, Listener: watched,
		Identity: validIdentity, Now: func() time.Time { return later }})

	// While the listener accepts, liveness is true.
	if status := ask(t, health, HealthPathLive, nil); status != http.StatusOK {
		t.Fatalf("a listener that has not failed yet answered %d", status)
	}
	if _, err := watched.Accept(); err == nil {
		t.Fatal("the listener of this test was meant to fail")
	}

	var live LivenessReport
	if status := ask(t, health, HealthPathLive, &live); status != http.StatusServiceUnavailable {
		t.Fatalf("a listener failing for an hour answered liveness %d", status)
	}
	if live.Code != HealthListenerUnavailable {
		t.Fatalf("liveness = %+v", live)
	}
	var ready ReadinessReport
	if status := ask(t, health, HealthPathReady, &ready); status != http.StatusServiceUnavailable {
		t.Fatalf("a wedged listener answered readiness %d", status)
	}
	if !named(ready, HealthListenerUnavailable) {
		t.Fatalf("readiness named %v", ready.Reasons)
	}
}

// TestAFailedAcceptThatPassesIsNotAWedgedRelay guards the grace period: a
// single refused accept under load is not a reason to throw away the spool of
// a site.
func TestAFailedAcceptThatPassesIsNotAWedgedRelay(t *testing.T) {
	relay := newTestRelay(t, spool.Options{})
	watched := WatchListener(failingListener{err: errors.New("too many open files")})
	health := NewHealth(HealthOptions{Relay: relay, Listener: watched, Identity: validIdentity})
	if _, err := watched.Accept(); err == nil {
		t.Fatal("the listener of this test was meant to fail")
	}
	if status := ask(t, health, HealthPathLive, nil); status != http.StatusOK {
		t.Fatalf("one failed accept answered liveness %d", status)
	}
}

// TestTheHealthListenerAnswersTwoQuestionsAndNothingElse guards what the
// listener is: it carries no client certificate, so it answers the two health
// questions and refuses to be a second way into the relay.
func TestTheHealthListenerAnswersTwoQuestionsAndNothingElse(t *testing.T) {
	relay := newTestRelay(t, spool.Options{})
	health := NewHealth(HealthOptions{Relay: relay, Identity: validIdentity})
	for _, path := range []string{"/", "/metrics", "/flotestro.agent.v1.AgentService/Connect"} {
		if status := ask(t, health, path, nil); status != http.StatusNotFound {
			t.Fatalf("the health listener answered %s with %d", path, status)
		}
	}
	if status := ask(t, health, HealthPathAlias, nil); status != http.StatusOK {
		t.Fatalf("the liveness alias answered %d", status)
	}
}
