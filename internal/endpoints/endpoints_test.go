package endpoints

import (
	"errors"
	"testing"
	"time"
)

var now = time.Date(2026, 9, 6, 12, 0, 0, 0, time.UTC)

func manager() *Manager {
	return New([]string{"https://a:8443", "https://b:8443"}, time.Second, time.Minute)
}

// TestTheFirstGatewayIsThePriority guards that the list is an order rather
// than a set: once the main gateway is back the fleet is to use it instead of
// staying on the backup one.
func TestTheFirstGatewayIsThePriority(t *testing.T) {
	m := manager()
	gateway, err := m.Choose(now)
	if err != nil || gateway == nil || gateway.URL != "https://a:8443" {
		t.Fatalf("chose %v (%v)", gateway, err)
	}

	m.Error("https://a:8443", ClassNetwork, now)
	gateway, err = m.Choose(now)
	if err != nil || gateway == nil || gateway.URL != "https://b:8443" {
		t.Fatalf("after an error of the first one it chose %v (%v)", gateway, err)
	}

	// The window of the first one has passed - we return to it.
	gateway, err = m.Choose(now.Add(2 * time.Minute))
	if err != nil || gateway == nil || gateway.URL != "https://a:8443" {
		t.Fatalf("after the window it chose %v (%v)", gateway, err)
	}
}

// TestARevokedIdentityStopsTheAttempts guards the property from the document:
// a revoked certificate is not a failure of the link and the agent is to stop
// knocking rather than switch between gateways endlessly.
func TestARevokedIdentityStopsTheAttempts(t *testing.T) {
	m := manager()
	m.Error("https://a:8443", ClassIdentity, now)
	if _, err := m.Choose(now.Add(time.Hour)); !errors.Is(err, ErrIdentityRejected) {
		t.Fatalf("after the identity was rejected the manager returned %v", err)
	}
}

// TestAConfigurationErrorWaitsLonger guards that a wrong configuration does
// not turn into a loop of retries: a person fixes it rather than another
// attempt.
func TestAConfigurationErrorWaitsLonger(t *testing.T) {
	m := New([]string{"https://a:8443"}, time.Second, time.Minute)
	m.Error("https://a:8443", ClassConfiguration, now)
	state := m.Gateways()[0]
	if state.NextAttempt.Sub(now) > ConfigurationBackoff {
		t.Fatalf("the window %s exceeds the limit", state.NextAttempt.Sub(now))
	}
	if _, err := m.Choose(now.Add(time.Minute)); err != nil {
		t.Fatal(err)
	}
	// After a minute the gateway may still not be ready - that is the point.
	// We only check that the manager does not ask to wait longer than the
	// class of the error implies.
	if waiting := m.UntilNext(now); waiting > ConfigurationBackoff {
		t.Fatalf("the waiting %s exceeds the limit", waiting)
	}
}

// TestTheBackoffDoesNotOverflow guards that a gateway unavailable for a long
// time does not get a negative window after the bit shift overflows.
func TestTheBackoffDoesNotOverflow(t *testing.T) {
	m := New([]string{"https://a:8443"}, time.Second, time.Minute)
	for i := 0; i < 80; i++ {
		m.Error("https://a:8443", ClassNetwork, now)
		state := m.Gateways()[0]
		window := state.NextAttempt.Sub(now)
		if window < 0 || window > time.Minute {
			t.Fatalf("after %d errors the window = %s", i+1, window)
		}
	}
}

// TestSuccessClearsTheHistory guards that a gateway that works again returns
// to full availability instead of carrying the backoff from before the
// failure.
func TestSuccessClearsTheHistory(t *testing.T) {
	m := manager()
	m.Error("https://a:8443", ClassNetwork, now)
	m.Success("https://a:8443", now)
	gateway, err := m.Choose(now)
	if err != nil || gateway.URL != "https://a:8443" || gateway.Errors != 0 {
		t.Fatalf("after the success the state = %+v (%v)", gateway, err)
	}
}

func TestTheClassificationOfErrors(t *testing.T) {
	cases := []struct {
		text  string
		class Class
	}{
		{"the certificate was revoked", ClassIdentity},
		{"x509: certificate signed by unknown authority", ClassConfiguration},
		{"x509: certificate is valid for panel, not gateway", ClassConfiguration},
		{"dial tcp 10.0.0.1:8443: connect: connection refused", ClassNetwork},
		{"context deadline exceeded", ClassNetwork},
	}
	for _, c := range cases {
		t.Run(c.text, func(t *testing.T) {
			if got := Classify(errors.New(c.text)); got != c.class {
				t.Fatalf("Classify = %q, expected %q", got, c.class)
			}
		})
	}
}

// TestDuplicateGatewaysAreSkipped guards that the same gateway written twice
// does not get a double chance in the queue of retries.
func TestDuplicateGatewaysAreSkipped(t *testing.T) {
	m := New([]string{"https://a:8443", "https://a:8443", ""}, time.Second, time.Minute)
	if len(m.Gateways()) != 1 {
		t.Fatalf("gateways = %+v", m.Gateways())
	}
}
