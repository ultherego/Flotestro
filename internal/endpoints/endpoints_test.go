package endpoints

import (
	"context"
	"errors"
	"strings"
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

// tryManager is a manager with the clock stopped and the backoff between the
// addresses skipped: the failover order is what the tests are about, not how
// long the waiting takes.
func tryManager(addresses ...string) *Manager {
	m := New(addresses, time.Second, time.Minute)
	m.now = func() time.Time { return now }
	m.sleep = func(ctx context.Context, wait time.Duration) error { return ctx.Err() }
	return m
}

// TestTheRenewalTriesTheGatewaysInOrder guards the property the gap names: a
// renewal or an identity recovery does not depend on the first address of the
// list being up.
func TestTheRenewalTriesTheGatewaysInOrder(t *testing.T) {
	m := tryManager("https://a:8443", "https://b:8443", "https://c:8443")
	var tried []string
	answered, err := m.Try(context.Background(), func(ctx context.Context, url string) error {
		tried = append(tried, url)
		if url == "https://b:8443" {
			return nil
		}
		return errors.New("dial tcp: connect: connection refused")
	})
	if err != nil {
		t.Fatalf("the failover gave up: %v", err)
	}
	if answered != "https://b:8443" {
		t.Fatalf("the gateway that answered = %q", answered)
	}
	if len(tried) != 2 || tried[0] != "https://a:8443" || tried[1] != "https://b:8443" {
		t.Fatalf("the addresses were tried as %v", tried)
	}
	// The one that answered carries no error history, and the one that did
	// not is in its retry window.
	states := m.Gateways()
	if states[0].Errors != 1 || states[1].Errors != 0 {
		t.Fatalf("the state after the failover = %+v", states)
	}
}

// TestEveryGatewayRefusingIsOneAnswer guards that a fleet-wide outage is
// reported as what it is: every address, in order, with the reason each one
// gave.
func TestEveryGatewayRefusingIsOneAnswer(t *testing.T) {
	m := tryManager("https://a:8443", "https://b:8443")
	_, err := m.Try(context.Background(), func(ctx context.Context, url string) error {
		if url == "https://b:8443" {
			return errors.New("x509: certificate signed by unknown authority")
		}
		return errors.New("dial tcp: connect: connection refused")
	})
	var failover *Failover
	if !errors.As(err, &failover) {
		t.Fatalf("the answer of a total outage = %v", err)
	}
	if len(failover.Attempts) != 2 {
		t.Fatalf("the attempts on record = %+v", failover.Attempts)
	}
	if failover.Attempts[0].Class != ClassNetwork || failover.Attempts[1].Class != ClassConfiguration {
		t.Fatalf("the classes = %s, %s", failover.Attempts[0].Class, failover.Attempts[1].Class)
	}
	if !strings.Contains(err.Error(), "https://a:8443") || !strings.Contains(err.Error(), "https://b:8443") {
		t.Fatalf("the message names only a part of the fleet: %s", err)
	}
}

// TestARejectedIdentityStopsTheFailover guards the doctrine of the class: a
// certificate the panel revoked is refused by every gateway, so the second
// address is not even tried - and the caller learns the reason rather than a
func TestARejectedIdentityStopsTheFailover(t *testing.T) {
	m := tryManager("https://a:8443", "https://b:8443")
	tried := 0
	_, err := m.Try(context.Background(), func(ctx context.Context, url string) error {
		tried++
		return errors.New("the certificate was revoked")
	})
	if !errors.Is(err, ErrIdentityRejected) {
		t.Fatalf("the answer = %v", err)
	}
	if tried != 1 {
		t.Fatalf("the addresses tried = %d; a revoked identity is not a matter of the address", tried)
	}
}

// TestOneAddressBehavesAsBefore guards the installations that configure a
// single gateway: one attempt, its own error, and no waiting introduced by the
// failover.
func TestOneAddressBehavesAsBefore(t *testing.T) {
	m := tryManager("https://a:8443")
	tried := 0
	answered, err := m.Try(context.Background(), func(ctx context.Context, url string) error {
		tried++
		return nil
	})
	if err != nil || answered != "https://a:8443" || tried != 1 {
		t.Fatalf("answered=%q tried=%d err=%v", answered, tried, err)
	}
	m = tryManager()
	if _, err := m.Try(context.Background(), func(ctx context.Context, url string) error {
		return nil
	}); !errors.Is(err, ErrNoGateway) {
		t.Fatalf("a manager without addresses answered %v", err)
	}
}
