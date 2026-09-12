package integrations

import (
	"errors"
	"testing"
	"time"
)

func TestTheBreakerOpensOnlyAfterARunOfErrors(t *testing.T) {
	now := time.Date(2026, 9, 5, 12, 0, 0, 0, time.UTC)
	breaker := NewBreaker()
	breaker.clock = func() time.Time { return now }
	failure := errors.New("the source says nothing")

	// One error must not cut a source off: failures are sometimes momentary.
	for i := 0; i < ErrorThreshold-1; i++ {
		if err := breaker.Do(func() error { return failure }); !errors.Is(err, failure) {
			t.Fatalf("attempt %d: %v", i, err)
		}
	}
	if breaker.Open() {
		t.Fatal("the breaker opened before the threshold")
	}

	if err := breaker.Do(func() error { return failure }); !errors.Is(err, failure) {
		t.Fatalf("the last attempt: %v", err)
	}
	if !breaker.Open() {
		t.Fatal("the breaker did not open after a run of errors")
	}

	// An open breaker refuses outright and carries an error of its own: a
	// screen that waits five seconds for each panel is a screen without
	// users.
	called := false
	err := breaker.Do(func() error { called = true; return nil })
	if !errors.Is(err, ErrBreakerOpen) {
		t.Fatalf("the open breaker returned %v", err)
	}
	if called {
		t.Fatal("the open breaker let a call through")
	}

	// After the pause we try again; one successful answer closes the breaker.
	now = now.Add(BreakerPause + time.Second)
	if err := breaker.Do(func() error { return nil }); err != nil {
		t.Fatalf("after the pause: %v", err)
	}
	if breaker.Open() {
		t.Fatal("the breaker did not close after a successful answer")
	}
}

func TestTheMappingSubstitutesTheDataOfAHost(t *testing.T) {
	mapping := DefaultMapping()
	mapping.DashboardURL = "https://grafana.example.test/d/hosts?var-host={hostname}&var-site={site}"
	host := Host{ID: "abc", Hostname: "web-01", Site: "waw", Environment: "prod"}

	if label := mapping.Label(host); label != "web-01:9100" {
		t.Fatalf("the label of the host = %q", label)
	}
	if filter := mapping.HostFilter(host); filter != `instance="web-01:9100"` {
		t.Fatalf("the filter of the alerts = %q", filter)
	}
	links := mapping.For(host)
	if links.Dashboard != "https://grafana.example.test/d/hosts?var-host=web-01&var-site=waw" {
		t.Fatalf("the link to the dashboard = %q", links.Dashboard)
	}
	// An installation without a dashboard gets no link leading nowhere.
	empty := DefaultMapping()
	if empty.For(host).Dashboard != "" {
		t.Fatal("the panel invented a link to a dashboard that does not exist")
	}
}
