package scheduler

import (
	"context"
	"log/slog"
	"testing"
	"time"

	"github.com/ultherego/flotestro/internal/gateway"
	"github.com/ultherego/flotestro/internal/jobs"
)

// The ambiguity check asks the database once per pass, about each host
// once; without a database it holds nobody and fails nobody.
func TestTheAmbiguityCheckNamesEachHostOnceAndNeedsNoDatabaseToPass(t *testing.T) {
	leased := []jobs.LeasedJob{
		{Job: jobs.Job{ID: "j1", HostID: "h1"}},
		{Job: jobs.Job{ID: "j2", HostID: "h2"}},
		{Job: jobs.Job{ID: "j3", HostID: "h1"}},
	}
	hosts := hostsOf(leased)
	if len(hosts) != 2 || hosts[0] != "h1" || hosts[1] != "h2" {
		t.Errorf("hosts = %v", hosts)
	}
	if hostsOf(nil) == nil || len(hostsOf(nil)) != 0 {
		t.Error("no tasks should give an empty list, not nothing")
	}

	s := &Scheduler{log: slog.Default()}
	ambiguous, err := s.ambiguousHosts(context.Background(), hosts)
	if err != nil || ambiguous != nil {
		t.Errorf("without a store: %v, %v", ambiguous, err)
	}
	if ambiguous["h1"] {
		t.Error("a nil answer must read as nobody ambiguous")
	}
}

// A task goes out only to the session the host's ownership row names, with the
// token it claimed; anything else holds the task, each under its own reason.
func TestATaskGoesOutOnlyToTheLiveOwnerWithItsToken(t *testing.T) {
	now := time.Now()
	session := gateway.NewSession("session-b", "h1", "0.53.0", "boot", "203.0.113.9", 1)
	session.FenceToken = 42

	cases := []struct {
		name   string
		owner  jobs.Owner
		reason string
	}{
		{name: "no row", owner: jobs.Owner{}, reason: ErrorSessionUnowned},
		{name: "released row", owner: jobs.Owner{Token: 42}, reason: ErrorSessionUnowned},
		{name: "lease ran out", owner: jobs.Owner{SessionID: "session-b", Token: 42,
			LeaseUntil: now.Add(-time.Second)}, reason: ErrorSessionUnowned},
		{name: "another session owns the host", owner: jobs.Owner{SessionID: "session-c", Token: 43,
			LeaseUntil: now.Add(time.Minute)}, reason: jobs.ErrorSessionFenceStale},
		{name: "same session, older token", owner: jobs.Owner{SessionID: "session-b", Token: 41,
			LeaseUntil: now.Add(time.Minute)}, reason: jobs.ErrorSessionFenceStale},
		{name: "the live owner", owner: jobs.Owner{SessionID: "session-b", Token: 42,
			LeaseUntil: now.Add(time.Minute)}},
	}
	for _, c := range cases {
		reason, ok := deliverable(c.owner, session, now)
		if ok != (c.reason == "") || reason != c.reason {
			t.Errorf("%s: deliverable = %v with reason %q, expected reason %q", c.name, ok, reason, c.reason)
		}
	}
}
