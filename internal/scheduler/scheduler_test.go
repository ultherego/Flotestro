package scheduler

import (
	"context"
	"log/slog"
	"testing"

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
