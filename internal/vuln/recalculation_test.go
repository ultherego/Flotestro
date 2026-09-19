package vuln

import (
	"testing"
	"time"
)

// TestWeRecomputeOnlyChangedInput guards that a sweep of the fleet does not
// rewrite assessments that would come out identical anyway - and that it
// misses no change that does change the result.
func TestWeRecomputeOnlyChangedInput(t *testing.T) {
	scheduler := &Scheduler{settings: DefaultSettings()}
	snapshot := Snapshot{
		Provider: "debian", Digest: "s1", Releases: []string{"trixie"},
		FetchedAt: now.Add(-time.Hour),
	}
	input := Input{
		HostID: "host-1", Distribution: "debian", Release: "trixie",
		InventoryDigest: "list-1", AdvisoryDigest: "",
	}
	assessed := now.Add(-time.Minute)
	previous := HostState{
		HostID: "host-1", Distribution: "debian", Release: "trixie",
		Provider: "debian", SnapshotDigest: "s1", InventoryDigest: "list-1",
		EvaluatedAt: &assessed,
	}

	if scheduler.toRecalculate(previous, input, snapshot, now) {
		t.Fatal("we recompute an assessment whose input has not changed")
	}

	// Each of the three sources has to force a recomputation on its own: the
	// feed, the package list and the set of findings change independently of one
	// another.
	changes := map[string]func(*HostState, *Input, *Snapshot){
		"a different feed snapshot": func(_ *HostState, _ *Input, s *Snapshot) { s.Digest = "s2" },
		"a different package list":  func(_ *HostState, i *Input, _ *Snapshot) { i.InventoryDigest = "list-2" },
		"different findings of the host": func(_ *HostState, i *Input, _ *Snapshot) {
			i.AdvisoryDigest = "a2"
		},
		"a different release": func(_ *HostState, i *Input, s *Snapshot) {
			i.Release = "forky"
			s.Releases = []string{"forky"}
		},
		"a host never assessed": func(p *HostState, _ *Input, _ *Snapshot) { p.EvaluatedAt = nil },
		"an assessment older than the age of the feed": func(p *HostState, _ *Input, _ *Snapshot) {
			longAgo := now.Add(-48 * time.Hour)
			p.EvaluatedAt = &longAgo
		},
		"the list has drifted apart from the host": func(_ *HostState, i *Input, _ *Snapshot) {
			i.ListStale = true
		},
	}
	for name, change := range changes {
		p, i, s := previous, input, snapshot
		change(&p, &i, &s)
		if !scheduler.toRecalculate(p, i, s, now) {
			t.Errorf("%s: the assessment was not recomputed", name)
		}
	}

	// The passage of time alone changes the result as well: a feed fresh in the
	// morning is sometimes stale in the evening, and that is a different answer
	// with the same digests.
	later := now.Add(12 * time.Hour)
	if !scheduler.toRecalculate(previous, input, snapshot, later) {
		t.Error("a feed that had grown old did not force a recomputation")
	}
}

// TestAHostWhoseLastPassFailedIsTriedAgain guards that a recorded failure does
// not freeze a host on its old verdict: without this the host waits for one of
// its digests to change, which may never happen.
func TestAHostWhoseLastPassFailedIsTriedAgain(t *testing.T) {
	scheduler := &Scheduler{settings: DefaultSettings()}
	snapshot := Snapshot{
		Provider: "debian", Digest: "s1", Releases: []string{"trixie"},
		FetchedAt: now.Add(-time.Hour),
	}
	input := Input{
		HostID: "host-1", Distribution: "debian", Release: "trixie",
		InventoryDigest: "list-1",
	}
	assessed := now.Add(-time.Minute)
	previous := HostState{
		HostID: "host-1", Distribution: "debian", Release: "trixie",
		Provider: "debian", SnapshotDigest: "s1", InventoryDigest: "list-1",
		EvaluatedAt: &assessed,
	}
	if scheduler.toRecalculate(previous, input, snapshot, now) {
		t.Fatal("an assessment whose input has not changed is recomputed")
	}

	previous.EvaluationFailedReason = EvaluationFailed
	previous.EvaluationFailedSource = SourcePackageList
	if !scheduler.toRecalculate(previous, input, snapshot, now) {
		t.Fatal("a host whose last pass failed is not tried again")
	}
}

// TestTheStatusSaysHowMuchOfAVerdictHolds guards the one word the panel shows
// beside every number.
func TestTheStatusSaysHowMuchOfAVerdictHolds(t *testing.T) {
	assessed := now.Add(-time.Minute)
	full := HostState{
		EvaluatedAt: &assessed, PackagesTotal: 10, PackagesCovered: 10,
	}
	cases := []struct {
		name  string
		state HostState
		want  EvaluationStatus
	}{
		{"never assessed", HostState{}, StatusUnknown},
		{"complete", full, StatusComplete},
		{"a package nobody could place", withUnknown(full, 1), StatusPartial},
		{"a feed that covers part of the host", withCovered(full, 7), StatusPartial},
		{"an obstacle that stopped the assessment",
			withReason(full, ReasonPackageListMissing), StatusUnknown},
		{"sources that aged", withReason(full, ReasonFeedStale), StatusStale},
		{"a pass that could not run", withFailure(full), StatusStale},
	}
	for _, test := range cases {
		if got := test.state.Status(); got != test.want {
			t.Errorf("%s: the status is %q, expected %q", test.name, got, test.want)
		}
	}
}

func withUnknown(state HostState, unknown int) HostState {
	state.Unknown = unknown
	return state
}

func withCovered(state HostState, covered int) HostState {
	state.PackagesCovered = covered
	return state
}

func withReason(state HostState, reason string) HostState {
	state.CoverageReason = reason
	return state
}

func withFailure(state HostState) HostState {
	state.EvaluationFailedReason = EvaluationFailed
	state.EvaluationFailedSource = SourceFeedAdvisories
	return state
}
