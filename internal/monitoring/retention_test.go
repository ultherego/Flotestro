package monitoring

import (
	"errors"
	"strings"
	"testing"
	"time"
)

// TestTheDefaultsAreTheOnesTheDocumentAsksFor pins the numbers an installation
// gets without saying anything: a week of readings at full resolution and a
// quarter of a year of quarter-hours.
func TestTheDefaultsAreTheOnesTheDocumentAsksFor(t *testing.T) {
	filled := Options{}.withDefaults()
	if filled.RawRetention != 7*24*time.Hour {
		t.Fatalf("the raw retention defaults to %s", filled.RawRetention)
	}
	if filled.RollupRetention != 90*24*time.Hour {
		t.Fatalf("the rollup retention defaults to %s", filled.RollupRetention)
	}
	if filled.MaxLateness != 24*time.Hour || filled.RawQueryWindow != 24*time.Hour {
		t.Fatalf("the lateness and the query window default to %s and %s",
			filled.MaxLateness, filled.RawQueryWindow)
	}
	if err := filled.Validate(); err != nil {
		t.Fatalf("the defaults do not pass their own validation: %v", err)
	}
}

// TestARetentionThatDeletesWhatIsStillArrivingIsRefused: a configuration whose
// raw retention is shorter than the window it offers plus the longest a sample
// may take to arrive throws readings away by definition, and the panel says so
func TestARetentionThatDeletesWhatIsStillArrivingIsRefused(t *testing.T) {
	options := Options{
		RawRetention:   24 * time.Hour,
		RawQueryWindow: 24 * time.Hour,
		MaxLateness:    24 * time.Hour,
	}
	err := options.Validate()
	if err == nil {
		t.Fatal("a retention shorter than the query window plus the lateness was accepted")
	}
	if !strings.Contains(err.Error(), ErrorRetentionTooShort) {
		t.Fatalf("the refusal carries no code an operator can look up: %v", err)
	}
	options.RawRetention = 48 * time.Hour
	if err := options.Validate(); err != nil {
		t.Fatalf("a retention exactly equal to the sum was refused: %v", err)
	}
}

// TestAnAbsurdMarginOfPartitionsIsRefused: a partition is a table, and a
// configuration asking for a year of empty ones is a mistake.
func TestAnAbsurdMarginOfPartitionsIsRefused(t *testing.T) {
	options := Options{PartitionsAhead: 365}
	if err := options.Validate(); err == nil {
		t.Fatal("a year of partitions created ahead was accepted")
	}
}

// TestAPartitionIsNamedAfterTheDayItBegins, and the name reads back: the
// retention derives the end of a partition's range from its name, so a name
// that does not round-trip is a partition that is dropped at the wrong moment
func TestAPartitionIsNamedAfterTheDayItBegins(t *testing.T) {
	at := time.Date(2026, 9, 18, 0, 0, 0, 0, time.UTC)
	name := partitionName(at)
	if name != "host_metrics_p20260918" {
		t.Fatalf("the partition of %s is named %s", at.Format(time.RFC3339), name)
	}
	back, ok := partitionDay(name)
	if !ok || !back.Equal(at) {
		t.Fatalf("the name %s reads back as %s (%v)", name, back, ok)
	}
	for _, other := range []string{"host_metrics", "host_metrics_15m", "host_metrics_pnotaday"} {
		if _, ok := partitionDay(other); ok {
			t.Fatalf("%s was taken for a daily partition; this code drops what it names", other)
		}
	}
}

// TestALeaseIsOnlyHeldWhileItLasts: the holder and the term together say
// whether an instance may write, and neither alone does.
func TestALeaseIsOnlyHeldWhileItLasts(t *testing.T) {
	now := time.Date(2026, 9, 18, 12, 0, 0, 0, time.UTC)
	held := Lease{Holder: "instance-a", Until: now.Add(30 * time.Second)}
	if !held.Held(now) {
		t.Fatal("a lease with a holder and a term that has not run out is not held")
	}
	if held.Held(now.Add(time.Minute)) {
		t.Fatal("a lease was still held after its term ran out")
	}
	if (Lease{Until: now.Add(time.Minute)}).Held(now) {
		t.Fatal("a lease nobody holds was held")
	}
}

// TestTheFenceRefusesOnlyWhatIsOlderThanTheRow walks the predicate the alert
// writes carry: not older than the token on the row, fail closed without a
// lease, and open for a row nothing ever stamped.
func TestTheFenceRefusesOnlyWhatIsOlderThanTheRow(t *testing.T) {
	token := func(value int64) *int64 { return &value }
	leader := fence{Holder: "instance-a", Token: 7}
	if !leader.held() {
		t.Fatal("a fence with a holder and a token minted from the lease is not held")
	}
	// A row a panel of the previous release wrote carries no token. Refusing it
	// would leave an episode nobody can ever resolve.
	if !leader.accepts(nil) {
		t.Fatal("the fence refused a row that carries no token")
	}
	if !leader.accepts(token(6)) {
		t.Fatal("the fence refused a row an older lease wrote")
	}
	// Its own: a leader writes the same episode again and again under one lease.
	if !leader.accepts(token(7)) {
		t.Fatal("the fence refused the row its own lease wrote; the pass would never make progress")
	}
	if leader.accepts(token(8)) {
		t.Fatal("the fence let a stale pass write over a newer leader")
	}

	// Fail closed: no lease, no write. The token is minted from zero the first
	// time the lease changes hands, so zero is nobody's.
	for _, without := range []fence{{}, {Holder: "instance-a"}, {Token: 7}} {
		if without.held() || without.accepts(nil) || without.accepts(token(1)) {
			t.Fatalf("a pass without a lease wrote under %+v", without)
		}
	}
}

// TestTheRefusedWriteAnswersToTheLostLease: the pass stops on a refusal
// because it recognises the lease loss in it, and the code is the one an
// operator looks up.
func TestTheRefusedWriteAnswersToTheLostLease(t *testing.T) {
	if !errors.Is(ErrFenceStale, ErrLeaseLost) {
		t.Fatal("a write the fence refused is not a lost lease; the pass would carry on")
	}
	if !strings.HasPrefix(ErrFenceStale.Error(), ErrorAlertFenceStale+":") {
		t.Fatalf("the refusal does not name its own code: %q", ErrFenceStale)
	}
	if !strings.Contains(ErrFenceStale.Error(), ErrorEvaluatorLeaseLost) {
		t.Fatalf("the refusal does not name the lease it lost: %q", ErrFenceStale)
	}
}

// TestEveryFencedStatementStampsAndCompares pins the two halves of the
// predicate that are easy to write the other way round and impossible to
// notice afterwards.
func TestEveryFencedStatementStampsAndCompares(t *testing.T) {
	if !strings.Contains(fencePredicate, "fencing_token is null") {
		t.Fatal("the predicate has nothing to say about a row no token was put on; " +
			"an episode from a panel of the previous release would never be writable again")
	}
	if !strings.Contains(fencePredicate, "<= fence_lease.token") {
		t.Fatal("the predicate refuses the row the lease itself wrote; " +
			"two instances would hand an episode back and forth without either writing it")
	}
	if !strings.Contains(fencedWrite, "lease_until > now()") {
		t.Fatal("the framed write does not check the lease in the same statement")
	}
	if !strings.Contains(fencedInsert, "fence_lease.token") {
		t.Fatal("an episode is opened without the token of the lease that opened it")
	}
}
