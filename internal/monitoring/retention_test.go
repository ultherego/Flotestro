package monitoring

import (
	"strings"
	"testing"
	"time"
)

// TestTheDefaultsAreTheOnesTheDocumentAsksFor pins the numbers an
// installation gets without saying anything: a week of readings at full
// resolution and a quarter of a year of quarter-hours.
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

// TestARetentionThatDeletesWhatIsStillArrivingIsRefused: a configuration
// whose raw retention is shorter than the window it offers plus the
// longest a sample may take to arrive throws readings away by definition,
// and the panel says so at start rather than from a missing week.
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
// retention derives the end of a partition's range from its name, so a
// name that does not round-trip is a partition that is dropped at the
// wrong moment or never.
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
