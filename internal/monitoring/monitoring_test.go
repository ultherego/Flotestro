package monitoring

import (
	"testing"
	"time"
)

// TestTheClockOfAHostIsBoundedInBothDirections: a reading dated ahead of the
// panel takes the panel's moment, because nothing observes the future; one
// dated behind keeps its own, because a reading that waited in a spool
// belongs where it was taken; one dated further back than the panel keeps
// any reading is refused rather than stored somewhere convenient.
func TestTheClockOfAHostIsBoundedInBothDirections(t *testing.T) {
	now := time.Date(2026, 9, 19, 12, 0, 0, 0, time.UTC)
	const skewLimit, maxLateness = 5 * time.Minute, 24 * time.Hour

	ahead := ClampObservation(now.Add(30*time.Minute), now, skewLimit, maxLateness)
	if !ahead.Substituted {
		t.Fatal("a reading half an hour in the future kept the host's moment")
	}
	if !ahead.At.Equal(now) {
		t.Fatalf("the substituted moment is %s, not the panel's %s", ahead.At, now)
	}
	if ahead.Skew != 30*time.Minute {
		t.Fatalf("the skew was measured as %s", ahead.Skew)
	}
	if ahead.TooOld {
		t.Fatal("a reading from the future was called too old")
	}

	// Inside the limit nothing is touched, in either direction.
	for _, offset := range []time.Duration{-time.Minute, 0, time.Minute} {
		at := now.Add(offset)
		observed := ClampObservation(at, now, skewLimit, maxLateness)
		if observed.Substituted || observed.TooOld || !observed.At.Equal(at) {
			t.Fatalf("a reading %s from the panel's clock was not left alone: %+v", offset, observed)
		}
	}

	// A relay that comes back after three hours delivers readings three hours
	// old. Stamping those with the moment they arrived would draw the outage
	// as an unbroken line, which is the one thing a gap exists to prevent.
	late := ClampObservation(now.Add(-3*time.Hour), now, skewLimit, maxLateness)
	if late.Substituted {
		t.Fatal("a reading drained from a spool was restamped with the panel's clock")
	}
	if !late.At.Equal(now.Add(-3 * time.Hour)) {
		t.Fatalf("the late reading was moved to %s", late.At)
	}
	if late.Skew != -3*time.Hour {
		t.Fatalf("the skew of a late reading was measured as %s", late.Skew)
	}

	older := ClampObservation(now.Add(-48*time.Hour), now, skewLimit, maxLateness)
	if !older.TooOld {
		t.Fatal("a reading older than the lateness budget was accepted")
	}
	if older.Substituted {
		t.Fatal("a refused reading was also restamped; a refusal stores nothing at all")
	}
}

// TestTheClampFallsBackToTheDefaultsOfTheInstallation: a gateway that asks
// with zero limits must not accept everything.
func TestTheClampFallsBackToTheDefaultsOfTheInstallation(t *testing.T) {
	now := time.Date(2026, 9, 19, 12, 0, 0, 0, time.UTC)
	observed := ClampObservation(now.Add(time.Hour), now, 0, 0)
	if !observed.Substituted {
		t.Fatal("with no limits given a reading an hour in the future was stored as the host dated it")
	}
	if !ClampObservation(now.Add(-48*time.Hour), now, 0, 0).TooOld {
		t.Fatal("with no limits given a reading two days old was accepted")
	}
}

// pointsAt builds a run of readings one step apart from the moment given.
func pointsAt(start time.Time, step time.Duration, count int, value float64) []Point {
	list := make([]Point, 0, count)
	for i := 0; i < count; i++ {
		list = append(list, Point{At: start.Add(time.Duration(i) * step), CPUPercent: value})
	}
	return list
}

// TestAHoleInTheSeriesIsReportedAsAHole: three hours without a reading are
// three hours the answer has to name. Left out, they reach the chart as two
// readings side by side and are drawn as a smooth line.
func TestAHoleInTheSeriesIsReportedAsAHole(t *testing.T) {
	r := Range{Name: "24h", Window: 24 * time.Hour, Step: SamplingInterval}
	until := time.Date(2026, 9, 19, 12, 0, 0, 0, time.UTC)
	from := until.Add(-r.Window)

	// An hour of readings, three hours of nothing, then readings up to now.
	head := pointsAt(from, r.Step, 60, 10)
	tail := pointsAt(from.Add(4*time.Hour), r.Step, 20*60, 10)
	gaps := gapsIn(append(head, tail...), r, from, until)
	if len(gaps) != 1 {
		t.Fatalf("the window holds %d holes, expected the one in the middle: %+v", len(gaps), gaps)
	}
	hole := gaps[0]
	if !hole.From.Equal(from.Add(59*time.Minute)) || !hole.To.Equal(from.Add(4*time.Hour)) {
		t.Fatalf("the hole is reported between %s and %s", hole.From, hole.To)
	}
	if hole.Steps < 170 {
		t.Fatalf("the hole swallowed %d steps; three hours of minutes is about 180", hole.Steps)
	}
	if hole.Reason != "" || hole.RefusedSamples != 0 {
		t.Fatalf("a hole nobody explained came back with the reason %q", hole.Reason)
	}
}

// TestAReadingOfZeroIsNotAHole: an idle machine reports zero busy time every
// minute, and that is data. Confusing it with no data is the whole gap.
func TestAReadingOfZeroIsNotAHole(t *testing.T) {
	r := Range{Name: "3h", Window: 3 * time.Hour, Step: SamplingInterval}
	until := time.Date(2026, 9, 19, 12, 0, 0, 0, time.UTC)
	from := until.Add(-r.Window)
	idle := pointsAt(from, r.Step, 180, 0)
	if gaps := gapsIn(idle, r, from, until); len(gaps) != 0 {
		t.Fatalf("a window of zero readings was reported as %d holes: %+v", len(gaps), gaps)
	}
}

// TestAWindowWithoutAnyReadingIsOneHole, and a host that never reported is
// not a host reporting zero.
func TestAWindowWithoutAnyReadingIsOneHole(t *testing.T) {
	r := Range{Name: "3h", Window: 3 * time.Hour, Step: SamplingInterval}
	until := time.Date(2026, 9, 19, 12, 0, 0, 0, time.UTC)
	from := until.Add(-r.Window)
	gaps := gapsIn(nil, r, from, until)
	if len(gaps) != 1 || !gaps[0].From.Equal(from) || !gaps[0].To.Equal(until) {
		t.Fatalf("an empty window came back as %+v", gaps)
	}
}

// TestTheQuarterNowRunningIsNotAHole: a rolled-up window has no row for the
// quarter still being collected, and a chart that called that a hole would
// report one on every host of the fleet for ever.
func TestTheQuarterNowRunningIsNotAHole(t *testing.T) {
	r := Range{Name: "7d", Window: 7 * 24 * time.Hour, Step: 15 * time.Minute}
	until := time.Date(2026, 9, 19, 12, 7, 0, 0, time.UTC)
	from := until.Add(-r.Window)
	rolled := pointsAt(from, r.Step, 7*24*4-1, 10)
	if gaps := gapsIn(rolled, r, from, until); len(gaps) != 0 {
		t.Fatalf("a complete week of quarters came back with %d holes: %+v", len(gaps), gaps)
	}
}

// TestAHoleCarriesTheReasonOfTheRefusalThatCausedIt: this is what tells a
// host the panel refused from a host that was simply quiet.
func TestAHoleCarriesTheReasonOfTheRefusalThatCausedIt(t *testing.T) {
	until := time.Date(2026, 9, 19, 12, 0, 0, 0, time.UTC)
	gaps := []Gap{
		{From: until.Add(-10 * time.Hour), To: until.Add(-8 * time.Hour)},
		{From: until.Add(-4 * time.Hour), To: until.Add(-3 * time.Hour)},
	}
	explain(gaps, []Refusal{{
		Reason:        ErrorSampleTooOld,
		Samples:       120,
		FirstSampleAt: until.Add(-10 * time.Hour),
		LastSampleAt:  until.Add(-9 * time.Hour),
	}})
	if gaps[0].Reason != ErrorSampleTooOld || gaps[0].RefusedSamples != 120 {
		t.Fatalf("the hole the refusals fall into came back as %+v", gaps[0])
	}
	if gaps[1].Reason != "" || gaps[1].RefusedSamples != 0 {
		t.Fatalf("a hole nothing explains was given the reason %q", gaps[1].Reason)
	}
}
