package relays

import (
	"testing"
	"time"
)

// The drop counter of a relay starts again with the process. Everything
// the history says about drops is therefore a difference within one
// process, and a difference taken across a restart is not a small error -
// it is a negative number where results were lost, or a silence where a
// whole process's losses were.
func TestTheHistoryReadsDropsWithinOneProcessOnly(t *testing.T) {
	base := time.Date(2026, 9, 18, 8, 0, 0, 0, time.UTC)
	at := func(minutes int) time.Time { return base.Add(time.Duration(minutes) * time.Minute) }

	points := markPoints([]BufferPoint{
		{At: at(0), InstanceID: "one", DroppedTotal: 0},
		{At: at(1), InstanceID: "one", DroppedTotal: 0},
		{At: at(2), InstanceID: "one", DroppedTotal: 5},
		// The relay restarted: a fresh process and a counter from zero.
		{At: at(3), InstanceID: "two", DroppedTotal: 0},
		{At: at(4), InstanceID: "two", DroppedTotal: 2},
	})

	if points[0].DroppedDelta != nil {
		t.Fatal("the first point of a window has nothing to be a difference against")
	}
	if points[1].DroppedDelta == nil || *points[1].DroppedDelta != 0 {
		t.Fatalf("a quiet minute should read as no drops: %v", points[1].DroppedDelta)
	}
	if points[2].DroppedDelta == nil || *points[2].DroppedDelta != 5 {
		t.Fatalf("delta at the drop = %v, expected 5", points[2].DroppedDelta)
	}
	if !points[3].Restarted {
		t.Fatal("a change of the process was not marked as a restart")
	}
	if points[3].DroppedDelta != nil {
		t.Fatalf("a difference was taken across a restart: %v", points[3].DroppedDelta)
	}
	if points[4].DroppedDelta == nil || *points[4].DroppedDelta != 2 {
		t.Fatalf("delta after the restart = %v, expected 2", points[4].DroppedDelta)
	}
}

// A relay too old to name its process still restarts, and the only trace
// it leaves is a counter that went backwards. That is read as a restart
// rather than as a negative number of drops.
func TestACounterGoingBackwardsIsReadAsARestart(t *testing.T) {
	points := markPoints([]BufferPoint{
		{DroppedTotal: 9},
		{DroppedTotal: 1},
	})
	if !points[1].Restarted || points[1].DroppedDelta != nil {
		t.Fatalf("a counter that fell was not read as a restart: %+v", points[1])
	}
}

// The fill of the buffer is a share of its limit, and a relay that
// reported no limit has no share. Unknown is not zero here either: a rule
// must not fire on it and must not resolve on it.
func TestAnUnknownLimitMakesTheFillUnknown(t *testing.T) {
	known := BufferPoint{BytesUsed: 800, BytesLimit: 1000}
	share, ok := known.UsedPercent()
	if !ok || share != 80 {
		t.Fatalf("used percent = %v, ok = %v", share, ok)
	}
	if _, ok := (BufferPoint{BytesUsed: 800}).UsedPercent(); ok {
		t.Fatal("a point without a limit answered with a share anyway")
	}

	reading := Reading{Latest: Sample{BytesUsed: 800}}
	if _, _, ok := reading.Value(MetricBufferUsedPercent); ok {
		t.Fatal("a rule was given a fill to compare although the limit is unknown")
	}
	reading.Latest.BytesLimit = 1000
	value, detail, ok := reading.Value(MetricBufferUsedPercent)
	if !ok || value != 80 {
		t.Fatalf("value = %v, ok = %v", value, ok)
	}
	if detail == "" {
		t.Fatal("the reading carries no detail for the alert to show")
	}
}

// The growth of the drop counter is an answer only when there is a
// difference to take. Without one the rule is not evaluated at all: a
// relay that has just started has not "dropped nothing", it has said
// nothing yet.
func TestTheGrowthOfTheDropCounterIsUnknownWithoutADifference(t *testing.T) {
	if _, _, ok := (Reading{}).Value(MetricBufferDroppedIncrease); ok {
		t.Fatal("a rule was given a growth although no difference could be taken")
	}
	growth := int64(3)
	value, _, ok := Reading{DroppedIncrease: &growth}.Value(MetricBufferDroppedIncrease)
	if !ok || value != 3 {
		t.Fatalf("value = %v, ok = %v", value, ok)
	}
	// A metric no rule of this store knows is never an answer.
	if _, _, ok := (Reading{}).Value("cpu_percent"); ok {
		t.Fatal("an unknown metric was answered")
	}
}

// The built-in rules are three steps on the fill and one on the drops. The
// comparison behind them is plain, but an operator it reads wrongly is an
// operator who stops trusting the page, and an unknown operator never
// holds.
func TestTheComparisonOfARuleHoldsOnlyWhenItShould(t *testing.T) {
	cases := []struct {
		operator string
		value    float64
		want     bool
	}{
		{"gt", 86, true}, {"gt", 85, false},
		{"gte", 85, true}, {"lt", 84, true}, {"lte", 85, true},
		{"lt", 86, false}, {"between", 99, false}, {"", 99, false},
	}
	for _, c := range cases {
		if got := CompareBuffer(c.operator, c.value, 85); got != c.want {
			t.Errorf("%s %v against 85 = %v, expected %v", c.operator, c.value, got, c.want)
		}
	}
}

// The limit of a relay that reports a spool is the spool's; a relay from
// before the spool reported only its memory buffer, and its history has to
// be readable on the same chart rather than as a relay with no limit at
// all.
func TestTheSampleTakesTheLimitTheRelayActuallyReported(t *testing.T) {
	reported := time.Date(2026, 9, 18, 8, 0, 0, 0, time.UTC)
	spooled := SampleOf("r1", Heartbeat{
		BufferBytes: 10, BufferMaxBytes: 100, SpoolBytesLimit: 4096,
		BufferedItems: 2, BufferDropped: 1, Sessions: 3, InstanceID: "one",
		UpstreamState: UpstreamBuffering, RelayVersion: "0.55.0", ReportedAt: reported,
	})
	if spooled.BytesLimit != 4096 {
		t.Fatalf("bytes_limit = %d, expected the spool's limit", spooled.BytesLimit)
	}
	if spooled.RelayID != "r1" || spooled.InstanceID != "one" ||
		spooled.UpstreamState != UpstreamBuffering || !spooled.ReportedAt.Equal(reported) {
		t.Fatalf("the sample lost part of the report: %+v", spooled)
	}

	old := SampleOf("r1", Heartbeat{BufferBytes: 10, BufferMaxBytes: 100})
	if old.BytesLimit != 100 {
		t.Fatalf("bytes_limit = %d, expected the memory buffer's maximum", old.BytesLimit)
	}
}

// The windows are the ones the retention can answer, and one of them is
// the default. A window nobody recognises is refused rather than silently
// turned into three hours: a chart of the wrong period is worse than an
// error message.
func TestTheWindowsOfTheChartAreTheOnesTheRetentionCanAnswer(t *testing.T) {
	window, err := ParseBufferRange("")
	if err != nil || window.Name != "24h" || window.Rollup() {
		t.Fatalf("the default window is %+v (%v)", window, err)
	}
	for _, name := range []string{"3h", "24h"} {
		window, err := ParseBufferRange(name)
		if err != nil || window.Rollup() {
			t.Fatalf("%s should read the raw reports: %+v (%v)", name, window, err)
		}
	}
	for _, name := range []string{"7d", "30d", "90d"} {
		window, err := ParseBufferRange(name)
		if err != nil || !window.Rollup() {
			t.Fatalf("%s should read the rollups: %+v (%v)", name, window, err)
		}
	}
	if _, err := ParseBufferRange("1y"); err == nil {
		t.Fatal("a window the retention cannot answer was accepted")
	}
}

// The defaults of the retention are the ones the documentation names, and
// an installation that sets nothing gets them rather than a sweep that
// deletes everything at once.
func TestTheRetentionFallsBackToTheDefaults(t *testing.T) {
	store := &Store{}
	retention := store.Retention()
	if retention.RawRetention != DefaultRawRetention ||
		retention.RollupRetention != DefaultRollupRetention {
		t.Fatalf("retention = %+v", retention)
	}
	store.SetRetention(Options{RawRetention: 24 * time.Hour})
	if got := store.Retention(); got.RawRetention != 24*time.Hour ||
		got.RollupRetention != DefaultRollupRetention {
		t.Fatalf("a half-set retention did not fall back for the rest: %+v", got)
	}
}
