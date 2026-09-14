package schedules

import (
	"testing"
	"time"
)

// The preview in the form shows the same dates the entry will run by, in
// the zone of the host: three of them, exact, with the zone name attached.
func TestPreviewComputesTheNextRunsInTheHostZone(t *testing.T) {
	zone := time.FixedZone("host", 2*60*60)
	now := time.Date(2026, 9, 14, 10, 30, 0, 0, zone)

	preview := PreviewExpression("0 3 * * *", now, "Europe/Warsaw")
	if preview.Error != "" {
		t.Fatalf("unexpected error: %s", preview.Error)
	}
	if preview.Timezone != "Europe/Warsaw" {
		t.Errorf("timezone = %q", preview.Timezone)
	}
	if len(preview.NextRuns) != PreviewRuns {
		t.Fatalf("next runs = %d: %v", len(preview.NextRuns), preview.NextRuns)
	}
	for i, date := range preview.NextRuns {
		expected := time.Date(2026, 9, 15+i, 3, 0, 0, 0, zone)
		if !date.Equal(expected) {
			t.Errorf("run %d = %s, want %s", i, date, expected)
		}
		if _, offset := date.Zone(); offset != 2*60*60 {
			t.Errorf("run %d lost the host zone: %s", i, date)
		}
	}
}

// An expression the host does not understand gets the reason, not an empty
// list that would look like "never".
func TestPreviewReportsABadExpression(t *testing.T) {
	preview := PreviewExpression("61 * * * *", time.Now(), "UTC")
	if preview.Error == "" {
		t.Fatal("a bad expression passed without a reason")
	}
	if preview.NextRuns == nil || len(preview.NextRuns) != 0 {
		t.Errorf("next runs = %v, want an empty list", preview.NextRuns)
	}
}

// An expression that never matches says so: February 30th has no date.
func TestPreviewReportsAnExpressionThatNeverMatches(t *testing.T) {
	preview := PreviewExpression("0 0 30 2 *", time.Now(), "UTC")
	if preview.Error == "" || len(preview.NextRuns) != 0 {
		t.Errorf("preview = %+v, want no runs and a reason", preview)
	}
}

// systemd-analyze prints one block per specification; the UTC line under
// every date is the unambiguous one and is the one read.
func TestCalendarPreviewReadsTheBlocksOfSystemdAnalyze(t *testing.T) {
	output := `  Original form: *-*-* 03:00:00
Normalized form: *-*-* 03:00:00
    Next elapse: Tue 2026-09-15 03:00:00 CEST
       (in UTC): Tue 2026-09-15 01:00:00 UTC
       From now: 10h left
       Iter. #2: Wed 2026-09-16 03:00:00 CEST
       (in UTC): Wed 2026-09-16 01:00:00 UTC
       From now: 1 day 10h left
       Iter. #3: Thu 2026-09-17 03:00:00 CEST
       (in UTC): Thu 2026-09-17 01:00:00 UTC
       From now: 2 days left

  Original form: Mon..Fri 06:00
Normalized form: Mon..Fri *-*-* 06:00:00
    Next elapse: Tue 2026-09-15 06:00:00 CEST
       (in UTC): Tue 2026-09-15 04:00:00 UTC
       From now: 13h left
`
	zone := time.FixedZone("CEST", 2*60*60)
	runs := ParseCalendarPreview(output, zone)

	daily := runs["*-*-* 03:00:00"]
	if len(daily) != 3 {
		t.Fatalf("daily runs = %v", daily)
	}
	for i, date := range daily {
		expected := time.Date(2026, 9, 15+i, 3, 0, 0, 0, zone)
		if !date.Equal(expected) {
			t.Errorf("daily run %d = %s, want %s", i, date, expected)
		}
		if _, offset := date.Zone(); offset != 2*60*60 {
			t.Errorf("daily run %d is not in the host zone: %s", i, date)
		}
	}
	weekdays := runs["Mon..Fri 06:00"]
	if len(weekdays) != 1 || !weekdays[0].Equal(time.Date(2026, 9, 15, 6, 0, 0, 0, zone)) {
		t.Errorf("weekday runs = %v", weekdays)
	}
}

// A host in UTC gets no "(in UTC)" lines: the local line is read then.
func TestCalendarPreviewReadsALocalLineWithoutTheUTCOne(t *testing.T) {
	output := `  Original form: daily
Normalized form: *-*-* 00:00:00
    Next elapse: Tue 2026-09-15 00:00:00 UTC
       From now: 13h left
`
	runs := ParseCalendarPreview(output, time.UTC)
	if len(runs["daily"]) != 1 || !runs["daily"][0].Equal(time.Date(2026, 9, 15, 0, 0, 0, 0, time.UTC)) {
		t.Errorf("runs = %v", runs["daily"])
	}
}

// A timer that will never elapse prints "never"; it gets no date rather
// than a made-up one.
func TestCalendarPreviewSkipsNever(t *testing.T) {
	output := `  Original form: *-02-30 00:00:00
Normalized form: *-02-30 00:00:00
    Next elapse: never
`
	if runs := ParseCalendarPreview(output, time.UTC); len(runs["*-02-30 00:00:00"]) != 0 {
		t.Errorf("runs = %v", runs)
	}
}

// A specification that is already in its normalized form has no "Original
// form" line, and systemd 257 numbers the runs "Iteration #n". A timer's
// expression is such a specification, and the runs must still find it.
func TestANormalizedSpecificationIsKeyedByItsOnlyForm(t *testing.T) {
	output := `Normalized form: Sun *-*-* 03:10:00
    Next elapse: Sun 2026-09-20 03:10:00 UTC
       From now: 5 days left
   Iteration #2: Sun 2026-09-27 03:10:00 UTC
       From now: 1 week 5 days left

  Original form: daily
Normalized form: *-*-* 00:00:00
    Next elapse: Tue 2026-09-15 00:00:00 UTC
       From now: 8h left
Failed to parse calendar specification 'bogus spec': Invalid argument
`
	runs := ParseCalendarPreview(output, time.UTC)
	if len(runs["Sun *-*-* 03:10:00"]) != 2 {
		t.Errorf("runs of the normalized spec = %v", runs["Sun *-*-* 03:10:00"])
	}
	if len(runs["daily"]) != 1 || len(runs["*-*-* 00:00:00"]) != 1 {
		t.Errorf("runs of daily = %v / %v", runs["daily"], runs["*-*-* 00:00:00"])
	}
	if len(runs) != 3 {
		t.Errorf("keys = %d, want the two forms of daily and the one of the timer", len(runs))
	}
}
