package schedules

import (
	"testing"
	"time"
)

// An expression the panel does not understand must not be written: an entry
// that never runs is worse than none, because it looks like a working one.
func TestInvalidExpressionsAreRejected(t *testing.T) {
	bad := []string{
		"", "* * * *", "* * * * * *",
		"60 * * * *", "* 24 * * *", "* * 0 * *", "* * * 13 *", "* * * * 8",
		"a * * * *", "*/0 * * * *", "5-1 * * * *", "1-2-3 * * * *",
		"@reboot", "@unknown",
	}
	for _, expression := range bad {
		if _, err := ParseExpression(expression); err == nil {
			t.Errorf("accepted expression %q", expression)
		}
	}
}

// Formats cron understands must pass - otherwise the panel refuses work the
// host would do without a problem.
func TestValidExpressionsAreAccepted(t *testing.T) {
	good := []string{
		"* * * * *", "0 3 * * *", "*/15 * * * *", "0 0 1 1 *",
		"0 9-17 * * 1-5", "30 2,14 * * *", "0 0 * * 0", "0 0 * * 7",
		"@daily", "@hourly", "@weekly",
	}
	for _, expression := range good {
		if _, err := ParseExpression(expression); err != nil {
			t.Errorf("rejected expression %q: %v", expression, err)
		}
	}
}

// The schedule wizard shows the next runs, so they must be computed
// exactly, not approximately.
func TestNextRunsAreExact(t *testing.T) {
	expression, err := ParseExpression("0 3 * * *")
	if err != nil {
		t.Fatal(err)
	}
	after := time.Date(2026, 8, 23, 15, 30, 0, 0, time.UTC)
	dates := expression.NextRuns(after, 3)

	expected := []time.Time{
		time.Date(2026, 8, 24, 3, 0, 0, 0, time.UTC),
		time.Date(2026, 8, 25, 3, 0, 0, 0, time.UTC),
		time.Date(2026, 8, 26, 3, 0, 0, 0, time.UTC),
	}
	if len(dates) != 3 {
		t.Fatalf("dates = %d: %v", len(dates), dates)
	}
	for i, date := range dates {
		if !date.Equal(expected[i]) {
			t.Errorf("date %d = %s, want %s", i, date, expected[i])
		}
	}
}

// A step of 15 minutes must give four dates in an hour, not one.
func TestStepGivesAllDates(t *testing.T) {
	expression, err := ParseExpression("*/15 * * * *")
	if err != nil {
		t.Fatal(err)
	}
	after := time.Date(2026, 8, 23, 10, 0, 0, 0, time.UTC)
	dates := expression.NextRuns(after, 4)

	for i, expected := range []int{15, 30, 45, 0} {
		if dates[i].Minute() != expected {
			t.Errorf("date %d = %s, want minute %d", i, dates[i], expected)
		}
	}
}

// Cron treats both day fields differently from the rest: when both are
// restricted, the job runs when either matches. Treating them as a
// conjunction would skip most dates.
func TestDaysAreUnionedNotIntersected(t *testing.T) {
	// The first day of the month or a Monday.
	expression, err := ParseExpression("0 0 1 * 1")
	if err != nil {
		t.Fatal(err)
	}
	// 2026-08-23 is a Sunday; 24 August is a Monday, 1 September a Tuesday.
	after := time.Date(2026, 8, 23, 12, 0, 0, 0, time.UTC)
	dates := expression.NextRuns(after, 2)

	if dates[0].Day() != 24 {
		t.Errorf("first date = %s, want Monday 24 August", dates[0])
	}
	if dates[1].Day() != 31 {
		t.Errorf("second date = %s, want Monday 31 August", dates[1])
	}
}

// Sunday has two numbers in cron and both describe the same day.
func TestSundayHasTwoNumbers(t *testing.T) {
	zero, err := ParseExpression("0 0 * * 0")
	if err != nil {
		t.Fatal(err)
	}
	seven, err := ParseExpression("0 0 * * 7")
	if err != nil {
		t.Fatal(err)
	}
	after := time.Date(2026, 8, 23, 12, 0, 0, 0, time.UTC)
	if !zero.NextRuns(after, 1)[0].Equal(seven.NextRuns(after, 1)[0]) {
		t.Error("0 and 7 describe different days of the week")
	}
}

// An expression that never matches must not hang the search.
func TestExpressionWithoutDateDoesNotHang(t *testing.T) {
	// 30 February does not exist.
	expression, err := ParseExpression("0 0 30 2 *")
	if err != nil {
		t.Fatal(err)
	}
	if dates := expression.NextRuns(time.Now(), 1); len(dates) != 0 {
		t.Errorf("found a date for an impossible day: %v", dates)
	}
}
