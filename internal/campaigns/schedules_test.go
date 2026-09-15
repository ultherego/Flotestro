package campaigns

import (
	"encoding/json"
	"strings"
	"testing"
	"time"
)

func mustLocation(t *testing.T, name string) *time.Location {
	t.Helper()
	loc, err := time.LoadLocation(name)
	if err != nil {
		t.Skipf("the zone %s is not on this machine: %v", name, err)
	}
	return loc
}

// TestAMonthlyRuleNamesTheNextDayOfTheMonth guards the monthly rule: the
// next occurrence is the named day of the month at the named wall-clock
// time in the schedule's zone, this month when the moment is still ahead
// and the next month otherwise; a month without the day is skipped, as
// RRULE skips it, rather than rounded to the day after.
func TestAMonthlyRuleNamesTheNextDayOfTheMonth(t *testing.T) {
	warsaw := mustLocation(t, "Europe/Warsaw")
	rule, err := ParseRecurrence("FREQ=MONTHLY;BYMONTHDAY=15;BYHOUR=2;BYMINUTE=30")
	if err != nil {
		t.Fatalf("a well-formed monthly rule was refused: %v", err)
	}
	if rule.String() != "FREQ=MONTHLY;BYMONTHDAY=15;BYHOUR=2;BYMINUTE=30" {
		t.Errorf("the rule writes back as %s", rule.String())
	}

	// The 10th of September, Warsaw time: the 15th is still ahead.
	from := time.Date(2026, time.September, 10, 12, 0, 0, 0, warsaw)
	next := rule.Next(from, warsaw)
	want := time.Date(2026, time.September, 15, 2, 30, 0, 0, warsaw)
	if !next.Equal(want) {
		t.Errorf("from %s the next occurrence is %s, expected %s", from, next, want)
	}
	if next.Location() != time.UTC {
		t.Errorf("the occurrence is returned in %s, expected UTC as the row keeps it", next.Location())
	}

	// The 15th at 02:30 is at or after itself - the same minute counts.
	if again := rule.Next(want, warsaw); !again.Equal(want) {
		t.Errorf("the occurrence at its own moment is %s, expected %s", again, want)
	}
	// A minute later, the next month.
	later := rule.Next(want.Add(time.Minute), warsaw)
	if want := time.Date(2026, time.October, 15, 2, 30, 0, 0, warsaw); !later.Equal(want) {
		t.Errorf("a minute after the occurrence the next is %s, expected %s", later, want)
	}

	// The 31st names nothing in a month of thirty days.
	last, _ := ParseRecurrence("FREQ=MONTHLY;BYMONTHDAY=31;BYHOUR=0;BYMINUTE=0")
	from = time.Date(2026, time.April, 1, 0, 0, 0, 0, time.UTC)
	if next := last.Next(from, time.UTC); !next.Equal(time.Date(2026, time.May, 31, 0, 0, 0, 0, time.UTC)) {
		t.Errorf("from April the 31st comes next on %s, expected the 31st of May", next)
	}
	// Across the year's end.
	from = time.Date(2026, time.December, 31, 0, 1, 0, 0, time.UTC)
	if next := last.Next(from, time.UTC); !next.Equal(time.Date(2027, time.January, 31, 0, 0, 0, 0, time.UTC)) {
		t.Errorf("after the last day of the year the next is %s, expected the 31st of January", next)
	}
}

// TestAWeeklyRuleNamesTheNextListedWeekday guards the weekly rule: the
// weekdays are read in any order and each once, and the next occurrence
// is the nearest listed weekday at the named time, today included when
// the time is still ahead.
func TestAWeeklyRuleNamesTheNextListedWeekday(t *testing.T) {
	rule, err := ParseRecurrence("freq=weekly;byday=FR,MO,MO;byhour=22;byminute=0")
	if err != nil {
		t.Fatalf("a weekly rule in lower case was refused: %v", err)
	}
	if rule.String() != "FREQ=WEEKLY;BYDAY=MO,FR;BYHOUR=22;BYMINUTE=0" {
		t.Errorf("the rule writes back as %s", rule.String())
	}
	// Wednesday the 16th of September 2026.
	from := time.Date(2026, time.September, 16, 9, 0, 0, 0, time.UTC)
	if next := rule.Next(from, time.UTC); !next.Equal(time.Date(2026, time.September, 18, 22, 0, 0, 0, time.UTC)) {
		t.Errorf("from Wednesday the next is %s, expected Friday 22:00", next)
	}
	// Friday at 22:00 itself counts; a minute later Monday comes.
	friday := time.Date(2026, time.September, 18, 22, 0, 0, 0, time.UTC)
	if next := rule.Next(friday, time.UTC); !next.Equal(friday) {
		t.Errorf("Friday at its own moment gives %s", next)
	}
	if next := rule.Next(friday.Add(time.Minute), time.UTC); !next.Equal(time.Date(2026, time.September, 21, 22, 0, 0, 0, time.UTC)) {
		t.Errorf("a minute after Friday the next is %s, expected Monday 22:00", next)
	}
}

// TestARecurrenceOutsideTheSubsetIsRefused guards the parser: a key the
// panel does not read, a frequency it does not schedule, a day out of
// range or a rule without its day are refused with the reason, never
// stored to fire at a moment the author did not write.
func TestARecurrenceOutsideTheSubsetIsRefused(t *testing.T) {
	refused := map[string]string{
		"":                                       "empty",
		"FREQ=DAILY;BYHOUR=1":                    "not supported",
		"FREQ=MONTHLY;BYHOUR=1":                  "needs BYMONTHDAY",
		"FREQ=WEEKLY;BYHOUR=1":                   "needs BYDAY",
		"FREQ=MONTHLY;BYMONTHDAY=32":             "1 to 31",
		"FREQ=MONTHLY;BYMONTHDAY=1;BYHOUR=24":    "0 to 23",
		"FREQ=MONTHLY;BYMONTHDAY=1;BYMINUTE=60":  "0 to 59",
		"FREQ=WEEKLY;BYDAY=XX":                   "weekdays are",
		"FREQ=MONTHLY;BYMONTHDAY=1;BYDAY=MO":     "not BYDAY",
		"FREQ=MONTHLY;BYMONTHDAY=1;COUNT=3":      "not supported",
		"FREQ=MONTHLY;BYMONTHDAY=1;BYMONTHDAY=2": "twice",
		"BYMONTHDAY=1":                           "no FREQ",
	}
	for text, want := range refused {
		_, err := ParseRecurrence(text)
		if err == nil {
			t.Errorf("the rule %q was accepted", text)
			continue
		}
		if !strings.Contains(err.Error(), want) {
			t.Errorf("the rule %q was refused with %q, expected a mention of %q", text, err, want)
		}
	}
}

// TestNextRunReadsTheStartAsTheEarliestMoment guards how the first moment
// is computed: a single moment fires at its start and never again; a rule
// fires from the later of its start and now.
func TestNextRunReadsTheStartAsTheEarliestMoment(t *testing.T) {
	now := time.Date(2026, time.September, 15, 12, 0, 0, 0, time.UTC)
	ahead := now.Add(48 * time.Hour)
	behind := now.Add(-time.Hour)

	if next := NextRun(&ahead, nil, time.UTC, now); next == nil || !next.Equal(ahead) {
		t.Errorf("a single moment ahead gives %v, expected the moment itself", next)
	}
	if next := NextRun(&behind, nil, time.UTC, now); next != nil {
		t.Errorf("a single moment behind gives %v, expected nothing more to place", next)
	}
	if next := NextRun(nil, nil, time.UTC, now); next != nil {
		t.Errorf("no moment and no rule gives %v", next)
	}

	rule, _ := ParseRecurrence("FREQ=MONTHLY;BYMONTHDAY=1;BYHOUR=3;BYMINUTE=0")
	october := time.Date(2026, time.October, 1, 3, 0, 0, 0, time.UTC)
	if next := NextRun(nil, rule, time.UTC, now); next == nil || !next.Equal(october) {
		t.Errorf("a rule without a start gives %v, expected the 1st of October", next)
	}
	// A start ahead of now holds the rule back to it.
	start := time.Date(2026, time.November, 20, 0, 0, 0, 0, time.UTC)
	if next := NextRun(&start, rule, time.UTC, now); next == nil || !next.Equal(time.Date(2026, time.December, 1, 3, 0, 0, 0, time.UTC)) {
		t.Errorf("a rule with a start in November gives %v, expected the 1st of December", next)
	}
	// A start behind now is no bound at all.
	if next := NextRun(&behind, rule, time.UTC, now); next == nil || !next.Equal(october) {
		t.Errorf("a rule with a start behind now gives %v, expected the 1st of October", next)
	}
}

// TestCheckScheduleRefusesWhatCannotFire guards the spec check: a name,
// an order with an operation, a real zone, a readable rule and a moment
// that lies ahead are each required with their own code, and a spec that
// passes carries its next moment.
func TestCheckScheduleRefusesWhatCannotFire(t *testing.T) {
	now := time.Date(2026, time.September, 15, 12, 0, 0, 0, time.UTC)
	ahead := now.Add(time.Hour)
	behind := now.Add(-time.Hour)
	order := json.RawMessage(`{"action":"unit.restart","name":"x"}`)
	cases := []struct {
		spec ScheduleSpec
		code string
	}{
		{ScheduleSpec{Order: order, StartAt: &ahead}, "name_required"},
		{ScheduleSpec{Name: "patching", StartAt: &ahead}, "invalid_order"},
		{ScheduleSpec{Name: "patching", Order: json.RawMessage(`{"name":"x"}`), StartAt: &ahead}, "invalid_order"},
		{ScheduleSpec{Name: "patching", Order: order, StartAt: &ahead, Timezone: "Mars/Olympus"}, "invalid_timezone"},
		{ScheduleSpec{Name: "patching", Order: order, Recurrence: "FREQ=DAILY"}, "invalid_recurrence"},
		{ScheduleSpec{Name: "patching", Order: order}, "moment_required"},
		{ScheduleSpec{Name: "patching", Order: order, StartAt: &behind}, "moment_in_past"},
	}
	for _, tc := range cases {
		_, err := CheckSchedule(tc.spec, now)
		var refusal ScheduleError
		if err == nil || !errorAs(err, &refusal) {
			t.Errorf("the spec %+v passed or failed untyped: %v", tc.spec, err)
			continue
		}
		if refusal.Code != tc.code {
			t.Errorf("the spec %+v was refused with %s, expected %s", tc.spec, refusal.Code, tc.code)
		}
	}

	checked, err := CheckSchedule(ScheduleSpec{
		Name: " monthly patching ", Order: order, Recurrence: "freq=monthly;bymonthday=3;byhour=1;byminute=15",
		Timezone: "UTC",
	}, now)
	if err != nil {
		t.Fatalf("a well-formed spec was refused: %v", err)
	}
	if checked.Spec.Name != "monthly patching" || checked.Spec.Recurrence != "FREQ=MONTHLY;BYMONTHDAY=3;BYHOUR=1;BYMINUTE=15" {
		t.Errorf("the spec was stored as %q with rule %q", checked.Spec.Name, checked.Spec.Recurrence)
	}
	if checked.NextRunAt == nil || !checked.NextRunAt.Equal(time.Date(2026, time.October, 3, 1, 15, 0, 0, time.UTC)) {
		t.Errorf("the next moment is %v, expected the 3rd of October", checked.NextRunAt)
	}
}

// TestOccurrencesListTheMomentsOfARange guards what the calendar draws:
// every moment of a rule inside the range from the row's next moment on,
// a single moment once, and nothing for a disabled schedule.
func TestOccurrencesListTheMomentsOfARange(t *testing.T) {
	next := time.Date(2026, time.September, 21, 22, 0, 0, 0, time.UTC)
	weekly := Schedule{Enabled: true, Recurrence: "FREQ=WEEKLY;BYDAY=MO;BYHOUR=22;BYMINUTE=0", Timezone: "UTC", NextRunAt: &next}
	from := time.Date(2026, time.September, 1, 0, 0, 0, 0, time.UTC)
	to := time.Date(2026, time.October, 1, 0, 0, 0, 0, time.UTC)
	moments := weekly.Occurrences(from, to, 10)
	if len(moments) != 2 || !moments[0].Equal(next) || !moments[1].Equal(next.AddDate(0, 0, 7)) {
		t.Errorf("the weekly schedule draws %v in September, expected the 21st and the 28th", moments)
	}
	once := Schedule{Enabled: true, Timezone: "UTC", NextRunAt: &next}
	if moments := once.Occurrences(from, to, 10); len(moments) != 1 || !moments[0].Equal(next) {
		t.Errorf("the single moment draws %v", moments)
	}
	disabled := weekly
	disabled.Enabled = false
	if moments := disabled.Occurrences(from, to, 10); len(moments) != 0 {
		t.Errorf("a disabled schedule draws %v", moments)
	}
	// The bound holds however long the range.
	if moments := weekly.Occurrences(from, to.AddDate(10, 0, 0), 3); len(moments) != 3 {
		t.Errorf("the bound of three gives %d moments", len(moments))
	}
}

func errorAs(err error, target *ScheduleError) bool {
	refusal, ok := err.(ScheduleError)
	if ok {
		*target = refusal
	}
	return ok
}
