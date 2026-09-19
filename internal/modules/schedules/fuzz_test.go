package schedules

import (
	"testing"
	"time"
)

// FuzzParseExpression feeds the cron parser what an operator may type into the
// panel.
func FuzzParseExpression(f *testing.F) {
	for _, seed := range []string{
		"* * * * *", "0 3 * * *", "*/15 * * * *", "0 0 1 1 *", "0 9-17 * * 1-5",
		"30 2,14 * * *", "0 0 * * 0", "0 0 * * 7", "@daily", "@hourly", "@weekly",
		"0 0 1 * 1", "0 0 30 2 *",
		"", "* * * *", "* * * * * *", "60 * * * *", "* 24 * * *", "* * 0 * *",
		"* * * 13 *", "* * * * 8", "a * * * *", "*/0 * * * *", "5-1 * * * *",
		"1-2-3 * * * *", "@reboot", "@unknown",
		// A step close to the largest integer wrapped the loop over the
		// field around zero and let junk values into the set.
		"59/9223372036854775806 * * * *",
		"*/9223372036854775807 * * * *",
		"-5 * * * *", ",,, * * * *", "1,,2 * * * *", "+5 * * * *",
	} {
		f.Add(seed)
	}

	after := time.Date(2026, 9, 15, 12, 0, 0, 0, time.UTC)
	f.Fuzz(func(t *testing.T, text string) {
		expression, err := ParseExpression(text)
		if err != nil {
			return
		}
		for i := range expression.allowed {
			for value := range expression.allowed[i] {
				if value < ranges[i].min || value > ranges[i].max {
					t.Fatalf("%q: field %d allows %d, outside %d-%d", text, i+1, value, ranges[i].min, ranges[i].max)
				}
			}
		}
		for _, run := range expression.NextRuns(after, 3) {
			if !run.After(after) {
				t.Fatalf("%q: the run %s is not after %s", text, run, after)
			}
			if !expression.matches(run) {
				t.Fatalf("%q: the planner returned %s, which the expression does not match", text, run)
			}
		}
	})
}

// FuzzParseCalendarPreview feeds the reader of "systemd-analyze calendar"
// arbitrary output.
func FuzzParseCalendarPreview(f *testing.F) {
	for _, seed := range []string{
		`  Original form: *-*-* 03:00:00
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
`,
		`  Original form: daily
Normalized form: *-*-* 00:00:00
    Next elapse: Tue 2026-09-15 00:00:00 UTC
       From now: 13h left
`,
		`  Original form: *-02-30 00:00:00
Normalized form: *-02-30 00:00:00
    Next elapse: never
`,
		`Normalized form: Sun *-*-* 03:10:00
    Next elapse: Sun 2026-09-20 03:10:00 UTC
       From now: 5 days left
   Iteration #2: Sun 2026-09-27 03:10:00 UTC
       From now: 1 week 5 days left

  Original form: daily
Normalized form: *-*-* 00:00:00
    Next elapse: Tue 2026-09-15 00:00:00 UTC
       From now: 8h left
Failed to parse calendar specification 'bogus spec': Invalid argument
`,
		"Next elapse: Tue 2026-09-15 00:00:00 UTC\n",
		"Normalized form:\nNext elapse:\n(in UTC):\n",
		"Original form: x\n(in UTC): Tue 2026-09-15 01:00:00 UTC\n",
		"",
	} {
		f.Add(seed)
	}

	zone := time.FixedZone("test", 2*3600)
	f.Fuzz(func(t *testing.T, output string) {
		for spec, dates := range ParseCalendarPreview(output, zone) {
			for _, date := range dates {
				if date.IsZero() {
					t.Fatalf("%q: a zero date for %q", output, spec)
				}
				if date.Location() != zone {
					t.Fatalf("%q: %s for %q is not in the zone asked for", output, date, spec)
				}
			}
		}
		// A nil zone means the zone of the host and must not be a special case.
		ParseCalendarPreview(output, nil)
	})
}
