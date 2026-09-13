package schedules

import (
	"strings"
	"time"
)

// ReadTimers assembles schedules from the systemctl output.
//
// Timers and cron are two mechanisms of the same thing: the operator wants
// to see one table of recurring jobs, not two lists to merge in their head.
// The panel does not create timers - managed entries go to cron, because
// there one entry is one file, while a timer needs two units and their
// mutual consistency.
func ReadTimers(timerList, unitList, calendars string) []Schedule {
	next := parseTimerList(timerList)
	states := parseUnitStates(unitList)
	expressions := parseCalendars(calendars)

	var entries []Schedule
	for name, date := range next {
		entry := Schedule{
			ID:     name,
			Kind:   KindTimer,
			Source: SourceManual,
			// An active timer is one that is loaded and enabled.
			Enabled: states[name] != "" && states[name] != "inactive",
			// A timer without OnCalendar runs relative to an event
			// (OnBootSec, OnUnitActiveSec). Its expression is unknown, so it
			// is left empty instead of writing anything.
			Expression: expressions[name],
			// A timer does not run a command, only a unit. It is the unit
			// that has the ExecStart, which this module does not read.
			CommandLine: strings.TrimSuffix(name, ".timer") + ".service",
		}
		if !date.IsZero() {
			copied := date
			entry.NextRun = &copied
		}
		entries = append(entries, entry)
	}
	return entries
}

// parseTimerList reads the output of "systemctl list-timers --all".
//
// The columns are separated by spaces and the date contains spaces, so the
// timer name is found by suffix, not by position: the format of this list
// has changed between systemd versions.
func parseTimerList(output string) map[string]time.Time {
	result := map[string]time.Time{}
	for _, line := range strings.Split(output, "\n") {
		fields := strings.Fields(line)
		var name string
		var index int
		for i, field := range fields {
			if strings.HasSuffix(field, ".timer") {
				name, index = field, i
				break
			}
		}
		if name == "" {
			continue
		}
		result[name] = parseTimerDate(fields[:index])
	}
	return result
}

// parseTimerDate reads the first date at the start of the row. The value
// "-" means a timer without a scheduled date and stays an empty time, not a
// zero date pretending to be a specific moment.
func parseTimerDate(fields []string) time.Time {
	if len(fields) < 2 {
		return time.Time{}
	}
	// Format: "Sun 2026-08-23 03:10:00 UTC" - the date and the time are
	// taken.
	for i := 0; i+1 < len(fields); i++ {
		if len(fields[i]) == 10 && strings.Count(fields[i], "-") == 2 {
			date, err := time.Parse("2006-01-02 15:04:05", fields[i]+" "+fields[i+1])
			if err != nil {
				return time.Time{}
			}
			return date
		}
	}
	return time.Time{}
}

// parseUnitStates reads the output of "systemctl list-units --type=timer".
func parseUnitStates(output string) map[string]string {
	states := map[string]string{}
	for _, line := range strings.Split(output, "\n") {
		fields := strings.Fields(line)
		if len(fields) < 3 || !strings.HasSuffix(fields[0], ".timer") {
			continue
		}
		states[fields[0]] = fields[2]
	}
	return states
}

// parseCalendars reads the output of "systemctl show --property=Id
// --property=TimersCalendar '*.timer'".
//
// The OnCalendar expression is what the operator knows from the unit file.
// Without it the timer row would only say "sometime" - and the next run by
// itself does not explain what is behind it.
//
// Records are separated by an empty line, and the order of properties in a
// record is not the order of the question: systemd can print
// TimersCalendar before Id. Reading line by line would therefore attribute
// the calendar to the previous timer.
func parseCalendars(output string) map[string]string {
	result := map[string]string{}
	for _, record := range strings.Split(output, "\n\n") {
		name, expression := "", ""
		for _, line := range strings.Split(record, "\n") {
			line = strings.TrimSpace(line)
			switch {
			case strings.HasPrefix(line, "Id="):
				name = strings.TrimPrefix(line, "Id=")
			case strings.HasPrefix(line, "TimersCalendar="):
				expression = onCalendar(strings.TrimPrefix(line, "TimersCalendar="))
			}
		}
		// A timer without OnCalendar runs relative to an event (OnBootSec,
		// OnUnitActiveSec) and really has no calendar expression.
		if name != "" && expression != "" {
			result[name] = expression
		}
	}
	return result
}

// onCalendar extracts the expression from "{ OnCalendar=... ; next_elapse=... }".
func onCalendar(content string) string {
	start := strings.Index(content, "OnCalendar=")
	if start < 0 {
		return ""
	}
	content = content[start+len("OnCalendar="):]
	if end := strings.Index(content, " ; "); end >= 0 {
		content = content[:end]
	}
	return strings.TrimSpace(strings.TrimSuffix(strings.TrimSpace(content), "}"))
}
