package schedules

import (
	"strings"
	"time"
)

// PreviewRuns is how many coming runs the host reports for an entry and
// for a preview. Three show the rhythm; a single date does not say whether
// "03:00 tomorrow" is daily or once a month.
const PreviewRuns = 3

// Preview is the answer of schedule.preview: the next runs of an
// expression computed on the host, in the host's time zone.
//
// The panel could compute the dates itself, but it knows neither the
// host's zone nor its clock. A preview from the host shows the same
// numbers the entry will run by.
type Preview struct {
	Expression string `json:"expression"`
	// Timezone is the name of the host zone, so "03:00" means a specific
	// hour. Empty when the host does not say.
	Timezone string      `json:"timezone,omitempty"`
	NextRuns []time.Time `json:"next_runs"`
	// Error says why there are no runs: an expression the host does not
	// understand, or one that never matches a date.
	Error string `json:"error,omitempty"`
}

// PreviewExpression computes the coming runs of a cron expression after the
// given moment, in the zone of that moment.
func PreviewExpression(expression string, now time.Time, timezone string) Preview {
	preview := Preview{Expression: strings.TrimSpace(expression), Timezone: timezone, NextRuns: []time.Time{}}
	parsed, err := ParseExpression(expression)
	if err != nil {
		preview.Error = err.Error()
		return preview
	}
	preview.NextRuns = parsed.NextRuns(now, PreviewRuns)
	if len(preview.NextRuns) == 0 {
		preview.Error = "the expression never matches a date"
	}
	return preview
}

// The layouts systemd prints dates in with LC_ALL=C. The first is the local
// form ("Tue 2026-09-15 03:00:00 CEST"), read in the host's own zone; the
// second is the UTC form systemd adds under it when the host zone is not
// UTC.
const (
	systemdLocalLayout = "Mon 2006-01-02 15:04:05 MST"
	systemdUTCLayout   = "Mon 2006-01-02 15:04:05 UTC"
)

// ParseCalendarPreview reads the output of "systemd-analyze calendar
// --iterations N spec...".
//
// The output is one block per specification: the original form (only when
// it differs from the normalized one), the normalized form, then "Next
// elapse:" and "Iteration #n:" lines ("Iter. #n:" on older systemd), each
// followed by an "(in UTC):" line when the host zone is not UTC. The dates
// are keyed by both forms, so the text the timer was asked with finds them.
// The UTC line is preferred when it exists: the local one carries a zone
// abbreviation, and an abbreviation is unambiguous only inside the zone it
// belongs to. Every date comes back in the given zone.
func ParseCalendarPreview(output string, zone *time.Location) map[string][]time.Time {
	if zone == nil {
		zone = time.Local
	}
	result := map[string][]time.Time{}
	lines := strings.Split(output, "\n")
	// A block is keyed by both forms of its specification. The tool prints
	// the original form only when it differs from the normalized one - a
	// timer's expression as systemd reports it is already normalized and
	// has no "Original form" line at all - so a date is filed under every
	// name the block gives it.
	var keys []string
	file := func(date time.Time) {
		for _, key := range keys {
			result[key] = append(result[key], date)
		}
	}
	for i := 0; i < len(lines); i++ {
		line := strings.TrimSpace(lines[i])
		switch {
		case line == "":
			keys = nil
		case strings.HasPrefix(line, "Original form:"):
			keys = []string{strings.TrimSpace(strings.TrimPrefix(line, "Original form:"))}
		case strings.HasPrefix(line, "Normalized form:"):
			normalized := strings.TrimSpace(strings.TrimPrefix(line, "Normalized form:"))
			if len(keys) == 0 || keys[0] != normalized {
				keys = append(keys, normalized)
			}
		case len(keys) > 0 && (strings.HasPrefix(line, "Next elapse:") ||
			strings.HasPrefix(line, "Iter. #") || strings.HasPrefix(line, "Iteration #")):
			_, value, _ := strings.Cut(line, ":")
			value = strings.TrimSpace(value)
			var date time.Time
			var err error
			if i+1 < len(lines) && strings.HasPrefix(strings.TrimSpace(lines[i+1]), "(in UTC):") {
				_, utc, _ := strings.Cut(strings.TrimSpace(lines[i+1]), ":")
				date, err = time.ParseInLocation(systemdUTCLayout, strings.TrimSpace(utc), time.UTC)
				i++
			} else {
				date, err = time.ParseInLocation(systemdLocalLayout, value, zone)
			}
			// "never" and a date the layout does not read leave the list as
			// it is: a missing run is more honest than a guessed one.
			if err == nil {
				file(date.In(zone))
			}
		}
	}
	return result
}
