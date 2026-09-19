package schedules

import (
	"strings"
	"time"
)

// PreviewRuns is how many coming runs the host reports for an entry and for a
// preview.
const PreviewRuns = 3

// Preview is the answer of schedule. preview: the next runs of an expression
// computed on the host, in the host's time zone.
type Preview struct {
	Expression string `json:"expression"`
	// Timezone is the name of the host zone, so "03:00" means a specific
	// hour. Empty when the host does not say.
	Timezone string      `json:"timezone,omitempty"`
	NextRuns []time.Time `json:"next_runs"`
	// Error says why there are no runs: an expression the host does not
	// understand, or one that never matches a date.
	Error string `json:"error,omitempty"`
	// Kind names the mechanism the preview was asked for. Empty means the
	// runs alone were asked for, as before timers could be written.
	Kind string `json:"kind,omitempty"`
	// Calendar is the OnCalendar expression a timer would run by, and Units are
	// the files that would be written.
	Calendar string     `json:"calendar,omitempty"`
	Units    []UnitFile `json:"units,omitempty"`
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

// The layouts systemd prints dates in with LC_ALL=C.
const (
	systemdLocalLayout = "Mon 2006-01-02 15:04:05 MST"
	systemdUTCLayout   = "Mon 2006-01-02 15:04:05 UTC"
)

// ParseCalendarPreview reads the output of "systemd-analyze calendar
// --iterations N spec.
func ParseCalendarPreview(output string, zone *time.Location) map[string][]time.Time {
	if zone == nil {
		zone = time.Local
	}
	result := map[string][]time.Time{}
	lines := strings.Split(output, "\n")
	// A block is keyed by both forms of its specification.
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
			// An empty form names nothing: a block without a specification
			// is not filed under "".
			keys = nil
			if original := strings.TrimSpace(strings.TrimPrefix(line, "Original form:")); original != "" {
				keys = []string{original}
			}
		case strings.HasPrefix(line, "Normalized form:"):
			normalized := strings.TrimSpace(strings.TrimPrefix(line, "Normalized form:"))
			if normalized != "" && (len(keys) == 0 || keys[0] != normalized) {
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
			// "never" and a date the layout does not read leave the list as it is: a
			// missing run is more honest than a guessed one.
			if err == nil && !date.IsZero() {
				file(date.In(zone))
			}
		}
	}
	return result
}
