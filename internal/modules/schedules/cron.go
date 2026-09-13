package schedules

import (
	"fmt"
	"strconv"
	"strings"
	"time"
)

// A cron expression has five fields: minute, hour, day of month, month, day
// of week.
const cronFields = 5

// ranges describe the allowed values of the consecutive fields.
var ranges = [cronFields]struct{ min, max int }{
	{0, 59}, {0, 23}, {1, 31}, {1, 12}, {0, 7},
}

// Expression is a parsed cron expression.
type Expression struct {
	// allowed[i] holds the values permitted in field i.
	allowed [cronFields]map[int]bool
	// dayOfMonthStar and dayOfWeekStar are needed because cron treats these
	// two fields differently from the rest: when both are restricted, the
	// job runs when either matches, not both at once.
	dayOfMonthStar bool
	dayOfWeekStar  bool
}

// Shortcuts cron accepts instead of the five fields.
var shortcuts = map[string]string{
	"@yearly":   "0 0 1 1 *",
	"@annually": "0 0 1 1 *",
	"@monthly":  "0 0 1 * *",
	"@weekly":   "0 0 * * 0",
	"@daily":    "0 0 * * *",
	"@midnight": "0 0 * * *",
	"@hourly":   "0 * * * *",
}

// ParseExpression reads a cron expression.
//
// The parser is our own, because the expression has to be checked before
// the write on the host and the next runs computed from it for the
// operator. An expression the panel does not understand is not written: an
// entry that never runs is worse than none, because it looks like a working
// one.
func ParseExpression(expression string) (Expression, error) {
	expression = strings.TrimSpace(expression)
	if expanded, ok := shortcuts[strings.ToLower(expression)]; ok {
		expression = expanded
	}
	if strings.HasPrefix(expression, "@") {
		// @reboot has no next run in the calendar, so the panel could
		// neither show nor plan it.
		return Expression{}, fmt.Errorf("unsupported expression %q", expression)
	}

	fields := strings.Fields(expression)
	if len(fields) != cronFields {
		return Expression{}, fmt.Errorf("a cron expression must have %d fields, has %d", cronFields, len(fields))
	}

	var result Expression
	result.dayOfMonthStar = fields[2] == "*"
	result.dayOfWeekStar = fields[4] == "*"
	for i, field := range fields {
		allowed, err := parseField(field, ranges[i].min, ranges[i].max)
		if err != nil {
			return Expression{}, fmt.Errorf("field %d (%q): %w", i+1, field, err)
		}
		result.allowed[i] = allowed
	}
	// Sunday has two numbers in cron. Without this "0" and "7" would
	// describe different days, although they mean the same one.
	if result.allowed[4][7] {
		result.allowed[4][0] = true
	}
	return result, nil
}

// parseField reads one field: an asterisk, a number, a range, a list or a
// step.
func parseField(field string, min, max int) (map[int]bool, error) {
	allowed := map[int]bool{}
	for _, part := range strings.Split(field, ",") {
		step := 1
		if index := strings.Index(part, "/"); index >= 0 {
			value, err := strconv.Atoi(part[index+1:])
			if err != nil || value <= 0 {
				return nil, fmt.Errorf("invalid step %q", part[index+1:])
			}
			step = value
			part = part[:index]
		}

		from, to := min, max
		switch {
		case part == "*" || part == "":
		case strings.Contains(part, "-"):
			bounds := strings.SplitN(part, "-", 2)
			start, err1 := strconv.Atoi(bounds[0])
			end, err2 := strconv.Atoi(bounds[1])
			if err1 != nil || err2 != nil {
				return nil, fmt.Errorf("invalid range %q", part)
			}
			from, to = start, end
		default:
			value, err := strconv.Atoi(part)
			if err != nil {
				return nil, fmt.Errorf("invalid value %q", part)
			}
			from, to = value, value
		}
		if from < min || to > max || from > to {
			return nil, fmt.Errorf("value outside the range %d-%d", min, max)
		}
		for value := from; value <= to; value += step {
			allowed[value] = true
		}
	}
	if len(allowed) == 0 {
		return nil, fmt.Errorf("the field allows no value")
	}
	return allowed, nil
}

// maxSearch bounds the search for the next run. An expression like
// "0 0 30 2 *" never matches - instead of searching forever, it is said
// directly that there is no date.
const maxSearch = 4 * 365 * 24 * time.Hour

// NextRuns returns the consecutive dates after the given moment.
//
// The dates are computed on the host and in its time zone: the panel knows
// neither, and "03:00" without a zone means nothing specific.
func (e Expression) NextRuns(after time.Time, count int) []time.Time {
	if count <= 0 {
		count = 1
	}
	var results []time.Time
	moment := after.Truncate(time.Minute)
	end := after.Add(maxSearch)

	for len(results) < count && moment.Before(end) {
		moment = moment.Add(time.Minute)
		if e.matches(moment) {
			results = append(results, moment)
		}
	}
	return results
}

// matches checks whether the moment satisfies the expression.
func (e Expression) matches(moment time.Time) bool {
	if !e.allowed[0][moment.Minute()] || !e.allowed[1][moment.Hour()] {
		return false
	}
	if !e.allowed[3][int(moment.Month())] {
		return false
	}

	dayOfMonth := e.allowed[2][moment.Day()]
	dayOfWeek := e.allowed[4][int(moment.Weekday())]

	// Cron treats both day fields differently from the rest: when both are
	// restricted, the job runs when either matches. Treating them as a
	// conjunction would skip most dates.
	switch {
	case e.dayOfMonthStar && e.dayOfWeekStar:
		return true
	case e.dayOfMonthStar:
		return dayOfWeek
	case e.dayOfWeekStar:
		return dayOfMonth
	default:
		return dayOfMonth || dayOfWeek
	}
}
