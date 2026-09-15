package campaigns

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

// A schedule is a campaign order kept for a moment: the same body the
// door takes, placed by the panel when the moment comes. The campaign it
// places is an ordinary one - it goes through every check the order goes
// through at the door, under the rights of the person who wrote the
// schedule as they stand at that moment, and waits for its approval like
// any other. The schedule places orders; it runs nothing by itself.
//
// The recurrence is the RRULE subset a maintenance calendar needs: a
// monthly rule by day of the month or a weekly rule by weekdays, each at
// an hour and a minute of the schedule's zone. A rule the panel cannot
// read is refused at the door with its reason, never stored to fire at
// some other moment.

// Frequency is how often a rule repeats.
type Frequency string

const (
	FreqMonthly Frequency = "MONTHLY"
	FreqWeekly  Frequency = "WEEKLY"
)

// Recurrence is a parsed rule.
type Recurrence struct {
	Freq Frequency
	// ByMonthDay is the day of the month of a monthly rule, 1..31. A month
	// without that day is skipped, as RRULE skips it: a rule for the 31st
	// names nothing in April rather than the 1st of May.
	ByMonthDay int
	// ByDay lists the weekdays of a weekly rule, sorted, each once.
	ByDay []time.Weekday
	// ByHour and ByMinute name the wall-clock moment of every occurrence
	// in the schedule's zone.
	ByHour   int
	ByMinute int
}

// The weekday codes of RRULE, in the order Go numbers the weekdays.
var weekdayCodes = [...]string{"SU", "MO", "TU", "WE", "TH", "FR", "SA"}

// ParseRecurrence reads a rule. The keys are the RRULE keys, separated by
// semicolons, in any order; a key the subset does not have is refused
// rather than ignored, because a rule with an ignored key would fire at
// moments its author did not write.
func ParseRecurrence(text string) (*Recurrence, error) {
	text = strings.TrimSpace(text)
	if text == "" {
		return nil, errors.New("the recurrence is empty")
	}
	rule := &Recurrence{}
	seen := map[string]bool{}
	for _, part := range strings.Split(text, ";") {
		key, value, found := strings.Cut(strings.TrimSpace(part), "=")
		key = strings.ToUpper(strings.TrimSpace(key))
		value = strings.ToUpper(strings.TrimSpace(value))
		if !found || key == "" || value == "" {
			return nil, fmt.Errorf("the recurrence part %q is not KEY=VALUE", part)
		}
		if seen[key] {
			return nil, fmt.Errorf("the recurrence names %s twice", key)
		}
		seen[key] = true
		switch key {
		case "FREQ":
			switch Frequency(value) {
			case FreqMonthly, FreqWeekly:
				rule.Freq = Frequency(value)
			default:
				return nil, fmt.Errorf("FREQ=%s is not supported; the panel schedules MONTHLY and WEEKLY rules", value)
			}
		case "BYMONTHDAY":
			day, err := strconv.Atoi(value)
			if err != nil || day < 1 || day > 31 {
				return nil, errors.New("BYMONTHDAY must be a day of the month, 1 to 31")
			}
			rule.ByMonthDay = day
		case "BYDAY":
			for _, code := range strings.Split(value, ",") {
				weekday, ok := weekdayOf(strings.TrimSpace(code))
				if !ok {
					return nil, fmt.Errorf("BYDAY names %q; the weekdays are MO, TU, WE, TH, FR, SA and SU", code)
				}
				rule.ByDay = appendWeekday(rule.ByDay, weekday)
			}
		case "BYHOUR":
			hour, err := strconv.Atoi(value)
			if err != nil || hour < 0 || hour > 23 {
				return nil, errors.New("BYHOUR must be an hour, 0 to 23")
			}
			rule.ByHour = hour
		case "BYMINUTE":
			minute, err := strconv.Atoi(value)
			if err != nil || minute < 0 || minute > 59 {
				return nil, errors.New("BYMINUTE must be a minute, 0 to 59")
			}
			rule.ByMinute = minute
		default:
			return nil, fmt.Errorf("the recurrence key %s is not supported; the panel reads FREQ, BYMONTHDAY, BYDAY, BYHOUR and BYMINUTE", key)
		}
	}
	switch rule.Freq {
	case "":
		return nil, errors.New("the recurrence names no FREQ")
	case FreqMonthly:
		if rule.ByMonthDay == 0 {
			return nil, errors.New("a MONTHLY rule needs BYMONTHDAY")
		}
		if len(rule.ByDay) > 0 {
			return nil, errors.New("a MONTHLY rule takes BYMONTHDAY, not BYDAY")
		}
	case FreqWeekly:
		if len(rule.ByDay) == 0 {
			return nil, errors.New("a WEEKLY rule needs BYDAY")
		}
		if rule.ByMonthDay != 0 {
			return nil, errors.New("a WEEKLY rule takes BYDAY, not BYMONTHDAY")
		}
	}
	return rule, nil
}

func weekdayOf(code string) (time.Weekday, bool) {
	for index, known := range weekdayCodes {
		if known == code {
			return time.Weekday(index), true
		}
	}
	return 0, false
}

func appendWeekday(list []time.Weekday, weekday time.Weekday) []time.Weekday {
	for _, present := range list {
		if present == weekday {
			return list
		}
	}
	list = append(list, weekday)
	sort.Slice(list, func(i, j int) bool { return list[i] < list[j] })
	return list
}

// String writes the rule back in its canonical form, so what is stored
// is what the parser read and not what the author typed.
func (r Recurrence) String() string {
	parts := []string{"FREQ=" + string(r.Freq)}
	switch r.Freq {
	case FreqMonthly:
		parts = append(parts, "BYMONTHDAY="+strconv.Itoa(r.ByMonthDay))
	case FreqWeekly:
		codes := make([]string, 0, len(r.ByDay))
		for _, weekday := range r.ByDay {
			codes = append(codes, weekdayCodes[weekday])
		}
		parts = append(parts, "BYDAY="+strings.Join(codes, ","))
	}
	parts = append(parts, "BYHOUR="+strconv.Itoa(r.ByHour), "BYMINUTE="+strconv.Itoa(r.ByMinute))
	return strings.Join(parts, ";")
}

// Next returns the first occurrence of the rule at or after the moment,
// in the zone given. The answer is in UTC, as the row keeps it. A rule
// that names nothing within four years - none does, but the loop must
// end - gets the zero time.
func (r Recurrence) Next(from time.Time, loc *time.Location) time.Time {
	local := from.In(loc)
	switch r.Freq {
	case FreqMonthly:
		year, month := local.Year(), local.Month()
		for i := 0; i < 48; i++ {
			candidateYear, candidateMonth := year, month+time.Month(i)
			for candidateMonth > time.December {
				candidateMonth -= 12
				candidateYear++
			}
			if r.ByMonthDay > daysIn(candidateYear, candidateMonth) {
				continue
			}
			candidate := time.Date(candidateYear, candidateMonth, r.ByMonthDay, r.ByHour, r.ByMinute, 0, 0, loc)
			if !candidate.Before(from) {
				return candidate.UTC()
			}
		}
	case FreqWeekly:
		for i := 0; i < 8; i++ {
			day := local.AddDate(0, 0, i)
			if !r.onWeekday(day.Weekday()) {
				continue
			}
			candidate := time.Date(day.Year(), day.Month(), day.Day(), r.ByHour, r.ByMinute, 0, 0, loc)
			if !candidate.Before(from) {
				return candidate.UTC()
			}
		}
	}
	return time.Time{}
}

func (r Recurrence) onWeekday(weekday time.Weekday) bool {
	for _, present := range r.ByDay {
		if present == weekday {
			return true
		}
	}
	return false
}

// daysIn is the length of a month: the day before the first of the next.
func daysIn(year int, month time.Month) int {
	return time.Date(year, month+1, 0, 0, 0, 0, 0, time.UTC).Day()
}

// NextRun computes the moment a schedule fires next, from the moment
// given. Without a rule the moment is the start when it lies ahead, and
// nothing once it has passed. With a rule the start is the earliest
// moment the rule may name: the first occurrence at or after the later
// of the start and now. Nil means the schedule has nothing more to place.
func NextRun(startAt *time.Time, rule *Recurrence, loc *time.Location, now time.Time) *time.Time {
	if rule == nil {
		if startAt != nil && startAt.After(now) {
			at := startAt.UTC()
			return &at
		}
		return nil
	}
	from := now
	if startAt != nil && startAt.After(now) {
		from = *startAt
	}
	next := rule.Next(from, loc)
	if next.IsZero() {
		return nil
	}
	return &next
}

// Schedule is a stored order with its moments.
type Schedule struct {
	ID   string `json:"id"`
	Name string `json:"name"`
	// Order is the campaign order as POST /api/v1/campaigns takes it.
	Order json.RawMessage `json:"order"`
	// StartAt is the first moment; the only one without a recurrence.
	StartAt *time.Time `json:"start_at,omitempty"`
	// Recurrence is the rule in its canonical text; empty for one moment.
	Recurrence string `json:"recurrence,omitempty"`
	// Timezone is the IANA zone the rule's hours are read in.
	Timezone string `json:"timezone"`
	// NextRunAt is when the loop places the order next; nil once there is
	// nothing more to place.
	NextRunAt *time.Time `json:"next_run_at,omitempty"`
	LastRunAt *time.Time `json:"last_run_at,omitempty"`
	// LastCampaignID names the campaign the last run ordered; LastError
	// says why the last run ordered none, in the words the door answered.
	LastCampaignID string    `json:"last_campaign_id,omitempty"`
	LastError      string    `json:"last_error,omitempty"`
	CreatedBy      string    `json:"created_by"`
	Enabled        bool      `json:"enabled"`
	Reason         string    `json:"reason"`
	CreatedAt      time.Time `json:"created_at"`
	UpdatedAt      time.Time `json:"updated_at"`
}

// ScheduleSpec is what a schedule is written from.
type ScheduleSpec struct {
	Name       string          `json:"name"`
	Order      json.RawMessage `json:"order"`
	StartAt    *time.Time      `json:"start_at,omitempty"`
	Recurrence string          `json:"recurrence,omitempty"`
	Timezone   string          `json:"timezone,omitempty"`
	// Enabled left out means enabled: a schedule is written to fire.
	Enabled *bool  `json:"enabled,omitempty"`
	Reason  string `json:"reason"`
}

// ScheduleError is a refusal of a spec with its code, so the door answers
// with the code and the calendar page can name the field.
type ScheduleError struct {
	Code    string
	Message string
}

func (e ScheduleError) Error() string { return e.Message }

// ErrScheduleNotFound means there is no such schedule.
var ErrScheduleNotFound = errors.New("the schedule does not exist")

// MaxScheduleName bounds the name; a longer one is a description.
const MaxScheduleName = 200

// CheckedSchedule is a spec once read: the rule and the zone parsed, the
// name trimmed, the next moment computed.
type CheckedSchedule struct {
	Spec      ScheduleSpec
	Rule      *Recurrence
	Location  *time.Location
	NextRunAt *time.Time
}

// CheckSchedule validates a spec against the clock. Everything that can
// be wrong with the schedule itself is refused here, with its code; what
// can be wrong with the order inside is the door's business at every run,
// and the door's answer is kept on the row.
func CheckSchedule(spec ScheduleSpec, now time.Time) (*CheckedSchedule, error) {
	spec.Name = strings.TrimSpace(spec.Name)
	spec.Reason = strings.TrimSpace(spec.Reason)
	spec.Recurrence = strings.TrimSpace(spec.Recurrence)
	spec.Timezone = strings.TrimSpace(spec.Timezone)
	if spec.Name == "" {
		return nil, ScheduleError{Code: "name_required", Message: "a schedule needs a name"}
	}
	if len([]rune(spec.Name)) > MaxScheduleName {
		return nil, ScheduleError{Code: "name_too_long",
			Message: fmt.Sprintf("the name is longer than %d characters", MaxScheduleName)}
	}
	if len(spec.Order) == 0 || !json.Valid(spec.Order) {
		return nil, ScheduleError{Code: "invalid_order", Message: "the order is not valid JSON"}
	}
	var probe struct {
		Action string `json:"action"`
	}
	if err := json.Unmarshal(spec.Order, &probe); err != nil || strings.TrimSpace(probe.Action) == "" {
		return nil, ScheduleError{Code: "invalid_order", Message: "the order names no operation (field action)"}
	}
	if spec.Timezone == "" {
		spec.Timezone = "UTC"
	}
	loc, err := time.LoadLocation(spec.Timezone)
	if err != nil {
		return nil, ScheduleError{Code: "invalid_timezone", Message: "the timezone is not an IANA zone name: " + spec.Timezone}
	}
	var rule *Recurrence
	if spec.Recurrence != "" {
		rule, err = ParseRecurrence(spec.Recurrence)
		if err != nil {
			return nil, ScheduleError{Code: "invalid_recurrence", Message: err.Error()}
		}
		spec.Recurrence = rule.String()
	}
	if spec.StartAt == nil && rule == nil {
		return nil, ScheduleError{Code: "moment_required",
			Message: "a schedule needs a moment: start_at for one run, a recurrence for many"}
	}
	if spec.StartAt != nil {
		at := spec.StartAt.UTC()
		spec.StartAt = &at
		if rule == nil && !at.After(now) {
			return nil, ScheduleError{Code: "moment_in_past", Message: "start_at lies in the past; the order would never be placed"}
		}
	}
	return &CheckedSchedule{Spec: spec, Rule: rule, Location: loc, NextRunAt: NextRun(spec.StartAt, rule, loc, now)}, nil
}

// Location returns the schedule's zone. A zone the database holds is one
// the check accepted; a name the host no longer knows falls back to UTC
// rather than stopping the loop.
func (s Schedule) Location() *time.Location {
	loc, err := time.LoadLocation(s.Timezone)
	if err != nil {
		return time.UTC
	}
	return loc
}

// Rule returns the parsed recurrence, nil for a single moment.
func (s Schedule) Rule() *Recurrence {
	if s.Recurrence == "" {
		return nil
	}
	rule, err := ParseRecurrence(s.Recurrence)
	if err != nil {
		return nil
	}
	return rule
}

// Occurrences lists the moments the schedule fires in [from, to), at most
// limit of them, from the row's next moment on: what the calendar draws.
// A disabled schedule or one with nothing more to place has none.
func (s Schedule) Occurrences(from, to time.Time, limit int) []time.Time {
	if !s.Enabled || s.NextRunAt == nil || limit <= 0 {
		return nil
	}
	rule := s.Rule()
	var moments []time.Time
	at := *s.NextRunAt
	for len(moments) < limit && at.Before(to) {
		if !at.Before(from) {
			moments = append(moments, at)
		}
		if rule == nil {
			break
		}
		next := rule.Next(at.Add(time.Minute), s.Location())
		if next.IsZero() {
			break
		}
		at = next
	}
	return moments
}

const scheduleColumns = `
	select id, name, order_body, start_at, recurrence, timezone, next_run_at, last_run_at,
	       coalesce(last_campaign_id::text, ''), last_error, created_by, enabled, reason,
	       created_at, updated_at
	from campaign_schedules `

type scheduleQuerier interface {
	Query(ctx context.Context, sql string, args ...any) (pgx.Rows, error)
}

func (s *Store) querySchedules(ctx context.Context, q scheduleQuerier, clause string, args ...any) ([]Schedule, error) {
	rows, err := q.Query(ctx, scheduleColumns+clause, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	schedules := []Schedule{}
	for rows.Next() {
		var schedule Schedule
		var recurrence *string
		if err := rows.Scan(&schedule.ID, &schedule.Name, &schedule.Order, &schedule.StartAt, &recurrence,
			&schedule.Timezone, &schedule.NextRunAt, &schedule.LastRunAt, &schedule.LastCampaignID,
			&schedule.LastError, &schedule.CreatedBy, &schedule.Enabled, &schedule.Reason,
			&schedule.CreatedAt, &schedule.UpdatedAt); err != nil {
			return nil, err
		}
		if recurrence != nil {
			schedule.Recurrence = *recurrence
		}
		schedules = append(schedules, schedule)
	}
	return schedules, rows.Err()
}

// ListSchedules returns every schedule, the next to fire first and the
// ones with nothing to place last.
func (s *Store) ListSchedules(ctx context.Context) ([]Schedule, error) {
	return s.querySchedules(ctx, s.pool, "order by next_run_at asc nulls last, name")
}

// GetSchedule returns one schedule.
func (s *Store) GetSchedule(ctx context.Context, id string) (*Schedule, error) {
	if _, err := uuid.Parse(id); err != nil {
		return nil, ErrScheduleNotFound
	}
	schedules, err := s.querySchedules(ctx, s.pool, "where id = $1", id)
	if err != nil {
		return nil, err
	}
	if len(schedules) == 0 {
		return nil, ErrScheduleNotFound
	}
	return &schedules[0], nil
}

// CreateSchedule records a checked spec under the subject given: the
// orders are placed under that subject's rights, read anew at every run.
func (s *Store) CreateSchedule(ctx context.Context, checked CheckedSchedule, createdBy string) (*Schedule, error) {
	spec := checked.Spec
	id := uuid.NewString()
	enabled := spec.Enabled == nil || *spec.Enabled
	_, err := s.pool.Exec(ctx, `
		insert into campaign_schedules (id, name, order_body, start_at, recurrence, timezone, next_run_at,
		                                created_by, enabled, reason)
		values ($1, $2, $3, $4, nullif($5, ''), $6, $7, $8, $9, $10)`,
		id, spec.Name, spec.Order, spec.StartAt, spec.Recurrence, spec.Timezone,
		nextIfEnabled(checked.NextRunAt, enabled), createdBy, enabled, spec.Reason)
	if err != nil {
		return nil, fmt.Errorf("creating the schedule: %w", err)
	}
	return s.GetSchedule(ctx, id)
}

// UpdateSchedule rewrites a schedule from a checked spec under the
// subject given, who becomes its author: the orders are placed under the
// rights of whoever last wrote the order, so nobody widens a colleague's
// schedule onto hosts only the colleague may change. The next moment is
// computed afresh from the new spec.
func (s *Store) UpdateSchedule(ctx context.Context, id string, checked CheckedSchedule, author string) (*Schedule, error) {
	spec := checked.Spec
	enabled := spec.Enabled == nil || *spec.Enabled
	tag, err := s.pool.Exec(ctx, `
		update campaign_schedules
		   set name = $2, order_body = $3, start_at = $4, recurrence = nullif($5, ''), timezone = $6,
		       next_run_at = $7, enabled = $8, reason = $9, created_by = $10, updated_at = now()
		 where id = $1`,
		id, spec.Name, spec.Order, spec.StartAt, spec.Recurrence, spec.Timezone,
		nextIfEnabled(checked.NextRunAt, enabled), enabled, spec.Reason, author)
	if err != nil {
		return nil, fmt.Errorf("updating the schedule: %w", err)
	}
	if tag.RowsAffected() == 0 {
		return nil, ErrScheduleNotFound
	}
	return s.GetSchedule(ctx, id)
}

// nextIfEnabled keeps the next moment off a disabled row, so the due
// index never lists it and the calendar does not draw it.
func nextIfEnabled(next *time.Time, enabled bool) *time.Time {
	if !enabled {
		return nil
	}
	return next
}

// DeleteSchedule removes a schedule. The campaigns it placed stay.
func (s *Store) DeleteSchedule(ctx context.Context, id string) error {
	tag, err := s.pool.Exec(ctx, `delete from campaign_schedules where id = $1`, id)
	if err != nil {
		return err
	}
	if tag.RowsAffected() == 0 {
		return ErrScheduleNotFound
	}
	return nil
}

// DueSchedules lists the enabled schedules whose moment has come, the
// earliest first.
func (s *Store) DueSchedules(ctx context.Context, now time.Time) ([]Schedule, error) {
	return s.querySchedules(ctx, s.pool,
		"where enabled and next_run_at is not null and next_run_at <= $1 order by next_run_at", now)
}

// ClaimSchedule moves a due schedule past its moment: the row's next
// moment becomes the one given and the run is noted. The claim holds only
// when the row still names the moment the caller read, so two panels
// ticking at once place one order between them, not two.
func (s *Store) ClaimSchedule(ctx context.Context, id string, due time.Time, next *time.Time) (bool, error) {
	tag, err := s.pool.Exec(ctx, `
		update campaign_schedules
		   set next_run_at = $3, last_run_at = now(), updated_at = now()
		 where id = $1 and next_run_at = $2`, id, due, next)
	if err != nil {
		return false, err
	}
	return tag.RowsAffected() == 1, nil
}

// RecordScheduleRun writes what a run did: the campaign it placed, or
// the refusal it got. One of the two is empty.
func (s *Store) RecordScheduleRun(ctx context.Context, id, campaignID, refusal string) error {
	_, err := s.pool.Exec(ctx, `
		update campaign_schedules
		   set last_run_at = now(), last_campaign_id = nullif($2, '')::uuid, last_error = $3, updated_at = now()
		 where id = $1`, id, campaignID, refusal)
	return err
}

// CampaignWindow is a campaign's maintenance window, for the calendar.
type CampaignWindow struct {
	ID    string     `json:"id"`
	Name  string     `json:"name"`
	State State      `json:"state"`
	Start *time.Time `json:"start,omitempty"`
	End   *time.Time `json:"end,omitempty"`
}

// CampaignWindows lists the campaigns whose maintenance window touches
// [from, to), narrowed to the scopes the caller may read campaigns in -
// the same narrowing the campaign list applies.
func (s *Store) CampaignWindows(ctx context.Context, from, to time.Time, scopes []Scope) ([]CampaignWindow, error) {
	clause := `where (maintenance_start is not null or maintenance_end is not null)
		 and coalesce(maintenance_end, maintenance_start) >= $1
		 and coalesce(maintenance_start, maintenance_end) < $2`
	args := []any{from, to}
	if condition, extra := scopeCondition(scopes, len(args)); condition != "" {
		clause += condition
		args = append(args, extra...)
	}
	rows, err := s.pool.Query(ctx, `
		select id, name, state, maintenance_start, maintenance_end from campaigns `+clause+
		` order by coalesce(maintenance_start, maintenance_end)`, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	windows := []CampaignWindow{}
	for rows.Next() {
		var window CampaignWindow
		if err := rows.Scan(&window.ID, &window.Name, &window.State, &window.Start, &window.End); err != nil {
			return nil, err
		}
		windows = append(windows, window)
	}
	return windows, rows.Err()
}
