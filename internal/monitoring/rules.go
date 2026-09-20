package monitoring

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"github.com/ultherego/flotestro/internal/authz"
	"github.com/ultherego/flotestro/internal/opspec"
	"github.com/ultherego/flotestro/internal/selector"
)

// ErrNotFound says the rule, alert or silence does not exist.
var ErrNotFound = errors.New("not found")

// The metrics a rule may watch.
const (
	MetricCPUPercent            = "cpu_percent"
	MetricLoad1PerCore          = "load1_per_core"
	MetricMemoryUsedPercent     = "memory_used_percent"
	MetricSwapUsedPercent       = "swap_used_percent"
	MetricFilesystemUsedPercent = "filesystem_used_percent"
	MetricInodesUsedPercent     = "inodes_used_percent"
	MetricHostOffline           = "host_offline"
	MetricUptimeSeconds         = "uptime_seconds"
	MetricAgentRSSBytes         = "agent_rss_bytes"
	MetricAgentCPUPercent       = "agent_cpu_percent"
)

// MetricInfo describes one metric of the catalogue: its unit, as the
// panel formats a threshold and a value, and what it measures.
type MetricInfo struct {
	Name string `json:"name"`
	// Unit is percent, bytes, seconds, minutes, count or ratio.
	Unit        string `json:"unit"`
	Description string `json:"description"`
}

// Catalogue lists the metrics a rule may watch with their units, in the order
// the panel shows them.
var Catalogue = []MetricInfo{
	{MetricCPUPercent, "percent", "busy time of the host across all cores"},
	{MetricLoad1PerCore, "ratio", "load average over one minute divided by the core count"},
	{MetricMemoryUsedPercent, "percent", "memory used of the total"},
	{MetricSwapUsedPercent, "percent", "swap used of the total; unknown on a host without swap"},
	{MetricFilesystemUsedPercent, "percent", "the fullest real filesystem"},
	{MetricInodesUsedPercent, "percent", "the fullest inode table of a real filesystem"},
	{MetricHostOffline, "minutes", "minutes since the last sample"},
	{MetricUptimeSeconds, "seconds", "time since the host booted"},
	{MetricAgentRSSBytes, "bytes", "resident memory of the agent process"},
	{MetricAgentCPUPercent, "percent", "busy time of the agent process as a share of one core"},
}

// Metrics lists the names of the catalogue, in the same order.
var Metrics = func() []string {
	names := make([]string, 0, len(Catalogue))
	for _, metric := range Catalogue {
		names = append(names, metric.Name)
	}
	return names
}()

// Operators lists the comparisons a rule may make.
var Operators = []string{"gt", "lt", "gte", "lte"}

// Severities lists the severities from the most urgent.
var Severities = []string{"critical", "warning", "info"}

// Selector names the hosts a rule covers, in the shape of a campaign selector.
type Selector struct {
	Site        string `json:"site,omitempty"`
	Environment string `json:"environment,omitempty"`
	OSFamily    string `json:"os_family,omitempty"`
	// Tags keeps the hosts carrying every one of the tags, 'key' or
	// 'key=value' as recorded on the host.
	Tags []string `json:"tags,omitempty"`
	// Groups keeps the hosts of any of the saved groups, named by identifier or
	// by name.
	Groups []string `json:"groups,omitempty"`
	Owner  string   `json:"owner,omitempty"`
	// Expression is the text form of a campaign selector, for a scope the flat
	// fields cannot say: "agent_version < 0.
	Expression string   `json:"expression,omitempty"`
	HostIDs    []string `json:"host_ids,omitempty"`
}

// Narrows says whether the selector leaves any host out.
func (sel Selector) Narrows() bool {
	return sel.Site != "" || sel.Environment != "" || sel.OSFamily != "" || len(sel.Tags) > 0 ||
		len(sel.Groups) > 0 || sel.Owner != "" || sel.Expression != "" || len(sel.HostIDs) > 0
}

// Tree renders the selector as the campaign selector package reads it, the
// host list aside: every set field is one condition, and all of them must hold.
func (sel Selector) Tree() (*selector.Expression, error) {
	var all []selector.Expression
	if sel.Site != "" {
		all = append(all, selector.Expression{Site: sel.Site})
	}
	if sel.Environment != "" {
		all = append(all, selector.Expression{Environment: sel.Environment})
	}
	if sel.OSFamily != "" {
		all = append(all, selector.Expression{OSFamily: sel.OSFamily})
	}
	for _, tag := range sel.Tags {
		all = append(all, selector.Expression{Tag: tag})
	}
	if len(sel.Groups) == 1 {
		all = append(all, selector.Expression{Group: sel.Groups[0]})
	} else if len(sel.Groups) > 1 {
		var groups []selector.Expression
		for _, group := range sel.Groups {
			groups = append(groups, selector.Expression{Group: group})
		}
		all = append(all, selector.Expression{Any: groups})
	}
	if sel.Owner != "" {
		all = append(all, selector.Expression{Owner: sel.Owner})
	}
	if sel.Expression != "" {
		parsed, err := selector.Parse(sel.Expression)
		if err != nil {
			return nil, fmt.Errorf("expression: %w", err)
		}
		all = append(all, *parsed)
	}
	switch len(all) {
	case 0:
		return nil, nil
	case 1:
		return &all[0], nil
	default:
		return &selector.Expression{All: all}, nil
	}
}

// validate checks the selector as the operator wrote it: the shape of every
// field, and the whole as one selector the campaign page would also accept.
func (sel Selector) validate() error {
	for _, tag := range sel.Tags {
		if !selector.TagPattern.MatchString(tag) {
			return fmt.Errorf("tags: %q is not a tag (key or key=value, lower-case key)", tag)
		}
	}
	for _, group := range sel.Groups {
		if _, err := uuid.Parse(group); err != nil && !selector.NamePattern.MatchString(group) {
			return fmt.Errorf("groups: %q is not a group name or identifier", group)
		}
	}
	if strings.TrimSpace(sel.Owner) != sel.Owner {
		return errors.New("owner: the name has surrounding whitespace")
	}
	for _, id := range sel.HostIDs {
		if _, err := uuid.Parse(id); err != nil {
			return fmt.Errorf("host_ids: %q is not a host identifier", id)
		}
	}
	expression, err := sel.Tree()
	if err != nil {
		return err
	}
	if expression != nil {
		if err := expression.Validate(); err != nil {
			return err
		}
	}
	return nil
}

// The no-data policies of a rule: what the evaluator makes of the readings
// stopping.
const (
	// NoDataAlert raises an episode on the gap and tells the notification
	// queue; for such a rule the silence is itself the news.
	NoDataAlert = "alert"
	// NoDataUnknown marks an open episode no_data, so the panel stops standing
	// on a value nobody can see any more, and tells nobody.
	NoDataUnknown = "unknown"
	// NoDataIgnore says nothing about a gap beyond restarting the window,
	// which is what every rule did before the setting existed.
	NoDataIgnore = "ignore"
)

// NoDataPolicies lists the policies in the order the panel offers them.
var NoDataPolicies = []string{NoDataAlert, NoDataUnknown, NoDataIgnore}

// The bounds of the cadence a rule declares.
const (
	// MaxCadence bounds both settings: a gap wider than a day says nothing
	// about a day of silence.
	MaxCadence = 24 * time.Hour
	// DefaultMaxGapFactor is how many cadences wide the gap of a rule that does
	// not say is: one lost reading is a lost reading, two in a row are a gap.
	DefaultMaxGapFactor = 2
)

// The refusals of the cadence settings. A code, not a sentence: the panel and
// the integrations branch on it.
const (
	// RefusalRuleCadenceTooFast: a rule that expects readings more often than
	// the agents take them stands in a gap between every two of them.
	RefusalRuleCadenceTooFast = "rule_cadence_too_fast"
	// RefusalRuleCadenceTooSlow: a cadence or a gap beyond a day.
	RefusalRuleCadenceTooSlow = "rule_cadence_too_slow"
	// RefusalRuleGapBelowCadence: a gap narrower than the cadence opens a hole
	// after every reading that arrives on time.
	RefusalRuleGapBelowCadence = "rule_gap_below_cadence"
	// RefusalRuleNoDataPolicyUnknown: a policy that is none of the three.
	RefusalRuleNoDataPolicyUnknown = "rule_no_data_policy_unknown"
)

// Rule is one alert rule.
type Rule struct {
	ID         string    `json:"id"`
	Name       string    `json:"name"`
	Metric     string    `json:"metric"`
	Operator   string    `json:"operator"`
	Threshold  float64   `json:"threshold"`
	ForMinutes int       `json:"for_minutes"`
	Severity   string    `json:"severity"`
	Selector   Selector  `json:"selector"`
	Enabled    bool      `json:"enabled"`
	CreatedBy  string    `json:"created_by"`
	CreatedAt  time.Time `json:"created_at"`
	UpdatedAt  time.Time `json:"updated_at"`
	// ExpectedCadenceSeconds is how often the rule expects a reading of its
	// metric; zero is the interval the agents sample at.
	ExpectedCadenceSeconds int `json:"expected_cadence_seconds"`
	// MaxGapSeconds is the widest hole in the readings that still counts as one
	// continuous run of them; zero is twice the cadence.
	MaxGapSeconds int `json:"max_gap_seconds"`
	// NoDataPolicy says what the evaluator does when the readings stop: alert,
	// unknown or ignore. Empty is ignore, the way rules behaved before the field.
	NoDataPolicy string `json:"no_data_policy"`
}

// Cadence is how often the rule expects a reading of its metric.
func (r Rule) Cadence() time.Duration {
	if r.ExpectedCadenceSeconds == 0 {
		return SamplingInterval
	}
	return time.Duration(r.ExpectedCadenceSeconds) * time.Second
}

// MaxGap is the widest hole in the readings that still counts as one
// continuous run of them.
func (r Rule) MaxGap() time.Duration {
	if r.MaxGapSeconds == 0 {
		return DefaultMaxGapFactor * r.Cadence()
	}
	return time.Duration(r.MaxGapSeconds) * time.Second
}

// Policy is the rule's no-data policy; a rule that does not say ignores gaps.
func (r Rule) Policy() string {
	if r.NoDataPolicy == "" {
		return NoDataIgnore
	}
	return r.NoDataPolicy
}

// settled fills in the settings the caller left out, so the row says what the
// evaluator will do instead of leaving it to a default read elsewhere.
func (r Rule) settled() Rule {
	r.ExpectedCadenceSeconds = int(r.Cadence() / time.Second)
	r.MaxGapSeconds = int(r.MaxGap() / time.Second)
	r.NoDataPolicy = r.Policy()
	return r
}

// validateCadence checks the three settings against each other and against the
// interval the agents sample at.
func (r Rule) validateCadence() error {
	cadence, gap := r.Cadence(), r.MaxGap()
	if cadence < SamplingInterval {
		return &opspec.RefusalError{Code: RefusalRuleCadenceTooFast, Err: fmt.Errorf(
			"the agents sample every %s; a rule cannot expect a reading every %s",
			SamplingInterval, cadence)}
	}
	if cadence > MaxCadence {
		return &opspec.RefusalError{Code: RefusalRuleCadenceTooSlow, Err: fmt.Errorf(
			"the expected cadence %s is longer than %s", cadence, MaxCadence)}
	}
	if gap < cadence {
		return &opspec.RefusalError{Code: RefusalRuleGapBelowCadence, Err: fmt.Errorf(
			"a gap of %s is narrower than the expected cadence %s, so a reading that "+
				"arrives on time opens one", gap, cadence)}
	}
	if gap > MaxCadence {
		return &opspec.RefusalError{Code: RefusalRuleCadenceTooSlow, Err: fmt.Errorf(
			"the widest gap %s is longer than %s", gap, MaxCadence)}
	}
	if !contains(NoDataPolicies, r.Policy()) {
		return &opspec.RefusalError{Code: RefusalRuleNoDataPolicyUnknown, Err: fmt.Errorf(
			"unknown no-data policy %q; use %s", r.NoDataPolicy,
			strings.Join(NoDataPolicies, ", "))}
	}
	return nil
}

// Validate checks the rule as the operator wrote it.
func (r Rule) Validate() error {
	if strings.TrimSpace(r.Name) == "" {
		return errors.New("the rule needs a name")
	}
	if !contains(Metrics, r.Metric) {
		return fmt.Errorf("unknown metric %q; use one of %s", r.Metric, strings.Join(Metrics, ", "))
	}
	if !contains(Operators, r.Operator) {
		return fmt.Errorf("unknown operator %q; use gt, lt, gte or lte", r.Operator)
	}
	if !contains(Severities, r.Severity) {
		return fmt.Errorf("unknown severity %q; use critical, warning or info", r.Severity)
	}
	if math.IsNaN(r.Threshold) || math.IsInf(r.Threshold, 0) {
		return errors.New("the threshold has to be a number")
	}
	if r.ForMinutes < 0 || r.ForMinutes > 24*60 {
		return errors.New("for_minutes has to be between 0 and 1440")
	}
	if err := r.validateCadence(); err != nil {
		return err
	}
	return r.Selector.validate()
}

func contains(list []string, value string) bool {
	for _, item := range list {
		if item == value {
			return true
		}
	}
	return false
}

// ruleColumns is the projection both rule queries share.
const ruleColumns = `
	id, name, metric, operator, threshold, for_minutes, severity, selector,
	enabled, created_by, created_at, updated_at,
	expected_cadence_seconds, max_gap_seconds, no_data_policy`

// ListRules returns every rule, the enabled ones first, by name.
func (s *Store) ListRules(ctx context.Context) ([]Rule, error) {
	rows, err := s.pool.Query(ctx, `
		select `+ruleColumns+`
		from alert_rules
		order by enabled desc, name, id`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	rules := []Rule{}
	for rows.Next() {
		rule, err := scanRule(rows)
		if err != nil {
			return nil, err
		}
		rules = append(rules, rule)
	}
	return rules, rows.Err()
}

// GetRule returns one rule.
func (s *Store) GetRule(ctx context.Context, id string) (*Rule, error) {
	if _, err := uuid.Parse(id); err != nil {
		return nil, ErrNotFound
	}
	rows, err := s.pool.Query(ctx, `
		select `+ruleColumns+`
		from alert_rules where id = $1`, id)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	if !rows.Next() {
		if err := rows.Err(); err != nil {
			return nil, err
		}
		return nil, ErrNotFound
	}
	rule, err := scanRule(rows)
	if err != nil {
		return nil, err
	}
	return &rule, nil
}

func scanRule(rows pgx.Rows) (Rule, error) {
	var rule Rule
	var selector []byte
	if err := rows.Scan(&rule.ID, &rule.Name, &rule.Metric, &rule.Operator, &rule.Threshold,
		&rule.ForMinutes, &rule.Severity, &selector, &rule.Enabled, &rule.CreatedBy,
		&rule.CreatedAt, &rule.UpdatedAt, &rule.ExpectedCadenceSeconds, &rule.MaxGapSeconds,
		&rule.NoDataPolicy); err != nil {
		return Rule{}, err
	}
	if len(selector) > 0 {
		if err := json.Unmarshal(selector, &rule.Selector); err != nil {
			return Rule{}, err
		}
	}
	return rule, nil
}

// groupDirectory resolves the group references of a selector against the saved
// groups.
func (s *Store) groupDirectory() selector.Groups {
	return selector.NewStore(s.pool)
}

// resolveSelector checks that the selector of a rule resolves: a group it
// names exists and the expansion stays within bounds.
func (s *Store) resolveSelector(ctx context.Context, sel Selector) error {
	expression, err := sel.Tree()
	if err != nil || expression == nil {
		return err
	}
	_, err = selector.Expand(ctx, expression, s.groupDirectory())
	return err
}

// CreateRule records a rule and returns it with its identifier.
func (s *Store) CreateRule(ctx context.Context, rule Rule) (*Rule, error) {
	if err := rule.Validate(); err != nil {
		return nil, err
	}
	if err := s.resolveSelector(ctx, rule.Selector); err != nil {
		return nil, err
	}
	encoded, err := json.Marshal(rule.Selector)
	if err != nil {
		return nil, err
	}
	id := uuid.NewString()
	settled := rule.settled()
	if _, err := s.pool.Exec(ctx, `
		insert into alert_rules (id, name, metric, operator, threshold, for_minutes,
		    severity, selector, enabled, created_by,
		    expected_cadence_seconds, max_gap_seconds, no_data_policy)
		values ($1, $2, $3, $4, $5, $6, $7, $8::jsonb, $9, $10, $11, $12, $13)`,
		id, strings.TrimSpace(rule.Name), rule.Metric, rule.Operator, rule.Threshold,
		rule.ForMinutes, rule.Severity, encoded, rule.Enabled, rule.CreatedBy,
		settled.ExpectedCadenceSeconds, settled.MaxGapSeconds,
		settled.NoDataPolicy); err != nil {
		return nil, err
	}
	return s.GetRule(ctx, id)
}

// UpdateRule replaces the settings of a rule.
func (s *Store) UpdateRule(ctx context.Context, id string, rule Rule) (*Rule, error) {
	if err := rule.Validate(); err != nil {
		return nil, err
	}
	current, err := s.GetRule(ctx, id)
	if err != nil {
		return nil, err
	}
	if err := s.resolveSelector(ctx, rule.Selector); err != nil {
		return nil, err
	}
	encoded, err := json.Marshal(rule.Selector)
	if err != nil {
		return nil, err
	}
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return nil, err
	}
	defer func() { _ = tx.Rollback(ctx) }()

	settled := rule.settled()
	if _, err := tx.Exec(ctx, `
		update alert_rules
		set name = $2, metric = $3, operator = $4, threshold = $5, for_minutes = $6,
		    severity = $7, selector = $8::jsonb, enabled = $9, updated_at = now(),
		    expected_cadence_seconds = $10, max_gap_seconds = $11, no_data_policy = $12
		where id = $1`,
		id, strings.TrimSpace(rule.Name), rule.Metric, rule.Operator, rule.Threshold,
		rule.ForMinutes, rule.Severity, encoded, rule.Enabled,
		settled.ExpectedCadenceSeconds, settled.MaxGapSeconds,
		settled.NoDataPolicy); err != nil {
		return nil, err
	}
	conditionChanged := current.Metric != rule.Metric || current.Operator != rule.Operator ||
		current.Threshold != rule.Threshold
	if conditionChanged || !rule.Enabled {
		if err := closeOpenAlerts(ctx, tx, id); err != nil {
			return nil, err
		}
	}
	if err := tx.Commit(ctx); err != nil {
		return nil, err
	}
	return s.GetRule(ctx, id)
}

// DeleteRule removes a rule. Its firing alerts resolve first, so the trail
// says they ended; the alerts stay as history without a rule.
func (s *Store) DeleteRule(ctx context.Context, id string) error {
	if _, err := uuid.Parse(id); err != nil {
		return ErrNotFound
	}
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback(ctx) }()
	if err := closeOpenAlerts(ctx, tx, id); err != nil {
		return err
	}
	tag, err := tx.Exec(ctx, `delete from alert_rules where id = $1`, id)
	if err != nil {
		return err
	}
	if tag.RowsAffected() == 0 {
		return ErrNotFound
	}
	return tx.Commit(ctx)
}

// closeOpenAlerts ends the episodes of a rule: one that never fired vanishes,
// one that did resolves, and a no-data episode is closed on the same terms.
func closeOpenAlerts(ctx context.Context, tx pgx.Tx, ruleID string) error {
	if _, err := tx.Exec(ctx, `
		delete from alerts
		where rule_id = $1 and fired_at is null and state in ('pending', 'no_data')`,
		ruleID); err != nil {
		return err
	}
	_, err := tx.Exec(ctx, `
		update alerts set state = 'resolved', resolved_at = now()
		where rule_id = $1 and state in ('firing', 'no_data')`, ruleID)
	return err
}

// Alert is one episode of a rule on a host as the API shows it.
type Alert struct {
	ID       string `json:"id"`
	RuleID   string `json:"rule_id"`
	RuleName string `json:"rule_name"`
	Metric   string `json:"metric"`
	Severity string `json:"severity"`
	// State is pending, firing, no_data or resolved. A no_data episode is one
	// whose readings stopped under a rule that asked to be told.
	State      string     `json:"state"`
	Value      float64    `json:"value"`
	Detail     string     `json:"detail"`
	StartedAt  time.Time  `json:"started_at"`
	FiredAt    *time.Time `json:"fired_at"`
	ResolvedAt *time.Time `json:"resolved_at"`
	// Silenced says an active silence covers this alert. The alert keeps
	// firing; the on-call view keeps it out of the way.
	Silenced bool   `json:"silenced"`
	HostID   string `json:"host_id"`
	Hostname string `json:"hostname"`
	// AcknowledgedBy and AcknowledgedAt say somebody took the alert: it keeps
	// firing, and the counts of what waits for a person leave it out.
	AcknowledgedBy string     `json:"acknowledged_by,omitempty"`
	AcknowledgedAt *time.Time `json:"acknowledged_at,omitempty"`
	Note           string     `json:"note,omitempty"`
}

// Acknowledged says somebody took the alert.
func (a Alert) Acknowledged() bool { return a.AcknowledgedAt != nil }

// AlertFilter narrows the alert history.
type AlertFilter struct {
	State    string
	Severity string
	HostID   string
	// Scopes narrow to the hosts the caller may read; nil narrows nothing.
	Scopes []authz.Scope
	// Acknowledged narrows to the alerts somebody took, or to the ones
	// nobody did; nil narrows nothing.
	Acknowledged *bool
	Limit        int
	// After is the last alert of the page before; nil reads from the newest.
	After *AlertKey
}

// AlertKey keys an alert in the order the history is read: when the episode
// started, and the identifier that settles a tie.
type AlertKey struct {
	StartedAt time.Time
	ID        string
}

// KeyOf keys an alert, for the cursor that carries a reader to the next page.
func KeyOf(alert Alert) AlertKey {
	return AlertKey{StartedAt: alert.StartedAt, ID: alert.ID}
}

// AlertPageMax is the most alerts one answer carries; beyond it a caller
// pages on with the cursor.
const AlertPageMax = 500

// silencedPredicate is true of an alert an active silence covers. A global
// silence is written for the security alerts of the installation; it is not a
// silence of every alert of every host.
const silencedPredicate = `exists (select 1 from silences s
	        where s.expired_at is null and s.until > now()
	          and not s.global
	          and (s.host_id is null or s.host_id = a.host_id)
	          and (s.rule_id is null or s.rule_id = a.rule_id))`

// alertColumns is the projection every alert query shares; a is the
// alerts alias and h the host.
const alertColumns = `
	a.id, coalesce(a.rule_id::text, ''), a.rule_name, a.metric, a.severity, a.state,
	a.value, a.detail, a.started_at, a.fired_at, a.resolved_at,
	` + silencedPredicate + `,
	a.host_id, h.hostname, coalesce(a.acknowledged_by, ''), a.acknowledged_at, a.note`

// alertConditions renders a filter as a where clause with its arguments. The
// last result is false for a filter no row can match. Paged adds the keyset of
// the cursor, which a count over the whole history leaves out.
func alertConditions(filter AlertFilter, paged bool) (string, []any, bool) {
	var conditions []string
	var args []any
	add := func(column, value string) {
		if value == "" {
			return
		}
		args = append(args, value)
		conditions = append(conditions, fmt.Sprintf("%s = $%d", column, len(args)))
	}
	add("a.state", filter.State)
	add("a.severity", filter.Severity)
	if filter.HostID != "" {
		if _, err := uuid.Parse(filter.HostID); err != nil {
			return "", nil, false
		}
		add("a.host_id", filter.HostID)
	}
	if filter.Scopes != nil {
		if condition, extra := authz.ScopeSQL(filter.Scopes, "h.site", "h.environment", len(args)); condition != "" {
			conditions = append(conditions, condition)
			args = append(args, extra...)
		}
	}
	if filter.Acknowledged != nil {
		if *filter.Acknowledged {
			conditions = append(conditions, "a.acknowledged_at is not null")
		} else {
			conditions = append(conditions, "a.acknowledged_at is null")
		}
	}
	// The keyset follows the order of the list: older than the last row, or
	// as old and further along the identifier.
	if paged && filter.After != nil {
		args = append(args, filter.After.StartedAt, filter.After.ID)
		conditions = append(conditions, fmt.Sprintf("(a.started_at < $%d or (a.started_at = $%d and a.id > $%d))",
			len(args)-1, len(args)-1, len(args)))
	}
	if len(conditions) == 0 {
		return "", args, true
	}
	return "where " + strings.Join(conditions, " and "), args, true
}

// ListAlerts reads one page of the alert history, newest first.
func (s *Store) ListAlerts(ctx context.Context, filter AlertFilter) ([]Alert, error) {
	where, args, ok := alertConditions(filter, true)
	if !ok {
		return []Alert{}, nil
	}
	limit := filter.Limit
	if limit <= 0 || limit > AlertPageMax {
		limit = 100
	}
	args = append(args, limit)
	return s.queryAlerts(ctx, `
		select `+alertColumns+`
		from alerts a join hosts h on h.id = a.host_id
		`+where+`
		order by a.started_at desc, a.id
		limit $`+fmt.Sprint(len(args)), args...)
}

// CountAlerts counts the whole history the filter keeps, whatever one page
// carries: a list that stops short is to say how much it left behind.
func (s *Store) CountAlerts(ctx context.Context, filter AlertFilter) (int, error) {
	where, args, ok := alertConditions(filter, false)
	if !ok {
		return 0, nil
	}
	var count int
	err := s.pool.QueryRow(ctx, `
		select count(*) from alerts a join hosts h on h.id = a.host_id
		`+where, args...).Scan(&count)
	return count, err
}

// FiringBoardLimit bounds the board one answer carries. The counts beside it
// are taken over every firing alert, so a bounded board is not a low count.
const FiringBoardLimit = 500

// Firing reads what is somebody's business now: the firing alerts and the
// no-data episodes, on the hosts the caller's scopes make visible. The most
// pressing come first, and at most limit of them.
func (s *Store) Firing(ctx context.Context, scopes []authz.Scope, limit int) ([]Alert, error) {
	condition, args := authz.ScopeSQL(scopes, "h.site", "h.environment", 0)
	if condition == "" {
		condition = "true"
	}
	if limit <= 0 || limit > FiringBoardLimit {
		limit = FiringBoardLimit
	}
	args = append(args, limit)
	return s.queryAlerts(ctx, `
		select `+alertColumns+`
		from alerts a join hosts h on h.id = a.host_id
		where a.state in ('firing', 'no_data') and `+condition+`
		order by a.acknowledged_at is not null,
		         case a.severity when 'critical' then 0 when 'warning' then 1 else 2 end,
		         coalesce(a.fired_at, a.started_at), a.id
		limit $`+fmt.Sprint(len(args)), args...)
}

// FiringGroup counts the alerts of the board that share everything the
// counts are taken by; what a group means stays with the caller.
type FiringGroup struct {
	State        string
	Severity     string
	Acknowledged bool
	Silenced     bool
	Count        int
}

// FiringCounts groups every firing alert of the visible hosts, board or no
// board: the board a request carries is bounded, these counts are not.
func (s *Store) FiringCounts(ctx context.Context, scopes []authz.Scope) ([]FiringGroup, error) {
	condition, args := authz.ScopeSQL(scopes, "h.site", "h.environment", 0)
	if condition == "" {
		condition = "true"
	}
	rows, err := s.pool.Query(ctx, `
		select a.state, a.severity, a.acknowledged_at is not null, `+silencedPredicate+`, count(*)
		from alerts a join hosts h on h.id = a.host_id
		where a.state in ('firing', 'no_data') and `+condition+`
		group by 1, 2, 3, 4`, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	groups := []FiringGroup{}
	for rows.Next() {
		var group FiringGroup
		if err := rows.Scan(&group.State, &group.Severity, &group.Acknowledged,
			&group.Silenced, &group.Count); err != nil {
			return nil, err
		}
		groups = append(groups, group)
	}
	return groups, rows.Err()
}

// ErrNotFiring says the alert is not open on the board, so it cannot be taken:
// a pending one is not yet an alert, a resolved one is history.
var ErrNotFiring = errors.New("the alert is not firing")

// Acknowledge marks an alert on the on-call board as taken by somebody, with
// what they wrote. A no-data episode is on that board, so it can be taken too.
func (s *Store) Acknowledge(ctx context.Context, id, by, note string) (*Alert, error) {
	if _, err := uuid.Parse(id); err != nil {
		return nil, ErrNotFound
	}
	tag, err := s.pool.Exec(ctx, `
		update alerts set acknowledged_by = $2, acknowledged_at = now(), note = $3
		where id = $1 and state in ('firing', 'no_data')`, id, by, strings.TrimSpace(note))
	if err != nil {
		return nil, err
	}
	if tag.RowsAffected() == 0 {
		alert, err := s.Alert(ctx, id)
		if err != nil {
			return nil, err
		}
		if alert.State != "firing" && alert.State != "no_data" {
			return nil, ErrNotFiring
		}
		return nil, ErrNotFound
	}
	return s.Alert(ctx, id)
}

// Annotate writes a note on an alert of any state: the cause found after
// it resolved is worth keeping with it.
func (s *Store) Annotate(ctx context.Context, id, note string) (*Alert, error) {
	if _, err := uuid.Parse(id); err != nil {
		return nil, ErrNotFound
	}
	tag, err := s.pool.Exec(ctx, `update alerts set note = $2 where id = $1`, id, strings.TrimSpace(note))
	if err != nil {
		return nil, err
	}
	if tag.RowsAffected() == 0 {
		return nil, ErrNotFound
	}
	return s.Alert(ctx, id)
}

// Alert reads one alert.
func (s *Store) Alert(ctx context.Context, id string) (*Alert, error) {
	if _, err := uuid.Parse(id); err != nil {
		return nil, ErrNotFound
	}
	alerts, err := s.queryAlerts(ctx, `
		select `+alertColumns+`
		from alerts a join hosts h on h.id = a.host_id
		where a.id = $1`, id)
	if err != nil {
		return nil, err
	}
	if len(alerts) == 0 {
		return nil, ErrNotFound
	}
	return &alerts[0], nil
}

// Pending counts the pending alerts of the visible hosts.
func (s *Store) Pending(ctx context.Context, scopes []authz.Scope) (int, error) {
	condition, args := authz.ScopeSQL(scopes, "h.site", "h.environment", 0)
	if condition == "" {
		condition = "true"
	}
	var count int
	err := s.pool.QueryRow(ctx, `
		select count(*) from alerts a join hosts h on h.id = a.host_id
		where a.state = 'pending' and `+condition, args...).Scan(&count)
	return count, err
}

// HostAlerts reads the alerts of one host for its tab: the open ones and
// the ones resolved within the last day, newest first.
func (s *Store) HostAlerts(ctx context.Context, hostID string) ([]Alert, error) {
	return s.queryAlerts(ctx, `
		select `+alertColumns+`
		from alerts a join hosts h on h.id = a.host_id
		where a.host_id = $1
		  and (a.state <> 'resolved' or a.resolved_at > now() - interval '24 hours')
		order by a.state = 'resolved', a.started_at desc, a.id
		limit 100`, hostID)
}

// RulesMatching counts the enabled rules whose selector covers the host.
func (s *Store) RulesMatching(ctx context.Context, hostID string) (int, error) {
	if _, err := uuid.Parse(hostID); err != nil {
		return 0, nil
	}
	rules, err := s.ListRules(ctx)
	if err != nil {
		return 0, err
	}
	args := []any{hostID}
	var conditions []string
	count := 0
	for _, rule := range rules {
		if !rule.Enabled {
			continue
		}
		if !rule.Selector.Narrows() {
			count++
			continue
		}
		condition, extra, err := s.compileSelector(ctx, rule.Selector, len(args))
		if err != nil {
			s.log.Warn("the selector of an alert rule does not resolve", "rule", rule.Name, "error", err)
			continue
		}
		conditions = append(conditions, condition)
		args = append(args, extra...)
	}
	if len(conditions) == 0 {
		return count, nil
	}
	var covered int
	err = s.pool.QueryRow(ctx, `
		select count(*)
		from hosts h, unnest(array[`+strings.Join(conditions, ", ")+`]) as covered
		where h.id = $1::uuid and covered`, args...).Scan(&covered)
	if err != nil {
		return 0, err
	}
	return count + covered, nil
}

// compileSelector renders a selector that narrows as one SQL condition over
// the alias h: group references resolved, the host list a condition of its own.
func (s *Store) compileSelector(ctx context.Context, sel Selector, offset int) (string, []any, error) {
	var conditions []string
	var args []any
	expression, err := sel.Tree()
	if err != nil {
		return "", nil, err
	}
	if expression != nil {
		expanded, err := selector.Expand(ctx, expression, s.groupDirectory())
		if err != nil {
			return "", nil, err
		}
		condition, extra, err := selector.Compile(expanded, offset)
		if err != nil {
			return "", nil, err
		}
		conditions = append(conditions, condition)
		args = append(args, extra...)
	}
	if len(sel.HostIDs) > 0 {
		// The identifiers travel as text and are cast in the query; the
		// validation has checked their shape, so the cast cannot fail.
		args = append(args, sel.HostIDs)
		conditions = append(conditions, fmt.Sprintf(
			"h.id in (select unnest($%d::text[])::uuid)", offset+len(args)))
	}
	if len(conditions) == 0 {
		return "true", nil, nil
	}
	return "(" + strings.Join(conditions, " and ") + ")", args, nil
}

func (s *Store) queryAlerts(ctx context.Context, query string, args ...any) ([]Alert, error) {
	rows, err := s.pool.Query(ctx, query, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	alerts := []Alert{}
	for rows.Next() {
		var alert Alert
		var value float32
		if err := rows.Scan(&alert.ID, &alert.RuleID, &alert.RuleName, &alert.Metric,
			&alert.Severity, &alert.State, &value, &alert.Detail, &alert.StartedAt,
			&alert.FiredAt, &alert.ResolvedAt, &alert.Silenced, &alert.HostID,
			&alert.Hostname, &alert.AcknowledgedBy, &alert.AcknowledgedAt, &alert.Note); err != nil {
			return nil, err
		}
		alert.Value = float64(value)
		alerts = append(alerts, alert)
	}
	return alerts, rows.Err()
}

// Silence keeps the alerts of a host, of a rule, or of a rule on a host
// out of the on-call view until a deadline.
type Silence struct {
	ID string `json:"id"`
	// HostID and RuleID narrow the silence; an empty one does not narrow.
	HostID   string    `json:"host_id,omitempty"`
	Hostname string    `json:"hostname,omitempty"`
	RuleID   string    `json:"rule_id,omitempty"`
	RuleName string    `json:"rule_name,omitempty"`
	Until    time.Time `json:"until"`
	Reason   string    `json:"reason"`
	// Global marks the silence that may keep back the security alerts of the
	// whole installation; it names neither a host nor a rule.
	Global bool `json:"global"`
	// SendSummary asks for one message per channel when the silence ends,
	// naming what it kept back; the kept-back messages themselves never go.
	SendSummary bool       `json:"send_summary"`
	CreatedBy   string     `json:"created_by"`
	CreatedAt   time.Time  `json:"created_at"`
	ExpiredAt   *time.Time `json:"expired_at"`
}

// The bounds of a silence: it is a decision to switch a sensor off, so it
// has a deadline at most a day away and a reason somebody can read.
const (
	MaxSilence       = 24 * time.Hour
	MinSilenceReason = 8
)

// The refusals a silence can get. A code, not a sentence: the panel and the
// integrations branch on it.
const (
	// RefusalSilenceScopeConflict: a global silence that also names a host or a
	// rule. A silence of one host is not a permission to blind the installation.
	RefusalSilenceScopeConflict = "silence_scope_conflict"
	// RefusalGlobalSilenceDenied: a global silence ordered without the global
	// notification.manage permission.
	RefusalGlobalSilenceDenied = "global_silence_denied"
)

// ValidateSilence checks a silence ordered from the panel.
func ValidateSilence(silence Silence, now time.Time) error {
	// The one refusal with a code of its own: everything else here is a
	// malformed request, and invalid_silence has named that since the start.
	if silence.Global && (silence.HostID != "" || silence.RuleID != "") {
		return &opspec.RefusalError{Code: RefusalSilenceScopeConflict, Err: errors.New(
			"a global silence names neither a host nor a rule: it covers the whole installation")}
	}
	if len(strings.TrimSpace(silence.Reason)) < MinSilenceReason {
		return fmt.Errorf("the reason needs at least %d characters", MinSilenceReason)
	}
	if !silence.Until.After(now) {
		return errors.New("the silence has to end in the future")
	}
	if silence.Until.Sub(now) > MaxSilence {
		return errors.New("a silence may last a day at most")
	}
	if silence.RuleID != "" {
		if _, err := uuid.Parse(silence.RuleID); err != nil {
			return errors.New("rule_id is not a rule identifier")
		}
	}
	return nil
}

// CreateSilence records a silence.
func (s *Store) CreateSilence(ctx context.Context, silence Silence) (*Silence, error) {
	if err := ValidateSilence(silence, time.Now()); err != nil {
		return nil, err
	}
	id := uuid.NewString()
	var hostID, ruleID *string
	if silence.HostID != "" {
		hostID = &silence.HostID
	}
	if silence.RuleID != "" {
		ruleID = &silence.RuleID
	}
	if _, err := s.pool.Exec(ctx, `
		insert into silences (id, host_id, rule_id, until, reason, created_by, global, send_summary)
		values ($1, $2, $3, $4, $5, $6, $7, $8)`,
		id, hostID, ruleID, silence.Until, strings.TrimSpace(silence.Reason), silence.CreatedBy,
		silence.Global, silence.SendSummary); err != nil {
		return nil, err
	}
	return s.GetSilence(ctx, id)
}

const silenceColumns = `
	s.id, coalesce(s.host_id::text, ''), coalesce(h.hostname, ''),
	coalesce(s.rule_id::text, ''), coalesce(r.name, ''),
	s.until, s.reason, s.global, s.send_summary,
	s.created_by, s.created_at, s.expired_at`

// GetSilence returns one silence.
func (s *Store) GetSilence(ctx context.Context, id string) (*Silence, error) {
	if _, err := uuid.Parse(id); err != nil {
		return nil, ErrNotFound
	}
	list, err := s.querySilences(ctx, `
		select `+silenceColumns+`
		from silences s
		left join hosts h on h.id = s.host_id
		left join alert_rules r on r.id = s.rule_id
		where s.id = $1`, id)
	if err != nil {
		return nil, err
	}
	if len(list) == 0 {
		return nil, ErrNotFound
	}
	return &list[0], nil
}

// ExpireSilence ends a silence of the host early. A silence of another host is
// not found: the path names the host, and the silence has to be its own.
func (s *Store) ExpireSilence(ctx context.Context, hostID, id string) error {
	if _, err := uuid.Parse(id); err != nil {
		return ErrNotFound
	}
	tag, err := s.pool.Exec(ctx, `
		update silences set expired_at = now()
		where id = $1 and host_id = $2 and expired_at is null`, id, hostID)
	if err != nil {
		return err
	}
	if tag.RowsAffected() == 0 {
		return ErrNotFound
	}
	return nil
}

// ExpireFleetSilence ends a silence that names no host early. A silence of a
// host is not found here: that one is ended through its host.
func (s *Store) ExpireFleetSilence(ctx context.Context, id string) error {
	if _, err := uuid.Parse(id); err != nil {
		return ErrNotFound
	}
	tag, err := s.pool.Exec(ctx, `
		update silences set expired_at = now()
		where id = $1 and host_id is null and expired_at is null`, id)
	if err != nil {
		return err
	}
	if tag.RowsAffected() == 0 {
		return ErrNotFound
	}
	return nil
}

// ActiveSilences lists the silences in force, the soonest to end first.
func (s *Store) ActiveSilences(ctx context.Context, scopes []authz.Scope) ([]Silence, error) {
	condition, args := authz.ScopeSQL(scopes, "h.site", "h.environment", 0)
	if condition == "" {
		condition = "true"
	}
	// A silence without a host is fleet-wide and visible to everyone who
	// may read alerts at all.
	return s.querySilences(ctx, `
		select `+silenceColumns+`
		from silences s
		left join hosts h on h.id = s.host_id
		left join alert_rules r on r.id = s.rule_id
		where s.expired_at is null and s.until > now()
		  and (s.host_id is null or `+condition+`)
		order by s.until, s.id`, args...)
}

// HostSilences lists the silences in force for one host: its own and the
// fleet-wide ones.
func (s *Store) HostSilences(ctx context.Context, hostID string) ([]Silence, error) {
	return s.querySilences(ctx, `
		select `+silenceColumns+`
		from silences s
		left join hosts h on h.id = s.host_id
		left join alert_rules r on r.id = s.rule_id
		where s.expired_at is null and s.until > now()
		  and (s.host_id is null or s.host_id = $1)
		order by s.until, s.id`, hostID)
}

func (s *Store) querySilences(ctx context.Context, query string, args ...any) ([]Silence, error) {
	rows, err := s.pool.Query(ctx, query, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	list := []Silence{}
	for rows.Next() {
		var silence Silence
		if err := rows.Scan(&silence.ID, &silence.HostID, &silence.Hostname, &silence.RuleID,
			&silence.RuleName, &silence.Until, &silence.Reason, &silence.Global,
			&silence.SendSummary, &silence.CreatedBy, &silence.CreatedAt,
			&silence.ExpiredAt); err != nil {
			return nil, err
		}
		list = append(list, silence)
	}
	return list, rows.Err()
}
