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
	"github.com/ultherego/flotestro/internal/selector"
)

// ErrNotFound says the rule, alert or silence does not exist.
var ErrNotFound = errors.New("not found")

// The metrics a rule may watch. Every one of them is computed from a sample
// of the host, except host_offline, which is computed from the absence of
// samples. The two agent_ metrics are the agent's own footprint: what the
// agent costs the host, as it read from /proc/self.
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

// Catalogue lists the metrics a rule may watch with their units, in the
// order the panel shows them. The sample fields the agent reports but no
// rule watches - goroutines, descriptors, the helper's memory - are on the
// host page and not here: they are read next to a chart, not alarmed on.
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

// Selector names the hosts a rule covers, in the shape of a campaign
// selector. Empty fields do not narrow - an empty host list included - so
// an empty selector covers the whole fleet. The fields that are set all
// have to hold: a site and a tag name the tagged hosts of that site.
type Selector struct {
	Site        string `json:"site,omitempty"`
	Environment string `json:"environment,omitempty"`
	OSFamily    string `json:"os_family,omitempty"`
	// Tags keeps the hosts carrying every one of the tags, 'key' or
	// 'key=value' as recorded on the host.
	Tags []string `json:"tags,omitempty"`
	// Groups keeps the hosts of any of the saved groups, named by
	// identifier or by name. A rule on the databases and the caches
	// watches both; a host has to be in one of them, not in all.
	Groups []string `json:"groups,omitempty"`
	Owner  string   `json:"owner,omitempty"`
	// Expression is the text form of a campaign selector, for a scope the
	// flat fields cannot say: "agent_version < 0.49.0 or reboot_required =
	// true". It is parsed when the rule is written and again when it is
	// evaluated, never evaluated from text.
	Expression string   `json:"expression,omitempty"`
	HostIDs    []string `json:"host_ids,omitempty"`
}

// Narrows says whether the selector leaves any host out.
func (sel Selector) Narrows() bool {
	return sel.Site != "" || sel.Environment != "" || sel.OSFamily != "" || len(sel.Tags) > 0 ||
		len(sel.Groups) > 0 || sel.Owner != "" || sel.Expression != "" || len(sel.HostIDs) > 0
}

// Tree renders the selector as the campaign selector package reads it,
// the host list aside: every set field is one condition and all of them
// hold at once. Nil means nothing narrows but the host list, if any. The
// tree is what the evaluator compiles into the host query, so a rule
// scoped by a tag and a campaign scoped by the same tag pick the same
// hosts.
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

// validate checks the selector as the operator wrote it: the shape of
// every field, and the whole as one selector, so that a scope the campaign
// page would refuse is refused here in the same words.
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

// ListRules returns every rule, the enabled ones first, by name.
func (s *Store) ListRules(ctx context.Context) ([]Rule, error) {
	rows, err := s.pool.Query(ctx, `
		select id, name, metric, operator, threshold, for_minutes, severity, selector,
		       enabled, created_by, created_at, updated_at
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
		select id, name, metric, operator, threshold, for_minutes, severity, selector,
		       enabled, created_by, created_at, updated_at
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
		&rule.CreatedAt, &rule.UpdatedAt); err != nil {
		return Rule{}, err
	}
	if len(selector) > 0 {
		if err := json.Unmarshal(selector, &rule.Selector); err != nil {
			return Rule{}, err
		}
	}
	return rule, nil
}

// groupDirectory resolves the group references of a selector against
// the saved groups. The directory is a view over the same pool, so it is
// made where it is used rather than kept.
func (s *Store) groupDirectory() selector.Groups {
	return selector.NewStore(s.pool)
}

// resolveSelector checks that the selector of a rule resolves: a group it
// names exists and the expansion stays within bounds. A rule naming a
// group nobody created is refused with the name rather than recorded as a
// rule that quietly watches nobody.
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
	if _, err := s.pool.Exec(ctx, `
		insert into alert_rules (id, name, metric, operator, threshold, for_minutes,
		    severity, selector, enabled, created_by)
		values ($1, $2, $3, $4, $5, $6, $7, $8::jsonb, $9, $10)`,
		id, strings.TrimSpace(rule.Name), rule.Metric, rule.Operator, rule.Threshold,
		rule.ForMinutes, rule.Severity, encoded, rule.Enabled, rule.CreatedBy); err != nil {
		return nil, err
	}
	return s.GetRule(ctx, id)
}

// UpdateRule replaces the settings of a rule. A rule that changes its
// metric or its condition starts its episodes afresh: the open alerts of
// the old condition are closed, because they answer a question nobody asks
// any more.
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

	if _, err := tx.Exec(ctx, `
		update alert_rules
		set name = $2, metric = $3, operator = $4, threshold = $5, for_minutes = $6,
		    severity = $7, selector = $8::jsonb, enabled = $9, updated_at = now()
		where id = $1`,
		id, strings.TrimSpace(rule.Name), rule.Metric, rule.Operator, rule.Threshold,
		rule.ForMinutes, rule.Severity, encoded, rule.Enabled); err != nil {
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

// closeOpenAlerts ends the episodes of a rule: a pending one vanishes, a
// firing one resolves.
func closeOpenAlerts(ctx context.Context, tx pgx.Tx, ruleID string) error {
	if _, err := tx.Exec(ctx,
		`delete from alerts where rule_id = $1 and state = 'pending'`, ruleID); err != nil {
		return err
	}
	_, err := tx.Exec(ctx, `
		update alerts set state = 'resolved', resolved_at = now()
		where rule_id = $1 and state = 'firing'`, ruleID)
	return err
}

// Alert is one episode of a rule on a host as the API shows it.
type Alert struct {
	ID       string `json:"id"`
	RuleID   string `json:"rule_id"`
	RuleName string `json:"rule_name"`
	Metric   string `json:"metric"`
	Severity string `json:"severity"`
	// State is pending, firing or resolved.
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
}

// AlertFilter narrows the alert history.
type AlertFilter struct {
	State    string
	Severity string
	HostID   string
	// Scopes narrow to the hosts the caller may read; nil narrows nothing.
	Scopes []authz.Scope
	Limit  int
}

// alertColumns is the projection every alert query shares; a is the
// alerts alias and h the host.
const alertColumns = `
	a.id, coalesce(a.rule_id::text, ''), a.rule_name, a.metric, a.severity, a.state,
	a.value, a.detail, a.started_at, a.fired_at, a.resolved_at,
	exists (select 1 from silences s
	        where s.expired_at is null and s.until > now()
	          and (s.host_id is null or s.host_id = a.host_id)
	          and (s.rule_id is null or s.rule_id = a.rule_id)),
	a.host_id, h.hostname`

// ListAlerts reads the alert history, newest first.
func (s *Store) ListAlerts(ctx context.Context, filter AlertFilter) ([]Alert, error) {
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
			return []Alert{}, nil
		}
		add("a.host_id", filter.HostID)
	}
	if filter.Scopes != nil {
		if condition, extra := authz.ScopeSQL(filter.Scopes, "h.site", "h.environment", len(args)); condition != "" {
			conditions = append(conditions, condition)
			args = append(args, extra...)
		}
	}
	where := ""
	if len(conditions) > 0 {
		where = "where " + strings.Join(conditions, " and ")
	}
	limit := filter.Limit
	if limit <= 0 || limit > 500 {
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

// Firing reads the firing alerts of the visible hosts: the most severe
// first, then the oldest, as on-call reads them.
func (s *Store) Firing(ctx context.Context, scopes []authz.Scope) ([]Alert, error) {
	condition, args := authz.ScopeSQL(scopes, "h.site", "h.environment", 0)
	if condition == "" {
		condition = "true"
	}
	return s.queryAlerts(ctx, `
		select `+alertColumns+`
		from alerts a join hosts h on h.id = a.host_id
		where a.state = 'firing' and `+condition+`
		order by case a.severity when 'critical' then 0 when 'warning' then 1 else 2 end,
		         a.fired_at, a.id`, args...)
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
//
// Every selector is compiled the way the evaluator compiles it and asked
// of this one host in a single query, so the count on the host page and
// the rules that fire on the host cannot disagree. A rule whose selector
// does not resolve any more - a group deleted since - covers nobody here,
// as it evaluates nobody.
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

// compileSelector renders a selector that narrows as one SQL condition
// over the alias h of the hosts table, group references resolved and the
// host list included. offset is the number of parameters the enclosing
// query already uses.
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
			&alert.Hostname); err != nil {
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
	HostID    string     `json:"host_id,omitempty"`
	Hostname  string     `json:"hostname,omitempty"`
	RuleID    string     `json:"rule_id,omitempty"`
	RuleName  string     `json:"rule_name,omitempty"`
	Until     time.Time  `json:"until"`
	Reason    string     `json:"reason"`
	CreatedBy string     `json:"created_by"`
	CreatedAt time.Time  `json:"created_at"`
	ExpiredAt *time.Time `json:"expired_at"`
}

// The bounds of a silence: it is a decision to switch a sensor off, so it
// has a deadline at most a day away and a reason somebody can read.
const (
	MaxSilence       = 24 * time.Hour
	MinSilenceReason = 8
)

// ValidateSilence checks a silence ordered from the panel.
func ValidateSilence(silence Silence, now time.Time) error {
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
		insert into silences (id, host_id, rule_id, until, reason, created_by)
		values ($1, $2, $3, $4, $5, $6)`,
		id, hostID, ruleID, silence.Until, strings.TrimSpace(silence.Reason), silence.CreatedBy); err != nil {
		return nil, err
	}
	return s.GetSilence(ctx, id)
}

const silenceColumns = `
	s.id, coalesce(s.host_id::text, ''), coalesce(h.hostname, ''),
	coalesce(s.rule_id::text, ''), coalesce(r.name, ''),
	s.until, s.reason, s.created_by, s.created_at, s.expired_at`

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

// ExpireSilence ends a silence of the host early. A silence of another
// host is not found: the path names the host, and the silence has to be
// its own.
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
			&silence.RuleName, &silence.Until, &silence.Reason, &silence.CreatedBy,
			&silence.CreatedAt, &silence.ExpiredAt); err != nil {
			return nil, err
		}
		list = append(list, silence)
	}
	return list, rows.Err()
}
