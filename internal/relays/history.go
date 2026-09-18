package relays

import (
	"context"
	"fmt"
	"log/slog"
	"time"

	"github.com/google/uuid"
)

// The rhythm of the buffer history.
//
// A relay reports itself once a minute, so that is the distance between
// two raw points. The rollup and the retention run on the quarter-hour,
// the same cadence the resource samples of the hosts are folded on, and
// the rules are evaluated at every sampling interval.
const (
	SamplingInterval   = time.Minute
	rollupInterval     = 15 * time.Minute
	evaluationInterval = time.Minute
	// maxSampleGap is how old the newest report may be and still count as
	// a reading. Beyond it the relay is not quiet about its buffer - it is
	// quiet altogether, which is what the silent state says.
	maxSampleGap = 5 * SamplingInterval
	// droppedWindow is the stretch the growth of the drop counter is read
	// over. It is deliberately longer than the sampling interval: one lost
	// heartbeat must not hide a drop.
	droppedWindow = 15 * time.Minute
)

// The retention of the buffer history.
//
// Seven days of raw points cover "was this site cut off last night" and
// the week an operator looks back over; ninety days of quarter-hour
// rollups cover "has this spool been filling for a month". Both are
// configurable, because a fleet of many relays pays for the raw days and
// a small installation may want a year of the rollups.
const (
	DefaultRawRetention    = 7 * 24 * time.Hour
	DefaultRollupRetention = 90 * 24 * time.Hour
)

// Options is the retention of the buffer history.
type Options struct {
	RawRetention    time.Duration
	RollupRetention time.Duration
}

func (o Options) withDefaults() Options {
	if o.RawRetention <= 0 {
		o.RawRetention = DefaultRawRetention
	}
	if o.RollupRetention <= 0 {
		o.RollupRetention = DefaultRollupRetention
	}
	return o
}

// SetRetention records how long the buffer history is kept. It is set once
// at startup, before the sweep runs and before the panel serves.
func (s *Store) SetRetention(options Options) { s.retention = options.withDefaults() }

// Retention is how long the buffer history is kept. The endpoint answers
// with it, so a window that reaches further back than the retention is
// read as "not kept that long" rather than as "the relay was quiet".
func (s *Store) Retention() Options { return s.retention.withDefaults() }

// Sample is one buffer report of a relay as the history keeps it.
type Sample struct {
	RelayID    string
	ReportedAt time.Time
	// InstanceID names the process of the relay. A change of it between
	// two samples is a restart, and that is the only thing that explains
	// the drop counter going back to zero.
	InstanceID     string
	BytesUsed      int64
	BytesLimit     int64
	ItemCount      int
	DroppedTotal   int64
	ActiveSessions int
	UpstreamState  string
	Version        string
}

// SampleOf renders a heartbeat as a row of the history.
//
// The limit is the spool's when the relay reports one and the old buffer
// maximum otherwise: a relay from before the spool reported only the
// memory buffer, and its history is to be readable next to a new one.
func SampleOf(relayID string, heartbeat Heartbeat) Sample {
	limit := heartbeat.SpoolBytesLimit
	if limit <= 0 {
		limit = heartbeat.BufferMaxBytes
	}
	return Sample{
		RelayID: relayID, ReportedAt: heartbeat.ReportedAt,
		InstanceID: heartbeat.InstanceID, BytesUsed: heartbeat.BufferBytes,
		BytesLimit: limit, ItemCount: heartbeat.BufferedItems,
		DroppedTotal: heartbeat.BufferDropped, ActiveSessions: heartbeat.Sessions,
		UpstreamState: heartbeat.UpstreamState, Version: heartbeat.RelayVersion,
	}
}

// RecordSample writes one report of a relay into the history.
//
// A repeated report for the same instant overwrites rather than fails: a
// relay that retries its heartbeat after a timeout must not be refused for
// a row it has already written.
func (s *Store) RecordSample(ctx context.Context, sample Sample) error {
	const query = `
		insert into relay_buffer_samples (relay_id, reported_at, instance_id, bytes_used,
		                                  bytes_limit, item_count, dropped_total,
		                                  active_sessions, upstream_state, version)
		values ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)
		on conflict (relay_id, reported_at) do update set
			instance_id = excluded.instance_id, bytes_used = excluded.bytes_used,
			bytes_limit = excluded.bytes_limit, item_count = excluded.item_count,
			dropped_total = excluded.dropped_total,
			active_sessions = excluded.active_sessions,
			upstream_state = excluded.upstream_state, version = excluded.version`
	_, err := s.pool.Exec(ctx, query, sample.RelayID, sample.ReportedAt, sample.InstanceID,
		sample.BytesUsed, sample.BytesLimit, sample.ItemCount, sample.DroppedTotal,
		sample.ActiveSessions, sample.UpstreamState, sample.Version)
	return err
}

// The states of the link as the relay names them in its report. They are
// the words the relay writes; the panel does not invent a fourth.
const (
	UpstreamConnected    = "connected"
	UpstreamBuffering    = "buffering"
	UpstreamReconnecting = "reconnecting"
)

// BufferPoint is one point of the buffer chart. A raw point is one report;
// a rollup point is a quarter-hour of them.
type BufferPoint struct {
	At         time.Time `json:"at"`
	InstanceID string    `json:"instance_id,omitempty"`
	BytesUsed  int64     `json:"bytes_used"`
	// BytesUsedMax is the peak within the step; the same as BytesUsed on a
	// raw point, where the step is one report.
	BytesUsedMax int64 `json:"bytes_used_max"`
	BytesLimit   int64 `json:"bytes_limit"`
	ItemCount    int   `json:"item_count"`
	ItemCountMax int   `json:"item_count_max"`
	DroppedTotal int64 `json:"dropped_total"`
	// DroppedDelta is the growth of the drop counter since the previous
	// point. It is empty across a restart and at the first point: the
	// counter starts again with the process, and a difference taken across
	// that would be a negative number nobody can read.
	DroppedDelta   *int64 `json:"dropped_delta"`
	ActiveSessions int    `json:"active_sessions"`
	UpstreamState  string `json:"upstream_state,omitempty"`
	// Disconnected says the relay had no upstream at this point. On a
	// rollup it is true when any report of the quarter said so, because a
	// quarter with one such report is an outage too.
	Disconnected bool `json:"disconnected"`
	// Restarted marks a point whose process differs from the previous
	// one's: the relay was restarted between them.
	Restarted bool   `json:"restarted"`
	Version   string `json:"version,omitempty"`
	// Samples is how many reports the point is made of: one on a raw
	// point, the reports of the quarter on a rollup. Zero reports are
	// never a point at all - a gap stays a gap.
	Samples int `json:"samples"`
}

// UsedPercent is the fill of the buffer as a share of its limit. The
// second result is false for a relay that reported no limit: an unknown
// limit makes the share unknown, and an unknown share is not zero.
func (p BufferPoint) UsedPercent() (float64, bool) {
	if p.BytesLimit <= 0 {
		return 0, false
	}
	return float64(p.BytesUsed) / float64(p.BytesLimit) * 100, true
}

// BufferRange is a named window of the buffer chart.
type BufferRange struct {
	Name   string
	Window time.Duration
	// Step is the distance between two points: the sampling interval for
	// the raw windows, a quarter-hour for the rolled-up ones.
	Step time.Duration
}

// Rollup says whether the range reads the quarter-hour rollups.
func (r BufferRange) Rollup() bool { return r.Step > SamplingInterval }

// The windows the buffer chart offers. Three hours and a day come from
// the raw reports, because that is where a single lost minute matters; a
// week, a month and a quarter come from the rollups, whose retention is
// what makes them answer at all.
var bufferRanges = map[string]BufferRange{
	"3h":  {Name: "3h", Window: 3 * time.Hour, Step: SamplingInterval},
	"24h": {Name: "24h", Window: 24 * time.Hour, Step: SamplingInterval},
	"7d":  {Name: "7d", Window: 7 * 24 * time.Hour, Step: rollupInterval},
	"30d": {Name: "30d", Window: 30 * 24 * time.Hour, Step: rollupInterval},
	"90d": {Name: "90d", Window: 90 * 24 * time.Hour, Step: rollupInterval},
}

// ParseBufferRange reads the range of a request; an empty one is three
// hours.
func ParseBufferRange(name string) (BufferRange, error) {
	if name == "" {
		name = "24h"
	}
	window, ok := bufferRanges[name]
	if !ok {
		return BufferRange{}, fmt.Errorf("unknown range %q; use 3h, 24h, 7d, 30d or 90d", name)
	}
	return window, nil
}

// BufferHistory is the answer of the history endpoint.
type BufferHistory struct {
	Points []BufferPoint `json:"points"`
	// Latest is the newest raw report whatever the range; empty for a
	// relay that has never reported.
	Latest *BufferPoint `json:"latest"`
}

// BufferSamples reads the points of a relay over a window.
func (s *Store) BufferSamples(ctx context.Context, relayID string,
	window BufferRange) (BufferHistory, error) {
	var history BufferHistory
	var points []BufferPoint
	var err error
	if window.Rollup() {
		points, err = s.bufferRollups(ctx, relayID, window.Window)
	} else {
		points, err = s.bufferRaw(ctx, relayID, window.Window)
	}
	if err != nil {
		return history, err
	}
	history.Points = markPoints(points)

	// The latest raw report is read separately: a long window answers from
	// the rollups, whose newest quarter is up to fifteen minutes behind,
	// and the head of the page is to say what the relay reports now.
	latest, err := s.bufferRaw(ctx, relayID, maxSampleGap)
	if err != nil {
		return history, err
	}
	if len(latest) > 0 {
		newest := latest[len(latest)-1]
		history.Latest = &newest
	}
	if history.Points == nil {
		history.Points = []BufferPoint{}
	}
	return history, nil
}

func (s *Store) bufferRaw(ctx context.Context, relayID string,
	window time.Duration) ([]BufferPoint, error) {
	const query = `
		select reported_at, instance_id, bytes_used, bytes_limit, item_count,
		       dropped_total, active_sessions, upstream_state, version
		from relay_buffer_samples
		where relay_id = $1 and reported_at >= now() - make_interval(secs => $2)
		order by reported_at`
	rows, err := s.pool.Query(ctx, query, relayID, window.Seconds())
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var points []BufferPoint
	for rows.Next() {
		var point BufferPoint
		if err := rows.Scan(&point.At, &point.InstanceID, &point.BytesUsed,
			&point.BytesLimit, &point.ItemCount, &point.DroppedTotal,
			&point.ActiveSessions, &point.UpstreamState, &point.Version); err != nil {
			return nil, err
		}
		point.BytesUsedMax = point.BytesUsed
		point.ItemCountMax = point.ItemCount
		point.Samples = 1
		// A relay that says nothing about its link is not a relay that
		// says the link is up: an empty state stays empty and the point is
		// not counted as an outage.
		point.Disconnected = point.UpstreamState != "" && point.UpstreamState != UpstreamConnected
		points = append(points, point)
	}
	return points, rows.Err()
}

func (s *Store) bufferRollups(ctx context.Context, relayID string,
	window time.Duration) ([]BufferPoint, error) {
	const query = `
		select at, instance_id, bytes_used, bytes_used_max, bytes_limit, item_count,
		       item_count_max, dropped_total, active_sessions, upstream_state,
		       disconnected_samples, version, samples
		from relay_buffer_samples_15m
		where relay_id = $1 and at >= now() - make_interval(secs => $2)
		order by at`
	rows, err := s.pool.Query(ctx, query, relayID, window.Seconds())
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var points []BufferPoint
	for rows.Next() {
		var point BufferPoint
		var disconnected int
		if err := rows.Scan(&point.At, &point.InstanceID, &point.BytesUsed,
			&point.BytesUsedMax, &point.BytesLimit, &point.ItemCount,
			&point.ItemCountMax, &point.DroppedTotal, &point.ActiveSessions,
			&point.UpstreamState, &disconnected, &point.Version, &point.Samples); err != nil {
			return nil, err
		}
		point.Disconnected = disconnected > 0
		points = append(points, point)
	}
	return points, rows.Err()
}

// markPoints fills in what one point alone cannot say: the growth of the
// drop counter and the restarts.
//
// Both are differences against the previous point, and both are left
// empty across a restart: the counter of a fresh process starts at zero,
// so a difference taken over the restart would report a negative growth
// or, worse, hide the drops of the process that ended.
func markPoints(points []BufferPoint) []BufferPoint {
	for i := range points {
		if i == 0 {
			continue
		}
		previous := points[i-1]
		if points[i].InstanceID != "" && previous.InstanceID != "" &&
			points[i].InstanceID != previous.InstanceID {
			points[i].Restarted = true
			continue
		}
		if points[i].DroppedTotal < previous.DroppedTotal {
			// The counter went backwards without the process changing
			// name: the relay is older than the instance identifier, and
			// the only honest reading of that is a restart.
			points[i].Restarted = true
			continue
		}
		delta := points[i].DroppedTotal - previous.DroppedTotal
		points[i].DroppedDelta = &delta
	}
	return points
}

// Run rolls the buffer reports up, applies the retention and evaluates the
// buffer rules until the context ends.
//
// It follows the shape of the resource samples of the hosts - raw rows, a
// quarter-hour rollup, a retention sweep and rules evaluated over the
// newest reading - but it is kept here rather than in the monitoring
// store, because the shapes do not fit: a monitoring rule carries a host
// selector and an alert carries a host that cannot be null, and a relay is
// not a host. The retention deletes rows rather than dropping daily
// partitions for the same reason the migration gives: a fleet of relays is
// three orders of magnitude smaller than a fleet of hosts.
func (s *Store) Run(ctx context.Context, log *slog.Logger) {
	options := s.Retention()
	rollup := time.NewTicker(rollupInterval)
	defer rollup.Stop()
	evaluate := time.NewTicker(evaluationInterval)
	defer evaluate.Stop()
	// A rollup at the start catches up after a restart: a panel down for
	// an hour has four quarter-hours waiting.
	s.maintain(ctx, options, log)
	for {
		select {
		case <-ctx.Done():
			return
		case <-rollup.C:
			s.maintain(ctx, options, log)
		case <-evaluate.C:
			if err := s.EvaluateBufferRules(ctx, time.Now().UTC()); err != nil && ctx.Err() == nil {
				log.Error("the relay buffer rules were not evaluated", "err", err)
			}
		}
	}
}

func (s *Store) maintain(ctx context.Context, options Options, log *slog.Logger) {
	if err := s.RollupBuffer(ctx, options); err != nil && ctx.Err() == nil {
		log.Error("the relay buffer reports were not rolled up", "err", err)
	}
	if err := s.sweepBuffer(ctx, options); err != nil && ctx.Err() == nil {
		log.Error("the retention of the relay buffer history was not applied", "err", err)
	}
}

// RollupBuffer folds the finished quarter-hours into the rollup table.
//
// The rollup starts at the newest quarter already written and ends at the
// start of the current one, so a quarter is written once complete and
// rewritten only while it is the newest - a report that arrived late for
// it is then counted. The drop counter is cumulative, so the quarter keeps
// its last value rather than a mean of counters.
func (s *Store) RollupBuffer(ctx context.Context, options Options) error {
	options = options.withDefaults()
	_, err := s.pool.Exec(ctx, `
		with bounds as (
		    select coalesce((select max(at) from relay_buffer_samples_15m),
		                    now() - make_interval(secs => $1)) as since,
		           date_trunc('hour', now())
		             + (extract(minute from now())::int / 15) * interval '15 minutes' as upto
		),
		bucketed as (
		    select s.*,
		           date_trunc('hour', s.reported_at)
		             + (extract(minute from s.reported_at)::int / 15) * interval '15 minutes' as bucket
		    from relay_buffer_samples s, bounds b
		    where s.reported_at >= b.since and s.reported_at < b.upto
		)
		insert into relay_buffer_samples_15m (relay_id, at, instance_id, bytes_used,
		    bytes_used_max, bytes_limit, item_count, item_count_max, dropped_total,
		    active_sessions, upstream_state, disconnected_samples, restarts, version, samples)
		select relay_id, bucket,
		       (array_agg(instance_id order by reported_at desc))[1],
		       avg(bytes_used)::bigint, max(bytes_used), max(bytes_limit),
		       avg(item_count)::integer, max(item_count),
		       (array_agg(dropped_total order by reported_at desc))[1],
		       (array_agg(active_sessions order by reported_at desc))[1],
		       (array_agg(upstream_state order by reported_at desc))[1],
		       -- A report that says nothing about the link is not a report
		       -- that the link was up, so it is not counted either way.
		       count(*) filter (where upstream_state <> '' and upstream_state <> 'connected'),
		       greatest(count(distinct instance_id) - 1, 0),
		       (array_agg(version order by reported_at desc))[1],
		       count(*)
		from bucketed
		group by relay_id, bucket
		on conflict (relay_id, at) do update set
		    instance_id = excluded.instance_id, bytes_used = excluded.bytes_used,
		    bytes_used_max = excluded.bytes_used_max, bytes_limit = excluded.bytes_limit,
		    item_count = excluded.item_count, item_count_max = excluded.item_count_max,
		    dropped_total = excluded.dropped_total,
		    active_sessions = excluded.active_sessions,
		    upstream_state = excluded.upstream_state,
		    disconnected_samples = excluded.disconnected_samples,
		    restarts = excluded.restarts, version = excluded.version,
		    samples = excluded.samples`,
		options.RawRetention.Seconds())
	return err
}

// sweepBuffer applies the retention: a week of raw reports and a quarter
// of a year of rollups, and the resolved episodes older than the rollups.
func (s *Store) sweepBuffer(ctx context.Context, options Options) error {
	options = options.withDefaults()
	if _, err := s.pool.Exec(ctx,
		`delete from relay_buffer_samples where reported_at < now() - make_interval(secs => $1)`,
		options.RawRetention.Seconds()); err != nil {
		return err
	}
	if _, err := s.pool.Exec(ctx,
		`delete from relay_buffer_samples_15m where at < now() - make_interval(secs => $1)`,
		options.RollupRetention.Seconds()); err != nil {
		return err
	}
	_, err := s.pool.Exec(ctx,
		`delete from relay_buffer_alerts
		 where state = 'resolved' and resolved_at < now() - make_interval(secs => $1)`,
		options.RollupRetention.Seconds())
	return err
}

// The metrics a buffer rule may watch.
const (
	// MetricBufferUsedPercent is the fill of the spool as a share of its
	// limit. Unknown for a relay that reports no limit.
	MetricBufferUsedPercent = "relay_buffer_used_percent"
	// MetricBufferDroppedIncrease is the growth of the drop counter over
	// the evaluation window. It is never read across a restart: the
	// counter starts again with the process.
	MetricBufferDroppedIncrease = "relay_buffer_dropped_increase"
)

// BufferRule is one alert rule over the buffer of a relay.
type BufferRule struct {
	ID         string    `json:"id"`
	Name       string    `json:"name"`
	Metric     string    `json:"metric"`
	Operator   string    `json:"operator"`
	Threshold  float64   `json:"threshold"`
	ForMinutes int       `json:"for_minutes"`
	Severity   string    `json:"severity"`
	Enabled    bool      `json:"enabled"`
	CreatedBy  string    `json:"created_by"`
	CreatedAt  time.Time `json:"created_at"`
}

// BufferRules lists the rules over the relay buffers, the built-in ones
// the migration seeded included.
func (s *Store) BufferRules(ctx context.Context) ([]BufferRule, error) {
	const query = `
		select id::text, name, metric, operator, threshold, for_minutes, severity,
		       enabled, created_by, created_at
		from relay_buffer_alert_rules order by metric, threshold`
	rows, err := s.pool.Query(ctx, query)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	rules := []BufferRule{}
	for rows.Next() {
		var rule BufferRule
		if err := rows.Scan(&rule.ID, &rule.Name, &rule.Metric, &rule.Operator,
			&rule.Threshold, &rule.ForMinutes, &rule.Severity, &rule.Enabled,
			&rule.CreatedBy, &rule.CreatedAt); err != nil {
			return nil, err
		}
		rules = append(rules, rule)
	}
	return rules, rows.Err()
}

// BufferAlert is one episode of a buffer rule on one relay.
type BufferAlert struct {
	ID         string     `json:"id"`
	RuleID     string     `json:"rule_id,omitempty"`
	RuleName   string     `json:"rule_name"`
	Metric     string     `json:"metric"`
	Severity   string     `json:"severity"`
	RelayID    string     `json:"relay_id"`
	State      string     `json:"state"`
	Value      float64    `json:"value"`
	Detail     string     `json:"detail,omitempty"`
	StartedAt  time.Time  `json:"started_at"`
	FiredAt    *time.Time `json:"fired_at,omitempty"`
	ResolvedAt *time.Time `json:"resolved_at,omitempty"`
}

// FiringBufferAlerts returns the episodes of a relay that have fired and
// not resolved. A pending episode is not yet news and is not listed.
func (s *Store) FiringBufferAlerts(ctx context.Context, relayID string) ([]BufferAlert, error) {
	const query = `
		select id::text, coalesce(rule_id::text, ''), rule_name, metric, severity,
		       relay_id::text, state, value, detail, started_at, fired_at, resolved_at
		from relay_buffer_alerts
		where relay_id = $1 and state = 'firing'
		order by started_at desc`
	rows, err := s.pool.Query(ctx, query, relayID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	alerts := []BufferAlert{}
	for rows.Next() {
		var alert BufferAlert
		if err := rows.Scan(&alert.ID, &alert.RuleID, &alert.RuleName, &alert.Metric,
			&alert.Severity, &alert.RelayID, &alert.State, &alert.Value, &alert.Detail,
			&alert.StartedAt, &alert.FiredAt, &alert.ResolvedAt); err != nil {
			return nil, err
		}
		alerts = append(alerts, alert)
	}
	return alerts, rows.Err()
}

// Reading is what one pass of the evaluator measures on one relay.
type Reading struct {
	RelayID string
	Latest  Sample
	// DroppedIncrease is the growth of the drop counter over the window,
	// within one process of the relay. Empty when it cannot be said: a
	// single report, or a restart inside the window.
	DroppedIncrease *int64
}

// Value returns the reading of a metric. The second result is false when
// nothing can be said - an unknown fill is not a fill of zero, and a rule
// must not fire or resolve on it.
func (r Reading) Value(metric string) (float64, string, bool) {
	switch metric {
	case MetricBufferUsedPercent:
		if r.Latest.BytesLimit <= 0 {
			return 0, "", false
		}
		share := float64(r.Latest.BytesUsed) / float64(r.Latest.BytesLimit) * 100
		return share, fmt.Sprintf("%d of %d bytes buffered, %d items waiting",
			r.Latest.BytesUsed, r.Latest.BytesLimit, r.Latest.ItemCount), true
	case MetricBufferDroppedIncrease:
		if r.DroppedIncrease == nil {
			return 0, "", false
		}
		return float64(*r.DroppedIncrease), fmt.Sprintf(
			"%d results dropped in the last %s; %d since the relay started",
			*r.DroppedIncrease, droppedWindow, r.Latest.DroppedTotal), true
	}
	return 0, "", false
}

// CompareBuffer applies the operator of a rule. An unknown operator never
// holds: a rule nobody can read must not fire.
func CompareBuffer(operator string, value, threshold float64) bool {
	switch operator {
	case "gt":
		return value > threshold
	case "gte":
		return value >= threshold
	case "lt":
		return value < threshold
	case "lte":
		return value <= threshold
	}
	return false
}

// readings gathers what every relay reports over the drop window.
func (s *Store) readings(ctx context.Context, now time.Time) (map[string]Reading, error) {
	const query = `
		select relay_id::text, reported_at, instance_id, bytes_used, bytes_limit,
		       item_count, dropped_total, active_sessions, upstream_state, version
		from relay_buffer_samples
		where reported_at >= now() - make_interval(secs => $1)
		order by relay_id, reported_at`
	rows, err := s.pool.Query(ctx, query, droppedWindow.Seconds())
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	// The oldest report of each relay within the window that still belongs
	// to the process reporting now: the growth is read between it and the
	// newest one, so a relay that restarted inside the window contributes
	// no growth at all rather than a difference across two counters.
	oldest := map[string]Sample{}
	result := map[string]Reading{}
	for rows.Next() {
		var sample Sample
		if err := rows.Scan(&sample.RelayID, &sample.ReportedAt, &sample.InstanceID,
			&sample.BytesUsed, &sample.BytesLimit, &sample.ItemCount, &sample.DroppedTotal,
			&sample.ActiveSessions, &sample.UpstreamState, &sample.Version); err != nil {
			return nil, err
		}
		reading := result[sample.RelayID]
		reading.RelayID = sample.RelayID
		reading.Latest = sample
		if previous, ok := oldest[sample.RelayID]; !ok || previous.InstanceID != sample.InstanceID {
			oldest[sample.RelayID] = sample
		}
		result[sample.RelayID] = reading
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}

	for id, reading := range result {
		// A reading older than a few heartbeats is not a reading: the
		// relay is silent, which is a matter for the relay state rather
		// than for its buffer.
		if now.Sub(reading.Latest.ReportedAt) > maxSampleGap {
			delete(result, id)
			continue
		}
		first := oldest[id]
		if first.ReportedAt.Equal(reading.Latest.ReportedAt) ||
			first.InstanceID != reading.Latest.InstanceID ||
			first.DroppedTotal > reading.Latest.DroppedTotal {
			result[id] = reading
			continue
		}
		growth := reading.Latest.DroppedTotal - first.DroppedTotal
		reading.DroppedIncrease = &growth
		result[id] = reading
	}
	return result, nil
}

// EvaluateBufferRules runs every enabled buffer rule over every relay that
// is reporting.
//
// An episode starts pending the first time the condition holds, fires once
// it has held for the rule's window, and resolves the first time it does
// not. A relay that says nothing advances no episode in either direction:
// silence is not a resolution, and a rule must not resolve itself because
// the site went off the air.
func (s *Store) EvaluateBufferRules(ctx context.Context, now time.Time) error {
	rules, err := s.BufferRules(ctx)
	if err != nil {
		return err
	}
	readings, err := s.readings(ctx, now)
	if err != nil {
		return err
	}
	open, err := s.openBufferAlerts(ctx)
	if err != nil {
		return err
	}
	for _, rule := range rules {
		if !rule.Enabled {
			continue
		}
		for relayID, reading := range readings {
			value, detail, known := reading.Value(rule.Metric)
			if !known {
				continue
			}
			key := rule.ID + "/" + relayID
			episode, exists := open[key]
			holds := CompareBuffer(rule.Operator, value, rule.Threshold)
			switch {
			case holds && !exists:
				if err := s.startBufferEpisode(ctx, rule, relayID, value, detail, now); err != nil {
					return err
				}
			case holds && episode.State == "pending":
				if now.Sub(episode.StartedAt) >= time.Duration(rule.ForMinutes)*time.Minute {
					if err := s.fireBufferEpisode(ctx, episode.ID, value, detail, now); err != nil {
						return err
					}
					continue
				}
				if err := s.refreshBufferEpisode(ctx, episode.ID, value, detail); err != nil {
					return err
				}
			case holds:
				if err := s.refreshBufferEpisode(ctx, episode.ID, value, detail); err != nil {
					return err
				}
			case exists && episode.State == "pending":
				// A condition that held for one reading is not an alert.
				if _, err := s.pool.Exec(ctx,
					`delete from relay_buffer_alerts where id = $1`, episode.ID); err != nil {
					return err
				}
			case exists:
				if _, err := s.pool.Exec(ctx, `
					update relay_buffer_alerts set state = 'resolved', resolved_at = $2, value = $3
					where id = $1 and state = 'firing'`, episode.ID, now, value); err != nil {
					return err
				}
			}
		}
	}
	return nil
}

// openEpisode is an episode that has not resolved.
type openEpisode struct {
	ID        string
	State     string
	StartedAt time.Time
}

func (s *Store) openBufferAlerts(ctx context.Context) (map[string]openEpisode, error) {
	rows, err := s.pool.Query(ctx, `
		select id::text, coalesce(rule_id::text, ''), relay_id::text, state, started_at
		from relay_buffer_alerts where state <> 'resolved'`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	open := map[string]openEpisode{}
	for rows.Next() {
		var episode openEpisode
		var ruleID, relayID string
		if err := rows.Scan(&episode.ID, &ruleID, &relayID, &episode.State,
			&episode.StartedAt); err != nil {
			return nil, err
		}
		if ruleID == "" {
			// The rule was removed; the episode stays as history and is
			// not advanced any more.
			continue
		}
		open[ruleID+"/"+relayID] = episode
	}
	return open, rows.Err()
}

// startBufferEpisode opens an episode. A rule with no holding window fires
// straight away: at that threshold waiting costs results.
func (s *Store) startBufferEpisode(ctx context.Context, rule BufferRule, relayID string,
	value float64, detail string, now time.Time) error {
	state := "pending"
	var firedAt *time.Time
	if rule.ForMinutes == 0 {
		state = "firing"
		firedAt = &now
	}
	const query = `
		insert into relay_buffer_alerts (id, rule_id, rule_name, metric, severity, relay_id,
		                                 state, value, detail, started_at, fired_at)
		values ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11)
		on conflict do nothing`
	_, err := s.pool.Exec(ctx, query, uuid.NewString(), rule.ID, rule.Name, rule.Metric,
		rule.Severity, relayID, state, value, detail, now, firedAt)
	return err
}

func (s *Store) fireBufferEpisode(ctx context.Context, id string, value float64,
	detail string, now time.Time) error {
	_, err := s.pool.Exec(ctx, `
		update relay_buffer_alerts set state = 'firing', fired_at = $2, value = $3, detail = $4
		where id = $1 and state = 'pending'`, id, now, value, detail)
	return err
}

func (s *Store) refreshBufferEpisode(ctx context.Context, id string, value float64,
	detail string) error {
	_, err := s.pool.Exec(ctx,
		`update relay_buffer_alerts set value = $2, detail = $3 where id = $1`, id, value, detail)
	return err
}
