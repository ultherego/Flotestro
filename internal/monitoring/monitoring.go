// Package monitoring keeps the resource samples of the hosts, rolls them up,
// evaluates the alert rules over them and holds the alerts and silences.
package monitoring

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

const (
	// SamplingInterval is how often an agent sends a sample.
	SamplingInterval = 60 * time.Second
	// silentAfter is the age of the last sample past which a host counts as
	// silent: three intervals, like the heartbeat.
	silentAfter = 3 * SamplingInterval
	// rollupInterval is how often the finished quarter-hours are rolled up
	// and the retention is applied.
	rollupInterval = 15 * time.Minute
	// evaluationInterval is how often the rules are evaluated. One sampling
	// interval: evaluating more often would look at the same sample twice.
	evaluationInterval = SamplingInterval

	// DefaultRawRetention and DefaultRollupRetention are the retention of the raw
	// samples and of the quarter-hour rollups: a week of readings at full
	// resolution, a quarter of a year of quarter-hours.
	DefaultRawRetention    = 7 * 24 * time.Hour
	DefaultRollupRetention = 90 * 24 * time.Hour
	// DefaultMaxLateness is how long after it was taken a sample may still arrive
	// and be stored.
	DefaultMaxLateness = 24 * time.Hour
	// DefaultRawQueryWindow is the longest window a chart reads raw samples over.
	DefaultRawQueryWindow = 24 * time.Hour
	// DefaultClockSkewLimit is how far a host's clock may differ from the panel's
	// before the sample is stamped with the panel's time instead.
	DefaultClockSkewLimit = 5 * time.Minute
	// DefaultPartitionsAhead is how many daily partitions of the raw samples
	// exist before they are needed.
	DefaultPartitionsAhead = 3
	// DefaultEvaluatorLease is how long one control-plane instance holds the
	// right to evaluate the alert rules.
	DefaultEvaluatorLease = 45 * time.Second
	// evaluatorRenewEvery is how often the holder renews while it
	// evaluates.
	evaluatorRenewEvery = 15 * time.Second
	// rollupCatchUp is how far back the rollup looks for buckets nobody queued.
	rollupCatchUp = 4 * rollupInterval
	// rollupBatchSize is how many buckets one pass of the rollup claims.
	rollupBatchSize = 500
	// rollupMaxPasses bounds one run of the rollup, so a backlog is worked
	// off over several runs rather than in one transaction that never ends.
	rollupMaxPasses = 40
	// identitySweepBatch and identitySweepPasses bound the deletion of the sample
	// identities.
	identitySweepBatch  = 20000
	identitySweepPasses = 16
)

// Filesystem is the usage of one mounted filesystem as the agent sent it.
type Filesystem struct {
	Mount       string `json:"mount"`
	Device      string `json:"device,omitempty"`
	Fstype      string `json:"fstype,omitempty"`
	TotalBytes  uint64 `json:"total_bytes"`
	UsedBytes   uint64 `json:"used_bytes"`
	InodesTotal uint64 `json:"inodes_total"`
	InodesUsed  uint64 `json:"inodes_used"`
}

// Interface is the cumulative traffic of one network interface.
type Interface struct {
	Name    string `json:"name"`
	RxBytes uint64 `json:"rx_bytes"`
	TxBytes uint64 `json:"tx_bytes"`
}

// Sample is one reading of a host as it is stored.
type Sample struct {
	// BootID and Sequence identify the reading: the boot the agent runs on and
	// the number of the sample within that boot, counted from one.
	BootID   string
	Sequence uint64
	// At is the moment the host says it took the reading and the moment the chart
	// draws it at; ReceivedAt is when the panel got it.
	At              time.Time
	ReceivedAt      time.Time
	CPUPercent      float64
	Load1           float64
	Load5           float64
	Load15          float64
	MemoryTotal     uint64
	MemoryUsed      uint64
	MemoryAvailable uint64
	SwapTotal       uint64
	SwapUsed        uint64
	UptimeSeconds   uint64
	Filesystems     []Filesystem
	Interfaces      []Interface
	// The agent's own footprint, as it read it from /proc/self.
	AgentRSSBytes   *uint64
	AgentCPUPercent *float64
	AgentGoroutines *uint32
	AgentOpenFDs    *uint32
	// HelperRSSBytes is present only while the root helper runs; it sleeps
	// between orders.
	HelperRSSBytes *uint64
	// The maxima exist only on a rollup: a raw sample is its own maximum.
	CPUPercentMax      *float64
	MemoryUsedMax      *uint64
	AgentRSSBytesMax   *uint64
	AgentCPUPercentMax *float64
}

// Options configures the store. Every field is a setting of the
// installation; a zero one is the default named above.
type Options struct {
	RawRetention    time.Duration
	RollupRetention time.Duration
	// MaxLateness is how old a sample may be on arrival and still be stored.
	MaxLateness time.Duration
	// RawQueryWindow is how far back the panel offers raw resolution.
	RawQueryWindow time.Duration
	// ClockSkewLimit is how far a host's clock may differ from the panel's
	// before the sample is stamped with the panel's time.
	ClockSkewLimit time.Duration
	// PartitionsAhead is how many days of raw partitions exist ahead of
	// today.
	PartitionsAhead int
	// EvaluatorLease is how long one instance holds the right to evaluate
	// the alert rules.
	EvaluatorLease time.Duration
}

// withDefaults fills the fields the installation left out.
func (o Options) withDefaults() Options {
	if o.RawRetention <= 0 {
		o.RawRetention = DefaultRawRetention
	}
	if o.RollupRetention <= 0 {
		o.RollupRetention = DefaultRollupRetention
	}
	if o.MaxLateness <= 0 {
		o.MaxLateness = DefaultMaxLateness
	}
	if o.RawQueryWindow <= 0 {
		o.RawQueryWindow = DefaultRawQueryWindow
	}
	if o.ClockSkewLimit <= 0 {
		o.ClockSkewLimit = DefaultClockSkewLimit
	}
	if o.PartitionsAhead <= 0 {
		o.PartitionsAhead = DefaultPartitionsAhead
	}
	if o.EvaluatorLease <= 0 {
		o.EvaluatorLease = DefaultEvaluatorLease
	}
	return o
}

// Validate refuses a configuration that throws data away by definition.
func (o Options) Validate() error {
	filled := o.withDefaults()
	if filled.RawRetention < filled.RawQueryWindow+filled.MaxLateness {
		return fmt.Errorf(
			"%s: the raw retention %s is shorter than the raw query window %s plus the maximum lateness %s; "+
				"raise the retention or lower the window or the lateness",
			ErrorRetentionTooShort, filled.RawRetention, filled.RawQueryWindow, filled.MaxLateness)
	}
	if filled.PartitionsAhead > maxPartitionsAhead {
		return fmt.Errorf("at most %d days of raw partitions may be created ahead, not %d",
			maxPartitionsAhead, filled.PartitionsAhead)
	}
	return nil
}

// maxPartitionsAhead bounds the margin.
const maxPartitionsAhead = 60

// Store is the database side of the monitoring.
type Store struct {
	pool    *pgxpool.Pool
	log     *slog.Logger
	options Options
	// instanceID names this control-plane process among the ones that share the
	// database.
	instanceID string
}

func NewStore(pool *pgxpool.Pool, log *slog.Logger, options Options) *Store {
	return &Store{pool: pool, log: log, options: options.withDefaults(), instanceID: uuid.NewString()}
}

// ClockSkewLimit and MaxLateness are what the gateway judges an arriving
// sample by: how far the host's clock may be out before the panel's time is
// used, and how old a sample may be before it is refused outright.
func (s *Store) ClockSkewLimit() time.Duration { return s.options.ClockSkewLimit }

func (s *Store) MaxLateness() time.Duration { return s.options.MaxLateness }

// Settings returns the retention and lateness the store runs on, for the
// status screen.
func (s *Store) Settings() Options { return s.options }

// The codes the monitoring puts on a refusal, as the error guide lists them.
const (
	// ErrorSampleTooOld: the sample reached the panel older than the raw
	// samples are kept for and was not stored.
	ErrorSampleTooOld = "metric_sample_too_old"
	// ErrorSampleNotKept: the gateway that received it keeps no samples.
	ErrorSampleNotKept = "metric_sample_not_kept"
	// ErrorRetentionTooShort: the configuration deletes samples before
	// they can arrive; the panel refuses to start on it.
	ErrorRetentionTooShort = "metrics_retention_too_short"
)

// RecordOutcome says what one delivery of a sample did.
type RecordOutcome string

const (
	// OutcomeUnknown is the outcome of a delivery that failed; the
	// acknowledgement is then not sent at all and the sample comes again.
	OutcomeUnknown RecordOutcome = ""
	// OutcomePersisted: this delivery wrote the sample.
	OutcomePersisted RecordOutcome = "persisted"
	// OutcomeDuplicate: the panel already held it.
	OutcomeDuplicate RecordOutcome = "duplicate"
)

// Record stores a sample of a host and marks the host as reporting.
func (s *Store) Record(ctx context.Context, hostID string, sample Sample) (RecordOutcome, error) {
	filesystems, err := json.Marshal(orEmptyFilesystems(sample.Filesystems))
	if err != nil {
		return OutcomeUnknown, err
	}
	interfaces, err := json.Marshal(orEmptyInterfaces(sample.Interfaces))
	if err != nil {
		return OutcomeUnknown, err
	}
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return OutcomeUnknown, err
	}
	defer func() { _ = tx.Rollback(ctx) }()

	if sample.BootID != "" && sample.Sequence > 0 {
		var taken bool
		err := tx.QueryRow(ctx, `
			insert into metric_samples (host_id, boot_id, sequence, at, received_at)
			values ($1, $2, $3, $4, coalesce($5::timestamptz, now()))
			on conflict (host_id, boot_id, sequence) do nothing
			returning true`,
			hostID, sample.BootID, int64(sample.Sequence), sample.At,
			orNullTime(sample.ReceivedAt)).Scan(&taken)
		if errors.Is(err, pgx.ErrNoRows) {
			// The panel holds this reading already.
			return OutcomeDuplicate, nil
		}
		if err != nil {
			return OutcomeUnknown, err
		}
	}

	if _, err := tx.Exec(ctx, `
		insert into host_metrics (host_id, at, cpu_percent, load1, load5, load15,
		    memory_total, memory_used, memory_available, swap_total, swap_used,
		    uptime_seconds, filesystems, interfaces,
		    agent_rss_bytes, agent_cpu_percent, agent_goroutines, agent_open_fds, helper_rss_bytes,
		    received_at)
		values ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13::jsonb, $14::jsonb,
		        $15, $16, $17, $18, $19, coalesce($20::timestamptz, now()))
		on conflict (host_id, at) do nothing`,
		hostID, sample.At, sample.CPUPercent, sample.Load1, sample.Load5, sample.Load15,
		int64(sample.MemoryTotal), int64(sample.MemoryUsed), int64(sample.MemoryAvailable),
		int64(sample.SwapTotal), int64(sample.SwapUsed), int64(sample.UptimeSeconds),
		filesystems, interfaces,
		nullableUint64(sample.AgentRSSBytes), sample.AgentCPUPercent,
		nullableUint32(sample.AgentGoroutines), nullableUint32(sample.AgentOpenFDs),
		nullableUint64(sample.HelperRSSBytes), orNullTime(sample.ReceivedAt)); err != nil {
		return OutcomeUnknown, err
	}
	// The quarter-hour this reading falls in has to be computed again.
	if _, err := tx.Exec(ctx, `
		insert into metric_rollup_dirty (host_id, bucket_at)
		values ($1, date_trunc('hour', $2::timestamptz)
		            + (extract(minute from $2::timestamptz)::int / 15) * interval '15 minutes')
		on conflict (host_id, bucket_at) do nothing`, hostID, sample.At); err != nil {
		return OutcomeUnknown, err
	}
	// The host row carries the moment of the newest sample; an old sample
	// replayed after a break must not move it backwards.
	if _, err := tx.Exec(ctx, `
		update hosts set last_metrics_at = greatest(coalesce(last_metrics_at, $2), $2)
		where id = $1`, hostID, sample.At); err != nil {
		return OutcomeUnknown, err
	}
	if err := tx.Commit(ctx); err != nil {
		return OutcomeUnknown, err
	}
	return OutcomePersisted, nil
}

// orNullTime passes a moment the caller did not observe as null, so the
// database stamps its own.
func orNullTime(at time.Time) *time.Time {
	if at.IsZero() {
		return nil
	}
	return &at
}

// nullableUint64 and nullableUint32 pass an absent value to the database
// as null in the signed types the columns have.
func nullableUint64(value *uint64) *int64 {
	if value == nil {
		return nil
	}
	signed := int64(*value)
	return &signed
}

func nullableUint32(value *uint32) *int32 {
	if value == nil {
		return nil
	}
	signed := int32(*value)
	return &signed
}

func orEmptyFilesystems(list []Filesystem) []Filesystem {
	if list == nil {
		return []Filesystem{}
	}
	return list
}

func orEmptyInterfaces(list []Interface) []Interface {
	if list == nil {
		return []Interface{}
	}
	return list
}

// Run rolls the samples up, applies the retention and evaluates the rules
// until the context ends.
func (s *Store) Run(ctx context.Context) {
	rollup := time.NewTicker(rollupInterval)
	defer rollup.Stop()
	evaluate := time.NewTicker(evaluationInterval)
	defer evaluate.Stop()
	// A rollup at the start catches up after a restart: a panel down for
	// an hour has four quarter-hours waiting.
	s.maintain(ctx)
	for {
		select {
		case <-ctx.Done():
			return
		case <-rollup.C:
			s.maintain(ctx)
		case <-evaluate.C:
			if err := s.EvaluateLeased(ctx, time.Now()); err != nil && ctx.Err() == nil {
				s.log.Error("the alert rules were not evaluated", "err", err)
			}
		}
	}
}

func (s *Store) maintain(ctx context.Context) {
	// The partitions of the days ahead come first.
	if err := s.EnsurePartitions(ctx, time.Now()); err != nil && ctx.Err() == nil {
		s.log.Error("the partitions of the raw samples were not prepared", "err", err)
	}
	if err := s.Rollup(ctx); err != nil && ctx.Err() == nil {
		s.log.Error("the samples were not rolled up", "err", err)
	}
	if err := s.sweep(ctx); err != nil && ctx.Err() == nil {
		s.log.Error("the retention of the samples was not applied", "err", err)
	}
}

// Rollup recomputes every quarter-hour bucket that owes one. The previous
// rollup asked the newest row of host_metrics_15m where to carry on from.
func (s *Store) Rollup(ctx context.Context) error {
	if err := s.queueFinishedBuckets(ctx); err != nil {
		return err
	}
	for pass := 0; pass < rollupMaxPasses; pass++ {
		done, err := s.rollupBatch(ctx)
		if err != nil {
			return err
		}
		if done == 0 {
			return nil
		}
	}
	// A backlog larger than one run - a panel that was down for a day -
	// is worked off over the next runs rather than in one transaction.
	s.log.Info("the rollup left buckets for the next pass",
		"claimed_per_pass", rollupBatchSize, "passes", rollupMaxPasses)
	return nil
}

// queueFinishedBuckets is the net under the queue: it looks over the last hour
// for a bucket of a host that nobody marked, queues it, and moves that host's
// mark to the quarter now running.
func (s *Store) queueFinishedBuckets(ctx context.Context) error {
	const queue = `
		with edge as (
		    select date_trunc('hour', now())
		             + (extract(minute from now())::int / 15) * interval '15 minutes' as at
		),
		pending as (
		    select m.host_id,
		           date_trunc('hour', m.at)
		             + (extract(minute from m.at)::int / 15) * interval '15 minutes' as bucket
		      from host_metrics m
		      cross join edge
		      left join metric_rollup_watermarks w on w.host_id = m.host_id
		     where m.at >= now() - make_interval(secs => $1::double precision)
		       and m.at >= coalesce(w.complete_through, '-infinity'::timestamptz)
		       and m.at < edge.at
		     group by 1, 2
		),
		queued as (
		    insert into metric_rollup_dirty (host_id, bucket_at)
		    select host_id, bucket from pending
		    on conflict (host_id, bucket_at) do nothing
		    returning host_id
		)
		insert into metric_rollup_watermarks (host_id, complete_through)
		select distinct p.host_id, edge.at from pending p cross join edge
		on conflict (host_id) do update
		   set complete_through = greatest(metric_rollup_watermarks.complete_through,
		                                   excluded.complete_through),
		       updated_at = now()`
	_, err := s.pool.Exec(ctx, queue, rollupCatchUp.Seconds())
	return err
}

// rollupBatch claims a batch of dirty buckets, recomputes exactly those and
// clears them, all in one statement and so in one transaction.
func (s *Store) rollupBatch(ctx context.Context) (int64, error) {
	const recompute = `
		with claimed as (
		    select host_id, bucket_at
		      from metric_rollup_dirty
		     where bucket_at < date_trunc('hour', now())
		             + (extract(minute from now())::int / 15) * interval '15 minutes'
		     order by dirty_at
		     limit $1::int
		     for update skip locked
		),
		bucketed as (
		    select c.host_id, c.bucket_at, m.at, m.cpu_percent, m.load1, m.load5, m.load15,
		           m.memory_total, m.memory_used, m.memory_available, m.swap_total, m.swap_used,
		           m.uptime_seconds, m.filesystems, m.interfaces,
		           m.agent_rss_bytes, m.agent_cpu_percent, m.agent_goroutines, m.agent_open_fds,
		           m.helper_rss_bytes
		      from claimed c
		      join host_metrics m
		        on m.host_id = c.host_id
		       and m.at >= c.bucket_at
		       and m.at <  c.bucket_at + interval '15 minutes'
		),
		rolled as (
		    insert into host_metrics_15m (host_id, at, cpu_percent, cpu_percent_max,
		        load1, load5, load15, memory_total, memory_used, memory_used_max,
		        memory_available, swap_total, swap_used, uptime_seconds,
		        filesystems, interfaces, samples,
		        agent_rss_bytes, agent_rss_bytes_max, agent_cpu_percent, agent_cpu_percent_max,
		        agent_goroutines, agent_open_fds, helper_rss_bytes)
		    select host_id, bucket_at,
		           avg(cpu_percent), max(cpu_percent),
		           avg(load1), avg(load5), avg(load15),
		           max(memory_total), avg(memory_used)::bigint, max(memory_used),
		           avg(memory_available)::bigint, max(swap_total), avg(swap_used)::bigint,
		           (array_agg(uptime_seconds order by at desc))[1],
		           (array_agg(filesystems order by at desc))[1],
		           (array_agg(interfaces order by at desc))[1],
		           count(*),
		           avg(agent_rss_bytes)::bigint, max(agent_rss_bytes),
		           avg(agent_cpu_percent), max(agent_cpu_percent),
		           avg(agent_goroutines)::integer, avg(agent_open_fds)::integer,
		           avg(helper_rss_bytes)::bigint
		    from bucketed
		    group by host_id, bucket_at
		    on conflict (host_id, at) do update set
		        cpu_percent = excluded.cpu_percent, cpu_percent_max = excluded.cpu_percent_max,
		        load1 = excluded.load1, load5 = excluded.load5, load15 = excluded.load15,
		        memory_total = excluded.memory_total, memory_used = excluded.memory_used,
		        memory_used_max = excluded.memory_used_max,
		        memory_available = excluded.memory_available,
		        swap_total = excluded.swap_total, swap_used = excluded.swap_used,
		        uptime_seconds = excluded.uptime_seconds,
		        filesystems = excluded.filesystems, interfaces = excluded.interfaces,
		        samples = excluded.samples,
		        agent_rss_bytes = excluded.agent_rss_bytes,
		        agent_rss_bytes_max = excluded.agent_rss_bytes_max,
		        agent_cpu_percent = excluded.agent_cpu_percent,
		        agent_cpu_percent_max = excluded.agent_cpu_percent_max,
		        agent_goroutines = excluded.agent_goroutines,
		        agent_open_fds = excluded.agent_open_fds,
		        helper_rss_bytes = excluded.helper_rss_bytes
		    returning 1
		)
		delete from metric_rollup_dirty d
		 using claimed c
		 where d.host_id = c.host_id and d.bucket_at = c.bucket_at`
	tag, err := s.pool.Exec(ctx, recompute, rollupBatchSize)
	if err != nil {
		return 0, err
	}
	return tag.RowsAffected(), nil
}

// sweep applies the retention: the raw samples a partition at a time, the
// rollups and the expired silences by the row, and the identities of the
// samples that can no longer arrive again.
func (s *Store) sweep(ctx context.Context) error {
	if err := s.DropExpiredPartitions(ctx, time.Now()); err != nil {
		return err
	}
	if err := s.sweepIdentities(ctx); err != nil {
		return err
	}
	// The quarter-hour rollups stay a delete by the row.
	if _, err := s.pool.Exec(ctx,
		`delete from host_metrics_15m where at < now() - make_interval(secs => $1)`,
		s.options.RollupRetention.Seconds()); err != nil {
		return err
	}
	_, err := s.pool.Exec(ctx,
		`delete from silences where until < now() - make_interval(secs => $1)`,
		s.options.RollupRetention.Seconds())
	return err
}

// sweepIdentities deletes the identities of the samples that can no longer be
// delivered a second time.
func (s *Store) sweepIdentities(ctx context.Context) error {
	horizon := (s.options.MaxLateness + time.Hour).Seconds()
	for pass := 0; pass < identitySweepPasses; pass++ {
		tag, err := s.pool.Exec(ctx, `
			delete from metric_samples
			 where ctid in (
			     select ctid from metric_samples
			      where at < now() - make_interval(secs => $1::double precision)
			      limit $2::int)`, horizon, identitySweepBatch)
		if err != nil {
			return err
		}
		if tag.RowsAffected() < identitySweepBatch {
			return nil
		}
	}
	return nil
}

// Range is a named chart window.
type Range struct {
	Name string
	// Window is how far back the points reach.
	Window time.Duration
	// Step is the distance between points: the sampling interval for the
	// raw windows, a quarter-hour for the rolled-up ones.
	Step time.Duration
}

// Rollup says whether the range reads the rollups instead of the raw
// samples.
func (r Range) Rollup() bool { return r.Step > SamplingInterval }

var ranges = map[string]Range{
	"3h":  {Name: "3h", Window: 3 * time.Hour, Step: SamplingInterval},
	"24h": {Name: "24h", Window: 24 * time.Hour, Step: SamplingInterval},
	"7d":  {Name: "7d", Window: 7 * 24 * time.Hour, Step: rollupInterval},
	"30d": {Name: "30d", Window: 30 * 24 * time.Hour, Step: rollupInterval},
}

// ParseRange reads a range name; empty means three hours.
func ParseRange(name string) (Range, error) {
	if name == "" {
		name = "3h"
	}
	r, ok := ranges[name]
	if !ok {
		return Range{}, fmt.Errorf("unknown range %q; use 3h, 24h, 7d or 30d", name)
	}
	return r, nil
}

// FilesystemPoint is the usage of one mount in a chart point.
type FilesystemPoint struct {
	Mount       string `json:"mount"`
	UsedBytes   uint64 `json:"used_bytes"`
	TotalBytes  uint64 `json:"total_bytes"`
	InodesUsed  uint64 `json:"inodes_used"`
	InodesTotal uint64 `json:"inodes_total"`
}

// InterfacePoint is the traffic rate of one interface between two
// consecutive samples.
type InterfacePoint struct {
	Name             string  `json:"name"`
	RxBytesPerSecond float64 `json:"rx_bytes_per_second"`
	TxBytesPerSecond float64 `json:"tx_bytes_per_second"`
}

// Point is one chart point as the API returns it: a raw sample or a
// quarter-hour rollup, with the network rates already computed.
type Point struct {
	At              time.Time         `json:"at"`
	CPUPercent      float64           `json:"cpu_percent"`
	Load1           float64           `json:"load1"`
	Load5           float64           `json:"load5"`
	Load15          float64           `json:"load15"`
	MemoryUsed      uint64            `json:"memory_used"`
	MemoryTotal     uint64            `json:"memory_total"`
	MemoryAvailable uint64            `json:"memory_available"`
	SwapUsed        uint64            `json:"swap_used"`
	SwapTotal       uint64            `json:"swap_total"`
	UptimeSeconds   uint64            `json:"uptime_seconds"`
	Filesystems     []FilesystemPoint `json:"filesystems"`
	Interfaces      []InterfacePoint  `json:"interfaces"`
	// The agent's own footprint; absent where the agent did not report it.
	AgentRSSBytes   *uint64  `json:"agent_rss_bytes,omitempty"`
	AgentCPUPercent *float64 `json:"agent_cpu_percent,omitempty"`
	AgentGoroutines *uint32  `json:"agent_goroutines,omitempty"`
	AgentOpenFDs    *uint32  `json:"agent_open_fds,omitempty"`
	HelperRSSBytes  *uint64  `json:"helper_rss_bytes,omitempty"`
	// The maxima of a rolled-up point; absent on a raw one.
	CPUPercentMax      *float64 `json:"cpu_percent_max,omitempty"`
	MemoryUsedMax      *uint64  `json:"memory_used_max,omitempty"`
	AgentRSSBytesMax   *uint64  `json:"agent_rss_bytes_max,omitempty"`
	AgentCPUPercentMax *float64 `json:"agent_cpu_percent_max,omitempty"`
}

// Series is the chart data of one host over a range.
type Series struct {
	Range        Range
	Points       []Point
	Latest       *Point
	LastSampleAt *time.Time
}

// Series reads the points of a host over a range: raw samples for the short
// windows, rollups for the long ones.
func (s *Store) Series(ctx context.Context, hostID string, r Range) (Series, error) {
	series := Series{Range: r, Points: []Point{}}
	var samples []Sample
	var err error
	if r.Rollup() {
		samples, err = s.rollups(ctx, hostID, r.Window)
	} else {
		samples, err = s.samples(ctx, hostID, r.Window, 0)
	}
	if err != nil {
		return series, err
	}
	series.Points = toPoints(samples)

	// The latest point comes from the newest two raw samples: a rate needs
	// a previous counter.
	series.Latest, series.LastSampleAt, err = s.Latest(ctx, hostID)
	return series, err
}

// Latest returns the newest raw sample of a host as a chart point, with the
// rates against the sample before it, and the moment it was taken.
func (s *Store) Latest(ctx context.Context, hostID string) (*Point, *time.Time, error) {
	newest, err := s.samples(ctx, hostID, 0, 2)
	if err != nil || len(newest) == 0 {
		return nil, nil, err
	}
	points := toPoints(newest)
	latest := points[len(points)-1]
	return &latest, &latest.At, nil
}

// samples reads the raw samples of a host within the window, oldest first. A
// window of zero means every sample; a limit above zero keeps the newest ones.
func (s *Store) samples(ctx context.Context, hostID string, window time.Duration, limit int) ([]Sample, error) {
	query := `
		select at, cpu_percent, load1, load5, load15, memory_total, memory_used,
		       memory_available, swap_total, swap_used, uptime_seconds,
		       filesystems, interfaces,
		       agent_rss_bytes, agent_cpu_percent, agent_goroutines, agent_open_fds, helper_rss_bytes
		from host_metrics
		where host_id = $1
		  and ($2::double precision <= 0 or at >= now() - make_interval(secs => $2::double precision))
		order by at desc
		limit $3::int`
	if limit <= 0 {
		limit = 100000
	}
	rows, err := s.pool.Query(ctx, query, hostID, window.Seconds(), limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var list []Sample
	for rows.Next() {
		var sample Sample
		var cpu, load1, load5, load15 float32
		var memoryTotal, memoryUsed, memoryAvailable, swapTotal, swapUsed, uptime int64
		var fp footprintColumns
		if err := rows.Scan(&sample.At, &cpu, &load1, &load5, &load15,
			&memoryTotal, &memoryUsed, &memoryAvailable, &swapTotal, &swapUsed, &uptime,
			&sample.Filesystems, &sample.Interfaces,
			&fp.rss, &fp.cpu, &fp.goroutines, &fp.openFDs, &fp.helperRSS); err != nil {
			return nil, err
		}
		sample.CPUPercent, sample.Load1, sample.Load5, sample.Load15 =
			float64(cpu), float64(load1), float64(load5), float64(load15)
		sample.MemoryTotal, sample.MemoryUsed, sample.MemoryAvailable =
			uint64(memoryTotal), uint64(memoryUsed), uint64(memoryAvailable)
		sample.SwapTotal, sample.SwapUsed, sample.UptimeSeconds =
			uint64(swapTotal), uint64(swapUsed), uint64(uptime)
		fp.into(&sample)
		list = append(list, sample)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	reverse(list)
	return list, nil
}

// footprintColumns is the footprint as the database holds it: signed
// types, null for an unknown value.
type footprintColumns struct {
	rss, helperRSS, rssMax *int64
	cpu, cpuMax            *float32
	goroutines, openFDs    *int32
}

// into copies the columns onto the sample, keeping null as nil.
func (fp footprintColumns) into(sample *Sample) {
	sample.AgentRSSBytes = unsignedOf(fp.rss)
	sample.HelperRSSBytes = unsignedOf(fp.helperRSS)
	sample.AgentRSSBytesMax = unsignedOf(fp.rssMax)
	sample.AgentCPUPercent = float64Of(fp.cpu)
	sample.AgentCPUPercentMax = float64Of(fp.cpuMax)
	sample.AgentGoroutines = unsigned32Of(fp.goroutines)
	sample.AgentOpenFDs = unsigned32Of(fp.openFDs)
}

func unsignedOf(value *int64) *uint64 {
	if value == nil {
		return nil
	}
	unsigned := uint64(*value)
	return &unsigned
}

func unsigned32Of(value *int32) *uint32 {
	if value == nil {
		return nil
	}
	unsigned := uint32(*value)
	return &unsigned
}

func float64Of(value *float32) *float64 {
	if value == nil {
		return nil
	}
	wide := float64(*value)
	return &wide
}

// rollups reads the quarter-hour rollups of a host within the window,
// oldest first.
func (s *Store) rollups(ctx context.Context, hostID string, window time.Duration) ([]Sample, error) {
	rows, err := s.pool.Query(ctx, `
		select at, cpu_percent, cpu_percent_max, load1, load5, load15, memory_total,
		       memory_used, memory_used_max, memory_available, swap_total, swap_used,
		       uptime_seconds, filesystems, interfaces,
		       agent_rss_bytes, agent_rss_bytes_max, agent_cpu_percent, agent_cpu_percent_max,
		       agent_goroutines, agent_open_fds, helper_rss_bytes
		from host_metrics_15m
		where host_id = $1 and at >= now() - make_interval(secs => $2)
		order by at`, hostID, window.Seconds())
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var list []Sample
	for rows.Next() {
		var sample Sample
		var cpu, cpuMax, load1, load5, load15 float32
		var memoryTotal, memoryUsed, memoryUsedMax, memoryAvailable, swapTotal, swapUsed, uptime int64
		var fp footprintColumns
		if err := rows.Scan(&sample.At, &cpu, &cpuMax, &load1, &load5, &load15,
			&memoryTotal, &memoryUsed, &memoryUsedMax, &memoryAvailable, &swapTotal, &swapUsed,
			&uptime, &sample.Filesystems, &sample.Interfaces,
			&fp.rss, &fp.rssMax, &fp.cpu, &fp.cpuMax, &fp.goroutines, &fp.openFDs, &fp.helperRSS); err != nil {
			return nil, err
		}
		sample.CPUPercent, sample.Load1, sample.Load5, sample.Load15 =
			float64(cpu), float64(load1), float64(load5), float64(load15)
		sample.MemoryTotal, sample.MemoryUsed, sample.MemoryAvailable =
			uint64(memoryTotal), uint64(memoryUsed), uint64(memoryAvailable)
		sample.SwapTotal, sample.SwapUsed, sample.UptimeSeconds =
			uint64(swapTotal), uint64(swapUsed), uint64(uptime)
		cpuMax64, memoryUsedMax64 := float64(cpuMax), uint64(memoryUsedMax)
		sample.CPUPercentMax, sample.MemoryUsedMax = &cpuMax64, &memoryUsedMax64
		fp.into(&sample)
		list = append(list, sample)
	}
	return list, rows.Err()
}

func reverse(list []Sample) {
	for i, j := 0, len(list)-1; i < j; i, j = i+1, j-1 {
		list[i], list[j] = list[j], list[i]
	}
}

// toPoints turns samples ordered oldest first into chart points, computing the
// network rates between consecutive samples.
func toPoints(samples []Sample) []Point {
	points := make([]Point, 0, len(samples))
	type counters struct {
		at     time.Time
		rx, tx uint64
	}
	previous := map[string]counters{}
	for _, sample := range samples {
		point := Point{
			At: sample.At, CPUPercent: sample.CPUPercent,
			Load1: sample.Load1, Load5: sample.Load5, Load15: sample.Load15,
			MemoryUsed: sample.MemoryUsed, MemoryTotal: sample.MemoryTotal,
			MemoryAvailable: sample.MemoryAvailable,
			SwapUsed:        sample.SwapUsed, SwapTotal: sample.SwapTotal,
			UptimeSeconds: sample.UptimeSeconds,
			Filesystems:   make([]FilesystemPoint, 0, len(sample.Filesystems)),
			Interfaces:    []InterfacePoint{},
			AgentRSSBytes: sample.AgentRSSBytes, AgentCPUPercent: sample.AgentCPUPercent,
			AgentGoroutines: sample.AgentGoroutines, AgentOpenFDs: sample.AgentOpenFDs,
			HelperRSSBytes: sample.HelperRSSBytes,
			CPUPercentMax:  sample.CPUPercentMax, MemoryUsedMax: sample.MemoryUsedMax,
			AgentRSSBytesMax: sample.AgentRSSBytesMax, AgentCPUPercentMax: sample.AgentCPUPercentMax,
		}
		for _, fs := range sample.Filesystems {
			point.Filesystems = append(point.Filesystems, FilesystemPoint{
				Mount: fs.Mount, UsedBytes: fs.UsedBytes, TotalBytes: fs.TotalBytes,
				InodesUsed: fs.InodesUsed, InodesTotal: fs.InodesTotal,
			})
		}
		for _, iface := range sample.Interfaces {
			last, seen := previous[iface.Name]
			previous[iface.Name] = counters{at: sample.At, rx: iface.RxBytes, tx: iface.TxBytes}
			if !seen {
				continue
			}
			seconds := sample.At.Sub(last.at).Seconds()
			if seconds <= 0 || iface.RxBytes < last.rx || iface.TxBytes < last.tx {
				continue
			}
			point.Interfaces = append(point.Interfaces, InterfacePoint{
				Name:             iface.Name,
				RxBytesPerSecond: float64(iface.RxBytes-last.rx) / seconds,
				TxBytesPerSecond: float64(iface.TxBytes-last.tx) / seconds,
			})
		}
		points = append(points, point)
	}
	return points
}

// Reporting counts the hosts that sent a sample within the last three
// intervals and those that did not, among the hosts that are not retired and
// within the given SQL condition over the alias h.
func (s *Store) Reporting(ctx context.Context, visible string, args []any) (reporting, silent int, err error) {
	params := append(append([]any{}, args...), silentAfter.Seconds())
	cutoff := fmt.Sprintf("now() - make_interval(secs => $%d::double precision)", len(params))
	err = s.pool.QueryRow(ctx, `
		select count(*) filter (where h.last_metrics_at >= `+cutoff+`),
		       count(*) filter (where h.last_metrics_at is null or h.last_metrics_at < `+cutoff+`)
		from hosts h
		where h.lifecycle_state <> 'retired' and `+visible, params...).Scan(&reporting, &silent)
	return reporting, silent, err
}
