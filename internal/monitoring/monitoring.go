// Package monitoring keeps the resource samples of the hosts, rolls them up,
// evaluates the alert rules over them and holds the alerts and silences.
//
// The agent reads the kernel counters and sends a sample every interval;
// the panel is the only place they go. There is no external metrics system
// and no external alert manager: an installation has charts and alerts the
// moment its hosts connect, and nothing to map its fleet onto.
package monitoring

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
)

const (
	// SamplingInterval is how often an agent sends a sample. The gateway
	// leaves the interval of the session configuration empty, so this is
	// what every agent runs at - and what the freshness of a host is
	// measured against.
	SamplingInterval = 60 * time.Second
	// silentAfter is the age of the last sample past which a host counts as
	// silent: three intervals, like the heartbeat.
	silentAfter = 3 * SamplingInterval
	// rollupInterval is how often the finished quarter-hours are rolled up
	// and the retention is applied.
	rollupInterval = 15 * time.Minute
	// evaluationInterval is how often the rules are evaluated. One
	// sampling interval: evaluating more often would look at the same
	// sample twice.
	evaluationInterval = SamplingInterval

	// DefaultRawRetention and DefaultRollupRetention are the retention of
	// the raw samples and of the quarter-hour rollups.
	DefaultRawRetention    = 48 * time.Hour
	DefaultRollupRetention = 30 * 24 * time.Hour
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
	At              time.Time
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
	// The maxima exist only on a rollup: a raw sample is its own maximum.
	CPUPercentMax *float64
	MemoryUsedMax *uint64
}

// Options configures the store.
type Options struct {
	RawRetention    time.Duration
	RollupRetention time.Duration
}

// Store is the database side of the monitoring.
type Store struct {
	pool    *pgxpool.Pool
	log     *slog.Logger
	options Options
}

func NewStore(pool *pgxpool.Pool, log *slog.Logger, options Options) *Store {
	if options.RawRetention <= 0 {
		options.RawRetention = DefaultRawRetention
	}
	if options.RollupRetention <= 0 {
		options.RollupRetention = DefaultRollupRetention
	}
	return &Store{pool: pool, log: log, options: options}
}

// Record stores a sample of a host and marks the host as reporting.
//
// A sample that arrives twice - the agent resent after a broken stream -
// is stored once: the pair of host and moment is the key.
func (s *Store) Record(ctx context.Context, hostID string, sample Sample) error {
	filesystems, err := json.Marshal(orEmptyFilesystems(sample.Filesystems))
	if err != nil {
		return err
	}
	interfaces, err := json.Marshal(orEmptyInterfaces(sample.Interfaces))
	if err != nil {
		return err
	}
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback(ctx) }()

	if _, err := tx.Exec(ctx, `
		insert into host_metrics (host_id, at, cpu_percent, load1, load5, load15,
		    memory_total, memory_used, memory_available, swap_total, swap_used,
		    uptime_seconds, filesystems, interfaces)
		values ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13::jsonb, $14::jsonb)
		on conflict (host_id, at) do nothing`,
		hostID, sample.At, sample.CPUPercent, sample.Load1, sample.Load5, sample.Load15,
		int64(sample.MemoryTotal), int64(sample.MemoryUsed), int64(sample.MemoryAvailable),
		int64(sample.SwapTotal), int64(sample.SwapUsed), int64(sample.UptimeSeconds),
		filesystems, interfaces); err != nil {
		return err
	}
	// The host row carries the moment of the newest sample; an old sample
	// replayed after a break must not move it backwards.
	if _, err := tx.Exec(ctx, `
		update hosts set last_metrics_at = greatest(coalesce(last_metrics_at, $2), $2)
		where id = $1`, hostID, sample.At); err != nil {
		return err
	}
	return tx.Commit(ctx)
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
			if err := s.Evaluate(ctx, time.Now()); err != nil && ctx.Err() == nil {
				s.log.Error("the alert rules were not evaluated", "err", err)
			}
		}
	}
}

func (s *Store) maintain(ctx context.Context) {
	if err := s.Rollup(ctx); err != nil && ctx.Err() == nil {
		s.log.Error("the samples were not rolled up", "err", err)
	}
	if err := s.sweep(ctx); err != nil && ctx.Err() == nil {
		s.log.Error("the retention of the samples was not applied", "err", err)
	}
}

// Rollup folds the finished quarter-hours into host_metrics_15m.
//
// The rollup starts at the newest rolled-up quarter and ends at the start
// of the current one, so a quarter is written once complete and rewritten
// only when it was the newest - a sample that arrived late for it is then
// counted. The network counters are cumulative, so a quarter keeps the
// last values rather than an average of counters.
func (s *Store) Rollup(ctx context.Context) error {
	_, err := s.pool.Exec(ctx, `
		with bounds as (
		    select coalesce((select max(at) from host_metrics_15m),
		                    now() - make_interval(secs => $1)) as since,
		           date_trunc('hour', now())
		             + (extract(minute from now())::int / 15) * interval '15 minutes' as upto
		),
		bucketed as (
		    select m.*,
		           date_trunc('hour', m.at)
		             + (extract(minute from m.at)::int / 15) * interval '15 minutes' as bucket
		    from host_metrics m, bounds b
		    where m.at >= b.since and m.at < b.upto
		)
		insert into host_metrics_15m (host_id, at, cpu_percent, cpu_percent_max,
		    load1, load5, load15, memory_total, memory_used, memory_used_max,
		    memory_available, swap_total, swap_used, uptime_seconds,
		    filesystems, interfaces, samples)
		select host_id, bucket,
		       avg(cpu_percent), max(cpu_percent),
		       avg(load1), avg(load5), avg(load15),
		       max(memory_total), avg(memory_used)::bigint, max(memory_used),
		       avg(memory_available)::bigint, max(swap_total), avg(swap_used)::bigint,
		       (array_agg(uptime_seconds order by at desc))[1],
		       (array_agg(filesystems order by at desc))[1],
		       (array_agg(interfaces order by at desc))[1],
		       count(*)
		from bucketed
		group by host_id, bucket
		on conflict (host_id, at) do update set
		    cpu_percent = excluded.cpu_percent, cpu_percent_max = excluded.cpu_percent_max,
		    load1 = excluded.load1, load5 = excluded.load5, load15 = excluded.load15,
		    memory_total = excluded.memory_total, memory_used = excluded.memory_used,
		    memory_used_max = excluded.memory_used_max,
		    memory_available = excluded.memory_available,
		    swap_total = excluded.swap_total, swap_used = excluded.swap_used,
		    uptime_seconds = excluded.uptime_seconds,
		    filesystems = excluded.filesystems, interfaces = excluded.interfaces,
		    samples = excluded.samples`,
		s.options.RawRetention.Seconds())
	return err
}

// sweep applies the retention: two days of raw samples, a month of
// rollups, and the silences that ran out a month ago.
func (s *Store) sweep(ctx context.Context) error {
	if _, err := s.pool.Exec(ctx,
		`delete from host_metrics where at < now() - make_interval(secs => $1)`,
		s.options.RawRetention.Seconds()); err != nil {
		return err
	}
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
	// The maxima of a rolled-up point; absent on a raw one.
	CPUPercentMax *float64 `json:"cpu_percent_max,omitempty"`
	MemoryUsedMax *uint64  `json:"memory_used_max,omitempty"`
}

// Series is the chart data of one host over a range.
type Series struct {
	Range        Range
	Points       []Point
	Latest       *Point
	LastSampleAt *time.Time
}

// Series reads the points of a host over a range: raw samples for the
// short windows, rollups for the long ones. The latest point is always the
// newest raw sample, whatever the range.
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

// Latest returns the newest raw sample of a host as a chart point, with
// the rates against the sample before it, and the moment it was taken. Nil
// for a host that never sent a sample.
func (s *Store) Latest(ctx context.Context, hostID string) (*Point, *time.Time, error) {
	newest, err := s.samples(ctx, hostID, 0, 2)
	if err != nil || len(newest) == 0 {
		return nil, nil, err
	}
	points := toPoints(newest)
	latest := points[len(points)-1]
	return &latest, &latest.At, nil
}

// samples reads the raw samples of a host within the window, oldest first.
// A window of zero means every sample; a limit above zero keeps the newest
// ones.
func (s *Store) samples(ctx context.Context, hostID string, window time.Duration, limit int) ([]Sample, error) {
	query := `
		select at, cpu_percent, load1, load5, load15, memory_total, memory_used,
		       memory_available, swap_total, swap_used, uptime_seconds,
		       filesystems, interfaces
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
		if err := rows.Scan(&sample.At, &cpu, &load1, &load5, &load15,
			&memoryTotal, &memoryUsed, &memoryAvailable, &swapTotal, &swapUsed, &uptime,
			&sample.Filesystems, &sample.Interfaces); err != nil {
			return nil, err
		}
		sample.CPUPercent, sample.Load1, sample.Load5, sample.Load15 =
			float64(cpu), float64(load1), float64(load5), float64(load15)
		sample.MemoryTotal, sample.MemoryUsed, sample.MemoryAvailable =
			uint64(memoryTotal), uint64(memoryUsed), uint64(memoryAvailable)
		sample.SwapTotal, sample.SwapUsed, sample.UptimeSeconds =
			uint64(swapTotal), uint64(swapUsed), uint64(uptime)
		list = append(list, sample)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	reverse(list)
	return list, nil
}

// rollups reads the quarter-hour rollups of a host within the window,
// oldest first.
func (s *Store) rollups(ctx context.Context, hostID string, window time.Duration) ([]Sample, error) {
	rows, err := s.pool.Query(ctx, `
		select at, cpu_percent, cpu_percent_max, load1, load5, load15, memory_total,
		       memory_used, memory_used_max, memory_available, swap_total, swap_used,
		       uptime_seconds, filesystems, interfaces
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
		if err := rows.Scan(&sample.At, &cpu, &cpuMax, &load1, &load5, &load15,
			&memoryTotal, &memoryUsed, &memoryUsedMax, &memoryAvailable, &swapTotal, &swapUsed,
			&uptime, &sample.Filesystems, &sample.Interfaces); err != nil {
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
		list = append(list, sample)
	}
	return list, rows.Err()
}

func reverse(list []Sample) {
	for i, j := 0, len(list)-1; i < j; i, j = i+1, j-1 {
		list[i], list[j] = list[j], list[i]
	}
}

// toPoints turns samples ordered oldest first into chart points, computing
// the network rates between consecutive samples.
//
// The first point has no previous counters and so no rates; its interface
// list is empty rather than a list of zeros, because an unknown rate is not
// a rate of zero. A counter that went backwards - a reboot, a reset of the
// interface - yields no rate for that step either.
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
			CPUPercentMax: sample.CPUPercentMax, MemoryUsedMax: sample.MemoryUsedMax,
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
// intervals and those that did not, among the hosts that are not retired
// and within the given SQL condition over the alias h.
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
