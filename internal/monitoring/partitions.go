package monitoring

// The daily partitions of the raw samples: creating the ones the coming days
// will need, and dropping the ones the retention has passed.

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
)

// errPartitionCovered means the day already lies inside a partition that exists.
// The first partition of the table has no lower bound - it is the one the
// partitioning migration left holding everything that came before it - so a day
// behind today can be served by a partition named after a later one.
var errPartitionCovered = errors.New("the day is already inside a partition")

const (
	// rawPartitionParent is the partitioned table, and rawPartitionPrefix with
	// rawPartitionLayout is how one of its partitions is named: the day its range
	// begins, in UTC.
	rawPartitionParent = "host_metrics"
	rawPartitionPrefix = "host_metrics_p"
	rawPartitionLayout = "20060102"
	// partitionWidth is the width of one partition.
	partitionWidth = 24 * time.Hour
)

// EnsurePartitions creates the partitions of the raw samples that the days
// ahead will need.
func (s *Store) EnsurePartitions(ctx context.Context, now time.Time) error {
	// The margin is read once here, so this pass works to one number even if
	// the installation stores another while it runs.
	options := s.current()
	partitioned, err := s.rawIsPartitioned(ctx)
	if err != nil || !partitioned {
		return err
	}
	days, err := s.partitionDays(ctx)
	if err != nil {
		return err
	}
	today := now.UTC().Truncate(partitionWidth)
	// The window starts as far back as a sample may still arrive from: a panel
	// that was down longer than its margin comes back with days missing behind
	// it, and a spooled reading for one of them has nowhere to land.
	from := today.Add(-options.MaxLateness).UTC().Truncate(partitionWidth)
	have := make(map[time.Time]bool, len(days))
	for _, day := range days {
		have[day.UTC().Truncate(partitionWidth)] = true
	}
	upto := today.Add(time.Duration(options.PartitionsAhead) * partitionWidth)
	for at := from; !at.After(upto); at = at.Add(partitionWidth) {
		if have[at] {
			continue
		}
		// A day the names do not account for may still be covered, and that is
		// not a reason to abandon the pass: the days ahead are the ones the
		// readings arriving now will need.
		switch err := s.createPartition(ctx, at); {
		case errors.Is(err, errPartitionCovered):
			continue
		case err != nil:
			return err
		}
	}
	return nil
}

// createPartition adds the partition of one day.
func (s *Store) createPartition(ctx context.Context, at time.Time) error {
	name := partitionName(at)
	statement := fmt.Sprintf(
		`create table if not exists %s partition of %s for values from ('%s') to ('%s')`,
		pgx.Identifier{name}.Sanitize(), pgx.Identifier{rawPartitionParent}.Sanitize(),
		at.UTC().Format(time.RFC3339), at.Add(partitionWidth).UTC().Format(time.RFC3339))
	if _, err := s.pool.Exec(ctx, statement); err != nil {
		// 42P17 is the overlap: the range asked for lies inside one that exists.
		// "if not exists" guards the name and says nothing about the range.
		var pgErr *pgconn.PgError
		if errors.As(err, &pgErr) && pgErr.Code == "42P17" {
			return fmt.Errorf("%w: %s", errPartitionCovered, name)
		}
		return fmt.Errorf("creating the partition %s of the raw samples: %w", name, err)
	}
	return nil
}

// DropExpiredPartitions removes the partitions whose whole range is past the
// raw retention.
func (s *Store) DropExpiredPartitions(ctx context.Context, now time.Time) error {
	// The retention in force at the start of this pass; a value stored while
	// it runs drops its partitions in the next pass, not halfway through this.
	retention := s.current().RawRetention
	partitioned, err := s.rawIsPartitioned(ctx)
	if err != nil || !partitioned {
		return err
	}
	days, err := s.partitionDays(ctx)
	if err != nil {
		return err
	}
	cutoff := now.UTC().Add(-retention)
	for _, at := range days {
		ends := at.Add(partitionWidth)
		if ends.After(cutoff) {
			continue
		}
		var owing bool
		if err := s.pool.QueryRow(ctx,
			`select exists (select 1 from metric_rollup_dirty where bucket_at < $1)`,
			ends).Scan(&owing); err != nil {
			return err
		}
		if owing {
			s.log.Info("a partition of the raw samples is past the retention but still owes a rollup; it is kept",
				"partition", partitionName(at), "ends", ends.Format(time.RFC3339))
			continue
		}
		name := partitionName(at)
		if _, err := s.pool.Exec(ctx,
			`drop table if exists `+pgx.Identifier{name}.Sanitize()); err != nil {
			return fmt.Errorf("dropping the partition %s of the raw samples: %w", name, err)
		}
		s.log.Info("a partition of the raw samples was dropped by the retention",
			"partition", name, "retention", retention.String())
	}
	return nil
}

// rawIsPartitioned says whether the raw samples live in a partitioned table.
func (s *Store) rawIsPartitioned(ctx context.Context) (bool, error) {
	var partitioned bool
	err := s.pool.QueryRow(ctx, `
		select exists (
		    select 1 from pg_partitioned_table
		     where partrelid = to_regclass($1)
		)`, rawPartitionParent).Scan(&partitioned)
	return partitioned, err
}

// partitionDays reads the days the existing partitions are named after, oldest
// first.
func (s *Store) partitionDays(ctx context.Context) ([]time.Time, error) {
	rows, err := s.pool.Query(ctx, `
		select c.relname
		  from pg_inherits i
		  join pg_class c on c.oid = i.inhrelid
		 where i.inhparent = to_regclass($1)
		 order by c.relname`, rawPartitionParent)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var days []time.Time
	for rows.Next() {
		var name string
		if err := rows.Scan(&name); err != nil {
			return nil, err
		}
		at, ok := partitionDay(name)
		if !ok {
			continue
		}
		days = append(days, at)
	}
	return days, rows.Err()
}

// partitionName is the name of the partition holding one day.
func partitionName(at time.Time) string {
	return rawPartitionPrefix + at.UTC().Format(rawPartitionLayout)
}

// partitionDay reads the day back out of the name.
func partitionDay(name string) (time.Time, bool) {
	rest, found := strings.CutPrefix(name, rawPartitionPrefix)
	if !found {
		return time.Time{}, false
	}
	at, err := time.ParseInLocation(rawPartitionLayout, rest, time.UTC)
	if err != nil {
		return time.Time{}, false
	}
	return at, true
}

// MaintenanceState is what the status screen says about the machinery behind
// the samples: how much raw history is on disk, how much of it is waiting to
// be rolled up, and who is judging the rules.
type MaintenanceState struct {
	Partitioned  bool       `json:"raw_partitioned"`
	Partitions   int        `json:"raw_partitions"`
	OldestRawDay *time.Time `json:"oldest_raw_day,omitempty"`
	NewestRawDay *time.Time `json:"newest_raw_day,omitempty"`
	// DirtyBuckets is the backlog of the rollup: quarters whose readings changed
	// and which have not been recomputed.
	DirtyBuckets  int64      `json:"dirty_buckets"`
	OldestDirtyAt *time.Time `json:"oldest_dirty_bucket_at,omitempty"`
	// HostsWatermarked counts the hosts the rollup has a mark for.
	HostsWatermarked int64 `json:"hosts_with_rollup_mark"`
	// SampleIdentities is the estimated size of the table the duplicates are
	// recognised by; an estimate because counting it exactly is a scan nobody
	// should pay for on a status page.
	SampleIdentities int64 `json:"sample_identities_estimate"`
	// The lease of the alert evaluator, as the database holds it.
	EvaluatorHolder string     `json:"evaluator_holder,omitempty"`
	EvaluatorUntil  *time.Time `json:"evaluator_lease_until,omitempty"`
	// The settings the figures above have to be read against.
	RawRetention    string `json:"raw_retention"`
	RollupRetention string `json:"rollup_retention"`
	MaxLateness     string `json:"max_lateness"`
	RawQueryWindow  string `json:"raw_query_window"`
	ClockSkewLimit  string `json:"clock_skew_limit"`
	PartitionsAhead int    `json:"partitions_ahead_days"`
	// Where those settings come from: an installation that stored its own, and
	// who stored them, rather than the environment of this process.
	SettingsStored    bool       `json:"settings_stored"`
	SettingsUpdatedAt *time.Time `json:"settings_updated_at,omitempty"`
	SettingsUpdatedBy string     `json:"settings_updated_by,omitempty"`
}

// MaintenanceState reads that state in one round of short queries.
func (s *Store) MaintenanceState(ctx context.Context) (MaintenanceState, error) {
	options := s.current()
	state := MaintenanceState{
		RawRetention:    options.RawRetention.String(),
		RollupRetention: options.RollupRetention.String(),
		MaxLateness:     options.MaxLateness.String(),
		RawQueryWindow:  options.RawQueryWindow.String(),
		ClockSkewLimit:  options.ClockSkewLimit.String(),
		PartitionsAhead: options.PartitionsAhead,
	}
	stored, err := s.StoredSettings(ctx)
	if err != nil {
		return state, err
	}
	state.SettingsStored = stored.Present
	state.SettingsUpdatedAt, state.SettingsUpdatedBy = stored.UpdatedAt, stored.UpdatedBy
	partitioned, err := s.rawIsPartitioned(ctx)
	if err != nil {
		return state, err
	}
	state.Partitioned = partitioned
	if partitioned {
		days, err := s.partitionDays(ctx)
		if err != nil {
			return state, err
		}
		state.Partitions = len(days)
		if len(days) > 0 {
			oldest, newest := days[0], days[len(days)-1]
			state.OldestRawDay, state.NewestRawDay = &oldest, &newest
		}
	}
	if err := s.pool.QueryRow(ctx, `
		select count(*), min(bucket_at) from metric_rollup_dirty`).
		Scan(&state.DirtyBuckets, &state.OldestDirtyAt); err != nil {
		return state, err
	}
	if err := s.pool.QueryRow(ctx,
		`select count(*) from metric_rollup_watermarks`).Scan(&state.HostsWatermarked); err != nil {
		return state, err
	}
	// The planner's own estimate: a count over a table of a fleet's identities is
	// a sequential scan, and a status page that answers in five seconds is worth
	// more here than an exact number.
	if err := s.pool.QueryRow(ctx, `
		select greatest(coalesce(reltuples, 0), 0)::bigint
		  from pg_class where oid = to_regclass('metric_samples')`).
		Scan(&state.SampleIdentities); err != nil {
		return state, err
	}
	lease, err := s.EvaluatorLease(ctx)
	if err != nil {
		return state, err
	}
	state.EvaluatorHolder = lease.Holder
	if !lease.Until.IsZero() {
		until := lease.Until
		state.EvaluatorUntil = &until
	}
	return state, nil
}
