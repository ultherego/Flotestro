package monitoring

// The daily partitions of the raw samples: creating the ones the coming
// days will need, and dropping the ones the retention has passed.
//
// A partition is dropped, never emptied. The sweep this replaces deleted a
// day of a fleet's samples row by row - fourteen million of them on ten
// thousand hosts - which writes as much WAL as the insert did, leaves the
// space to the vacuum and holds the oldest transaction in the database
// while it runs. Dropping the partition is a catalogue write and the
// removal of its files.

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"
)

const (
	// rawPartitionParent is the partitioned table, and rawPartitionPrefix
	// with rawPartitionLayout is how one of its partitions is named: the
	// day its range begins, in UTC. The name is not decoration - the
	// retention reads the day out of it to know where the range ends,
	// which keeps this code out of the business of parsing partition
	// bounds out of the catalogue.
	rawPartitionParent = "host_metrics"
	rawPartitionPrefix = "host_metrics_p"
	rawPartitionLayout = "20060102"
	// partitionWidth is the width of one partition.
	partitionWidth = 24 * time.Hour
)

// EnsurePartitions creates the partitions of the raw samples that the days
// ahead will need.
//
// It only ever creates days after the newest partition there is. A day
// older than every partition cannot need one: the migration left the table
// it converted as the partition that holds everything up to its cutover,
// so there is no gap below, and a sample too old for the retention is
// refused by the gateway before it is ever written. Creating a day that
// another partition already covers would be an overlap, which is an error
// and not a no-op.
//
// A panel that was down for a week creates the days it missed on its first
// pass, which is right: they are empty, and the next sample lands in the
// day it belongs to rather than in whatever was left open.
func (s *Store) EnsurePartitions(ctx context.Context, now time.Time) error {
	partitioned, err := s.rawIsPartitioned(ctx)
	if err != nil || !partitioned {
		return err
	}
	days, err := s.partitionDays(ctx)
	if err != nil {
		return err
	}
	today := now.UTC().Truncate(partitionWidth)
	from := today
	if len(days) > 0 {
		if newest := days[len(days)-1]; !newest.Before(from) {
			from = newest.Add(partitionWidth)
		}
	}
	upto := today.Add(time.Duration(s.options.PartitionsAhead) * partitionWidth)
	for at := from; !at.After(upto); at = at.Add(partitionWidth) {
		if err := s.createPartition(ctx, at); err != nil {
			return err
		}
	}
	return nil
}

// createPartition adds the partition of one day. The bounds are written
// into the statement rather than bound as parameters, because a partition
// bound is part of the definition of a table and not a value a statement
// takes; they are formatted from a moment this code computed, so nothing
// of a host's making reaches the text.
func (s *Store) createPartition(ctx context.Context, at time.Time) error {
	name := partitionName(at)
	statement := fmt.Sprintf(
		`create table if not exists %s partition of %s for values from ('%s') to ('%s')`,
		pgx.Identifier{name}.Sanitize(), pgx.Identifier{rawPartitionParent}.Sanitize(),
		at.UTC().Format(time.RFC3339), at.Add(partitionWidth).UTC().Format(time.RFC3339))
	if _, err := s.pool.Exec(ctx, statement); err != nil {
		return fmt.Errorf("creating the partition %s of the raw samples: %w", name, err)
	}
	return nil
}

// DropExpiredPartitions removes the partitions whose whole range is past
// the raw retention.
//
// A partition that still owes a rollup is kept. The queue of dirty buckets
// is the only record that a quarter has to be recomputed, and the raw
// samples are the only place the numbers to recompute it from exist: a
// partition dropped while a bucket of its days is queued would leave the
// queue pointing at readings nobody can read, and the long chart would
// keep a hole that no later pass can fill. The wait is bounded - the
// rollup drains the queue every quarter of an hour - and one more day of
// samples is a cheaper mistake than a rollup that is quietly wrong.
func (s *Store) DropExpiredPartitions(ctx context.Context, now time.Time) error {
	partitioned, err := s.rawIsPartitioned(ctx)
	if err != nil || !partitioned {
		return err
	}
	days, err := s.partitionDays(ctx)
	if err != nil {
		return err
	}
	cutoff := now.UTC().Add(-s.options.RawRetention)
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
			"partition", name, "retention", s.options.RawRetention.String())
	}
	return nil
}

// rawIsPartitioned says whether the raw samples live in a partitioned
// table. A database whose migration has not run yet keeps the plain table,
// and the maintenance has nothing to do on it.
func (s *Store) rawIsPartitioned(ctx context.Context) (bool, error) {
	var partitioned bool
	err := s.pool.QueryRow(ctx, `
		select exists (
		    select 1 from pg_partitioned_table
		     where partrelid = to_regclass($1)
		)`, rawPartitionParent).Scan(&partitioned)
	return partitioned, err
}

// partitionDays reads the days the existing partitions are named after,
// oldest first. A child whose name does not follow the convention is left
// alone: this code created none such and will not drop one.
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

// MaintenanceState is what the status screen says about the machinery
// behind the samples: how much raw history is on disk, how much of it is
// waiting to be rolled up, and who is judging the rules.
type MaintenanceState struct {
	Partitioned  bool       `json:"raw_partitioned"`
	Partitions   int        `json:"raw_partitions"`
	OldestRawDay *time.Time `json:"oldest_raw_day,omitempty"`
	NewestRawDay *time.Time `json:"newest_raw_day,omitempty"`
	// DirtyBuckets is the backlog of the rollup: quarters whose readings
	// changed and which have not been recomputed. A number that does not
	// come back down is a rollup that has stopped.
	DirtyBuckets  int64      `json:"dirty_buckets"`
	OldestDirtyAt *time.Time `json:"oldest_dirty_bucket_at,omitempty"`
	// HostsWatermarked counts the hosts the rollup has a mark for.
	HostsWatermarked int64 `json:"hosts_with_rollup_mark"`
	// SampleIdentities is the estimated size of the table the duplicates
	// are recognised by; an estimate because counting it exactly is a scan
	// nobody should pay for on a status page.
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
}

// MaintenanceState reads that state in one round of short queries.
func (s *Store) MaintenanceState(ctx context.Context) (MaintenanceState, error) {
	state := MaintenanceState{
		RawRetention:    s.options.RawRetention.String(),
		RollupRetention: s.options.RollupRetention.String(),
		MaxLateness:     s.options.MaxLateness.String(),
		RawQueryWindow:  s.options.RawQueryWindow.String(),
		ClockSkewLimit:  s.options.ClockSkewLimit.String(),
		PartitionsAhead: s.options.PartitionsAhead,
	}
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
	// The planner's own estimate: a count over a table of a fleet's
	// identities is a sequential scan, and a status page that answers in
	// five seconds is worth more here than an exact number.
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
