package backup

import (
	"context"
	"fmt"
	"strconv"
	"time"

	"github.com/google/uuid"

	"github.com/ultherego/flotestro/internal/authz"
	"github.com/ultherego/flotestro/internal/paging"
)

// The fleet screen, counted by the database.

// The size of a page of the fleet list: what a screen gets without
// asking, and the most it may ask for.
const (
	DefaultPage = 100
	MaxPage     = 500
)

// The kinds of run the fleet view reads.
const (
	kindPlan    = "plan"
	kindBackup  = "run"
	kindVerify  = "verify"
	kindRestore = "restore"
)

// FleetSummary is what the database counted over the visible fleet.
type FleetSummary struct {
	// Hosts is the number of hosts in scope; HostsWithDefinitions those with at
	// least one backup definition.
	Hosts                int
	HostsWithDefinitions int
	// Definitions is the number of rows the list has across every page.
	Definitions int
	// Counts is the number of definitions in every state of State.
	Counts map[string]int
	// Unverified counts the definitions nobody has verified within
	// VerificationThreshold; NeverRestored those nobody has ever restored.
	Unverified    int
	NeverRestored int
}

// FleetRow is one definition of the fleet list with the moments the
// assessment reads.
type FleetRow struct {
	HostID     string
	Hostname   string
	Definition string
	Tool       string
	Repository string
	// LastSuccessAt is the newest successful copy: what the last plan reported,
	// or the moment of the last successful run when no plan said.
	LastSuccessAt *time.Time
	VerifiedAt    *time.Time
	RestoredAt    *time.Time
}

// RepositoryLoad describes one backend seen from the whole fleet.
type RepositoryLoad struct {
	Repository string
	// Definitions counts the definitions writing to the backend.
	Definitions int
	Unverified  int
	// OldestAgeHours is the age of the oldest copy in this repository.
	OldestAgeHours *float64
}

// FleetCursor is the key of the last row of a page.
type FleetCursor struct {
	Now        time.Time
	Rank       int
	Last       string
	Hostname   string
	HostID     string
	Definition string
	Set        bool
}

// neverKey is the sort key of a copy that never ran: before every
// instant, as the database reads it.
const neverKey = "-infinity"

// ParseFleetCursor reads a cursor issued by FleetPage; an empty value is
// the first page.
func ParseFleetCursor(value string) (FleetCursor, error) {
	parts, err := paging.Decode(value, 6)
	if err != nil {
		return FleetCursor{}, err
	}
	if parts == nil {
		return FleetCursor{}, nil
	}
	now, err := paging.ParseTime(parts[0])
	if err != nil {
		return FleetCursor{}, err
	}
	rank, err := strconv.Atoi(parts[1])
	if err != nil {
		return FleetCursor{}, fmt.Errorf("%w: %v", paging.ErrInvalidCursor, err)
	}
	if parts[2] != neverKey {
		if _, err := paging.ParseTime(parts[2]); err != nil {
			return FleetCursor{}, err
		}
	}
	if _, err := uuid.Parse(parts[4]); err != nil {
		return FleetCursor{}, fmt.Errorf("%w: %v", paging.ErrInvalidCursor, err)
	}
	return FleetCursor{
		Now: now, Rank: rank, Last: parts[2], Hostname: parts[3], HostID: parts[4], Definition: parts[5], Set: true,
	}, nil
}

// String renders the cursor for the next request.
func (c FleetCursor) String() string {
	return paging.Encode(paging.FormatTime(c.Now), strconv.Itoa(c.Rank), c.Last, c.Hostname, c.HostID, c.Definition)
}

// scopeCondition renders the visibility of a host row; an empty scope
// list sees nothing.
func scopeCondition(scopes []authz.Scope, offset int) (string, []any) {
	condition, args := authz.ScopeSQL(scopes, "h.site", "h.environment", offset)
	if condition == "" {
		return "true", nil
	}
	return condition, args
}

// copiesSQL joins every definition of the hosts in scope with the newest
// successful run of each kind.
const copiesSQL = `
	with scoped as (
		select h.id, h.hostname from hosts h where %s
	),
	copies as (
		select d.host_id, s.hostname, d.name, d.tool, d.repository,
		       coalesce(p.last_success_at, b.recorded_at) as last_success_at,
		       v.recorded_at as verified_at,
		       r.recorded_at as restored_at
		from backup_definitions d
		join scoped s on s.id = d.host_id
		left join lateral (
			select last_success_at from backup_runs
			where host_id = d.host_id and definition = d.name and kind = '` + kindPlan + `' and outcome = 'succeeded'
			order by recorded_at desc limit 1) p on true
		left join lateral (
			select recorded_at from backup_runs
			where host_id = d.host_id and definition = d.name and kind = '` + kindBackup + `' and outcome = 'succeeded'
			order by recorded_at desc limit 1) b on true
		left join lateral (
			select recorded_at from backup_runs
			where host_id = d.host_id and definition = d.name and kind = '` + kindVerify + `' and outcome = 'succeeded'
			order by recorded_at desc limit 1) v on true
		left join lateral (
			select recorded_at from backup_runs
			where host_id = d.host_id and definition = d.name and kind = '` + kindRestore + `' and outcome = 'succeeded'
			order by recorded_at desc limit 1) r on true
	),
	judged as (
		select c.*,
		       case when c.last_success_at is null then ` + rankNever + `
		            when c.last_success_at <= $1 then ` + rankCritical + `
		            when c.last_success_at <= $2 then ` + rankWarning + `
		            else ` + rankOK + ` end as rank,
		       (c.verified_at is null or c.verified_at < $3) as unverified,
		       $4::timestamptz as judged_at
		from copies c
	)`

// The ranks of the states, the worst highest, as severity orders them.
// They are text because they are pasted into the query.
const (
	rankNever    = "4"
	rankCritical = "3"
	rankWarning  = "1"
	rankOK       = "0"
)

// thresholds are the instants the query judges by at the moment now.
func thresholds(now time.Time) []any {
	return []any{now.Add(-CriticalThreshold), now.Add(-WarningThreshold), now.Add(-VerificationThreshold), now}
}

// FleetSummary counts the definitions of the visible fleet at the
// moment now.
func (s *Store) FleetSummary(ctx context.Context, scopes []authz.Scope, now time.Time) (FleetSummary, error) {
	args := thresholds(now)
	condition, extra := scopeCondition(scopes, len(args))
	args = append(args, extra...)
	query := fmt.Sprintf(copiesSQL, condition) + `
		select
			(select count(*) from scoped),
			(select count(distinct host_id) from copies),
			count(*),
			count(*) filter (where rank = ` + rankNever + `),
			count(*) filter (where rank = ` + rankCritical + `),
			count(*) filter (where rank = ` + rankWarning + `),
			count(*) filter (where rank = ` + rankOK + `),
			count(*) filter (where unverified),
			count(*) filter (where restored_at is null)
		from judged`
	summary := FleetSummary{Counts: map[string]int{}}
	var never, critical, warning, ok int
	if err := s.pool.QueryRow(ctx, query, args...).Scan(
		&summary.Hosts, &summary.HostsWithDefinitions, &summary.Definitions,
		&never, &critical, &warning, &ok, &summary.Unverified, &summary.NeverRestored); err != nil {
		return summary, err
	}
	summary.Counts[StateNever] = never
	summary.Counts[StateCritical] = critical
	summary.Counts[StateWarning] = warning
	summary.Counts[StateOK] = ok
	return summary, nil
}

// FleetPage reads one page of the definitions of the visible fleet, the worst
// first.
func (s *Store) FleetPage(ctx context.Context, scopes []authz.Scope, cursor FleetCursor, limit int,
	now time.Time) ([]FleetRow, string, error) {
	// A caller asking for more than a page may hold gets the page, not the
	// default: it then pages on with the cursor rather than quietly receiving a
	// fifth of what it asked for.
	limit = paging.Limit(limit, DefaultPage, MaxPage)
	if cursor.Set {
		now = cursor.Now
	}
	args := thresholds(now)
	condition, extra := scopeCondition(scopes, len(args))
	args = append(args, extra...)
	query := fmt.Sprintf(copiesSQL, condition) + `
		select host_id::text, hostname, name, tool, repository, last_success_at, verified_at, restored_at, rank
		from judged`
	if cursor.Set {
		// Every column of the key ascends: the rank is negated so the worst state
		// comes first, and a copy that never ran carries the key before every
		// instant.
		args = append(args, -cursor.Rank, cursor.Last, cursor.Hostname, cursor.HostID, cursor.Definition)
		query += fmt.Sprintf(` where (-rank, coalesce(last_success_at, '-infinity'::timestamptz), hostname, host_id, name)
		       > ($%d, $%d::timestamptz, $%d, $%d::uuid, $%d)`,
			len(args)-4, len(args)-3, len(args)-2, len(args)-1, len(args))
	}
	args = append(args, limit+1)
	query += fmt.Sprintf(` order by -rank, coalesce(last_success_at, '-infinity'::timestamptz), hostname, host_id, name
		limit $%d`, len(args))

	rows, err := s.pool.Query(ctx, query, args...)
	if err != nil {
		return nil, "", err
	}
	defer rows.Close()
	result := []FleetRow{}
	ranks := []int{}
	for rows.Next() {
		var row FleetRow
		var rank int
		if err := rows.Scan(&row.HostID, &row.Hostname, &row.Definition, &row.Tool, &row.Repository,
			&row.LastSuccessAt, &row.VerifiedAt, &row.RestoredAt, &rank); err != nil {
			return nil, "", err
		}
		result = append(result, row)
		ranks = append(ranks, rank)
	}
	if err := rows.Err(); err != nil {
		return nil, "", err
	}
	if len(result) <= limit {
		return result, "", nil
	}
	// One row more than the page says there is a next page; the cursor names the
	// last row of the page, not the extra one, with the rank the query sorted it
	// by.
	last := result[limit-1]
	result = result[:limit]
	next := FleetCursor{
		Now: now, Rank: ranks[limit-1], Last: neverKey, Hostname: last.Hostname, HostID: last.HostID,
		Definition: last.Definition, Set: true,
	}
	if last.LastSuccessAt != nil {
		next.Last = paging.FormatTime(*last.LastSuccessAt)
	}
	return result, next.String(), nil
}

// RepositoryLoads groups the definitions of the visible fleet by backend,
// the backend with the oldest copy first.
func (s *Store) RepositoryLoads(ctx context.Context, scopes []authz.Scope, now time.Time) ([]RepositoryLoad, error) {
	args := thresholds(now)
	condition, extra := scopeCondition(scopes, len(args))
	args = append(args, extra...)
	query := fmt.Sprintf(copiesSQL, condition) + `
		select repository, count(*), count(*) filter (where unverified),
		       max(extract(epoch from ($4 - last_success_at)) / 3600.0)
		from judged
		where repository <> ''
		group by repository
		order by max(extract(epoch from ($4 - last_success_at)) / 3600.0) desc nulls last, repository`
	rows, err := s.pool.Query(ctx, query, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	result := []RepositoryLoad{}
	for rows.Next() {
		var load RepositoryLoad
		if err := rows.Scan(&load.Repository, &load.Definitions, &load.Unverified, &load.OldestAgeHours); err != nil {
			return nil, err
		}
		result = append(result, load)
	}
	return result, rows.Err()
}
