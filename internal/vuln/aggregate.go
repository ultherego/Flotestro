package vuln

import (
	"context"
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/google/uuid"

	"github.com/ultherego/flotestro/internal/authz"
	"github.com/ultherego/flotestro/internal/paging"
)

// The fleet screen, counted by the database.
//
// The screen used to read the first five hundred hosts, fetch their
// assessment states and add them up in the panel; on a bigger fleet the
// counters were plausible and wrong, and the table was sorted and cut in
// memory. The queries here count over every host in scope, tell the hosts
// without an assessment from the hosts with none, and hand the table out
// a page at a time by a key that holds still under the reader.

// The size of a page of the fleet table: what a screen gets without
// asking, and the most it may ask for.
const (
	DefaultPage = 100
	MaxPage     = 500
)

// The orders of the fleet table.
const (
	SortAffected = "affected"
	SortFixable  = "fixable"
	SortHostname = "hostname"
)

// FleetSummary is what the database counted over the visible fleet.
type FleetSummary struct {
	// Hosts is the number of hosts in scope; Evaluated those with an
	// assessment; Unassessed those without one - not hosts without
	// vulnerabilities; FullyAssessed those whose assessment is complete
	// in the sense of FullAssessment.
	Hosts         int
	Evaluated     int
	Unassessed    int
	FullyAssessed int
	// The sums over the assessed hosts.
	Affected              int
	AffectedWithVendorFix int
	AffectedNoFix         int
	Unknown               int
	AffectedPackages      int
	// HostsAffected counts the hosts with at least one affected finding.
	HostsAffected int
	// CoverageReasons counts the hosts by the reason their assessment is
	// incomplete; a host without an assessment stands under
	// ReasonPackageListMissing.
	CoverageReasons map[string]int
}

// FleetFilter narrows the fleet table. The summary is never narrowed:
// a filter changes what the table lists, not how bad the fleet is.
type FleetFilter struct {
	// Scopes narrow the fleet to what the caller may read; an empty list
	// sees nothing.
	Scopes []authz.Scope
	// Query is a fragment of the hostname, matched without regard to case.
	Query string
	// Severity keeps the hosts with an affected finding of this canonical
	// severity.
	Severity string
	// Sort is one of the Sort constants; empty is SortAffected.
	Sort string
}

// FleetCursor is the key of the last row of a page under one order: the
// order itself, the two counters the order reads, the host name and the
// identifier.
type FleetCursor struct {
	Sort      string
	Primary   int
	Secondary int
	Hostname  string
	HostID    string
	Set       bool
}

// ParseFleetCursor reads a cursor issued by FleetPage; an empty value is
// the first page.
func ParseFleetCursor(value string) (FleetCursor, error) {
	parts, err := paging.Decode(value, 5)
	if err != nil {
		return FleetCursor{}, err
	}
	if parts == nil {
		return FleetCursor{}, nil
	}
	switch parts[0] {
	case SortAffected, SortFixable, SortHostname:
	default:
		return FleetCursor{}, fmt.Errorf("%w: unknown order %q", paging.ErrInvalidCursor, parts[0])
	}
	primary, err := strconv.Atoi(parts[1])
	if err != nil {
		return FleetCursor{}, fmt.Errorf("%w: %v", paging.ErrInvalidCursor, err)
	}
	secondary, err := strconv.Atoi(parts[2])
	if err != nil {
		return FleetCursor{}, fmt.Errorf("%w: %v", paging.ErrInvalidCursor, err)
	}
	if _, err := uuid.Parse(parts[4]); err != nil {
		return FleetCursor{}, fmt.Errorf("%w: %v", paging.ErrInvalidCursor, err)
	}
	return FleetCursor{Sort: parts[0], Primary: primary, Secondary: secondary, Hostname: parts[3], HostID: parts[4], Set: true}, nil
}

// String renders the cursor for the next request.
func (c FleetCursor) String() string {
	return paging.Encode(c.Sort, strconv.Itoa(c.Primary), strconv.Itoa(c.Secondary), c.Hostname, c.HostID)
}

// FleetPage is one page of the fleet table.
type FleetPage struct {
	Items []HostState
	// Total is the number of hosts matching the filter across every page.
	Total int
	// NextCursor is empty on the last page.
	NextCursor string
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

// unassessedSQL is the condition of a host without an assessment: no
// state row, or one that was never evaluated.
const unassessedSQL = "(v.host_id is null or v.evaluated_at is null)"

// fullAssessmentSQL is FullAssessment in the database.
const fullAssessmentSQL = "(v.evaluated_at is not null and v.coverage_reason = '' and v.packages_total > 0" +
	" and v.packages_covered = v.packages_total and v.unknown = 0)"

// FleetSummary counts the assessment of the visible fleet.
func (s *Store) FleetSummary(ctx context.Context, scopes []authz.Scope) (FleetSummary, error) {
	condition, args := scopeCondition(scopes, 0)
	summary := FleetSummary{CoverageReasons: map[string]int{}}
	err := s.pool.QueryRow(ctx, `
		select count(*),
		       count(*) filter (where not `+unassessedSQL+`),
		       count(*) filter (where `+unassessedSQL+`),
		       count(*) filter (where `+fullAssessmentSQL+`),
		       coalesce(sum(v.affected), 0), coalesce(sum(v.affected_with_vendor_fix), 0),
		       coalesce(sum(v.affected_no_fix), 0), coalesce(sum(v.unknown), 0),
		       coalesce(sum(v.affected_packages), 0),
		       count(*) filter (where v.affected > 0)
		from hosts h
		left join vuln_host_state v on v.host_id = h.id
		where `+condition, args...).Scan(
		&summary.Hosts, &summary.Evaluated, &summary.Unassessed, &summary.FullyAssessed,
		&summary.Affected, &summary.AffectedWithVendorFix, &summary.AffectedNoFix, &summary.Unknown,
		&summary.AffectedPackages, &summary.HostsAffected)
	if err != nil {
		return summary, err
	}
	// A host without an assessment has the most common reason of all, and
	// the one most dangerous to pass over: nobody has read its packages.
	rows, err := s.pool.Query(ctx, `
		select case when `+unassessedSQL+` then '`+ReasonPackageListMissing+`'
		            else v.coverage_reason end as reason, count(*)
		from hosts h
		left join vuln_host_state v on v.host_id = h.id
		where `+condition+`
		group by reason`, args...)
	if err != nil {
		return summary, err
	}
	defer rows.Close()
	for rows.Next() {
		var reason string
		var count int
		if err := rows.Scan(&reason, &count); err != nil {
			return summary, err
		}
		if reason != "" {
			summary.CoverageReasons[reason] = count
		}
	}
	return summary, rows.Err()
}

// UniquesInScope counts the distinct CVEs and advisories among the
// affected findings of the hosts in scope.
func (s *Store) UniquesInScope(ctx context.Context, scopes []authz.Scope) (UniqueCounts, error) {
	condition, args := scopeCondition(scopes, 0)
	var result UniqueCounts
	err := s.pool.QueryRow(ctx, `
		select coalesce(count(distinct cve), 0), count(distinct f.advisory_id)
		from vuln_findings f
		join hosts h on h.id = f.host_id
		left join lateral unnest(f.cve_ids) as cve on true
		where f.state = 'affected' and `+condition, args...).Scan(&result.CVE, &result.Advisories)
	return result, err
}

// HostRepositorySourceInScope tallies the advisories the hosts in scope
// carry from their own repositories; nil when none of them has any.
func (s *Store) HostRepositorySourceInScope(ctx context.Context, scopes []authz.Scope) (*RepositorySource, error) {
	condition, args := scopeCondition(scopes, 0)
	var source RepositorySource
	var collected *time.Time
	err := s.pool.QueryRow(ctx, `
		select count(distinct a.advisory_id), count(distinct a.host_id), max(a.collected_at)
		from host_advisories a
		join hosts h on h.id = a.host_id
		where `+condition, args...).Scan(&source.Advisories, &source.Hosts, &collected)
	if err != nil {
		return nil, err
	}
	if source.Hosts == 0 || collected == nil {
		return nil, nil
	}
	source.CollectedAt = *collected
	return &source, nil
}

// fleetKeys are the two counters an order reads, as expressions over the
// joined row, both ascending: a count the order wants descending is
// negated. The host name and the identifier complete the key.
func fleetKeys(sort string) (primary, secondary string) {
	switch sort {
	case SortFixable:
		return "-coalesce(v.affected_with_vendor_fix, 0)", "-coalesce(v.affected, 0)"
	case SortHostname:
		return "0::int", "0::int"
	default:
		// The worst first, then the hosts that could not be assessed
		// before the clean ones: a zero with a reason is not a result.
		return "-coalesce(v.affected, 0)",
			"case when " + unassessedSQL + " or v.coverage_reason <> '' then 0 else 1 end"
	}
}

// fleetConditions renders the filter as conditions over the joined row.
func fleetConditions(filter FleetFilter) ([]string, []any) {
	condition, args := scopeCondition(filter.Scopes, 0)
	conditions := []string{condition}
	if query := strings.TrimSpace(filter.Query); query != "" {
		args = append(args, "%"+escapeLike(query)+"%")
		conditions = append(conditions, fmt.Sprintf("h.hostname ilike $%d escape '\\'", len(args)))
	}
	if filter.Severity != "" {
		args = append(args, SeverityRank(filter.Severity))
		conditions = append(conditions, fmt.Sprintf(`exists (select 1 from vuln_findings f
			where f.host_id = h.id and f.state = 'affected' and `+severityRankSQL("f.vendor_severity")+` = $%d)`, len(args)))
	}
	return conditions, args
}

// escapeLike keeps the wildcards of a pattern out of a search text.
func escapeLike(value string) string {
	replacer := strings.NewReplacer(`\`, `\\`, `%`, `\%`, `_`, `\_`)
	return replacer.Replace(value)
}

// hostStateColumns are the columns of a host row joined with its state;
// a host without a state row reads as empty counters and no evaluation.
const hostStateColumns = `h.id::text, h.hostname,
	coalesce(v.distribution, ''), coalesce(v.release, ''), coalesce(v.provider, ''),
	coalesce(v.snapshot_digest, ''), coalesce(v.inventory_digest, ''), coalesce(v.advisory_digest, ''),
	coalesce(v.packages_total, 0), coalesce(v.packages_covered, 0),
	coalesce(v.affected, 0), coalesce(v.affected_with_vendor_fix, 0), coalesce(v.affected_no_fix, 0),
	coalesce(v.unknown, 0), coalesce(v.affected_packages, 0), coalesce(v.unique_advisories, 0),
	coalesce(v.unique_cves, 0), coalesce(v.coverage_reason, ''), coalesce(v.advisories_reason, ''),
	v.evaluated_at, coalesce(v.generation_id::text, ''), v.generation_at`

// FleetPage reads one page of the fleet table under the filter's order.
// A cursor issued under another order is refused. offset skips rows
// before the page for a caller that pages the old way; a cursor is the
// way that holds still when the fleet moves.
func (s *Store) FleetPage(ctx context.Context, filter FleetFilter, cursor FleetCursor, limit, offset int) (FleetPage, error) {
	page := FleetPage{Items: []HostState{}}
	if filter.Sort == "" {
		filter.Sort = SortAffected
	}
	if cursor.Set && cursor.Sort != filter.Sort {
		return page, fmt.Errorf("%w: issued for the order %s, not %s", paging.ErrInvalidCursor, cursor.Sort, filter.Sort)
	}
	// A caller asking for more than a page may hold gets the page, not the
	// default: it then pages on with the cursor rather than quietly
	// receiving a fifth of what it asked for.
	limit = paging.Limit(limit, DefaultPage, MaxPage)
	conditions, args := fleetConditions(filter)
	from := ` from hosts h left join vuln_host_state v on v.host_id = h.id where `
	if err := s.pool.QueryRow(ctx, "select count(*)"+from+strings.Join(conditions, " and "), args...).
		Scan(&page.Total); err != nil {
		return page, err
	}

	primary, secondary := fleetKeys(filter.Sort)
	if cursor.Set {
		args = append(args, cursor.Primary, cursor.Secondary, cursor.Hostname, cursor.HostID)
		conditions = append(conditions, fmt.Sprintf("(%s, %s, h.hostname, h.id) > ($%d, $%d, $%d, $%d::uuid)",
			primary, secondary, len(args)-3, len(args)-2, len(args)-1, len(args)))
	}
	// One row more than the page says whether there is a next page
	// without a second count.
	args = append(args, limit+1)
	query := "select " + hostStateColumns + ", " + primary + ", " + secondary + from +
		strings.Join(conditions, " and ") +
		fmt.Sprintf(" order by %s, %s, h.hostname, h.id limit $%d", primary, secondary, len(args))
	if offset > 0 && !cursor.Set {
		args = append(args, offset)
		query += fmt.Sprintf(" offset $%d", len(args))
	}
	rows, err := s.pool.Query(ctx, query, args...)
	if err != nil {
		return page, err
	}
	defer rows.Close()
	var keys [][2]int
	for rows.Next() {
		var state HostState
		var key [2]int
		if err := rows.Scan(&state.HostID, &state.Hostname, &state.Distribution, &state.Release, &state.Provider,
			&state.SnapshotDigest, &state.InventoryDigest, &state.AdvisoryDigest,
			&state.PackagesTotal, &state.PackagesCovered, &state.Affected, &state.AffectedWithVendorFix,
			&state.AffectedNoFix, &state.Unknown, &state.AffectedPackages, &state.UniqueAdvisories,
			&state.UniqueCVEs, &state.CoverageReason, &state.AdvisoriesReason, &state.EvaluatedAt,
			&state.GenerationID, &state.GenerationAt, &key[0], &key[1]); err != nil {
			return page, err
		}
		if state.EvaluatedAt == nil {
			// A host not assessed yet is not a host without vulnerabilities.
			state.CoverageReason = ReasonPackageListMissing
		}
		page.Items = append(page.Items, state)
		keys = append(keys, key)
	}
	if err := rows.Err(); err != nil {
		return page, err
	}
	if len(page.Items) > limit {
		page.Items = page.Items[:limit]
		last := page.Items[limit-1]
		page.NextCursor = FleetCursor{
			Sort: filter.Sort, Primary: keys[limit-1][0], Secondary: keys[limit-1][1],
			Hostname: last.Hostname, HostID: last.HostID, Set: true,
		}.String()
	}
	return page, nil
}
