package vuln

import (
	"context"
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/ultherego/flotestro/internal/authz"
	"github.com/ultherego/flotestro/internal/paging"
)

// The CVE-centric reading of the findings.

// The canonical severities the panel groups by.
const (
	SeverityCritical   = "critical"
	SeverityHigh       = "high"
	SeverityMedium     = "medium"
	SeverityLow        = "low"
	SeverityNegligible = "negligible"
	SeverityUnrated    = "unrated"
)

// severityLadder lists the canonical severities from the worst down; the
// index is the rank the SQL computes.
var severityLadder = []string{
	SeverityCritical, SeverityHigh, SeverityMedium, SeverityLow, SeverityNegligible, SeverityUnrated,
}

// severityRankSQL renders the rank of a vendor severity for the aliased
// finding.
func severityRankSQL(column string) string {
	return "case lower(" + column + ")" +
		" when 'critical' then 0" +
		" when 'high' then 1 when 'important' then 1" +
		" when 'medium' then 2 when 'moderate' then 2" +
		" when 'low' then 3" +
		" when 'negligible' then 4 when 'unimportant' then 4" +
		" else 5 end"
}

// SeverityName translates a rank back into the canonical word.
func SeverityName(rank int) string {
	if rank < 0 || rank >= len(severityLadder) {
		return SeverityUnrated
	}
	return severityLadder[rank]
}

// SeverityRank translates a canonical word into its rank; -1 means no such
// severity, so a filter with a typo matches nothing rather than everything.
func SeverityRank(name string) int {
	for rank, candidate := range severityLadder {
		if candidate == strings.ToLower(strings.TrimSpace(name)) {
			return rank
		}
	}
	return -1
}

// CVEFilter narrows the CVE list.
type CVEFilter struct {
	// Scopes narrow the result to the hosts the caller may read.
	Scopes []authz.Scope
	// Query is a prefix of a CVE number or of a package name.
	Query string
	// Severity is a canonical word; empty means every severity.
	Severity string
	// Fixable keeps only the CVEs with a vendor fix on at least one host.
	Fixable bool
	Limit   int
	Offset  int
	// Cursor is the key of the last row of the previous page; when it is
	// set, Offset is ignored, because the two are two ways of asking for
	// the same next page and only one of them survives a changing list.
	Cursor CVECursor
}

// CVECursor is the key of the last row of a page under the order of the CVE
// list: the rung of the severity, the number of affected hosts and the CVE
// itself, which the three together make unique.
type CVECursor struct {
	Rank  int
	Hosts int
	CVE   string
	Set   bool
}

// ParseCVECursor reads a cursor issued by CVEs; an empty value is the first
// page.
func ParseCVECursor(value string) (CVECursor, error) {
	parts, err := paging.Decode(value, 3)
	if err != nil {
		return CVECursor{}, err
	}
	if parts == nil {
		return CVECursor{}, nil
	}
	rank, err := strconv.Atoi(parts[0])
	if err != nil {
		return CVECursor{}, fmt.Errorf("%w: %v", paging.ErrInvalidCursor, err)
	}
	hosts, err := strconv.Atoi(parts[1])
	if err != nil {
		return CVECursor{}, fmt.Errorf("%w: %v", paging.ErrInvalidCursor, err)
	}
	if parts[2] == "" {
		return CVECursor{}, fmt.Errorf("%w: the key names no CVE", paging.ErrInvalidCursor)
	}
	return CVECursor{Rank: rank, Hosts: hosts, CVE: parts[2], Set: true}, nil
}

// String renders the cursor for the next request.
func (c CVECursor) String() string {
	return paging.Encode(strconv.Itoa(c.Rank), strconv.Itoa(c.Hosts), c.CVE)
}

// CVESummary is one row of the CVE list.
type CVESummary struct {
	CVE string `json:"cve"`
	// Severity is the canonical rung of the worst vendor rating among the
	// affected hosts, and VendorSeverity the vendor's own word for it.
	Severity       string `json:"severity"`
	VendorSeverity string `json:"vendor_severity,omitempty"`
	// The CVSS score is enrichment from the upstream database and may be
	// missing; it never decides anything.
	CVSSScore    *float64 `json:"cvss_score,omitempty"`
	CVSSSeverity string   `json:"cvss_severity,omitempty"`
	// Hosts counts the affected hosts and HostsWithVendorFix those of them whose
	// vendor has released a fix.
	Hosts              int      `json:"hosts"`
	HostsWithVendorFix int      `json:"hosts_with_vendor_fix"`
	Packages           []string `json:"packages"`
	// FirstSeen is the oldest assessment among the hosts that carry the finding
	// now.
	FirstSeen time.Time `json:"first_seen"`
}

// CVEPage is one page of the CVE list together with the size of the whole.
type CVEPage struct {
	Items []CVESummary
	Total int
	// NextCursor is empty on the last page.
	NextCursor string
}

// escapePattern neutralises the pattern characters of a search. An
// operator looking for "libssl_1" means an underscore, not any character.
func escapePattern(value string) string {
	return strings.NewReplacer(`\`, `\\`, `%`, `\%`, `_`, `\_`).Replace(value)
}

// CVEs lists the distinct CVEs among the affected findings of the hosts in
// scope, the gravest and the most widespread first.
func (s *Store) CVEs(ctx context.Context, filter CVEFilter) (CVEPage, error) {
	page := CVEPage{Items: []CVESummary{}}
	// A page of no rows is a question nobody asks: a caller that names no
	// size is given one rather than an empty answer.
	if filter.Limit <= 0 {
		filter.Limit = DefaultPage
	}
	var args []any
	scope := ""
	if filter.Scopes != nil {
		condition, extra := authz.ScopeSQL(filter.Scopes, authz.HostColumns("h"), 0)
		if condition != "" {
			scope = " and " + condition
			args = append(args, extra...)
		}
	}
	pattern := ""
	if query := strings.TrimSpace(filter.Query); query != "" {
		pattern = escapePattern(query) + "%"
	}
	rank := -1
	if filter.Severity != "" {
		rank = SeverityRank(filter.Severity)
	}
	args = append(args, pattern, rank, filter.Fixable)
	base := len(args) - 3
	// The key of the page walks the order itself - the rung, the number of
	// hosts descending, the CVE - so a row that appears or goes away between
	// two pages cannot make the list skip another.
	keyset := ""
	if filter.Cursor.Set {
		args = append(args, filter.Cursor.Rank, -filter.Cursor.Hosts, filter.Cursor.CVE)
		keyset = fmt.Sprintf(" where (r.rank, -r.hosts, r.cve) > ($%d::int, $%d::int, $%d::text)",
			len(args)-2, len(args)-1, len(args))
	}
	// One row more than the page says whether there is a next one.
	args = append(args, filter.Limit+1)
	tail := fmt.Sprintf(" limit $%d", len(args))
	// The offset is the older way of asking for the next page; a cursor
	// says the same thing better, so it wins where both are given.
	if filter.Offset > 0 && !filter.Cursor.Set {
		args = append(args, filter.Offset)
		tail += fmt.Sprintf(" offset $%d", len(args))
	}
	query := fmt.Sprintf(`
		with affected as (
		    select f.host_id, cve.id as cve, f.vendor_severity, f.vendor_fix, f.evaluated_at,
		           coalesce(nullif(f.binary_package, ''), f.source_package) as package,
		           f.source_package, `+severityRankSQL("f.vendor_severity")+` as rank
		    from vuln_findings f
		    join hosts h on h.id = f.host_id
		    cross join lateral unnest(f.cve_ids) as cve(id)
		    where f.state = 'affected' and cve.id <> ''%[1]s
		),
		grouped as (
		    select cve, min(rank) as rank,
		           (array_agg(vendor_severity order by rank))[1] as vendor_severity,
		           count(distinct host_id) as hosts,
		           count(distinct host_id) filter (where vendor_fix = 'known') as hosts_with_fix,
		           array_agg(distinct package) as packages,
		           min(evaluated_at) as first_seen,
		           bool_or(package ilike $%[2]d::text or source_package ilike $%[2]d::text) as package_match
		    from affected
		    group by cve
		),
		matching as (
		    select g.cve, g.rank, g.vendor_severity, d.cvss_score, coalesce(d.cvss_severity, '') as cvss_severity,
		           g.hosts, g.hosts_with_fix, g.packages, g.first_seen, count(*) over () as total
		    from grouped g
		    left join vuln_cve_details d on d.cve = g.cve
		    where ($%[2]d::text = '' or g.cve ilike $%[2]d::text or g.package_match)
		      and ($%[3]d::int < 0 or g.rank = $%[3]d::int)
		      and (not $%[4]d::boolean or g.hosts_with_fix > 0)
		)
		select r.cve, r.rank, r.vendor_severity, r.cvss_score, r.cvss_severity,
		       r.hosts, r.hosts_with_fix, r.packages, r.first_seen, r.total
		from matching r%[5]s
		order by r.rank, r.hosts desc, r.cve%[6]s`,
		scope, base+1, base+2, base+3, keyset, tail)
	rows, err := s.pool.Query(ctx, query, args...)
	if err != nil {
		return page, err
	}
	defer rows.Close()
	var ranks []int
	for rows.Next() {
		var item CVESummary
		var rank int
		var severity string
		if err := rows.Scan(&item.CVE, &rank, &item.VendorSeverity, &item.CVSSScore,
			&severity, &item.Hosts, &item.HostsWithVendorFix, &item.Packages,
			&item.FirstSeen, &page.Total); err != nil {
			return page, err
		}
		item.Severity = SeverityName(rank)
		item.CVSSSeverity = strings.ToLower(severity)
		if item.Packages == nil {
			item.Packages = []string{}
		}
		page.Items = append(page.Items, item)
		ranks = append(ranks, rank)
	}
	if err := rows.Err(); err != nil {
		return page, err
	}
	if len(page.Items) > filter.Limit {
		page.Items = page.Items[:filter.Limit]
		last := page.Items[filter.Limit-1]
		page.NextCursor = CVECursor{
			Rank: ranks[filter.Limit-1], Hosts: last.Hosts, CVE: last.CVE, Set: true,
		}.String()
	}
	return page, nil
}

// CVEHost is one finding of one CVE on one host, as the CVE page lists it.
type CVEHost struct {
	HostID      string `json:"host_id"`
	Hostname    string `json:"hostname"`
	Site        string `json:"site,omitempty"`
	Environment string `json:"environment,omitempty"`
	Provider    string `json:"provider"`
	AdvisoryID  string `json:"advisory_id"`
	// Package is the name the operator sees on the host: the binary
	// package, or the source one where the vendor names no binary.
	Package          string          `json:"package"`
	SourcePackage    string          `json:"source_package,omitempty"`
	Architecture     string          `json:"architecture,omitempty"`
	InstalledVersion string          `json:"installed_version,omitempty"`
	FixedVersion     string          `json:"fixed_version,omitempty"`
	State            AssessmentState `json:"state"`
	ReasonCode       string          `json:"reason_code,omitempty"`
	VendorFix        VendorFixState  `json:"vendor_fix"`
	// RepositoryCandidate says whether the fixed version is visible in the
	// repositories of the host; only the package plan says whether it installs.
	RepositoryCandidate RepositoryCandidateState `json:"repository_candidate"`
	VendorSeverity      string                   `json:"vendor_severity,omitempty"`
	Severity            string                   `json:"severity"`
	EvaluatedAt         time.Time                `json:"evaluated_at"`
}

// CVEHostsLimit caps the rows of one CVE page.
const CVEHostsLimit = 1000

// CVEHosts lists the findings of one CVE on the hosts in scope: the affected
// ones and the ones the panel could not decide.
func (s *Store) CVEHosts(ctx context.Context, cve string, scopes []authz.Scope) ([]CVEHost, int, error) {
	args := []any{cve, CVEHostsLimit}
	scope := ""
	if scopes != nil {
		condition, extra := authz.ScopeSQL(scopes, authz.HostColumns("h"), len(args))
		if condition != "" {
			scope = " and " + condition
			args = append(args, extra...)
		}
	}
	query := `
		select f.host_id::text, h.hostname, h.site, h.environment, f.provider, f.advisory_id,
		       coalesce(nullif(f.binary_package, ''), f.source_package), f.source_package,
		       f.architecture, f.installed_version, f.fixed_version, f.state, f.reason_code,
		       f.vendor_fix, f.repository_candidate, f.vendor_severity,
		       ` + severityRankSQL("f.vendor_severity") + ` as rank, f.evaluated_at,
		       count(*) over ()
		from vuln_findings f
		join hosts h on h.id = f.host_id
		where $1 = any(f.cve_ids) and f.state in ('affected', 'unknown')` + scope + `
		order by case f.state when 'affected' then 0 else 1 end, rank, h.hostname, f.binary_package,
		         f.installed_version
		limit $2`
	rows, err := s.pool.Query(ctx, query, args...)
	if err != nil {
		return nil, 0, err
	}
	defer rows.Close()
	result := []CVEHost{}
	total := 0
	for rows.Next() {
		var item CVEHost
		var state, fix, candidate string
		var rank int
		if err := rows.Scan(&item.HostID, &item.Hostname, &item.Site, &item.Environment,
			&item.Provider, &item.AdvisoryID, &item.Package, &item.SourcePackage,
			&item.Architecture, &item.InstalledVersion, &item.FixedVersion, &state,
			&item.ReasonCode, &fix, &candidate, &item.VendorSeverity, &rank,
			&item.EvaluatedAt, &total); err != nil {
			return nil, 0, err
		}
		item.State = AssessmentState(state)
		item.VendorFix = VendorFixState(fix)
		item.RepositoryCandidate = RepositoryCandidateState(candidate)
		item.Severity = SeverityName(rank)
		result = append(result, item)
	}
	return result, total, rows.Err()
}

// CVEReference is what a vendor published about the CVE: the advisory, its
// title and where it is described.
type CVEReference struct {
	Provider    string     `json:"provider"`
	AdvisoryID  string     `json:"advisory_id"`
	Title       string     `json:"title,omitempty"`
	URL         string     `json:"url,omitempty"`
	Status      string     `json:"status,omitempty"`
	Release     string     `json:"release,omitempty"`
	PublishedAt *time.Time `json:"published_at,omitempty"`
}

// cveReferencesLimit caps the references of one CVE per source; a CVE in a
// kernel appears in one advisory per release, not in hundreds.
const cveReferencesLimit = 50

// CVEReferences gathers the vendor advisories that name the CVE: the ones from
// the active feed snapshots and the ones read from the repository metadata of
// the hosts in scope.
func (s *Store) CVEReferences(ctx context.Context, cve string, scopes []authz.Scope) ([]CVEReference, error) {
	result := []CVEReference{}
	const fromFeeds = `
		select distinct on (a.provider, a.advisory_id)
		       a.provider, a.advisory_id, a.title, a.url, a.status, a.release, a.published_at
		from vuln_advisories a
		join vuln_snapshots s on s.id = a.snapshot_id and s.active
		where $1 = any(a.cve_ids)
		order by a.provider, a.advisory_id, a.published_at desc nulls last
		limit $2`
	rows, err := s.pool.Query(ctx, fromFeeds, cve, cveReferencesLimit)
	if err != nil {
		return nil, err
	}
	for rows.Next() {
		var item CVEReference
		if err := rows.Scan(&item.Provider, &item.AdvisoryID, &item.Title, &item.URL,
			&item.Status, &item.Release, &item.PublishedAt); err != nil {
			rows.Close()
			return nil, err
		}
		result = append(result, item)
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return nil, err
	}

	// The RPM family reads its advisories from the metadata of the host's own
	// repositories, so they have no feed snapshot and no URL - only an identifier
	// and a title.
	args := []any{cve, cveReferencesLimit}
	scope := ""
	if scopes != nil {
		condition, extra := authz.ScopeSQL(scopes, authz.HostColumns("h"), len(args))
		if condition != "" {
			scope = " and " + condition
			args = append(args, extra...)
		}
	}
	fromHosts := `
		select distinct on (ha.advisory_id) ha.advisory_id, ha.title, ha.issued_at
		from host_advisories ha
		join hosts h on h.id = ha.host_id
		where $1 = any(ha.cve_ids)` + scope + `
		order by ha.advisory_id, ha.issued_at desc nulls last
		limit $2`
	rows, err = s.pool.Query(ctx, fromHosts, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	for rows.Next() {
		item := CVEReference{Provider: "host repository metadata", Status: StatusFixed}
		if err := rows.Scan(&item.AdvisoryID, &item.Title, &item.PublishedAt); err != nil {
			return nil, err
		}
		result = append(result, item)
	}
	return result, rows.Err()
}

// SeverityCounts counts the affected findings of every host by canonical
// severity, so the fleet table can be narrowed to the hosts that carry a
// critical finding without reading every finding into the panel.
func (s *Store) SeverityCounts(ctx context.Context, hostIDs []string) (map[string]map[string]int, error) {
	result := map[string]map[string]int{}
	if len(hostIDs) == 0 {
		return result, nil
	}
	query := `
		select host_id::text, ` + severityRankSQL("vendor_severity") + ` as rank, count(*)
		from vuln_findings
		where host_id = any($1) and state = 'affected'
		group by host_id, rank`
	rows, err := s.pool.Query(ctx, query, hostIDs)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	for rows.Next() {
		var hostID string
		var rank, count int
		if err := rows.Scan(&hostID, &rank, &count); err != nil {
			return nil, err
		}
		if result[hostID] == nil {
			result[hostID] = map[string]int{}
		}
		result[hostID][SeverityName(rank)] += count
	}
	return result, rows.Err()
}
