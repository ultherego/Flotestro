package adminapi

import (
	"context"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/ultherego/flotestro/internal/authz"
	"github.com/ultherego/flotestro/internal/vuln"
)

// SetVulnerabilities attaches the vulnerability correlator.
func (s *Server) SetVulnerabilities(store *vuln.Store, packages *vuln.PackageStore,
	maxFeedAge time.Duration) {
	s.vulnerabilities = store
	s.hostPackages = packages
	s.feedAge = maxFeedAge
}

// vulnerabilityReport is the answer of the host tab.
//
// A finding count without coverage means nothing: a host the feed does not
// cover and a host without vulnerabilities both have zero on the counter.
// That is why the coverage and the reason for its absence stand here next
// to the list, not below it.
type vulnerabilityReport struct {
	HostID   string            `json:"host_id"`
	State    vuln.HostState    `json:"state"`
	Findings []vuln.Assessment `json:"findings"`
	// PackageState describes the package list the assessment was based on,
	// and AdvisoryState - the set of vendor advisories known to the host.
	// These are two separate sources and two separate refresh cycles.
	PackageState  vuln.PackageListState `json:"package_state"`
	AdvisoryState vuln.AdvisoryState    `json:"advisory_state"`
	// Snapshot describes the data that decided.
	Snapshot *vuln.Snapshot `json:"snapshot,omitempty"`
	// SnapshotStale says the data is older than the policy allows.
	SnapshotStale bool `json:"snapshot_stale"`
	// CoveragePercent is the share of packages covered by the feed.
	CoveragePercent float64 `json:"coverage_percent"`
	// FullyAssessed says whether the assessment is complete: no coverage
	// obstacle, a feed covering all the packages and not a single
	// undetermined package. An empty reason alone does not mean that.
	FullyAssessed bool `json:"fully_assessed"`
	// CVEDetails are an enrichment: the CVSS score and the vulnerability
	// description from the upstream database. They stand next to the
	// findings, not in them, because they change nothing in them - whether
	// a package is vulnerable is said only by the distribution vendor. A
	// missing entry is normal.
	CVEDetails map[string]vuln.CVEDetails `json:"cve_details,omitempty"`
}

// cveDetails picks the enrichment for the findings.
//
// Silently: missing descriptions must not prevent showing the assessment,
// because the assessment does not use them. When the enriching source is
// missing or the read fails, the tab shows the same as always, only without
// the upstream weight.
func (s *Server) cveDetails(ctx context.Context, findings []vuln.Assessment) map[string]vuln.CVEDetails {
	seen := map[string]bool{}
	ids := make([]string, 0, len(findings))
	for _, finding := range findings {
		for _, id := range finding.CVEIDs {
			if id == "" || seen[id] {
				continue
			}
			seen[id] = true
			ids = append(ids, id)
		}
	}
	if len(ids) == 0 {
		return nil
	}
	details, err := s.vulnerabilities.Details(ctx, ids)
	if err != nil {
		s.log.Error("the vulnerability descriptions were not read", "err", err)
		return nil
	}
	return details
}

// handleHostVulnerabilities returns the findings and the assessment
// coverage of a host.
func (s *Server) handleHostVulnerabilities(w http.ResponseWriter, r *http.Request) {
	hostID := r.PathValue("id")
	_, scope, ok := s.hostScope(w, r, hostID)
	if !ok {
		return
	}
	if _, ok := s.authorize(w, r, authz.PermVulnerabilityRead, scope, "host", hostID); !ok {
		return
	}
	if s.vulnerabilities == nil {
		problem(w, http.StatusNotImplemented, "vulnerability_correlator_disabled",
			"the vulnerability correlator is disabled in this installation")
		return
	}

	states, err := s.vulnerabilities.HostStates(r.Context(), []string{hostID})
	if err != nil {
		s.fail(w, err)
		return
	}
	findings, err := s.vulnerabilities.Advisories(r.Context(), hostID, false)
	if err != nil {
		s.fail(w, err)
		return
	}
	listState, err := s.hostPackages.State(r.Context(), hostID)
	if err != nil {
		s.fail(w, err)
		return
	}

	advisoryState, err := s.hostPackages.HostAdvisoryState(r.Context(), hostID)
	if err != nil {
		s.fail(w, err)
		return
	}

	report := vulnerabilityReport{
		HostID: hostID, State: states[hostID], PackageState: listState,
		AdvisoryState: advisoryState, Findings: findings,
	}
	if report.Findings == nil {
		report.Findings = []vuln.Assessment{}
	}
	report.CoveragePercent = report.State.Coverage() * 100
	report.FullyAssessed = report.State.FullAssessment()
	report.CVEDetails = s.cveDetails(r.Context(), report.Findings)
	if report.State.Provider != "" {
		if snapshot, err := s.vulnerabilities.ActiveSnapshot(r.Context(), report.State.Provider); err == nil {
			report.Snapshot = &snapshot
			report.SnapshotStale = snapshot.Stale(s.feedAge, time.Now().UTC())
		} else if report.State.SnapshotDigest != "" {
			// The RPM family reads the advisories from the metadata of its own
			// repositories, so there is no central snapshot. The panel must
			// still say what decided the assessment - otherwise the result has
			// no source.
			findings, collected, err := s.hostPackages.HostAdvisories(r.Context(), hostID)
			if err == nil {
				count := 0
				for _, perPackage := range findings {
					count += len(perPackage)
				}
				snapshot := vuln.Snapshot{
					Provider: report.State.Provider + " (host repository metadata)",
					Digest:   report.State.SnapshotDigest, AdvisoryCount: count,
					Releases: []string{report.State.Release}, FetchedAt: collected, Active: true,
				}
				report.Snapshot = &snapshot
				report.SnapshotStale = snapshot.Stale(s.feedAge, time.Now().UTC())
			}
		}
	}
	writeJSON(w, http.StatusOK, report)
}

// hostVulnerabilities describes one host on the fleet screen.
type hostVulnerabilities struct {
	vuln.HostState
	CoveragePercent float64 `json:"coverage_percent"`
	// FullyAssessed says whether the assessment of this host is complete.
	// Without this field the screen would have to guess from the empty
	// reason alone - and a host with one package outside the distribution
	// has an empty reason and an incomplete assessment.
	FullyAssessed bool `json:"fully_assessed"`
	// BySeverity counts the affected findings by canonical severity, so
	// the table can say "three critical" without the operator opening the
	// host. An absent word is a zero here, because the count comes from the
	// findings themselves; it is the coverage next to it that says whether
	// zero means anything.
	BySeverity map[string]int `json:"by_severity"`
}

// fleetHostFilter narrows the host table of the fleet screen. The summary
// numbers above the table are counted over the whole visible fleet either
// way: a filter changes what the table lists, not how bad the fleet is.
type fleetHostFilter struct {
	// Query is a fragment of the hostname.
	Query string
	// Severity keeps the hosts with an affected finding of this canonical
	// severity.
	Severity string
	// Sort is "affected" (the default: the worst first), "fixable" (the
	// most vendor fixes waiting first) or "hostname".
	Sort  string
	Limit int
	// Cursor is the key of the last row of the previous page; Offset the
	// number of rows to skip for a caller that still pages the old way.
	// The cursor wins when both are given.
	Cursor vuln.FleetCursor
	Offset int
}

// parseFleetHostFilter reads the table filters of the fleet screen; a
// filter it cannot read ends the request.
func parseFleetHostFilter(w http.ResponseWriter, r *http.Request) (fleetHostFilter, bool) {
	query := r.URL.Query()
	filter := fleetHostFilter{
		Query:    strings.ToLower(strings.TrimSpace(query.Get("q"))),
		Severity: strings.ToLower(strings.TrimSpace(query.Get("severity"))),
		Sort:     strings.ToLower(strings.TrimSpace(query.Get("sort"))),
	}
	if filter.Severity != "" && vuln.SeverityRank(filter.Severity) < 0 {
		problem(w, http.StatusBadRequest, "invalid_filter",
			"severity must be one of critical, high, medium, low, negligible or unrated")
		return filter, false
	}
	switch filter.Sort {
	case "":
		filter.Sort = vuln.SortAffected
	case vuln.SortAffected, vuln.SortFixable, vuln.SortHostname:
	default:
		problem(w, http.StatusBadRequest, "invalid_filter", "sort must be affected, fixable or hostname")
		return filter, false
	}
	limit, cursorText, ok := parseFleetPage(w, r)
	if !ok {
		return filter, false
	}
	filter.Limit = limit
	cursor, err := vuln.ParseFleetCursor(cursorText)
	if err != nil {
		invalidCursor(w, err)
		return filter, false
	}
	filter.Cursor = cursor
	if offset, err := strconv.Atoi(query.Get("offset")); err == nil && offset > 0 {
		filter.Offset = offset
	}
	return filter, true
}

// store renders the table filter for the store under the caller's scopes.
func (f fleetHostFilter) store(scopes []authz.Scope) vuln.FleetFilter {
	return vuln.FleetFilter{Scopes: scopes, Query: f.Query, Severity: f.Severity, Sort: f.Sort}
}

// fleetVulnerabilitiesView is the answer of the fleet screen: the coverage
// of the fleet, the sums over every assessed host in scope, the sources
// and one page of the host table.
type fleetVulnerabilitiesView struct {
	fleetCoverage
	Items      []hostVulnerabilities `json:"items"`
	Count      int                   `json:"count"`
	Total      int                   `json:"total"`
	NextCursor string                `json:"next_cursor,omitempty"`
	Limit      int                   `json:"limit"`
	Offset     int                   `json:"offset"`

	Affected              int `json:"affected"`
	AffectedWithVendorFix int `json:"affected_with_vendor_fix"`
	AffectedNoFix         int `json:"affected_no_fix"`
	Unknown               int `json:"unknown"`
	// Four numbers, because they are four different questions: how many
	// CVEs, how many vendor issues, how many package instances to touch
	// and how many hosts it concerns. One "findings" number answers none
	// of them.
	UniqueCVEs               int `json:"unique_cves"`
	UniqueAdvisories         int `json:"unique_advisories"`
	AffectedPackageInstances int `json:"affected_package_instances"`
	HostsAffected            int `json:"hosts_affected"`
	// HostsTotal, HostsAssessed and HostsWithoutAssessment keep the names
	// the screen read before the coverage head: the hosts in scope, those
	// fully assessed and those never assessed.
	HostsTotal             int              `json:"hosts_total"`
	HostsAssessed          int              `json:"hosts_assessed"`
	HostsWithoutAssessment int              `json:"hosts_without_assessment"`
	CoverageReasons        map[string]int   `json:"coverage_reasons"`
	Sources                []map[string]any `json:"sources"`
	MaxSnapshotAgeHours    int              `json:"max_snapshot_age_hours"`
}

// handleFleetVulnerabilities returns the assessment of the whole visible
// fleet.
//
// The screen has two numbers, not one: how many vulnerabilities and what
// part of the fleet could be assessed at all. Without the second the first
// is a promise, not a result. Both are counted by the database over every
// host in scope, and the table comes a page at a time under its order.
func (s *Server) handleFleetVulnerabilities(w http.ResponseWriter, r *http.Request) {
	principal, ok := s.authorizeCollection(w, r, authz.PermVulnerabilityRead, "fleet")
	if !ok {
		return
	}
	if s.vulnerabilities == nil {
		problem(w, http.StatusNotImplemented, "vulnerability_correlator_disabled",
			"the vulnerability correlator is disabled in this installation")
		return
	}
	filter, ok := parseFleetHostFilter(w, r)
	if !ok {
		return
	}
	asCSV, ok := exportFormat(w, r)
	if !ok {
		return
	}
	scopes := principal.ScopesFor(authz.PermVulnerabilityRead)
	now := time.Now().UTC()
	if asCSV {
		s.writeVulnerabilitiesCSV(w, r, filter.store(scopes), now)
		return
	}

	summary, err := s.vulnerabilities.FleetSummary(r.Context(), scopes)
	if err != nil {
		s.fail(w, err)
		return
	}
	// Uniques are counted at the fleet level, not by summing per host: the
	// same CVE on twenty hosts is one vendor issue and twenty hosts to
	// touch. Summing the host counters turns one into the other.
	uniques, err := s.vulnerabilities.UniquesInScope(r.Context(), scopes)
	if err != nil {
		s.fail(w, err)
		return
	}
	page, err := s.vulnerabilities.FleetPage(r.Context(), filter.store(scopes), filter.Cursor, filter.Limit, filter.Offset)
	if err != nil {
		s.fail(w, err)
		return
	}
	rows, err := s.fleetVulnerabilityRows(r.Context(), page.Items)
	if err != nil {
		s.fail(w, err)
		return
	}
	snapshots, err := s.vulnerabilities.Snapshots(r.Context())
	if err != nil {
		s.fail(w, err)
		return
	}
	sources := make([]map[string]any, 0, len(snapshots)+1)
	for _, snapshot := range snapshots {
		sources = append(sources, map[string]any{
			"provider": snapshot.Provider, "digest": snapshot.Digest,
			"advisories": snapshot.AdvisoryCount, "releases": snapshot.Releases,
			"fetched_at": snapshot.FetchedAt, "stale": snapshot.Stale(s.feedAge, now),
			"error": snapshot.Error,
		})
	}
	// The advisories a host reads from its own repositories - Fedora's
	// updateinfo - are a source too, without a feed of their own: the
	// table names it, or a Fedora host's findings would seem to come from
	// nowhere.
	if repository, err := s.vulnerabilities.HostRepositorySourceInScope(r.Context(), scopes); err != nil {
		s.fail(w, err)
		return
	} else if repository != nil {
		sources = append(sources, map[string]any{
			"provider": "host repository metadata", "advisories": repository.Advisories,
			"hosts": repository.Hosts, "fetched_at": repository.CollectedAt,
			"stale": repository.CollectedAt.Before(now.Add(-s.feedAge)),
		})
	}

	coverage := fleetCoverage{
		TotalHosts: summary.Hosts, EvaluatedHosts: summary.Evaluated, UnknownHosts: summary.Unassessed,
		UnknownReasons: map[string]int{},
	}
	if summary.Unassessed > 0 {
		coverage.UnknownReasons[unknownNoAssessment] = summary.Unassessed
	}
	writeJSON(w, http.StatusOK, fleetVulnerabilitiesView{
		fleetCoverage: coverage,
		Items:         rows, Count: len(rows), Total: page.Total, NextCursor: page.NextCursor,
		Limit: filter.Limit, Offset: filter.Offset,
		Affected: summary.Affected, AffectedWithVendorFix: summary.AffectedWithVendorFix,
		AffectedNoFix: summary.AffectedNoFix, Unknown: summary.Unknown,
		UniqueCVEs: uniques.CVE, UniqueAdvisories: uniques.Advisories,
		AffectedPackageInstances: summary.AffectedPackages, HostsAffected: summary.HostsAffected,
		HostsTotal: summary.Hosts, HostsAssessed: summary.FullyAssessed,
		HostsWithoutAssessment: summary.Unassessed,
		CoverageReasons:        summary.CoverageReasons,
		Sources:                sources,
		MaxSnapshotAgeHours:    int(s.feedAge.Hours()),
	})
}

// fleetVulnerabilityRows dresses one page of host states for the table:
// the coverage as a share, the verdict on its completeness and the
// findings by severity, the last read in one query for the page.
func (s *Server) fleetVulnerabilityRows(ctx context.Context, states []vuln.HostState) ([]hostVulnerabilities, error) {
	ids := make([]string, 0, len(states))
	for _, state := range states {
		ids = append(ids, state.HostID)
	}
	severities, err := s.vulnerabilities.SeverityCounts(ctx, ids)
	if err != nil {
		return nil, err
	}
	rows := make([]hostVulnerabilities, 0, len(states))
	for _, state := range states {
		bySeverity := severities[state.HostID]
		if bySeverity == nil {
			bySeverity = map[string]int{}
		}
		rows = append(rows, hostVulnerabilities{
			HostState: state, CoveragePercent: state.Coverage() * 100,
			FullyAssessed: state.FullAssessment(), BySeverity: bySeverity,
		})
	}
	return rows, nil
}

// vulnerabilitiesCSVColumns is the header of the fleet export. The order
// is fixed: a sheet built against one export reads the next one. The
// severity columns count the affected findings of that canonical
// severity on the host.
var vulnerabilitiesCSVColumns = []string{
	"hostname", "host_id", "distribution", "release", "affected", "affected_with_vendor_fix", "affected_no_fix",
	"unknown", "critical", "high", "medium", "low", "negligible", "unrated",
	"affected_packages", "unique_advisories", "unique_cves", "packages_total", "packages_covered",
	"coverage_percent", "fully_assessed", "coverage_reason", "advisories_reason", "provider", "evaluated_at",
}

// writeVulnerabilitiesCSV streams the fleet assessment as a file: one row
// per host of the filtered table, in the order the screen sorts it, a
// page at a time from the same cursor the screen pages with, with the
// coverage next to the counts - a host with zero findings and no
// assessment is not a clean host, and the file says so in its own
// columns. The screen's page does not apply; the export's own cap does.
func (s *Server) writeVulnerabilitiesCSV(w http.ResponseWriter, r *http.Request, filter vuln.FleetFilter, now time.Time) {
	s.writeCSV(w, r, exportFileName("vulnerabilities", now), vulnerabilitiesCSVColumns, func(yield func([]string) bool) error {
		cursor := vuln.FleetCursor{}
		for {
			page, err := s.vulnerabilities.FleetPage(r.Context(), filter, cursor, vuln.MaxPage, 0)
			if err != nil {
				return err
			}
			rows, err := s.fleetVulnerabilityRows(r.Context(), page.Items)
			if err != nil {
				return err
			}
			for _, item := range rows {
				if !yield(hostVulnerabilitiesCSVRow(item)) {
					return nil
				}
			}
			if page.NextCursor == "" {
				return nil
			}
			if cursor, err = vuln.ParseFleetCursor(page.NextCursor); err != nil {
				return err
			}
		}
	})
}

// hostVulnerabilitiesCSVRow renders one host in the order of
// vulnerabilitiesCSVColumns.
func hostVulnerabilitiesCSVRow(item hostVulnerabilities) []string {
	severity := func(name string) string { return strconv.Itoa(item.BySeverity[name]) }
	return []string{
		item.Hostname, item.HostID, item.Distribution, item.Release, strconv.Itoa(item.Affected),
		strconv.Itoa(item.AffectedWithVendorFix), strconv.Itoa(item.AffectedNoFix), strconv.Itoa(item.Unknown),
		severity("critical"), severity("high"), severity("medium"), severity("low"), severity("negligible"), severity("unrated"),
		strconv.Itoa(item.AffectedPackages), strconv.Itoa(item.UniqueAdvisories), strconv.Itoa(item.UniqueCVEs),
		strconv.Itoa(item.PackagesTotal), strconv.Itoa(item.PackagesCovered), csvFloat(item.CoveragePercent),
		strconv.FormatBool(item.FullyAssessed), item.CoverageReason, item.AdvisoriesReason, item.Provider,
		formatTime(item.EvaluatedAt),
	}
}
