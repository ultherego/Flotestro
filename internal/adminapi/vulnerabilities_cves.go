package adminapi

import (
	"net/http"
	"regexp"
	"sort"
	"strconv"
	"strings"

	"github.com/ultherego/flotestro/internal/authz"
	"github.com/ultherego/flotestro/internal/paging"
	"github.com/ultherego/flotestro/internal/vuln"
)

// cveNumber is the shape of a CVE identifier.
var cveNumber = regexp.MustCompile(`^CVE-\d{4}-\d{4,}$`)

// The page of the CVE list: what the screen gets without asking and the
// most it may ask for.
const (
	defaultCVEPage = 50
	maxCVEPage     = 500
)

// handleFleetCVEs lists the vulnerabilities of the visible fleet one CVE per
// row, the gravest and the most widespread first.
func (s *Server) handleFleetCVEs(w http.ResponseWriter, r *http.Request) {
	principal, ok := s.authorizeCollection(w, r, authz.PermVulnerabilityRead, "fleet")
	if !ok {
		return
	}
	if s.vulnerabilities == nil {
		problem(w, http.StatusNotImplemented, "vulnerability_correlator_disabled",
			"the vulnerability correlator is disabled in this installation")
		return
	}
	query := r.URL.Query()
	filter := vuln.CVEFilter{
		Scopes:   principal.ScopesFor(authz.PermVulnerabilityRead),
		Query:    strings.TrimSpace(query.Get("q")),
		Severity: strings.ToLower(strings.TrimSpace(query.Get("severity"))),
	}
	if filter.Severity != "" && vuln.SeverityRank(filter.Severity) < 0 {
		problem(w, http.StatusBadRequest, "invalid_filter",
			"severity must be one of critical, high, medium, low, negligible or unrated")
		return
	}
	if value := query.Get("fixable"); value != "" {
		fixable, err := strconv.ParseBool(value)
		if err != nil {
			problem(w, http.StatusBadRequest, "invalid_filter", "fixable must be true or false")
			return
		}
		filter.Fixable = fixable
	}
	limit, _ := strconv.Atoi(query.Get("limit"))
	filter.Limit = paging.Limit(limit, defaultCVEPage, maxCVEPage)
	if offset, err := strconv.Atoi(query.Get("offset")); err == nil && offset > 0 {
		filter.Offset = offset
	}

	page, err := s.vulnerabilities.CVEs(r.Context(), filter)
	if err != nil {
		s.fail(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"items": page.Items, "count": len(page.Items),
		"total": page.Total, "limit": filter.Limit, "offset": filter.Offset,
	})
}

// cveReport is the answer of the CVE page: what the upstream database says
// about the vulnerability, what the vendors published and which hosts in scope
// carry it.
type cveReport struct {
	CVE string `json:"cve"`
	// Details is the enrichment; it may be missing and it decides nothing.
	Details *vuln.CVEDetails `json:"details,omitempty"`
	// Severity is the worst vendor rating among the affected hosts.
	Severity   string              `json:"severity"`
	References []vuln.CVEReference `json:"references"`
	Hosts      []vuln.CVEHost      `json:"hosts"`
	// HostsTotal counts the rows the page could list, which may exceed the rows
	// it did; AffectedHosts and HostsWithVendorFix count distinct hosts among the
	// rows returned, because those are the hosts the operator can act on from
	HostsTotal         int      `json:"hosts_total"`
	AffectedHosts      int      `json:"affected_hosts"`
	UndecidedHosts     int      `json:"undecided_hosts"`
	HostsWithVendorFix int      `json:"hosts_with_vendor_fix"`
	Packages           []string `json:"packages"`
	Truncated          bool     `json:"truncated"`
}

// handleCVE returns one vulnerability across the visible fleet.
func (s *Server) handleCVE(w http.ResponseWriter, r *http.Request) {
	principal, ok := s.authorizeCollection(w, r, authz.PermVulnerabilityRead, "fleet")
	if !ok {
		return
	}
	if s.vulnerabilities == nil {
		problem(w, http.StatusNotImplemented, "vulnerability_correlator_disabled",
			"the vulnerability correlator is disabled in this installation")
		return
	}
	cve := strings.ToUpper(strings.TrimSpace(r.PathValue("cve")))
	if !cveNumber.MatchString(cve) {
		problem(w, http.StatusBadRequest, "invalid_cve", "the identifier must look like CVE-2024-12345")
		return
	}
	scopes := principal.ScopesFor(authz.PermVulnerabilityRead)

	rows, total, err := s.vulnerabilities.CVEHosts(r.Context(), cve, scopes)
	if err != nil {
		s.fail(w, err)
		return
	}
	details, err := s.vulnerabilities.Details(r.Context(), []string{cve})
	if err != nil {
		s.fail(w, err)
		return
	}
	if len(rows) == 0 && len(details) == 0 {
		problem(w, http.StatusNotFound, "cve_not_found",
			"no host you can see carries this CVE and no feed describes it")
		return
	}
	references, err := s.vulnerabilities.CVEReferences(r.Context(), cve, scopes)
	if err != nil {
		s.fail(w, err)
		return
	}

	report := cveReport{
		CVE: cve, Severity: vuln.SeverityUnrated, References: references, Hosts: rows,
		HostsTotal: total, Truncated: total > len(rows), Packages: []string{},
	}
	if entry, present := details[cve]; present {
		report.Details = &entry
	}
	affected := map[string]bool{}
	undecided := map[string]bool{}
	withFix := map[string]bool{}
	packages := map[string]bool{}
	bestRank := vuln.SeverityRank(vuln.SeverityUnrated) + 1
	for _, row := range rows {
		packages[row.Package] = true
		if row.State == vuln.StateAffected {
			affected[row.HostID] = true
			if row.VendorFix == vuln.VendorFixKnown {
				withFix[row.HostID] = true
			}
			// The rows come ordered by the affected state and the rank,
			// so the first affected row carries the worst rating.
			if rank := vuln.SeverityRank(row.Severity); rank >= 0 && rank < bestRank {
				bestRank = rank
				report.Severity = row.Severity
			}
		} else {
			undecided[row.HostID] = true
		}
	}
	report.AffectedHosts = len(affected)
	report.UndecidedHosts = len(undecided)
	report.HostsWithVendorFix = len(withFix)
	for name := range packages {
		report.Packages = append(report.Packages, name)
	}
	sort.Strings(report.Packages)
	writeJSON(w, http.StatusOK, report)
}
