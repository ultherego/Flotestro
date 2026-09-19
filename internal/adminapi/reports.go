package adminapi

import (
	"context"
	"net/http"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/ultherego/flotestro/internal/authz"
	"github.com/ultherego/flotestro/internal/compliance"
	"github.com/ultherego/flotestro/internal/hosts"
	"github.com/ultherego/flotestro/internal/inventory"
	"github.com/ultherego/flotestro/internal/paging"
	"github.com/ultherego/flotestro/internal/reports"
)

// The management reports: the patch status of the fleet, the campaigns of a
// period and the compliance with the policies, each as a document the panel
// prints and as a file a spreadsheet opens.

// The bounds of a report period.
const (
	defaultReportPeriod = 30 * 24 * time.Hour
	maxReportPeriod     = 366 * 24 * time.Hour
)

// The most host rows the patch status carries in JSON.
const (
	defaultReportHosts = 1000
	maxReportHosts     = 5000
)

// reportRequest is what every report reads off the query: the period,
// the filter and the format.
type reportRequest struct {
	period      reports.Period
	site        string
	environment string
	asCSV       bool
	generatedAt time.Time
}

// reportEnvelope is the head of every report document: what was asked
// and when, so a printed page says what it is a report of.
type reportEnvelope struct {
	Report      string    `json:"report"`
	From        time.Time `json:"from"`
	To          time.Time `json:"to"`
	Site        string    `json:"site,omitempty"`
	Environment string    `json:"environment,omitempty"`
	GeneratedAt time.Time `json:"generated_at"`
	GeneratedBy string    `json:"generated_by"`
}

func (s *Server) handleReport(w http.ResponseWriter, r *http.Request) {
	switch r.PathValue("name") {
	case "patch-status":
		s.handlePatchStatusReport(w, r)
	case "campaigns":
		s.handleCampaignsReport(w, r)
	case "compliance":
		s.handleComplianceReport(w, r)
	default:
		problem(w, http.StatusNotFound, "report_not_found", "the reports are patch-status, campaigns and compliance")
	}
}

// parseReportRequest reads the period, the filter and the format.
func (s *Server) parseReportRequest(w http.ResponseWriter, r *http.Request) (reportRequest, bool) {
	query := r.URL.Query()
	request := reportRequest{
		site:        strings.TrimSpace(query.Get("site")),
		environment: strings.TrimSpace(query.Get("environment")),
		generatedAt: time.Now().UTC(),
	}
	fromText, toText := strings.TrimSpace(query.Get("from")), strings.TrimSpace(query.Get("to"))
	switch {
	case fromText == "" && toText == "":
		request.period.To = request.generatedAt
		request.period.From = request.generatedAt.Add(-defaultReportPeriod)
	case fromText == "" || toText == "":
		problem(w, http.StatusBadRequest, "invalid_range", "from and to go together, both RFC 3339 timestamps")
		return request, false
	default:
		from, err := time.Parse(time.RFC3339, fromText)
		if err != nil {
			problem(w, http.StatusBadRequest, "invalid_range", "from must be an RFC 3339 timestamp")
			return request, false
		}
		to, err := time.Parse(time.RFC3339, toText)
		if err != nil {
			problem(w, http.StatusBadRequest, "invalid_range", "to must be an RFC 3339 timestamp")
			return request, false
		}
		if !to.After(from) || to.Sub(from) > maxReportPeriod {
			problem(w, http.StatusBadRequest, "invalid_range", "the period must end after it starts and span a year at most")
			return request, false
		}
		request.period = reports.Period{From: from.UTC(), To: to.UTC()}
	}
	asCSV, ok := exportFormat(w, r)
	if !ok {
		return request, false
	}
	request.asCSV = asCSV
	return request, true
}

// envelope heads a report document with the request that produced it.
func (request reportRequest) envelope(name string, principal authz.Principal) reportEnvelope {
	return reportEnvelope{
		Report: name, From: request.period.From, To: request.period.To,
		Site: request.site, Environment: request.environment,
		GeneratedAt: request.generatedAt, GeneratedBy: principal.Subject,
	}
}

// filter narrows a report to the reader's scope under the permission
// and to the site and environment asked for.
func (request reportRequest) filter(principal authz.Principal, permission authz.Permission) reports.Filter {
	return reports.Filter{
		Site: request.site, Environment: request.environment,
		Scopes: principal.ScopesFor(permission),
	}
}

func (s *Server) reportStore() *reports.Store { return reports.NewStore(s.pool) }

// The patch status of the fleet: every visible host with its pending updates
// and the work of the period on it, and the totals by site and by environment.
func (s *Server) handlePatchStatusReport(w http.ResponseWriter, r *http.Request) {
	principal, ok := s.authorizeCollection(w, r, authz.PermHostRead, "report")
	if !ok {
		return
	}
	request, ok := s.parseReportRequest(w, r)
	if !ok {
		return
	}
	filter := request.filter(principal, authz.PermHostRead)
	seesCampaigns := principal.CanAnywhere(authz.PermCampaignRead)
	if request.asCSV {
		s.writePatchStatusCSV(w, r, request, filter, seesCampaigns)
		return
	}
	store := s.reportStore()
	report, err := store.PatchStatus(r.Context(), request.period, filter)
	if err != nil {
		s.fail(w, err)
		return
	}
	requested, _ := strconv.Atoi(r.URL.Query().Get("limit"))
	limit := paging.Limit(requested, defaultReportHosts, maxReportHosts)
	rows := make([]reports.PatchHost, 0, min(limit, report.Totals.Hosts))
	truncated := false
	err = store.PatchHosts(r.Context(), request.period, filter, func(host reports.PatchHost) bool {
		if len(rows) >= limit {
			truncated = true
			return false
		}
		if !seesCampaigns {
			host.Campaigns = nil
		}
		rows = append(rows, host)
		return true
	})
	if err != nil {
		s.fail(w, err)
		return
	}
	writeJSON(w, http.StatusOK, struct {
		reportEnvelope
		*reports.PatchStatus
		Hosts          []reports.PatchHost `json:"hosts"`
		HostsListed    int                 `json:"hosts_listed"`
		HostsTruncated bool                `json:"hosts_truncated"`
		CampaignsRead  bool                `json:"campaigns_read"`
	}{request.envelope("patch-status", principal), report, rows, len(rows), truncated, seesCampaigns})
}

// patchStatusCSVColumns is the header of the patch status file. The
// order is fixed: a sheet built against one file reads the next one.
var patchStatusCSVColumns = []string{
	"hostname", "id", "site", "environment", "lifecycle_state", "connection_state", "agent_version",
	"last_seen_at", "pending_updates", "pending_security_updates", "reboot_required",
	"last_upgrade_at", "campaigns",
}

// writePatchStatusCSV streams the host rows of the patch status: every
// visible host, in the order of the host list, straight from the query.
func (s *Server) writePatchStatusCSV(w http.ResponseWriter, r *http.Request, request reportRequest,
	filter reports.Filter, seesCampaigns bool) {
	s.writeCSV(w, r, exportFileName("report-patch-status", request.generatedAt), patchStatusCSVColumns,
		func(yield func([]string) bool) error {
			return s.reportStore().PatchHosts(r.Context(), request.period, filter, func(host reports.PatchHost) bool {
				campaigns := ""
				if seesCampaigns {
					campaigns = csvInt(host.Campaigns)
				}
				return yield([]string{
					host.Hostname, host.HostID, host.Site, host.Environment, host.LifecycleState, host.ConnectionState,
					host.AgentVersion, formatTime(host.LastSeenAt), csvInt(host.PendingUpdates),
					csvInt(host.PendingSecurityUpdates), csvBool(host.RebootRequired),
					formatTime(host.LastUpgradeAt), campaigns,
				})
			})
		})
}

// The campaigns that closed in the period, with their outcome and the totals
// over them.
func (s *Server) handleCampaignsReport(w http.ResponseWriter, r *http.Request) {
	principal, ok := s.authorizeCollection(w, r, authz.PermCampaignRead, "report")
	if !ok {
		return
	}
	request, ok := s.parseReportRequest(w, r)
	if !ok {
		return
	}
	report, err := s.reportStore().Campaigns(r.Context(), request.period, request.filter(principal, authz.PermCampaignRead))
	if err != nil {
		s.fail(w, err)
		return
	}
	if request.asCSV {
		s.writeCampaignsCSV(w, r, request, report)
		return
	}
	writeJSON(w, http.StatusOK, struct {
		reportEnvelope
		*reports.CampaignsReport
	}{request.envelope("campaigns", principal), report})
}

// campaignsCSVColumns is the header of the campaign file.
var campaignsCSVColumns = []string{
	"id", "name", "operation", "state", "requester", "approver", "created_at", "started_at", "finished_at",
	"duration_seconds", "targets", "succeeded", "no_change", "failed", "unknown", "skipped", "canceled",
	"success_rate", "by_site",
}

// writeCampaignsCSV writes the campaigns of the report, one per row.
func (s *Server) writeCampaignsCSV(w http.ResponseWriter, r *http.Request, request reportRequest, report *reports.CampaignsReport) {
	s.writeCSV(w, r, exportFileName("report-campaigns", request.generatedAt), campaignsCSVColumns,
		func(yield func([]string) bool) error {
			for _, row := range report.Campaigns {
				sites := make([]string, 0, len(row.BySite))
				for _, group := range row.BySite {
					sites = append(sites, group.Key+"="+strconv.Itoa(group.Succeeded)+"/"+strconv.Itoa(group.Targets))
				}
				rate := ""
				if row.SuccessRate != nil {
					rate = csvFloat(*row.SuccessRate)
				}
				if !yield([]string{
					row.ID, row.Name, row.Operation, row.State, row.Requester, row.Approver,
					csvInstant(row.CreatedAt), formatTime(row.StartedAt), csvInstant(row.FinishedAt),
					csvInt(row.DurationSeconds), strconv.Itoa(row.Targets), strconv.Itoa(row.Succeeded),
					strconv.Itoa(row.NoChange), strconv.Itoa(row.Failed), strconv.Itoa(row.Unknown),
					strconv.Itoa(row.Skipped), strconv.Itoa(row.Canceled), rate, csvList(sites),
				}) {
					return nil
				}
			}
			return nil
		})
}

// securityCounts tallies the findings of one check or one severity over the
// visible hosts.
type securityCounts struct {
	Failed        int `json:"failed"`
	Passed        int `json:"passed"`
	Unknown       int `json:"unknown"`
	NotApplicable int `json:"not_applicable"`
}

func (c *securityCounts) add(finding compliance.Finding) {
	switch {
	case !finding.Applicable:
		c.NotApplicable++
	case finding.Unknown:
		c.Unknown++
	case finding.Passed:
		c.Passed++
	default:
		c.Failed++
	}
}

type severityView struct {
	Severity string `json:"severity"`
	// Checks counts the checks of the severity.
	Checks int `json:"checks"`
	securityCounts
}

type checkSummary struct {
	CheckID  string `json:"check_id"`
	Title    string `json:"title"`
	Severity string `json:"severity"`
	securityCounts
}

// securitySummary is the security part of the compliance report: the findings
// of the built-in checks over the hosts the reader may read the security of,
// judged now from the facts the hosts last reported.
type securitySummary struct {
	Hosts int `json:"hosts"`
	// HostsWithFindings counts the hosts that fail at least one check.
	HostsWithFindings int            `json:"hosts_with_findings"`
	BySeverity        []severityView `json:"by_severity"`
	Checks            []checkSummary `json:"checks"`
	EvaluatedAt       time.Time      `json:"evaluated_at"`
	// Partial says the sweep did not reach every host of the filter within its
	// time budget; the numbers then describe the hosts it reached, and
	// PartialReason says why it stopped.
	Partial       bool   `json:"partial"`
	PartialReason string `json:"partial_reason,omitempty"`
}

// severityRank orders the severities of the checks, the gravest first;
// a severity the list does not know goes last.
var severityRank = map[string]int{
	compliance.SeverityHigh: 0, compliance.SeverityMedium: 1, compliance.SeverityLow: 2, compliance.SeverityInfo: 3,
}

// securityReport judges every host of the filter with the built-in checks, a
// page of hosts at a time, and tallies the findings by check and by severity.
func (s *Server) securityReport(ctx context.Context, request reportRequest, principal authz.Principal) (*securitySummary, error) {
	filter := hosts.ListFilter{
		Site: request.site, Environment: request.environment,
		Scopes: principal.ScopesFor(authz.PermSecurityRead),
	}
	checks := map[string]*checkSummary{}
	order := make([]string, 0, len(compliance.Checks))
	for _, check := range compliance.Checks {
		checks[check.ID] = &checkSummary{CheckID: check.ID, Title: check.Title, Severity: check.Severity}
		order = append(order, check.ID)
	}
	summary := &securitySummary{BySeverity: []severityView{}, Checks: []checkSummary{}, EvaluatedAt: request.generatedAt}
	sweep, err := s.sweepFleet(ctx, filter, "", "", complianceModules(),
		func(host hosts.Host, fragments []inventory.Fragment) bool {
			summary.Hosts++
			failed := false
			report := compliance.Evaluate(host.ID, hostInput(host, fragments), request.generatedAt)
			for _, finding := range report.Findings {
				check, ok := checks[finding.CheckID]
				if !ok {
					continue
				}
				check.add(finding)
				if finding.Applicable && !finding.Unknown && !finding.Passed {
					failed = true
				}
			}
			if failed {
				summary.HostsWithFindings++
			}
			return true
		})
	if err != nil {
		return nil, err
	}
	summary.Partial, summary.PartialReason = sweep.Partial, sweep.Reason
	severities := map[string]*severityView{}
	for _, id := range order {
		check := checks[id]
		summary.Checks = append(summary.Checks, *check)
		view, ok := severities[check.Severity]
		if !ok {
			view = &severityView{Severity: check.Severity}
			severities[check.Severity] = view
		}
		view.Checks++
		view.Failed += check.Failed
		view.Passed += check.Passed
		view.Unknown += check.Unknown
		view.NotApplicable += check.NotApplicable
	}
	for _, view := range severities {
		summary.BySeverity = append(summary.BySeverity, *view)
	}
	sortBySeverity(summary.BySeverity, func(view severityView) string { return view.Severity })
	sortBySeverity(summary.Checks, func(check checkSummary) string { return check.Severity })
	return summary, nil
}

// sortBySeverity orders the rows the gravest severity first and keeps the
// order of the rows within one severity.
func sortBySeverity[T any](rows []T, severity func(T) string) {
	rank := func(row T) int {
		if r, ok := severityRank[severity(row)]; ok {
			return r
		}
		return len(severityRank)
	}
	sort.SliceStable(rows, func(i, j int) bool { return rank(rows[i]) < rank(rows[j]) })
}

// The compliance of the fleet: the policies with their hosts by verdict at the
// end of the period, the hosts in drift, and the findings of the security
// checks.
func (s *Server) handleComplianceReport(w http.ResponseWriter, r *http.Request) {
	principal, ok := s.authorizeCollection(w, r, authz.PermHostRead, "report")
	if !ok {
		return
	}
	request, ok := s.parseReportRequest(w, r)
	if !ok {
		return
	}
	seesPolicies := principal.CanAnywhere(authz.PermPolicyRead)
	seesSecurity := principal.CanAnywhere(authz.PermSecurityRead)
	if request.asCSV {
		s.writeComplianceCSV(w, r, request, principal, seesPolicies, seesSecurity)
		return
	}
	var policies *reports.PolicyCompliance
	if seesPolicies {
		var err error
		policies, err = s.reportStore().Policies(r.Context(), request.period, request.filter(principal, authz.PermHostRead))
		if err != nil {
			s.fail(w, err)
			return
		}
	}
	var security *securitySummary
	if seesSecurity {
		var err error
		security, err = s.securityReport(r.Context(), request, principal)
		if err != nil {
			s.fail(w, err)
			return
		}
	}
	writeJSON(w, http.StatusOK, struct {
		reportEnvelope
		Policies *reports.PolicyCompliance `json:"policies"`
		Security *securitySummary          `json:"security"`
	}{request.envelope("compliance", principal), policies, security})
}

// The headers of the compliance files, one per section.
var (
	compliancePoliciesCSVColumns = []string{
		"policy_id", "name", "version", "enabled", "remediation_mode", "last_evaluated_at", "hosts",
		"compliant", "drift", "error", "not_applicable", "unknown", "drift_hosts",
	}
	complianceHostsCSVColumns = []string{
		"hostname", "host_id", "site", "environment", "policies_in_drift", "rules_in_drift",
	}
	complianceSecurityCSVColumns = []string{
		"check_id", "title", "severity", "failed", "passed", "unknown", "not_applicable",
	}
)

// writeComplianceCSV writes one section of the compliance report as a file:
// the policies by default, the hosts in drift, or the security checks.
func (s *Server) writeComplianceCSV(w http.ResponseWriter, r *http.Request, request reportRequest,
	principal authz.Principal, seesPolicies, seesSecurity bool) {
	section := r.URL.Query().Get("section")
	switch section {
	case "", "policies", "hosts":
		if !seesPolicies {
			problem(w, http.StatusForbidden, "permission_denied", "missing permission policy.read in any scope")
			return
		}
		report, err := s.reportStore().Policies(r.Context(), request.period, request.filter(principal, authz.PermHostRead))
		if err != nil {
			s.fail(w, err)
			return
		}
		if section == "hosts" {
			s.writeCSV(w, r, exportFileName("report-compliance-hosts", request.generatedAt), complianceHostsCSVColumns,
				func(yield func([]string) bool) error {
					for _, host := range report.DriftHosts {
						if !yield([]string{host.Hostname, host.HostID, host.Site, host.Environment,
							strconv.Itoa(host.Policies), strconv.Itoa(host.Rules)}) {
							return nil
						}
					}
					return nil
				})
			return
		}
		s.writeCSV(w, r, exportFileName("report-compliance-policies", request.generatedAt), compliancePoliciesCSVColumns,
			func(yield func([]string) bool) error {
				for _, row := range report.Policies {
					names := make([]string, 0, len(row.DriftHosts))
					for _, host := range row.DriftHosts {
						names = append(names, host.Hostname)
					}
					if !yield([]string{
						row.ID, row.Name, strconv.Itoa(row.Version), strconv.FormatBool(row.Enabled), row.RemediationMode,
						formatTime(row.LastEvaluatedAt), strconv.Itoa(row.Hosts), strconv.Itoa(row.Compliant),
						strconv.Itoa(row.Drift), strconv.Itoa(row.Error), strconv.Itoa(row.NotApplicable),
						strconv.Itoa(row.Unknown), csvList(names),
					}) {
						return nil
					}
				}
				return nil
			})
	case "security":
		if !seesSecurity {
			problem(w, http.StatusForbidden, "permission_denied", "missing permission security.read in any scope")
			return
		}
		summary, err := s.securityReport(r.Context(), request, principal)
		if err != nil {
			s.fail(w, err)
			return
		}
		if summary.Partial {
			// Every check has its row; the counts in them cover only the hosts the
			// sweep reached, and a file that did not say so would be filed as the
			// compliance of the whole fleet.
			markPartial(w)
		}
		s.writeCSV(w, r, exportFileName("report-compliance-security", request.generatedAt), complianceSecurityCSVColumns,
			func(yield func([]string) bool) error {
				for _, check := range summary.Checks {
					if !yield([]string{
						check.CheckID, check.Title, check.Severity, strconv.Itoa(check.Failed), strconv.Itoa(check.Passed),
						strconv.Itoa(check.Unknown), strconv.Itoa(check.NotApplicable),
					}) {
						return nil
					}
				}
				return nil
			})
	default:
		problem(w, http.StatusBadRequest, "invalid_section", "section is policies, hosts or security")
	}
}
