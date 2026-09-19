package adminapi

import (
	"encoding/json"
	"errors"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/ultherego/flotestro/internal/audit"
	"github.com/ultherego/flotestro/internal/authz"
	"github.com/ultherego/flotestro/internal/monitoring"
	"github.com/ultherego/flotestro/internal/opspec"
	"github.com/ultherego/flotestro/internal/selector"
)

// SetMonitoring attaches the built-in monitoring: the samples the agents
// send, the rules evaluated over them, the alerts and the silences.
func (s *Server) SetMonitoring(store *monitoring.Store) { s.monitoring = store }

// monitoringRoutes registers the monitoring endpoints.
func (s *Server) monitoringRoutes(mux *http.ServeMux) {
	// The fleet view: what is firing now, who reports and who went quiet.
	s.route(mux, "GET /api/v1/monitoring", s.handleFleetMonitoring)
	// The rules are fleet-wide policy: reading them goes with reading the
	// alerts, writing them has a permission of its own.
	s.route(mux, "GET /api/v1/monitoring/rules", s.handleListAlertRules)
	s.route(mux, "POST /api/v1/monitoring/rules", s.handleCreateAlertRule)
	s.route(mux, "GET /api/v1/monitoring/rules/{id}", s.handleGetAlertRule)
	s.route(mux, "PUT /api/v1/monitoring/rules/{id}", s.handleUpdateAlertRule)
	s.route(mux, "DELETE /api/v1/monitoring/rules/{id}", s.handleDeleteAlertRule)
	s.route(mux, "GET /api/v1/monitoring/alerts", s.handleListAlerts)
	// Taking an alert and writing on it: the sensor stays on, the counts
	// of what waits for a person leave it out.
	s.route(mux, "POST /api/v1/monitoring/alerts/{id}/acknowledge", s.handleAcknowledgeAlert)
	s.route(mux, "POST /api/v1/monitoring/alerts/{id}/annotate", s.handleAnnotateAlert)
	s.route(mux, "GET /api/v1/monitoring/silences", s.handleListSilences)
	// A silence that names no host covers every host, so it is written and
	// ended with the permission over the whole installation.
	s.route(mux, "POST /api/v1/monitoring/silences", s.handleCreateFleetSilence)
	s.route(mux, "DELETE /api/v1/monitoring/silences/{silence}", s.handleExpireFleetSilence)
	// The host view: its charts, its alerts and its silences.
	s.route(mux, "GET /api/v1/hosts/{id}/metrics", s.handleHostMetrics)
	s.route(mux, "GET /api/v1/hosts/{id}/monitoring", s.handleHostMonitoring)
	s.route(mux, "POST /api/v1/hosts/{id}/monitoring/silences", s.handleCreateSilence)
	s.route(mux, "DELETE /api/v1/hosts/{id}/monitoring/silences/{silence}", s.handleExpireSilence)
}

// monitoringEnabled refuses the request when the installation runs without the
// monitoring store.
func (s *Server) monitoringEnabled(w http.ResponseWriter) bool {
	if s.monitoring == nil {
		problem(w, http.StatusServiceUnavailable, "monitoring_disabled",
			"this installation runs without the built-in monitoring")
		return false
	}
	return true
}

// hostMetricsView is the answer of the chart endpoint.
type hostMetricsView struct {
	HostID string `json:"host_id"`
	// Range is the window the points cover, and StepSeconds the distance between
	// them: the sampling interval for the short windows, a quarter-hour for the
	Range       string             `json:"range"`
	StepSeconds int                `json:"step_seconds"`
	Points      []monitoring.Point `json:"points"`
	// Gaps are the stretches of the window with no reading at all, each with
	// the typed code of the refusal that explains it where there is one. A
	Gaps []monitoring.Gap `json:"gaps"`
	// Latest is the newest raw sample whatever the range; nil for a host
	// that never sent one.
	Latest       *monitoring.Point `json:"latest"`
	LastSampleAt *time.Time        `json:"last_sample_at"`
	// SamplingIntervalSeconds is how often the agent samples; Source says
	// where the samples come from.
	SamplingIntervalSeconds int    `json:"sampling_interval_seconds"`
	Source                  string `json:"source"`
}

// handleHostMetrics returns the chart points of a host over a range.
func (s *Server) handleHostMetrics(w http.ResponseWriter, r *http.Request) {
	hostID := r.PathValue("id")
	_, scope, ok := s.hostScope(w, r, hostID)
	if !ok {
		return
	}
	if _, ok := s.authorize(w, r, authz.PermMonitoringRead, scope, "host", hostID); !ok {
		return
	}
	if !s.monitoringEnabled(w) {
		return
	}
	window, err := monitoring.ParseRange(r.URL.Query().Get("range"))
	if err != nil {
		problem(w, http.StatusBadRequest, "invalid_range", err.Error())
		return
	}
	series, err := s.monitoring.Series(r.Context(), hostID, window)
	if err != nil {
		s.fail(w, err)
		return
	}
	writeJSON(w, http.StatusOK, hostMetricsView{
		HostID: hostID, Range: window.Name, StepSeconds: int(window.Step.Seconds()),
		Points: series.Points, Gaps: series.Gaps,
		Latest: series.Latest, LastSampleAt: series.LastSampleAt,
		SamplingIntervalSeconds: int(monitoring.SamplingInterval.Seconds()),
		Source:                  "agent",
	})
}

// hostMonitoringView is the answer of the host tab.
type hostMonitoringView struct {
	HostID       string               `json:"host_id"`
	LastSampleAt *time.Time           `json:"last_sample_at"`
	Latest       *monitoring.Point    `json:"latest"`
	Alerts       []monitoring.Alert   `json:"alerts"`
	Silences     []monitoring.Silence `json:"silences"`
	// RulesMatching counts the enabled rules whose selector covers this
	// host: a host nobody watches is to say so.
	RulesMatching int `json:"rules_matching"`
	// Refused is what this host sent and the panel would not store, with the
	// typed code of each refusal. It is what tells a host with a hole in its
	Refused []monitoring.Refusal `json:"refused"`
	// ClockSubstitution is present only where the panel had to stamp this
	// host's readings with its own time.
	ClockSubstitution *monitoring.ClockSubstitution `json:"clock_substitution"`
}

// handleHostMonitoring returns the alerts, silences and latest sample of a
// host.
func (s *Server) handleHostMonitoring(w http.ResponseWriter, r *http.Request) {
	hostID := r.PathValue("id")
	_, scope, ok := s.hostScope(w, r, hostID)
	if !ok {
		return
	}
	if _, ok := s.authorize(w, r, authz.PermMonitoringRead, scope, "host", hostID); !ok {
		return
	}
	if !s.monitoringEnabled(w) {
		return
	}
	ctx := r.Context()
	latest, lastSampleAt, err := s.monitoring.Latest(ctx, hostID)
	if err != nil {
		s.fail(w, err)
		return
	}
	alerts, err := s.monitoring.HostAlerts(ctx, hostID)
	if err != nil {
		s.fail(w, err)
		return
	}
	silences, err := s.monitoring.HostSilences(ctx, hostID)
	if err != nil {
		s.fail(w, err)
		return
	}
	matching, err := s.monitoring.RulesMatching(ctx, hostID)
	if err != nil {
		s.fail(w, err)
		return
	}
	// Everything the panel still holds, not only the window of the chart: a
	// refusal from yesterday explains a hole an operator meets today.
	refused, err := s.monitoring.Refusals(ctx, hostID, time.Time{})
	if err != nil {
		s.fail(w, err)
		return
	}
	clock, err := s.monitoring.HostClock(ctx, hostID)
	if err != nil {
		s.fail(w, err)
		return
	}
	writeJSON(w, http.StatusOK, hostMonitoringView{
		HostID: hostID, LastSampleAt: lastSampleAt, Latest: latest,
		Alerts: alerts, Silences: silences, RulesMatching: matching,
		Refused: refused, ClockSubstitution: clock,
	})
}

// alertCounts summarises the open alerts for the fleet view.
type alertCounts struct {
	Critical int `json:"critical"`
	Warning  int `json:"warning"`
	Info     int `json:"info"`
	// Silenced counts the firing alerts an active silence covers; they are
	// counted in their severity as well.
	Silenced int `json:"silenced"`
	// Acknowledged counts the firing alerts somebody took.
	Acknowledged int `json:"acknowledged"`
	// NoData counts the episodes whose readings stopped under a rule that asked
	// to be told; they are not firing, so they are counted apart.
	NoData int `json:"no_data"`
	// Pending counts the episodes whose window is still filling.
	Pending int `json:"pending"`
}

// fleetMonitoringView is the answer of the fleet view.
type fleetMonitoringView struct {
	Firing []monitoring.Alert `json:"firing"`
	Counts alertCounts        `json:"counts"`
	// HostsReporting counts the hosts that sent a sample within the last three
	// intervals, HostsSilent those that did not - a silent host has no charts and
	HostsReporting int `json:"hosts_reporting"`
	HostsSilent    int `json:"hosts_silent"`
	// Rules counts the enabled rules.
	Rules int `json:"rules"`
	// AgentFootprint is what the agents cost the reporting hosts: the
	// release gate's question, answered on the fleet that runs.
	AgentFootprint monitoring.FleetFootprint `json:"agent_footprint"`
	GeneratedAt    time.Time                 `json:"generated_at"`
}

// handleFleetMonitoring returns the firing alerts of the visible fleet.
func (s *Server) handleFleetMonitoring(w http.ResponseWriter, r *http.Request) {
	principal, ok := s.authorizeCollection(w, r, authz.PermMonitoringRead, "fleet")
	if !ok {
		return
	}
	if !s.monitoringEnabled(w) {
		return
	}
	ctx := r.Context()
	scopes := principal.ScopesFor(authz.PermMonitoringRead)
	firing, err := s.monitoring.Firing(ctx, scopes)
	if err != nil {
		s.fail(w, err)
		return
	}
	view := fleetMonitoringView{Firing: firing, GeneratedAt: time.Now().UTC()}
	for _, alert := range firing {
		if alert.State == "no_data" {
			view.Counts.NoData++
			continue
		}
		if alert.Acknowledged() {
			view.Counts.Acknowledged++
			continue
		}
		switch alert.Severity {
		case "critical":
			view.Counts.Critical++
		case "warning":
			view.Counts.Warning++
		default:
			view.Counts.Info++
		}
		if alert.Silenced {
			view.Counts.Silenced++
		}
	}
	if view.Counts.Pending, err = s.monitoring.Pending(ctx, scopes); err != nil {
		s.fail(w, err)
		return
	}
	condition, args := authz.ScopeSQL(scopes, "h.site", "h.environment", 0)
	if condition == "" {
		condition = "true"
	}
	if view.HostsReporting, view.HostsSilent, err = s.monitoring.Reporting(ctx, condition, args); err != nil {
		s.fail(w, err)
		return
	}
	if view.AgentFootprint, err = s.monitoring.FleetFootprint(ctx, condition, args); err != nil {
		s.fail(w, err)
		return
	}
	rules, err := s.monitoring.ListRules(ctx)
	if err != nil {
		s.fail(w, err)
		return
	}
	for _, rule := range rules {
		if rule.Enabled {
			view.Rules++
		}
	}
	writeJSON(w, http.StatusOK, view)
}

// alertRuleRequest is the body of a rule to create or to replace.
type alertRuleRequest struct {
	Name       string              `json:"name"`
	Metric     string              `json:"metric"`
	Operator   string              `json:"operator"`
	Threshold  float64             `json:"threshold"`
	ForMinutes int                 `json:"for_minutes"`
	Severity   string              `json:"severity"`
	Selector   monitoring.Selector `json:"selector"`
	// Enabled defaults to true: a rule written down is a rule meant to
	// run.
	Enabled *bool `json:"enabled"`
	// The cadence a rule declares; a request that omits them gets the defaults,
	// which are what a rule did before they existed.
	ExpectedCadenceSeconds int    `json:"expected_cadence_seconds"`
	MaxGapSeconds          int    `json:"max_gap_seconds"`
	NoDataPolicy           string `json:"no_data_policy"`
}

func (request alertRuleRequest) rule() monitoring.Rule {
	enabled := true
	if request.Enabled != nil {
		enabled = *request.Enabled
	}
	return monitoring.Rule{
		Name: request.Name, Metric: request.Metric, Operator: request.Operator,
		Threshold: request.Threshold, ForMinutes: request.ForMinutes,
		Severity: request.Severity, Selector: request.Selector, Enabled: enabled,
		ExpectedCadenceSeconds: request.ExpectedCadenceSeconds,
		MaxGapSeconds:          request.MaxGapSeconds,
		NoDataPolicy:           request.NoDataPolicy,
	}
}

func (s *Server) handleListAlertRules(w http.ResponseWriter, r *http.Request) {
	if _, ok := s.authorizeCollection(w, r, authz.PermMonitoringRead, "alert_rule"); !ok {
		return
	}
	if !s.monitoringEnabled(w) {
		return
	}
	rules, err := s.monitoring.ListRules(r.Context())
	if err != nil {
		s.fail(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"items": rules, "count": len(rules),
		// The vocabulary of a rule, so the form does not carry a copy; the
		// catalogue adds the unit and a description to each metric name.
		"metrics": monitoring.Metrics, "catalogue": monitoring.Catalogue,
		"operators": monitoring.Operators, "severities": monitoring.Severities,
		"no_data_policies": monitoring.NoDataPolicies,
	})
}

func (s *Server) handleGetAlertRule(w http.ResponseWriter, r *http.Request) {
	if _, ok := s.authorizeCollection(w, r, authz.PermMonitoringRead, "alert_rule"); !ok {
		return
	}
	if !s.monitoringEnabled(w) {
		return
	}
	rule, err := s.monitoring.GetRule(r.Context(), r.PathValue("id"))
	if s.ruleProblem(w, err) {
		return
	}
	writeJSON(w, http.StatusOK, rule)
}

// ruleProblem answers a store error of the rules; true when it did.
func (s *Server) ruleProblem(w http.ResponseWriter, err error) bool {
	switch {
	case err == nil:
		return false
	case errors.Is(err, monitoring.ErrNotFound):
		problem(w, http.StatusNotFound, "rule_not_found", "no such alert rule")
	case errors.Is(err, selector.ErrInvalid), errors.Is(err, selector.ErrUnknownGroup),
		errors.Is(err, selector.ErrCycle):
		s.selectorProblem(w, err)
	default:
		s.fail(w, err)
	}
	return true
}

// handleCreateAlertRule records a rule.
func (s *Server) handleCreateAlertRule(w http.ResponseWriter, r *http.Request) {
	principal, ok := s.authorize(w, r, authz.PermMonitoringRulesWrite, authz.GlobalScope, "alert_rule", "")
	if !ok {
		return
	}
	if !s.monitoringEnabled(w) {
		return
	}
	var request alertRuleRequest
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<16)).Decode(&request); err != nil {
		problem(w, http.StatusBadRequest, "invalid_body", "the request body is not valid JSON")
		return
	}
	rule := request.rule()
	rule.CreatedBy = principal.Subject
	if err := rule.Validate(); err != nil {
		problem(w, http.StatusBadRequest, ruleRefusal(err), err.Error())
		return
	}
	created, err := s.monitoring.CreateRule(r.Context(), rule)
	if s.ruleProblem(w, err) {
		return
	}
	s.audit.Record(r.Context(), audit.Event{
		ActorType: audit.ActorUser, ActorID: principal.Subject,
		Action: "monitoring.rule.create", TargetType: "alert_rule", TargetID: created.ID,
		RequestID: requestIDOf(r), Outcome: audit.OutcomeSuccess,
		Detail: ruleDetail(*created),
	})
	writeJSON(w, http.StatusCreated, created)
}

func (s *Server) handleUpdateAlertRule(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	principal, ok := s.authorize(w, r, authz.PermMonitoringRulesWrite, authz.GlobalScope, "alert_rule", id)
	if !ok {
		return
	}
	if !s.monitoringEnabled(w) {
		return
	}
	var request alertRuleRequest
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<16)).Decode(&request); err != nil {
		problem(w, http.StatusBadRequest, "invalid_body", "the request body is not valid JSON")
		return
	}
	rule := request.rule()
	if err := rule.Validate(); err != nil {
		problem(w, http.StatusBadRequest, ruleRefusal(err), err.Error())
		return
	}
	updated, err := s.monitoring.UpdateRule(r.Context(), id, rule)
	if s.ruleProblem(w, err) {
		return
	}
	s.audit.Record(r.Context(), audit.Event{
		ActorType: audit.ActorUser, ActorID: principal.Subject,
		Action: "monitoring.rule.update", TargetType: "alert_rule", TargetID: id,
		RequestID: requestIDOf(r), Outcome: audit.OutcomeSuccess,
		Detail: ruleDetail(*updated),
	})
	writeJSON(w, http.StatusOK, updated)
}

func (s *Server) handleDeleteAlertRule(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	principal, ok := s.authorize(w, r, authz.PermMonitoringRulesWrite, authz.GlobalScope, "alert_rule", id)
	if !ok {
		return
	}
	if !s.monitoringEnabled(w) {
		return
	}
	rule, err := s.monitoring.GetRule(r.Context(), id)
	if s.ruleProblem(w, err) {
		return
	}
	if err := s.monitoring.DeleteRule(r.Context(), id); s.ruleProblem(w, err) {
		return
	}
	s.audit.Record(r.Context(), audit.Event{
		ActorType: audit.ActorUser, ActorID: principal.Subject,
		Action: "monitoring.rule.delete", TargetType: "alert_rule", TargetID: id,
		RequestID: requestIDOf(r), Outcome: audit.OutcomeSuccess,
		Detail: ruleDetail(*rule),
	})
	w.WriteHeader(http.StatusNoContent)
}

// ruleDetail is what the trail records about a rule: enough to read what
// the fleet alarmed on at the time without the rule row.
func ruleDetail(rule monitoring.Rule) map[string]any {
	return map[string]any{
		"name": rule.Name, "metric": rule.Metric, "operator": rule.Operator,
		"threshold": rule.Threshold, "for_minutes": rule.ForMinutes,
		"severity": rule.Severity, "selector": rule.Selector, "enabled": rule.Enabled,
		"expected_cadence_seconds": rule.ExpectedCadenceSeconds,
		"max_gap_seconds":          rule.MaxGapSeconds,
		"no_data_policy":           rule.NoDataPolicy,
	}
}

// handleListAlerts returns the alert history, newest first.
func (s *Server) handleListAlerts(w http.ResponseWriter, r *http.Request) {
	principal, ok := s.authorizeCollection(w, r, authz.PermMonitoringRead, "fleet")
	if !ok {
		return
	}
	if !s.monitoringEnabled(w) {
		return
	}
	query := r.URL.Query()
	asCSV, ok := exportFormat(w, r)
	if !ok {
		return
	}
	limit, _ := strconv.Atoi(query.Get("limit"))
	if asCSV {
		// The file takes the most the store hands out at once, whatever the screen
		// asked for: the alert history has no cursor, so the export is the newest
		limit = alertHistoryCeiling
	}
	var acknowledged *bool
	switch query.Get("acknowledged") {
	case "true":
		acknowledged = new(bool)
		*acknowledged = true
	case "false":
		acknowledged = new(bool)
	}
	alerts, err := s.monitoring.ListAlerts(r.Context(), monitoring.AlertFilter{
		State:        query.Get("state"),
		Severity:     query.Get("severity"),
		HostID:       query.Get("host_id"),
		Scopes:       principal.ScopesFor(authz.PermMonitoringRead),
		Acknowledged: acknowledged,
		Limit:        limit,
	})
	if err != nil {
		s.fail(w, err)
		return
	}
	if asCSV {
		s.writeAlertsCSV(w, r, alerts)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"items": alerts, "count": len(alerts)})
}

// alertHistoryCeiling is the most alerts the store lists in one answer,
// and so the most an export carries.
const alertHistoryCeiling = 500

// alertsCSVColumns is the header of the alert export. The order is fixed:
// a sheet built against one export reads the next one.
var alertsCSVColumns = []string{
	"id", "hostname", "host_id", "rule_name", "rule_id", "metric", "severity", "state", "value", "detail",
	"started_at", "fired_at", "resolved_at", "silenced", "acknowledged_by", "acknowledged_at", "note",
}

// writeAlertsCSV streams the alert history as a file, newest first as the
// screen lists it, with the same state, severity and host filter.
func (s *Server) writeAlertsCSV(w http.ResponseWriter, r *http.Request, alerts []monitoring.Alert) {
	s.writeCSV(w, r, exportFileName("alerts", time.Now()), alertsCSVColumns, func(yield func([]string) bool) error {
		for _, alert := range alerts {
			if !yield(alertCSVRow(alert)) {
				return nil
			}
		}
		return nil
	})
}

// alertCSVRow renders one alert in the order of alertsCSVColumns. An
// alert that never fired has no fired_at; one still open no resolved_at.
func alertCSVRow(alert monitoring.Alert) []string {
	return []string{
		alert.ID, alert.Hostname, alert.HostID, alert.RuleName, alert.RuleID, alert.Metric, alert.Severity, alert.State,
		csvFloat(alert.Value), alert.Detail, csvInstant(alert.StartedAt), formatTime(alert.FiredAt),
		formatTime(alert.ResolvedAt), strconv.FormatBool(alert.Silenced),
		alert.AcknowledgedBy, formatTime(alert.AcknowledgedAt), alert.Note,
	}
}

// alertNoteRequest is the body of an acknowledgement or a note.
type alertNoteRequest struct {
	Note string `json:"note"`
	// Reason is accepted in place of the note, so a client that sends
	// every mutation the same way is not refused.
	Reason string `json:"reason"`
}

func (request alertNoteRequest) text() string {
	if strings.TrimSpace(request.Note) != "" {
		return strings.TrimSpace(request.Note)
	}
	return strings.TrimSpace(request.Reason)
}

// maxAlertNote bounds a note: a longer one is a report, not a note.
const maxAlertNote = 2000

// alertForWrite reads the alert and checks the permission of taking it in the
// scope of its host.
func (s *Server) alertForWrite(w http.ResponseWriter, r *http.Request) (*monitoring.Alert, authz.Principal, bool) {
	id := r.PathValue("id")
	alert, err := s.monitoring.Alert(r.Context(), id)
	if errors.Is(err, monitoring.ErrNotFound) {
		problem(w, http.StatusNotFound, "alert_not_found", "no such alert")
		return nil, authz.Principal{}, false
	}
	if err != nil {
		s.fail(w, err)
		return nil, authz.Principal{}, false
	}
	_, scope, ok := s.hostScope(w, r, alert.HostID)
	if !ok {
		return nil, authz.Principal{}, false
	}
	principal, ok := s.authorize(w, r, authz.PermMonitoringSilence, scope, "alert", id)
	if !ok {
		return nil, authz.Principal{}, false
	}
	return alert, principal, true
}

// readAlertNote decodes the body of an acknowledgement or a note; the
// answer has been written when the second result is false.
func readAlertNote(w http.ResponseWriter, r *http.Request) (alertNoteRequest, bool) {
	var request alertNoteRequest
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<16)).Decode(&request); err != nil {
		problem(w, http.StatusBadRequest, "invalid_body", "the request body is not valid JSON")
		return request, false
	}
	if len([]rune(request.text())) > maxAlertNote {
		problem(w, http.StatusBadRequest, "note_too_long",
			"a note has at most "+strconv.Itoa(maxAlertNote)+" characters")
		return request, false
	}
	return request, true
}

// handleAcknowledgeAlert marks a firing alert as taken by the caller.
func (s *Server) handleAcknowledgeAlert(w http.ResponseWriter, r *http.Request) {
	if !s.monitoringEnabled(w) {
		return
	}
	alert, principal, ok := s.alertForWrite(w, r)
	if !ok {
		return
	}
	request, ok := readAlertNote(w, r)
	if !ok {
		return
	}
	note := request.text()
	if len([]rune(note)) < minimalStepUpReason {
		problem(w, http.StatusBadRequest, "reason_required",
			"an acknowledgement needs a note (field note, min. 8 characters): what is being done about the alert")
		return
	}
	updated, err := s.monitoring.Acknowledge(r.Context(), alert.ID, principal.Subject, note)
	switch {
	case errors.Is(err, monitoring.ErrNotFiring):
		problem(w, http.StatusConflict, "alert_not_firing",
			"only a firing alert can be taken; this one is "+alert.State)
		return
	case errors.Is(err, monitoring.ErrNotFound):
		problem(w, http.StatusNotFound, "alert_not_found", "no such alert")
		return
	case err != nil:
		s.fail(w, err)
		return
	}
	s.audit.Record(r.Context(), audit.Event{
		ActorType: audit.ActorUser, ActorID: principal.Subject,
		Action: "monitoring.alert.acknowledge", TargetType: "host", TargetID: alert.HostID,
		RequestID: requestIDOf(r), Outcome: audit.OutcomeSuccess,
		Detail: map[string]any{
			"alert_id": alert.ID, "rule_id": alert.RuleID, "rule_name": alert.RuleName,
			"severity": alert.Severity, "note": note, "previously_by": alert.AcknowledgedBy,
		},
	})
	writeJSON(w, http.StatusOK, updated)
}

// handleAnnotateAlert writes a note on an alert of any state.
func (s *Server) handleAnnotateAlert(w http.ResponseWriter, r *http.Request) {
	if !s.monitoringEnabled(w) {
		return
	}
	alert, principal, ok := s.alertForWrite(w, r)
	if !ok {
		return
	}
	request, ok := readAlertNote(w, r)
	if !ok {
		return
	}
	note := request.text()
	updated, err := s.monitoring.Annotate(r.Context(), alert.ID, note)
	if errors.Is(err, monitoring.ErrNotFound) {
		problem(w, http.StatusNotFound, "alert_not_found", "no such alert")
		return
	}
	if err != nil {
		s.fail(w, err)
		return
	}
	s.audit.Record(r.Context(), audit.Event{
		ActorType: audit.ActorUser, ActorID: principal.Subject,
		Action: "monitoring.alert.annotate", TargetType: "host", TargetID: alert.HostID,
		RequestID: requestIDOf(r), Outcome: audit.OutcomeSuccess,
		Detail: map[string]any{
			"alert_id": alert.ID, "rule_id": alert.RuleID, "rule_name": alert.RuleName,
			"note": note, "previous_note": alert.Note,
		},
	})
	writeJSON(w, http.StatusOK, updated)
}

// handleListSilences returns the silences in force on the visible hosts.
func (s *Server) handleListSilences(w http.ResponseWriter, r *http.Request) {
	principal, ok := s.authorizeCollection(w, r, authz.PermMonitoringRead, "fleet")
	if !ok {
		return
	}
	if !s.monitoringEnabled(w) {
		return
	}
	silences, err := s.monitoring.ActiveSilences(r.Context(), principal.ScopesFor(authz.PermMonitoringRead))
	if err != nil {
		s.fail(w, err)
		return
	}
	// The panel offers the global switch only to whoever may actually flip it;
	// the endpoint refuses it anyway, this only keeps the form honest.
	writeJSON(w, http.StatusOK, map[string]any{
		"items": silences, "count": len(silences),
		"can_silence_fleet":  principal.Can(authz.PermMonitoringSilence, authz.GlobalScope),
		"can_silence_global": globalSilenceAllowed(principal),
	})
}

// silenceRequest describes a silence ordered from the panel.
type silenceRequest struct {
	Reason string `json:"reason"`
	// Minutes is the length counted from now; zero means an hour. An
	// open-ended silence cannot be ordered here.
	Minutes int `json:"minutes"`
	// RuleID narrows the silence to one rule. Empty means every alert of
	// this host.
	RuleID string `json:"rule_id,omitempty"`
	// Global asks for the silence that may keep back the security alerts of
	// the installation; it names no host and no rule, and it needs the right
	Global bool `json:"global,omitempty"`
	// SendSummary asks for one message per channel when the silence ends,
	// naming what it kept back.
	SendSummary bool `json:"send_summary,omitempty"`
}

// globalSilenceAllowed says whether the principal may write a silence that
// keeps back the security alerts of the installation. Managing the
func globalSilenceAllowed(principal authz.Principal) bool {
	return principal.Can(authz.PermNotificationManage, authz.GlobalScope)
}

// refuseGlobalSilence answers a global silence nobody may write. Fail-closed:
// the caller stops here.
func (s *Server) refuseGlobalSilence(w http.ResponseWriter, r *http.Request,
	principal authz.Principal, targetType, targetID string) {
	s.audit.Record(r.Context(), audit.Event{
		ActorType: audit.ActorUser, ActorID: principal.Subject,
		Action: "monitoring.silence.create", TargetType: targetType, TargetID: targetID,
		RequestID: requestIDOf(r), Outcome: audit.OutcomeDenied,
		Detail: map[string]any{
			"reason": monitoring.RefusalGlobalSilenceDenied, "global": true,
			"permission": string(authz.PermNotificationManage),
			"scope":      authz.GlobalScope.String(), "roles": principal.Roles(),
		},
	})
	problem(w, http.StatusForbidden, monitoring.RefusalGlobalSilenceDenied,
		"a global silence may keep back the security alerts of the installation: it needs "+
			string(authz.PermNotificationManage)+" over the whole installation, not over one site")
}

// silenceRefusal names a refused silence: a typed refusal keeps its own code,
// and a plain validation error stays invalid_silence, as it always was.
func ruleRefusal(err error) string {
	var refusal *opspec.RefusalError
	if errors.As(err, &refusal) {
		return refusal.Code
	}
	return "invalid_rule"
}

func silenceRefusal(err error) string {
	var refusal *opspec.RefusalError
	if errors.As(err, &refusal) {
		return refusal.Code
	}
	return "invalid_silence"
}

// defaultSilence is the length of a silence ordered without one.
const defaultSilence = time.Hour

// handleCreateSilence creates a silence of the host alerts.
func (s *Server) handleCreateSilence(w http.ResponseWriter, r *http.Request) {
	hostID := r.PathValue("id")
	_, scope, ok := s.hostScope(w, r, hostID)
	if !ok {
		return
	}
	principal, ok := s.authorize(w, r, authz.PermMonitoringSilence, scope, "host", hostID)
	if !ok {
		return
	}
	if !s.monitoringEnabled(w) {
		return
	}
	var request silenceRequest
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<16)).Decode(&request); err != nil {
		problem(w, http.StatusBadRequest, "invalid_body", "the request body is not valid JSON")
		return
	}
	length := time.Duration(request.Minutes) * time.Minute
	if request.Minutes == 0 {
		length = defaultSilence
	}
	// The right to blind the security alerts is asked for before the shape of
	// the silence is judged: whoever may not have it learns nothing else.
	if request.Global && !globalSilenceAllowed(principal) {
		s.refuseGlobalSilence(w, r, principal, "host", hostID)
		return
	}
	now := time.Now().UTC()
	silence := monitoring.Silence{
		HostID: hostID, RuleID: strings.TrimSpace(request.RuleID),
		Until: now.Add(length), Reason: request.Reason, Global: request.Global,
		SendSummary: request.SendSummary, CreatedBy: principal.Subject,
	}
	if err := monitoring.ValidateSilence(silence, now); err != nil {
		problem(w, http.StatusBadRequest, silenceRefusal(err), err.Error())
		return
	}
	if silence.RuleID != "" {
		if _, err := s.monitoring.GetRule(r.Context(), silence.RuleID); s.ruleProblem(w, err) {
			return
		}
	}
	created, err := s.monitoring.CreateSilence(r.Context(), silence)
	if err != nil {
		s.fail(w, err)
		return
	}
	s.audit.Record(r.Context(), audit.Event{
		ActorType: audit.ActorUser, ActorID: principal.Subject,
		Action: "monitoring.silence.create", TargetType: "host", TargetID: hostID,
		RequestID: requestIDOf(r), Outcome: audit.OutcomeSuccess,
		Detail: map[string]any{
			"silence_id": created.ID, "until": created.Until.Format(time.RFC3339),
			"reason": created.Reason, "rule_id": created.RuleID,
			"global": created.Global, "send_summary": created.SendSummary,
		},
	})
	writeJSON(w, http.StatusCreated, created)
}

// handleCreateFleetSilence creates a silence that names no host. It covers
// every host the installation has, so it is written with the permission over
func (s *Server) handleCreateFleetSilence(w http.ResponseWriter, r *http.Request) {
	principal, ok := s.authorize(w, r, authz.PermMonitoringSilence, authz.GlobalScope, "fleet", "")
	if !ok {
		return
	}
	if !s.monitoringEnabled(w) {
		return
	}
	var request silenceRequest
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<16)).Decode(&request); err != nil {
		problem(w, http.StatusBadRequest, "invalid_body", "the request body is not valid JSON")
		return
	}
	if request.Global && !globalSilenceAllowed(principal) {
		s.refuseGlobalSilence(w, r, principal, "fleet", "")
		return
	}
	length := time.Duration(request.Minutes) * time.Minute
	if request.Minutes == 0 {
		length = defaultSilence
	}
	now := time.Now().UTC()
	silence := monitoring.Silence{
		RuleID: strings.TrimSpace(request.RuleID), Until: now.Add(length),
		Reason: request.Reason, Global: request.Global,
		SendSummary: request.SendSummary, CreatedBy: principal.Subject,
	}
	if err := monitoring.ValidateSilence(silence, now); err != nil {
		problem(w, http.StatusBadRequest, silenceRefusal(err), err.Error())
		return
	}
	if silence.RuleID != "" {
		if _, err := s.monitoring.GetRule(r.Context(), silence.RuleID); s.ruleProblem(w, err) {
			return
		}
	}
	created, err := s.monitoring.CreateSilence(r.Context(), silence)
	if err != nil {
		s.fail(w, err)
		return
	}
	s.audit.Record(r.Context(), audit.Event{
		ActorType: audit.ActorUser, ActorID: principal.Subject,
		Action: "monitoring.silence.create", TargetType: "fleet",
		RequestID: requestIDOf(r), Outcome: audit.OutcomeSuccess,
		Detail: map[string]any{
			"silence_id": created.ID, "until": created.Until.Format(time.RFC3339),
			"reason": created.Reason, "rule_id": created.RuleID,
			"global": created.Global, "send_summary": created.SendSummary,
		},
	})
	writeJSON(w, http.StatusCreated, created)
}

// handleExpireFleetSilence ends a silence that names no host early. Ending one
// only brings alerts back, so it asks for no right beyond writing it.
func (s *Server) handleExpireFleetSilence(w http.ResponseWriter, r *http.Request) {
	principal, ok := s.authorize(w, r, authz.PermMonitoringSilence, authz.GlobalScope, "fleet", "")
	if !ok {
		return
	}
	if !s.monitoringEnabled(w) {
		return
	}
	id := r.PathValue("silence")
	err := s.monitoring.ExpireFleetSilence(r.Context(), id)
	if errors.Is(err, monitoring.ErrNotFound) {
		problem(w, http.StatusNotFound, "silence_not_found",
			"no such active silence of the whole fleet; a silence of one host is ended through its host")
		return
	}
	if err != nil {
		s.fail(w, err)
		return
	}
	s.audit.Record(r.Context(), audit.Event{
		ActorType: audit.ActorUser, ActorID: principal.Subject,
		Action: "monitoring.silence.expire", TargetType: "fleet",
		RequestID: requestIDOf(r), Outcome: audit.OutcomeSuccess,
		Detail: map[string]any{"silence_id": id},
	})
	w.WriteHeader(http.StatusNoContent)
}

// handleExpireSilence ends a silence early.
func (s *Server) handleExpireSilence(w http.ResponseWriter, r *http.Request) {
	hostID := r.PathValue("id")
	_, scope, ok := s.hostScope(w, r, hostID)
	if !ok {
		return
	}
	principal, ok := s.authorize(w, r, authz.PermMonitoringSilence, scope, "host", hostID)
	if !ok {
		return
	}
	if !s.monitoringEnabled(w) {
		return
	}
	id := r.PathValue("silence")
	err := s.monitoring.ExpireSilence(r.Context(), hostID, id)
	if errors.Is(err, monitoring.ErrNotFound) {
		problem(w, http.StatusNotFound, "silence_not_found", "no such active silence of this host")
		return
	}
	if err != nil {
		s.fail(w, err)
		return
	}
	s.audit.Record(r.Context(), audit.Event{
		ActorType: audit.ActorUser, ActorID: principal.Subject,
		Action: "monitoring.silence.expire", TargetType: "host", TargetID: hostID,
		RequestID: requestIDOf(r), Outcome: audit.OutcomeSuccess,
		Detail: map[string]any{"silence_id": id},
	})
	w.WriteHeader(http.StatusNoContent)
}
