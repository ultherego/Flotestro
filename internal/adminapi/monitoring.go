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
	s.route(mux, "GET /api/v1/monitoring/silences", s.handleListSilences)
	// The host view: its charts, its alerts and its silences.
	s.route(mux, "GET /api/v1/hosts/{id}/metrics", s.handleHostMetrics)
	s.route(mux, "GET /api/v1/hosts/{id}/monitoring", s.handleHostMonitoring)
	s.route(mux, "POST /api/v1/hosts/{id}/monitoring/silences", s.handleCreateSilence)
	s.route(mux, "DELETE /api/v1/hosts/{id}/monitoring/silences/{silence}", s.handleExpireSilence)
}

// monitoringEnabled refuses the request when the installation runs without
// the monitoring store. That is a configuration of the panel rather than a
// failure, so the answer says so instead of an internal error.
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
	// Range is the window the points cover, and StepSeconds the distance
	// between them: the sampling interval for the short windows, a
	// quarter-hour for the long ones.
	Range       string             `json:"range"`
	StepSeconds int                `json:"step_seconds"`
	Points      []monitoring.Point `json:"points"`
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
		Points: series.Points, Latest: series.Latest, LastSampleAt: series.LastSampleAt,
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
	writeJSON(w, http.StatusOK, hostMonitoringView{
		HostID: hostID, LastSampleAt: lastSampleAt, Latest: latest,
		Alerts: alerts, Silences: silences, RulesMatching: matching,
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
	// Pending counts the episodes whose window is still filling.
	Pending int `json:"pending"`
}

// fleetMonitoringView is the answer of the fleet view.
type fleetMonitoringView struct {
	Firing []monitoring.Alert `json:"firing"`
	Counts alertCounts        `json:"counts"`
	// HostsReporting counts the hosts that sent a sample within the last
	// three intervals, HostsSilent those that did not - a silent host has
	// no charts and no sample rules, only host_offline.
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
//
// Alerts work fleet-wide by nature: one bad change is visible at once on
// dozens of hosts. The view is narrowed to the hosts this operator may
// see, so the operator of one environment reads their own alarms rather
// than the whole fleet's.
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
	default:
		s.fail(w, err)
	}
	return true
}

// handleCreateAlertRule records a rule. A rule is fleet-wide policy, so it
// takes the write permission in the global scope: a rule scoped to one
// site by its selector still decides what that site alarms on.
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
		problem(w, http.StatusBadRequest, "invalid_rule", err.Error())
		return
	}
	created, err := s.monitoring.CreateRule(r.Context(), rule)
	if err != nil {
		s.fail(w, err)
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
		problem(w, http.StatusBadRequest, "invalid_rule", err.Error())
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
	limit, _ := strconv.Atoi(query.Get("limit"))
	alerts, err := s.monitoring.ListAlerts(r.Context(), monitoring.AlertFilter{
		State:    query.Get("state"),
		Severity: query.Get("severity"),
		HostID:   query.Get("host_id"),
		Scopes:   principal.ScopesFor(authz.PermMonitoringRead),
		Limit:    limit,
	})
	if err != nil {
		s.fail(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"items": alerts, "count": len(alerts)})
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
	writeJSON(w, http.StatusOK, map[string]any{"items": silences, "count": len(silences)})
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
}

// defaultSilence is the length of a silence ordered without one.
const defaultSilence = time.Hour

// handleCreateSilence creates a silence of the host alerts.
//
// This is not an operation on the host and does not go through opspec: it
// changes what the panel thinks about the host, not the machine state -
// just like a maintenance window. But it is a decision to switch a sensor
// off, so it has its own permission, a mandatory end, a mandatory reason
// and an audit trail.
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
	now := time.Now().UTC()
	silence := monitoring.Silence{
		HostID: hostID, RuleID: strings.TrimSpace(request.RuleID),
		Until: now.Add(length), Reason: request.Reason, CreatedBy: principal.Subject,
	}
	if err := monitoring.ValidateSilence(silence, now); err != nil {
		problem(w, http.StatusBadRequest, "invalid_silence", err.Error())
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
		},
	})
	writeJSON(w, http.StatusCreated, created)
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
