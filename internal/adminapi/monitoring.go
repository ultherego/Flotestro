package adminapi

import (
	"encoding/json"
	"net/http"
	"sort"
	"time"

	"github.com/ultherego/flotestro/internal/audit"
	"github.com/ultherego/flotestro/internal/authz"
	"github.com/ultherego/flotestro/internal/hosts"
	"github.com/ultherego/flotestro/internal/integrations"
	"github.com/ultherego/flotestro/internal/integrations/alerts"
	"github.com/ultherego/flotestro/internal/integrations/metrics"
)

// Monitoring gathers the sources the panel reads metrics and alerts from.
//
// None of them is required: an installation without monitoring works the
// same, only the monitoring tab says directly that no sources were named.
// A failure of an integration must not take host management away from the
// operator either - hence every question has a timeout and a fuse.
type Monitoring struct {
	Metrics metrics.Provider
	Alerts  alerts.Provider
	Mapping integrations.Mapping
}

// SetMonitoring attaches the monitoring integrations.
func (s *Server) SetMonitoring(monitoring Monitoring) { s.monitoring = monitoring }

// monitoringReport is the answer of the host tab.
type monitoringReport struct {
	HostID string `json:"host_id"`
	// Sources describes the source states: unconfigured, working or not
	// answering. These are three different answers.
	Sources []integrations.State `json:"sources"`
	// Label says what the panel recognises this host by at the sources.
	// Without it an empty chart has no explanation.
	Label    string             `json:"label"`
	Links    integrations.Links `json:"links"`
	Alerts   []alerts.Alert     `json:"alerts"`
	Silences []alerts.Silence   `json:"silences"`
	Series   []metrics.Series   `json:"series"`
	// From and To describe the time range of the charts: the panel shows
	// somebody else's data and says which window it comes from.
	From time.Time `json:"from"`
	To   time.Time `json:"to"`
	// AlertsUnavailable and MetricsUnavailable say why something is missing.
	AlertsUnavailable  string `json:"alerts_unavailable_reason,omitempty"`
	MetricsUnavailable string `json:"metrics_unavailable_reason,omitempty"`
}

// handleHostMonitoring returns the alerts, charts and links of a host.
func (s *Server) handleHostMonitoring(w http.ResponseWriter, r *http.Request) {
	hostID := r.PathValue("id")
	host, scope, ok := s.hostScope(w, r, hostID)
	if !ok {
		return
	}
	if _, ok := s.authorize(w, r, authz.PermMonitoringRead, scope, "host", hostID); !ok {
		return
	}

	description := describeHost(*host)
	window := s.monitoring.Mapping.WindowOr(queryWindow(r))
	to := time.Now().UTC()
	from := to.Add(-window)

	report := monitoringReport{
		HostID: hostID,
		Label:  s.monitoring.Mapping.Label(description),
		Links:  s.monitoring.Mapping.For(description),
		From:   from, To: to,
		Alerts: []alerts.Alert{}, Silences: []alerts.Silence{}, Series: []metrics.Series{},
	}
	report.Sources = s.sourceStates(r)

	if s.monitoring.Alerts != nil && s.monitoring.Alerts.Configured() {
		filter := []string{s.monitoring.Mapping.HostFilter(description)}
		if list, err := s.monitoring.Alerts.Alerts(r.Context(), filter); err != nil {
			// A failure of the alert source must not topple the tab: it is
			// said what is unknown, and the rest is shown.
			report.AlertsUnavailable = err.Error()
		} else if list != nil {
			// An empty list stays an empty list, not a missing field: the
			// interface is meant to show "nothing is burning", not "unknown".
			report.Alerts = list
		}
		if silences, err := s.monitoring.Alerts.Silences(r.Context(), filter); err != nil {
			if report.AlertsUnavailable == "" {
				report.AlertsUnavailable = err.Error()
			}
		} else if silences != nil {
			report.Silences = silences
		}
	}
	if s.monitoring.Metrics != nil && s.monitoring.Metrics.Configured() {
		report.Series = s.monitoring.Metrics.Series(r.Context(), report.Label, from, to)
	} else {
		report.MetricsUnavailable = "this installation has no metrics source configured"
	}
	writeJSON(w, http.StatusOK, report)
}

// sourceStates asks the integrations about their health.
func (s *Server) sourceStates(r *http.Request) []integrations.State {
	states := make([]integrations.State, 0, 2)
	if s.monitoring.Metrics != nil {
		states = append(states, s.monitoring.Metrics.Health(r.Context()))
	}
	if s.monitoring.Alerts != nil {
		states = append(states, s.monitoring.Alerts.Health(r.Context()))
	}
	return states
}

// queryWindow reads the time range from the query.
func queryWindow(r *http.Request) time.Duration {
	value := r.URL.Query().Get("range")
	if value == "" {
		return 0
	}
	window, err := time.ParseDuration(value)
	if err != nil || window <= 0 || window > 7*24*time.Hour {
		return 0
	}
	return window
}

func describeHost(host hosts.Host) integrations.Host {
	return integrations.Host{
		ID: host.ID, Hostname: host.Hostname, Address: host.ManagementAddress,
		Site: host.Site, Environment: host.Environment,
	}
}

// silenceRequest describes a silence ordered from the panel.
type silenceRequest struct {
	// DurationMinutes is the end counted from now. Zero means the default
	// time; an open-ended silence cannot be ordered here.
	DurationMinutes int    `json:"duration_minutes,omitempty"`
	Comment         string `json:"comment"`
	// AlertName narrows the silence to one alert. Empty means all the
	// alerts of this host.
	AlertName string `json:"alert_name,omitempty"`
}

// handleCreateSilence creates a silence of the host alerts.
//
// This is not an operation on the host and does not go through opspec: it
// changes what the alerting system thinks about the host, not the machine
// state - just like a maintenance window. But it is a decision to switch a
// sensor off, so it has its own permission, a mandatory end, a mandatory
// reason and an audit trail.
func (s *Server) handleCreateSilence(w http.ResponseWriter, r *http.Request) {
	hostID := r.PathValue("id")
	host, scope, ok := s.hostScope(w, r, hostID)
	if !ok {
		return
	}
	principal, ok := s.authorize(w, r, authz.PermMonitoringSilence, scope, "host", hostID)
	if !ok {
		return
	}
	if s.monitoring.Alerts == nil || !s.monitoring.Alerts.Configured() {
		problem(w, http.StatusServiceUnavailable, "alerts_not_configured",
			"this installation has no alert source configured")
		return
	}

	var request silenceRequest
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<16)).Decode(&request); err != nil {
		problem(w, http.StatusBadRequest, "invalid_body", "the request body is not valid JSON")
		return
	}
	duration := time.Duration(request.DurationMinutes) * time.Minute
	if duration <= 0 {
		duration = alerts.DefaultSilence
	}

	description := describeHost(*host)
	now := time.Now().UTC()
	silence := alerts.Silence{
		Matchers: []alerts.Matcher{{
			Name:  s.monitoring.Mapping.HostLabel,
			Value: s.monitoring.Mapping.Label(description),
		}},
		StartsAt: now, EndsAt: now.Add(duration),
		CreatedBy: principal.Subject, Comment: request.Comment,
	}
	if request.AlertName != "" {
		silence.Matchers = append(silence.Matchers,
			alerts.Matcher{Name: "alertname", Value: request.AlertName})
	}
	if err := alerts.ValidateSilence(silence); err != nil {
		problem(w, http.StatusBadRequest, "invalid_silence", err.Error())
		return
	}

	id, err := s.monitoring.Alerts.Silence(r.Context(), silence)
	if err != nil {
		s.audit.Record(r.Context(), audit.Event{
			ActorType: audit.ActorUser, ActorID: principal.Subject,
			Action: "monitoring.silence.create", TargetType: "host", TargetID: hostID,
			RequestID: requestIDOf(r), Outcome: audit.OutcomeFailure,
			Detail: map[string]any{"reason": err.Error()},
		})
		problem(w, http.StatusBadGateway, "alerts_unavailable", err.Error())
		return
	}
	silence.ID = id

	s.audit.Record(r.Context(), audit.Event{
		ActorType: audit.ActorUser, ActorID: principal.Subject,
		Action: "monitoring.silence.create", TargetType: "host", TargetID: hostID,
		RequestID: requestIDOf(r), Outcome: audit.OutcomeSuccess,
		Detail: map[string]any{
			"silence_id": id, "ends_at": silence.EndsAt.Format(time.RFC3339),
			"comment": silence.Comment, "alert_name": request.AlertName,
			"label": silence.Matchers[0].Name + "=" + silence.Matchers[0].Value,
		},
	})
	writeJSON(w, http.StatusCreated, silence)
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
	if s.monitoring.Alerts == nil || !s.monitoring.Alerts.Configured() {
		problem(w, http.StatusServiceUnavailable, "alerts_not_configured",
			"this installation has no alert source configured")
		return
	}
	id := r.PathValue("silence")
	if err := s.monitoring.Alerts.Unsilence(r.Context(), id); err != nil {
		problem(w, http.StatusBadGateway, "alerts_unavailable", err.Error())
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

// fleetAlert joins an alert with a panel host.
type fleetAlert struct {
	HostID   string       `json:"host_id,omitempty"`
	Hostname string       `json:"hostname,omitempty"`
	Alert    alerts.Alert `json:"alert"`
}

// handleFleetMonitoring returns the alerts of the whole visible fleet.
//
// Alerts work fleet-wide by nature: one bad change is visible at once on
// dozens of hosts. The panel adds to them what the alerting system does not
// know - which fleet host this is and whether this operator may be shown
// it.
func (s *Server) handleFleetMonitoring(w http.ResponseWriter, r *http.Request) {
	principal, ok := s.authorizeCollection(w, r, authz.PermMonitoringRead, "fleet")
	if !ok {
		return
	}
	response := map[string]any{
		"sources": s.sourceStates(r),
		"items":   []fleetAlert{},
	}
	if s.monitoring.Alerts == nil || !s.monitoring.Alerts.Configured() {
		response["alerts_unavailable_reason"] = "this installation has no alert source configured"
		writeJSON(w, http.StatusOK, response)
		return
	}

	list, err := s.hosts.List(r.Context(), hosts.ListFilter{Limit: 500})
	if err != nil {
		s.fail(w, err)
		return
	}
	byLabel := map[string]hosts.Host{}
	for _, host := range list {
		if principal.Can(authz.PermMonitoringRead, authz.Scope{Site: host.Site, Environment: host.Environment}) {
			byLabel[s.monitoring.Mapping.Label(describeHost(host))] = host
		}
	}

	all, err := s.monitoring.Alerts.Alerts(r.Context(), nil)
	if err != nil {
		response["alerts_unavailable_reason"] = err.Error()
		writeJSON(w, http.StatusOK, response)
		return
	}

	items := make([]fleetAlert, 0, len(all))
	foreign := 0
	for _, alert := range all {
		label := alert.Labels[s.monitoring.Mapping.HostLabel]
		host, known := byLabel[label]
		if !known {
			// An alert from outside the fleet or from a host this operator does
			// not see. It is not shown, but counted: silence here would look
			// like a calm fleet.
			foreign++
			continue
		}
		items = append(items, fleetAlert{
			HostID: host.ID, Hostname: host.Hostname, Alert: alert,
		})
	}
	// The most severe first, then the oldest: that is how on-call reads.
	sort.SliceStable(items, func(i, j int) bool {
		if items[i].Alert.Severity != items[j].Alert.Severity {
			return severityWeight(items[i].Alert.Severity) > severityWeight(items[j].Alert.Severity)
		}
		if items[i].Alert.StartsAt == nil || items[j].Alert.StartsAt == nil {
			return items[i].Hostname < items[j].Hostname
		}
		return items[i].Alert.StartsAt.Before(*items[j].Alert.StartsAt)
	})

	response["items"] = items
	response["hosts_visible"] = len(byLabel)
	response["alerts_outside_fleet"] = foreign
	response["host_label"] = s.monitoring.Mapping.HostLabel
	writeJSON(w, http.StatusOK, response)
}

// severityWeight orders the alerts by how urgent they are for on-call.
func severityWeight(severity string) int {
	switch severity {
	case "critical", "page":
		return 3
	case "warning":
		return 2
	case "info", "none":
		return 1
	}
	return 0
}
