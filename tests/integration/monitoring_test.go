//go:build integration

package integration

import (
	"net/http"
	"strings"
	"testing"
	"time"
)

const monitoringReason = "integration test of the monitoring module"

type metricsPointView struct {
	At          time.Time `json:"at"`
	CPUPercent  float64   `json:"cpu_percent"`
	Load1       float64   `json:"load1"`
	MemoryUsed  uint64    `json:"memory_used"`
	MemoryTotal uint64    `json:"memory_total"`
	Filesystems []struct {
		Mount      string `json:"mount"`
		UsedBytes  uint64 `json:"used_bytes"`
		TotalBytes uint64 `json:"total_bytes"`
	} `json:"filesystems"`
	Interfaces []struct {
		Name             string  `json:"name"`
		RxBytesPerSecond float64 `json:"rx_bytes_per_second"`
	} `json:"interfaces"`
}

type hostMetricsView struct {
	HostID                  string             `json:"host_id"`
	Range                   string             `json:"range"`
	StepSeconds             int                `json:"step_seconds"`
	Points                  []metricsPointView `json:"points"`
	Latest                  *metricsPointView  `json:"latest"`
	LastSampleAt            *time.Time         `json:"last_sample_at"`
	SamplingIntervalSeconds int                `json:"sampling_interval_seconds"`
	Source                  string             `json:"source"`
}

type alertView struct {
	ID         string     `json:"id"`
	RuleID     string     `json:"rule_id"`
	RuleName   string     `json:"rule_name"`
	Metric     string     `json:"metric"`
	Severity   string     `json:"severity"`
	State      string     `json:"state"`
	Value      float64    `json:"value"`
	Detail     string     `json:"detail"`
	StartedAt  time.Time  `json:"started_at"`
	FiredAt    *time.Time `json:"fired_at"`
	ResolvedAt *time.Time `json:"resolved_at"`
	Silenced   bool       `json:"silenced"`
	HostID     string     `json:"host_id"`
	Hostname   string     `json:"hostname"`
}

type silenceView struct {
	ID        string     `json:"id"`
	HostID    string     `json:"host_id"`
	RuleID    string     `json:"rule_id"`
	Until     time.Time  `json:"until"`
	Reason    string     `json:"reason"`
	CreatedBy string     `json:"created_by"`
	ExpiredAt *time.Time `json:"expired_at"`
}

type hostMonitoringView struct {
	HostID        string            `json:"host_id"`
	LastSampleAt  *time.Time        `json:"last_sample_at"`
	Latest        *metricsPointView `json:"latest"`
	Alerts        []alertView       `json:"alerts"`
	Silences      []silenceView     `json:"silences"`
	RulesMatching int               `json:"rules_matching"`
}

type alertRuleView struct {
	ID         string  `json:"id"`
	Name       string  `json:"name"`
	Metric     string  `json:"metric"`
	Operator   string  `json:"operator"`
	Threshold  float64 `json:"threshold"`
	ForMinutes int     `json:"for_minutes"`
	Severity   string  `json:"severity"`
	Selector   struct {
		HostIDs []string `json:"host_ids"`
	} `json:"selector"`
	Enabled   bool   `json:"enabled"`
	CreatedBy string `json:"created_by"`
}

type fleetMonitoringView struct {
	Firing []alertView `json:"firing"`
	Counts struct {
		Critical int `json:"critical"`
		Warning  int `json:"warning"`
		Info     int `json:"info"`
		Silenced int `json:"silenced"`
		Pending  int `json:"pending"`
	} `json:"counts"`
	HostsReporting int       `json:"hosts_reporting"`
	HostsSilent    int       `json:"hosts_silent"`
	Rules          int       `json:"rules"`
	GeneratedAt    time.Time `json:"generated_at"`
}

type probeResultView struct {
	Kind           string `json:"kind"`
	Target         string `json:"target"`
	Reachable      bool   `json:"reachable"`
	Passed         bool   `json:"passed"`
	StatusCode     *int   `json:"status_code"`
	DurationMillis int64  `json:"duration_millis"`
	Error          string `json:"error"`
}

// hostMonitoring reads the monitoring tab of a host.
func hostMonitoring(h *harness, hostID string) hostMonitoringView {
	h.t.Helper()
	var view hostMonitoringView
	h.get("/api/v1/hosts/"+hostID+"/monitoring", &view)
	return view
}

// awaitSample waits until the host has sent a resource sample. The agent
// samples once a minute, so a host that just connected needs a moment.
func awaitSample(h *harness, hostID string, limit time.Duration) hostMonitoringView {
	h.t.Helper()
	deadline := time.Now().Add(limit)
	for {
		view := hostMonitoring(h, hostID)
		if view.LastSampleAt != nil {
			return view
		}
		if time.Now().After(deadline) {
			h.t.Fatalf("host %s sent no resource sample within %s", hostID, limit)
		}
		time.Sleep(5 * time.Second)
	}
}

// awaitAlert waits until the host has an alert of the rule in the given
// state.
func awaitAlert(h *harness, hostID, ruleID, state string, limit time.Duration) alertView {
	h.t.Helper()
	deadline := time.Now().Add(limit)
	for {
		for _, alert := range hostMonitoring(h, hostID).Alerts {
			if alert.RuleID == ruleID && alert.State == state {
				return alert
			}
		}
		if time.Now().After(deadline) {
			h.t.Fatalf("host %s got no %s alert of rule %s within %s", hostID, state, ruleID, limit)
		}
		time.Sleep(5 * time.Second)
	}
}

// TestHostReportsItsOwnMetrics guards the property the built-in monitoring
// rests on: the agent samples the host itself, and the panel answers with
// the charts without any system in between.
func TestHostReportsItsOwnMetrics(t *testing.T) {
	h := newHarness(t)
	host := h.hostByFamily("debian")
	tab := awaitSample(h, host.ID, 2*time.Minute)
	if tab.Latest == nil || tab.Latest.MemoryTotal == 0 {
		t.Fatalf("the tab has a sample time but no sample: %+v", tab)
	}

	var metrics hostMetricsView
	h.get("/api/v1/hosts/"+host.ID+"/metrics?range=3h", &metrics)
	if metrics.Range != "3h" || metrics.StepSeconds != 60 || metrics.Source != "agent" ||
		metrics.SamplingIntervalSeconds != 60 {
		t.Errorf("the chart describes itself as %+v", metrics)
	}
	if len(metrics.Points) == 0 {
		t.Fatal("the chart has no points although the host sampled")
	}
	last := metrics.Points[len(metrics.Points)-1]
	if last.MemoryTotal == 0 || last.MemoryUsed == 0 || last.MemoryUsed > last.MemoryTotal {
		t.Errorf("the last point has memory %d of %d", last.MemoryUsed, last.MemoryTotal)
	}
	if last.CPUPercent < 0 || last.CPUPercent > 100 {
		t.Errorf("the last point has cpu_percent %v", last.CPUPercent)
	}
	rootSeen := false
	for _, fs := range last.Filesystems {
		if fs.Mount == "/" && fs.TotalBytes > 0 && fs.UsedBytes > 0 {
			rootSeen = true
		}
	}
	if !rootSeen {
		t.Errorf("the last point does not describe the root filesystem: %+v", last.Filesystems)
	}
	if metrics.Latest == nil || metrics.LastSampleAt == nil {
		t.Error("the chart does not say when the host last sampled")
	}

	// The long windows answer with rollups: a different step, the same
	// shape.
	var month hostMetricsView
	h.get("/api/v1/hosts/"+host.ID+"/metrics?range=30d", &month)
	if month.StepSeconds != 900 || month.Range != "30d" {
		t.Errorf("the month window describes itself as range %s, step %d", month.Range, month.StepSeconds)
	}
	h.do(http.MethodGet, "/api/v1/hosts/"+host.ID+"/metrics?range=1y", nil, nil, http.StatusBadRequest)

	// The fleet view knows the host reports.
	var fleet fleetMonitoringView
	h.get("/api/v1/monitoring", &fleet)
	if fleet.HostsReporting == 0 {
		t.Errorf("the fleet view counts no reporting host: %+v", fleet)
	}
	if fleet.Rules == 0 {
		t.Error("the installation has no enabled rules; the defaults were not seeded")
	}
}

// TestAlertRuleFiresSilencesAndResolves walks an alert through its life: a
// rule that always holds fires on its host at once, a silence keeps it out
// of the on-call view without hiding it, and removing the rule resolves
// it.
func TestAlertRuleFiresSilencesAndResolves(t *testing.T) {
	h := newHarness(t)
	host := h.hostByFamily("debian")
	awaitSample(h, host.ID, 2*time.Minute)

	// A rule nobody would write for real - the CPU is always above minus
	// one - scoped to this one host so the rest of the fleet stays quiet.
	var rule alertRuleView
	h.do(http.MethodPost, "/api/v1/monitoring/rules", map[string]any{
		"name": "integration: cpu above -1", "metric": "cpu_percent", "operator": "gt",
		"threshold": -1, "for_minutes": 0, "severity": "info",
		"selector": map[string]any{"host_ids": []string{host.ID}},
	}, &rule, http.StatusCreated)
	if rule.ID == "" || !rule.Enabled || rule.CreatedBy == "" {
		t.Fatalf("the rule came back as %+v", rule)
	}
	t.Cleanup(func() {
		h.do(http.MethodDelete, "/api/v1/monitoring/rules/"+rule.ID, nil, nil, 0)
	})
	if len(rule.Selector.HostIDs) != 1 || rule.Selector.HostIDs[0] != host.ID {
		t.Errorf("the selector came back as %+v", rule.Selector)
	}

	// A rule that makes no sense is refused before it reaches the store.
	h.do(http.MethodPost, "/api/v1/monitoring/rules", map[string]any{
		"name": "broken", "metric": "temperature", "operator": "gt", "threshold": 1, "severity": "info",
	}, nil, http.StatusBadRequest)

	// The evaluator runs once a minute; the rule has an empty window, so
	// the first evaluation fires.
	fired := awaitAlert(h, host.ID, rule.ID, "firing", 3*time.Minute)
	if fired.FiredAt == nil || fired.Severity != "info" || fired.Metric != "cpu_percent" ||
		fired.Hostname != host.Hostname || fired.Value < 0 {
		t.Fatalf("the alert fired as %+v", fired)
	}
	if !strings.Contains(fired.Detail, "cpu_percent") {
		t.Errorf("the alert does not say what fired: %q", fired.Detail)
	}
	if fired.Silenced {
		t.Fatal("the alert is silenced although nobody silenced it")
	}

	var fleet fleetMonitoringView
	h.get("/api/v1/monitoring", &fleet)
	inFleet := false
	for _, alert := range fleet.Firing {
		if alert.ID == fired.ID {
			inFleet = true
		}
	}
	if !inFleet || fleet.Counts.Info == 0 {
		t.Errorf("the fleet view does not show the firing alert: %+v", fleet)
	}
	var history struct {
		Items []alertView `json:"items"`
	}
	h.get("/api/v1/monitoring/alerts?host_id="+host.ID+"&state=firing", &history)
	if len(history.Items) == 0 || history.Items[0].HostID != host.ID {
		t.Errorf("the history does not list the alert: %+v", history.Items)
	}

	// A silence needs a deadline within a day and a readable reason.
	h.do(http.MethodPost, "/api/v1/hosts/"+host.ID+"/monitoring/silences",
		map[string]any{"minutes": 60, "reason": "short"}, nil, http.StatusBadRequest)
	h.do(http.MethodPost, "/api/v1/hosts/"+host.ID+"/monitoring/silences",
		map[string]any{"minutes": 60 * 48, "reason": monitoringReason}, nil, http.StatusBadRequest)

	var silence silenceView
	h.do(http.MethodPost, "/api/v1/hosts/"+host.ID+"/monitoring/silences",
		map[string]any{"minutes": 30, "reason": monitoringReason, "rule_id": rule.ID},
		&silence, http.StatusCreated)
	if silence.ID == "" || silence.CreatedBy == "" || silence.HostID != host.ID || silence.RuleID != rule.ID {
		t.Fatalf("the silence came back as %+v", silence)
	}
	t.Cleanup(func() {
		h.do(http.MethodDelete,
			"/api/v1/hosts/"+host.ID+"/monitoring/silences/"+silence.ID, nil, nil, 0)
	})

	// The alert keeps firing, marked as silenced; the tab lists the silence.
	silenced := hostMonitoring(h, host.ID)
	found := false
	for _, alert := range silenced.Alerts {
		if alert.ID == fired.ID {
			found = true
			if alert.State != "firing" || !alert.Silenced {
				t.Errorf("the silenced alert is %s, silenced %v", alert.State, alert.Silenced)
			}
		}
	}
	if !found {
		t.Fatalf("the alert vanished from the tab after the silence: %+v", silenced.Alerts)
	}
	listed := false
	for _, entry := range silenced.Silences {
		if entry.ID == silence.ID {
			listed = true
		}
	}
	if !listed {
		t.Errorf("the tab does not list the silence: %+v", silenced.Silences)
	}
	var silences struct {
		Items []silenceView `json:"items"`
	}
	h.get("/api/v1/monitoring/silences", &silences)
	listed = false
	for _, entry := range silences.Items {
		if entry.ID == silence.ID {
			listed = true
		}
	}
	if !listed {
		t.Errorf("the fleet does not list the silence: %+v", silences.Items)
	}

	// Ending the silence early is a decision too, and the alert shows
	// again in the on-call view.
	h.do(http.MethodDelete,
		"/api/v1/hosts/"+host.ID+"/monitoring/silences/"+silence.ID, nil, nil, http.StatusNoContent)
	h.do(http.MethodDelete,
		"/api/v1/hosts/"+host.ID+"/monitoring/silences/"+silence.ID, nil, nil, http.StatusNotFound)
	for _, alert := range hostMonitoring(h, host.ID).Alerts {
		if alert.ID == fired.ID && alert.Silenced {
			t.Error("the alert is still silenced after the silence ended")
		}
	}

	// Removing the rule resolves what it raised; the alert stays as history.
	h.do(http.MethodDelete, "/api/v1/monitoring/rules/"+rule.ID, nil, nil, http.StatusNoContent)
	h.do(http.MethodGet, "/api/v1/monitoring/rules/"+rule.ID, nil, nil, http.StatusNotFound)
	resolved := false
	for _, alert := range hostMonitoring(h, host.ID).Alerts {
		if alert.ID == fired.ID {
			resolved = alert.State == "resolved" && alert.ResolvedAt != nil
		}
	}
	if !resolved {
		t.Fatal("the alert did not resolve when its rule was removed")
	}
}

// TestProbeSaysWhatTheHostSees guards the distinction that is the whole
// value of a probe: the operation succeeded and the service does not answer
// - that is not the same as an operation that failed.
func TestProbeSaysWhatTheHostSees(t *testing.T) {
	h := newHarness(t)
	host := h.hostByFamily("debian")

	// A probe to the panel: the host sees it, so the answer is to agree.
	job, attempts := h.runOperation(host.ID, map[string]any{
		"action": "monitoring.probe.run", "reason": monitoringReason,
		"payload": map[string]any{"monitoring": map[string]any{
			"kind": "http", "target": envOr("FLOTESTRO_TEST_API", defaultAPI) + "/healthz",
			"expect_body": "ok",
		}},
	}, 3*time.Minute)
	if job.State != "succeeded" {
		t.Fatalf("the probe ended in state %s: %+v", job.State, attempts)
	}
	result := probeResult(t, h, job.ID)
	if !result.Reachable || !result.Passed {
		t.Fatalf("the probe to the panel described as %+v", result)
	}

	// A closed port: the job succeeds, and the answer says "does not work".
	closed, attempts := h.runOperation(host.ID, map[string]any{
		"action": "monitoring.probe.run", "reason": monitoringReason,
		"payload": map[string]any{"monitoring": map[string]any{
			"kind": "tcp", "target": "127.0.0.1:9", "timeout_seconds": 3,
		}},
	}, 3*time.Minute)
	if closed.State != "succeeded" {
		t.Fatalf("the probe to a closed port ended in state %s: %+v",
			closed.State, attempts)
	}
	closedResult := probeResult(t, h, closed.ID)
	if closedResult.Reachable || closedResult.Error == "" {
		t.Fatalf("the closed port described as %+v", closedResult)
	}
	if len(attempts) > 0 && !strings.Contains(attempts[len(attempts)-1].Message, "does not answer") {
		t.Errorf("the message does not say the service does not answer: %q",
			attempts[len(attempts)-1].Message)
	}

	// A probe is not a way to read host files with somebody else's hands.
	h.do(http.MethodPost, "/api/v1/hosts/"+host.ID+"/operations", map[string]any{
		"action": "monitoring.probe.run", "reason": monitoringReason,
		"payload": map[string]any{"monitoring": map[string]any{
			"kind": "http", "target": "file:///etc/shadow",
		}},
	}, nil, http.StatusBadRequest)
}

// probeResult reads the probe result from the last attempt of the job.
func probeResult(t *testing.T, h *harness, jobID string) probeResultView {
	t.Helper()
	var result struct {
		Items []struct {
			Detail struct {
				Probe probeResultView `json:"probe"`
			} `json:"detail"`
		} `json:"items"`
	}
	h.get("/api/v1/jobs/"+jobID+"/attempts", &result)
	if len(result.Items) == 0 {
		t.Fatalf("job %s has no attempts", jobID)
	}
	return result.Items[len(result.Items)-1].Detail.Probe
}
