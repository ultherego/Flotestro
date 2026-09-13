//go:build integration

package integration

import (
	"net/http"
	"strings"
	"testing"
	"time"
)

const monitoringReason = "integration test of the monitoring module"

type sourceView struct {
	Name          string `json:"name"`
	Configured    bool   `json:"configured"`
	Healthy       bool   `json:"healthy"`
	URL           string `json:"url"`
	Reason        string `json:"reason"`
	LatencyMillis *int64 `json:"latency_millis"`
}

type alertView struct {
	Name       string            `json:"name"`
	Severity   string            `json:"severity"`
	Summary    string            `json:"summary"`
	Labels     map[string]string `json:"labels"`
	StartsAt   *time.Time        `json:"starts_at"`
	SilencedBy []string          `json:"silenced_by"`
}

type silenceView struct {
	ID        string `json:"id"`
	EndsAt    string `json:"ends_at"`
	CreatedBy string `json:"created_by"`
	Comment   string `json:"comment"`
	Matchers  []struct {
		Name  string `json:"name"`
		Value string `json:"value"`
	} `json:"matchers"`
}

type monitoringReportView struct {
	Sources []sourceView `json:"sources"`
	Label   string       `json:"label"`
	Links   struct {
		Dashboard string `json:"dashboard"`
		Logs      string `json:"logs"`
	} `json:"links"`
	Alerts   []alertView   `json:"alerts"`
	Silences []silenceView `json:"silences"`
	Series   []struct {
		Name   string   `json:"name"`
		Last   *float64 `json:"last"`
		Query  string   `json:"query"`
		Reason string   `json:"unavailable_reason"`
		Points []struct {
			At    time.Time `json:"at"`
			Value float64   `json:"value"`
		} `json:"points"`
	} `json:"series"`
	From               time.Time `json:"from"`
	To                 time.Time `json:"to"`
	AlertsUnavailable  string    `json:"alerts_unavailable_reason"`
	MetricsUnavailable string    `json:"metrics_unavailable_reason"`
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
func hostMonitoring(h *harness, hostID string) monitoringReportView {
	h.t.Helper()
	var report monitoringReportView
	h.get("/api/v1/hosts/"+hostID+"/monitoring", &report)
	return report
}

func source(report monitoringReportView, name string) *sourceView {
	for i := range report.Sources {
		if report.Sources[i].Name == name {
			return &report.Sources[i]
		}
	}
	return nil
}

// TestMonitoringDescribesTheSourcesEvenWhenThereAreNone guards the property
// that decides whether this tab is useful: no source, a working source and
// a source that does not answer are three different answers.
func TestMonitoringDescribesTheSourcesEvenWhenThereAreNone(t *testing.T) {
	h := newHarness(t)
	host := h.hostByFamily("debian")
	report := hostMonitoring(h, host.ID)

	if len(report.Sources) != 2 {
		t.Fatalf("the panel described %d sources: %+v", len(report.Sources), report.Sources)
	}
	for _, source := range report.Sources {
		if !source.Configured && source.Reason == "" {
			t.Errorf("%s: unconfigured source without an explanation", source.Name)
		}
		if source.Configured && !source.Healthy && source.Reason == "" {
			t.Errorf("%s: a source that does not answer, without a reason", source.Name)
		}
	}
	// The label is always there: without it an empty chart has no
	// explanation.
	if report.Label == "" {
		t.Error("the panel does not say how it recognises this host at the sources")
	}
	// The time range too: the panel shows somebody else's data and says
	// from which window.
	if !report.To.After(report.From) {
		t.Errorf("time range = %s .. %s", report.From, report.To)
	}
	if metrics := source(report, "prometheus"); metrics != nil && !metrics.Configured {
		if report.MetricsUnavailable == "" {
			t.Error("no metrics source without an explanation")
		}
	}
}

// TestSilenceRequiresADeadlineAndAReason guards the rule that tells a
// silence from switching an alert off forever.
func TestSilenceRequiresADeadlineAndAReason(t *testing.T) {
	h := newHarness(t)
	host := h.hostByFamily("debian")
	report := hostMonitoring(h, host.ID)
	alerts := source(report, "alertmanager")
	if alerts == nil || !alerts.Configured {
		// An installation without an alert source refuses outright - and
		// that too is behaviour worth checking.
		h.do(http.MethodPost, "/api/v1/hosts/"+host.ID+"/monitoring/silences",
			map[string]any{"duration_minutes": 60, "comment": monitoringReason},
			nil, http.StatusServiceUnavailable)
		t.Skip("this installation has no alert source")
	}

	// A reason shorter than eight characters and a silence longer than a
	// day fall out in the panel, before anything goes to the alerting
	// system.
	h.do(http.MethodPost, "/api/v1/hosts/"+host.ID+"/monitoring/silences",
		map[string]any{"duration_minutes": 60, "comment": "short"},
		nil, http.StatusBadRequest)
	h.do(http.MethodPost, "/api/v1/hosts/"+host.ID+"/monitoring/silences",
		map[string]any{"duration_minutes": 60 * 48, "comment": monitoringReason},
		nil, http.StatusBadRequest)

	var silence silenceView
	h.do(http.MethodPost, "/api/v1/hosts/"+host.ID+"/monitoring/silences",
		map[string]any{"duration_minutes": 45, "comment": monitoringReason},
		&silence, http.StatusCreated)
	if silence.ID == "" || silence.CreatedBy == "" {
		t.Fatalf("silence without an identifier or an owner: %+v", silence)
	}
	if len(silence.Matchers) == 0 || silence.Matchers[0].Value != report.Label {
		t.Errorf("the silence does not concern this host: %+v", silence.Matchers)
	}
	t.Cleanup(func() {
		h.do(http.MethodDelete,
			"/api/v1/hosts/"+host.ID+"/monitoring/silences/"+silence.ID, nil, nil, 0)
	})

	after := hostMonitoring(h, host.ID)
	found := false
	for _, entry := range after.Silences {
		if entry.ID == silence.ID {
			found = true
		}
	}
	if !found {
		t.Fatalf("the created silence did not come back from the tab: %+v", after.Silences)
	}

	// Ending a silence early is a decision too - and leaves a trace too.
	h.do(http.MethodDelete,
		"/api/v1/hosts/"+host.ID+"/monitoring/silences/"+silence.ID, nil, nil, http.StatusNoContent)
	afterEnding := hostMonitoring(h, host.ID)
	for _, entry := range afterEnding.Silences {
		if entry.ID == silence.ID {
			t.Fatal("the ended silence still applies")
		}
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
