package metrics

import (
	"context"
	"strings"
	"testing"
	"time"
)

type sessionCounter struct{ count int }

func (l sessionCounter) Count() int { return l.count }

type certificate struct{ end time.Time }

func (c certificate) NotAfter() time.Time { return c.end }

// TestTheExpositionFormat checks conformance with the Prometheus text format:
// every metric has HELP and TYPE before its values, and the labels are
// sorted.
func TestTheExpositionFormat(t *testing.T) {
	result := render([]metric{{
		name: "flotestro_hosts", kind: "gauge", help: "The fleet's hosts.",
		samples: labelled("connection_state", map[string]float64{
			"online": 3, "offline": 1, "stale": 2,
		}),
	}})

	text := string(result)
	if !strings.HasPrefix(text, "# HELP flotestro_hosts The fleet's hosts.\n# TYPE flotestro_hosts gauge\n") {
		t.Fatalf("the metric headers are missing:\n%s", text)
	}
	expected := "" +
		`flotestro_hosts{connection_state="offline"} 1` + "\n" +
		`flotestro_hosts{connection_state="online"} 3` + "\n" +
		`flotestro_hosts{connection_state="stale"} 2` + "\n"
	if !strings.HasSuffix(text, expected) {
		t.Errorf("the values have the wrong shape or order:\n%s", text)
	}
}

// TestLabelsDoNotBreakTheFormat guards the values coming from the database.
// The state of a task is text from a column, not a constant from the code.
func TestLabelsDoNotBreakTheFormat(t *testing.T) {
	result := string(render([]metric{{
		name: "flotestro_jobs", kind: "gauge", help: "Tasks.",
		samples: []sample{{
			labels: map[string]string{"state": "odd\"state\nwith a newline"},
			value:  1,
		}},
	}}))

	if strings.Count(result, "\n") != 3 {
		t.Errorf("the label value broke the format into more lines:\n%s", result)
	}
	if !strings.Contains(result, `\"state\n`) {
		t.Errorf("the special characters were not escaped:\n%s", result)
	}
}

// TestAnUndeterminedStateIsSkipped guards the rule that a metric which could
// not be determined disappears from the answer instead of showing zero. Zero
// means a measured zero and would fire alerts describing something untrue.
func TestAnUndeterminedStateIsSkipped(t *testing.T) {
	// A collector without a database, without a session counter and without a
	// certificate: only the metrics that can be computed in the process
	// remain.
	collector := NewCollector(nil, nil, nil, "panel")
	text := string(collector.Gather(context.Background()))

	for _, absent := range []string{
		"flotestro_agent_sessions_active",
		"flotestro_ca_certificate_expires_in_seconds",
		"flotestro_hosts",
		"flotestro_job_queue_age_seconds",
	} {
		if strings.Contains(text, absent) {
			t.Errorf("the metric %s appeared although its data source is missing", absent)
		}
	}
	for _, present := range []string{"flotestro_build_info", "flotestro_goroutines"} {
		if !strings.Contains(text, present) {
			t.Errorf("the metric %s, which does not depend on the database, is missing", present)
		}
	}

	// A certificate without a determined expiry date must not give zero
	// either: zero would mean "expires now" and would raise an alarm for no
	// reason.
	withCert := NewCollector(nil, sessionCounter{count: 7}, certificate{}, "panel")
	text = string(withCert.Gather(context.Background()))
	if strings.Contains(text, "flotestro_ca_certificate_expires_in_seconds") {
		t.Error("an undetermined certificate validity was shown as a value")
	}
	if !strings.Contains(text, `flotestro_agent_sessions_active{gateway="panel"} 7`) {
		t.Errorf("the number of sessions was not exposed:\n%s", text)
	}
}

// TestTwoLabelsHaveAFixedOrder guards the series in which the state alone is
// not enough.
//
// A campaign host held back by a lack of capacity and a host without the
// required adapter are both "did not start". The reason code is what tells
// them apart, so it travels in the metric together with the state - and the
// order of the series has to be repeatable, because otherwise consecutive
// scrapes differ for no reason.
func TestTwoLabelsHaveAFixedOrder(t *testing.T) {
	result := string(render([]metric{{
		name: "flotestro_campaign_targets", kind: "gauge", help: "Campaign hosts.",
		samples: []sample{
			{labels: map[string]string{"state": "awaiting_budget", "reason_code": "budget_capacity"}, value: 3},
			{labels: map[string]string{"state": "pending", "reason_code": "none"}, value: 7},
		},
	}}))

	// The labels within one series go alphabetically, so the reason code
	// comes before the state.
	expected := "" +
		`flotestro_campaign_targets{reason_code="budget_capacity",state="awaiting_budget"} 3` + "\n" +
		`flotestro_campaign_targets{reason_code="none",state="pending"} 7` + "\n"
	if !strings.HasSuffix(result, expected) {
		t.Errorf("the series have the wrong shape or order:\n%s", result)
	}
}

// TestCapacityAndUsageAreSeparateSeries guards that a budget says at once how
// much it has and how much is taken. Usage alone does not answer the question
// whether the budget is at its limit - and that is the only question an
// operator asks when a campaign is stopped.
func TestCapacityAndUsageAreSeparateSeries(t *testing.T) {
	result := string(render([]metric{{
		name: "flotestro_budget_tokens", kind: "gauge", help: "Budget tokens.",
		samples: []sample{
			{labels: map[string]string{"budget": "site:warsaw:packages", "status": "capacity"}, value: 5},
			{labels: map[string]string{"budget": "site:warsaw:packages", "status": "used"}, value: 5},
			{labels: map[string]string{"budget": "site:warsaw:packages", "status": "waiting"}, value: 2},
		},
	}}))

	for _, fragment := range []string{`status="capacity"} 5`, `status="used"} 5`, `status="waiting"} 2`} {
		if !strings.Contains(result, fragment) {
			t.Errorf("the series %q is missing:\n%s", fragment, result)
		}
	}
}
