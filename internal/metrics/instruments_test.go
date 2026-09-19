package metrics

import (
	"strings"
	"testing"
)

// A histogram renders every bucket, +Inf, the sum and the count for each
// series - the shape Prometheus expects.
func TestHistogramRendersTheExpositionShape(t *testing.T) {
	r := &Registry{}
	h := r.NewHistogram("test_duration_seconds", "Test.", []float64{1, 10}, "action")
	h.Observe(0.5, "unit.restart")
	h.Observe(5, "unit.restart")
	h.Observe(50, "unit.restart")
	h.Observe(-1, "unit.restart") // a clock that went back is no observation
	c := r.NewCounter("test_total", "Test.", "outcome")
	c.Inc("ok")
	c.Inc("ok")

	var b strings.Builder
	r.render(&b)
	out := b.String()
	for _, line := range []string{
		`# TYPE test_total counter`,
		`test_total{outcome="ok"} 2`,
		`# TYPE test_duration_seconds histogram`,
		`test_duration_seconds_bucket{action="unit.restart",le="1"} 1`,
		`test_duration_seconds_bucket{action="unit.restart",le="10"} 2`,
		`test_duration_seconds_bucket{action="unit.restart",le="+Inf"} 3`,
		`test_duration_seconds_sum{action="unit.restart"} 55.5`,
		`test_duration_seconds_count{action="unit.restart"} 3`,
	} {
		if !strings.Contains(out, line+"\n") {
			t.Errorf("missing line %q in:\n%s", line, out)
		}
	}
}

// A counter adds counts as well as events, and never goes down: a pass that
// held back a batch reports the batch, and nothing reports a negative one.
func TestCounterAddsCountsAndOnlyGoesUp(t *testing.T) {
	r := &Registry{}
	c := r.NewCounter("test_held_total", "Test.", "gateway")
	c.Add(7, "gw-a")
	c.Inc("gw-a")
	c.Add(0, "gw-a")
	c.Add(-3, "gw-a")

	var b strings.Builder
	r.render(&b)
	if !strings.Contains(b.String(), `test_held_total{gateway="gw-a"} 8`+"\n") {
		t.Errorf("the counter rendered:\n%s", b.String())
	}
}

// The buckets are cumulative and their bound is inclusive: an observation
// exactly on a bound belongs to that bucket and to every wider one. A
// percentile read off these counts is only right if this is.
func TestTheBucketsAreCumulativeAndInclusive(t *testing.T) {
	r := &Registry{}
	h := r.NewHistogram("test_ack_seconds", "Test.", AckBuckets, "status")
	for _, value := range []float64{0.05, 0.06, 0.25, 0.7, 90} {
		h.Observe(value, "persisted")
	}

	var b strings.Builder
	r.render(&b)
	out := b.String()
	for _, line := range []string{
		// 0.05 falls on the first bound and is counted there.
		`test_ack_seconds_bucket{status="persisted",le="0.05"} 1`,
		`test_ack_seconds_bucket{status="persisted",le="0.1"} 2`,
		`test_ack_seconds_bucket{status="persisted",le="0.25"} 3`,
		`test_ack_seconds_bucket{status="persisted",le="0.5"} 3`,
		`test_ack_seconds_bucket{status="persisted",le="1"} 4`,
		// Past the widest bound only +Inf counts it, and the count agrees.
		`test_ack_seconds_bucket{status="persisted",le="60"} 4`,
		`test_ack_seconds_bucket{status="persisted",le="+Inf"} 5`,
		`test_ack_seconds_count{status="persisted"} 5`,
	} {
		if !strings.Contains(out, line+"\n") {
			t.Errorf("missing line %q in:\n%s", line, out)
		}
	}
}

// Each label value is its own series: a rejected sample must not raise the
// tail of the persisted ones.
func TestTheSeriesOfAHistogramDoNotMix(t *testing.T) {
	r := &Registry{}
	h := r.NewHistogram("test_split_seconds", "Test.", []float64{1}, "status")
	h.Observe(0.5, "persisted")
	h.Observe(30, "rejected")

	var b strings.Builder
	r.render(&b)
	out := b.String()
	for _, line := range []string{
		`test_split_seconds_bucket{status="persisted",le="1"} 1`,
		`test_split_seconds_count{status="persisted"} 1`,
		`test_split_seconds_bucket{status="rejected",le="1"} 0`,
		`test_split_seconds_sum{status="rejected"} 30`,
	} {
		if !strings.Contains(out, line+"\n") {
			t.Errorf("missing line %q in:\n%s", line, out)
		}
	}
}

// The gateway instruments the chapter asks for are registered on the default
// registry with the buckets of an acknowledgement.
func TestTheGatewayLatencyInstrumentsAreRegistered(t *testing.T) {
	SampleAck.Observe(0.2, "persisted")
	HeartbeatApply.Observe(0.2, "applied")

	var b strings.Builder
	Default.render(&b)
	out := b.String()
	for _, line := range []string{
		"# TYPE flotestro_metric_sample_ack_seconds histogram",
		`flotestro_metric_sample_ack_seconds_bucket{status="persisted",le="0.25"} 1`,
		"# TYPE flotestro_heartbeat_seconds histogram",
		`flotestro_heartbeat_seconds_bucket{outcome="applied",le="0.25"} 1`,
	} {
		if !strings.Contains(out, line+"\n") {
			t.Errorf("missing line %q in:\n%s", line, out)
		}
	}
}
