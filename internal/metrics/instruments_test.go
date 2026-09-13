package metrics

import (
	"strings"
	"testing"
)

// A histogram renders every bucket, +Inf, the sum and the count for each
// series - the shape Prometheus expects. Rendering the shape by hand is the
// point of this package, so the shape is what the test nails down.
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
