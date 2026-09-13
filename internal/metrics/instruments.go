package metrics

import (
	"fmt"
	"sort"
	"strings"
	"sync"
)

// The instruments measured at the point of the event, as opposed to the
// series computed from the database at scrape time. A histogram cannot be
// reconstructed after the fact: buckets computed from a table would describe
// a distribution nobody measured. So the code that dispatches, plans and
// grants records the observation itself, and the collector renders it.
//
// The instruments live in the process, hence per panel instance; the
// gateway label of the build info tells the instances apart.

// DurationBuckets covers everything from a sub-second dispatch to an
// hour-long transaction.
var DurationBuckets = []float64{0.1, 0.5, 1, 2, 5, 10, 30, 60, 120, 300, 600, 1800, 3600}

// Registry keeps the instruments of one process.
type Registry struct {
	mu         sync.Mutex
	counters   []*Counter
	histograms []*Histogram
}

// Default is the registry of this process.
var Default = &Registry{}

// Counter counts events by label values.
type Counter struct {
	name, help string
	labels     []string
	mu         sync.Mutex
	values     map[string]float64
}

// Histogram observes values by label values into fixed buckets.
type Histogram struct {
	name, help string
	labels     []string
	buckets    []float64
	mu         sync.Mutex
	series     map[string]*histogramSeries
}

type histogramSeries struct {
	counts []float64
	sum    float64
	count  float64
}

// NewCounter registers a counter.
func (r *Registry) NewCounter(name, help string, labels ...string) *Counter {
	c := &Counter{name: name, help: help, labels: labels, values: map[string]float64{}}
	r.mu.Lock()
	r.counters = append(r.counters, c)
	r.mu.Unlock()
	return c
}

// NewHistogram registers a histogram.
func (r *Registry) NewHistogram(name, help string, buckets []float64, labels ...string) *Histogram {
	h := &Histogram{name: name, help: help, labels: labels, buckets: buckets,
		series: map[string]*histogramSeries{}}
	r.mu.Lock()
	r.histograms = append(r.histograms, h)
	r.mu.Unlock()
	return h
}

// Inc adds one to the series of the given label values.
func (c *Counter) Inc(values ...string) {
	c.mu.Lock()
	c.values[key(values)]++
	c.mu.Unlock()
}

// Observe records one value in the series of the given label values.
func (h *Histogram) Observe(value float64, values ...string) {
	if value < 0 {
		// A negative duration is a clock that went back, not an
		// observation of the thing being measured.
		return
	}
	h.mu.Lock()
	defer h.mu.Unlock()
	k := key(values)
	s := h.series[k]
	if s == nil {
		s = &histogramSeries{counts: make([]float64, len(h.buckets))}
		h.series[k] = s
	}
	for i, upper := range h.buckets {
		if value <= upper {
			s.counts[i]++
		}
	}
	s.sum += value
	s.count++
}

// key joins the label values; the separator cannot occur in a label value
// because escape takes care of it at render time, not here, so a value with
// the separator would only merge two series - it never breaks the format.
func key(values []string) string { return strings.Join(values, "\x00") }

func splitKey(k string) []string {
	if k == "" {
		return nil
	}
	return strings.Split(k, "\x00")
}

// render writes the instruments in the exposition format.
func (r *Registry) render(b *strings.Builder) {
	r.mu.Lock()
	counters := append([]*Counter(nil), r.counters...)
	histograms := append([]*Histogram(nil), r.histograms...)
	r.mu.Unlock()

	for _, c := range counters {
		c.mu.Lock()
		keys := make([]string, 0, len(c.values))
		for k := range c.values {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		fmt.Fprintf(b, "# HELP %s %s\n# TYPE %s counter\n", c.name, c.help, c.name)
		for _, k := range keys {
			fmt.Fprintf(b, "%s%s %g\n", c.name, labelSet(c.labels, splitKey(k), "", 0), c.values[k])
		}
		c.mu.Unlock()
	}
	for _, h := range histograms {
		h.mu.Lock()
		keys := make([]string, 0, len(h.series))
		for k := range h.series {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		fmt.Fprintf(b, "# HELP %s %s\n# TYPE %s histogram\n", h.name, h.help, h.name)
		for _, k := range keys {
			s := h.series[k]
			values := splitKey(k)
			for i, upper := range h.buckets {
				fmt.Fprintf(b, "%s_bucket%s %g\n", h.name,
					labelSet(h.labels, values, "le", upper), s.counts[i])
			}
			fmt.Fprintf(b, "%s_bucket%s %g\n", h.name, labelSetInf(h.labels, values), s.count)
			fmt.Fprintf(b, "%s_sum%s %g\n", h.name, labelSet(h.labels, values, "", 0), s.sum)
			fmt.Fprintf(b, "%s_count%s %g\n", h.name, labelSet(h.labels, values, "", 0), s.count)
		}
		h.mu.Unlock()
	}
}

// labelSet renders the label pairs, with an optional trailing le bound.
func labelSet(names, values []string, extra string, bound float64) string {
	parts := make([]string, 0, len(names)+1)
	for i, name := range names {
		value := ""
		if i < len(values) {
			value = values[i]
		}
		parts = append(parts, fmt.Sprintf("%s=%q", name, escape(value)))
	}
	if extra != "" {
		parts = append(parts, fmt.Sprintf("%s=\"%g\"", extra, bound))
	}
	if len(parts) == 0 {
		return ""
	}
	return "{" + strings.Join(parts, ",") + "}"
}

func labelSetInf(names, values []string) string {
	set := labelSet(names, values, "", 0)
	if set == "" {
		return `{le="+Inf"}`
	}
	return strings.TrimSuffix(set, "}") + `,le="+Inf"}`
}

// The instruments of the campaign machinery, named as the document lists
// them.
var (
	// JobDispatch counts the hand-overs of tasks to agents by outcome.
	JobDispatch = Default.NewCounter("flotestro_job_dispatch_total",
		"Tasks handed to agents, by outcome and gateway.", "outcome", "gateway")
	// AgentTaskDuration measures the time from the hand-over to the result.
	AgentTaskDuration = Default.NewHistogram("flotestro_agent_task_duration_seconds",
		"Time from handing a task to the agent to its result, by operation and outcome.",
		DurationBuckets, "action", "outcome")
	// PlanStale counts the changes refused because the state moved after the plan.
	PlanStale = Default.NewCounter("flotestro_plan_stale_total",
		"Changes refused because the host state moved after the plan, by operation and reason.",
		"action", "reason")
	// PlannerDuration measures the planning of one host in a campaign.
	PlannerDuration = Default.NewHistogram("flotestro_planner_duration_seconds",
		"Time from ordering a host plan to its result, by operation and result.",
		DurationBuckets, "action", "result")
	// TargetStateDuration measures how long a campaign target spent in a state it left.
	TargetStateDuration = Default.NewHistogram("flotestro_target_state_duration_seconds",
		"Time a campaign target spent in a state before leaving it, by state and operation.",
		DurationBuckets, "state", "action")
	// BudgetWait measures the wait for capacity that ended in a grant.
	BudgetWait = Default.NewHistogram("flotestro_budget_wait_seconds",
		"Wait for budget capacity that ended in a grant, by class and site.",
		DurationBuckets, "class", "site")
)
