package metrics

import (
	"fmt"
	"sort"
	"strings"
	"sync"
)

// The instruments measured at the point of the event, as opposed to the series
// computed from the database at scrape time.

// DurationBuckets covers everything from a sub-second dispatch to an
// hour-long transaction.
var DurationBuckets = []float64{0.1, 0.5, 1, 2, 5, 10, 30, 60, 120, 300, 600, 1800, 3600}

// AckBuckets covers an acknowledgement: a round trip on a healthy stream is
// well under a second, and the dispatch lease is a minute, so the buckets are
var AckBuckets = []float64{0.05, 0.1, 0.25, 0.5, 1, 2, 5, 10, 30, 60}

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
func (c *Counter) Inc(values ...string) { c.Add(1, values...) }

// Add adds a count to the series of the given label values: one event that
// stands for many, like a pass that held back a batch.
func (c *Counter) Add(count float64, values ...string) {
	if count <= 0 {
		return
	}
	c.mu.Lock()
	c.values[key(values)] += count
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
	// DispatchThrottled counts the queued jobs a pass of the scheduler left in
	// the queue because the dispatch rate had no token for them.
	DispatchThrottled = Default.NewCounter("flotestro_dispatch_throttled_total",
		"Queued jobs held back by the dispatch rate, by gateway.", "gateway")
	// DuplicateIdentity counts the sessions opened while another session
	// of the same certificate, on a different boot, was still alive.
	DuplicateIdentity = Default.NewCounter("flotestro_duplicate_identity_total",
		"Sessions opened while the same identity was alive on a different boot, by gateway.", "gateway")
	// BudgetWait measures the wait for capacity that ended in a grant.
	BudgetWait = Default.NewHistogram("flotestro_budget_wait_seconds",
		"Wait for budget capacity that ended in a grant, by class and site.",
		DurationBuckets, "class", "site")
	// TaskAck measures the time from handing a task to the agent to the agent's
	// word that it holds it.
	TaskAck = Default.NewHistogram("flotestro_task_ack_seconds",
		"Time from handing a task to the agent to its acceptance, by operation.",
		AckBuckets, "action")
	// ResourceLockWait measures how long a task waited on its host for a resource
	// another task held, from the acceptance to the start.
	ResourceLockWait = Default.NewHistogram("flotestro_resource_lock_wait_seconds",
		"Time a task waited on its host for a resource held by another task, by operation.",
		DurationBuckets, "action")
	// SampleAck measures the time from taking a resource sample off the stream
	// to the word the panel sends back about it. At fleet cadence this is the
	SampleAck = Default.NewHistogram("flotestro_metric_sample_ack_seconds",
		"Time from taking a resource sample off the stream to acknowledging it, by status.",
		AckBuckets, "status")
	// HeartbeatApply measures the time to apply one heartbeat of a host: the
	// health it carries and the mark on its session.
	HeartbeatApply = Default.NewHistogram("flotestro_heartbeat_seconds",
		"Time to apply a host heartbeat, by outcome.",
		AckBuckets, "outcome")

	// AgentReconnect counts the sessions opened by a host whose previous session
	// ended within the last ten minutes: a link that flaps or an agent that
	AgentReconnect = Default.NewCounter("flotestro_agent_reconnect_total",
		"Agent sessions opened within ten minutes of the host's previous session ending, by host family.",
		"host_family")
	// RelaySessionIdentity counts the sessions opened through a relay by how the
	// host was identified: end_to_end, when the host signed its envelope and the
	RelaySessionIdentity = Default.NewCounter("flotestro_relay_session_identity_total",
		"Agent sessions opened through a relay, by the strength of the host's identity.",
		"strength")
	// RelayEnvelopeRefusal counts the relayed messages and calls whose identity
	// envelope was refused, by the refusal code: relay_envelope_invalid,
	RelayEnvelopeRefusal = Default.NewCounter("flotestro_relay_envelope_refusal_total",
		"Relayed messages whose identity envelope was refused, by code.",
		"code")
	// RelayEnvelopeRedelivery counts the relayed messages the panel had consumed
	// already and the relay carried a second time because it never saw the
	RelayEnvelopeRedelivery = Default.NewCounter("flotestro_relay_envelope_redelivery_total",
		"Relayed messages carried again after the panel had already consumed them.")
	// AgentRenewal counts the certificate renewals by how they ended. The gateway
	// increments it where the renewal is settled (renewal.
	AgentRenewal = Default.NewCounter("flotestro_agent_renewal_total",
		"Agent certificate renewals, by outcome.", "outcome")
	// SessionFence counts what the session ownership fence refused or held, by
	// outcome: delivery_held when the scheduler kept a task in the queue because
	SessionFence = Default.NewCounter("flotestro_session_fence_total",
		"Writes refused and tasks held by the session ownership fence, by outcome.", "outcome")
	// NotificationDeliveries counts the settled attempts of the notification
	// queue by the state they settled in: delivered, retry_wait, dead_letter.
	NotificationDeliveries = Default.NewCounter("flotestro_notification_deliveries_total",
		"Settled attempts of the notification queue, by the state they settled in.", "state")
	// AlertFence counts the writes of the alert state the evaluator's fencing
	// token refused, by the write refused: start, fire, refresh, restart,
	AlertFence = Default.NewCounter("flotestro_alert_fence_refused_total",
		"Writes of the alert state refused because the instance no longer holds the evaluator lease, by the write refused.",
		"write")
)
