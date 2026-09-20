// Package metrics exposes the state of the panel in the Prometheus text
// format.
package metrics

import (
	"context"
	"fmt"
	"math"
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/ultherego/flotestro/internal/pki"
	"github.com/ultherego/flotestro/internal/relays"
)

// SessionCounter gives the number of active agent sessions of this instance.
type SessionCounter interface {
	Count() int
}

// CertificateSource gives the validity time of the CA certificate.
type CertificateSource interface {
	NotAfter() time.Time
}

// RelayHeartbeats gives the latest report of a relay about itself.
type RelayHeartbeats interface {
	LastHeartbeat(id string) (relays.Heartbeat, bool)
}

type Collector struct {
	pool     *pgxpool.Pool
	sessions SessionCounter
	ca       CertificateSource
	// authorities describes the whole trust set, if the installation manages one.
	authorities func() []pki.Authority
	// relays gives the buffer reports of the relays, if the panel keeps them.
	relays  RelayHeartbeats
	gateway string
	started time.Time
	// footprint reads what this process costs on its host; tests replace it so
	// the readers are fed fixtures instead of the running kernel.
	footprint func() Footprint
}

// WithAuthorities adds metrics for every CA in the trust set.
func (c *Collector) WithAuthorities(source func() []pki.Authority) *Collector {
	c.authorities = source
	return c
}

// WithRelays adds the buffer metrics of the relays from their heartbeats.
func (c *Collector) WithRelays(source RelayHeartbeats) *Collector {
	c.relays = source
	return c
}

func NewCollector(pool *pgxpool.Pool, sessions SessionCounter, ca CertificateSource,
	gatewayID string) *Collector {
	return &Collector{pool: pool, sessions: sessions, ca: ca,
		gateway: gatewayID, started: time.Now()}
}

// sample is a single value with labels.
type sample struct {
	labels map[string]string
	value  float64
}

// metric groups values under one name together with a description.
type metric struct {
	name    string
	help    string
	kind    string
	samples []sample
}

// Gather collects the state of the panel.
func (c *Collector) Gather(ctx context.Context) []byte {
	metrics := []metric{
		{
			name: "flotestro_build_info", kind: "gauge",
			help:    "The panel instance; the gateway label distinguishes processes in a multi-gateway installation.",
			samples: []sample{{labels: map[string]string{"gateway": c.gateway}, value: 1}},
		},
		{
			name: "flotestro_uptime_seconds", kind: "gauge",
			help:    "How long the panel process has been running.",
			samples: []sample{{value: time.Since(c.started).Seconds()}},
		},
	}

	if c.sessions != nil {
		metrics = append(metrics, metric{
			name: "flotestro_agent_sessions_active", kind: "gauge",
			help: "Agent sessions held by this instance of the panel.",
			samples: []sample{{
				labels: map[string]string{"gateway": c.gateway},
				value:  float64(c.sessions.Count()),
			}},
		})
	}

	if c.ca != nil {
		if notAfter := c.ca.NotAfter(); !notAfter.IsZero() {
			metrics = append(metrics, metric{
				name: "flotestro_ca_certificate_expires_in_seconds", kind: "gauge",
				help:    "Time until the CA signing agent certificates expires.",
				samples: []sample{{value: time.Until(notAfter).Seconds()}},
			})
		}
	}
	if c.authorities != nil {
		// A withdrawn CA has to be visible too: its expiry cuts off the hosts
		// that did not manage to move to the new one.
		var samples []sample
		for _, ca := range c.authorities() {
			samples = append(samples, sample{
				labels: map[string]string{"state": ca.State, "serial": ca.Serial},
				value:  time.Until(ca.NotAfter).Seconds(),
			})
		}
		if len(samples) > 0 {
			metrics = append(metrics, metric{
				name: "flotestro_trust_authority_expires_in_seconds", kind: "gauge",
				help:    "Time until every CA in the fleet's trust set expires.",
				samples: samples,
			})
		}
	}

	metrics = append(metrics, c.runtimeMetrics()...)
	metrics = append(metrics, c.databaseMetrics(ctx)...)
	var b strings.Builder
	b.Write(render(metrics))
	// The instruments measured at the point of the event come last: they
	// belong to this process, the rest to the database.
	Default.render(&b)
	return []byte(b.String())
}

func (c *Collector) runtimeMetrics() []metric {
	var memory runtime.MemStats
	runtime.ReadMemStats(&memory)
	result := []metric{
		{
			name: "flotestro_goroutines", kind: "gauge",
			help:    "The number of goroutines of the panel process.",
			samples: []sample{{value: float64(runtime.NumGoroutine())}},
		},
		{
			// Sys is address space the runtime has taken, not pages the host
			// holds; a node's budget is judged on the resident set instead.
			name: "flotestro_go_memory_reserved_bytes", kind: "gauge",
			help:    "Address space the Go runtime has taken from the host; the resident set is flotestro_process_resident_bytes.",
			samples: []sample{{value: float64(memory.Sys)}},
		},
		{
			name: "flotestro_gc_pause_seconds_total", kind: "counter",
			help:    "Time this process spent stopped for garbage collection since it started.",
			samples: []sample{{value: float64(memory.PauseTotalNs) / float64(time.Second)}},
		},
		{
			name: "flotestro_gc_cycles_total", kind: "counter",
			help:    "Garbage collections since the process started.",
			samples: []sample{{value: float64(memory.NumGC)}},
		},
	}
	// The percentiles describe the pauses the runtime still remembers. Before
	// the first collection there is nothing to describe, so they are left out.
	if pauses := gcPauses(&memory); len(pauses) > 0 {
		for _, rank := range []struct {
			name string
			at   float64
		}{
			{"flotestro_gc_pause_seconds_p95", 0.95},
			{"flotestro_gc_pause_seconds_p99", 0.99},
			{"flotestro_gc_pause_seconds_max", 1},
		} {
			value, ok := quantile(pauses, rank.at)
			if !ok {
				continue
			}
			result = append(result, metric{
				name: rank.name, kind: "gauge",
				help:    "Garbage collection pause over the collections the runtime still remembers.",
				samples: []sample{{value: value}},
			})
		}
	}
	return append(result, c.processMetrics()...)
}

// processMetrics are the numbers the host keeps about this process rather than
// the ones the runtime keeps about itself: the resident set, the descriptors.
func (c *Collector) processMetrics() []metric {
	read := c.footprint
	if read == nil {
		read = ReadFootprint
	}
	fp := read()

	var result []metric
	if fp.ResidentBytes != nil {
		result = append(result, metric{
			name: "flotestro_process_resident_bytes", kind: "gauge",
			help: "Resident set of the panel process as the host measures it; the source label says where the number came from.",
			samples: []sample{{
				labels: map[string]string{"source": fp.ResidentFrom},
				value:  float64(*fp.ResidentBytes),
			}},
		})
	}
	if fp.OpenFDs != nil {
		result = append(result, metric{
			name: "flotestro_process_open_fds", kind: "gauge",
			help:    "File descriptors the panel process holds; a reconnect storm that leaks leaves this number up.",
			samples: []sample{{value: float64(*fp.OpenFDs)}},
		})
	}
	if fp.MaxFDs != nil {
		result = append(result, metric{
			name: "flotestro_process_max_fds", kind: "gauge",
			help:    "The descriptor limit of the panel process; the open count alone does not say how close it is.",
			samples: []sample{{value: float64(*fp.MaxFDs)}},
		})
	}
	if fp.CPUSeconds != nil {
		result = append(result, metric{
			name: "flotestro_process_cpu_seconds_total", kind: "counter",
			help:    "CPU time the panel process has used, user and system together.",
			samples: []sample{{value: *fp.CPUSeconds}},
		})
	}
	return result
}

// gcPauses returns the garbage collection pauses the runtime remembers, in
// seconds, sorted; the runtime keeps the last 256, so that is the window.
func gcPauses(memory *runtime.MemStats) []float64 {
	ring := len(memory.PauseNs)
	count := int(memory.NumGC)
	if count > ring {
		count = ring
	}
	pauses := make([]float64, 0, count)
	for i := 0; i < count; i++ {
		// The runtime writes the ring at (NumGC+255)%256, so it is walked back
		// from the most recent collection.
		index := (int(memory.NumGC) - 1 - i + 2*ring) % ring
		pauses = append(pauses, float64(memory.PauseNs[index])/float64(time.Second))
	}
	sort.Float64s(pauses)
	return pauses
}

// quantile takes the value at the nearest rank of a sorted series, so the
// answer is an observation that really happened, never an interpolation.
func quantile(sorted []float64, at float64) (float64, bool) {
	if len(sorted) == 0 {
		return 0, false
	}
	index := int(math.Ceil(at*float64(len(sorted)))) - 1
	if index < 0 {
		index = 0
	}
	if index >= len(sorted) {
		index = len(sorted) - 1
	}
	return sorted[index], true
}

// databaseMetrics reads the state of the fleet and the queue.
func (c *Collector) databaseMetrics(ctx context.Context) []metric {
	if c.pool == nil {
		return nil
	}
	queryCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()

	var result []metric

	if grouped, err := c.groupCount(queryCtx,
		`select connection_state, count(*) from hosts group by 1`); err == nil {
		result = append(result, metric{
			name: "flotestro_hosts", kind: "gauge",
			help:    "The fleet's hosts by connection state.",
			samples: labelled("connection_state", grouped),
		})
	}

	if grouped, err := c.groupCount(queryCtx,
		`select state, count(*) from jobs where created_at > now() - interval '24 hours' group by 1`); err == nil {
		result = append(result, metric{
			name: "flotestro_jobs", kind: "gauge",
			help:    "Tasks from the last day by state.",
			samples: labelled("state", grouped),
		})
	}

	// The age of the oldest task in the queue is a signal that dispatching
	// has stopped keeping up. The number of tasks alone does not show it.
	var queueAge *float64
	if err := c.pool.QueryRow(queryCtx,
		`select extract(epoch from now() - min(created_at)) from jobs where state = 'queued'`).
		Scan(&queueAge); err == nil {
		value := 0.0
		if queueAge != nil {
			value = *queueAge
		}
		result = append(result, metric{
			name: "flotestro_job_queue_age_seconds", kind: "gauge",
			help:    "The age of the oldest task waiting to be dispatched.",
			samples: []sample{{value: value}},
		})
	}

	// We measure the dispatch latency from the creation of a task to handing it
	// over to the agent. The average hides the tail, so p95, p99 and max go too.
	var avg, max, p95, p99 *float64
	if err := c.pool.QueryRow(queryCtx, `
		select avg(extract(epoch from a.dispatched_at - j.created_at)),
		       max(extract(epoch from a.dispatched_at - j.created_at)),
		       percentile_cont(0.95) within group (order by extract(epoch from a.dispatched_at - j.created_at)),
		       percentile_cont(0.99) within group (order by extract(epoch from a.dispatched_at - j.created_at))
		from job_attempts a
		join jobs j on j.id = a.job_id
		where a.dispatched_at > now() - interval '15 minutes'`).Scan(&avg, &max, &p95, &p99); err == nil {
		for _, reading := range []struct {
			name  string
			help  string
			value *float64
		}{
			{"flotestro_dispatch_latency_seconds_avg",
				"The average time from creating a task to handing it to the agent, over the last 15 minutes.", avg},
			{"flotestro_dispatch_latency_seconds_p95",
				"The time from creating a task to handing it to the agent that 95 in 100 stayed under, over the last 15 minutes.", p95},
			{"flotestro_dispatch_latency_seconds_p99",
				"The time from creating a task to handing it to the agent that 99 in 100 stayed under, over the last 15 minutes.", p99},
			{"flotestro_dispatch_latency_seconds_max",
				"The longest time from creating a task to handing it to the agent, over the last 15 minutes.", max},
		} {
			// No task dispatched in the window leaves every reading null: a
			// quarter of an hour nothing was measured in, not a latency of zero.
			if reading.value == nil {
				continue
			}
			result = append(result, metric{
				name: reading.name, kind: "gauge", help: reading.help,
				samples: []sample{{value: *reading.value}},
			})
		}
	}

	if grouped, err := c.groupCount(queryCtx, `
		select status, count(*) from job_attempts
		where finished_at > now() - interval '24 hours' group by 1`); err == nil {
		result = append(result, metric{
			name: "flotestro_task_results", kind: "gauge",
			help:    "Task results from the last day by status.",
			samples: labelled("status", grouped),
		})
	}

	result = append(result, c.lifecycleMetrics(queryCtx)...)
	return append(result, c.campaignMetrics(queryCtx)...)
}

// lifecycleMetrics show the way into and out of the fleet: the enrollment
// orders, the certificates and their expiry, the hosts by state and by build.
func (c *Collector) lifecycleMetrics(ctx context.Context) []metric {
	var result []metric

	if grouped, err := c.groupCount(ctx,
		`select status, count(*) from enrollment_requests group by 1`); err == nil {
		result = append(result, metric{
			name: "flotestro_enrollment_requests", kind: "gauge",
			help:    "Enrollment orders by status.",
			samples: labelled("status", grouped),
		})
	}
	var pending float64
	if err := c.pool.QueryRow(ctx, `
		select count(*) from enrollment_requests
		where status = 'pending' and expires_at > now()`).Scan(&pending); err == nil {
		result = append(result, metric{
			name: "flotestro_enrollment_pending", kind: "gauge",
			help:    "Enrollment orders still valid and not yet used.",
			samples: []sample{{value: pending}},
		})
	}
	// From the order to the certificate: the time an installation takes end to
	// end, over the last day.
	var avg, max *float64
	if err := c.pool.QueryRow(ctx, `
		select avg(extract(epoch from a.completed_at - r.created_at)),
		       max(extract(epoch from a.completed_at - r.created_at))
		from enrollment_attempts a join enrollment_requests r on r.id = a.request_id
		where a.completed_at > now() - interval '24 hours'`).Scan(&avg, &max); err == nil {
		if avg != nil {
			result = append(result, metric{
				name: "flotestro_enrollment_duration_seconds_avg", kind: "gauge",
				help:    "The average time from ordering an enrollment to the certificate, over the last day.",
				samples: []sample{{value: *avg}},
			})
		}
		if max != nil {
			result = append(result, metric{
				name: "flotestro_enrollment_duration_seconds_max", kind: "gauge",
				help:    "The longest time from ordering an enrollment to the certificate, over the last day.",
				samples: []sample{{value: *max}},
			})
		}
	}

	if grouped, err := c.groupCount(ctx,
		`select lifecycle_state, count(*) from hosts group by 1`); err == nil {
		result = append(result, metric{
			name: "flotestro_hosts_lifecycle", kind: "gauge",
			help:    "The fleet's hosts by lifecycle state.",
			samples: labelled("lifecycle_state", grouped),
		})
	}
	if grouped, err := c.groupCount(ctx,
		`select coalesce(nullif(agent_version, ''), 'unknown'), count(*) from hosts
		 where lifecycle_state <> 'retired' group by 1`); err == nil {
		result = append(result, metric{
			name: "flotestro_agent_builds", kind: "gauge",
			help:    "Hosts by the version of the agent they last reported.",
			samples: labelled("agent_version", grouped),
		})
	}

	// The soonest expiry among the live certificates of hosts that are not
	// retired, and how many run out within a week and a month.
	var soonest *float64
	if err := c.pool.QueryRow(ctx, `
		select min(extract(epoch from c.not_after - now()))
		from agent_certificates c join hosts h on h.id = c.host_id
		where c.revoked_at is null and c.not_after > now() and h.lifecycle_state <> 'retired'`).
		Scan(&soonest); err == nil && soonest != nil {
		result = append(result, metric{
			name: "flotestro_agent_certificate_expiry_seconds_min", kind: "gauge",
			help:    "Seconds until the soonest expiry among the live agent certificates.",
			samples: []sample{{value: *soonest}},
		})
	}
	if grouped, err := c.groupCount(ctx, `
		select window, count(*) from (
			select h.id, case when min(c.not_after) < now() + interval '7 days' then '7d' else '30d' end as window
			from agent_certificates c join hosts h on h.id = c.host_id
			where c.revoked_at is null and c.not_after > now() and h.lifecycle_state <> 'retired'
			group by h.id having min(c.not_after) < now() + interval '30 days') t
		group by 1`); err == nil {
		result = append(result, metric{
			name: "flotestro_agent_certificates_expiring", kind: "gauge",
			help:    "Hosts whose live certificate expires within the window.",
			samples: labelled("within", grouped),
		})
	}

	// Sessions opened over the last day, by how they ended: a host that
	// reconnects every few minutes has a flapping link or a restarting agent.
	if grouped, err := c.groupCount(ctx, `
		select coalesce(end_reason, 'open'), count(*) from agent_sessions
		where started_at > now() - interval '24 hours' group by 1`); err == nil {
		result = append(result, metric{
			name: "flotestro_agent_sessions_opened", kind: "gauge",
			help:    "Agent sessions opened over the last day, by how they ended (open = still running).",
			samples: labelled("end_reason", grouped),
		})
	}
	var recoveries float64
	if err := c.pool.QueryRow(ctx, `
		select count(*) from enrollment_requests
		where purpose = 'replace_identity' and created_at > now() - interval '24 hours'`).
		Scan(&recoveries); err == nil {
		result = append(result, metric{
			name: "flotestro_identity_recovery_orders", kind: "gauge",
			help:    "Identity recovery orders placed over the last day.",
			samples: []sample{{value: recoveries}},
		})
	}

	if grouped, err := c.groupCount(ctx, `
		select case
			when revoked_at is not null then 'revoked'
			when last_seen_at is null then 'never_seen'
			when last_seen_at < now() - interval '10 minutes' then 'silent'
			else 'active' end, count(*)
		from relays group by 1`); err == nil {
		result = append(result, metric{
			name: "flotestro_relays", kind: "gauge",
			help:    "Relays by state: active, silent for ten minutes, never seen, or revoked.",
			samples: labelled("state", grouped),
		})
	}
	result = append(result, c.relayBufferMetrics(ctx)...)
	return result
}

// relayBufferMetrics show the results waiting on every relay for the link to
// the centre, and what the relay has already thrown away.
func (c *Collector) relayBufferMetrics(ctx context.Context) []metric {
	if c.relays == nil {
		return nil
	}
	rows, err := c.pool.Query(ctx, `select id, name from relays where revoked_at is null order by name`)
	if err != nil {
		return nil
	}
	defer rows.Close()

	var used, capacity, dropped []sample
	for rows.Next() {
		var id, name string
		if err := rows.Scan(&id, &name); err != nil {
			return nil
		}
		heartbeat, ok := c.relays.LastHeartbeat(id)
		if !ok {
			continue
		}
		labels := map[string]string{"relay": name}
		used = append(used, sample{labels: labels, value: float64(heartbeat.BufferBytes)})
		capacity = append(capacity, sample{labels: labels, value: float64(heartbeat.BufferMaxBytes)})
		dropped = append(dropped, sample{labels: labels, value: float64(heartbeat.BufferDropped)})
	}
	if rows.Err() != nil || len(used) == 0 {
		return nil
	}
	return []metric{
		{
			name: "flotestro_relay_buffer_bytes", kind: "gauge",
			help:    "Results waiting on the relay for the link to the centre, in bytes, by relay.",
			samples: used,
		},
		{
			name: "flotestro_relay_buffer_max_bytes", kind: "gauge",
			help:    "The buffer the relay was given, in bytes, by relay; the fill ratio is the two divided.",
			samples: capacity,
		},
		{
			// The relay counts the drops since its start; the panel renders the number
			// as the relay reports it, so a relay restart shows as a counter reset.
			name: "flotestro_relay_buffer_dropped_total", kind: "counter",
			help:    "Results the relay threw away because its buffer was full, since the relay started, by relay.",
			samples: dropped,
		},
	}
}

// campaignMetrics show the machinery of a fleet-wide change: the campaigns
// under way, the fate of their hosts and the capacity that governs them.
func (c *Collector) campaignMetrics(ctx context.Context) []metric {
	var result []metric

	if samples, err := c.labelPairs(ctx, `
		select state, action_type, count(*) from campaigns
		 where state in ('planning', 'planned', 'awaiting_approval', 'canary', 'running', 'pausing', 'paused')
		 group by 1, 2`, "state", "action"); err == nil {
		result = append(result, metric{
			name: "flotestro_campaigns_active", kind: "gauge",
			help:    "Campaigns under way by state and operation.",
			samples: samples,
		})
	}

	// The reason code matters here as much as the state: a host held back for
	// lack of capacity and one missing the adapter share a state, not a reason.
	if samples, err := c.labelPairs(ctx, `
		select t.state, coalesce(nullif(t.error_code, ''), 'none'), count(*)
		  from campaign_targets t
		  join campaigns c on c.id = t.campaign_id
		 where c.state in ('planning', 'planned', 'awaiting_approval', 'canary', 'manual_gate', 'running', 'pausing', 'paused', 'canceling')
		 group by 1, 2`, "state", "reason_code"); err == nil {
		result = append(result, metric{
			name: "flotestro_campaign_targets", kind: "gauge",
			help:    "The hosts of campaigns under way by state and reason code.",
			samples: samples,
		})
	}

	// Capacity and usage in one series, told apart by a label: without the
	// capacity the usage alone does not say whether the budget is at its limit.
	if samples, err := c.budgetSamples(ctx); err == nil && len(samples) > 0 {
		result = append(result, metric{
			name: "flotestro_budget_tokens", kind: "gauge",
			help:    "Budget tokens: capacity, usage and the number of claimants waiting.",
			samples: samples,
		})
	}

	// The jobs ordered one by one that stand in the queue for a budget, by the
	// key that had no room.
	if grouped, err := c.groupCount(ctx, `
		select substr(wait_reason, length('awaiting_budget:') + 1), count(*)
		  from jobs
		 where state = 'queued' and wait_reason like 'awaiting_budget:%'
		 group by 1`); err == nil && len(grouped) > 0 {
		result = append(result, metric{
			name: "flotestro_jobs_awaiting_budget", kind: "gauge",
			help:    "Single-host jobs standing in the queue for a budget, by budget key.",
			samples: labelled("budget", grouped),
		})
	}

	// The longest current wait for capacity.
	if samples, err := c.budgetWaits(ctx); err == nil && len(samples) > 0 {
		result = append(result, metric{
			name: "flotestro_budget_wait_seconds_max", kind: "gauge",
			help:    "The longest current wait for budget capacity.",
			samples: samples,
		})
	}

	// The lag of the durable trail: how old the oldest unpublished event is.
	if samples, err := c.outboxLag(ctx); err == nil {
		result = append(result, metric{
			name: "flotestro_outbox_lag_seconds", kind: "gauge",
			help:    "Age of the oldest event of the durable trail not published yet, by event type.",
			samples: samples,
		})
	}
	// An external consumer that stopped shows as a distance from the end of the
	// trail and as its failures; both point at the receiver, not at the panel.
	if samples, err := c.consumerLag(ctx); err == nil && len(samples) > 0 {
		result = append(result, metric{
			name: "flotestro_outbox_consumer_lag_events", kind: "gauge",
			help:    "Events of the durable trail not yet delivered to an external consumer.",
			samples: samples,
		})
	}
	return result
}

func (c *Collector) consumerLag(ctx context.Context) ([]sample, error) {
	rows, err := c.pool.Query(ctx, `
		select name, (select coalesce(max(id), 0) from outbox_events) - last_id, failures
		  from outbox_consumers`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	samples := []sample{}
	for rows.Next() {
		var name string
		var lag, failures float64
		if err := rows.Scan(&name, &lag, &failures); err != nil {
			return nil, err
		}
		samples = append(samples,
			sample{labels: map[string]string{"consumer": name, "kind": "behind"}, value: lag},
			sample{labels: map[string]string{"consumer": name, "kind": "failures"}, value: failures})
	}
	return samples, rows.Err()
}

// outboxLag measures the unpublished part of the trail. A type with nothing
// waiting reports zero: that is a measured zero, not a missing value.
func (c *Collector) outboxLag(ctx context.Context) ([]sample, error) {
	rows, err := c.pool.Query(ctx, `
		select event_type, extract(epoch from now() - min(occurred_at))
		  from outbox_events
		 where published_at is null
		 group by 1`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	samples := []sample{}
	for rows.Next() {
		var eventType string
		var lag float64
		if err := rows.Scan(&eventType, &lag); err != nil {
			return nil, err
		}
		samples = append(samples, sample{labels: map[string]string{"event_type": eventType}, value: lag})
	}
	if len(samples) == 0 {
		samples = append(samples, sample{labels: map[string]string{"event_type": "none"}, value: 0})
	}
	return samples, rows.Err()
}

// labelPairs reads a query with three columns: two labels and a count.
func (c *Collector) labelPairs(ctx context.Context, query, first, second string) ([]sample, error) {
	rows, err := c.pool.Query(ctx, query)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	samples := []sample{}
	for rows.Next() {
		var a, b string
		var count float64
		if err := rows.Scan(&a, &b, &count); err != nil {
			return nil, err
		}
		samples = append(samples, sample{
			labels: map[string]string{first: a, second: b}, value: count,
		})
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	sort.Slice(samples, func(i, j int) bool {
		if samples[i].labels[first] != samples[j].labels[first] {
			return samples[i].labels[first] < samples[j].labels[first]
		}
		return samples[i].labels[second] < samples[j].labels[second]
	})
	return samples, nil
}

func (c *Collector) budgetSamples(ctx context.Context) ([]sample, error) {
	const query = `
		select l.key, l.capacity,
		       coalesce((select sum(weight) from budget_leases d
		                  where d.key = l.key and d.lease_until > now()), 0),
		       (select count(*) from budget_waiters w
		         where w.key = l.key and w.seen_at > now() - interval '30 seconds')
		  from budget_limits l
		 order by l.key`
	rows, err := c.pool.Query(ctx, query)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	samples := []sample{}
	for rows.Next() {
		var key string
		var capacity, used, waiting float64
		if err := rows.Scan(&key, &capacity, &used, &waiting); err != nil {
			return nil, err
		}
		for status, value := range map[string]float64{
			"capacity": capacity, "used": used, "waiting": waiting,
		} {
			samples = append(samples, sample{
				labels: map[string]string{"budget": key, "status": status},
				value:  value,
			})
		}
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	sort.Slice(samples, func(i, j int) bool {
		if samples[i].labels["budget"] != samples[j].labels["budget"] {
			return samples[i].labels["budget"] < samples[j].labels["budget"]
		}
		return samples[i].labels["status"] < samples[j].labels["status"]
	})
	return samples, nil
}

func (c *Collector) budgetWaits(ctx context.Context) ([]sample, error) {
	const query = `
		select key, class, max(extract(epoch from now() - since))
		  from budget_waiters
		 where seen_at > now() - interval '30 seconds'
		 group by 1, 2`
	rows, err := c.pool.Query(ctx, query)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	samples := []sample{}
	for rows.Next() {
		var key, class string
		var seconds float64
		if err := rows.Scan(&key, &class, &seconds); err != nil {
			return nil, err
		}
		samples = append(samples, sample{
			labels: map[string]string{"budget": key, "class": class}, value: seconds,
		})
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	sort.Slice(samples, func(i, j int) bool {
		return samples[i].labels["budget"] < samples[j].labels["budget"]
	})
	return samples, nil
}

func (c *Collector) groupCount(ctx context.Context, query string) (map[string]float64, error) {
	rows, err := c.pool.Query(ctx, query)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	grouped := map[string]float64{}
	for rows.Next() {
		var key *string
		var count float64
		if err := rows.Scan(&key, &count); err != nil {
			return nil, err
		}
		name := "unknown"
		if key != nil {
			name = *key
		}
		grouped[name] = count
	}
	return grouped, rows.Err()
}

func labelled(name string, grouped map[string]float64) []sample {
	keys := make([]string, 0, len(grouped))
	for key := range grouped {
		keys = append(keys, key)
	}
	// A fixed order makes comparing consecutive scrapes by eye easier.
	sort.Strings(keys)

	samples := make([]sample, 0, len(keys))
	for _, key := range keys {
		samples = append(samples, sample{
			labels: map[string]string{name: key}, value: grouped[key],
		})
	}
	return samples
}

func render(metrics []metric) []byte {
	var builder strings.Builder
	for _, m := range metrics {
		fmt.Fprintf(&builder, "# HELP %s %s\n", m.name, m.help)
		fmt.Fprintf(&builder, "# TYPE %s %s\n", m.name, m.kind)
		for _, s := range m.samples {
			builder.WriteString(m.name)
			if len(s.labels) > 0 {
				keys := make([]string, 0, len(s.labels))
				for key := range s.labels {
					keys = append(keys, key)
				}
				sort.Strings(keys)
				pairs := make([]string, 0, len(keys))
				for _, key := range keys {
					// %q would escape the value a second time, giving double backslashes in
					// the result; escape does it once and correctly.
					pairs = append(pairs, fmt.Sprintf(`%s="%s"`, key, escape(s.labels[key])))
				}
				builder.WriteString("{" + strings.Join(pairs, ",") + "}")
			}
			fmt.Fprintf(&builder, " %g\n", s.value)
		}
	}
	return []byte(builder.String())
}

// escape escapes a label value. The name of a state comes from the database
// rather than from the code, so it must not break the format of the response.
func escape(value string) string {
	replacer := strings.NewReplacer(`\`, `\\`, `"`, `\"`, "\n", `\n`)
	return replacer.Replace(value)
}

// The panel reads its own cost the way the agent reads the host's: from the
// cgroup or from procfs, never from the runtime's own bookkeeping.

// userHZ is the unit of the CPU times in /proc/[pid]/stat.
const userHZ = 100

// Footprint is what a process costs on its host. A nil field is a number
// neither the cgroup nor procfs would give: unknown, not zero.
type Footprint struct {
	ResidentBytes *uint64
	// ResidentFrom names where the resident set came from: cgroup or procfs.
	ResidentFrom string
	OpenFDs      *uint64
	MaxFDs       *uint64
	CPUSeconds   *float64
}

// ReadFootprint reads the footprint of this process from the running host.
func ReadFootprint() Footprint { return readFootprint("/proc", "/sys/fs/cgroup") }

// readFootprint takes both roots as arguments so the readers can be given
// fixture text instead of the kernel.
func readFootprint(procRoot, cgroupRoot string) Footprint {
	var fp Footprint
	self := filepath.Join(procRoot, "self")

	// The cgroup is the budget a container is killed against, so where there is
	// one it is the number to report; procfs answers everywhere else.
	if resident, ok := cgroupResident(procRoot, cgroupRoot); ok {
		fp.ResidentBytes, fp.ResidentFrom = &resident, "cgroup"
	} else if data, err := os.ReadFile(filepath.Join(self, "status")); err == nil {
		if resident, ok := parseResidentBytes(string(data)); ok {
			fp.ResidentBytes, fp.ResidentFrom = &resident, "procfs"
		}
	}

	if entries, err := os.ReadDir(filepath.Join(self, "fd")); err == nil {
		// The directory handle of this read is one of the descriptors it counts.
		count := uint64(len(entries))
		fp.OpenFDs = &count
	}
	if data, err := os.ReadFile(filepath.Join(self, "limits")); err == nil {
		if limit, ok := parseFDLimit(string(data)); ok {
			fp.MaxFDs = &limit
		}
	}
	if data, err := os.ReadFile(filepath.Join(self, "stat")); err == nil {
		if ticks, ok := parseCPUTicks(string(data)); ok {
			seconds := float64(ticks) / userHZ
			fp.CPUSeconds = &seconds
		}
	}
	return fp
}

// cgroupResident reads the resident set the cgroup charges this process. The
// charge counts page cache the kernel can drop, so inactive_file is taken off.
func cgroupResident(procRoot, cgroupRoot string) (uint64, bool) {
	membership, err := os.ReadFile(filepath.Join(procRoot, "self", "cgroup"))
	if err != nil {
		return 0, false
	}
	path, ok := parseCgroupPath(string(membership))
	if !ok {
		return 0, false
	}
	directory := filepath.Join(cgroupRoot, filepath.FromSlash(path))
	current, err := os.ReadFile(filepath.Join(directory, "memory.current"))
	if err != nil {
		return 0, false
	}
	charged, ok := parseCgroupBytes(string(current))
	if !ok {
		return 0, false
	}
	if stat, err := os.ReadFile(filepath.Join(directory, "memory.stat")); err == nil {
		if inactive, ok := parseCgroupField(string(stat), "inactive_file"); ok && inactive <= charged {
			charged -= inactive
		}
	}
	return charged, true
}

// parseCgroupPath finds the unified hierarchy line of /proc/[pid]/cgroup. A
// host still on the first version has no such line, and procfs answers instead.
func parseCgroupPath(content string) (string, bool) {
	for _, line := range strings.Split(content, "\n") {
		rest, ok := strings.CutPrefix(strings.TrimSpace(line), "0::")
		if !ok || rest == "" {
			continue
		}
		return rest, true
	}
	return "", false
}

// parseCgroupBytes reads a single-value cgroup file. The word "max" stands
// where a number would be when nothing is set, and it is not a measurement.
func parseCgroupBytes(content string) (uint64, bool) {
	value, err := strconv.ParseUint(strings.TrimSpace(content), 10, 64)
	if err != nil {
		return 0, false
	}
	return value, true
}

// parseCgroupField reads one "name value" line of memory.stat.
func parseCgroupField(content, field string) (uint64, bool) {
	for _, line := range strings.Split(content, "\n") {
		fields := strings.Fields(line)
		if len(fields) != 2 || fields[0] != field {
			continue
		}
		value, err := strconv.ParseUint(fields[1], 10, 64)
		if err != nil {
			return 0, false
		}
		return value, true
	}
	return 0, false
}

// parseResidentBytes reads VmRSS out of /proc/[pid]/status. The file reports
// kilobytes; the metric carries bytes like every other size.
func parseResidentBytes(status string) (uint64, bool) {
	for _, line := range strings.Split(status, "\n") {
		key, rest, ok := strings.Cut(line, ":")
		if !ok || key != "VmRSS" {
			continue
		}
		fields := strings.Fields(rest)
		if len(fields) == 0 {
			return 0, false
		}
		value, err := strconv.ParseUint(fields[0], 10, 64)
		if err != nil {
			return 0, false
		}
		return value * 1024, true
	}
	return 0, false
}

// parseFDLimit reads the soft descriptor limit out of /proc/[pid]/limits.
func parseFDLimit(limits string) (uint64, bool) {
	for _, line := range strings.Split(limits, "\n") {
		rest, ok := strings.CutPrefix(line, "Max open files")
		if !ok {
			continue
		}
		fields := strings.Fields(rest)
		if len(fields) == 0 {
			return 0, false
		}
		// "unlimited" stands where the number would be; a limit that is not a
		// number is no limit to compare the open count with.
		value, err := strconv.ParseUint(fields[0], 10, 64)
		if err != nil {
			return 0, false
		}
		return value, true
	}
	return 0, false
}

// parseCPUTicks reads utime plus stime out of /proc/[pid]/stat. The command
// name is in brackets and may contain spaces, so counting starts after them.
func parseCPUTicks(stat string) (uint64, bool) {
	end := strings.LastIndex(stat, ")")
	if end < 0 {
		return 0, false
	}
	fields := strings.Fields(stat[end+1:])
	if len(fields) < 13 {
		return 0, false
	}
	user, errUser := strconv.ParseUint(fields[11], 10, 64)
	system, errSystem := strconv.ParseUint(fields[12], 10, 64)
	if errUser != nil || errSystem != nil {
		return 0, false
	}
	return user + system, true
}
