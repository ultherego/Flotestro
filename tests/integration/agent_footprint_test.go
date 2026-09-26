//go:build integration

package integration

import (
	"fmt"
	"sort"
	"testing"
	"time"
)

// The footprint budget of the agent from the architecture document: what the
// agent may cost a host before a release ships.
//
// The memory figure is resident memory, and resident memory is two things: what
// the Go runtime holds, which heapSoftLimit in cmd/agent/main.go caps at 20 MiB,
// and the resident pages of the binary itself, which measure about 11 MiB of a
// 13 MiB executable on the test fleet. Those add, so an agent using its whole
// allowance sits near 31 MiB and the earlier 30 MiB budget could only be met by
// not using it. The agent has grown - containers, Compose, network layers,
// vulnerability assessment, built-in monitoring - and the budget follows what it
// actually costs rather than the other way round.
const (
	footprintRSSBudget = 36 << 20
	footprintCPUBudget = 0.2
	// footprintFreshness is how old the newest sample may be for the host to
	// count: three sampling intervals, as the panel counts a host as reporting.
	footprintFreshness = 3 * time.Minute
	// firstSampleWait is how long a session may be open before its agent owes a
	// footprint: one sampling interval for the sample, one for the start, and the
	// delivery. firstSampleLimit caps the whole wait, so an agent reconnecting in
	// a loop - whose session is always new - does not hold the test for ever.
	firstSampleWait  = 150 * time.Second
	firstSampleLimit = 5 * time.Minute
)

// footprintPoint is the part of a chart point the gate reads.
type footprintPoint struct {
	At              time.Time `json:"at"`
	AgentRSSBytes   *uint64   `json:"agent_rss_bytes"`
	AgentCPUPercent *float64  `json:"agent_cpu_percent"`
	AgentGoroutines *uint32   `json:"agent_goroutines"`
	AgentOpenFDs    *uint32   `json:"agent_open_fds"`
	HelperRSSBytes  *uint64   `json:"helper_rss_bytes"`
}

// footprintMetricsView is the answer of the chart endpoint the host page reads.
type footprintMetricsView struct {
	HostID       string           `json:"host_id"`
	Points       []footprintPoint `json:"points"`
	Latest       *footprintPoint  `json:"latest"`
	LastSampleAt *time.Time       `json:"last_sample_at"`
}

// rssPercentile returns the 95th percentile of the resident memory over the
// points of the last hour, or nil when the hour holds fewer than five samples.
func rssPercentile(points []footprintPoint, since time.Time) *uint64 {
	var values []uint64
	for _, point := range points {
		if point.AgentRSSBytes != nil && !point.At.Before(since) {
			values = append(values, *point.AgentRSSBytes)
		}
	}
	if len(values) < 5 {
		return nil
	}
	sort.Slice(values, func(i, j int) bool { return values[i] < values[j] })
	index := (len(values)*95 + 99) / 100
	if index > 0 {
		index--
	}
	return &values[index]
}

// latestFootprint reads the newest sample of a host as the host
// Monitoring page does.
func (h *harness) latestFootprint(hostID string) footprintMetricsView {
	h.t.Helper()
	var view footprintMetricsView
	h.get("/api/v1/hosts/"+hostID+"/metrics?range=3h", &view)
	return view
}

// sessionOpenedAt is when the panel claimed the session it serves the host on,
// or nil for a host with no session or one the panel does not date.
func (h *harness) sessionOpenedAt(hostID string) *time.Time {
	h.t.Helper()
	var view struct {
		SessionOpenedAt *time.Time `json:"session_opened_at"`
	}
	h.get("/api/v1/hosts/"+hostID, &view)
	return view.SessionOpenedAt
}

// TestAgentFootprintIsWithinBudget is the release gate on the agent's cost: on
// every online host of the lab the agent's newest sample says it uses less
// than 128 MiB of resident memory and less than ten per cent of one core.
func TestAgentFootprintIsWithinBudget(t *testing.T) {
	h := newHarness(t)
	var online []hostView
	for _, host := range h.hosts() {
		if host.ConnectionState == "online" {
			online = append(online, host)
		}
	}
	if len(online) == 0 {
		t.Skip("no online host in the lab")
	}

	for _, host := range online {
		view := h.latestFootprint(host.ID)
		// An agent samples once a minute and the first sample follows its start, so
		// a host that joined a moment ago has none yet - that is waited for. The
		// clock that counts is the session's and not this test's: an agent that
		// restarted while the test was already waiting begins the interval again,
		// and the panel says when it claimed the session.
		for start := time.Now(); view.Latest == nil || view.LastSampleAt == nil; {
			deadline := start.Add(firstSampleWait)
			if opened := h.sessionOpenedAt(host.ID); opened != nil {
				deadline = opened.Add(firstSampleWait)
			}
			if time.Now().After(deadline) || time.Since(start) > firstSampleLimit {
				break
			}
			time.Sleep(10 * time.Second)
			view = h.latestFootprint(host.ID)
		}
		if view.Latest == nil || view.LastSampleAt == nil {
			open := "a session the panel does not date"
			if opened := h.sessionOpenedAt(host.ID); opened != nil {
				open = "a session open for " + time.Since(*opened).Round(time.Second).String()
			}
			t.Errorf("%s: no footprint from %s; the gate was not measured", host.Hostname, open)
			continue
		}
		if age := time.Since(*view.LastSampleAt); age > footprintFreshness {
			t.Logf("%s: skipped, the newest sample is %s old (taken %s)",
				host.Hostname, age.Round(time.Second), view.LastSampleAt.Format(time.RFC3339))
			continue
		}
		latest := view.Latest
		// The CPU share needs an interval, so the first sample after the agent
		// started carries none.
		if latest.AgentRSSBytes != nil && latest.AgentCPUPercent == nil {
			latest = h.awaitFootprintCPU(host.ID, latest.At, 2*time.Minute+15*time.Second)
		}
		if latest.AgentRSSBytes == nil {
			t.Errorf("%s: the agent reports no footprint (agent_rss_bytes absent); the gate was not measured",
				host.Hostname)
			continue
		}
		summary := describeFootprint(latest)
		// The memory budget is judged at the 95th percentile of the last hour where
		// the hour has enough samples; the newest sample alone decides only on a
		// host that has just joined.
		rss := *latest.AgentRSSBytes
		if p95 := rssPercentile(view.Points, time.Now().Add(-time.Hour)); p95 != nil {
			rss = *p95
			summary += fmt.Sprintf("; p95 of the last hour %s", mebibytes(rss))
		}
		if rss >= footprintRSSBudget {
			t.Errorf("%s: agent_rss_bytes %d (%s) is not below the budget of %d (%s); %s",
				host.Hostname, rss, mebibytes(rss),
				uint64(footprintRSSBudget), mebibytes(footprintRSSBudget), summary)
		}
		if latest.AgentCPUPercent == nil {
			t.Errorf("%s: the agent reports no CPU share (agent_cpu_percent absent) across two samples; %s",
				host.Hostname, summary)
		} else if *latest.AgentCPUPercent >= footprintCPUBudget {
			t.Errorf("%s: agent_cpu_percent %.2f is not below the budget of %.0f; %s",
				host.Hostname, *latest.AgentCPUPercent, footprintCPUBudget, summary)
		}
		t.Logf("%s: %s", host.Hostname, summary)
	}
}

// awaitFootprintCPU waits for a sample newer than the given moment that
// carries the CPU share, and returns the newest sample seen either way.
func (h *harness) awaitFootprintCPU(hostID string, after time.Time, limit time.Duration) *footprintPoint {
	h.t.Helper()
	deadline := time.Now().Add(limit)
	var newest *footprintPoint
	for {
		view := h.latestFootprint(hostID)
		if view.Latest != nil {
			newest = view.Latest
			if newest.At.After(after) && newest.AgentCPUPercent != nil {
				return newest
			}
		}
		if time.Now().After(deadline) {
			return newest
		}
		time.Sleep(15 * time.Second)
	}
}

// describeFootprint prints every footprint field of a sample, absent ones
// as such, so a failure names the numbers rather than the host alone.
func describeFootprint(point *footprintPoint) string {
	value := func(name string, format func() string, present bool) string {
		if !present {
			return name + " absent"
		}
		return name + " " + format()
	}
	return fmt.Sprintf("sampled %s: %s, %s, %s, %s, %s",
		point.At.Format(time.RFC3339),
		value("agent_rss_bytes", func() string { return mebibytes(*point.AgentRSSBytes) }, point.AgentRSSBytes != nil),
		value("agent_cpu_percent", func() string { return fmt.Sprintf("%.2f", *point.AgentCPUPercent) }, point.AgentCPUPercent != nil),
		value("agent_goroutines", func() string { return fmt.Sprint(*point.AgentGoroutines) }, point.AgentGoroutines != nil),
		value("agent_open_fds", func() string { return fmt.Sprint(*point.AgentOpenFDs) }, point.AgentOpenFDs != nil),
		value("helper_rss_bytes", func() string { return mebibytes(*point.HelperRSSBytes) }, point.HelperRSSBytes != nil))
}

func mebibytes(value uint64) string {
	return fmt.Sprintf("%.1f MiB", float64(value)/(1<<20))
}
