package monitoring

import (
	"context"
	"fmt"
)

// The agent's footprint budget from the architecture document (chapter 8: RSS
// at most 30 MiB, CPU below 0.
const (
	FootprintRSSBudgetBytes = 30 << 20
	FootprintCPUBudget      = 0.2
)

// FootprintHost is one host over the budget, with the readings that put
// it there.
type FootprintHost struct {
	HostID          string   `json:"host_id"`
	Hostname        string   `json:"hostname"`
	AgentRSSBytes   *uint64  `json:"agent_rss_bytes,omitempty"`
	AgentCPUPercent *float64 `json:"agent_cpu_percent,omitempty"`
}

// FleetFootprint summarises the agents' own cost across the reporting hosts,
// from the newest sample of each.
type FleetFootprint struct {
	// HostsMeasured counts the reporting hosts whose newest sample
	// carries the agent's memory.
	HostsMeasured    int      `json:"hosts_measured"`
	RSSBytesMax      *uint64  `json:"rss_bytes_max,omitempty"`
	RSSBytesMedian   *uint64  `json:"rss_bytes_median,omitempty"`
	CPUPercentMax    *float64 `json:"cpu_percent_max,omitempty"`
	CPUPercentMedian *float64 `json:"cpu_percent_median,omitempty"`
	HelperRSSMax     *uint64  `json:"helper_rss_bytes_max,omitempty"`
	// The budget the hosts below are over, so the view says what it
	// measured against.
	RSSBudgetBytes uint64  `json:"rss_budget_bytes"`
	CPUBudget      float64 `json:"cpu_budget_percent"`
	// OverBudget lists the hosts whose newest sample is over either
	// budget, the heaviest first.
	OverBudget []FootprintHost `json:"over_budget"`
}

// latestFootprints is the newest sample of every reporting host that is not
// retired and within the visibility condition over the alias h.
func latestFootprints(cutoffParam int, visible string) string {
	return `
	with latest as (
	    select h.id, h.hostname, m.agent_rss_bytes, m.agent_cpu_percent, m.helper_rss_bytes
	    from hosts h
	    join lateral (
	        select agent_rss_bytes, agent_cpu_percent, helper_rss_bytes
	        from host_metrics where host_id = h.id
	        order by at desc limit 1
	    ) m on true
	    where h.lifecycle_state <> 'retired'
	      and h.last_metrics_at >= now() - make_interval(secs => $` + fmt.Sprint(cutoffParam) + `::double precision)
	      and ` + visible + `
	)`
}

// FleetFootprint reads the footprint summary over the visible hosts.
func (s *Store) FleetFootprint(ctx context.Context, visible string, args []any) (FleetFootprint, error) {
	summary := FleetFootprint{
		RSSBudgetBytes: FootprintRSSBudgetBytes, CPUBudget: FootprintCPUBudget,
		OverBudget: []FootprintHost{},
	}
	params := append(append([]any{}, args...), silentAfter.Seconds())
	prelude := latestFootprints(len(params), visible)

	// The aggregates skip the hosts without a reading, so the median is the
	// median of what was measured rather than of a list padded with zeros.
	var rssMax, helperMax *int64
	var rssMedian, cpuMedian *float64
	var cpuMax *float32
	if err := s.pool.QueryRow(ctx, prelude+`
		select count(*) filter (where agent_rss_bytes is not null),
		       max(agent_rss_bytes),
		       percentile_cont(0.5) within group (order by agent_rss_bytes::double precision),
		       max(agent_cpu_percent),
		       percentile_cont(0.5) within group (order by agent_cpu_percent::double precision),
		       max(helper_rss_bytes)
		from latest`, params...).Scan(&summary.HostsMeasured, &rssMax, &rssMedian,
		&cpuMax, &cpuMedian, &helperMax); err != nil {
		return summary, err
	}
	summary.RSSBytesMax = unsignedOf(rssMax)
	summary.HelperRSSMax = unsignedOf(helperMax)
	if rssMedian != nil {
		median := uint64(*rssMedian)
		summary.RSSBytesMedian = &median
	}
	summary.CPUPercentMax = float64Of(cpuMax)
	summary.CPUPercentMedian = cpuMedian

	over := append(append([]any{}, params...), int64(FootprintRSSBudgetBytes), FootprintCPUBudget)
	rows, err := s.pool.Query(ctx, prelude+fmt.Sprintf(`
		select id, hostname, agent_rss_bytes, agent_cpu_percent
		from latest
		where agent_rss_bytes > $%d or agent_cpu_percent > $%d
		order by agent_rss_bytes desc nulls last, agent_cpu_percent desc nulls last, hostname
		limit 50`, len(params)+1, len(params)+2), over...)
	if err != nil {
		return summary, err
	}
	defer rows.Close()
	for rows.Next() {
		var host FootprintHost
		var rss *int64
		var cpu *float32
		if err := rows.Scan(&host.HostID, &host.Hostname, &rss, &cpu); err != nil {
			return summary, err
		}
		host.AgentRSSBytes = unsignedOf(rss)
		host.AgentCPUPercent = float64Of(cpu)
		summary.OverBudget = append(summary.OverBudget, host)
	}
	return summary, rows.Err()
}
