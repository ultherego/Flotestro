package monitoring

import (
	"context"
	"fmt"
	"time"

	"github.com/google/uuid"
)

// hostState is what the evaluator knows about one host: where it is, how
// many cores it has, when it last reported and what it reported.
type hostState struct {
	ID          string
	Hostname    string
	Site        string
	Environment string
	OSFamily    string
	// Cores comes from the inventory; zero when the host did not report it.
	Cores int
	// LastSampleAt is nil for a host that never sent a sample.
	LastSampleAt *time.Time
	// Latest is the newest sample; nil for a host that never sent one.
	Latest *Sample
}

// openAlert is an episode that has not resolved.
type openAlert struct {
	ID        string
	State     string
	Value     float64
	Detail    string
	StartedAt time.Time
}

// Evaluate runs every enabled rule over the matching hosts once.
//
// An episode starts pending the first time the condition holds, fires once
// it has held for the rule's window, and resolves the first time it does
// not. The window is measured from the start of the episode rather than
// over a set of samples: the evaluator runs every sampling interval, so a
// condition that stops holding in between clears the episode before it
// fires. A rule with an empty window fires at the first sample.
//
// A host whose newest sample is older than three intervals is not
// evaluated by the sample rules: a stale reading is not a reading, and
// its silence is a matter for host_offline.
func (s *Store) Evaluate(ctx context.Context, now time.Time) error {
	rules, err := s.ListRules(ctx)
	if err != nil {
		return err
	}
	hosts, err := s.hostStates(ctx)
	if err != nil {
		return err
	}
	open, err := s.openAlerts(ctx)
	if err != nil {
		return err
	}
	for _, rule := range rules {
		if !rule.Enabled {
			continue
		}
		for _, host := range hosts {
			if !rule.Selector.matches(host) {
				continue
			}
			value, detail, known := measure(rule, host, now)
			key := rule.ID + "/" + host.ID
			episode, exists := open[key]
			if !known {
				// Nothing can be said: the episode stays as it is, neither
				// advanced nor cleared.
				continue
			}
			holds := compare(rule.Operator, value, rule.Threshold)
			switch {
			case holds && !exists:
				if err := s.startEpisode(ctx, rule, host, value, detail, now); err != nil {
					return err
				}
			case holds && episode.State == "pending":
				if now.Sub(episode.StartedAt) >= time.Duration(rule.ForMinutes)*time.Minute {
					if err := s.fire(ctx, episode.ID, value, detail, now); err != nil {
						return err
					}
				} else if err := s.refresh(ctx, episode, value, detail); err != nil {
					return err
				}
			case holds:
				if err := s.refresh(ctx, episode, value, detail); err != nil {
					return err
				}
			case !holds && exists && episode.State == "pending":
				if _, err := s.pool.Exec(ctx, `delete from alerts where id = $1`, episode.ID); err != nil {
					return err
				}
			case !holds && exists:
				if _, err := s.pool.Exec(ctx, `
					update alerts set state = 'resolved', resolved_at = $2, value = $3
					where id = $1 and state = 'firing'`, episode.ID, now, float32(value)); err != nil {
					return err
				}
			}
		}
	}
	// The episodes of the rules that no longer cover their host - the
	// selector changed, the host moved - end here rather than staying open
	// for ever.
	return s.closeOrphans(ctx, rules, hosts, open, now)
}

func (s *Store) startEpisode(ctx context.Context, rule Rule, host hostState,
	value float64, detail string, now time.Time) error {
	state := "pending"
	var firedAt *time.Time
	if rule.ForMinutes == 0 {
		state = "firing"
		firedAt = &now
	}
	_, err := s.pool.Exec(ctx, `
		insert into alerts (id, rule_id, rule_name, metric, severity, host_id, state,
		    value, detail, started_at, fired_at)
		values ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11)
		on conflict do nothing`,
		uuid.NewString(), rule.ID, rule.Name, rule.Metric, rule.Severity, host.ID, state,
		float32(value), detail, now, firedAt)
	return err
}

func (s *Store) fire(ctx context.Context, id string, value float64, detail string, now time.Time) error {
	_, err := s.pool.Exec(ctx, `
		update alerts set state = 'firing', fired_at = $2, value = $3, detail = $4
		where id = $1 and state = 'pending'`, id, now, float32(value), detail)
	return err
}

// refresh keeps the value and the message of an open episode current. A
// write only when something changed: the fleet has many quiet minutes.
func (s *Store) refresh(ctx context.Context, episode openAlert, value float64, detail string) error {
	if float32(value) == float32(episode.Value) && detail == episode.Detail {
		return nil
	}
	_, err := s.pool.Exec(ctx, `update alerts set value = $2, detail = $3 where id = $1`,
		episode.ID, float32(value), detail)
	return err
}

// closeOrphans ends the open episodes whose rule no longer covers their
// host or whose host is gone from the fleet.
func (s *Store) closeOrphans(ctx context.Context, rules []Rule, hosts []hostState,
	open map[string]openAlert, now time.Time) error {
	covered := map[string]bool{}
	for _, rule := range rules {
		if !rule.Enabled {
			continue
		}
		for _, host := range hosts {
			if rule.Selector.matches(host) {
				covered[rule.ID+"/"+host.ID] = true
			}
		}
	}
	for key, episode := range open {
		if covered[key] {
			continue
		}
		if episode.State == "pending" {
			if _, err := s.pool.Exec(ctx, `delete from alerts where id = $1`, episode.ID); err != nil {
				return err
			}
			continue
		}
		if _, err := s.pool.Exec(ctx, `
			update alerts set state = 'resolved', resolved_at = $2
			where id = $1 and state = 'firing'`, episode.ID, now); err != nil {
			return err
		}
	}
	return nil
}

// matches says whether the selector covers the host.
func (sel Selector) matches(host hostState) bool {
	if sel.Site != "" && sel.Site != host.Site {
		return false
	}
	if sel.Environment != "" && sel.Environment != host.Environment {
		return false
	}
	if sel.OSFamily != "" && sel.OSFamily != host.OSFamily {
		return false
	}
	if len(sel.HostIDs) == 0 {
		return true
	}
	for _, id := range sel.HostIDs {
		if id == host.ID {
			return true
		}
	}
	return false
}

// measure computes the value of the rule's metric for the host and the
// message an alert would carry. Known is false when the host gave nothing
// the metric can be computed from.
func measure(rule Rule, host hostState, now time.Time) (value float64, detail string, known bool) {
	if rule.Metric == MetricHostOffline {
		if host.LastSampleAt == nil {
			// A host that never sent a sample runs an agent without the
			// sampler or has not connected since it was enrolled; neither
			// is a host that went quiet.
			return 0, "", false
		}
		minutes := now.Sub(*host.LastSampleAt).Minutes()
		if minutes < 0 {
			minutes = 0
		}
		return minutes, fmt.Sprintf("no sample for %.0f min (%s %s %.0f min)",
			minutes, rule.Metric, symbol(rule.Operator), rule.Threshold), true
	}
	sample := host.Latest
	if sample == nil || now.Sub(sample.At) > silentAfter {
		return 0, "", false
	}
	describe := func(value float64, unit string) string {
		return fmt.Sprintf("%s %s%s (%s %s%s)", rule.Metric, formatValue(value), unit,
			symbol(rule.Operator), formatValue(rule.Threshold), unit)
	}
	switch rule.Metric {
	case MetricCPUPercent:
		return sample.CPUPercent, describe(sample.CPUPercent, "%"), true
	case MetricLoad1PerCore:
		value := sample.Load1
		if host.Cores > 0 {
			value = sample.Load1 / float64(host.Cores)
		}
		return value, describe(value, ""), true
	case MetricMemoryUsedPercent:
		if sample.MemoryTotal == 0 {
			return 0, "", false
		}
		value := ratio(sample.MemoryUsed, sample.MemoryTotal)
		return value, describe(value, "%"), true
	case MetricSwapUsedPercent:
		if sample.SwapTotal == 0 {
			// A host without swap has no swap usage to speak of; zero here
			// would fire every "less than" rule on a host that cannot swap.
			return 0, "", false
		}
		value := ratio(sample.SwapUsed, sample.SwapTotal)
		return value, describe(value, "%"), true
	case MetricFilesystemUsedPercent, MetricInodesUsedPercent:
		var worst *Filesystem
		var worstValue float64
		for i := range sample.Filesystems {
			fs := &sample.Filesystems[i]
			var used, total uint64
			if rule.Metric == MetricFilesystemUsedPercent {
				used, total = fs.UsedBytes, fs.TotalBytes
			} else {
				used, total = fs.InodesUsed, fs.InodesTotal
			}
			if total == 0 {
				continue
			}
			if value := ratio(used, total); worst == nil || value > worstValue {
				worst, worstValue = fs, value
			}
		}
		if worst == nil {
			return 0, "", false
		}
		return worstValue, fmt.Sprintf("%s: %s", worst.Mount, describe(worstValue, "%")), true
	case MetricUptimeSeconds:
		value := float64(sample.UptimeSeconds)
		return value, fmt.Sprintf("uptime %s (%s %s %s)", formatDuration(value),
			rule.Metric, symbol(rule.Operator), formatDuration(rule.Threshold)), true
	}
	return 0, "", false
}

func ratio(part, whole uint64) float64 {
	if whole == 0 {
		return 0
	}
	return float64(part) * 100 / float64(whole)
}

// compare applies the rule's operator.
func compare(operator string, value, threshold float64) bool {
	switch operator {
	case "gt":
		return value > threshold
	case "lt":
		return value < threshold
	case "gte":
		return value >= threshold
	case "lte":
		return value <= threshold
	}
	return false
}

func symbol(operator string) string {
	switch operator {
	case "gt":
		return ">"
	case "lt":
		return "<"
	case "gte":
		return ">="
	case "lte":
		return "<="
	}
	return operator
}

// formatValue renders a value with one decimal, or none when it is whole.
func formatValue(value float64) string {
	if value == float64(int64(value)) {
		return fmt.Sprintf("%.0f", value)
	}
	return fmt.Sprintf("%.1f", value)
}

// formatDuration renders seconds as the largest whole unit that fits.
func formatDuration(seconds float64) string {
	d := time.Duration(seconds) * time.Second
	switch {
	case d >= 24*time.Hour:
		return fmt.Sprintf("%.1fd", d.Hours()/24)
	case d >= time.Hour:
		return fmt.Sprintf("%.1fh", d.Hours())
	case d >= time.Minute:
		return fmt.Sprintf("%.0fm", d.Minutes())
	}
	return fmt.Sprintf("%.0fs", d.Seconds())
}

// hostStates reads every host that is not retired with its newest sample
// and its core count from the newest inventory.
func (s *Store) hostStates(ctx context.Context) ([]hostState, error) {
	rows, err := s.pool.Query(ctx, `
		select h.id, h.hostname, h.site, h.environment, coalesce(h.os_family, ''),
		       h.last_metrics_at,
		       coalesce((select nullif(i.payload->'hardware'->>'cpu_cores', '')::int
		                 from inventory_revisions i
		                 where i.host_id = h.id
		                 order by i.observed_at desc limit 1), 0),
		       m.at, m.cpu_percent, m.load1, m.memory_total, m.memory_used,
		       m.swap_total, m.swap_used, m.uptime_seconds, m.filesystems
		from hosts h
		left join lateral (
		    select at, cpu_percent, load1, memory_total, memory_used, swap_total, swap_used,
		           uptime_seconds, filesystems
		    from host_metrics where host_id = h.id
		    order by at desc limit 1
		) m on true
		where h.lifecycle_state <> 'retired'`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var hosts []hostState
	for rows.Next() {
		var host hostState
		var at *time.Time
		var cpu, load1 *float32
		var memoryTotal, memoryUsed, swapTotal, swapUsed, uptime *int64
		var filesystems []Filesystem
		if err := rows.Scan(&host.ID, &host.Hostname, &host.Site, &host.Environment, &host.OSFamily,
			&host.LastSampleAt, &host.Cores, &at, &cpu, &load1, &memoryTotal, &memoryUsed,
			&swapTotal, &swapUsed, &uptime, &filesystems); err != nil {
			return nil, err
		}
		if at != nil {
			host.Latest = &Sample{
				At: *at, CPUPercent: float64(*cpu), Load1: float64(*load1),
				MemoryTotal: uint64(*memoryTotal), MemoryUsed: uint64(*memoryUsed),
				SwapTotal: uint64(*swapTotal), SwapUsed: uint64(*swapUsed),
				UptimeSeconds: uint64(*uptime), Filesystems: filesystems,
			}
		}
		hosts = append(hosts, host)
	}
	return hosts, rows.Err()
}

// openAlerts reads the episodes that have not resolved, keyed by rule and
// host.
func (s *Store) openAlerts(ctx context.Context) (map[string]openAlert, error) {
	rows, err := s.pool.Query(ctx, `
		select id, coalesce(rule_id::text, ''), host_id, state, value, detail, started_at
		from alerts where state <> 'resolved'`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	open := map[string]openAlert{}
	for rows.Next() {
		var episode openAlert
		var ruleID, hostID string
		var value float32
		if err := rows.Scan(&episode.ID, &ruleID, &hostID, &episode.State, &value,
			&episode.Detail, &episode.StartedAt); err != nil {
			return nil, err
		}
		episode.Value = float64(value)
		open[ruleID+"/"+hostID] = episode
	}
	return open, rows.Err()
}
