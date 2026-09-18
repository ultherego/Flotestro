package monitoring

import (
	"context"
	"errors"
	"fmt"
	"strings"
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
// The window counts only the time the fleet was actually watched. A hole
// in the samples longer than maxSampleGap - the agent was restarted, the
// host was rebooted, the panel was down - is not a stretch of the
// condition holding; it is a stretch of nobody looking. The episode's
// timer therefore restarts after the hole, and an alert says "this held
// for ten minutes" only when ten minutes of samples say so. Without that,
// a host that goes quiet for an hour under a load spike and comes back
// under the same spike fires at once for a window nobody observed.
//
// A host whose newest sample is older than three intervals is not
// evaluated by the sample rules: a stale reading is not a reading, and
// its silence is a matter for host_offline. A rule left without data that
// way holds its pending episode in place - the no-data state - rather
// than letting the timer run on to firing.
func (s *Store) Evaluate(ctx context.Context, now time.Time) error {
	return s.evaluate(ctx, now, nil)
}

// EvaluateLeased is the pass the running panel makes: one instance at a
// time, under a lease taken from the database.
//
// An instance that does not get the lease evaluates nothing. It does not
// evaluate a little, or evaluate and let an index swallow the second
// insert: the rest of an episode - firing, refreshing, resolving - is
// plain updates that no index guards, and two instances a second apart
// would contradict each other about one alert. An instance that loses the
// lease in the middle of a pass stops where it is for the same reason;
// what it has written is a state the new holder reads and carries on
// from, which is exactly what an open episode is for.
func (s *Store) EvaluateLeased(ctx context.Context, now time.Time) error {
	lease, held, err := s.acquireEvaluatorLease(ctx)
	if err != nil {
		return err
	}
	if !held {
		s.log.Debug("another instance holds the lease of the alert evaluator; the rules are judged there")
		return nil
	}
	defer func() {
		// The lease is given back at the end of the pass so that the next
		// instance may take it at once instead of waiting out the term.
		// The context of the run may already be cancelled - the panel is
		// shutting down - and that is precisely when handing it back
		// matters.
		if err := s.releaseEvaluatorLease(context.WithoutCancel(ctx), lease); err != nil {
			s.log.Warn("the lease of the alert evaluator was not given back; it runs out by itself",
				"err", err)
		}
	}()

	renewed := time.Now()
	guard := func(ctx context.Context) error {
		if time.Since(renewed) < evaluatorRenewEvery {
			return nil
		}
		if err := s.renewEvaluatorLease(ctx, lease); err != nil {
			return err
		}
		renewed = time.Now()
		return nil
	}
	if err := s.evaluate(ctx, now, guard); err != nil {
		if errors.Is(err, ErrLeaseLost) {
			// Not a failure of the panel: another instance judges the
			// fleet now, and this pass stopped rather than writing over it.
			s.log.Warn("the lease of the alert evaluator was lost during the pass; the pass was stopped",
				"holder", lease.Holder, "token", lease.Token)
			return nil
		}
		return err
	}
	return nil
}

// evaluate is the pass itself. The guard, when there is one, is asked
// between rules whether the caller may still write; without one - a test,
// or a single-instance call - the pass simply runs.
func (s *Store) evaluate(ctx context.Context, now time.Time, guard func(context.Context) error) error {
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
	scopes := s.scopes(ctx, rules)
	for _, rule := range rules {
		// Asked between rules rather than only at the start: a pass over a
		// fleet takes time, and an instance that lost the fleet halfway
		// must not write the second half of a verdict somebody else is
		// already giving.
		if guard != nil {
			if err := guard(ctx); err != nil {
				return err
			}
		}
		within := scopes[rule.ID]
		if !rule.Enabled || within == nil {
			continue
		}
		for _, host := range hosts {
			if !within.covers(host.ID) {
				continue
			}
			value, detail, known := measure(rule, host, now)
			key := rule.ID + "/" + host.ID
			episode, exists := open[key]
			if !known {
				// Nothing can be said: the episode is not cleared - the
				// condition may well still hold - but it is not advanced
				// either. A pending episode is held in its no-data state,
				// its timer restarted, so that when the readings come back
				// the window is counted from the reading rather than from
				// a silence.
				if exists && noDataHold(episode, now) {
					if err := s.restart(ctx, episode.ID, now); err != nil {
						return err
					}
				}
				continue
			}
			holds := compare(rule.Operator, value, rule.Threshold)
			switch {
			case holds && !exists:
				if err := s.startEpisode(ctx, rule, host, value, detail, now); err != nil {
					return err
				}
			case holds && episode.State == "pending":
				since, err := s.observedSince(ctx, rule, host, episode, now)
				if err != nil {
					return err
				}
				if now.Sub(since) >= time.Duration(rule.ForMinutes)*time.Minute {
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
	return s.closeOrphans(ctx, rules, scopes, hosts, open, now)
}

// scope is the answer of a rule's selector over the fleet for one run of
// the evaluator.
type scope struct {
	// everybody is true for a selector that narrows nothing; hosts is the
	// set the selector resolved to otherwise.
	everybody bool
	hosts     map[string]bool
}

// covers says whether the host is in the scope.
func (sc *scope) covers(hostID string) bool {
	return sc.everybody || sc.hosts[hostID]
}

// scopes resolves the selector of every enabled rule once per run, in the
// database, through the same compiler the campaign preview uses: a rule
// on a tag, a group or an expression picks exactly the hosts a campaign
// on the same selector would.
//
// A rule whose selector does not resolve - a group deleted since the rule
// was written - has no entry. Its episodes stay as they are, neither
// advanced nor closed: nothing can be said about hosts nobody can name,
// and a log line says which rule needs mending.
func (s *Store) scopes(ctx context.Context, rules []Rule) map[string]*scope {
	scopes := make(map[string]*scope, len(rules))
	for _, rule := range rules {
		if !rule.Enabled {
			continue
		}
		if !rule.Selector.Narrows() {
			scopes[rule.ID] = &scope{everybody: true}
			continue
		}
		covered, err := s.coveredHosts(ctx, rule.Selector)
		if err != nil {
			s.log.Warn("the selector of an alert rule does not resolve; the rule is not evaluated",
				"rule", rule.Name, "error", err)
			continue
		}
		scopes[rule.ID] = &scope{hosts: covered}
	}
	return scopes
}

// coveredHosts reads the identifiers of the hosts a selector names among
// the ones the evaluator looks at.
func (s *Store) coveredHosts(ctx context.Context, sel Selector) (map[string]bool, error) {
	condition, args, err := s.compileSelector(ctx, sel, 0)
	if err != nil {
		return nil, err
	}
	rows, err := s.pool.Query(ctx,
		`select h.id from hosts h where h.lifecycle_state <> 'retired' and `+condition, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	covered := map[string]bool{}
	for rows.Next() {
		var id string
		if err := rows.Scan(&id); err != nil {
			return nil, err
		}
		covered[id] = true
	}
	return covered, rows.Err()
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

// maxSampleGap is the longest hole in a host's samples that still counts
// as one continuous run of readings: twice the sampling interval, so a
// single lost sample is a lost sample and two in a row are a gap. The
// same limit answers both questions - how long a for-window may be
// believed, and how long a rule may be without data before its pending
// episode is held back.
const maxSampleGap = 2 * SamplingInterval

// observedSince returns the moment from which the rule's window is
// counted for the episode: the start of the uninterrupted run of samples
// that reaches now. A rule that fires at the first sample, and the
// host_offline rule - whose subject is the absence of samples, so a gap
// is its evidence rather than its blind spot - count from the episode.
//
// A run that starts later than the episode is written onto the episode,
// so the history says when the condition began to be watched rather than
// when it was first seen, and the next run of the evaluator does not read
// the samples of the gap again.
func (s *Store) observedSince(ctx context.Context, rule Rule, host hostState,
	episode openAlert, now time.Time) (time.Time, error) {
	if rule.ForMinutes == 0 || rule.Metric == MetricHostOffline {
		return episode.StartedAt, nil
	}
	samples, err := s.sampleTimes(ctx, host.ID, episode.StartedAt)
	if err != nil {
		return time.Time{}, err
	}
	since := continuousSince(episode.StartedAt, samples, now, maxSampleGap)
	if since.After(episode.StartedAt) {
		if err := s.restart(ctx, episode.ID, since); err != nil {
			return time.Time{}, err
		}
	}
	return since, nil
}

// continuousSince walks the samples of an episode in order and returns
// the start of the last uninterrupted run: the moment after the last hole
// wider than gap. A last sample older than gap means no run reaches now
// at all, and the run starts now - the condition has yet to be watched.
func continuousSince(started time.Time, samples []time.Time, now time.Time, gap time.Duration) time.Time {
	since, last := started, started
	for _, at := range samples {
		if at.Before(started) {
			continue
		}
		if at.Sub(last) > gap {
			since = at
		}
		last = at
	}
	if now.Sub(last) > gap {
		return now
	}
	return since
}

// noDataHold says whether a pending episode without a reading has been
// without one long enough to have its timer restarted. The check spares
// the database a write on every run of the evaluator for a host that has
// nothing to say - a rule on swap over a host without swap - while a
// silence longer than a gap still cannot carry the episode to firing.
func noDataHold(episode openAlert, now time.Time) bool {
	return episode.State == "pending" && now.Sub(episode.StartedAt) > maxSampleGap
}

// sampleTimes reads the moments of the host's samples since the given one,
// oldest first.
func (s *Store) sampleTimes(ctx context.Context, hostID string, since time.Time) ([]time.Time, error) {
	rows, err := s.pool.Query(ctx,
		`select at from host_metrics where host_id = $1 and at >= $2 order by at`, hostID, since)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var moments []time.Time
	for rows.Next() {
		var at time.Time
		if err := rows.Scan(&at); err != nil {
			return nil, err
		}
		moments = append(moments, at)
	}
	return moments, rows.Err()
}

// restart moves the start of a pending episode, so its window is counted
// from there. A firing episode is never moved: it has already fired.
func (s *Store) restart(ctx context.Context, id string, at time.Time) error {
	_, err := s.pool.Exec(ctx,
		`update alerts set started_at = $2 where id = $1 and state = 'pending'`, id, at)
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
//
// A rule whose selector did not resolve this run keeps its episodes: they
// are not orphans, they are waiting for the rule to be mended.
func (s *Store) closeOrphans(ctx context.Context, rules []Rule, scopes map[string]*scope,
	hosts []hostState, open map[string]openAlert, now time.Time) error {
	covered := map[string]bool{}
	unresolved := map[string]bool{}
	for _, rule := range rules {
		if !rule.Enabled {
			continue
		}
		within := scopes[rule.ID]
		if within == nil {
			unresolved[rule.ID] = true
			continue
		}
		for _, host := range hosts {
			if within.covers(host.ID) {
				covered[rule.ID+"/"+host.ID] = true
			}
		}
	}
	for key, episode := range open {
		if covered[key] {
			continue
		}
		if ruleID, _, _ := strings.Cut(key, "/"); unresolved[ruleID] {
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
	case MetricAgentRSSBytes:
		// An agent that did not report its footprint - too old, or a
		// procfs it could not read - is not an agent using no memory.
		if sample.AgentRSSBytes == nil {
			return 0, "", false
		}
		value := float64(*sample.AgentRSSBytes)
		return value, fmt.Sprintf("agent rss %s (%s %s %s)", formatBytes(value),
			rule.Metric, symbol(rule.Operator), formatBytes(rule.Threshold)), true
	case MetricAgentCPUPercent:
		if sample.AgentCPUPercent == nil {
			return 0, "", false
		}
		value := *sample.AgentCPUPercent
		return value, describe(value, "%"), true
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

// formatBytes renders a size in the binary unit that fits, as the panel
// does.
func formatBytes(value float64) string {
	units := []string{"B", "KiB", "MiB", "GiB", "TiB"}
	unit := 0
	for value >= 1024 && unit < len(units)-1 {
		value /= 1024
		unit++
	}
	return fmt.Sprintf("%s %s", formatValue(value), units[unit])
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
		       m.swap_total, m.swap_used, m.uptime_seconds, m.filesystems,
		       m.agent_rss_bytes, m.agent_cpu_percent
		from hosts h
		left join lateral (
		    select at, cpu_percent, load1, memory_total, memory_used, swap_total, swap_used,
		           uptime_seconds, filesystems, agent_rss_bytes, agent_cpu_percent
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
		var agentRSS *int64
		var agentCPU *float32
		if err := rows.Scan(&host.ID, &host.Hostname, &host.Site, &host.Environment, &host.OSFamily,
			&host.LastSampleAt, &host.Cores, &at, &cpu, &load1, &memoryTotal, &memoryUsed,
			&swapTotal, &swapUsed, &uptime, &filesystems, &agentRSS, &agentCPU); err != nil {
			return nil, err
		}
		if at != nil {
			host.Latest = &Sample{
				At: *at, CPUPercent: float64(*cpu), Load1: float64(*load1),
				MemoryTotal: uint64(*memoryTotal), MemoryUsed: uint64(*memoryUsed),
				SwapTotal: uint64(*swapTotal), SwapUsed: uint64(*swapUsed),
				UptimeSeconds: uint64(*uptime), Filesystems: filesystems,
				AgentRSSBytes: unsignedOf(agentRSS), AgentCPUPercent: float64Of(agentCPU),
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
