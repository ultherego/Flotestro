package monitoring

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/google/uuid"

	"github.com/ultherego/flotestro/internal/metrics"
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
	// Fired says the episode reached its firing point at some moment: it
	// decides what a no-data episode goes back to and how it ends.
	Fired bool
}

// Evaluate runs every enabled rule over the matching hosts once. It takes the
// lease like any other pass: there is no unfenced way to judge the fleet.
func (s *Store) Evaluate(ctx context.Context, now time.Time) error {
	return s.EvaluateLeased(ctx, now)
}

// EvaluateLeased is the pass the running panel makes: one instance at a time,
// under a lease taken from the database.
func (s *Store) EvaluateLeased(ctx context.Context, now time.Time) error {
	lease, held, err := s.TakeEvaluatorLease(ctx)
	if err != nil {
		return err
	}
	if !held {
		s.log.Debug("another instance holds the lease of the alert evaluator; the rules are judged there")
		return nil
	}
	defer func() {
		// The lease is given back at the end of the pass so that the next instance
		// may take it at once instead of waiting out the term.
		if err := s.ReleaseEvaluatorLease(context.WithoutCancel(ctx), lease); err != nil {
			s.log.Warn("the lease of the alert evaluator was not given back; it runs out by itself",
				"err", err)
		}
	}()

	if err := s.EvaluateUnder(ctx, now, lease); err != nil {
		if errors.Is(err, ErrLeaseLost) {
			// Not a failure of the panel: another instance judges the
			// fleet now, and this pass stopped rather than writing over it.
			s.log.Warn("the lease of the alert evaluator was lost during the pass; the pass was stopped",
				"holder", lease.Holder, "token", lease.Token, "err", err)
			return nil
		}
		return err
	}
	return nil
}

// EvaluateUnder runs one pass under a lease this instance already holds: it
// renews the lease as it goes and stamps every write with the lease's token.
func (s *Store) EvaluateUnder(ctx context.Context, now time.Time, lease Lease) error {
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
	return s.evaluate(ctx, now, fenceOf(lease), guard)
}

// evaluatorGuardEvery is how many hosts of one rule pass between two checks of
// the lease; the renewal behind the check is spaced by time, not by hosts.
const evaluatorGuardEvery = 256

// evaluate is the pass itself.
func (s *Store) evaluate(ctx context.Context, now time.Time, f fence, guard func(context.Context) error) error {
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
		// Asked between rules rather than only at the start: a pass over a fleet
		// takes time, and an instance that lost its lease halfway must stop writing.
		if guard != nil {
			if err := guard(ctx); err != nil {
				return err
			}
		}
		within := scopes[rule.ID]
		if !rule.Enabled || within == nil {
			continue
		}
		for index, host := range hosts {
			// Asked inside the fleet as well: a rule over ten thousand hosts is a long
			// way to walk on a lease somebody else may already have taken.
			if guard != nil && index > 0 && index%evaluatorGuardEvery == 0 {
				if err := guard(ctx); err != nil {
					return err
				}
			}
			if !within.covers(host.ID) {
				continue
			}
			key := rule.ID + "/" + host.ID
			episode, exists := open[key]
			mark := alertWrite{rule: rule.ID, host: host.ID}
			// Asked before anything is computed: past the rule's own gap the newest
			// reading is not current, whatever a value taken from it would say.
			if rule.Policy() != NoDataIgnore && readingsStopped(rule, host, now) {
				if err := s.noData(ctx, f, rule, host, mark, episode, exists, now); err != nil {
					return err
				}
				continue
			}
			value, detail, known := measure(rule, host, now)
			if !known {
				// Nothing can be said: the episode is not cleared - the condition may well
				// still hold - but it is not advanced either.
				if exists && noDataHold(episode, now, rule.MaxGap()) {
					if err := s.restart(ctx, f, mark.on(episode.ID), now); err != nil {
						return err
					}
				}
				continue
			}
			holds := compare(rule.Operator, value, rule.Threshold)
			switch {
			case exists && episode.State == "no_data":
				if err := s.resume(ctx, f, mark.on(episode.ID), rule, episode,
					holds, value, detail, now); err != nil {
					return err
				}
			case holds && !exists:
				if err := s.startEpisode(ctx, f, rule, host, value, detail, now); err != nil {
					return err
				}
			case holds && episode.State == "pending":
				since, err := s.observedSince(ctx, f, rule, host, episode, now)
				if err != nil {
					return err
				}
				if now.Sub(since) >= time.Duration(rule.ForMinutes)*time.Minute {
					if err := s.fire(ctx, f, mark.on(episode.ID), value, detail, now); err != nil {
						return err
					}
				} else if err := s.refresh(ctx, f, mark.on(episode.ID), episode, value, detail); err != nil {
					return err
				}
			case holds:
				if err := s.refresh(ctx, f, mark.on(episode.ID), episode, value, detail); err != nil {
					return err
				}
			case !holds && exists && episode.State == "pending":
				if err := s.discard(ctx, f, mark.on(episode.ID)); err != nil {
					return err
				}
			case !holds && exists:
				if err := s.resolve(ctx, f, mark.on(episode.ID), now, &value); err != nil {
					return err
				}
			}
		}
	}
	// The episodes of the rules that no longer cover their host - the selector
	// changed, the host moved - end here rather than staying open for ever.
	return s.closeOrphans(ctx, f, rules, scopes, hosts, open, now)
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
// database, through the same compiler the campaign preview uses.
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

// alertWrite names one write for the counter and the log line: which write, on
// which rule and host, and on which episode.
type alertWrite struct {
	kind string
	rule string
	host string
	id   string
}

// on names the episode the write lands on, kinded the write itself.
func (w alertWrite) on(id string) alertWrite { w.id = id; return w }

func (w alertWrite) kinded(kind string) alertWrite { w.kind = kind; return w }

// fencePredicate is the row half of the fence as every statement carries it.
const fencePredicate = `(fence_row.fencing_token is null or
	 fence_row.fencing_token <= fence_lease.token)`

// fencedWrite frames one statement that moves an alert row. The lease is read
// in the same statement as the write, so a pass that lost it writes nothing.
const fencedWrite = `
with fence_lease as (
    select token from monitoring_leases
     where name = '` + evaluatorLeaseName + `'
       and holder = $2::uuid and token = $3 and lease_until > now()
),
fence_row as (
    select id, state, fencing_token from alerts where id = $1::uuid
),
written as (
    %s
)
select exists (select 1 from written),
       (select fencing_token from fence_row),
       exists (select 1 from fence_lease)`

// write runs one statement of the evaluator under the fence. It answers nil
// both when the row moved and when a state guard found it already moved on.
func (s *Store) write(ctx context.Context, f fence, w alertWrite, body string, args ...any) error {
	if !f.held() {
		// Fail closed: a pass with no lease to write under writes nothing.
		return s.fenceRefused(f, w, nil)
	}
	params := append([]any{w.id, f.Holder, f.Token}, args...)
	var wrote, leased bool
	var rowToken *int64
	if err := s.pool.QueryRow(ctx, fmt.Sprintf(fencedWrite, body), params...).
		Scan(&wrote, &rowToken, &leased); err != nil {
		return err
	}
	if wrote {
		return nil
	}
	if !leased || !f.accepts(rowToken) {
		return s.fenceRefused(f, w, rowToken)
	}
	return nil
}

// fenceRefused counts and names a write the fence turned down: which write, on
// which host and rule, under which token and over which.
func (s *Store) fenceRefused(f fence, w alertWrite, rowToken *int64) error {
	metrics.AlertFence.Inc(w.kind)
	// Zero is "the row carries no token": nothing fenced whatever wrote it last.
	var onRow int64
	if rowToken != nil {
		onRow = *rowToken
	}
	s.log.Warn("the fence refused a write of the alert state; a newer leader owns the episode",
		"code", ErrorAlertFenceStale, "write", w.kind, "rule", w.rule, "host", w.host,
		"alert", w.id, "token", f.Token, "row_token", onRow, "holder", f.Holder)
	return ErrFenceStale
}

// fencedInsert opens an episode under the lease, so an instance that lost the
// fleet cannot start one on it either.
const fencedInsert = `
with fence_lease as (
    select token from monitoring_leases
     where name = '` + evaluatorLeaseName + `'
       and holder = $1::uuid and token = $2 and lease_until > now()
),
written as (
    insert into alerts (id, rule_id, rule_name, metric, severity, host_id, state,
        value, detail, started_at, fired_at, no_data_policy, fencing_token)
    select $3::uuid, $4::uuid, $5::text, $6::text, $7::text, $8::uuid, $9::text,
           $10::real, $11::text, $12::timestamptz, $13::timestamptz, $14::text,
           fence_lease.token
      from fence_lease
    on conflict do nothing
    returning id
)
select exists (select 1 from written), exists (select 1 from fence_lease)`

// startEpisode opens the episode of a condition that has just been seen.
func (s *Store) startEpisode(ctx context.Context, f fence, rule Rule, host hostState,
	value float64, detail string, now time.Time) error {
	state := "pending"
	var firedAt *time.Time
	if rule.ForMinutes == 0 {
		state = "firing"
		firedAt = &now
	}
	return s.openEpisode(ctx, f, rule, host, state, value, detail, firedAt, now)
}

// openEpisode writes the row of a new episode in whichever state it starts in,
// stamped with the policy the rule carried at the time.
func (s *Store) openEpisode(ctx context.Context, f fence, rule Rule, host hostState,
	state string, value float64, detail string, firedAt *time.Time, now time.Time) error {
	mark := alertWrite{kind: "start", rule: rule.ID, host: host.ID}
	if !f.held() {
		return s.fenceRefused(f, mark, nil)
	}
	var wrote, leased bool
	if err := s.pool.QueryRow(ctx, fencedInsert,
		f.Holder, f.Token, uuid.NewString(), rule.ID, rule.Name, rule.Metric, rule.Severity,
		host.ID, state, float32(value), detail, now, firedAt, rule.Policy()).
		Scan(&wrote, &leased); err != nil {
		return err
	}
	if !wrote && !leased {
		return s.fenceRefused(f, mark, nil)
	}
	// Nothing written under a standing lease means the open episode was already
	// there: the list of open episodes is read once, at the start of the pass.
	return nil
}

// readingsStopped says the readings the rule needs have stopped for longer than
// it allows. A host_offline rule is never in a gap: silence is its reading.
func readingsStopped(rule Rule, host hostState, now time.Time) bool {
	if rule.Metric == MetricHostOffline {
		return false
	}
	if host.Latest == nil {
		return true
	}
	// The panel's own clock decides whether a host is talking: a host whose
	// clock runs slow is not silent, and stamping it silent evaluates nothing.
	return now.Sub(currentAt(host.Latest)) > rule.MaxGap()
}

// currentAt is the moment a reading's freshness is measured from: when the
// panel received it, or, for one that carries no receipt, when it was taken.
func currentAt(sample *Sample) time.Time {
	if sample == nil {
		return time.Time{}
	}
	if !sample.ReceivedAt.IsZero() {
		return sample.ReceivedAt
	}
	return sample.At
}

// receivedOrTaken is the moment the panel got the reading, falling back to the
// moment the host says it took it for a row written before the column.
func receivedOrTaken(received *time.Time, taken time.Time) time.Time {
	if received != nil && !received.IsZero() {
		return *received
	}
	return taken
}

// gapDetail says how long the readings have been missing and what the rule
// allows, in the words the episode carries.
func gapDetail(rule Rule, host hostState, now time.Time) string {
	allowed := formatDuration(rule.MaxGap().Seconds())
	if host.Latest == nil {
		return fmt.Sprintf("no reading of %s at all; the rule allows a gap of %s",
			rule.Metric, allowed)
	}
	return fmt.Sprintf("no reading of %s for %s; the rule allows a gap of %s",
		rule.Metric, formatDuration(now.Sub(currentAt(host.Latest)).Seconds()), allowed)
}

// noData is the gap the rule asked to be told about: alert raises an episode
// where there is none, unknown only marks the open one and leaves its value.
func (s *Store) noData(ctx context.Context, f fence, rule Rule, host hostState,
	w alertWrite, episode openAlert, exists bool, now time.Time) error {
	detail := gapDetail(rule, host, now)
	if !exists {
		if rule.Policy() != NoDataAlert {
			return nil
		}
		return s.openEpisode(ctx, f, rule, host, "no_data", 0, detail, nil, now)
	}
	if episode.State == "no_data" {
		return nil
	}
	return s.write(ctx, f, w.on(episode.ID).kinded("no_data"), `
		update alerts a
		   set state = 'no_data', detail = $4, no_data_policy = $5,
		       fencing_token = fence_lease.token
		  from fence_row, fence_lease
		 where a.id = fence_row.id and fence_row.state in ('pending', 'firing')
		   and `+fencePredicate+`
		returning a.id`, detail, rule.Policy())
}

// resume takes an episode out of no_data now that the readings are back: one
// that had fired fires again, one that had not starts its window now.
func (s *Store) resume(ctx context.Context, f fence, w alertWrite, rule Rule,
	episode openAlert, holds bool, value float64, detail string, now time.Time) error {
	if !holds {
		if episode.Fired {
			return s.resolve(ctx, f, w, now, &value)
		}
		return s.discard(ctx, f, w)
	}
	state, startedAt := "pending", now
	var firedAt *time.Time
	switch {
	case episode.Fired:
		state, startedAt = "firing", episode.StartedAt
	case rule.ForMinutes == 0:
		state, firedAt = "firing", &now
	}
	return s.write(ctx, f, w.kinded("resume"), `
		update alerts a
		   set state = $4, started_at = $5,
		       fired_at = coalesce($6::timestamptz, a.fired_at),
		       value = $7, detail = $8, fencing_token = fence_lease.token
		  from fence_row, fence_lease
		 where a.id = fence_row.id and fence_row.state = 'no_data' and `+fencePredicate+`
		returning a.id`, state, startedAt, firedAt, float32(value), detail)
}

// observedSince returns the moment from which the rule's window is counted for
// the episode: the start of the uninterrupted run of samples that reaches now.
func (s *Store) observedSince(ctx context.Context, f fence, rule Rule, host hostState,
	episode openAlert, now time.Time) (time.Time, error) {
	if rule.ForMinutes == 0 || rule.Metric == MetricHostOffline {
		return episode.StartedAt, nil
	}
	samples, err := s.sampleRun(ctx, host.ID, episode.StartedAt)
	if err != nil {
		return time.Time{}, err
	}
	since := continuousSince(episode.StartedAt, samples, now, rule.MaxGap(), holdsFor(rule, host))
	if since.After(episode.StartedAt) {
		mark := alertWrite{rule: rule.ID, host: host.ID, id: episode.ID}
		if err := s.restart(ctx, f, mark, since); err != nil {
			return time.Time{}, err
		}
	}
	return since, nil
}

// holdsFor judges one reading of the run by the rule, as the pass judges the
// newest one: a reading the rule does not hold for breaks the run.
func holdsFor(rule Rule, host hostState) func(Sample) bool {
	return func(sample Sample) bool {
		at := host
		at.Latest = &sample
		// The sample's own moment stands for now, or measure would call every
		// reading of the history stale and break every run.
		value, _, known := measure(rule, at, currentAt(&sample))
		return known && compare(rule.Operator, value, rule.Threshold)
	}
}

// continuousSince walks the samples of an episode in order and returns the
// start of its last unbroken run: the first reading after the last wide hole
// or after the last reading the rule did not hold for. A window counted from
// the timestamps alone would read high-low-high as one long high.
func continuousSince(started time.Time, samples []Sample, now time.Time, gap time.Duration,
	holds func(Sample) bool) time.Time {
	since, last := started, started
	broke := false
	for _, sample := range samples {
		at := sample.At
		if at.Before(started) {
			continue
		}
		switch {
		case at.Sub(last) > gap:
			// The hole lies before this reading, so the run starts here.
			since, broke = at, false
		case broke:
			since, broke = at, false
		}
		if holds != nil && !holds(sample) {
			// The condition broke here; the run can only start with the next
			// reading, and there may be none.
			broke = true
		}
		last = at
	}
	if broke || now.Sub(last) > gap {
		return now
	}
	return since
}

// noDataHold says whether a pending episode without a reading has been without
// one long enough to have its timer restarted.
func noDataHold(episode openAlert, now time.Time, gap time.Duration) bool {
	return episode.State == "pending" && now.Sub(episode.StartedAt) > gap
}

// sampleRun reads the host's samples since the given moment, oldest first,
// with what the rules measure: the window is judged on the readings, not on
// the fact that rows exist.
func (s *Store) sampleRun(ctx context.Context, hostID string, since time.Time) ([]Sample, error) {
	rows, err := s.pool.Query(ctx, `
		select at, received_at, cpu_percent, load1, memory_total, memory_used,
		       swap_total, swap_used, uptime_seconds, filesystems,
		       agent_rss_bytes, agent_cpu_percent
		  from host_metrics where host_id = $1 and at >= $2 order by at`, hostID, since)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var samples []Sample
	for rows.Next() {
		var sample Sample
		var receivedAt *time.Time
		var cpu, load1, agentCPU *float32
		var memoryTotal, memoryUsed, swapTotal, swapUsed, uptime, agentRSS *int64
		var filesystems []Filesystem
		if err := rows.Scan(&sample.At, &receivedAt, &cpu, &load1, &memoryTotal, &memoryUsed,
			&swapTotal, &swapUsed, &uptime, &filesystems, &agentRSS, &agentCPU); err != nil {
			return nil, err
		}
		sample.ReceivedAt = receivedOrTaken(receivedAt, sample.At)
		sample.CPUPercent, sample.Load1 = float64Value(cpu), float64Value(load1)
		sample.MemoryTotal, sample.MemoryUsed = unsignedValue(memoryTotal), unsignedValue(memoryUsed)
		sample.SwapTotal, sample.SwapUsed = unsignedValue(swapTotal), unsignedValue(swapUsed)
		sample.UptimeSeconds, sample.Filesystems = unsignedValue(uptime), filesystems
		sample.AgentRSSBytes, sample.AgentCPUPercent = unsignedOf(agentRSS), float64Of(agentCPU)
		samples = append(samples, sample)
	}
	return samples, rows.Err()
}

// float64Value and unsignedValue read a column that may be null as zero: a
// reading without the number is a reading the rule cannot be judged on, and
// measure says so by the metric it is asked about.
func float64Value(value *float32) float64 {
	if value == nil {
		return 0
	}
	return float64(*value)
}

func unsignedValue(value *int64) uint64 {
	if value == nil || *value < 0 {
		return 0
	}
	return uint64(*value)
}

// restart moves the start of a pending episode, so its window is counted
// from there. A firing episode is never moved: it has already fired.
func (s *Store) restart(ctx context.Context, f fence, w alertWrite, at time.Time) error {
	return s.write(ctx, f, w.kinded("restart"), `
		update alerts a
		   set started_at = $4, fencing_token = fence_lease.token
		  from fence_row, fence_lease
		 where a.id = fence_row.id and fence_row.state = 'pending' and `+fencePredicate+`
		returning a.id`, at)
}

func (s *Store) fire(ctx context.Context, f fence, w alertWrite,
	value float64, detail string, now time.Time) error {
	return s.write(ctx, f, w.kinded("fire"), `
		update alerts a
		   set state = 'firing', fired_at = $4, value = $5, detail = $6,
		       fencing_token = fence_lease.token
		  from fence_row, fence_lease
		 where a.id = fence_row.id and fence_row.state = 'pending' and `+fencePredicate+`
		returning a.id`, now, float32(value), detail)
}

// refresh keeps the value and the message of an open episode current. A
// write only when something changed: the fleet has many quiet minutes.
func (s *Store) refresh(ctx context.Context, f fence, w alertWrite,
	episode openAlert, value float64, detail string) error {
	if float32(value) == float32(episode.Value) && detail == episode.Detail {
		return nil
	}
	return s.write(ctx, f, w.kinded("refresh"), `
		update alerts a
		   set value = $4, detail = $5, fencing_token = fence_lease.token
		  from fence_row, fence_lease
		 where a.id = fence_row.id and `+fencePredicate+`
		returning a.id`, float32(value), detail)
}

// resolve ends a firing episode. The value is the last reading where there is
// one; without a reading the episode keeps the value it already had.
func (s *Store) resolve(ctx context.Context, f fence, w alertWrite,
	now time.Time, value *float64) error {
	var reading *float32
	if value != nil {
		last := float32(*value)
		reading = &last
	}
	return s.write(ctx, f, w.kinded("resolve"), `
		update alerts a
		   set state = 'resolved', resolved_at = $4,
		       value = coalesce($5::real, a.value), fencing_token = fence_lease.token
		  from fence_row, fence_lease
		 where a.id = fence_row.id and fence_row.state in ('firing', 'no_data')
		   and `+fencePredicate+`
		returning a.id`, now, reading)
}

// discard removes a pending episode that never fired: a condition that lasted
// one sample is not an alert.
func (s *Store) discard(ctx context.Context, f fence, w alertWrite) error {
	return s.write(ctx, f, w.kinded("discard"), `
		delete from alerts a
		 using fence_row, fence_lease
		 where a.id = fence_row.id and fence_row.state in ('pending', 'no_data')
		   and `+fencePredicate+`
		returning a.id`)
}

// closeOrphans ends the open episodes whose rule no longer covers their host
// or whose host is gone from the fleet.
func (s *Store) closeOrphans(ctx context.Context, f fence, rules []Rule, scopes map[string]*scope,
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
		ruleID, hostID, _ := strings.Cut(key, "/")
		if unresolved[ruleID] {
			continue
		}
		mark := alertWrite{rule: ruleID, host: hostID, id: episode.ID}
		if !episode.Fired {
			if err := s.discard(ctx, f, mark); err != nil {
				return err
			}
			continue
		}
		if err := s.resolve(ctx, f, mark, now, nil); err != nil {
			return err
		}
	}
	return nil
}

// measure computes the value of the rule's metric for the host and the message
// an alert would carry.
func measure(rule Rule, host hostState, now time.Time) (value float64, detail string, known bool) {
	if rule.Metric == MetricHostOffline {
		if host.LastSampleAt == nil {
			// A host that never sent a sample runs an agent without the sampler or has
			// not connected since it was enrolled; neither is a host that went quiet.
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
	// Whether a reading is still current is the panel's clock; the host's own
	// moment says where the chart draws it, not whether it arrived.
	if sample == nil || now.Sub(currentAt(sample)) > silentAfter {
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
		       m.at, m.received_at, m.cpu_percent, m.load1, m.memory_total, m.memory_used,
		       m.swap_total, m.swap_used, m.uptime_seconds, m.filesystems,
		       m.agent_rss_bytes, m.agent_cpu_percent
		from hosts h
		left join lateral (
		    select at, received_at, cpu_percent, load1, memory_total, memory_used, swap_total, swap_used,
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
		var at, receivedAt *time.Time
		var cpu, load1 *float32
		var memoryTotal, memoryUsed, swapTotal, swapUsed, uptime *int64
		var filesystems []Filesystem
		var agentRSS *int64
		var agentCPU *float32
		if err := rows.Scan(&host.ID, &host.Hostname, &host.Site, &host.Environment, &host.OSFamily,
			&host.LastSampleAt, &host.Cores, &at, &receivedAt, &cpu, &load1, &memoryTotal, &memoryUsed,
			&swapTotal, &swapUsed, &uptime, &filesystems, &agentRSS, &agentCPU); err != nil {
			return nil, err
		}
		if at != nil {
			host.Latest = &Sample{
				At: *at, ReceivedAt: receivedOrTaken(receivedAt, *at),
				CPUPercent: float64(*cpu), Load1: float64(*load1),
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
		select id, coalesce(rule_id::text, ''), host_id, state, value, detail, started_at,
		       fired_at is not null
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
			&episode.Detail, &episode.StartedAt, &episode.Fired); err != nil {
			return nil, err
		}
		episode.Value = float64(value)
		open[ruleID+"/"+hostID] = episode
	}
	return open, rows.Err()
}
