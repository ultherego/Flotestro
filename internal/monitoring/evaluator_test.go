package monitoring

import (
	"strings"
	"testing"
	"time"
)

func TestMeasureComputesEveryMetric(t *testing.T) {
	now := time.Date(2026, 9, 13, 12, 0, 0, 0, time.UTC)
	sampledAt := now.Add(-30 * time.Second)
	agentRSS, agentCPU := uint64(300<<20), 12.5
	host := hostState{
		ID: "h1", Cores: 4, LastSampleAt: &sampledAt,
		Latest: &Sample{
			At: sampledAt, CPUPercent: 93.5, Load1: 6,
			MemoryTotal: 1000, MemoryUsed: 960, SwapTotal: 200, SwapUsed: 50,
			UptimeSeconds: 120,
			AgentRSSBytes: &agentRSS, AgentCPUPercent: &agentCPU,
			Filesystems: []Filesystem{
				{Mount: "/", TotalBytes: 100, UsedBytes: 40, InodesTotal: 10, InodesUsed: 9},
				{Mount: "/var", TotalBytes: 100, UsedBytes: 98, InodesTotal: 10, InodesUsed: 1},
				{Mount: "/empty", TotalBytes: 0, UsedBytes: 0},
			},
		},
	}
	cases := []struct {
		metric string
		value  float64
		detail string
	}{
		{MetricCPUPercent, 93.5, "cpu_percent 93.5%"},
		{MetricLoad1PerCore, 1.5, "load1_per_core 1.5"},
		{MetricMemoryUsedPercent, 96, "memory_used_percent 96%"},
		{MetricSwapUsedPercent, 25, "swap_used_percent 25%"},
		{MetricFilesystemUsedPercent, 98, "/var: filesystem_used_percent 98%"},
		{MetricInodesUsedPercent, 90, "/: inodes_used_percent 90%"},
		{MetricHostOffline, 0.5, "no sample for 0 min"},
		{MetricUptimeSeconds, 120, "uptime 2m"},
		{MetricAgentRSSBytes, 300 << 20, "agent rss 300 MiB"},
		{MetricAgentCPUPercent, 12.5, "agent_cpu_percent 12.5%"},
	}
	for _, c := range cases {
		rule := Rule{Metric: c.metric, Operator: "gt", Threshold: 1}
		value, detail, known := measure(rule, host, now)
		if !known {
			t.Errorf("%s: not known", c.metric)
			continue
		}
		if value != c.value {
			t.Errorf("%s: value = %v, want %v", c.metric, value, c.value)
		}
		if !strings.Contains(detail, c.detail) {
			t.Errorf("%s: detail %q does not name %q", c.metric, detail, c.detail)
		}
	}
}

func TestMeasureSaysUnknownRatherThanZero(t *testing.T) {
	now := time.Date(2026, 9, 13, 12, 0, 0, 0, time.UTC)
	stale := now.Add(-10 * time.Minute)
	cases := map[string]struct {
		rule Rule
		host hostState
	}{
		"a host that never sampled": {
			Rule{Metric: MetricCPUPercent, Operator: "gt"}, hostState{},
		},
		"a stale sample": {
			Rule{Metric: MetricCPUPercent, Operator: "gt"},
			hostState{LastSampleAt: &stale, Latest: &Sample{At: stale, CPUPercent: 99}},
		},
		"host_offline without any sample": {
			Rule{Metric: MetricHostOffline, Operator: "gt"}, hostState{},
		},
		"swap on a host without swap": {
			Rule{Metric: MetricSwapUsedPercent, Operator: "lt"},
			hostState{LastSampleAt: &now, Latest: &Sample{At: now}},
		},
		"filesystems without a measurable mount": {
			Rule{Metric: MetricFilesystemUsedPercent, Operator: "gt"},
			hostState{LastSampleAt: &now, Latest: &Sample{At: now}},
		},
		// An agent that sent no footprint - too old, or a procfs it could
		// not read - is not an agent using nothing.
		"agent memory the agent did not report": {
			Rule{Metric: MetricAgentRSSBytes, Operator: "lt"},
			hostState{LastSampleAt: &now, Latest: &Sample{At: now}},
		},
		"agent cpu the agent did not report": {
			Rule{Metric: MetricAgentCPUPercent, Operator: "lt"},
			hostState{LastSampleAt: &now, Latest: &Sample{At: now}},
		},
	}
	for name, c := range cases {
		if _, _, known := measure(c.rule, c.host, now); known {
			t.Errorf("%s: measured as known", name)
		}
	}

	// A stale sample says nothing about the CPU, but everything about the
	// host being quiet.
	value, _, known := measure(Rule{Metric: MetricHostOffline, Operator: "gt", Threshold: 5},
		hostState{LastSampleAt: &stale}, now)
	if !known || value != 10 {
		t.Errorf("host_offline over a stale host = %v (known %v)", value, known)
	}
}

func TestCompareAppliesTheOperator(t *testing.T) {
	cases := []struct {
		operator         string
		value, threshold float64
		want             bool
	}{
		{"gt", 91, 90, true}, {"gt", 90, 90, false},
		{"gte", 90, 90, true}, {"lt", 89, 90, true},
		{"lt", 90, 90, false}, {"lte", 90, 90, true},
		{"between", 1, 2, false},
	}
	for _, c := range cases {
		if got := compare(c.operator, c.value, c.threshold); got != c.want {
			t.Errorf("compare(%s, %v, %v) = %v", c.operator, c.value, c.threshold, got)
		}
	}
}

// TestSelectorTreeIsACampaignSelector: the scope of a rule is the same
// structure a campaign selector is, so the two compile the same way.
func TestSelectorTreeIsACampaignSelector(t *testing.T) {
	cases := []struct {
		name     string
		selector Selector
		want     string
	}{
		{"empty narrows nothing", Selector{}, ""},
		{"only a host list narrows nothing here", Selector{HostIDs: []string{"h1"}}, ""},
		{"the site", Selector{Site: "warsaw"}, "site=warsaw"},
		{"the environment and family", Selector{Environment: "prod", OSFamily: "debian"},
			"(environment=prod and os_family=debian)"},
		{"every tag", Selector{Tags: []string{"role=db", "tier=gold"}}, "(tag=role=db and tag=tier=gold)"},
		{"one group", Selector{Groups: []string{"databases"}}, "group=databases"},
		{"any of the groups", Selector{Groups: []string{"databases", "caches"}},
			"(group=databases or group=caches)"},
		{"the owner", Selector{Owner: "platform"}, "owner=platform"},
		{"the expression", Selector{Expression: "agent_version < 0.49.0 or reboot_required = true"},
			"(agent_version < 0.49.0 or reboot_required=true)"},
		{"everything at once", Selector{Site: "warsaw", Tags: []string{"role=db"}, Expression: "security_updates = true"},
			"(site=warsaw and tag=role=db and security_updates=true)"},
	}
	for _, c := range cases {
		expression, err := c.selector.Tree()
		if err != nil {
			t.Errorf("%s: %v", c.name, err)
			continue
		}
		if got := expression.Describe(); got != c.want {
			t.Errorf("%s: expression = %q, expected %q", c.name, got, c.want)
		}
		if narrows := c.selector.Narrows(); narrows != (c.want != "" || len(c.selector.HostIDs) > 0) {
			t.Errorf("%s: narrows = %v", c.name, narrows)
		}
	}
	if _, err := (Selector{Expression: "colour = blue"}).Tree(); err == nil {
		t.Error("an expression naming no key was rendered")
	}
}

// TestScopeCoversTheResolvedHosts: a scope that narrows nothing covers
// every host; one resolved to a set covers exactly that set.
func TestScopeCoversTheResolvedHosts(t *testing.T) {
	everybody := &scope{everybody: true}
	if !everybody.covers("h1") || !everybody.covers("h2") {
		t.Error("a scope that narrows nothing left a host out")
	}
	some := &scope{hosts: map[string]bool{"h1": true}}
	if !some.covers("h1") || some.covers("h2") {
		t.Error("a resolved scope covers the wrong hosts")
	}
}

func TestRuleValidation(t *testing.T) {
	valid := Rule{Name: "High CPU", Metric: MetricCPUPercent, Operator: "gt", Threshold: 90,
		ForMinutes: 15, Severity: "warning"}
	if err := valid.Validate(); err != nil {
		t.Fatalf("a valid rule was refused: %v", err)
	}
	broken := map[string]func(*Rule){
		"no name":          func(r *Rule) { r.Name = " " },
		"unknown metric":   func(r *Rule) { r.Metric = "temperature" },
		"unknown operator": func(r *Rule) { r.Operator = "eq" },
		"unknown severity": func(r *Rule) { r.Severity = "page" },
		"negative window":  func(r *Rule) { r.ForMinutes = -1 },
		"window too long":  func(r *Rule) { r.ForMinutes = 24*60 + 1 },
		"bad host id":      func(r *Rule) { r.Selector.HostIDs = []string{"not-a-uuid"} },
		"bad tag":          func(r *Rule) { r.Selector.Tags = []string{"Role=db"} },
		"bad group name":   func(r *Rule) { r.Selector.Groups = []string{"data bases"} },
		"padded owner":     func(r *Rule) { r.Selector.Owner = " platform" },
		"unknown key":      func(r *Rule) { r.Selector.Expression = "colour = blue" },
		"ordered site":     func(r *Rule) { r.Selector.Expression = "site < warsaw" },
		"bad state":        func(r *Rule) { r.Selector.Expression = "connection = sleeping" },
	}
	for name, change := range broken {
		rule := valid
		change(&rule)
		if err := rule.Validate(); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
	scoped := valid
	scoped.Selector = Selector{Tags: []string{"role=db"}, Groups: []string{"databases"},
		Owner: "platform", Expression: "agent_version < 0.49.0 and not reboot_required = true"}
	if err := scoped.Validate(); err != nil {
		t.Errorf("a rule scoped by tag, group, owner and expression was refused: %v", err)
	}
}

func TestSilenceValidation(t *testing.T) {
	now := time.Date(2026, 9, 13, 12, 0, 0, 0, time.UTC)
	good := Silence{Reason: "disk swap in progress", Until: now.Add(45 * time.Minute)}
	if err := ValidateSilence(good, now); err != nil {
		t.Fatalf("a valid silence was refused: %v", err)
	}
	if err := ValidateSilence(Silence{Reason: "short", Until: now.Add(time.Hour)}, now); err == nil {
		t.Error("a silence without a readable reason was accepted")
	}
	if err := ValidateSilence(Silence{Reason: good.Reason, Until: now.Add(25 * time.Hour)}, now); err == nil {
		t.Error("a silence longer than a day was accepted")
	}
	if err := ValidateSilence(Silence{Reason: good.Reason, Until: now}, now); err == nil {
		t.Error("a silence that already ended was accepted")
	}
}

func TestPointsCarryRatesBetweenConsecutiveSamples(t *testing.T) {
	start := time.Date(2026, 9, 13, 12, 0, 0, 0, time.UTC)
	samples := []Sample{
		{At: start, Interfaces: []Interface{{Name: "eth0", RxBytes: 1000, TxBytes: 100}}},
		{At: start.Add(60 * time.Second), Interfaces: []Interface{{Name: "eth0", RxBytes: 7000, TxBytes: 700}}},
		// The counters went backwards: the interface was reset, so there
		// is no rate for this step.
		{At: start.Add(120 * time.Second), Interfaces: []Interface{{Name: "eth0", RxBytes: 100, TxBytes: 10}}},
		{At: start.Add(180 * time.Second), Interfaces: []Interface{{Name: "eth0", RxBytes: 700, TxBytes: 70}}},
	}
	points := toPoints(samples)
	if len(points) != 4 {
		t.Fatalf("points = %d", len(points))
	}
	if len(points[0].Interfaces) != 0 {
		t.Errorf("the first point has rates: %+v", points[0].Interfaces)
	}
	if len(points[1].Interfaces) != 1 || points[1].Interfaces[0].RxBytesPerSecond != 100 ||
		points[1].Interfaces[0].TxBytesPerSecond != 10 {
		t.Errorf("the second point = %+v", points[1].Interfaces)
	}
	if len(points[2].Interfaces) != 0 {
		t.Errorf("the reset step has rates: %+v", points[2].Interfaces)
	}
	if len(points[3].Interfaces) != 1 || points[3].Interfaces[0].RxBytesPerSecond != 10 {
		t.Errorf("the point after the reset = %+v", points[3].Interfaces)
	}
	// Lists come back as lists, never as null: a chart reads them without
	// guarding.
	if points[0].Filesystems == nil || points[0].Interfaces == nil {
		t.Error("a point carries a null list")
	}
}

// atSamples turns a list of moments into the readings continuousSince walks,
// for the cases that are about the holes and not about the values.
func atSamples(moments []time.Time) []Sample {
	samples := make([]Sample, 0, len(moments))
	for _, at := range moments {
		samples = append(samples, Sample{At: at, ReceivedAt: at})
	}
	return samples
}

// always is the judge for those cases: every reading holds.
func always(Sample) bool { return true }

// A "for" window says the condition held that long, and holding is something
// somebody watched.
func TestAGapInTheSamplesRestartsTheWindow(t *testing.T) {
	started := time.Date(2026, 9, 18, 12, 0, 0, 0, time.UTC)
	gap := Rule{}.MaxGap()
	// An unbroken minute-by-minute run counts from the start of the
	// episode: ten samples, no hole, the window is the whole ten minutes.
	var unbroken []time.Time
	for i := 1; i <= 10; i++ {
		unbroken = append(unbroken, started.Add(time.Duration(i)*time.Minute))
	}
	now := started.Add(10 * time.Minute)
	if since := continuousSince(started, atSamples(unbroken), now, gap, always); !since.Equal(started) {
		t.Errorf("an unbroken run counts from %s rather than from the start of the episode", since)
	}

	// The host went quiet after the third sample and came back at the eighth
	// minute: the window counts from that reading, not from the episode's start.
	broken := []time.Time{
		started.Add(1 * time.Minute), started.Add(2 * time.Minute), started.Add(3 * time.Minute),
		started.Add(8 * time.Minute), started.Add(9 * time.Minute), started.Add(10 * time.Minute),
	}
	since := continuousSince(started, atSamples(broken), now, gap, always)
	if !since.Equal(started.Add(8 * time.Minute)) {
		t.Errorf("the window after a gap counts from %s rather than from the sample that came back", since)
	}
	// Which is what keeps the alert from firing: five minutes of samples
	// are not the ten minutes the rule asks for, however old the episode.
	if now.Sub(since) >= 10*time.Minute {
		t.Error("an episode fired on a window that was not watched")
	}
	if now.Sub(started) < 10*time.Minute {
		t.Fatal("the episode itself is younger than the window; the case checks nothing")
	}

	// One lost sample is a lost sample, not a gap: the run holds.
	oneLost := []time.Time{
		started.Add(1 * time.Minute), started.Add(3 * time.Minute), started.Add(4 * time.Minute),
		started.Add(5 * time.Minute), started.Add(6 * time.Minute), started.Add(7 * time.Minute),
		started.Add(8 * time.Minute), started.Add(9 * time.Minute), started.Add(10 * time.Minute),
	}
	if since := continuousSince(started, atSamples(oneLost), now, gap, always); !since.Equal(started) {
		t.Errorf("a single lost sample broke the run at %s", since)
	}

	// An episode whose newest sample is older than a gap has no run that
	// reaches now: it starts now and has nothing behind it.
	stale := []time.Time{started.Add(1 * time.Minute), started.Add(2 * time.Minute)}
	if since := continuousSince(started, atSamples(stale), now, gap, always); !since.Equal(now) {
		t.Errorf("a run with no recent sample starts at %s rather than now", since)
	}
	// And an episode with no sample at all behind it likewise.
	if since := continuousSince(started, nil, now, gap, always); !since.Equal(now) {
		t.Errorf("an episode without samples starts at %s rather than now", since)
	}
	// While an episode a moment old, whose samples have yet to arrive,
	// keeps its start: it has not been waiting long enough to be a gap.
	fresh := started.Add(time.Minute)
	if since := continuousSince(started, nil, fresh, gap, always); !since.Equal(started) {
		t.Errorf("a fresh episode was restarted at %s", since)
	}
}

func TestARuleWithoutDataHoldsItsEpisodeRatherThanFiring(t *testing.T) {
	started := time.Date(2026, 9, 18, 12, 0, 0, 0, time.UTC)
	pending := openAlert{ID: "a1", State: "pending", StartedAt: started}
	// Within a gap nothing is done: the sample may simply be late, and a
	// write on every run for every quiet host is not worth it.
	gap := Rule{}.MaxGap()
	if noDataHold(pending, started.Add(time.Minute), gap) {
		t.Error("a late sample restarted the window")
	}
	// Past it the episode is held: the window restarts, so however long the host
	// stays silent the episode never reaches its firing point on old readings.
	if !noDataHold(pending, started.Add(5*time.Minute), gap) {
		t.Error("an episode without data for five minutes was not held")
	}
	// A firing episode is not touched: it has fired, and the absence of
	// readings is not the resolve of the condition either.
	firing := openAlert{ID: "a2", State: "firing", StartedAt: started}
	if noDataHold(firing, started.Add(time.Hour), gap) {
		t.Error("a firing episode was restarted")
	}
}

// TestTheLeaseIsAskedAboutInsideTheFleet: the interval is a number of hosts.
// Once per rule would run a whole fleet on a lease that may already be gone.
func TestTheLeaseIsAskedAboutInsideTheFleet(t *testing.T) {
	if evaluatorGuardEvery <= 1 {
		t.Fatalf("the guard is asked every %d hosts: that is every host", evaluatorGuardEvery)
	}
	const fleet = 10000
	if asks := fleet / evaluatorGuardEvery; asks < 8 {
		t.Fatalf("one rule over %d hosts asks about the lease %d times; most of the rule "+
			"is judged without looking", fleet, asks)
	}
}

// TestAWriteNamesTheRuleTheHostAndTheEpisode: a refusal is counted and logged,
// and a count nobody can trace back to a host and a rule is not an answer.
func TestAWriteNamesTheRuleTheHostAndTheEpisode(t *testing.T) {
	mark := alertWrite{rule: "r1", host: "h1"}.on("a1").kinded("resolve")
	if mark.rule != "r1" || mark.host != "h1" || mark.id != "a1" || mark.kind != "resolve" {
		t.Fatalf("the write describes itself as %+v", mark)
	}
	// The descriptors are copies: naming one episode must not rename another.
	base := alertWrite{rule: "r1", host: "h1"}
	if base.on("a1").id == base.on("a2").id || base.id != "" {
		t.Fatalf("naming an episode changed the write it was taken from: %+v", base)
	}
}

// The window is counted over the gap the rule declares, not over one the
// package fixed for the whole fleet.
func TestTheWindowIsCountedOverTheRulesOwnGap(t *testing.T) {
	started := time.Date(2026, 9, 19, 12, 0, 0, 0, time.UTC)
	now := started.Add(10 * time.Minute)
	// The host reports every five minutes, and the rule says so: the same
	// readings are one run for it and a hole for a minute-by-minute rule.
	slow := Rule{ExpectedCadenceSeconds: 300}
	quick := Rule{}
	samples := []time.Time{
		started.Add(5 * time.Minute), started.Add(10 * time.Minute),
	}
	if since := continuousSince(started, atSamples(samples), now, slow.MaxGap(), always); !since.Equal(started) {
		t.Errorf("a five-minute cadence read its own readings as a gap at %s", since)
	}
	if since := continuousSince(started, atSamples(samples), now, quick.MaxGap(), always); since.Equal(started) {
		t.Error("a minute-by-minute rule counted five-minute holes as one continuous run")
	}
	// And the hold on a pending episode follows the same gap: what the rule
	// tolerates decides when its timer is restarted.
	pending := openAlert{ID: "a1", State: "pending", StartedAt: started}
	if noDataHold(pending, started.Add(8*time.Minute), slow.MaxGap()) {
		t.Error("an episode was held within the gap its own rule declares")
	}
	if !noDataHold(pending, started.Add(11*time.Minute), slow.MaxGap()) {
		t.Error("an episode past the gap its own rule declares was not held")
	}
}

// Whether the readings have stopped is a question about the rule's gap, not
// about whether a value could be computed from the last one.
func TestReadingsStoppedFollowsTheRulesGap(t *testing.T) {
	now := time.Date(2026, 9, 19, 12, 0, 0, 0, time.UTC)
	at := now.Add(-4 * time.Minute)
	host := hostState{ID: "h1", LastSampleAt: &at, Latest: &Sample{At: at, CPUPercent: 10}}

	if !readingsStopped(Rule{Metric: MetricCPUPercent}, host, now) {
		t.Error("four minutes of silence is not a gap for a rule that allows two")
	}
	wide := Rule{Metric: MetricCPUPercent, ExpectedCadenceSeconds: 300}
	if readingsStopped(wide, host, now) {
		t.Error("four minutes of silence is a gap for a rule that allows ten")
	}
	// A host_offline rule measures the silence, so silence is its reading and
	// never its gap; judging it no-data would hide the thing it watches.
	if readingsStopped(Rule{Metric: MetricHostOffline}, host, now) {
		t.Error("a host_offline rule was judged to be without data")
	}
	// A host that never reported has no readings at all, whatever the gap.
	if !readingsStopped(wide, hostState{ID: "h2"}, now) {
		t.Error("a host that never reported was judged to have data")
	}
}

// The ignore policy is what every rule did before the setting existed, so the
// no-data path has to be shut for it.
func TestOnlyTheAlertAndUnknownPoliciesReachTheNoDataPath(t *testing.T) {
	if (Rule{}).Policy() != NoDataIgnore {
		t.Fatal("a rule that says nothing does not ignore gaps")
	}
	for _, policy := range NoDataPolicies {
		rule := Rule{Metric: MetricCPUPercent, NoDataPolicy: policy}
		reaches := rule.Policy() != NoDataIgnore
		if reaches != (policy != NoDataIgnore) {
			t.Errorf("the policy %q reaches the no-data path: %v", policy, reaches)
		}
	}
}

// What an episode says while its readings are missing: how long they have been
// missing and what the rule allowed, never a value.
func TestGapDetailSaysHowLongAndWhatWasAllowed(t *testing.T) {
	now := time.Date(2026, 9, 19, 12, 0, 0, 0, time.UTC)
	at := now.Add(-7 * time.Minute)
	rule := Rule{Metric: MetricCPUPercent, ExpectedCadenceSeconds: 120}
	detail := gapDetail(rule, hostState{Latest: &Sample{At: at}}, now)
	for _, want := range []string{"cpu_percent", "7m", "4m"} {
		if !strings.Contains(detail, want) {
			t.Errorf("the gap reads %q and does not name %q", detail, want)
		}
	}
	never := gapDetail(rule, hostState{}, now)
	if !strings.Contains(never, "at all") {
		t.Errorf("a host that never reported reads %q", never)
	}
}

// A host whose clock runs slow is talking, not silent. Its readings carry a
// moment in the past, and judging freshness by that moment put the host in a
// permanent gap - unevaluated, while host_offline said it was fine.
func TestFreshnessIsThePanelsClockAndNotTheHosts(t *testing.T) {
	now := time.Now()
	rule := Rule{Metric: MetricCPUPercent, Operator: ">", Threshold: 50, ForMinutes: 0}
	slow := hostState{
		ID: "slow-clock", Cores: 4,
		LastSampleAt: &now,
		Latest: &Sample{
			At: now.Add(-20 * time.Minute), ReceivedAt: now.Add(-10 * time.Second),
			CPUPercent: 80, MemoryTotal: 100, MemoryUsed: 10, SwapTotal: 100, SwapUsed: 1,
		},
	}
	if readingsStopped(rule, slow, now) {
		t.Errorf("a host that answered ten seconds ago was called silent")
	}
	if _, _, known := measure(rule, slow, now); !known {
		t.Errorf("the reading of a host with a slow clock was not read")
	}

	// A host that really has gone quiet is still found, by the same clock.
	quiet := slow
	quiet.Latest = &Sample{At: now, ReceivedAt: now.Add(-30 * time.Minute), CPUPercent: 80}
	if !readingsStopped(rule, quiet, now) {
		t.Errorf("a host whose last reading arrived half an hour ago was called current")
	}

	// A sample from before the receipt moment was stored falls back to the
	// moment the host took it, rather than to the epoch.
	older := slow
	older.Latest = &Sample{At: now.Add(-10 * time.Second), CPUPercent: 80,
		MemoryTotal: 100, MemoryUsed: 10, SwapTotal: 100, SwapUsed: 1}
	if readingsStopped(rule, older, now) {
		t.Errorf("a sample without a receipt moment was called silent")
	}
}

// The window of a "for" rule has to be a window the condition held through.
// Counting rows rather than readings made high-low-high across a missed pass
// look like one long high, and the alert fired on a minute it was not.
func TestTheWindowIsBrokenByAReadingTheRuleDoesNotHoldFor(t *testing.T) {
	started := time.Date(2026, 9, 18, 12, 0, 0, 0, time.UTC)
	gap := Rule{}.MaxGap()
	now := started.Add(10 * time.Minute)
	rule := Rule{Metric: MetricCPUPercent, Operator: "gt", Threshold: 90}
	host := hostState{ID: "h1", Cores: 4}

	reading := func(minute int, cpu float64) Sample {
		at := started.Add(time.Duration(minute) * time.Minute)
		return Sample{At: at, ReceivedAt: at, CPUPercent: cpu,
			MemoryTotal: 100, MemoryUsed: 10, SwapTotal: 100, SwapUsed: 1}
	}
	var samples []Sample
	for minute := 1; minute <= 10; minute++ {
		cpu := 95.0
		// The eighth minute is the dip nobody watched.
		if minute == 8 {
			cpu = 10
		}
		samples = append(samples, reading(minute, cpu))
	}
	since := continuousSince(started, samples, now, gap, holdsFor(rule, host))
	if !since.Equal(started.Add(9 * time.Minute)) {
		t.Errorf("the window counts from %s rather than from the reading after the dip", since)
	}
	// Which is the whole point: two minutes are not the ten the rule asks for.
	if now.Sub(since) >= 10*time.Minute {
		t.Error("an episode would fire on a window the condition did not hold through")
	}

	// An unbroken run is still unbroken.
	var held []Sample
	for minute := 1; minute <= 10; minute++ {
		held = append(held, reading(minute, 95))
	}
	if since := continuousSince(started, held, now, gap, holdsFor(rule, host)); !since.Equal(started) {
		t.Errorf("an unbroken run counts from %s rather than from the start of the episode", since)
	}

	// A reading the rule cannot be judged on is not agreement either: a host
	// that stopped reporting the number breaks the run.
	unreadable := append([]Sample(nil), held[:9]...)
	last := reading(10, 95)
	last.MemoryTotal = 0
	unreadable = append(unreadable, last)
	memory := Rule{Metric: MetricMemoryUsedPercent, Operator: "gt", Threshold: 5}
	if since := continuousSince(started, unreadable, now, gap, holdsFor(memory, host)); !since.Equal(now) {
		t.Errorf("a run whose newest reading cannot be judged starts at %s rather than now", since)
	}
}
