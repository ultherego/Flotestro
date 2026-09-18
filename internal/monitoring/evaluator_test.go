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
// structure a campaign selector is, so the two compile into the same host
// query. Every set field is one condition, all of them hold at once, and
// the groups are alternatives.
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

// A "for" window says the condition held that long, and holding is
// something somebody watched. These check the two halves of that: a hole
// in the samples restarts the window, and a rule left without readings
// holds its episode instead of letting the window run on to firing.
func TestAGapInTheSamplesRestartsTheWindow(t *testing.T) {
	started := time.Date(2026, 9, 18, 12, 0, 0, 0, time.UTC)
	gap := maxSampleGap
	// An unbroken minute-by-minute run counts from the start of the
	// episode: ten samples, no hole, the window is the whole ten minutes.
	var unbroken []time.Time
	for i := 1; i <= 10; i++ {
		unbroken = append(unbroken, started.Add(time.Duration(i)*time.Minute))
	}
	now := started.Add(10 * time.Minute)
	if since := continuousSince(started, unbroken, now, gap); !since.Equal(started) {
		t.Errorf("an unbroken run counts from %s rather than from the start of the episode", since)
	}

	// The host went quiet after the third sample and came back at the
	// eighth minute: the window counts from the reading that came back,
	// not from the condition nobody was watching.
	broken := []time.Time{
		started.Add(1 * time.Minute), started.Add(2 * time.Minute), started.Add(3 * time.Minute),
		started.Add(8 * time.Minute), started.Add(9 * time.Minute), started.Add(10 * time.Minute),
	}
	since := continuousSince(started, broken, now, gap)
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
	if since := continuousSince(started, oneLost, now, gap); !since.Equal(started) {
		t.Errorf("a single lost sample broke the run at %s", since)
	}

	// An episode whose newest sample is older than a gap has no run that
	// reaches now: it starts now and has nothing behind it.
	stale := []time.Time{started.Add(1 * time.Minute), started.Add(2 * time.Minute)}
	if since := continuousSince(started, stale, now, gap); !since.Equal(now) {
		t.Errorf("a run with no recent sample starts at %s rather than now", since)
	}
	// And an episode with no sample at all behind it likewise.
	if since := continuousSince(started, nil, now, gap); !since.Equal(now) {
		t.Errorf("an episode without samples starts at %s rather than now", since)
	}
	// While an episode a moment old, whose samples have yet to arrive,
	// keeps its start: it has not been waiting long enough to be a gap.
	fresh := started.Add(time.Minute)
	if since := continuousSince(started, nil, fresh, gap); !since.Equal(started) {
		t.Errorf("a fresh episode was restarted at %s", since)
	}
}

func TestARuleWithoutDataHoldsItsEpisodeRatherThanFiring(t *testing.T) {
	started := time.Date(2026, 9, 18, 12, 0, 0, 0, time.UTC)
	pending := openAlert{ID: "a1", State: "pending", StartedAt: started}
	// Within a gap nothing is done: the sample may simply be late, and a
	// write on every run for every quiet host is not worth it.
	if noDataHold(pending, started.Add(time.Minute)) {
		t.Error("a late sample restarted the window")
	}
	// Past it the episode is held: the window restarts, so however long
	// the host stays silent the episode cannot reach its firing point on
	// the strength of that silence.
	if !noDataHold(pending, started.Add(5*time.Minute)) {
		t.Error("an episode without data for five minutes was not held")
	}
	// A firing episode is not touched: it has fired, and the absence of
	// readings is not the resolve of the condition either.
	firing := openAlert{ID: "a2", State: "firing", StartedAt: started}
	if noDataHold(firing, started.Add(time.Hour)) {
		t.Error("a firing episode was restarted")
	}
}
