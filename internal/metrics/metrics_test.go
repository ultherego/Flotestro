package metrics

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

type sessionCounter struct{ count int }

func (l sessionCounter) Count() int { return l.count }

type certificate struct{ end time.Time }

func (c certificate) NotAfter() time.Time { return c.end }

// TestTheExpositionFormat checks conformance with the Prometheus text format:
// every metric has HELP and TYPE before its values, and the labels are sorted.
func TestTheExpositionFormat(t *testing.T) {
	result := render([]metric{{
		name: "flotestro_hosts", kind: "gauge", help: "The fleet's hosts.",
		samples: labelled("connection_state", map[string]float64{
			"online": 3, "offline": 1, "stale": 2,
		}),
	}})

	text := string(result)
	if !strings.HasPrefix(text, "# HELP flotestro_hosts The fleet's hosts.\n# TYPE flotestro_hosts gauge\n") {
		t.Fatalf("the metric headers are missing:\n%s", text)
	}
	expected := "" +
		`flotestro_hosts{connection_state="offline"} 1` + "\n" +
		`flotestro_hosts{connection_state="online"} 3` + "\n" +
		`flotestro_hosts{connection_state="stale"} 2` + "\n"
	if !strings.HasSuffix(text, expected) {
		t.Errorf("the values have the wrong shape or order:\n%s", text)
	}
}

// TestLabelsDoNotBreakTheFormat guards the values coming from the database.
// The state of a task is text from a column, not a constant from the code.
func TestLabelsDoNotBreakTheFormat(t *testing.T) {
	result := string(render([]metric{{
		name: "flotestro_jobs", kind: "gauge", help: "Tasks.",
		samples: []sample{{
			labels: map[string]string{"state": "odd\"state\nwith a newline"},
			value:  1,
		}},
	}}))

	if strings.Count(result, "\n") != 3 {
		t.Errorf("the label value broke the format into more lines:\n%s", result)
	}
	if !strings.Contains(result, `\"state\n`) {
		t.Errorf("the special characters were not escaped:\n%s", result)
	}
}

// TestAnUndeterminedStateIsSkipped guards the rule that a metric which could
// not be determined disappears from the answer instead of showing zero.
func TestAnUndeterminedStateIsSkipped(t *testing.T) {
	// A collector without a database, without a session counter and without a
	// certificate: only the metrics that can be computed in the process remain.
	collector := NewCollector(nil, nil, nil, "panel")
	text := string(collector.Gather(context.Background()))

	for _, absent := range []string{
		"flotestro_agent_sessions_active",
		"flotestro_ca_certificate_expires_in_seconds",
		"flotestro_hosts",
		"flotestro_job_queue_age_seconds",
	} {
		if strings.Contains(text, absent) {
			t.Errorf("the metric %s appeared although its data source is missing", absent)
		}
	}
	for _, present := range []string{"flotestro_build_info", "flotestro_goroutines"} {
		if !strings.Contains(text, present) {
			t.Errorf("the metric %s, which does not depend on the database, is missing", present)
		}
	}

	// A certificate without a determined expiry date must not give zero either:
	// zero would mean "expires now" and would raise an alarm for no reason.
	withCert := NewCollector(nil, sessionCounter{count: 7}, certificate{}, "panel")
	text = string(withCert.Gather(context.Background()))
	if strings.Contains(text, "flotestro_ca_certificate_expires_in_seconds") {
		t.Error("an undetermined certificate validity was shown as a value")
	}
	if !strings.Contains(text, `flotestro_agent_sessions_active{gateway="panel"} 7`) {
		t.Errorf("the number of sessions was not exposed:\n%s", text)
	}
}

// TestTwoLabelsHaveAFixedOrder guards the series in which the state alone is
// not enough.
func TestTwoLabelsHaveAFixedOrder(t *testing.T) {
	result := string(render([]metric{{
		name: "flotestro_campaign_targets", kind: "gauge", help: "Campaign hosts.",
		samples: []sample{
			{labels: map[string]string{"state": "awaiting_budget", "reason_code": "budget_capacity"}, value: 3},
			{labels: map[string]string{"state": "pending", "reason_code": "none"}, value: 7},
		},
	}}))

	// The labels within one series go alphabetically, so the reason code
	// comes before the state.
	expected := "" +
		`flotestro_campaign_targets{reason_code="budget_capacity",state="awaiting_budget"} 3` + "\n" +
		`flotestro_campaign_targets{reason_code="none",state="pending"} 7` + "\n"
	if !strings.HasSuffix(result, expected) {
		t.Errorf("the series have the wrong shape or order:\n%s", result)
	}
}

// TestCapacityAndUsageAreSeparateSeries guards that a budget says at once how
// much it has and how much is taken.
func TestCapacityAndUsageAreSeparateSeries(t *testing.T) {
	result := string(render([]metric{{
		name: "flotestro_budget_tokens", kind: "gauge", help: "Budget tokens.",
		samples: []sample{
			{labels: map[string]string{"budget": "site:warsaw:packages", "status": "capacity"}, value: 5},
			{labels: map[string]string{"budget": "site:warsaw:packages", "status": "used"}, value: 5},
			{labels: map[string]string{"budget": "site:warsaw:packages", "status": "waiting"}, value: 2},
		},
	}}))

	for _, fragment := range []string{`status="capacity"} 5`, `status="used"} 5`, `status="waiting"} 2`} {
		if !strings.Contains(result, fragment) {
			t.Errorf("the series %q is missing:\n%s", fragment, result)
		}
	}
}

// TestTheLifecycleCountersAreExposed guards the names the lifecycle document
// gives: a reconnect and a renewal are counted at the point of the event.
func TestTheLifecycleCountersAreExposed(t *testing.T) {
	AgentReconnect.Inc("debian")
	AgentRenewal.Inc("renewed")
	AgentRenewal.Inc("refused")

	text := string(NewCollector(nil, nil, nil, "panel").Gather(context.Background()))
	for _, line := range []string{
		"# TYPE flotestro_agent_reconnect_total counter",
		`flotestro_agent_reconnect_total{host_family="debian"} 1`,
		"# TYPE flotestro_agent_renewal_total counter",
		`flotestro_agent_renewal_total{outcome="refused"} 1`,
		`flotestro_agent_renewal_total{outcome="renewed"} 1`,
	} {
		if !strings.Contains(text, line+"\n") {
			t.Errorf("missing line %q in:\n%s", line, text)
		}
	}
	// The relay buffers come from the heartbeats the panel keeps; without that
	// source, or without a database to name the relays, it says nothing.
	if strings.Contains(text, "flotestro_relay_buffer") {
		t.Errorf("relay buffer metrics appeared without a relay source:\n%s", text)
	}
}

// writeFixture puts fixture text where the readers look for a kernel file.
func writeFixture(t *testing.T, path, content string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatalf("the fixture directory: %v", err)
	}
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatalf("the fixture file: %v", err)
	}
}

// The cgroup is the budget a container is killed against, so where there is
// one it decides; the reclaimable page cache is not the panel's memory.
func TestTheResidentSetComesFromTheCgroup(t *testing.T) {
	procRoot, cgroupRoot := t.TempDir(), t.TempDir()
	writeFixture(t, filepath.Join(procRoot, "self", "cgroup"),
		"0::/system.slice/flotestro-panel.service\n")
	// A process under the first cgroup version also has these lines; the
	// unified one is the only one the reader takes.
	writeFixture(t, filepath.Join(procRoot, "self", "status"), "Name:\tflotestro\nVmRSS:\t  4096 kB\n")
	unit := filepath.Join(cgroupRoot, "system.slice", "flotestro-panel.service")
	writeFixture(t, filepath.Join(unit, "memory.current"), "2147483648\n")
	writeFixture(t, filepath.Join(unit, "memory.stat"), "anon 1610612736\ninactive_file 147483648\nfile 200000000\n")

	fp := readFootprint(procRoot, cgroupRoot)
	if fp.ResidentBytes == nil {
		t.Fatal("the cgroup gave no resident set")
	}
	if want := uint64(2147483648 - 147483648); *fp.ResidentBytes != want {
		t.Errorf("resident set = %d; want %d", *fp.ResidentBytes, want)
	}
	if fp.ResidentFrom != "cgroup" {
		t.Errorf("the source is %q; want cgroup", fp.ResidentFrom)
	}
}

// A native installation has no unified cgroup line, or none the reader can
// follow, and is measured from procfs instead.
func TestTheResidentSetFallsBackToProcfs(t *testing.T) {
	procRoot, cgroupRoot := t.TempDir(), t.TempDir()
	writeFixture(t, filepath.Join(procRoot, "self", "cgroup"),
		"11:devices:/user.slice\n1:name=systemd:/user.slice/session-3.scope\n")
	writeFixture(t, filepath.Join(procRoot, "self", "status"),
		"Name:\tflotestro\nVmPeak:\t 900000 kB\nVmRSS:\t 1884160 kB\nThreads:\t42\n")
	writeFixture(t, filepath.Join(procRoot, "self", "limits"),
		"Limit                     Soft Limit           Hard Limit           Units\n"+
			"Max processes             62000                62000                processes\n"+
			"Max open files            65536                65536                files\n")
	writeFixture(t, filepath.Join(procRoot, "self", "stat"),
		"7 (flotestro panel) S 1 7 7 0 -1 4194560 100 0 0 0 1234 567 0 0 20 0 42 0 900 0 0\n")

	fp := readFootprint(procRoot, cgroupRoot)
	if fp.ResidentBytes == nil || *fp.ResidentBytes != 1884160*1024 {
		t.Fatalf("resident set = %v; want %d", fp.ResidentBytes, 1884160*1024)
	}
	if fp.ResidentFrom != "procfs" {
		t.Errorf("the source is %q; want procfs", fp.ResidentFrom)
	}
	if fp.MaxFDs == nil || *fp.MaxFDs != 65536 {
		t.Errorf("the descriptor limit is %v; want 65536", fp.MaxFDs)
	}
	// utime 1234 plus stime 567 ticks, at a hundred ticks to the second.
	if fp.CPUSeconds == nil || *fp.CPUSeconds != 18.01 {
		t.Errorf("the CPU time is %v; want 18.01", fp.CPUSeconds)
	}
}

// Where neither the cgroup nor procfs answers, every number stays nil. A
// resident set of zero would say the process holds no memory at all.
func TestAnUnreadableFootprintIsUnknown(t *testing.T) {
	fp := readFootprint(t.TempDir(), t.TempDir())
	if fp.ResidentBytes != nil || fp.MaxFDs != nil || fp.CPUSeconds != nil {
		t.Errorf("an unreadable host gave numbers: %+v", fp)
	}
	if fp.ResidentFrom != "" {
		t.Errorf("the source is %q although nothing was read", fp.ResidentFrom)
	}
}

// The readers take the shapes the kernel actually writes, and refuse the ones
// that carry no number.
func TestTheProcfsReadersTakeWhatTheKernelWrites(t *testing.T) {
	if _, ok := parseResidentBytes("Name:\tx\nVmSize:\t 10 kB\n"); ok {
		t.Error("a status without VmRSS gave a value")
	}
	if _, ok := parseFDLimit("Max open files            unlimited            unlimited            files\n"); ok {
		t.Error("an unlimited soft limit was read as a number")
	}
	if _, ok := parseCgroupBytes("max\n"); ok {
		t.Error("the word max was read as a byte count")
	}
	if _, ok := parseCgroupPath("11:devices:/user.slice\n"); ok {
		t.Error("a hierarchy without a unified line gave a path")
	}
	path, ok := parseCgroupPath("0::/\n")
	if !ok || path != "/" {
		t.Errorf("the cgroup of a container is %q, %v; want /", path, ok)
	}
	// The command name is in brackets and may hold spaces of its own, so the
	// fields are counted from the closing bracket and not from the start.
	ticks, ok := parseCPUTicks("7 (a name with spaces) S 1 7 7 0 -1 0 0 0 0 0 10 5 0 0 20 0 1 0 0 0 0\n")
	if !ok || ticks != 15 {
		t.Errorf("the CPU ticks are %d, %v; want 15", ticks, ok)
	}
}

// The percentiles take the value at the nearest rank: no number is invented
// between two the process actually saw.
func TestTheQuantileTakesTheNearestRank(t *testing.T) {
	sorted := []float64{1, 2, 3, 4, 5, 6, 7, 8, 9, 10}
	for _, want := range []struct {
		at    float64
		value float64
	}{{0.5, 5}, {0.95, 10}, {0.99, 10}, {1, 10}} {
		value, ok := quantile(sorted, want.at)
		if !ok || value != want.value {
			t.Errorf("quantile %g = %g, %v; want %g", want.at, value, ok, want.value)
		}
	}
	if _, ok := quantile(nil, 0.99); ok {
		t.Error("an empty series gave a percentile")
	}
}

// The process gauges come from the host, and a number the host would not give
// is absent from the exposition rather than shown as zero.
func TestTheProcessGaugesComeFromTheHost(t *testing.T) {
	resident, fds, limit := uint64(1884160*1024), uint64(2048), uint64(65536)
	collector := NewCollector(nil, nil, nil, "panel")
	collector.footprint = func() Footprint {
		return Footprint{ResidentBytes: &resident, ResidentFrom: "cgroup", OpenFDs: &fds, MaxFDs: &limit}
	}
	text := string(collector.Gather(context.Background()))
	for _, line := range []string{
		`flotestro_process_resident_bytes{source="cgroup"} 1.92937984e+09`,
		"flotestro_process_open_fds 2048",
		"flotestro_process_max_fds 65536",
	} {
		if !strings.Contains(text, line+"\n") {
			t.Errorf("missing line %q in:\n%s", line, text)
		}
	}
	// The CPU was not read, so it is not in the answer at all.
	if strings.Contains(text, "flotestro_process_cpu_seconds_total") {
		t.Error("an unread CPU time appeared in the exposition")
	}
	// The runtime's own bookkeeping is still exposed, under a name that says
	// what it is: reserved address space, not the resident set.
	if !strings.Contains(text, "flotestro_go_memory_reserved_bytes") {
		t.Errorf("the reserved address space is missing:\n%s", text)
	}
	if strings.Contains(text, "flotestro_memory_bytes") {
		t.Error("the old name, which read as the resident set, is still exposed")
	}

	// A host that answers nothing leaves every process gauge out. The name is
	// looked for as a declared family, not as a substring: a help line names it.
	silent := NewCollector(nil, nil, nil, "panel")
	silent.footprint = func() Footprint { return Footprint{} }
	text = string(silent.Gather(context.Background()))
	for _, absent := range []string{
		"flotestro_process_resident_bytes", "flotestro_process_open_fds", "flotestro_process_max_fds",
	} {
		if strings.Contains(text, "# TYPE "+absent+" ") {
			t.Errorf("%s appeared although the host gave no number", absent)
		}
	}
}
