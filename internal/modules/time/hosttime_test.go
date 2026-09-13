package hosttime

import (
	"context"
	"math"
	"strings"
	"testing"
)

func TestTrackingReadsOffsetAndStratum(t *testing.T) {
	output := "C0248F97,192.168.1.1,3,1755978000.123456,-0.000123,-0.000045," +
		"0.000234,-1.234,0.001,0.123,0.002345,0.012345,64,Normal\n"
	snapshot := ParseTracking(output)

	if snapshot.ReferenceName != "192.168.1.1" {
		t.Fatalf("reference: %q", snapshot.ReferenceName)
	}
	if snapshot.Stratum == nil || *snapshot.Stratum != 3 {
		t.Fatalf("stratum: %v", snapshot.Stratum)
	}
	if snapshot.OffsetSeconds == nil || math.Abs(*snapshot.OffsetSeconds+0.000123) > 1e-9 {
		t.Fatalf("offset: %v", snapshot.OffsetSeconds)
	}
	if snapshot.LeapStatus != "Normal" {
		t.Fatalf("leap: %q", snapshot.LeapStatus)
	}
	if !snapshot.IsSynchronized() {
		t.Fatal("a daemon with a selected source is meant to be synchronised")
	}
}

// A daemon without a selected source runs, but is not synchronised. These
// are two different answers and the result must not merge them.
func TestTrackingWithoutSourceIsNotSynchronized(t *testing.T) {
	output := "00000000,0.0.0.0,0,0.000000,0.000000,0.000000,0.000000," +
		"0.000,0.000,0.000,0.000000,0.000000,0,Not synchronised\n"
	snapshot := ParseTracking(output)

	if snapshot.ReferenceName != "" {
		t.Fatalf("an empty reference became a name: %q", snapshot.ReferenceName)
	}
	if snapshot.Stratum != nil {
		t.Fatalf("stratum zero is not a stratum: %v", *snapshot.Stratum)
	}
	if snapshot.IsSynchronized() {
		t.Fatal("a daemon without a source is not synchronised")
	}
}

func TestSourcesTranslateSymbolsIntoWords(t *testing.T) {
	sources := ParseSources("^,*,192.168.1.1,3,6,377,23,-0.000123,-0.000125,0.000456\n" +
		"^,?,10.0.0.9,0,6,0,-,0.000000,0.000000,0.000000\n")
	if len(sources) != 2 {
		t.Fatalf("sources: %d", len(sources))
	}
	if sources[0].Mode != "server" || sources[0].State != "selected" {
		t.Fatalf("first source: %+v", sources[0])
	}
	if sources[0].PollSeconds == nil || *sources[0].PollSeconds != 64 {
		t.Fatalf("polling interval: %v", sources[0].PollSeconds)
	}
	if sources[1].State != "unreachable" {
		t.Fatalf("second source: %+v", sources[1])
	}
	if sources[1].LastRxSeconds != nil {
		t.Fatalf("no measurement is not zero: %v", *sources[1].LastRxSeconds)
	}
}

func TestDropInDirPicksDirectoryIncludedByDaemon(t *testing.T) {
	cases := []struct {
		name    string
		content string
		dir     string
		kind    string
	}{
		{"confdir", "pool 2.debian.pool.ntp.org iburst\nconfdir /etc/chrony/conf.d\n",
			"/etc/chrony/conf.d", KindConfiguration},
		{"sourcedir", "sourcedir /etc/chrony/sources.d\n",
			"/etc/chrony/sources.d", KindSources},
		{"include", "include /etc/chrony.d/*.conf\n", "/etc/chrony.d", KindConfiguration},
		{"comment", "# confdir /etc/chrony/conf.d\n", "", ""},
		{"none", "server 10.0.0.1 iburst\n", "", ""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			dir, kind := DropInDir(tc.content)
			if dir != tc.dir || kind != tc.kind {
				t.Fatalf("got %q/%q, want %q/%q",
					dir, kind, tc.dir, tc.kind)
			}
		})
	}
}

// The DHCP sources directory lives in /run and vanishes after a reboot. The
// panel would keep its desired state there only if it wanted to lose it.
func TestDropInDirSkipsVolatileDirectory(t *testing.T) {
	dir, _ := DropInDir("sourcedir /run/chrony-dhcp\n")
	if dir != "" {
		t.Fatalf("a directory in /run was picked: %q", dir)
	}
}

func TestConfigurationComposition(t *testing.T) {
	content, err := ComposeChrony([]string{"10.0.0.1", "ntp.example.org"}, KindConfiguration)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(content, FileHeader) {
		t.Fatalf("configuration file without the panel header: %q", content)
	}
	if !strings.Contains(content, "server 10.0.0.1 iburst") {
		t.Fatalf("no server entry: %q", content)
	}

	// A sources directory accepts only server directives, so there is no
	// header there - the file is owned by its name.
	sources, err := ComposeChrony([]string{"10.0.0.1"}, KindSources)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(sources, "#") {
		t.Fatalf("sources file with a comment: %q", sources)
	}
}

func TestRejectedServersAndZones(t *testing.T) {
	if err := ValidateServer("10.0.0.1 iburst\nallow all"); err == nil {
		t.Fatal("an address with a newline passed validation")
	}
	if err := ValidateServers([]string{"10.0.0.1", "10.0.0.1"}); err == nil {
		t.Fatal("a repeated server passed validation")
	}
	if err := ValidateServers(nil); err == nil {
		t.Fatal("an empty list passed validation")
	}
	if err := ValidateZone("../../etc/passwd"); err == nil {
		t.Fatal("a relative path passed as a zone")
	}
	if err := ValidateZone("Europe/Warsaw"); err != nil {
		t.Fatalf("a valid zone rejected: %v", err)
	}
}

func TestTimesyncReadsNTPMessage(t *testing.T) {
	output := "SystemNTPServers=ntp.example.org\n" +
		"FallbackNTPServers=0.debian.pool.ntp.org\n" +
		"ServerName=ntp.example.org\nServerAddress=10.0.0.1\n" +
		"NTPMessage={ Leap=0, Version=4, Mode=4, Stratum=2, Precision=-24, " +
		"RootDelay=1.907ms, RootDispersion=15.945ms, Reference=C0248F97 }\n"
	state := ParseTimesync(output, "timesyncd.conf")

	if state.Stratum == nil || *state.Stratum != 2 {
		t.Fatalf("stratum: %v", state.Stratum)
	}
	if state.RootDelay == nil || math.Abs(*state.RootDelay-0.001907) > 1e-9 {
		t.Fatalf("root delay: %v", state.RootDelay)
	}
	if state.LeapStatus != "Normal" {
		t.Fatalf("leap: %q", state.LeapStatus)
	}
	if len(state.Servers) != 2 || state.Servers[1].Source != "systemd fallback" {
		t.Fatalf("servers: %+v", state.Servers)
	}
}

func TestStepCountsFromOneSecondThreshold(t *testing.T) {
	small := 0.2
	large := -3.5
	smallDelay, largeDelay := 0.01, 0.2
	probes := []Probe{
		{Server: "slow", Reachable: true, OffsetSeconds: &large, DelaySeconds: &largeDelay},
		{Server: "fast", Reachable: true, OffsetSeconds: &small, DelaySeconds: &smallDelay},
		{Server: "dead"},
	}
	if Reachable(probes) != 2 {
		t.Fatalf("reachable: %d", Reachable(probes))
	}
	best := BestProbe(probes)
	if best == nil || best.Server != "fast" {
		t.Fatalf("picked probe: %+v", best)
	}
	if Steps(best) {
		t.Fatal("two tenths of a second are not a step")
	}
	if !Steps(&probes[0]) {
		t.Fatal("three and a half seconds are a step")
	}
}

// Systemd answers "inactive" also about a unit the host does not have.
// Without the load state the panel would name chrony on a host where it is
// not installed.
func TestDaemonUnitSkipsUnitsUnknownToHost(t *testing.T) {
	output := "Id=chronyd.service\nLoadState=not-found\nActiveState=inactive\n\n" +
		"Id=chrony.service\nLoadState=not-found\nActiveState=inactive\n\n" +
		"ActiveState=active\nId=systemd-timesyncd.service\nLoadState=loaded\n"
	run := func(_ context.Context, _ string, _ ...string) (string, error) { return output, nil }

	name, active := daemonUnit(context.Background(), run)
	if name != "systemd-timesyncd.service" {
		t.Fatalf("unit: %q", name)
	}
	if active == nil || !*active {
		t.Fatalf("unit state: %v", active)
	}
}

// A unit installed but stopped is a different answer than its absence.
func TestDaemonUnitReportsStopped(t *testing.T) {
	output := "Id=chronyd.service\nLoadState=loaded\nActiveState=inactive\n\n" +
		"Id=chrony.service\nLoadState=not-found\nActiveState=inactive\n\n" +
		"Id=systemd-timesyncd.service\nLoadState=masked\nActiveState=inactive\n"
	run := func(_ context.Context, _ string, _ ...string) (string, error) { return output, nil }

	name, active := daemonUnit(context.Background(), run)
	if name != "chronyd.service" {
		t.Fatalf("unit: %q", name)
	}
	if active == nil || *active {
		t.Fatalf("a stopped unit reported as active: %v", active)
	}
}
