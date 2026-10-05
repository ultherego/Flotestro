package firewall

import (
	"strings"
	"testing"
)

// The two listings of an ordinary host, shortened to the fields these cases are
// about; the whole text of a live host is in testdata and is what
// zone_fields_test.go reads. firewall-cmd marks a zone that is on an interface
// and names the interface in the running configuration; the permanent listing
// marks the default zone and nothing else, and NetworkManager is what puts the
// interface in the running one. A host like this has nothing pending.
const (
	runningListing = `public (default, active)
  target: default
  interfaces: enp0s3
  services: cockpit dhcpv6-client ssh
  ports: 8443/tcp 9090/udp
trusted
  target: ACCEPT
`
	keptListing = `public (default)
  target: default
  services: ssh cockpit dhcpv6-client
  ports: 9090/udp 8443/tcp
trusted
  target: ACCEPT
`
)

// views parses the two listings the way the helper does.
func views(running, kept string) ([]Zone, []Zone) {
	return ParseZones(running, "public"), ParseZones(kept, "public")
}

// The permanent listing prints the same fields as the running one, so one
// parser reads both. If it did not, every host would read as keeping nothing -
// which would look like a working guard and refuse or allow at random.
//
// Measured on a live host: the permanent header is not bare. It carries
// "(default)" where the running one carries "(default, active)", and this test
// asked for a bare name until the measurement said otherwise.
func TestThePermanentListingIsReadTheSameWayAsTheRunningOne(t *testing.T) {
	kept := ParseZones(keptListing, "public")
	if len(kept) != 2 {
		t.Fatalf("the permanent listing read as %d zones: %+v", len(kept), kept)
	}
	public, ok := zoneNamed(kept, "public")
	if !ok || public.Target != "default" || len(public.Services) != 3 || len(public.Ports) != 2 {
		t.Fatalf("the permanent listing of a zone read as %+v", public)
	}
	// The marker names the default zone and never an active one: a permanent
	// configuration has no notion of a zone being on an interface.
	if !public.Default || public.Active {
		t.Errorf("default=%v active=%v for a zone of the permanent listing", public.Default, public.Active)
	}
	// A bare header is read the same way, because the default zone is also
	// known by name from firewall-cmd --get-default-zone.
	bare, _ := zoneNamed(ParseZones("public\n  target: default\n", "public"), "public")
	if !bare.Default || bare.Active {
		t.Errorf("a bare header read as default=%v active=%v", bare.Default, bare.Active)
	}
}

// Adjacency, from the legitimate side: the differences every real host has -
// the markers, the interface NetworkManager bound, the order the entries come
// in - are not pending changes, and a guard that called them one would refuse
// every zone change on every host.
func TestTheTwoConfigurationsOfAnOrdinaryHostDoNotDrift(t *testing.T) {
	running, kept := views(runningListing, keptListing)
	if drift := ZoneDrift(running, kept, "", ""); len(drift) != 0 {
		t.Fatalf("an ordinary host reads as drifting: %+v", drift)
	}
	if refusal := ZoneReloadRefusal(ZoneDrift(running, kept, "", "")); refusal != "" {
		t.Errorf("an ordinary host was refused a zone change: %s", refusal)
	}
	// A host that is not firewalld answers neither question and has no zone
	// difference to report.
	if drift := ZoneDrift(nil, nil, "", ""); len(drift) != 0 {
		t.Errorf("a host without zones reads as drifting: %+v", drift)
	}
	if refusal := ZoneReloadRefusal(nil); refusal != "" {
		t.Errorf("a host without zones was refused: %s", refusal)
	}
}

// What a reload would carry, in both directions, and the whole zone as well as
// an entry in it. Each of these is a change nobody in a panel order asked for.
func TestWhatAReloadWouldCarryIsReported(t *testing.T) {
	for _, tc := range []struct {
		why     string
		running string
		kept    string
		reason  string
		rule    string
	}{
		{why: "an entry kept and not in force", running: runningListing,
			kept:   strings.Replace(keptListing, "ports: ", "ports: 5432/tcp ", 1),
			reason: DriftZonePending, rule: "port 5432/tcp"},
		{why: "an entry in force and not kept", running: runningListing,
			kept:   strings.Replace(keptListing, " 8443/tcp", "", 1),
			reason: DriftZoneRuntimeOnly, rule: "port 8443/tcp"},
		{why: "a service kept and not in force", running: runningListing,
			kept:   strings.Replace(keptListing, "services: ", "services: http ", 1),
			reason: DriftZonePending, rule: "service http"},
		{why: "a target waiting for the next reload", running: runningListing,
			kept:   strings.Replace(keptListing, "target: default", "target: DROP", 1),
			reason: DriftZonePending, rule: "target DROP"},
		{why: "a zone kept and not in force", running: runningListing,
			kept:   keptListing + "dmz\n  target: default\n",
			reason: DriftZonePending, rule: "zone dmz"},
		{why: "a zone in force and not kept", running: runningListing + "dmz\n  target: default\n",
			kept:   keptListing,
			reason: DriftZoneRuntimeOnly, rule: "zone dmz"},
	} {
		t.Run(tc.why, func(t *testing.T) {
			running, kept := views(tc.running, tc.kept)
			drift := ZoneDrift(running, kept, "", "")
			if len(drift) == 0 {
				t.Fatal("the difference was not reported, so a reload would have carried it unannounced")
			}
			found := false
			for _, entry := range drift {
				if entry.Reason == tc.reason && entry.Rule == tc.rule {
					found = true
					if entry.Detail == "" {
						t.Error("the difference says nothing about what it means for the host")
					}
					if entry.Zone == "" {
						t.Error("the difference does not name the zone it is in")
					}
				}
			}
			if !found {
				t.Fatalf("%s %s is not among %+v", tc.reason, tc.rule, drift)
			}
			refusal := ZoneReloadRefusal(drift)
			if refusal == "" {
				t.Fatal("the change was allowed to reload a configuration nobody approved")
			}
			if !strings.Contains(refusal, tc.rule) {
				t.Errorf("the refusal does not name %s: %s", tc.rule, refusal)
			}
		})
	}
}

// A reading that could not compare the two is not a reading that found them
// equal. The entry says which one was missing and why.
func TestNotKnowingOneConfigurationIsNotAgreement(t *testing.T) {
	running, kept := views(runningListing, keptListing)
	for _, tc := range []struct {
		why             string
		runtimeReason   string
		permanentReason string
		names           string
	}{
		{why: "the permanent listing failed", permanentReason: "firewall-cmd --permanent: exit status 252",
			names: "exit status 252"},
		{why: "the running listing failed", runtimeReason: "firewall-cmd: FirewallD is not running",
			names: "FirewallD is not running"},
	} {
		t.Run(tc.why, func(t *testing.T) {
			drift := ZoneDrift(running, kept, tc.runtimeReason, tc.permanentReason)
			if len(drift) != 1 || drift[0].Reason != DriftZoneNotComparable {
				t.Fatalf("two configurations that cannot be compared read as %+v", drift)
			}
			if !strings.Contains(drift[0].Detail, tc.names) {
				t.Errorf("the entry does not carry why: %s", drift[0].Detail)
			}
			if ZoneReloadRefusal(drift) == "" {
				t.Error("a host nothing is known about was allowed to reload")
			}
		})
	}
}

// The refusal names a few differences and counts the rest; the whole list
// travels in the snapshot beside it.
func TestTheRefusalNamesSomeAndCountsTheRest(t *testing.T) {
	running, _ := views(runningListing, keptListing)
	kept := ParseZones(strings.Replace(keptListing, "ports: ",
		"ports: 1/tcp 2/tcp 3/tcp 4/tcp ", 1), "public")
	drift := ZoneDrift(running, kept, "", "")
	if len(drift) != 4 {
		t.Fatalf("four pending entries read as %+v", drift)
	}
	refusal := ZoneReloadRefusal(drift)
	if !strings.Contains(refusal, "4 difference(s)") || !strings.Contains(refusal, "and 1 more") {
		t.Errorf("the refusal does not account for every difference: %s", refusal)
	}
}
