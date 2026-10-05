package firewall

import (
	"strings"
	"testing"
)

// testZones is one host's two answers. They carry the same entries, because
// the plan of an ordinary host is what these tests are about; what the plan
// reads from which of them is the test below them.
func testZones() ZoneViews {
	permanent := []Zone{
		{Name: "public", Default: true, Services: []string{"ssh", "dhcpv6-client"},
			Ports: []string{"8080/tcp"}},
		{Name: "trusted"},
	}
	running := []Zone{
		{Name: "public", Active: true, Default: true, Services: []string{"ssh", "dhcpv6-client"},
			Ports: []string{"8080/tcp"}},
		{Name: "trusted"},
	}
	return ZoneViews{Permanent: permanent, Runtime: running}
}

// The plan decides against the configuration the change writes. Computed from
// the running one, it called an order with work to do "already done", and one
// with none a change - and the way back followed the same wrong answer.
func TestThePlanIsComputedFromTheConfigurationItWrites(t *testing.T) {
	pair := ZoneViews{
		Permanent: []Zone{{Name: "public", Ports: []string{"8443/tcp"}}},
		Runtime:   []Zone{{Name: "public", Active: true, Ports: []string{"9090/tcp"}}},
	}
	kept := ComputePort(pair, "public", "8443", "tcp", true, "h1", AdapterFirewalld)
	if kept.Action != PlanNoChange || !kept.Present {
		t.Errorf("an entry the host keeps: %+v", kept)
	}
	pending := ComputePort(pair, "public", "9090", "tcp", true, "h1", AdapterFirewalld)
	if pending.Action != PlanCreate || pending.Present {
		t.Errorf("an entry only the running configuration carries: %+v", pending)
	}
	// Whether the zone is on an interface is still read from the running
	// configuration, because the permanent listing has no such notion -
	// reading it there would warn about every zone of every host.
	if !pending.ZoneActive || len(pending.Changes) != 1 {
		t.Errorf("the zone of a plan read as inactive: %+v", pending)
	}
	// A zone only the running configuration has is nowhere to write.
	absent := ComputePort(ZoneViews{Runtime: pair.Runtime}, "public", "80", "tcp",
		true, "h1", AdapterFirewalld)
	if absent.Refusal == "" || absent.ZoneExists {
		t.Errorf("a zone the host does not keep was planned into: %+v", absent)
	}
}

func TestPortPlanDistinguishesOpeningFromTargetState(t *testing.T) {
	opening := ComputePort(testZones(), "public", "9090", "tcp", true, "h1", AdapterFirewalld)
	if opening.Action != PlanCreate || opening.Present || !opening.ZoneExists {
		t.Errorf("opening a new port: %+v", opening)
	}
	already := ComputePort(testZones(), "public", "8080", "tcp", true, "h1", AdapterFirewalld)
	if already.Action != PlanNoChange || !already.Present {
		t.Errorf("port already open: %+v", already)
	}
	closing := ComputePort(testZones(), "public", "8080", "tcp", false, "h1", AdapterFirewalld)
	if closing.Action != PlanRemove {
		t.Errorf("closing an open port: %+v", closing)
	}
	if opening.PlanHash == already.PlanHash || opening.PlanHash == closing.PlanHash {
		t.Error("different plans have the same fingerprint")
	}
}

func TestZonePlanRefusesWithoutZoneAndWithoutSense(t *testing.T) {
	missing := ComputeService(testZones(), "dmz", "http", true, "h1", AdapterFirewalld)
	if !strings.Contains(missing.Refusal, "zone dmz") || missing.ZoneExists {
		t.Errorf("a zone that does not exist: %+v", missing)
	}
	bad := ComputePort(testZones(), "public", "99999", "tcp", true, "h1", AdapterFirewalld)
	if bad.Refusal == "" {
		t.Error("a port out of range passed without a refusal")
	}
	inactive := ComputeService(testZones(), "trusted", "http", true, "h1", AdapterFirewalld)
	if inactive.Action != PlanCreate || len(inactive.Changes) != 2 ||
		!strings.Contains(inactive.Changes[1], "is not active") {
		t.Errorf("inactive zone without a warning: %+v", inactive)
	}
}

func TestRefusalChangesZonePlanFingerprint(t *testing.T) {
	plan := ComputePort(testZones(), "public", "22", "tcp", false, "h1", AdapterFirewalld)
	before := plan.PlanHash
	plan.Refuse("the port 22 is the management channel")
	if plan.PlanHash == before || plan.Refusal == "" {
		t.Error("the refusal did not change the fingerprint")
	}
}
