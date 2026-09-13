package firewall

import (
	"strings"
	"testing"
)

func testZones() []Zone {
	return []Zone{
		{Name: "public", Active: true, Default: true, Services: []string{"ssh", "dhcpv6-client"},
			Ports: []string{"8080/tcp"}},
		{Name: "trusted", Active: false},
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
