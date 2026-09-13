package network

import (
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// Output copied from a host of the test fleet.
const connectionsOutput = `enp0s3:4a0293d8-8529-4912-947a-ad53f52d9c76:enp0s3:802-3-ethernet:activated
enp0s8:071696f0-9e5f-477c-a92c-0da64a4e0fd9:enp0s8:802-3-ethernet:activated
lo:b4b1089d-07af-4228-8df8-5d3e9342825c:lo:loopback:activated`

const profileOutput = `connection.id:enp0s8
connection.interface-name:enp0s8
ipv4.method:manual
ipv4.addresses:192.168.56.40/24
ipv4.gateway:192.168.56.1
ipv4.dns:
ipv4.routes:
802-3-ethernet.mtu:auto`

func TestProfileReadsConnectionSettings(t *testing.T) {
	profile := ParseProfile(profileOutput)
	if profile.Connection != "enp0s8" || profile.Method != "manual" {
		t.Fatalf("profile = %+v", profile)
	}
	if len(profile.Addresses) != 1 || profile.Addresses[0] != "192.168.56.40/24" {
		t.Errorf("addresses = %v", profile.Addresses)
	}
	// An empty field is a missing setting, not an empty string in the
	// configuration.
	if len(profile.DNS) != 0 || len(profile.Routes) != 0 {
		t.Errorf("empty fields turned into values: %+v", profile)
	}
	// "auto" is an equal MTU value and must not become zero.
	if profile.MTU != MTUAuto {
		t.Errorf("MTU = %q", profile.MTU)
	}
}

// An IPv6 address contains colons, so the value is everything after the
// first one. Splitting on each would break the address into pieces.
func TestValueWithColonsIsNotSplit(t *testing.T) {
	profile := ParseProfile("ipv4.dns:fd00::1,fd00::2\nconnection.id:test")
	if len(profile.DNS) != 2 || profile.DNS[0] != "fd00::1" {
		t.Fatalf("DNS = %v", profile.DNS)
	}
}

func TestConnectionIsFoundByDevice(t *testing.T) {
	connections := ParseConnections(connectionsOutput)
	if len(connections) != 3 {
		t.Fatalf("connections = %d", len(connections))
	}
	if connection := DeviceConnection(connections, "enp0s8"); connection == nil ||
		connection.Name != "enp0s8" {
		t.Errorf("enp0s8 connection = %+v", connection)
	}
	if DeviceConnection(connections, "eth9") != nil {
		t.Error("a connection was found for a non-existent device")
	}
}

// Values that would cut the host off or are not a configuration are meant
// to be rejected before touching the host.
func TestBadConfigurationIsRejected(t *testing.T) {
	if err := ValidateMTU("900"); err == nil {
		t.Error("accepted an MTU below the IPv6 threshold")
	}
	if err := ValidateMTU(MTUAuto); err != nil {
		t.Errorf("rejected MTU auto: %v", err)
	}
	if err := ValidateRoute("192.168.9.0/24 192.168.56.1 extra"); err == nil {
		t.Error("accepted a route with an extra field")
	}
	if err := ValidateRoute("192.168.9.0 192.168.56.1"); err == nil {
		t.Error("accepted a route destination without a mask")
	}
	if err := ValidateRoute("192.168.9.0/24"); err != nil {
		t.Errorf("rejected a route without a gateway: %v", err)
	}
	// The manual method without an address would leave the interface
	// without an address - that is not a configuration, it is a mistake.
	if _, err := ProfileArguments(Profile{Connection: "enp0s8", Method: "manual"}); err == nil {
		t.Error("accepted a manual profile without addresses")
	}
}

func TestChangeArgumentsGoThroughProfile(t *testing.T) {
	steps, err := MTUArguments("enp0s8", "1400")
	if err != nil {
		t.Fatal(err)
	}
	if len(steps) != 2 {
		t.Fatalf("steps = %d", len(steps))
	}
	// A change set directly on the device vanishes at a connection switch;
	// the profile survives a host reboot.
	if strings.Join(steps[0], " ") !=
		NmcliPath+" connection modify enp0s8 802-3-ethernet.mtu 1400" {
		t.Errorf("modification step = %v", steps[0])
	}
	if steps[1][len(steps[1])-1] != "enp0s8" || steps[1][2] != "up" {
		t.Errorf("activation step = %v", steps[1])
	}
}

// A rollback plan describes a state, not commands: a file that could steer
// the execution would be a door to root.
func TestRollbackPlanReturnsToStateBeforeChange(t *testing.T) {
	dir := t.TempDir()
	plan := RollbackPlan{
		ID:        "plan-test",
		Interface: "enp0s8",
		Profile:   ParseProfile(profileOutput),
		CreatedAt: time.Now().UTC(),
		Deadline:  time.Now().UTC().Add(2 * time.Minute),
	}
	if err := SavePlan(dir, plan); err != nil {
		t.Fatal(err)
	}
	loaded, err := LoadPlan(dir, plan.ID)
	if err != nil {
		t.Fatal(err)
	}
	steps, err := RollbackSteps(loaded)
	if err != nil {
		t.Fatal(err)
	}
	command := strings.Join(steps[0], " ")
	if !strings.Contains(command, "ipv4.addresses 192.168.56.40/24") ||
		!strings.Contains(command, "ipv4.method manual") {
		t.Errorf("the rollback does not restore the state: %v", steps[0])
	}

	if err := RemovePlan(dir, plan.ID); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadPlan(dir, plan.ID); err == nil {
		t.Error("the plan survived removal")
	}
}

// The plan identifier is part of the file name, so it must not lead the
// path outside the plans directory.
func TestPlanIdentifierStaysInDirectory(t *testing.T) {
	for _, id := range []string{"", "../etc/passwd", "plan/../../x", "PLAN", "plan.json"} {
		if ValidPlanID(id) {
			t.Errorf("accepted identifier %q", id)
		}
		if _, err := PlanPath("/var/lib", id); err == nil {
			t.Errorf("composed a path for %q", id)
		}
	}
	path, err := PlanPath("/var/lib", "plan-1")
	if err != nil || filepath.Dir(path) != "/var/lib" {
		t.Errorf("path = %q, err = %v", path, err)
	}
}

func TestProfileReadsAndWritesRestOfResolver(t *testing.T) {
	profile := ParseProfile("connection.id:enp0s8\nipv4.dns:192.168.56.50\n" +
		"ipv4.dns-search:flotestro.test,lab.test\nipv4.ignore-auto-dns:yes")
	if len(profile.DNSSearch) != 2 || !profile.IgnoreAutoDNS {
		t.Fatalf("profile without the rest of the resolver: %+v", profile)
	}
	profile.Method = "auto"
	steps, err := ProfileArguments(profile)
	if err != nil {
		t.Fatal(err)
	}
	write := strings.Join(steps[0], " ")
	// The rollback recreates the profile with the same code: the search
	// domains and the DHCP server rejection must come back with the
	// servers.
	if !strings.Contains(write, "ipv4.dns-search flotestro.test,lab.test") ||
		!strings.Contains(write, "ipv4.ignore-auto-dns yes") {
		t.Errorf("the profile write loses the rest of the resolver: %s", write)
	}
}
