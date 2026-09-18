package network

import (
	"strings"
	"testing"
)

// Output of "nmstatectl show" copied from a host with a static management
// interface and a DHCP uplink.
const nmstateYAML = `---
dns-resolver:
  config:
    server:
    - 192.168.56.50
    search:
    - flotestro.test
  running:
    server:
    - 192.168.56.50
    - 10.0.2.3
routes:
  config:
  - destination: 0.0.0.0/0
    next-hop-address: 192.168.56.1
    next-hop-interface: enp0s8
    table-id: 254
  - destination: 10.9.0.0/24
    next-hop-address: 192.168.56.1
    next-hop-interface: enp0s8
    table-id: 254
  - destination: 0.0.0.0/0
    next-hop-address: 10.0.2.2
    next-hop-interface: enp0s3
    table-id: 254
  running:
  - destination: 192.168.56.0/24
    next-hop-interface: enp0s8
    table-id: 254
interfaces:
- name: enp0s3
  type: ethernet
  state: up
  mac-address: 08:00:27:11:22:33
  mtu: 1500
  ipv4:
    enabled: true
    dhcp: true
    auto-dns: true
    address:
    - ip: 10.0.2.15
      prefix-length: 24
  ipv6:
    enabled: true
    autoconf: true
- name: enp0s8
  type: ethernet
  state: up
  mac-address: 08:00:27:44:55:66
  mtu: 1500
  ipv4:
    enabled: true
    dhcp: false
    address:
    - ip: 192.168.56.40
      prefix-length: 24
  ipv6:
    enabled: false
- name: lo
  type: loopback
  state: up
  mtu: 65536
  ipv4:
    enabled: true
    address:
    - ip: 127.0.0.1
      prefix-length: 8
`

// The same state as "nmstatectl show --json" prints it.
const nmstateJSON = `{
  "dns-resolver": {"config": {"server": ["192.168.56.50"], "search": ["flotestro.test"]}},
  "routes": {"config": [
    {"destination": "0.0.0.0/0", "next-hop-address": "192.168.56.1", "next-hop-interface": "enp0s8", "table-id": 254},
    {"destination": "10.9.0.0/24", "next-hop-address": "192.168.56.1", "next-hop-interface": "enp0s8", "table-id": 254}
  ]},
  "interfaces": [
    {"name": "enp0s8", "type": "ethernet", "state": "up", "mtu": 1500,
     "ipv4": {"enabled": true, "dhcp": false, "address": [{"ip": "192.168.56.40", "prefix-length": 24}]}},
    {"name": "lo", "type": "loopback", "state": "up", "mtu": 65536}
  ]
}`

func TestNmstateStateIsReadInBothForms(t *testing.T) {
	for name, fixture := range map[string]string{"yaml": nmstateYAML, "json": nmstateJSON} {
		t.Run(name, func(t *testing.T) {
			state, err := ParseNmstateState([]byte(fixture))
			if err != nil {
				t.Fatal(err)
			}
			profile, err := state.Profile("enp0s8")
			if err != nil {
				t.Fatal(err)
			}
			if profile.Method != "manual" || profile.Type != "ethernet" || profile.MTU != "1500" {
				t.Errorf("profile = %+v", profile)
			}
			if len(profile.Addresses) != 1 || profile.Addresses[0] != "192.168.56.40/24" {
				t.Errorf("addresses = %v", profile.Addresses)
			}
			// The default route is the gateway, the rest are routes; a route
			// of another interface stays out.
			if profile.Gateway != "192.168.56.1" || len(profile.Routes) != 1 ||
				profile.Routes[0] != "10.9.0.0/24 192.168.56.1" {
				t.Errorf("gateway = %q, routes = %v", profile.Gateway, profile.Routes)
			}
			if len(profile.DNS) != 1 || profile.DNS[0] != "192.168.56.50" ||
				len(profile.DNSSearch) != 1 {
				t.Errorf("resolver = %v / %v", profile.DNS, profile.DNSSearch)
			}
			// The loopback is nobody's decision and stays out of the list.
			for _, entry := range state.Profiles() {
				if entry.Connection == "lo" {
					t.Error("the loopback appeared among the profiles")
				}
			}
			if _, err := state.Profile("eth9"); err == nil {
				t.Error("an interface nmstate does not describe got a profile")
			}
		})
	}
}

func TestNmstateDHCPInterfaceIsAuto(t *testing.T) {
	state, err := ParseNmstateState([]byte(nmstateYAML))
	if err != nil {
		t.Fatal(err)
	}
	profile, err := state.Profile("enp0s3")
	if err != nil {
		t.Fatal(err)
	}
	if profile.Method != "auto" || profile.IgnoreAutoDNS || profile.Gateway != "10.0.2.2" {
		t.Errorf("DHCP profile = %+v", profile)
	}
	// A leased address is still an address the host has; the plan shows it
	// and the method says where it came from.
	if len(profile.Addresses) != 1 || profile.Addresses[0] != "10.0.2.15/24" {
		t.Errorf("addresses = %v", profile.Addresses)
	}
}

// The document carries only the touched interface and only the section the
// change concerns: nmstate merges it into the running state, and everything
// left out stays as it is.
func TestNmstateDocumentIsMinimal(t *testing.T) {
	state, _ := ParseNmstateState([]byte(nmstateYAML))
	current, _ := state.Profile("enp0s8")

	plan := ComputeMTU("enp0s8", current, "9000")
	document, err := NmstateDocument(PlanMTU, current, *plan.Desired)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(document, "name: enp0s8") || !strings.Contains(document, "mtu: 9000") {
		t.Errorf("MTU document = %q", document)
	}
	for _, foreign := range []string{"enp0s3", "routes:", "dns-resolver:", "ipv4:"} {
		if strings.Contains(document, foreign) {
			t.Errorf("the MTU document carries %q: %s", foreign, document)
		}
	}

	// The rollback document is the same function the other way round.
	back, err := NmstateDocument(PlanMTU, *plan.Desired, current)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(back, "mtu: 1500") {
		t.Errorf("rollback document = %q", back)
	}
	// nmstate knows only numbers; the driver default is not a state it can
	// describe.
	if _, err := NmstateDocument(PlanMTU, current, Profile{Connection: "enp0s8", MTU: MTUAuto}); err == nil {
		t.Error("MTU auto passed to nmstate")
	}
}

// Replacing the routes removes the ones the interface has and adds the
// desired ones: nmstate has no "set the list" - an entry not marked absent
// stays.
func TestNmstateRoutesAreReplacedNotAppended(t *testing.T) {
	state, _ := ParseNmstateState([]byte(nmstateYAML))
	current, _ := state.Profile("enp0s8")
	desired := current
	desired.Routes = []string{"10.8.0.0/24 192.168.56.1"}

	document, err := NmstateDocument(PlanRoutes, current, desired)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(document, "destination: 10.9.0.0/24") || !strings.Contains(document, "state: absent") {
		t.Errorf("the old route is not marked absent: %s", document)
	}
	if !strings.Contains(document, "destination: 10.8.0.0/24") ||
		!strings.Contains(document, "next-hop-address: 192.168.56.1") {
		t.Errorf("the new route is missing: %s", document)
	}
	if strings.Contains(document, "0.0.0.0/0") {
		t.Errorf("the route change touched the default route: %s", document)
	}
	if strings.Contains(document, "interfaces:") {
		t.Errorf("the route change carries an interface entry: %s", document)
	}
}

func TestNmstateProfileDocumentSetsAddressesGatewayAndResolver(t *testing.T) {
	state, _ := ParseNmstateState([]byte(nmstateYAML))
	current, _ := state.Profile("enp0s8")

	plan := ComputeProfile("enp0s8", current, ProfileRequest{Method: "manual",
		Addresses: []string{"192.168.56.41/24"}, Gateway: "192.168.56.2",
		DNS: []string{"192.168.56.51"}}, IPv6Settings{})
	document, err := NmstateDocument(PlanProfile, current, *plan.Desired)
	if err != nil {
		t.Fatal(err)
	}
	for _, expected := range []string{
		"ip: 192.168.56.41", "prefix-length: 24", "dhcp: false",
		"next-hop-address: 192.168.56.2", "state: absent", "- 192.168.56.51",
	} {
		if !strings.Contains(document, expected) {
			t.Errorf("the profile document lacks %q:\n%s", expected, document)
		}
	}
	// The routes stay: the address profile is a separate operation.
	if strings.Contains(document, "10.9.0.0/24") {
		t.Errorf("the profile document touched the static routes: %s", document)
	}
	// The way back is the same function the other way round, and it names
	// the interface by its type too: the desired profile carries the type
	// over from the one found.
	back, err := NmstateDocument(PlanProfile, *plan.Desired, current)
	if err != nil {
		t.Fatal(err)
	}
	for _, expected := range []string{"type: ethernet", "ip: 192.168.56.40", "next-hop-address: 192.168.56.1", "- 192.168.56.50"} {
		if !strings.Contains(back, expected) {
			t.Errorf("the rollback document lacks %q:\n%s", expected, back)
		}
	}

	auto := current
	auto.Method = "auto"
	auto.Addresses = nil
	document, err = NmstateDocument(PlanProfile, current, auto)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(document, "dhcp: true") || strings.Contains(document, "address:") {
		t.Errorf("the DHCP document = %s", document)
	}
	if _, err := NmstateDocument(PlanProfile, current, Profile{Connection: "enp0s8", Method: "shared"}); err == nil {
		t.Error("a method nmstate cannot express passed")
	}
}

func TestNmstateCommandsUseItsOwnCheckpoint(t *testing.T) {
	apply := strings.Join(NmstateApplyArguments(NmstatectlPath, "/var/lib/x/w1.desired.yaml", 120), " ")
	if apply != NmstatectlPath+" apply --no-commit --timeout 120 /var/lib/x/w1.desired.yaml" {
		t.Errorf("apply = %q", apply)
	}
	if got := strings.Join(NmstateCommitArguments(NmstatectlPath), " "); got != NmstatectlPath+" commit" {
		t.Errorf("commit = %q", got)
	}
	if got := strings.Join(NmstateRollbackArguments(NmstatectlPath), " "); got != NmstatectlPath+" rollback" {
		t.Errorf("rollback = %q", got)
	}
	if NmstatectlBinary(func(path string) bool { return path == NmstatectlPathAlt }) != NmstatectlPathAlt {
		t.Error("the alternative nmstatectl path was not found")
	}
}

// The interface name goes into documents and file names, so a name the
// kernel would not accept is refused before anything is assembled.
func TestInterfaceNamesAreCheckedBeforeDocumentsAreAssembled(t *testing.T) {
	for _, name := range []string{"enp0s8", "eth0.100", "br-lan", "bond0:1"} {
		if err := ValidateInterfaceName(name); err != nil {
			t.Errorf("%q refused: %v", name, err)
		}
	}
	for _, name := range []string{"", "../etc", "eth 0", "enp0s8-with-a-name-too-long", "-eth0", "eth0\n"} {
		if err := ValidateInterfaceName(name); err == nil {
			t.Errorf("%q passed", name)
		}
	}
	state, _ := ParseNmstateState([]byte(nmstateYAML))
	current, _ := state.Profile("enp0s8")
	current.Connection = "../etc"
	if _, err := NmstateDocument(PlanMTU, current, Profile{Connection: "../etc", MTU: "9000"}); err == nil {
		t.Error("an nmstate document was assembled for a path")
	}
	config, _ := ParseNetplan(netplanGetOutput)
	if _, err := NetplanManagedDocument("", config, "../etc", PlanMTU, Profile{}, Profile{MTU: "9000"}); err == nil {
		t.Error("a netplan document was assembled for a path")
	}
}

// A plan for another mechanism, or with another document, is another
// change: the fingerprint has to tell them apart.
func TestPlanFingerprintCoversAdapterAndDocument(t *testing.T) {
	state, _ := ParseNmstateState([]byte(nmstateYAML))
	current, _ := state.Profile("enp0s8")
	first := ComputeMTU("enp0s8", current, "9000")
	second := first
	document, _ := NmstateDocument(PlanMTU, current, *first.Desired)
	first.Attach(AdapterNmstate, document)
	second.Attach(AdapterNetplan, "network: {}")
	if first.PlanHash == second.PlanHash || first.Adapter != AdapterNmstate {
		t.Errorf("fingerprints do not tell the adapters apart: %s / %s", first.PlanHash, second.PlanHash)
	}
}
