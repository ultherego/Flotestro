package network

import (
	"strings"
	"testing"
)

// Output of "netplan get" copied from the Ubuntu host of the test fleet:
// the cloud-init uplink and the host-only interface written by the
// virtualisation tool.
const netplanGetOutput = `network:
  version: 2
  renderer: networkd
  ethernets:
    enp0s3:
      dhcp4: true
      match:
        macaddress: "08:00:27:11:22:33"
      set-name: "enp0s3"
    enp0s8:
      addresses:
      - "192.168.56.60/24"
      routes:
      - to: "default"
        via: "192.168.56.1"
      - to: "10.9.0.0/24"
        via: "192.168.56.1"
      nameservers:
        addresses:
        - "192.168.56.50"
        search:
        - "flotestro.test"
      mtu: 1500
`

// The distribution's files as they lie in /etc/netplan, for a host whose
// netplan is too old for "netplan get".
const (
	netplanCloudInit = `network:
  version: 2
  ethernets:
    enp0s3:
      dhcp4: true
`
	netplanVagrant = `network:
  version: 2
  renderer: networkd
  ethernets:
    enp0s8:
      addresses:
      - 192.168.56.60/24
      gateway4: 192.168.56.1
`
)

func TestNetplanGetIsReadIntoProfiles(t *testing.T) {
	config, err := ParseNetplan(netplanGetOutput)
	if err != nil {
		t.Fatal(err)
	}
	if config.Renderer != "networkd" {
		t.Errorf("renderer = %q", config.Renderer)
	}
	profile, err := config.Profile("enp0s8")
	if err != nil {
		t.Fatal(err)
	}
	if profile.Method != "manual" || profile.Type != "ethernets" || profile.MTU != "1500" {
		t.Errorf("profile = %+v", profile)
	}
	if len(profile.Addresses) != 1 || profile.Addresses[0] != "192.168.56.60/24" {
		t.Errorf("addresses = %v", profile.Addresses)
	}
	if profile.Gateway != "192.168.56.1" || len(profile.Routes) != 1 ||
		profile.Routes[0] != "10.9.0.0/24 192.168.56.1" {
		t.Errorf("gateway = %q, routes = %v", profile.Gateway, profile.Routes)
	}
	if len(profile.DNS) != 1 || len(profile.DNSSearch) != 1 {
		t.Errorf("resolver = %v / %v", profile.DNS, profile.DNSSearch)
	}
	uplink, _ := config.Profile("enp0s3")
	// No MTU key means the driver default, and that is "auto" - the same
	// word NetworkManager uses for it - not a number made up here.
	if uplink.Method != "auto" || uplink.MTU != MTUAuto {
		t.Errorf("uplink = %+v", uplink)
	}
	if _, err := config.Profile("eth9"); err == nil {
		t.Error("an interface netplan does not describe got a profile")
	}
}

// Without "netplan get" the files are merged the way netplan merges them:
// a later file amends an earlier one and a scalar in it wins.
func TestNetplanFilesAreMergedInOrder(t *testing.T) {
	config, err := MergeNetplanDocuments(netplanCloudInit, netplanVagrant)
	if err != nil {
		t.Fatal(err)
	}
	if len(config.Interfaces) != 2 || config.Renderer != "networkd" {
		t.Fatalf("merged = %+v", config)
	}
	entry := config.Interfaces["enp0s8"]
	if entry.Profile.Gateway != "192.168.56.1" || !entry.Gateway4 {
		t.Errorf("the deprecated gateway4 was not read: %+v", entry)
	}
}

// The panel's file carries only the keys of the change for the touched
// interface. The distribution's definition is not copied into it: a copy
// would freeze the rest of the definition at today's values.
func TestNetplanManagedFileCarriesOnlyTheChange(t *testing.T) {
	config, _ := ParseNetplan(netplanGetOutput)
	current, _ := config.Profile("enp0s8")

	plan := ComputeMTU("enp0s8", current, "1400")
	document, err := NetplanManagedDocument("", config, "enp0s8", PlanMTU, current, *plan.Desired)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(document, "mtu: 1400") || !strings.Contains(document, "version: 2") ||
		!strings.Contains(document, "ethernets:") {
		t.Errorf("managed file = %s", document)
	}
	for _, foreign := range []string{"addresses", "routes", "nameservers", "enp0s3", "renderer"} {
		if strings.Contains(document, foreign) {
			t.Errorf("the managed file carries %q:\n%s", foreign, document)
		}
	}

	// A second change on another interface keeps the first one.
	uplink, _ := config.Profile("enp0s3")
	plan = ComputeMTU("enp0s3", uplink, "1300")
	document, err = NetplanManagedDocument(document, config, "enp0s3", PlanMTU, uplink, *plan.Desired)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(document, "mtu: 1400") || !strings.Contains(document, "mtu: 1300") {
		t.Errorf("the second change lost the first: %s", document)
	}

	// "auto" removes the panel's override rather than writing a number.
	back := ComputeMTU("enp0s8", current, MTUAuto)
	document, err = NetplanManagedDocument(document, config, "enp0s8", PlanMTU, current, *back.Desired)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(document, "1400") || strings.Contains(document, "enp0s8") {
		t.Errorf("the override was not removed: %s", document)
	}
	if _, err := NetplanManagedDocument("", config, "eth9", PlanMTU, current, *plan.Desired); err == nil {
		t.Error("a definition was created for an interface netplan does not describe")
	}
}

// A list in a later file replaces the earlier one, so a route change has
// to carry the default route along - otherwise the host would lose its
// gateway together with the static routes.
func TestNetplanRouteListKeepsTheGateway(t *testing.T) {
	config, _ := ParseNetplan(netplanGetOutput)
	current, _ := config.Profile("enp0s8")
	desired := current
	desired.Routes = []string{"10.8.0.0/24 192.168.56.1"}

	document, err := NetplanManagedDocument("", config, "enp0s8", PlanRoutes, current, desired)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(document, "to: default") || !strings.Contains(document, "via: 192.168.56.1") {
		t.Errorf("the route list dropped the gateway: %s", document)
	}
	if !strings.Contains(document, "to: 10.8.0.0/24") || strings.Contains(document, "10.9.0.0/24") {
		t.Errorf("the route list = %s", document)
	}

	// With the deprecated gateway4 the default stays in that key and the
	// list carries the static routes alone.
	old, _ := MergeNetplanDocuments(netplanCloudInit, netplanVagrant)
	oldCurrent, _ := old.Profile("enp0s8")
	document, err = NetplanManagedDocument("", old, "enp0s8", PlanRoutes, oldCurrent, desired)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(document, "to: default") {
		t.Errorf("a gateway4 host got a second default route: %s", document)
	}
}

func TestNetplanProfileDocumentSetsAddressesAndGateway(t *testing.T) {
	config, _ := ParseNetplan(netplanGetOutput)
	current, _ := config.Profile("enp0s8")
	plan := ComputeProfile("enp0s8", current, "manual", []string{"192.168.56.61/24"},
		"192.168.56.2", []string{"192.168.56.51"})
	document, err := NetplanManagedDocument("", config, "enp0s8", PlanProfile, current, *plan.Desired)
	if err != nil {
		t.Fatal(err)
	}
	for _, expected := range []string{
		"dhcp4: false", "- 192.168.56.61/24", "via: 192.168.56.2", "to: 10.9.0.0/24",
		"- 192.168.56.51", "- flotestro.test",
	} {
		if !strings.Contains(document, expected) {
			t.Errorf("the profile document lacks %q:\n%s", expected, document)
		}
	}
	if strings.Contains(document, "mtu") {
		t.Errorf("the address profile touched the MTU: %s", document)
	}

	old, _ := MergeNetplanDocuments(netplanCloudInit, netplanVagrant)
	oldCurrent, _ := old.Profile("enp0s8")
	plan = ComputeProfile("enp0s8", oldCurrent, "manual", []string{"192.168.56.61/24"}, "192.168.56.2", nil)
	document, err = NetplanManagedDocument("", old, "enp0s8", PlanProfile, oldCurrent, *plan.Desired)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(document, "gateway4: 192.168.56.2") || strings.Contains(document, "routes") {
		t.Errorf("a gateway4 host did not get its gateway through gateway4: %s", document)
	}
	if _, err := NetplanManagedDocument("", config, "enp0s8", PlanProfile, current,
		Profile{Connection: "enp0s8", Method: "manual"}); err == nil {
		t.Error("manual without an address passed")
	}
}

func TestNetplanCommandsUseItsOwnRevert(t *testing.T) {
	if got := strings.Join(NetplanTryArguments(120), " "); got != NetplanPath+" try --timeout 120" {
		t.Errorf("try = %q", got)
	}
	if got := strings.Join(NetplanGenerateArguments(), " "); got != NetplanPath+" generate" {
		t.Errorf("generate = %q", got)
	}
	// The prompt is the sign that the change is on the host and the
	// connectivity check makes sense.
	if !NetplanPromptSeen("Do you want to keep these settings?\n\n\nPress ENTER before the timeout to accept the new configuration\n") {
		t.Error("the confirmation prompt was not recognised")
	}
	if NetplanPromptSeen("Generating configuration...\n") {
		t.Error("output before the prompt counted as the prompt")
	}
}

func TestDetectionPrefersDesiredStateMechanisms(t *testing.T) {
	present := func(paths ...string) func(string) bool {
		return func(path string) bool {
			for _, candidate := range paths {
				if candidate == path {
					return true
				}
			}
			return false
		}
	}
	if got := DetectAdapter(present(NetplanPath, NetplanDir)); got != AdapterNetplan {
		t.Errorf("an Ubuntu host detected %q", got)
	}
	if got := DetectAdapter(present(NetplanPath, NetplanDir, NmcliPath, "/run/NetworkManager")); got != AdapterNetworkManager {
		t.Errorf("a NetworkManager host with netplan detected %q", got)
	}
	if got := DetectAdapter(present(NmstatectlPathAlt, NmcliPath, "/run/NetworkManager")); got != AdapterNmstate {
		t.Errorf("an nmstate host detected %q", got)
	}
	if got := DetectAdapter(present()); got != "" || ReadOnlyReason(got) == "" {
		t.Errorf("a host without a mechanism detected %q", got)
	}
}
