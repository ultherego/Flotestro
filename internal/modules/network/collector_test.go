package network

import (
	"os"
	"path/filepath"
	"testing"
)

// Output copied from a host of the test fleet: a physical interface with a
// static address and a link-local address, and the docker bridge.
const interfacesOutput = `[
 {"ifindex":1,"ifname":"lo","flags":["LOOPBACK","UP","LOWER_UP"],"mtu":65536,"operstate":"UNKNOWN","link_type":"loopback","address":"00:00:00:00:00:00",
  "addr_info":[{"family":"inet","local":"127.0.0.1","prefixlen":8,"scope":"host","valid_life_time":4294967295}]},
 {"ifindex":3,"ifname":"eth1","flags":["BROADCAST","MULTICAST","UP","LOWER_UP"],"mtu":1500,"operstate":"UP","link_type":"ether","address":"08:00:27:9d:b0:1a",
  "addr_info":[
   {"family":"inet","local":"192.168.56.30","prefixlen":24,"scope":"global","valid_life_time":4294967295},
   {"family":"inet6","local":"fe80::a00:27ff:fe9d:b01a","prefixlen":64,"scope":"link","protocol":"kernel_ll","valid_life_time":4294967295}]},
 {"ifindex":2,"ifname":"eth0","flags":["BROADCAST","MULTICAST","UP","LOWER_UP"],"mtu":1500,"operstate":"UP","link_type":"ether","address":"08:00:27:11:22:33",
  "addr_info":[{"family":"inet","local":"10.0.2.15","prefixlen":24,"scope":"global","dynamic":true,"valid_life_time":85846}]},
 {"ifindex":4,"ifname":"docker0","flags":["BROADCAST","MULTICAST","UP"],"mtu":1500,"operstate":"DOWN","link_type":"ether","address":"02:42:1a:2b:3c:4d",
  "linkinfo":{"info_kind":"bridge"},
  "addr_info":[{"family":"inet","local":"172.17.0.1","prefixlen":16,"scope":"global","valid_life_time":4294967295}]}]`

const routesOutput = `[
 {"dst":"default","gateway":"10.0.2.2","dev":"eth0","protocol":"dhcp","prefsrc":"10.0.2.15","metric":1002,"flags":[]},
 {"dst":"192.168.56.0/24","dev":"eth1","protocol":"kernel","scope":"link","prefsrc":"192.168.56.30","flags":[]}]`

func TestInterfacesHaveAddressesWithMasks(t *testing.T) {
	interfaces, err := ParseInterfaces(interfacesOutput)
	if err != nil {
		t.Fatal(err)
	}
	if len(interfaces) != 4 {
		t.Fatalf("interfaces = %d", len(interfaces))
	}
	byName := map[string]Interface{}
	for _, iface := range interfaces {
		byName[iface.Name] = iface
	}

	// An address without the mask does not say which network the host
	// considers local.
	if byName["eth1"].Addresses[0].Address != "192.168.56.30/24" {
		t.Errorf("eth1 address = %q", byName["eth1"].Addresses[0].Address)
	}
	// A DHCP address vanishes with the lease; a permanent one does not.
	if !byName["eth1"].Addresses[0].Permanent {
		t.Error("a static address treated as temporary")
	}
	if byName["eth0"].Addresses[0].Permanent {
		t.Error("a DHCP address treated as permanent")
	}
	// A host with docker has a dozen interfaces and only some mean anything
	// to the operator: the kind is what tells them apart.
	if byName["docker0"].Kind != "bridge" || byName["eth1"].Kind != "ethernet" || byName["lo"].Kind != "loopback" {
		t.Errorf("kinds = %q %q %q", byName["docker0"].Kind, byName["eth1"].Kind, byName["lo"].Kind)
	}
	// The state "unknown" stays the word: that is how virtual interfaces
	// report and it must not be turned into "down".
	if byName["lo"].OperState != "unknown" {
		t.Errorf("lo state = %q", byName["lo"].OperState)
	}
}

func TestRoutesKeepProtocolAndMetric(t *testing.T) {
	routes, err := ParseRoutes(routesOutput, FamilyIPv4)
	if err != nil {
		t.Fatal(err)
	}
	if len(routes) != 2 {
		t.Fatalf("routes = %d", len(routes))
	}
	if routes[0].Destination != "default" || routes[0].Gateway != "10.0.2.2" ||
		routes[0].Protocol != "dhcp" || routes[0].Metric != 1002 {
		t.Errorf("default route = %+v", routes[0])
	}
	if routes[1].Family != FamilyIPv4 {
		t.Errorf("family = %q", routes[1].Family)
	}
}

// The management channel is pointed at by the address the agent really
// talks to the panel with. Guessing from the first position of the list
// would end in changing the interface the order has just arrived through.
func TestManagementChannelPointsAtConnectionInterface(t *testing.T) {
	interfaces, err := ParseInterfaces(interfacesOutput)
	if err != nil {
		t.Fatal(err)
	}
	snapshot := Snapshot{Interfaces: interfaces}
	MarkManagementChannel(&snapshot, "192.168.56.30:48212")

	if snapshot.ManagementInterface != "eth1" {
		t.Errorf("management interface = %q", snapshot.ManagementInterface)
	}
	if snapshot.ManagementAddress != "192.168.56.30/24" {
		t.Errorf("management address = %q", snapshot.ManagementAddress)
	}
	if !snapshot.InterfaceByName("eth1").Management || snapshot.InterfaceByName("eth0").Management {
		t.Error("the wrong interface was marked")
	}

	// An address not on the host must not mark anything "just in case".
	empty := Snapshot{Interfaces: interfaces}
	MarkManagementChannel(&empty, "10.9.9.9")
	if empty.ManagementInterface != "" {
		t.Errorf("an interface was marked for a foreign address: %q", empty.ManagementInterface)
	}
}

func TestSysDataSupplementsLink(t *testing.T) {
	dir := t.TempDir()
	eth := filepath.Join(dir, "eth1")
	if err := os.MkdirAll(eth, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(eth, "carrier"), []byte("1\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	// The kernel returns -1 for a link without a carrier. An unknown speed
	// must stay unknown, not become zero.
	if err := os.WriteFile(filepath.Join(eth, "speed"), []byte("-1\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	interfaces := []Interface{{Name: "eth1"}, {Name: "missing"}}
	SupplementFromSys(dir, interfaces)

	if interfaces[0].Carrier == nil || !*interfaces[0].Carrier {
		t.Errorf("carrier = %v", interfaces[0].Carrier)
	}
	if interfaces[0].SpeedMbps != nil {
		t.Errorf("speed = %v", *interfaces[0].SpeedMbps)
	}
	// An interface without a directory in /sys must not get values
	// pretending to be facts.
	if interfaces[1].Carrier != nil || interfaces[1].SpeedMbps != nil {
		t.Errorf("interface without /sys = %+v", interfaces[1])
	}
}

// A host without a write mechanism is meant to say so directly, not stay
// silent.
func TestMissingWriteAdapterHasReason(t *testing.T) {
	if adapter := DetectAdapter(func(string) bool { return false }); adapter != "" {
		t.Errorf("adapter = %q", adapter)
	}
	if ReadOnlyReason("") == "" {
		t.Error("missing adapter without a reason")
	}
	if ReadOnlyReason(AdapterNetworkManager) != "" {
		t.Error("a host with an adapter reports an unavailability reason")
	}
	present := map[string]bool{"/usr/bin/nmcli": true, "/run/NetworkManager": true}
	if adapter := DetectAdapter(func(s string) bool { return present[s] }); adapter != AdapterNetworkManager {
		t.Errorf("adapter = %q", adapter)
	}
}
