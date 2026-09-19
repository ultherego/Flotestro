package network

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// The output of "ip -details -json link show" on a host that has all three
// kinds of layer at once: a bond of two cards, a VLAN riding on the bond, and
// a bridge with one port.
const ipLinkOutput = `[
  {"ifindex":1,"ifname":"lo","mtu":65536,"linkinfo":{}},
  {"ifindex":2,"ifname":"enp0s3","mtu":1500},
  {"ifindex":3,"ifname":"enp0s8","mtu":1500,"master":"bond0",
   "linkinfo":{"info_slave_kind":"bond"}},
  {"ifindex":4,"ifname":"enp0s9","mtu":1500,"master":"bond0",
   "linkinfo":{"info_slave_kind":"bond"}},
  {"ifindex":5,"ifname":"bond0","mtu":1500,
   "linkinfo":{"info_kind":"bond","info_data":{"mode":"active-backup","miimon":100,
     "primary":"enp0s8","ad_lacp_rate":"","xmit_hash_policy":"layer2"}}},
  {"ifindex":6,"ifname":"bond0.100","link":"bond0","mtu":1500,
   "linkinfo":{"info_kind":"vlan","info_data":{"id":100,"protocol":"802.1Q"}}},
  {"ifindex":7,"ifname":"br0","mtu":1500,
   "linkinfo":{"info_kind":"bridge","info_data":{"stp_state":1,"vlan_filtering":1,
     "vlan_protocol":"802.1Q"}}},
  {"ifindex":8,"ifname":"enp0s10","mtu":1500,"master":"br0",
   "linkinfo":{"info_slave_kind":"bridge"}}
]`

// The matching "ip -j -d addr show": the addresses of both families, so
// that a plan and a verifier reading only the first one would be caught.
const ipAddressOutput = `[
  {"ifindex":2,"ifname":"enp0s3","mtu":1500,"operstate":"UP","link_type":"ether",
   "address":"08:00:27:00:00:01",
   "addr_info":[
     {"family":"inet","local":"10.0.2.15","prefixlen":24,"scope":"global","protocol":"dhcp","dynamic":true},
     {"family":"inet6","local":"2001:db8::15","prefixlen":64,"scope":"global","valid_life_time":4294967295},
     {"family":"inet6","local":"fe80::a00:27ff:fe00:1","prefixlen":64,"scope":"link","valid_life_time":4294967295}]},
  {"ifindex":3,"ifname":"enp0s8","mtu":1500,"operstate":"UP","link_type":"ether","address":"08:00:27:00:00:02","addr_info":[]},
  {"ifindex":4,"ifname":"enp0s9","mtu":1500,"operstate":"UP","link_type":"ether","address":"08:00:27:00:00:03","addr_info":[]},
  {"ifindex":5,"ifname":"bond0","mtu":1500,"operstate":"UP","link_type":"ether","address":"08:00:27:00:00:02",
   "addr_info":[{"family":"inet","local":"192.168.56.30","prefixlen":24,"scope":"global","valid_life_time":4294967295}]},
  {"ifindex":6,"ifname":"bond0.100","mtu":1500,"operstate":"UP","link_type":"ether","address":"08:00:27:00:00:02","addr_info":[]},
  {"ifindex":7,"ifname":"br0","mtu":1500,"operstate":"UP","link_type":"ether","address":"08:00:27:00:00:04","addr_info":[]},
  {"ifindex":8,"ifname":"enp0s10","mtu":1500,"operstate":"UP","link_type":"ether","address":"08:00:27:00:00:04","addr_info":[]}
]`

// "bridge -json vlan show" for the same host, with a range on one port.
const bridgeVLANOutput = `[
  {"ifname":"br0","vlans":[{"vlan":1,"flags":["PVID","Egress Untagged"]}]},
  {"ifname":"enp0s10","vlans":[{"vlan":1,"flags":["PVID","Egress Untagged"]},{"vlan":10,"vlanEnd":12,"flags":[]}]}
]`

// layeredSnapshot builds the picture the plans in this file are computed
// against: the addresses of both families with the layering merged onto them,
// and the management channel on enp0s3.
func layeredSnapshot(t *testing.T) Snapshot {
	t.Helper()
	interfaces, err := ParseInterfaces(ipAddressOutput)
	if err != nil {
		t.Fatalf("the addresses were not read: %v", err)
	}
	links, err := ParseLinks(ipLinkOutput)
	if err != nil {
		t.Fatalf("the layering was not read: %v", err)
	}
	MergeLayering(interfaces, links)
	vlans, err := ParseBridgeVLANs(bridgeVLANOutput)
	if err != nil {
		t.Fatalf("the bridge VLANs were not read: %v", err)
	}
	AttachBridgeVLANs(interfaces, vlans)
	snapshot := Snapshot{Interfaces: interfaces}
	MarkManagementChannel(&snapshot, "10.0.2.15")
	return snapshot
}

func TestLayeringIsReadFromTheHost(t *testing.T) {
	snapshot := layeredSnapshot(t)

	bond := snapshot.InterfaceByName("bond0")
	if bond == nil || bond.Bond == nil {
		t.Fatalf("bond0 was not read as a bond: %+v", bond)
	}
	if got := strings.Join(bond.Bond.Members, ","); got != "enp0s8,enp0s9" {
		t.Errorf("the members of bond0 = %q", got)
	}
	if bond.Bond.Mode != "active-backup" || bond.Bond.MIIMonMS != 100 || bond.Bond.Primary != "enp0s8" {
		t.Errorf("the bond settings: %+v", bond.Bond)
	}

	member := snapshot.InterfaceByName("enp0s8")
	if member == nil || member.Master != "bond0" {
		t.Errorf("the member does not name its owner: %+v", member)
	}

	vlan := snapshot.InterfaceByName("bond0.100")
	if vlan == nil || vlan.VLAN == nil || vlan.VLAN.Parent != "bond0" || vlan.VLAN.ID != 100 {
		t.Errorf("the VLAN was not read: %+v", vlan)
	}

	bridge := snapshot.InterfaceByName("br0")
	if bridge == nil || bridge.Bridge == nil || !bridge.Bridge.STP || !bridge.Bridge.VLANFiltering {
		t.Fatalf("the bridge was not read: %+v", bridge)
	}
	if got := strings.Join(bridge.Bridge.Members, ","); got != "enp0s10" {
		t.Errorf("the members of br0 = %q", got)
	}
	// The range 10-12 on the port is expanded: the operator asks which VLAN
	// a port carries, and a range would leave them to work it out.
	var tagged int
	for _, entry := range bridge.Bridge.VLANs {
		if entry.Port == "enp0s10" && entry.VID >= 10 && entry.VID <= 12 {
			tagged++
		}
	}
	if tagged != 3 {
		t.Errorf("the VLAN range of the port was not expanded: %+v", bridge.Bridge.VLANs)
	}

	// Both families are on the interface: a snapshot that dropped the
	// second one would make every IPv6 plan offer to add what is there.
	uplink := snapshot.InterfaceByName("enp0s3")
	var six int
	for _, address := range uplink.Addresses {
		if address.Family == FamilyIPv6 {
			six++
		}
	}
	if six != 2 {
		t.Errorf("the IPv6 addresses of the uplink = %d: %+v", six, uplink.Addresses)
	}
	if !uplink.Management || snapshot.ManagementInterface != "enp0s3" {
		t.Errorf("the management channel was not marked: %+v", snapshot)
	}
}

func TestLinkStateReadsWhatTheHostHas(t *testing.T) {
	snapshot := layeredSnapshot(t)
	state := LinkStateOf(snapshot, "bond0")
	if !state.Present || state.Kind != LinkBond || state.Mode != "active-backup" {
		t.Errorf("the state of bond0: %+v", state)
	}
	if strings.Join(state.Members, ",") != "enp0s8,enp0s9" {
		t.Errorf("the members of the state: %+v", state.Members)
	}
	// An interface the host does not have is a state that is not present:
	// that is an answer, and it is how a creation is written down.
	if missing := LinkStateOf(snapshot, "bond9"); missing.Present {
		t.Errorf("an interface that is not there came back present: %+v", missing)
	}
}

// TestLayeredRefusalsAreNamed walks every relation that forbids a layered
// change.
func TestLayeredRefusalsAreNamed(t *testing.T) {
	snapshot := layeredSnapshot(t)

	cases := []struct {
		why  string
		spec LinkSpec
		code string
	}{
		{"a member another bond already owns",
			LinkSpec{Name: "bond1", Kind: LinkBond, Mode: "active-backup",
				Members: []string{"enp0s8", "enp0s10"}},
			CodeLinkMemberTaken},
		{"a member the host does not have",
			LinkSpec{Name: "bond1", Kind: LinkBond, Mode: "active-backup",
				Members: []string{"enp0s20", "enp0s21"}},
			CodeLinkMemberMissing},
		{"a bond of one member",
			LinkSpec{Name: "bond1", Kind: LinkBond, Mode: "active-backup",
				Members: []string{"enp0s20"}},
			CodeBondNeedsMembers},
		{"a VLAN on a parent that is not there",
			LinkSpec{Name: "vlan7", Kind: LinkVLAN, Parent: "enp0s99", VLANID: 7},
			CodeVLANParentMissing},
		{"a bridge that would swallow the management interface",
			LinkSpec{Name: "br1", Kind: LinkBridge, Members: []string{"enp0s3"}},
			CodeLinkSwallowsManagement},
		{"a bond that would swallow the management interface",
			LinkSpec{Name: "bond1", Kind: LinkBond, Mode: "active-backup",
				Members: []string{"enp0s3", "enp0s20"}},
			CodeLinkSwallowsManagement},
		{"a name the host uses for something else",
			LinkSpec{Name: "br0", Kind: LinkBond, Mode: "active-backup",
				Members: []string{"enp0s20", "enp0s21"}},
			CodeLinkKindMismatch},
		{"a VLAN on an interface another layer owns",
			LinkSpec{Name: "vlan7", Kind: LinkVLAN, Parent: "enp0s8", VLANID: 7},
			CodeLinkMemberTaken},
	}
	for _, tc := range cases {
		t.Run(tc.why, func(t *testing.T) {
			plan := ComputeLink(snapshot, AdapterNmstate, tc.spec)
			if plan.RefusalCode != tc.code {
				t.Fatalf("code = %q (%s), wanted %q", plan.RefusalCode, plan.Refusal, tc.code)
			}
			if plan.Refusal == "" || plan.PlanHash == "" {
				t.Errorf("a refusal without a reason or a fingerprint: %+v", plan)
			}
			if plan.DesiredLink != nil {
				t.Errorf("a refused plan still carries a desired state: %+v", plan.DesiredLink)
			}
		})
	}
}

func TestLayeredRemovalRefusals(t *testing.T) {
	snapshot := layeredSnapshot(t)

	// The bond carries a VLAN; removing it would take the VLAN with it.
	if plan := ComputeLinkRemoval(snapshot, AdapterNmstate, "bond0"); plan.RefusalCode != CodeLinkInUse {
		t.Errorf("removing a bond that carries a VLAN: %q (%s)", plan.RefusalCode, plan.Refusal)
	}
	// A plain network card is not a layer this panel built.
	if plan := ComputeLinkRemoval(snapshot, AdapterNmstate, "enp0s3"); plan.RefusalCode != CodeLinkNotLayered {
		t.Errorf("removing a plain interface: %q (%s)", plan.RefusalCode, plan.Refusal)
	}
	// A member of a layer goes out of that layer first.
	if plan := ComputeLinkRemoval(snapshot, AdapterNmstate, "enp0s10"); plan.RefusalCode == "" {
		t.Errorf("removing a bridge port passed without a refusal: %+v", plan)
	}
	// The VLAN itself has nothing standing on it and comes away.
	plan := ComputeLinkRemoval(snapshot, AdapterNmstate, "bond0.100")
	if plan.Refusal != "" || plan.Action != PlanUpdate || plan.DesiredLink.Present {
		t.Errorf("removing the VLAN: %+v", plan)
	}
	// An interface that is already gone is not a refusal: it is a change
	// with nothing left to do.
	if gone := ComputeLinkRemoval(snapshot, AdapterNmstate, "bond9"); gone.Action != PlanNoChange || gone.Refusal != "" {
		t.Errorf("removing an interface that is not there: %+v", gone)
	}
}

// TestManagementLayerIsNeverRemoved guards the one removal that has no way
// back: the layer the panel itself comes through.
func TestManagementLayerIsNeverRemoved(t *testing.T) {
	snapshot := layeredSnapshot(t)
	// Move the management channel onto the bridge and take its port away,
	// so that nothing but the management mark stands in the way.
	for i := range snapshot.Interfaces {
		snapshot.Interfaces[i].Management = snapshot.Interfaces[i].Name == "br0"
		if snapshot.Interfaces[i].Master == "br0" {
			snapshot.Interfaces[i].Master = ""
		}
	}
	snapshot.ManagementInterface = "br0"
	if plan := ComputeLinkRemoval(snapshot, AdapterNmstate, "br0"); plan.RefusalCode != CodeLinkCarriesManagement {
		t.Errorf("removing the management layer: %q (%s)", plan.RefusalCode, plan.Refusal)
	}
}

// TestMechanismThatCannotExpressALayerSaysSo is the difference between a
// refusal and half a bond: a host driven profile by profile is told no, rather
// than left with the first of the several profiles a bond needs.
func TestMechanismThatCannotExpressALayerSaysSo(t *testing.T) {
	snapshot := layeredSnapshot(t)
	spec := LinkSpec{Name: "bond1", Kind: LinkBond, Mode: "active-backup",
		Members: []string{"enp0s20", "enp0s21"}}
	plan := ComputeLink(snapshot, AdapterNetworkManager, spec)
	if plan.RefusalCode != CodeLinkMechanismUnsupported {
		t.Fatalf("NetworkManager alone: %q (%s)", plan.RefusalCode, plan.Refusal)
	}
	if plan := ComputeLink(snapshot, "", spec); plan.RefusalCode != CodeLinkMechanismUnsupported {
		t.Errorf("a host with no write mechanism: %q (%s)", plan.RefusalCode, plan.Refusal)
	}
	// The refusal comes before the relations are even looked at: there is
	// nothing to say about a member on a host nothing can be written to.
	if plan.Refusal == "" || plan.DesiredLink != nil {
		t.Errorf("the mechanism refusal: %+v", plan)
	}
}

func TestLinkSpecShapeIsRefusedBeforeTheHost(t *testing.T) {
	cases := []struct {
		why  string
		spec LinkSpec
	}{
		{"a kind the panel does not build", LinkSpec{Name: "tun0", Kind: "tunnel"}},
		{"a VLAN identifier outside the space",
			LinkSpec{Name: "vlan0", Kind: LinkVLAN, Parent: "enp0s8", VLANID: 5000}},
		{"a VLAN with members instead of a parent",
			LinkSpec{Name: "vlan0", Kind: LinkVLAN, Parent: "enp0s8", VLANID: 10, Members: []string{"enp0s9"}}},
		{"a bond mode the kernel does not know",
			LinkSpec{Name: "bond0", Kind: LinkBond, Mode: "round-robin", Members: []string{"a", "b"}}},
		{"an LACP rate on a mode that has none",
			LinkSpec{Name: "bond0", Kind: LinkBond, Mode: "active-backup",
				Members: []string{"a", "b"}, LACPRate: "fast"}},
		{"a primary member that is not a member",
			LinkSpec{Name: "bond0", Kind: LinkBond, Mode: "active-backup",
				Members: []string{"a", "b"}, Primary: "c"}},
		{"a member named twice",
			LinkSpec{Name: "bond0", Kind: LinkBond, Mode: "active-backup", Members: []string{"a", "a"}}},
		{"an interface that is a member of itself",
			LinkSpec{Name: "bond0", Kind: LinkBond, Mode: "active-backup", Members: []string{"bond0", "a"}}},
		{"a monitoring interval the driver would round to nothing",
			LinkSpec{Name: "bond0", Kind: LinkBond, Mode: "active-backup",
				Members: []string{"a", "b"}, MIIMonMS: 5}},
		{"a name the kernel would not take",
			LinkSpec{Name: "../etc", Kind: LinkBridge}},
	}
	for _, tc := range cases {
		t.Run(tc.why, func(t *testing.T) {
			if err := ValidateLinkSpec(tc.spec); err == nil {
				t.Errorf("%+v passed without a refusal", tc.spec)
			}
		})
	}
	// A bridge with no member is a legitimate thing to build: virtual
	// machines are attached to it afterwards.
	if err := ValidateLinkSpec(LinkSpec{Name: "br1", Kind: LinkBridge}); err != nil {
		t.Errorf("an empty bridge was refused: %v", err)
	}
}

func TestLayeredPlanDescribesWhatItBuilds(t *testing.T) {
	snapshot := layeredSnapshot(t)
	plan := ComputeLink(snapshot, AdapterNmstate, LinkSpec{
		Name: "bond1", Kind: LinkBond, Mode: "802.3ad", LACPRate: "fast",
		MIIMonMS: 100, Members: []string{"enp0s20", "enp0s21"},
	})
	if plan.Refusal == "" {
		t.Fatalf("members the host does not have passed: %+v", plan)
	}

	// The same bond on interfaces the host really has: the existing bond and its
	// VLAN are taken out of the picture and its members set free, which is the
	// host an operator building a first bond is looking at.
	taken := layeredSnapshot(t)
	var free Snapshot
	free.ManagementInterface = taken.ManagementInterface
	for _, iface := range taken.Interfaces {
		if iface.Name == "bond0" || iface.Name == "bond0.100" {
			continue
		}
		if iface.Master == "bond0" {
			iface.Master = ""
		}
		free.Interfaces = append(free.Interfaces, iface)
	}
	plan = ComputeLink(free, AdapterNmstate, LinkSpec{
		Name: "bond1", Kind: LinkBond, Mode: "802.3ad", LACPRate: "fast",
		MIIMonMS: 100, Members: []string{"enp0s8", "enp0s9"},
	})
	if plan.Refusal != "" || plan.Action != PlanUpdate {
		t.Fatalf("building a bond from free interfaces: %+v", plan)
	}
	if len(plan.Changes) == 0 || !strings.Contains(plan.Changes[0], "is created") {
		t.Errorf("the plan does not say what it builds: %+v", plan.Changes)
	}
	// The same order twice is no change: the plan compares the members as a
	// set, so their order in the list is not a difference.
	again := ComputeLink(snapshot, AdapterNmstate, LinkSpec{
		Name: "bond0", Kind: LinkBond, Mode: "active-backup", MIIMonMS: 100,
		Primary: "enp0s8", Members: []string{"enp0s9", "enp0s8"},
	})
	if again.Refusal != "" || again.Action != PlanNoChange {
		t.Errorf("the bond the host already has: %+v", again)
	}
	// A different order is a different fingerprint; the change the operator
	// approved is the one the host applies.
	changed := ComputeLink(snapshot, AdapterNmstate, LinkSpec{
		Name: "bond0", Kind: LinkBond, Mode: "active-backup", MIIMonMS: 500,
		Primary: "enp0s8", Members: []string{"enp0s9", "enp0s8"},
	})
	if changed.PlanHash == again.PlanHash {
		t.Error("two different layered changes share a fingerprint")
	}
}

func TestNmstateLinkDocumentCarriesTheLayer(t *testing.T) {
	document, err := NmstateLinkDocument(
		LinkState{Name: "bond1"},
		LinkState{Name: "bond1", Kind: LinkBond, Present: true, Mode: "802.3ad",
			Members: []string{"enp0s8", "enp0s9"}, MIIMonMS: 100, LACPRate: "fast"})
	if err != nil {
		t.Fatal(err)
	}
	for _, expected := range []string{"type: bond", "state: up", "mode: 802.3ad",
		"- enp0s8", "miimon: 100", "lacp_rate: fast"} {
		if !strings.Contains(document, expected) {
			t.Errorf("the bond document lacks %q:\n%s", expected, document)
		}
	}

	// A removal is the same call with a state that is not present, and it
	// is how the rollback document of a creation is produced as well.
	removal, err := NmstateLinkDocument(
		LinkState{Name: "bond1", Kind: LinkBond, Present: true}, LinkState{Name: "bond1"})
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(removal, "state: absent") {
		t.Errorf("the removal document:\n%s", removal)
	}

	// VLAN filtering is refused by name: nmstate expresses it through the VLAN
	// configuration of every bridge port, which this module does not write, and a
	// bridge built silently without it is not what was ordered.
	if _, err := NmstateLinkDocument(LinkState{Name: "br1"},
		LinkState{Name: "br1", Kind: LinkBridge, Present: true, VLANFiltering: true}); err == nil {
		t.Error("VLAN filtering passed without a refusal")
	}

	vlan, err := NmstateLinkDocument(LinkState{Name: "v100"},
		LinkState{Name: "v100", Kind: LinkVLAN, Present: true, Parent: "bond0", VLANID: 100})
	if err != nil {
		t.Fatal(err)
	}
	for _, expected := range []string{"type: vlan", "base-iface: bond0", "id: 100"} {
		if !strings.Contains(vlan, expected) {
			t.Errorf("the VLAN document lacks %q:\n%s", expected, vlan)
		}
	}
}

func TestNetplanLinkDocumentWritesItsOwnSection(t *testing.T) {
	config, err := ParseNetplan(netplanGetOutput)
	if err != nil {
		t.Fatal(err)
	}
	plan := Plan{
		Interface: "bond1", Operation: PlanLink,
		CurrentLink: &LinkState{Name: "bond1"},
		DesiredLink: &LinkState{Name: "bond1", Kind: LinkBond, Present: true,
			Mode: "active-backup", Members: []string{"enp0s8", "enp0s9"}, MIIMonMS: 100},
	}
	document, err := NetplanManagedLinkDocument("", config, plan)
	if err != nil {
		t.Fatal(err)
	}
	for _, expected := range []string{"bonds:", "bond1:", "- enp0s8", "mode: active-backup",
		"mii-monitor-interval: 100", "version: 2"} {
		if !strings.Contains(document, expected) {
			t.Errorf("the netplan bond document lacks %q:\n%s", expected, document)
		}
	}

	// Removing something the panel never defined is refused rather than
	// pretended: a later netplan file cannot unmake an earlier one's definition,
	// so the interface would be back after the next boot.
	removal := Plan{
		Interface: "bond1", Operation: PlanLinkRemove,
		CurrentLink: &LinkState{Name: "bond1", Kind: LinkBond, Present: true},
		DesiredLink: &LinkState{Name: "bond1"},
	}
	if _, err := NetplanManagedLinkDocument("", config, removal); err == nil {
		t.Error("removing an interface the panel never defined passed without a refusal")
	}

	// Removing one the panel did define takes the entry out of its file.
	back, err := NetplanManagedLinkDocument(document, config, removal)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(back, "bond1") {
		t.Errorf("the removal left the definition behind:\n%s", back)
	}
}

func TestIPv6SettingsAreReadAndCombined(t *testing.T) {
	dir := t.TempDir()
	write := func(iface, name, value string) {
		t.Helper()
		if err := os.MkdirAll(filepath.Join(dir, iface), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(dir, iface, name), []byte(value+"\n"), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	write("all", "disable_ipv6", "0")
	write("all", "accept_ra", "1")
	write("enp0s3", "disable_ipv6", "0")
	write("enp0s3", "use_tempaddr", "2")

	settings := CombineIPv6(ReadIPv6Settings(dir, "all"), ReadIPv6Settings(dir, "enp0s3"))
	if settings.Off() {
		t.Errorf("a host with IPv6 on came back off: %+v", settings)
	}
	// What the interface did not report is filled in from the host-wide
	// value; what it did report stays its own.
	if settings.AcceptRA == nil || *settings.AcceptRA != 1 {
		t.Errorf("accept_ra was not carried over: %+v", settings.AcceptRA)
	}
	if settings.Privacy == nil || *settings.Privacy != 2 {
		t.Errorf("use_tempaddr of the interface: %+v", settings.Privacy)
	}

	// The host-wide switch wins: the kernel refuses an address on an
	// interface whose "all" switch is set, whatever the interface says.
	write("all", "disable_ipv6", "1")
	if combined := CombineIPv6(ReadIPv6Settings(dir, "all"), ReadIPv6Settings(dir, "enp0s3")); !combined.Off() {
		t.Errorf("the host-wide switch was ignored: %+v", combined)
	}

	// An unread setting is unknown, never zero: a host whose sysctls could
	// not be read is not a host with IPv6 on.
	if unknown := ReadIPv6Settings(dir, "enp0s99"); unknown.Disabled != nil || unknown.Off() {
		t.Errorf("an unread interface: %+v", unknown)
	}
	// A kernel without IPv6 at all has no such directory, and that is a
	// definite "off" rather than an unread value.
	if off := HostIPv6Disabled(filepath.Join(dir, "nothing-here")); off == nil || !*off {
		t.Errorf("a kernel without IPv6: %+v", off)
	}
}

func TestIPv6PlanRefusesAHostWithTheFamilyOff(t *testing.T) {
	current := testProfile()
	off := true
	plan := ComputeProfile("eth1", current, ProfileRequest{
		Method6: "manual", Addresses6: []string{"2001:db8::5/64"},
	}, IPv6Settings{Disabled: &off})
	if plan.RefusalCode != CodeIPv6Disabled {
		t.Fatalf("an IPv6 order on a host with the family off: %q (%s)", plan.RefusalCode, plan.Refusal)
	}
	// An order about the first family alone is not refused by the second
	// family being off: the two are separate decisions.
	if first := ComputeProfile("eth1", current, ProfileRequest{
		Method: "manual", Addresses: []string{"192.168.56.61/24"},
	}, IPv6Settings{Disabled: &off}); first.Refusal != "" {
		t.Errorf("an IPv4 order was refused for IPv6 being off: %+v", first)
	}
}

func TestIPv6PlanCarriesBothFamilies(t *testing.T) {
	current := testProfile()
	plan := ComputeProfile("eth1", current, ProfileRequest{
		Method: "manual", Addresses: []string{"192.168.56.61/24"},
		Method6: "manual", Addresses6: []string{"2001:db8::5/64"},
		Gateway6: "fe80::1", AcceptRA: AcceptRAOff, Privacy: PrivacyPreferTemporary,
	}, IPv6Settings{})
	if plan.Refusal != "" || plan.Action != PlanUpdate {
		t.Fatalf("a dual-stack profile: %+v", plan)
	}
	if plan.Desired.Gateway6 != "fe80::1" {
		t.Errorf("the link-local gateway was dropped: %+v", plan.Desired)
	}
	// The two families are listed on their own lines: folding them into one
	// sentence would hide which family an address belongs to, and that is the one
	// thing an operator reading a dual-stack plan has to see.
	var sixth bool
	for _, change := range plan.Changes {
		if strings.HasPrefix(change, "IPv6") {
			sixth = true
		}
	}
	if !sixth {
		t.Errorf("the plan says nothing about the second family: %+v", plan.Changes)
	}
}

func TestRoutesAreSplitByFamily(t *testing.T) {
	v4, v6 := SplitRouteFamilies([]string{
		"10.8.0.0/24 192.168.56.1", "2001:db8:1::/48 fe80::1", "::/0 fe80::1"})
	if len(v4) != 1 || v4[0] != "10.8.0.0/24 192.168.56.1" {
		t.Errorf("the IPv4 routes: %+v", v4)
	}
	if len(v6) != 2 {
		t.Errorf("the IPv6 routes: %+v", v6)
	}
	// A route list that names both families reaches both: a v6 route
	// written into the v4 setting of a profile is dropped without a word.
	current := testProfile()
	plan := ComputeRoutes("eth1", current, []string{"10.8.0.0/24 192.168.56.1", "2001:db8:1::/48 fe80::1"})
	if plan.Refusal != "" {
		t.Fatalf("a dual-stack route list: %+v", plan)
	}
	if len(plan.Desired.Routes) != 1 || len(plan.Desired.Routes6) != 1 {
		t.Errorf("the routes were not split: %+v", plan.Desired)
	}
}

func TestBondStatusReadsWhatTheDriverKnows(t *testing.T) {
	// The shape /proc/net/bonding/bond0 really has.
	const status = `Ethernet Channel Bonding Driver: v5.15.0

Bonding Mode: fault-tolerance (active-backup)
Primary Slave: enp0s8 (primary_reselect always)
Currently Active Slave: enp0s9
MII Status: up
MII Polling Interval (ms): 100

Slave Interface: enp0s8
MII Status: down
Speed: Unknown

Slave Interface: enp0s9
MII Status: up
Speed: 1000 Mbps
`
	details := ParseBondStatus(status)
	if details.Mode != "active-backup" {
		t.Errorf("the driver's sentence was not turned into the kernel's word: %q", details.Mode)
	}
	if details.Primary != "enp0s8" || details.ActiveMember != "enp0s9" {
		t.Errorf("primary %q, active %q", details.Primary, details.ActiveMember)
	}
	// A bond whose active member is not its primary is a bond that failed
	// over, and that is what an operator looks at this page for.
	if details.MemberStates["enp0s8"] != "down" || details.MemberStates["enp0s9"] != "up" {
		t.Errorf("the member states: %+v", details.MemberStates)
	}
	if details.MIIMonMS != 100 {
		t.Errorf("the monitoring interval: %d", details.MIIMonMS)
	}
}
