// Package network inventories the interfaces, addresses and routes of a host.
package network

import "time"

// Address families.
const (
	FamilyIPv4 = "inet"
	FamilyIPv6 = "inet6"
)

// The layered interface kinds the module reads and writes. A layered interface
// is one that sits on other interfaces.
const (
	LinkBond   = "bond"
	LinkBridge = "bridge"
	LinkVLAN   = "vlan"
)

// BondDetails is what the host reports about a bond.
type BondDetails struct {
	Mode    string   `json:"mode,omitempty"`
	Members []string `json:"members,omitempty"`
	// MIIMonMS is the link monitoring interval in milliseconds.
	MIIMonMS int    `json:"miimon_ms"`
	Primary  string `json:"primary,omitempty"`
	// LACPRate and XmitHashPolicy mean something only for the modes that
	// use them; the host reports them as it has them.
	LACPRate       string `json:"lacp_rate,omitempty"`
	XmitHashPolicy string `json:"xmit_hash_policy,omitempty"`
	// ActiveMember is the member carrying the traffic, as /proc/net/bonding
	// reports it.
	ActiveMember string `json:"active_member,omitempty"`
	// MemberStates says what the bond thinks of each member (up, down). An absent
	// entry is not "down": it is a member the driver said nothing about.
	MemberStates map[string]string `json:"member_states,omitempty"`
}

// BridgePortVLAN is one VLAN of one port of a bridge, as "bridge vlan show"
// reports it.
type BridgePortVLAN struct {
	Port string `json:"port"`
	VID  int    `json:"vid"`
	// PVID marks the VLAN untagged frames of this port land in, Untagged the
	// VLANs leaving the port without a tag.
	PVID     bool `json:"pvid,omitempty"`
	Untagged bool `json:"untagged,omitempty"`
}

// BridgeDetails is what the host reports about a bridge.
type BridgeDetails struct {
	Members []string `json:"members,omitempty"`
	STP     bool     `json:"stp"`
	// VLANFiltering says whether the bridge separates VLANs at all. With it
	// off every port carries everything, whatever "bridge vlan show" lists.
	VLANFiltering bool             `json:"vlan_filtering"`
	VLANProtocol  string           `json:"vlan_protocol,omitempty"`
	VLANs         []BridgePortVLAN `json:"vlans,omitempty"`
}

// VLANDetails is what the host reports about a VLAN interface.
type VLANDetails struct {
	// Parent is the interface the tagged traffic runs on. A VLAN without a
	// parent is not a VLAN the host can carry.
	Parent   string `json:"parent,omitempty"`
	ID       int    `json:"id"`
	Protocol string `json:"protocol,omitempty"`
}

// IPv6Settings is what the kernel says about the second family on a link.
type IPv6Settings struct {
	// Disabled is disable_ipv6: with it set the interface has no second
	// family at all and an IPv6 address written to it goes into the void.
	Disabled *bool `json:"disabled,omitempty"`
	// AcceptRA is accept_ra: 0 ignores router advertisements, 1 takes them
	// when the host does not forward, 2 takes them even when it does.
	AcceptRA *int `json:"accept_ra,omitempty"`
	// Privacy is use_tempaddr: 0 off, 1 generates temporary addresses, 2
	// prefers them for outgoing connections.
	Privacy *int `json:"privacy,omitempty"`
}

// Address is one address assigned to an interface.
type Address struct {
	Family string `json:"family"`
	// Address is written together with the mask (10. 0. 2.
	Address string `json:"address"`
	Scope   string `json:"scope"`
	// Source says where the address comes from, as far as the kernel reports it:
	// a dynamic one from DHCP behaves differently from a static one, and the
	// operator is meant to see that before changing the configuration.
	Source string `json:"source,omitempty"`
	// Permanent is false for addresses with a lifetime. An address that
	// vanishes in an hour is not the same as a permanent one.
	Permanent bool `json:"permanent"`
}

// Interface describes one network interface.
type Interface struct {
	Name  string `json:"name"`
	Index int    `json:"index"`
	// Kind distinguishes a physical interface from a bridge, veth or tunnel: a
	// host with docker has a dozen of them and only some mean anything.
	Kind string `json:"kind,omitempty"`
	MAC  string `json:"mac,omitempty"`
	MTU  int    `json:"mtu"`
	// OperState is the state from the kernel (up, down, unknown). "unknown" stays
	// the word "unknown", because that is exactly how virtual interfaces report.
	OperState string `json:"oper_state"`
	// Carrier tells about the carrier. Unknown stays unknown: no value is
	// not the same as no cable.
	Carrier *bool `json:"carrier,omitempty"`
	// SpeedMbps is reported by the kernel only for some drivers. Zero would
	// mean "a link with zero throughput", so unknown is a nil pointer.
	SpeedMbps *int      `json:"speed_mbps,omitempty"`
	Driver    string    `json:"driver,omitempty"`
	Addresses []Address `json:"addresses,omitempty"`
	// Master names the layer that owns this interface: the bond or the bridge it
	// was enslaved to.
	Master string `json:"master,omitempty"`
	// Bond, Bridge and VLAN describe the layering where this interface is
	// one of them. At most one is set; a plain link has none.
	Bond   *BondDetails   `json:"bond,omitempty"`
	Bridge *BridgeDetails `json:"bridge,omitempty"`
	VLAN   *VLANDetails   `json:"vlan,omitempty"`
	// IPv6 carries the kernel settings of the second family. Unknown stays
	// unknown: a host whose sysctls could not be read is not a host with IPv6 on.
	IPv6 *IPv6Settings `json:"ipv6,omitempty"`
	// Management marks the interface the host talks to the panel through.
	// Changing exactly this interface is changing the branch we sit on.
	Management bool `json:"management"`
}

// Route is one route from the routing table.
type Route struct {
	// Destination "default" is written as the kernel reports it.
	Destination string `json:"destination"`
	Gateway     string `json:"gateway,omitempty"`
	Interface   string `json:"interface,omitempty"`
	Source      string `json:"source,omitempty"`
	// Protocol says who created the route (kernel, dhcp, static, ra).
	Protocol string `json:"protocol,omitempty"`
	Scope    string `json:"scope,omitempty"`
	Metric   int    `json:"metric"`
	Family   string `json:"family"`
	Table    string `json:"table,omitempty"`
}

// Snapshot is the picture of the host network at one moment.
type Snapshot struct {
	Interfaces []Interface `json:"interfaces"`
	Routes     []Route     `json:"routes"`
	// ManagementInterface and ManagementAddress describe the channel to the
	// panel.
	ManagementInterface string `json:"management_interface,omitempty"`
	ManagementAddress   string `json:"management_address,omitempty"`
	// WriteAdapter names the mechanism the configuration can be changed
	// with. Empty means a host on which the panel can only read.
	WriteAdapter string `json:"write_adapter,omitempty"`
	// IPv6Disabled says the host turned the second family off for every interface
	// at once, or that the kernel has no IPv6 at all.
	IPv6Disabled *bool `json:"ipv6_disabled,omitempty"`
	// LayeringUnavailableReason says why the bonds, the bridges and the VLANs
	// could not be read.
	LayeringUnavailableReason string    `json:"layering_unavailable_reason,omitempty"`
	ObservedAt                time.Time `json:"observed_at"`
	// UnavailableReason says why the state could not be determined.
	UnavailableReason string `json:"unavailable_reason,omitempty"`
}

// InterfaceByName returns the interface with the given name or nil.
func (s Snapshot) InterfaceByName(name string) *Interface {
	for i := range s.Interfaces {
		if s.Interfaces[i].Name == name {
			return &s.Interfaces[i]
		}
	}
	return nil
}

// MembersOf lists the interfaces the given layer owns, in the order the host
// reported them.
func (s Snapshot) MembersOf(name string) []string {
	var members []string
	for i := range s.Interfaces {
		if s.Interfaces[i].Master == name {
			members = append(members, s.Interfaces[i].Name)
		}
	}
	return members
}

// VLANsOn lists the VLAN interfaces whose parent is the given interface.
func (s Snapshot) VLANsOn(parent string) []string {
	var vlans []string
	for i := range s.Interfaces {
		if s.Interfaces[i].VLAN != nil && s.Interfaces[i].VLAN.Parent == parent {
			vlans = append(vlans, s.Interfaces[i].Name)
		}
	}
	return vlans
}

// LayerKind names the layered kind of an interface, or an empty string for a
// link that is not one.
func (i Interface) LayerKind() string {
	switch {
	case i.Bond != nil:
		return LinkBond
	case i.Bridge != nil:
		return LinkBridge
	case i.VLAN != nil:
		return LinkVLAN
	}
	switch i.Kind {
	case LinkBond, LinkBridge, LinkVLAN:
		return i.Kind
	}
	return ""
}
