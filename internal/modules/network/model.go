// Package network inventories the interfaces, addresses and routes of a
// host.
//
// The module reads the kernel state, not the configuration files: what the
// host really has up and what somebody once wrote into the configuration
// can drift apart - and the operator looking at the panel asks about the
// former.
package network

import "time"

// Address families.
const (
	FamilyIPv4 = "inet"
	FamilyIPv6 = "inet6"
)

// Address is one address assigned to an interface.
type Address struct {
	Family string `json:"family"`
	// Address is written together with the mask (10.0.2.15/24): the
	// address alone without the prefix does not say which network the host
	// considers local.
	Address string `json:"address"`
	Scope   string `json:"scope"`
	// Source says where the address comes from, as far as the kernel
	// reports it: a dynamic one from DHCP behaves differently from a static
	// one, and the operator is meant to see that before changing the
	// configuration.
	Source string `json:"source,omitempty"`
	// Permanent is false for addresses with a lifetime. An address that
	// vanishes in an hour is not the same as a permanent one.
	Permanent bool `json:"permanent"`
}

// Interface describes one network interface.
type Interface struct {
	Name  string `json:"name"`
	Index int    `json:"index"`
	// Kind distinguishes a physical interface from a bridge, veth or
	// tunnel: a host with docker has a dozen of them and only some mean
	// anything.
	Kind string `json:"kind,omitempty"`
	MAC  string `json:"mac,omitempty"`
	MTU  int    `json:"mtu"`
	// OperState is the state from the kernel (up, down, unknown). "unknown"
	// stays the word "unknown", because that is exactly how virtual
	// interfaces report.
	OperState string `json:"oper_state"`
	// Carrier tells about the carrier. Unknown stays unknown: no value is
	// not the same as no cable.
	Carrier *bool `json:"carrier,omitempty"`
	// SpeedMbps is reported by the kernel only for some drivers. Zero would
	// mean "a link with zero throughput", so unknown is a nil pointer.
	SpeedMbps *int      `json:"speed_mbps,omitempty"`
	Driver    string    `json:"driver,omitempty"`
	Addresses []Address `json:"addresses,omitempty"`
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
	// panel. The panel does not guess the address from the first position
	// of the list: it is the host that knows which interface its connection
	// went out through.
	ManagementInterface string `json:"management_interface,omitempty"`
	ManagementAddress   string `json:"management_address,omitempty"`
	// WriteAdapter names the mechanism the configuration can be changed
	// with. Empty means a host on which the panel can only read.
	WriteAdapter string    `json:"write_adapter,omitempty"`
	ObservedAt   time.Time `json:"observed_at"`
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
