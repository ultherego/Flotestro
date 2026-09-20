package network

import (
	"fmt"
	"strconv"
	"strings"

	"gopkg.in/yaml.v3"
)

// The nmstate tool. Distributions put it in one of two places; the path is
// picked from the two, not searched in PATH.
const (
	NmstatectlPath    = "/usr/bin/nmstatectl"
	NmstatectlPathAlt = "/usr/sbin/nmstatectl"
)

// NmstatectlBinary returns the nmstate tool present on the host or an empty
// string.
func NmstatectlBinary(exists func(string) bool) string {
	for _, path := range []string{NmstatectlPath, NmstatectlPathAlt} {
		if exists(path) {
			return path
		}
	}
	return ""
}

// The wildcard destinations nmstate uses for the default route.
const (
	defaultRouteIPv4 = "0.0.0.0/0"
	defaultRouteIPv6 = "::/0"
)

// NmstateState is the part of "nmstatectl show" the panel reads: the
// interfaces with their IPv4 settings, the configured routes and the resolver.
type NmstateState struct {
	Interfaces []NmstateInterface `yaml:"interfaces" json:"interfaces"`
	Routes     struct {
		Config []NmstateRoute `yaml:"config" json:"config"`
	} `yaml:"routes" json:"routes"`
	DNS struct {
		Config NmstateDNS `yaml:"config" json:"config"`
	} `yaml:"dns-resolver" json:"dns-resolver"`
}

// NmstateInterface is one interface of the nmstate state.
type NmstateInterface struct {
	Name  string           `yaml:"name" json:"name"`
	Type  string           `yaml:"type" json:"type"`
	State string           `yaml:"state" json:"state"`
	MTU   int              `yaml:"mtu" json:"mtu"`
	IPv4  *NmstateIPFamily `yaml:"ipv4" json:"ipv4"`
	// IPv6 is read exactly like IPv4: a host with a static IPv6 address and
	// nothing read about it looks like a host without one, and the plan would
	// then offer to "add" an address the host already has.
	IPv6 *NmstateIPFamily `yaml:"ipv6" json:"ipv6"`
}

// NmstateIPFamily is one address family of an nmstate interface.
type NmstateIPFamily struct {
	Enabled  bool  `yaml:"enabled" json:"enabled"`
	DHCP     *bool `yaml:"dhcp" json:"dhcp"`
	Autoconf *bool `yaml:"autoconf" json:"autoconf"`
	AutoDNS  *bool `yaml:"auto-dns" json:"auto-dns"`
	Address  []struct {
		IP           string `yaml:"ip" json:"ip"`
		PrefixLength int    `yaml:"prefix-length" json:"prefix-length"`
	} `yaml:"address" json:"address"`
}

// NmstateRoute is one configured route.
type NmstateRoute struct {
	Destination      string `yaml:"destination" json:"destination"`
	NextHopAddress   string `yaml:"next-hop-address" json:"next-hop-address"`
	NextHopInterface string `yaml:"next-hop-interface" json:"next-hop-interface"`
}

// NmstateDNS is the configured resolver. nmstate keeps it globally, not per
// interface.
type NmstateDNS struct {
	Server []string `yaml:"server" json:"server"`
	Search []string `yaml:"search" json:"search"`
}

// ParseNmstateState reads the output of "nmstatectl show" in either of its
// forms: YAML or, with --json, JSON.
func ParseNmstateState(output []byte) (NmstateState, error) {
	var state NmstateState
	if err := yaml.Unmarshal(output, &state); err != nil {
		return NmstateState{}, fmt.Errorf("reading the nmstate state: %w", err)
	}
	return state, nil
}

// Profiles turns the nmstate state into the profiles the panel compares
// against.
func (s NmstateState) Profiles() []Profile {
	var profiles []Profile
	for _, iface := range s.Interfaces {
		if iface.Type == "loopback" || iface.Name == "lo" {
			continue
		}
		profiles = append(profiles, s.profileOf(iface))
	}
	return profiles
}

// Profile returns the profile of one interface. An interface nmstate does
// not describe is a refusal: the panel does not create new interfaces.
func (s NmstateState) Profile(name string) (Profile, error) {
	for _, iface := range s.Interfaces {
		if iface.Name == name {
			return s.profileOf(iface), nil
		}
	}
	return Profile{}, fmt.Errorf("the interface %s is not described by nmstate; the panel does not create new interfaces here", name)
}

func (s NmstateState) profileOf(iface NmstateInterface) Profile {
	profile := Profile{
		Connection: iface.Name, Interface: iface.Name, Type: iface.Type,
		Method: "disabled",
	}
	if iface.MTU > 0 {
		profile.MTU = strconv.Itoa(iface.MTU)
	}
	if ipv4 := iface.IPv4; ipv4 != nil && ipv4.Enabled {
		profile.Method = "manual"
		if ipv4.DHCP != nil && *ipv4.DHCP {
			profile.Method = "auto"
			profile.IgnoreAutoDNS = ipv4.AutoDNS != nil && !*ipv4.AutoDNS
		}
		for _, address := range ipv4.Address {
			if strings.Contains(address.IP, ":") {
				continue
			}
			profile.Addresses = append(profile.Addresses,
				address.IP+"/"+strconv.Itoa(address.PrefixLength))
		}
		// An enabled IPv4 without DHCP and without an address is not manual in any
		// useful sense; it stays "manual" so the difference is visible rather than
		// papered over.
	}
	if ipv6 := iface.IPv6; ipv6 != nil {
		profile.Method6 = "disabled"
		if ipv6.Enabled {
			profile.Method6 = "manual"
			if ipv6.DHCP != nil && *ipv6.DHCP {
				profile.Method6 = "auto"
			}
			for _, address := range ipv6.Address {
				if !strings.Contains(address.IP, ":") {
					continue
				}
				profile.Addresses6 = append(profile.Addresses6,
					address.IP+"/"+strconv.Itoa(address.PrefixLength))
			}
		}
		if ipv6.Autoconf != nil {
			profile.AcceptRA = AcceptRAOff
			if *ipv6.Autoconf {
				profile.AcceptRA = AcceptRAOn
			}
		}
	}
	for _, route := range s.Routes.Config {
		if route.NextHopInterface != iface.Name {
			continue
		}
		if isIPv6Route(route) {
			if route.Destination == defaultRouteIPv6 {
				profile.Gateway6 = route.NextHopAddress
				continue
			}
			entry := route.Destination
			if route.NextHopAddress != "" {
				entry += " " + route.NextHopAddress
			}
			profile.Routes6 = append(profile.Routes6, entry)
			continue
		}
		if route.Destination == defaultRouteIPv4 {
			profile.Gateway = route.NextHopAddress
			continue
		}
		entry := route.Destination
		if route.NextHopAddress != "" {
			entry += " " + route.NextHopAddress
		}
		profile.Routes = append(profile.Routes, entry)
	}
	// The resolver is global in nmstate. It is shown on every profile, so
	// the operator sees on any interface what the host resolves with.
	profile.DNS = append([]string(nil), s.DNS.Config.Server...)
	profile.DNSSearch = append([]string(nil), s.DNS.Config.Search...)
	return profile
}

func isIPv6Route(route NmstateRoute) bool {
	return strings.Contains(route.Destination, ":") || strings.Contains(route.NextHopAddress, ":")
}

// The nmstate document the panel writes.
type nmstateDocument struct {
	Interfaces []nmstateInterfaceDoc `yaml:"interfaces,omitempty"`
	Routes     *nmstateRoutesDoc     `yaml:"routes,omitempty"`
	DNS        *nmstateDNSDoc        `yaml:"dns-resolver,omitempty"`
}

type nmstateInterfaceDoc struct {
	Name string `yaml:"name"`
	Type string `yaml:"type,omitempty"`
	// State carries "up" for an interface being built and "absent" for one being
	// taken away.
	State string        `yaml:"state,omitempty"`
	MTU   int           `yaml:"mtu,omitempty"`
	IPv4  *nmstateIPDoc `yaml:"ipv4,omitempty"`
	IPv6  *nmstateIPDoc `yaml:"ipv6,omitempty"`
	// The layering. Exactly one of them is written, for the kind of layer
	// the change builds.
	LinkAggregation *nmstateBondDoc   `yaml:"link-aggregation,omitempty"`
	Bridge          *nmstateBridgeDoc `yaml:"bridge,omitempty"`
	VLAN            *nmstateVLANDoc   `yaml:"vlan,omitempty"`
}

// nmstateIPDoc is one address family.
type nmstateIPDoc struct {
	Enabled  bool                `yaml:"enabled"`
	DHCP     *bool               `yaml:"dhcp,omitempty"`
	Autoconf *bool               `yaml:"autoconf,omitempty"`
	AutoDNS  *bool               `yaml:"auto-dns,omitempty"`
	Address  []nmstateAddressDoc `yaml:"address,omitempty"`
}

// nmstateBondDoc is the link aggregation section. The members are written
// under "port", which is what nmstate calls them.
type nmstateBondDoc struct {
	Mode    string              `yaml:"mode"`
	Port    []string            `yaml:"port"`
	Options *nmstateBondOptions `yaml:"options,omitempty"`
}

type nmstateBondOptions struct {
	MIIMon   int    `yaml:"miimon"`
	Primary  string `yaml:"primary,omitempty"`
	LACPRate string `yaml:"lacp_rate,omitempty"`
}

// nmstateBridgeDoc is the Linux bridge section. Only what the panel writes
// is here: the ports and the spanning tree.
type nmstateBridgeDoc struct {
	Options *nmstateBridgeOptions `yaml:"options,omitempty"`
	Port    []nmstateBridgePort   `yaml:"port"`
}

type nmstateBridgeOptions struct {
	STP nmstateSTPDoc `yaml:"stp"`
}

type nmstateSTPDoc struct {
	Enabled bool `yaml:"enabled"`
}

type nmstateBridgePort struct {
	Name string `yaml:"name"`
}

type nmstateVLANDoc struct {
	BaseIface string `yaml:"base-iface"`
	ID        int    `yaml:"id"`
	Protocol  string `yaml:"protocol,omitempty"`
}

type nmstateAddressDoc struct {
	IP           string `yaml:"ip"`
	PrefixLength int    `yaml:"prefix-length"`
}

type nmstateRoutesDoc struct {
	Config []nmstateRouteDoc `yaml:"config"`
}

type nmstateRouteDoc struct {
	Destination      string `yaml:"destination,omitempty"`
	NextHopAddress   string `yaml:"next-hop-address,omitempty"`
	NextHopInterface string `yaml:"next-hop-interface"`
	State            string `yaml:"state,omitempty"`
}

type nmstateDNSDoc struct {
	Config nmstateDNSConfigDoc `yaml:"config"`
}

type nmstateDNSConfigDoc struct {
	Server []string `yaml:"server"`
	Search []string `yaml:"search"`
}

// NmstateDocument assembles the minimal nmstate document that carries the
// interface from the current profile to the desired one.
func NmstateDocument(kind string, current, desired Profile) (string, error) {
	if current.Connection == "" {
		return "", fmt.Errorf("nmstate document without an interface name")
	}
	if err := ValidateInterfaceName(current.Connection); err != nil {
		return "", err
	}
	iface := nmstateInterfaceDoc{Name: current.Connection, Type: current.Type}
	document := nmstateDocument{}

	switch kind {
	case PlanMTU:
		mtu, err := nmstateMTU(desired.MTU)
		if err != nil {
			return "", err
		}
		iface.MTU = mtu

	case PlanRoutes:
		for _, route := range append(append([]string(nil), desired.Routes...), desired.Routes6...) {
			if err := ValidateRoute(route); err != nil {
				return "", err
			}
		}
		// Both families go in one document, so the routes of the family the order
		// did not touch have to be carried over rather than dropped.
		entries := routeEntries(current.Connection, current.Routes, desired.Routes)
		entries = append(entries, routeEntries(current.Connection, current.Routes6, desired.Routes6)...)
		document.Routes = &nmstateRoutesDoc{Config: entries}

	case PlanProfile:
		ipv4, err := nmstateIPv4(desired)
		if err != nil {
			return "", err
		}
		iface.IPv4 = ipv4
		ipv6, err := nmstateIPv6(desired)
		if err != nil {
			return "", err
		}
		iface.IPv6 = ipv6
		var routes []nmstateRouteDoc
		if current.Gateway != desired.Gateway {
			if desired.Gateway != "" {
				if err := ValidateIPAddress(desired.Gateway); err != nil {
					return "", fmt.Errorf("gateway: %w", err)
				}
			}
			routes = append(routes, gatewayEntries(current.Connection, defaultRouteIPv4,
				current.Gateway, desired.Gateway)...)
		}
		if current.Gateway6 != desired.Gateway6 {
			if desired.Gateway6 != "" {
				if err := ValidateIPv6Gateway(desired.Gateway6); err != nil {
					return "", fmt.Errorf("IPv6 gateway: %w", err)
				}
			}
			routes = append(routes, gatewayEntries(current.Connection, defaultRouteIPv6,
				current.Gateway6, desired.Gateway6)...)
		}
		if len(routes) > 0 {
			document.Routes = &nmstateRoutesDoc{Config: routes}
		}
		if !sameSet(current.DNS, desired.DNS) {
			for _, server := range desired.DNS {
				if err := ValidateIPAddress(server); err != nil {
					return "", fmt.Errorf("DNS server: %w", err)
				}
			}
			document.DNS = &nmstateDNSDoc{Config: nmstateDNSConfigDoc{
				Server: nonNil(desired.DNS), Search: nonNil(desired.DNSSearch)}}
		}

	case PlanDNS:
		for _, server := range desired.DNS {
			if err := ValidateIPAddress(server); err != nil {
				return "", fmt.Errorf("DNS server: %w", err)
			}
		}
		document.DNS = &nmstateDNSDoc{Config: nmstateDNSConfigDoc{
			Server: nonNil(desired.DNS), Search: nonNil(desired.DNSSearch)}}
		if current.IgnoreAutoDNS != desired.IgnoreAutoDNS && current.Method == "auto" {
			autoDNS := !desired.IgnoreAutoDNS
			iface.IPv4 = &nmstateIPDoc{Enabled: true, AutoDNS: &autoDNS}
		}

	default:
		return "", fmt.Errorf("unknown change kind %q", kind)
	}

	// The interface entry goes in only when it carries something: a bare
	// name would be a no-op nmstate still has to verify.
	if iface.MTU != 0 || iface.IPv4 != nil || iface.IPv6 != nil {
		document.Interfaces = []nmstateInterfaceDoc{iface}
	}
	encoded, err := yaml.Marshal(document)
	if err != nil {
		return "", err
	}
	return string(encoded), nil
}

// nmstateMTU turns the MTU text into a number.
func nmstateMTU(mtu string) (int, error) {
	if err := ValidateMTU(mtu); err != nil {
		return 0, err
	}
	if mtu == MTUAuto {
		return 0, fmt.Errorf("nmstate needs a numeric MTU; \"auto\" is a NetworkManager value")
	}
	return strconv.Atoi(mtu)
}

// nmstateIPv4 turns the method and the addresses of a profile into the IPv4
// section.
func nmstateIPv4(profile Profile) (*nmstateIPDoc, error) {
	for _, address := range profile.Addresses {
		if err := ValidateAddress(address); err != nil {
			return nil, err
		}
	}
	yes, no := true, false
	switch profile.Method {
	case "auto":
		ipv4 := &nmstateIPDoc{Enabled: true, DHCP: &yes}
		if profile.IgnoreAutoDNS {
			ipv4.AutoDNS = &no
		}
		return ipv4, nil
	case "manual":
		if len(profile.Addresses) == 0 {
			return nil, fmt.Errorf("the manual method requires at least one address")
		}
		ipv4 := &nmstateIPDoc{Enabled: true, DHCP: &no}
		for _, address := range profile.Addresses {
			ip, prefix, _ := strings.Cut(address, "/")
			length, _ := strconv.Atoi(prefix)
			ipv4.Address = append(ipv4.Address, nmstateAddressDoc{IP: ip, PrefixLength: length})
		}
		return ipv4, nil
	case "disabled":
		return &nmstateIPDoc{Enabled: false}, nil
	}
	return nil, fmt.Errorf("nmstate cannot express the method %q", profile.Method)
}

// routeEntries removes the routes the interface has and adds the desired ones.
func routeEntries(iface string, current, desired []string) []nmstateRouteDoc {
	entries := []nmstateRouteDoc{}
	for _, route := range current {
		fields := strings.Fields(route)
		if len(fields) == 0 {
			continue
		}
		entries = append(entries, nmstateRouteDoc{
			Destination: fields[0], NextHopInterface: iface, State: "absent"})
	}
	for _, route := range desired {
		fields := strings.Fields(route)
		entry := nmstateRouteDoc{Destination: fields[0], NextHopInterface: iface}
		if len(fields) == 2 {
			entry.NextHopAddress = fields[1]
		}
		entries = append(entries, entry)
	}
	return entries
}

// gatewayEntries replaces the default route of the interface in one family.
func gatewayEntries(iface, destination, current, desired string) []nmstateRouteDoc {
	entries := []nmstateRouteDoc{}
	if current != "" {
		entries = append(entries, nmstateRouteDoc{
			Destination: destination, NextHopInterface: iface, State: "absent"})
	}
	if desired != "" {
		entries = append(entries, nmstateRouteDoc{
			Destination: destination, NextHopAddress: desired, NextHopInterface: iface})
	}
	return entries
}

// nmstateIPv6 turns the second family of a profile into the ipv6 section.
func nmstateIPv6(profile Profile) (*nmstateIPDoc, error) {
	if profile.Method6 == "" && profile.AcceptRA == "" && profile.Privacy == "" {
		return nil, nil
	}
	if profile.Privacy != "" {
		return nil, fmt.Errorf("nmstate does not express the IPv6 privacy extensions; this host cannot be told so through nmstate")
	}
	for _, address := range profile.Addresses6 {
		if err := ValidateIPv6Address(address); err != nil {
			return nil, err
		}
	}
	yes, no := true, false
	var autoconf *bool
	switch profile.AcceptRA {
	case AcceptRAOff:
		autoconf = &no
	case AcceptRAOn, AcceptRAForwarding:
		autoconf = &yes
	case "":
	default:
		return nil, fmt.Errorf("unsupported router advertisement setting %q", profile.AcceptRA)
	}
	switch profile.Method6 {
	case "":
		// Only the router advertisements were ordered: the family stays as
		// it is and just that one switch moves.
		return &nmstateIPDoc{Enabled: true, Autoconf: autoconf}, nil
	case "auto":
		ipv6 := &nmstateIPDoc{Enabled: true, DHCP: &yes, Autoconf: &yes}
		if autoconf != nil {
			ipv6.Autoconf = autoconf
		}
		if profile.IgnoreAutoDNS {
			ipv6.AutoDNS = &no
		}
		return ipv6, nil
	case "manual":
		if len(profile.Addresses6) == 0 {
			return nil, fmt.Errorf("the manual IPv6 method requires at least one address")
		}
		ipv6 := &nmstateIPDoc{Enabled: true, DHCP: &no, Autoconf: &no}
		if autoconf != nil {
			ipv6.Autoconf = autoconf
		}
		for _, address := range profile.Addresses6 {
			ip, prefix, _ := strings.Cut(address, "/")
			length, _ := strconv.Atoi(prefix)
			ipv6.Address = append(ipv6.Address, nmstateAddressDoc{IP: ip, PrefixLength: length})
		}
		return ipv6, nil
	case "disabled":
		return &nmstateIPDoc{Enabled: false}, nil
	}
	return nil, fmt.Errorf("nmstate cannot express the IPv6 method %q", profile.Method6)
}

// NmstateLinkDocument assembles the document that carries a layered interface
// from the state the host has to the one ordered.
func NmstateLinkDocument(current, desired LinkState) (string, error) {
	target := desired
	if !desired.Present {
		// A removal names the interface that is going, not the one that
		// would replace it: its kind is what the host has.
		target = current
		target.Present = false
	}
	if err := ValidateInterfaceName(target.Name); err != nil {
		return "", err
	}
	iface := nmstateInterfaceDoc{Name: target.Name}
	if !desired.Present {
		iface.State = "absent"
		encoded, err := yaml.Marshal(nmstateDocument{Interfaces: []nmstateInterfaceDoc{iface}})
		if err != nil {
			return "", err
		}
		return string(encoded), nil
	}
	iface.State = "up"
	if target.MTU != "" && target.MTU != MTUAuto {
		mtu, err := nmstateMTU(target.MTU)
		if err != nil {
			return "", err
		}
		iface.MTU = mtu
	}
	switch target.Kind {
	case LinkBond:
		iface.Type = "bond"
		iface.LinkAggregation = &nmstateBondDoc{
			Mode: target.Mode, Port: nonNil(target.Members),
			Options: &nmstateBondOptions{
				MIIMon: target.MIIMonMS, Primary: target.Primary, LACPRate: target.LACPRate},
		}
	case LinkBridge:
		if target.VLANFiltering {
			return "", fmt.Errorf("nmstate expresses VLAN filtering through the VLAN configuration of every bridge port, which this module does not write; build the bridge without it")
		}
		iface.Type = "linux-bridge"
		ports := []nmstateBridgePort{}
		for _, member := range target.Members {
			ports = append(ports, nmstateBridgePort{Name: member})
		}
		iface.Bridge = &nmstateBridgeDoc{
			Options: &nmstateBridgeOptions{STP: nmstateSTPDoc{Enabled: target.STP}},
			Port:    ports,
		}
	case LinkVLAN:
		iface.Type = "vlan"
		iface.VLAN = &nmstateVLANDoc{
			BaseIface: target.Parent, ID: target.VLANID, Protocol: nmstateVLANProtocol(target.Protocol)}
	default:
		return "", fmt.Errorf("nmstate cannot build a layer of the kind %q", target.Kind)
	}
	encoded, err := yaml.Marshal(nmstateDocument{Interfaces: []nmstateInterfaceDoc{iface}})
	if err != nil {
		return "", err
	}
	return string(encoded), nil
}

// nmstateVLANProtocol writes the protocol the way nmstate spells it: in
// lower case, and left out where the order did not name one.
func nmstateVLANProtocol(protocol string) string {
	return strings.ToLower(protocol)
}

func nonNil(items []string) []string {
	if items == nil {
		return []string{}
	}
	return items
}

// NmstateApplyArguments applies a document under nmstate's own checkpoint.
func NmstateApplyArguments(binary, file string, timeoutSeconds int) []string {
	return []string{binary, "apply", "--no-commit", "--timeout", strconv.Itoa(timeoutSeconds), file}
}

// NmstateCommitArguments keeps the change after the panel confirmed
// connectivity.
func NmstateCommitArguments(binary string) []string {
	return []string{binary, "commit"}
}

// NmstateRollbackArguments returns to the checkpoint while it is still
// open.
func NmstateRollbackArguments(binary string) []string {
	return []string{binary, "rollback"}
}

// NmstateRestoreArguments applies the state from before the change when
// the checkpoint is no longer there to roll back to.
func NmstateRestoreArguments(binary, previousStateFile string) []string {
	return []string{binary, "apply", previousStateFile}
}

// NmstateShowArguments reads the whole state as JSON.
func NmstateShowArguments(binary string) []string {
	return []string{binary, "show", "--json"}
}
