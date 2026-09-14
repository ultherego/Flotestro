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
// interfaces with their IPv4 settings, the configured routes and the
// resolver. nmstate describes a desired state, so the read and the write
// speak the same language - only the write carries just the touched
// interface.
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
	Name  string `yaml:"name" json:"name"`
	Type  string `yaml:"type" json:"type"`
	State string `yaml:"state" json:"state"`
	MTU   int    `yaml:"mtu" json:"mtu"`
	IPv4  *struct {
		Enabled bool  `yaml:"enabled" json:"enabled"`
		DHCP    *bool `yaml:"dhcp" json:"dhcp"`
		AutoDNS *bool `yaml:"auto-dns" json:"auto-dns"`
		Address []struct {
			IP           string `yaml:"ip" json:"ip"`
			PrefixLength int    `yaml:"prefix-length" json:"prefix-length"`
		} `yaml:"address" json:"address"`
	} `yaml:"ipv4" json:"ipv4"`
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
// forms: YAML or, with --json, JSON. JSON is a YAML document too, so one
// reader covers both.
func ParseNmstateState(output []byte) (NmstateState, error) {
	var state NmstateState
	if err := yaml.Unmarshal(output, &state); err != nil {
		return NmstateState{}, fmt.Errorf("reading the nmstate state: %w", err)
	}
	return state, nil
}

// Profiles turns the nmstate state into the profiles the panel compares
// against. The loopback is left out: nothing about it is the operator's
// decision.
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
		// An enabled IPv4 without DHCP and without an address is not manual
		// in any useful sense; it stays "manual" so the difference is
		// visible rather than papered over.
	}
	for _, route := range s.Routes.Config {
		if route.NextHopInterface != iface.Name || isIPv6Route(route) {
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

// The nmstate document the panel writes. Only the touched interface and
// only the sections the change concerns: nmstate merges a partial document
// into the running state, so everything left out stays as it is.
type nmstateDocument struct {
	Interfaces []nmstateInterfaceDoc `yaml:"interfaces,omitempty"`
	Routes     *nmstateRoutesDoc     `yaml:"routes,omitempty"`
	DNS        *nmstateDNSDoc        `yaml:"dns-resolver,omitempty"`
}

type nmstateInterfaceDoc struct {
	Name string          `yaml:"name"`
	Type string          `yaml:"type,omitempty"`
	MTU  int             `yaml:"mtu,omitempty"`
	IPv4 *nmstateIPv4Doc `yaml:"ipv4,omitempty"`
}

type nmstateIPv4Doc struct {
	Enabled bool                `yaml:"enabled"`
	DHCP    *bool               `yaml:"dhcp,omitempty"`
	AutoDNS *bool               `yaml:"auto-dns,omitempty"`
	Address []nmstateAddressDoc `yaml:"address,omitempty"`
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
//
// The kind says which sections go in: an MTU change carries the MTU alone,
// a route change the routes alone. The rollback document is the same
// function called the other way round - the same code assembles both, so
// the plan cannot express a state this module does not know.
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
		for _, route := range desired.Routes {
			if err := ValidateRoute(route); err != nil {
				return "", err
			}
		}
		document.Routes = &nmstateRoutesDoc{Config: routeEntries(current.Connection, current.Routes, desired.Routes)}

	case PlanProfile:
		ipv4, err := nmstateIPv4(desired)
		if err != nil {
			return "", err
		}
		iface.IPv4 = ipv4
		if current.Gateway != desired.Gateway {
			if desired.Gateway != "" {
				if err := ValidateIPAddress(desired.Gateway); err != nil {
					return "", fmt.Errorf("gateway: %w", err)
				}
			}
			document.Routes = &nmstateRoutesDoc{Config: gatewayEntries(current.Connection, current.Gateway, desired.Gateway)}
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
			iface.IPv4 = &nmstateIPv4Doc{Enabled: true, AutoDNS: &autoDNS}
		}

	default:
		return "", fmt.Errorf("unknown change kind %q", kind)
	}

	// The interface entry goes in only when it carries something: a bare
	// name would be a no-op nmstate still has to verify.
	if iface.MTU != 0 || iface.IPv4 != nil {
		document.Interfaces = []nmstateInterfaceDoc{iface}
	}
	encoded, err := yaml.Marshal(document)
	if err != nil {
		return "", err
	}
	return string(encoded), nil
}

// nmstateMTU turns the MTU text into a number. "auto" is a NetworkManager
// value: nmstate knows only numbers, and the driver default is not a
// state it can describe.
func nmstateMTU(mtu string) (int, error) {
	if err := ValidateMTU(mtu); err != nil {
		return 0, err
	}
	if mtu == MTUAuto {
		return 0, fmt.Errorf("nmstate needs a numeric MTU; \"auto\" is a NetworkManager value")
	}
	return strconv.Atoi(mtu)
}

// nmstateIPv4 turns the method and the addresses of a profile into the
// IPv4 section. The methods are the NetworkManager ones the operator knows;
// the ones nmstate cannot express are refused rather than approximated.
func nmstateIPv4(profile Profile) (*nmstateIPv4Doc, error) {
	for _, address := range profile.Addresses {
		if err := ValidateAddress(address); err != nil {
			return nil, err
		}
	}
	yes, no := true, false
	switch profile.Method {
	case "auto":
		ipv4 := &nmstateIPv4Doc{Enabled: true, DHCP: &yes}
		if profile.IgnoreAutoDNS {
			ipv4.AutoDNS = &no
		}
		return ipv4, nil
	case "manual":
		if len(profile.Addresses) == 0 {
			return nil, fmt.Errorf("the manual method requires at least one address")
		}
		ipv4 := &nmstateIPv4Doc{Enabled: true, DHCP: &no}
		for _, address := range profile.Addresses {
			ip, prefix, _ := strings.Cut(address, "/")
			length, _ := strconv.Atoi(prefix)
			ipv4.Address = append(ipv4.Address, nmstateAddressDoc{IP: ip, PrefixLength: length})
		}
		return ipv4, nil
	case "disabled":
		return &nmstateIPv4Doc{Enabled: false}, nil
	}
	return nil, fmt.Errorf("nmstate cannot express the method %q", profile.Method)
}

// routeEntries removes the routes the interface has and adds the desired
// ones. nmstate handles the absent entries before the additions, so a
// route present in both lists ends up present once.
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

// gatewayEntries replaces the default route of the interface.
func gatewayEntries(iface, current, desired string) []nmstateRouteDoc {
	entries := []nmstateRouteDoc{}
	if current != "" {
		entries = append(entries, nmstateRouteDoc{
			Destination: defaultRouteIPv4, NextHopInterface: iface, State: "absent"})
	}
	if desired != "" {
		entries = append(entries, nmstateRouteDoc{
			Destination: defaultRouteIPv4, NextHopAddress: desired, NextHopInterface: iface})
	}
	return entries
}

func nonNil(items []string) []string {
	if items == nil {
		return []string{}
	}
	return items
}

// NmstateApplyArguments applies a document under nmstate's own checkpoint.
//
// Without a commit within the timeout nmstate returns the host to the
// state from before the change on its own - also when the helper that
// started the change is no longer there.
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
