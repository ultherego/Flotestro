package network

import (
	"fmt"
	"net"
	"strconv"
	"strings"
)

// NmcliPath points at the NetworkManager tool. The path is fixed, not
// searched in PATH: the helper runs only known binaries.
const NmcliPath = "/usr/bin/nmcli"

// MTUAuto means the driver default. "auto" and a specific number are two
// different things, so zero cannot stand in for either.
const MTUAuto = "auto"

// Connection is a NetworkManager profile assigned to a device.
type Connection struct {
	Name   string
	UUID   string
	Device string
	Type   string
	State  string
}

// Profile describes the settings of one connection within the scope the
// panel manages. Empty fields mean "NetworkManager has nothing here", not
// "clear".
type Profile struct {
	Connection string   `json:"connection"`
	Interface  string   `json:"interface,omitempty"`
	Method     string   `json:"method,omitempty"`
	Addresses  []string `json:"addresses,omitempty"`
	Gateway    string   `json:"gateway,omitempty"`
	DNS        []string `json:"dns,omitempty"`
	// DNSSearch and IgnoreAutoDNS belong to the resolver just like the
	// servers: a rollback that restores only the servers leaves the host
	// with somebody else's search domains and with the DHCP servers
	// rejected.
	DNSSearch     []string `json:"dns_search,omitempty"`
	IgnoreAutoDNS bool     `json:"ignore_auto_dns,omitempty"`
	Routes        []string `json:"routes,omitempty"`
	// MTU is text, because "auto" is an equal value here.
	MTU string `json:"mtu,omitempty"`
}

// ProfileFields lists the settings the panel asks NetworkManager for.
var ProfileFields = []string{
	"connection.id", "connection.interface-name", "ipv4.method",
	"ipv4.addresses", "ipv4.gateway", "ipv4.dns", "ipv4.dns-search",
	"ipv4.ignore-auto-dns", "ipv4.routes", "802-3-ethernet.mtu",
}

// ParseConnections reads the output of "nmcli -t -f NAME,UUID,DEVICE,TYPE,STATE con show".
func ParseConnections(output string) []Connection {
	var connections []Connection
	for _, line := range strings.Split(output, "\n") {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		fields := strings.Split(line, ":")
		if len(fields) < 5 {
			continue
		}
		connections = append(connections, Connection{
			Name: fields[0], UUID: fields[1], Device: fields[2],
			Type: fields[3], State: fields[4],
		})
	}
	return connections
}

// DeviceConnection returns the profile active on the given interface.
func DeviceConnection(connections []Connection, iface string) *Connection {
	for i := range connections {
		if connections[i].Device == iface {
			return &connections[i]
		}
	}
	return nil
}

// ParseProfile reads the output of "nmcli -t -f <fields> con show <name>".
//
// The value is everything after the first colon: IPv6 addresses contain
// colons and splitting on each of them would break them into pieces.
func ParseProfile(output string) Profile {
	profile := Profile{}
	for _, line := range strings.Split(output, "\n") {
		line = strings.TrimSpace(line)
		split := strings.Index(line, ":")
		if split < 0 {
			continue
		}
		key, value := line[:split], strings.TrimSpace(line[split+1:])
		if value == "--" {
			value = ""
		}
		switch key {
		case "connection.id":
			profile.Connection = value
		case "connection.interface-name":
			profile.Interface = value
		case "ipv4.method":
			profile.Method = value
		case "ipv4.addresses":
			profile.Addresses = valueList(value)
		case "ipv4.gateway":
			profile.Gateway = value
		case "ipv4.dns":
			profile.DNS = valueList(value)
		case "ipv4.dns-search":
			profile.DNSSearch = valueList(value)
		case "ipv4.ignore-auto-dns":
			profile.IgnoreAutoDNS = value == "yes"
		case "ipv4.routes":
			profile.Routes = valueList(value)
		case "802-3-ethernet.mtu":
			profile.MTU = value
		}
	}
	return profile
}

func valueList(value string) []string {
	if value == "" {
		return nil
	}
	var result []string
	for _, element := range strings.Split(value, ",") {
		element = strings.TrimSpace(element)
		if element != "" {
			result = append(result, element)
		}
	}
	return result
}

// MTUArguments assembles the MTU change of a profile.
//
// The change goes through the profile, not through "ip link set": a value
// set directly on the device vanishes at the first connection switch, and
// the operator would see a change the host forgets after a reboot.
func MTUArguments(connection, mtu string) ([][]string, error) {
	if err := ValidateMTU(mtu); err != nil {
		return nil, err
	}
	return [][]string{
		{NmcliPath, "connection", "modify", connection, "802-3-ethernet.mtu", mtu},
		{NmcliPath, "connection", "up", connection},
	}, nil
}

// RouteArguments writes the full route list of a profile.
//
// The list is the desired state, not an addition: the operator saw a
// specific set of routes in the plan and that is what is to stay on the
// host.
func RouteArguments(connection string, routes []string) ([][]string, error) {
	for _, route := range routes {
		if err := ValidateRoute(route); err != nil {
			return nil, err
		}
	}
	return [][]string{
		{NmcliPath, "connection", "modify", connection, "ipv4.routes", strings.Join(routes, ",")},
		{NmcliPath, "connection", "up", connection},
	}, nil
}

// DNSArguments assembles the change of the resolver alone.
//
// Only the DNS fields of the profile are changed: the address, the gateway
// and the routes stay as they were. The operator asked for the resolver, so
// they get the resolver - not the whole profile rewritten, the rest of
// which they did not view.
func DNSArguments(connection string, servers, domains []string, ignoreAuto bool) ([][]string, error) {
	if connection == "" {
		return nil, fmt.Errorf("resolver change without a connection name")
	}
	// A resolver without a server resolves nothing, and a host without name
	// resolution loses the directory, Kerberos and logins.
	if len(servers) == 0 {
		return nil, fmt.Errorf("a resolver change requires at least one server")
	}
	for _, server := range servers {
		if err := ValidateIPAddress(server); err != nil {
			return nil, fmt.Errorf("DNS server: %w", err)
		}
	}
	ignore := "no"
	if ignoreAuto {
		ignore = "yes"
	}
	return [][]string{
		{NmcliPath, "connection", "modify", connection,
			"ipv4.dns", strings.Join(servers, ","),
			"ipv4.dns-search", strings.Join(domains, ","),
			"ipv4.ignore-auto-dns", ignore},
		{NmcliPath, "connection", "up", connection},
	}, nil
}

// ProfileArguments assembles the write of the whole address profile.
func ProfileArguments(profile Profile) ([][]string, error) {
	if profile.Connection == "" {
		return nil, fmt.Errorf("profile without a connection name")
	}
	switch profile.Method {
	case "auto", "manual", "disabled", "link-local", "shared":
	default:
		return nil, fmt.Errorf("unsupported method %q", profile.Method)
	}
	// The manual method without an address would leave the interface
	// without an address, and so cut the host off - that is not a
	// configuration, it is a mistake.
	if profile.Method == "manual" && len(profile.Addresses) == 0 {
		return nil, fmt.Errorf("the manual method requires at least one address")
	}
	for _, address := range profile.Addresses {
		if err := ValidateAddress(address); err != nil {
			return nil, err
		}
	}
	if profile.Gateway != "" {
		if err := ValidateIPAddress(profile.Gateway); err != nil {
			return nil, fmt.Errorf("gateway: %w", err)
		}
	}
	for _, server := range profile.DNS {
		if err := ValidateIPAddress(server); err != nil {
			return nil, fmt.Errorf("DNS server: %w", err)
		}
	}
	for _, route := range profile.Routes {
		if err := ValidateRoute(route); err != nil {
			return nil, err
		}
	}

	ignore := "no"
	if profile.IgnoreAutoDNS {
		ignore = "yes"
	}
	modification := []string{NmcliPath, "connection", "modify", profile.Connection,
		"ipv4.method", profile.Method,
		"ipv4.addresses", strings.Join(profile.Addresses, ","),
		"ipv4.gateway", profile.Gateway,
		"ipv4.dns", strings.Join(profile.DNS, ","),
		"ipv4.dns-search", strings.Join(profile.DNSSearch, ","),
		"ipv4.ignore-auto-dns", ignore,
		"ipv4.routes", strings.Join(profile.Routes, ",")}
	if profile.MTU != "" {
		modification = append(modification, "802-3-ethernet.mtu", profile.MTU)
	}
	return [][]string{modification, {NmcliPath, "connection", "up", profile.Connection}}, nil
}

// ValidateMTU checks an MTU value.
func ValidateMTU(mtu string) error {
	if mtu == MTUAuto {
		return nil
	}
	value, err := strconv.Atoi(mtu)
	if err != nil {
		return fmt.Errorf("MTU %q is neither a number nor the value auto", mtu)
	}
	// Below 1280 IPv6 does not pass, and below 68 IPv4 does not. The upper
	// bound is the kernel limit for jumbo frames.
	if value < 1280 || value > 65536 {
		return fmt.Errorf("MTU %d is outside the range 1280-65536", value)
	}
	return nil
}

// ValidateAddress checks an address with a mask.
func ValidateAddress(address string) error {
	if _, _, err := net.ParseCIDR(address); err != nil {
		return fmt.Errorf("the address %q is not an address with a mask", address)
	}
	return nil
}

// ValidateIPAddress checks a bare address.
func ValidateIPAddress(address string) error {
	if net.ParseIP(address) == nil {
		return fmt.Errorf("%q is not an IP address", address)
	}
	return nil
}

// ValidateRoute checks a route in the form "network/mask [gateway]".
func ValidateRoute(route string) error {
	fields := strings.Fields(route)
	if len(fields) == 0 || len(fields) > 2 {
		return fmt.Errorf("the route %q must have the form \"network/mask [gateway]\"", route)
	}
	if err := ValidateAddress(fields[0]); err != nil {
		return fmt.Errorf("route destination: %w", err)
	}
	if len(fields) == 2 {
		if err := ValidateIPAddress(fields[1]); err != nil {
			return fmt.Errorf("route gateway: %w", err)
		}
	}
	return nil
}
