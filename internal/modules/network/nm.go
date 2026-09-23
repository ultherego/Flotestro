package network

import (
	"fmt"
	"net"
	"regexp"
	"slices"
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

// Profile describes the settings of one connection within the scope the panel
// manages.
type Profile struct {
	// Connection names the profile: the NetworkManager connection, or the
	// interface itself where the mechanism has no profile names (nmstate,
	// netplan).
	Connection string `json:"connection"`
	Interface  string `json:"interface,omitempty"`
	// Type is the interface type as the mechanism names it: the nmstate interface
	// type (ethernet, bond) or the netplan section (ethernets, bonds).
	Type      string   `json:"type,omitempty"`
	Method    string   `json:"method,omitempty"`
	Addresses []string `json:"addresses,omitempty"`
	Gateway   string   `json:"gateway,omitempty"`
	DNS       []string `json:"dns,omitempty"`
	// DNSSearch and IgnoreAutoDNS belong to the resolver just like the servers: a
	// rollback that restores only the servers leaves the host with somebody
	// else's search domains and with the DHCP servers rejected.
	DNSSearch     []string `json:"dns_search,omitempty"`
	IgnoreAutoDNS bool     `json:"ignore_auto_dns,omitempty"`
	Routes        []string `json:"routes,omitempty"`
	// The second family.
	Method6    string   `json:"method6,omitempty"`
	Addresses6 []string `json:"addresses6,omitempty"`
	Gateway6   string   `json:"gateway6,omitempty"`
	Routes6    []string `json:"routes6,omitempty"`
	// AcceptRA and Privacy are the router advertisement and the privacy
	// extensions in the panel's own words (off, on, on-forwarding; off,
	// prefer-public, prefer-temporary).
	AcceptRA string `json:"accept_ra,omitempty"`
	Privacy  string `json:"privacy,omitempty"`
	// MTU is text, because "auto" is an equal value here.
	MTU string `json:"mtu,omitempty"`
}

// ProfileFields lists the settings the panel asks NetworkManager for.
var ProfileFields = []string{
	"connection.id", "connection.interface-name", "ipv4.method",
	"ipv4.addresses", "ipv4.gateway", "ipv4.dns", "ipv4.dns-search",
	"ipv4.ignore-auto-dns", "ipv4.routes", "802-3-ethernet.mtu",
	// The second family is asked for by name as well.
	"ipv6.method", "ipv6.addresses", "ipv6.gateway", "ipv6.routes",
	"ipv6.ip6-privacy", "ipv6.dns", "ipv6.dns-search", "ipv6.ignore-auto-dns",
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
		case "ipv6.method":
			profile.Method6 = value
		case "ipv6.addresses":
			profile.Addresses6 = valueList(value)
		case "ipv6.gateway":
			profile.Gateway6 = value
		case "ipv6.routes":
			profile.Routes6 = valueList(value)
		case "ipv6.ip6-privacy":
			profile.Privacy = nmPrivacyWord(value)
		// A resolver is a resolver whichever family its address belongs to.
		// Asking only about the first one reported an incomplete list as whole.
		case "ipv6.dns":
			profile.DNS = append(profile.DNS, valueList(value)...)
		case "ipv6.dns-search":
			profile.DNSSearch = appendMissing(profile.DNSSearch, valueList(value))
		case "ipv6.ignore-auto-dns":
			profile.IgnoreAutoDNS = profile.IgnoreAutoDNS || value == "yes"
		case "802-3-ethernet.mtu":
			profile.MTU = value
		}
	}
	return profile
}

// nmPrivacyWord turns the NetworkManager value of ipv6. ip6-privacy into the
// panel's word.
func nmPrivacyWord(value string) string {
	switch strings.TrimSpace(value) {
	case "0", "disabled":
		return PrivacyOff
	case "1", "enabled (prefer public IP)":
		return PrivacyPreferPublic
	case "2", "enabled (prefer temporary IP)":
		return PrivacyPreferTemporary
	}
	return ""
}

// nmPrivacyValue is the other direction: the value nmcli takes.
func nmPrivacyValue(word string) (string, error) {
	switch word {
	case PrivacyOff:
		return "0", nil
	case PrivacyPreferPublic:
		return "1", nil
	case PrivacyPreferTemporary:
		return "2", nil
	}
	return "", fmt.Errorf("unsupported IPv6 privacy setting %q", word)
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
func MTUArguments(connection, mtu string) ([][]string, error) {
	if err := ValidateMTU(mtu); err != nil {
		return nil, err
	}
	return [][]string{
		{NmcliPath, "connection", "modify", connection, "802-3-ethernet.mtu", mtu},
		{NmcliPath, "connection", "up", connection},
	}, nil
}

// RouteArguments writes the full route list of a profile, one family at a
// time.
func RouteArguments(connection string, routes, routes6 []string) ([][]string, error) {
	for _, route := range append(append([]string(nil), routes...), routes6...) {
		if err := ValidateRoute(route); err != nil {
			return nil, err
		}
	}
	return [][]string{
		{NmcliPath, "connection", "modify", connection,
			"ipv4.routes", strings.Join(routes, ","),
			"ipv6.routes", strings.Join(routes6, ",")},
		{NmcliPath, "connection", "up", connection},
	}, nil
}

// DNSArguments assembles the change of the resolver alone.
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
	// Each family takes its own key: an IPv6 server written into ipv4.dns is
	// refused by nmcli, and the operator sees the refusal of a command they
	// never composed.
	v4, v6 := splitDNSFamilies(servers)
	return [][]string{
		{NmcliPath, "connection", "modify", connection,
			"ipv4.dns", strings.Join(v4, ","),
			"ipv4.dns-search", strings.Join(domains, ","),
			"ipv4.ignore-auto-dns", ignore,
			"ipv6.dns", strings.Join(v6, ","),
			"ipv6.dns-search", strings.Join(domains, ","),
			"ipv6.ignore-auto-dns", ignore},
		{NmcliPath, "connection", "up", connection},
	}, nil
}

// splitDNSFamilies divides the servers by the family of their address.
func splitDNSFamilies(servers []string) (v4, v6 []string) {
	for _, server := range servers {
		if strings.Contains(server, ":") {
			v6 = append(v6, server)
			continue
		}
		v4 = append(v4, server)
	}
	return v4, v6
}

// appendMissing adds what is not in the list already, keeping its order.
func appendMissing(list, extra []string) []string {
	for _, value := range extra {
		if !slices.Contains(list, value) {
			list = append(list, value)
		}
	}
	return list
}

// ProfileArguments assembles the write of the whole address profile.
func ProfileArguments(profile Profile) ([][]string, error) {
	if err := ValidateProfile(profile); err != nil {
		return nil, err
	}
	if profile.Connection == "" {
		return nil, fmt.Errorf("profile without a connection name")
	}
	// What NetworkManager in particular cannot express.
	if profile.AcceptRA != "" {
		return nil, fmt.Errorf("NetworkManager has no separate setting for router advertisements; they follow from the IPv6 method, where auto is the method that listens to them")
	}

	ignore := "no"
	if profile.IgnoreAutoDNS {
		ignore = "yes"
	}
	v4, v6 := splitDNSFamilies(profile.DNS)
	modification := []string{NmcliPath, "connection", "modify", profile.Connection,
		"ipv4.method", profile.Method,
		"ipv4.addresses", strings.Join(profile.Addresses, ","),
		"ipv4.gateway", profile.Gateway,
		"ipv4.dns", strings.Join(v4, ","),
		"ipv4.dns-search", strings.Join(profile.DNSSearch, ","),
		"ipv4.ignore-auto-dns", ignore,
		"ipv6.dns", strings.Join(v6, ","),
		"ipv6.dns-search", strings.Join(profile.DNSSearch, ","),
		"ipv6.ignore-auto-dns", ignore,
		"ipv4.routes", strings.Join(profile.Routes, ",")}
	// The second family is written only when the profile says something about it.
	if profile.Method6 != "" {
		modification = append(modification,
			"ipv6.method", profile.Method6,
			"ipv6.addresses", strings.Join(profile.Addresses6, ","),
			"ipv6.gateway", profile.Gateway6,
			"ipv6.routes", strings.Join(profile.Routes6, ","))
	}
	if profile.Privacy != "" {
		value, err := nmPrivacyValue(profile.Privacy)
		if err != nil {
			return nil, err
		}
		modification = append(modification, "ipv6.ip6-privacy", value)
	}
	if profile.MTU != "" {
		modification = append(modification, "802-3-ethernet.mtu", profile.MTU)
	}
	return [][]string{modification, {NmcliPath, "connection", "up", profile.Connection}}, nil
}

// ValidateProfile checks what any mechanism has to be able to express: a
// method it knows, addresses with their mask or prefix length, a gateway of
// the right family, and routes that say where they go.
func ValidateProfile(profile Profile) error {
	switch profile.Method {
	case "auto", "manual", "disabled", "link-local", "shared":
	default:
		return fmt.Errorf("unsupported method %q", profile.Method)
	}
	// The manual method without an address would leave the interface without an
	// address, and so cut the host off - that is not a configuration, it is a
	// mistake.
	if profile.Method == "manual" && len(profile.Addresses) == 0 {
		return fmt.Errorf("the manual method requires at least one address")
	}
	for _, address := range profile.Addresses {
		if err := ValidateAddress(address); err != nil {
			return err
		}
	}
	if profile.Gateway != "" {
		if err := ValidateIPAddress(profile.Gateway); err != nil {
			return fmt.Errorf("gateway: %w", err)
		}
	}
	for _, server := range profile.DNS {
		if err := ValidateIPAddress(server); err != nil {
			return fmt.Errorf("DNS server: %w", err)
		}
	}
	for _, route := range profile.Routes {
		if err := ValidateRoute(route); err != nil {
			return err
		}
	}
	return validateIPv6Profile(profile)
}

// validateIPv6Profile checks the second family of a profile to the same
// standard as the first, and no further: which mechanism can express which of
// its settings is the mechanism's own answer, given where the document is.
func validateIPv6Profile(profile Profile) error {
	switch profile.Method6 {
	case "", "auto", "dhcp", "manual", "disabled", "ignore", "link-local", "shared":
	default:
		return fmt.Errorf("unsupported IPv6 method %q", profile.Method6)
	}
	if profile.Method6 == "manual" && len(profile.Addresses6) == 0 {
		return fmt.Errorf("the manual IPv6 method requires at least one address")
	}
	for _, address := range profile.Addresses6 {
		if err := ValidateIPv6Address(address); err != nil {
			return err
		}
	}
	if profile.Gateway6 != "" {
		if err := ValidateIPv6Gateway(profile.Gateway6); err != nil {
			return fmt.Errorf("IPv6 gateway: %w", err)
		}
	}
	for _, route := range profile.Routes6 {
		if err := ValidateRoute(route); err != nil {
			return err
		}
	}
	if !ValidAcceptRA(profile.AcceptRA) {
		return fmt.Errorf("unsupported router advertisement setting %q", profile.AcceptRA)
	}
	if !ValidPrivacy(profile.Privacy) {
		return fmt.Errorf("unsupported IPv6 privacy setting %q", profile.Privacy)
	}
	return nil
}

// interfaceName is what the kernel accepts as an interface name: up to 15
// characters, none of them a slash, a space or a control character.
var interfaceName = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._:-]{0,14}$`)

// ValidateInterfaceName checks an interface name before it is looked up or
// written anywhere.
func ValidateInterfaceName(name string) error {
	if !interfaceName.MatchString(name) {
		return fmt.Errorf("invalid interface name %q", name)
	}
	return nil
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

// ValidateIPv6Address checks an address of the second family with its prefix
// length.
func ValidateIPv6Address(address string) error {
	ip, _, err := net.ParseCIDR(address)
	if err != nil {
		return fmt.Errorf("the address %q is not an address with a prefix length", address)
	}
	if ip.To4() != nil {
		return fmt.Errorf("the address %q belongs to IPv4 and cannot be an IPv6 address of the interface", address)
	}
	return nil
}

// ValidateIPv6Gateway checks the default gateway of the second family.
func ValidateIPv6Gateway(gateway string) error {
	address := net.ParseIP(gateway)
	if address == nil || address.To4() != nil {
		return fmt.Errorf("%q is not an IPv6 address", gateway)
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
