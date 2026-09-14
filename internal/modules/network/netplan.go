package network

import (
	"fmt"
	"sort"
	"strconv"
	"strings"

	"gopkg.in/yaml.v3"
)

// The netplan tool and the panel's own file.
//
// The panel writes one file of its own and never edits the distribution's:
// netplan merges the files in name order and a later file amends an
// earlier one, so 90-flotestro.yaml overrides exactly the keys the
// operator changed and nothing else. Removing the file returns the host to
// the distribution's configuration.
const (
	NetplanPath        = "/usr/sbin/netplan"
	NetplanDir         = "/etc/netplan"
	NetplanManagedFile = "/etc/netplan/90-flotestro.yaml"
)

// netplanSections lists the netplan sections that hold interfaces.
var netplanSections = []string{
	"ethernets", "bonds", "bridges", "vlans", "vrfs", "tunnels",
	"dummy-devices", "virtual-ethernets", "wifis", "modems",
}

// NetplanConfig is the merged netplan configuration as the panel reads it.
type NetplanConfig struct {
	Renderer   string
	Interfaces map[string]NetplanInterface
}

// NetplanInterface is one interface definition after the merge.
type NetplanInterface struct {
	Section string
	Profile Profile
	// Gateway4 says the default route came from the deprecated gateway4
	// key. A later file cannot remove a key an earlier one set, so a
	// gateway change has to go through the same key.
	Gateway4 bool
}

// ParseNetplan reads one netplan document: the output of "netplan get" or
// the content of one file. The root "network" key is optional, because
// "netplan get" prints the tree with it and a subtree without.
func ParseNetplan(document string) (NetplanConfig, error) {
	tree, err := netplanTree(document)
	if err != nil {
		return NetplanConfig{}, err
	}
	return netplanConfig(tree), nil
}

// MergeNetplanDocuments merges files the way netplan does when "netplan
// get" is not there to do it: in the given order, a later document amends
// an earlier one key by key and a scalar or a list in a later file replaces
// the one before.
func MergeNetplanDocuments(documents ...string) (NetplanConfig, error) {
	merged := map[string]any{}
	for _, document := range documents {
		tree, err := netplanTree(document)
		if err != nil {
			return NetplanConfig{}, err
		}
		merged = mergeTrees(merged, tree)
	}
	return netplanConfig(merged), nil
}

// netplanTree reads a document into the tree under the "network" key.
func netplanTree(document string) (map[string]any, error) {
	var root map[string]any
	if err := yaml.Unmarshal([]byte(document), &root); err != nil {
		return nil, fmt.Errorf("reading the netplan configuration: %w", err)
	}
	if root == nil {
		return map[string]any{}, nil
	}
	if inner, ok := root["network"].(map[string]any); ok {
		return inner, nil
	}
	return root, nil
}

func mergeTrees(base, overlay map[string]any) map[string]any {
	result := map[string]any{}
	for key, value := range base {
		result[key] = value
	}
	for key, value := range overlay {
		existing, hadMap := result[key].(map[string]any)
		incoming, isMap := value.(map[string]any)
		if hadMap && isMap {
			result[key] = mergeTrees(existing, incoming)
			continue
		}
		result[key] = value
	}
	return result
}

func netplanConfig(tree map[string]any) NetplanConfig {
	config := NetplanConfig{Interfaces: map[string]NetplanInterface{}}
	config.Renderer, _ = tree["renderer"].(string)
	for _, section := range netplanSections {
		entries, ok := tree[section].(map[string]any)
		if !ok {
			continue
		}
		for name, raw := range entries {
			definition, _ := raw.(map[string]any)
			config.Interfaces[name] = netplanInterface(section, name, definition)
		}
	}
	return config
}

// Profiles returns the interfaces in a stable order.
func (c NetplanConfig) Profiles() []Profile {
	names := make([]string, 0, len(c.Interfaces))
	for name := range c.Interfaces {
		names = append(names, name)
	}
	sort.Strings(names)
	profiles := make([]Profile, 0, len(names))
	for _, name := range names {
		profiles = append(profiles, c.Interfaces[name].Profile)
	}
	return profiles
}

// Profile returns the profile of one interface. An interface netplan does
// not describe is a refusal: the panel does not create new definitions,
// because a definition of its own would have to guess the match rules and
// the renderer the distribution chose.
func (c NetplanConfig) Profile(name string) (Profile, error) {
	entry, ok := c.Interfaces[name]
	if !ok {
		return Profile{}, fmt.Errorf("the interface %s is not described by netplan; the panel does not create new definitions here", name)
	}
	return entry.Profile, nil
}

func netplanInterface(section, name string, definition map[string]any) NetplanInterface {
	profile := Profile{Connection: name, Interface: name, Type: section, Method: "disabled", MTU: MTUAuto}
	entry := NetplanInterface{Section: section}
	if definition == nil {
		entry.Profile = profile
		return entry
	}
	if dhcp, ok := definition["dhcp4"].(bool); ok && dhcp {
		profile.Method = "auto"
	}
	for _, address := range netplanAddresses(definition["addresses"]) {
		if strings.Contains(address, ":") {
			continue
		}
		profile.Addresses = append(profile.Addresses, address)
	}
	if profile.Method != "auto" && len(profile.Addresses) > 0 {
		profile.Method = "manual"
	}
	if gateway, ok := definition["gateway4"].(string); ok && gateway != "" {
		profile.Gateway = gateway
		entry.Gateway4 = true
	}
	for _, route := range netplanRoutes(definition["routes"]) {
		if route.to == "default" || route.to == defaultRouteIPv4 {
			if !entry.Gateway4 {
				profile.Gateway = route.via
			}
			continue
		}
		text := route.to
		if route.via != "" {
			text += " " + route.via
		}
		profile.Routes = append(profile.Routes, text)
	}
	if nameservers, ok := definition["nameservers"].(map[string]any); ok {
		profile.DNS = stringList(nameservers["addresses"])
		profile.DNSSearch = stringList(nameservers["search"])
	}
	if overrides, ok := definition["dhcp4-overrides"].(map[string]any); ok {
		if useDNS, ok := overrides["use-dns"].(bool); ok && !useDNS {
			profile.IgnoreAutoDNS = true
		}
	}
	if mtu, ok := netplanNumber(definition["mtu"]); ok && mtu > 0 {
		profile.MTU = strconv.Itoa(mtu)
	}
	entry.Profile = profile
	return entry
}

// netplanAddresses reads the addresses list: plain strings, or a mapping
// with options keyed by the address.
func netplanAddresses(raw any) []string {
	items, _ := raw.([]any)
	var addresses []string
	for _, item := range items {
		switch value := item.(type) {
		case string:
			addresses = append(addresses, value)
		case map[string]any:
			for address := range value {
				addresses = append(addresses, address)
			}
		}
	}
	return addresses
}

type netplanRoute struct{ to, via string }

func netplanRoutes(raw any) []netplanRoute {
	items, _ := raw.([]any)
	var routes []netplanRoute
	for _, item := range items {
		entry, ok := item.(map[string]any)
		if !ok {
			continue
		}
		to, _ := entry["to"].(string)
		via, _ := entry["via"].(string)
		if to == "" || strings.Contains(to, ":") || strings.Contains(via, ":") {
			continue
		}
		routes = append(routes, netplanRoute{to: to, via: via})
	}
	return routes
}

func stringList(raw any) []string {
	items, _ := raw.([]any)
	var result []string
	for _, item := range items {
		if text, ok := item.(string); ok {
			result = append(result, text)
		}
	}
	return result
}

func netplanNumber(raw any) (int, bool) {
	switch value := raw.(type) {
	case int:
		return value, true
	case int64:
		return int(value), true
	case float64:
		return int(value), true
	case string:
		number, err := strconv.Atoi(value)
		return number, err == nil
	}
	return 0, false
}

// NetplanManagedDocument assembles the panel's file after the change.
//
// The file starts from what the panel already wrote (other interfaces, other
// keys of this one) and gets the keys of this change for the touched
// interface - only those. The distribution's files stay untouched; the
// merge result is what "netplan get" shows afterwards.
func NetplanManagedDocument(managed string, config NetplanConfig, iface, kind string,
	current, desired Profile) (string, error) {
	if err := ValidateInterfaceName(iface); err != nil {
		return "", err
	}
	entry, ok := config.Interfaces[iface]
	if !ok {
		return "", fmt.Errorf("the interface %s is not described by netplan; the panel does not create new definitions here", iface)
	}
	tree, err := netplanTree(managed)
	if err != nil {
		return "", fmt.Errorf("the panel's netplan file: %w", err)
	}
	section, _ := tree[entry.Section].(map[string]any)
	if section == nil {
		section = map[string]any{}
	}
	definition, _ := section[iface].(map[string]any)
	if definition == nil {
		definition = map[string]any{}
	}

	switch kind {
	case PlanMTU:
		if err := ValidateMTU(desired.MTU); err != nil {
			return "", err
		}
		if desired.MTU == MTUAuto {
			// "auto" is the absence of the panel's override. The link keeps
			// its running value until the next reconfiguration: networkd
			// leaves an MTU alone when the definition stops naming one.
			delete(definition, "mtu")
		} else {
			mtu, _ := strconv.Atoi(desired.MTU)
			definition["mtu"] = mtu
		}

	case PlanRoutes:
		for _, route := range desired.Routes {
			if err := ValidateRoute(route); err != nil {
				return "", err
			}
		}
		definition["routes"] = netplanRouteList(entry, current.Gateway, desired.Routes)

	case PlanProfile:
		if err := netplanProfileKeys(definition, entry, current, desired); err != nil {
			return "", err
		}

	case PlanDNS:
		for _, server := range desired.DNS {
			if err := ValidateIPAddress(server); err != nil {
				return "", fmt.Errorf("DNS server: %w", err)
			}
		}
		definition["nameservers"] = map[string]any{
			"addresses": anyList(desired.DNS), "search": anyList(desired.DNSSearch)}
		if current.IgnoreAutoDNS != desired.IgnoreAutoDNS {
			definition["dhcp4-overrides"] = map[string]any{"use-dns": !desired.IgnoreAutoDNS}
		}

	default:
		return "", fmt.Errorf("unknown change kind %q", kind)
	}

	if len(definition) == 0 {
		delete(section, iface)
	} else {
		section[iface] = definition
	}
	if len(section) == 0 {
		delete(tree, entry.Section)
	} else {
		tree[entry.Section] = section
	}
	tree["version"] = 2
	encoded, err := yaml.Marshal(map[string]any{"network": tree})
	if err != nil {
		return "", err
	}
	return string(encoded), nil
}

// netplanProfileKeys writes the method, the addresses, the gateway and the
// resolver of the address profile. The routes and the MTU stay: the address
// profile is a separate operation.
func netplanProfileKeys(definition map[string]any, entry NetplanInterface, current, desired Profile) error {
	for _, address := range desired.Addresses {
		if err := ValidateAddress(address); err != nil {
			return err
		}
	}
	switch desired.Method {
	case "auto":
		definition["dhcp4"] = true
		definition["addresses"] = []any{}
	case "manual":
		if len(desired.Addresses) == 0 {
			return fmt.Errorf("the manual method requires at least one address")
		}
		definition["dhcp4"] = false
		definition["addresses"] = anyList(desired.Addresses)
	case "disabled":
		definition["dhcp4"] = false
		definition["addresses"] = []any{}
	default:
		return fmt.Errorf("netplan cannot express the method %q", desired.Method)
	}
	if desired.Gateway != "" {
		if err := ValidateIPAddress(desired.Gateway); err != nil {
			return fmt.Errorf("gateway: %w", err)
		}
	}
	if current.Gateway != desired.Gateway {
		if entry.Gateway4 {
			// The distribution set gateway4; a later file cannot unset it,
			// only override it.
			definition["gateway4"] = desired.Gateway
		} else {
			definition["routes"] = netplanRouteList(entry, desired.Gateway, current.Routes)
		}
	}
	if !sameSet(current.DNS, desired.DNS) {
		for _, server := range desired.DNS {
			if err := ValidateIPAddress(server); err != nil {
				return fmt.Errorf("DNS server: %w", err)
			}
		}
		definition["nameservers"] = map[string]any{
			"addresses": anyList(desired.DNS), "search": anyList(current.DNSSearch)}
	}
	return nil
}

// netplanRouteList writes the full route list of the interface: the
// default route when it lives in the routes key, then the static ones. A
// list in a later file replaces the earlier one, so leaving the default
// out would drop it.
func netplanRouteList(entry NetplanInterface, gateway string, routes []string) []any {
	list := []any{}
	if gateway != "" && !entry.Gateway4 {
		list = append(list, map[string]any{"to": "default", "via": gateway})
	}
	for _, route := range routes {
		fields := strings.Fields(route)
		if len(fields) == 0 {
			continue
		}
		item := map[string]any{"to": fields[0]}
		if len(fields) == 2 {
			item["via"] = fields[1]
		} else {
			item["scope"] = "link"
		}
		list = append(list, item)
	}
	return list
}

func anyList(items []string) []any {
	list := make([]any, 0, len(items))
	for _, item := range items {
		list = append(list, item)
	}
	return list
}

// NetplanGenerateArguments validates the configuration and renders it for
// the layer below without applying it.
func NetplanGenerateArguments() []string {
	return []string{NetplanPath, "generate"}
}

// NetplanTryArguments applies the configuration under netplan's own
// revert: without a confirmation on its standard input within the timeout
// netplan returns the host to the previous running state.
func NetplanTryArguments(timeoutSeconds int) []string {
	return []string{NetplanPath, "try", "--timeout", strconv.Itoa(timeoutSeconds)}
}

// NetplanApplyArguments applies the configuration on disk.
func NetplanApplyArguments() []string {
	return []string{NetplanPath, "apply"}
}

// NetplanGetArguments prints the merged configuration.
func NetplanGetArguments() []string {
	return []string{NetplanPath, "get"}
}

// NetplanPromptSeen says whether "netplan try" has finished applying and
// is waiting for the confirmation. The prompt is the only sign of it: the
// change is on the host from that moment, and the connectivity check makes
// sense only after it.
func NetplanPromptSeen(output string) bool {
	lower := strings.ToLower(output)
	return strings.Contains(lower, "press enter") || strings.Contains(lower, "keep these settings")
}
