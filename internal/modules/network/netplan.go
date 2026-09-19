package network

import (
	"fmt"
	"sort"
	"strconv"
	"strings"

	"gopkg.in/yaml.v3"
)

// The netplan tool and the panel's own file.
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
	// Gateway4 and Gateway6 say the default route came from the deprecated
	// gateway4/gateway6 keys.
	Gateway4 bool
	Gateway6 bool
	// Layer is the layering netplan describes for this interface: a bond,
	// a bridge or a VLAN. It is nil for an ordinary link.
	Layer *LinkState
}

// ParseNetplan reads one netplan document: the output of "netplan get" or the
// content of one file.
func ParseNetplan(document string) (NetplanConfig, error) {
	tree, err := netplanTree(document)
	if err != nil {
		return NetplanConfig{}, err
	}
	return netplanConfig(tree), nil
}

// MergeNetplanDocuments merges files the way netplan does when "netplan get"
// is not there to do it: in the given order, a later document amends an
// earlier one key by key and a scalar or a list in a later file replaces the.
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

// Profile returns the profile of one interface.
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
	if dhcp, ok := definition["dhcp6"].(bool); ok && dhcp {
		profile.Method6 = "auto"
	}
	for _, address := range netplanAddresses(definition["addresses"]) {
		if strings.Contains(address, ":") {
			profile.Addresses6 = append(profile.Addresses6, address)
			continue
		}
		profile.Addresses = append(profile.Addresses, address)
	}
	if profile.Method != "auto" && len(profile.Addresses) > 0 {
		profile.Method = "manual"
	}
	if profile.Method6 != "auto" && len(profile.Addresses6) > 0 {
		profile.Method6 = "manual"
	}
	if gateway, ok := definition["gateway4"].(string); ok && gateway != "" {
		profile.Gateway = gateway
		entry.Gateway4 = true
	}
	if gateway, ok := definition["gateway6"].(string); ok && gateway != "" {
		profile.Gateway6 = gateway
		entry.Gateway6 = true
	}
	// The second family is read to the same depth as the first: the router
	// advertisements and the privacy extensions are settings netplan does
	// express, and a plan that could not see them would offer to set what the.
	if accept, ok := definition["accept-ra"].(bool); ok {
		profile.AcceptRA = AcceptRAOff
		if accept {
			profile.AcceptRA = AcceptRAOn
		}
	}
	if privacy, ok := definition["ipv6-privacy"].(bool); ok {
		profile.Privacy = PrivacyOff
		if privacy {
			profile.Privacy = PrivacyPreferTemporary
		}
	}
	for _, route := range netplanRoutes(definition["routes"]) {
		sixth := strings.Contains(route.to, ":") || strings.Contains(route.via, ":")
		if route.to == "default" {
			// "default" in netplan says nothing about the family; the
			// gateway does.
			sixth = strings.Contains(route.via, ":")
		}
		switch {
		case sixth && (route.to == "default" || route.to == defaultRouteIPv6):
			if !entry.Gateway6 {
				profile.Gateway6 = route.via
			}
			continue
		case !sixth && (route.to == "default" || route.to == defaultRouteIPv4):
			if !entry.Gateway4 {
				profile.Gateway = route.via
			}
			continue
		}
		text := route.to
		if route.via != "" {
			text += " " + route.via
		}
		if sixth {
			profile.Routes6 = append(profile.Routes6, text)
			continue
		}
		profile.Routes = append(profile.Routes, text)
	}
	entry.Layer = netplanLayer(section, definition)
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
		if to == "" {
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
			// "auto" is the absence of the panel's override.
			delete(definition, "mtu")
		} else {
			mtu, _ := strconv.Atoi(desired.MTU)
			definition["mtu"] = mtu
		}

	case PlanRoutes:
		for _, route := range append(append([]string(nil), desired.Routes...), desired.Routes6...) {
			if err := ValidateRoute(route); err != nil {
				return "", err
			}
		}
		// netplan keeps both families in one list, so both have to be written: a
		// list in a later file replaces the earlier one whole, and leaving the
		// second family out would drop it.
		definition["routes"] = netplanRouteList(entry, current.Gateway, current.Gateway6,
			desired.Routes, desired.Routes6)

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
// resolver of the address profile.
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
	if err := netplanIPv6Keys(definition, current, desired); err != nil {
		return err
	}
	if current.Gateway != desired.Gateway || current.Gateway6 != desired.Gateway6 {
		if entry.Gateway4 && current.Gateway != desired.Gateway {
			// The distribution set gateway4; a later file cannot unset it,
			// only override it.
			definition["gateway4"] = desired.Gateway
		}
		if entry.Gateway6 && current.Gateway6 != desired.Gateway6 {
			definition["gateway6"] = desired.Gateway6
		}
		// Whatever did not go through a deprecated key goes through the
		// route list, which carries both families at once.
		gateway, gateway6 := desired.Gateway, desired.Gateway6
		if entry.Gateway4 {
			gateway = ""
		}
		if entry.Gateway6 {
			gateway6 = ""
		}
		if gateway != "" || gateway6 != "" || len(current.Routes) > 0 || len(current.Routes6) > 0 {
			definition["routes"] = netplanRouteList(entry, gateway, gateway6, current.Routes, current.Routes6)
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

// netplanRouteList writes the full route list of the interface: the default
// route of each family when it lives in the routes key, then the static ones
// of both.
func netplanRouteList(entry NetplanInterface, gateway, gateway6 string, routes, routes6 []string) []any {
	list := []any{}
	if gateway != "" && !entry.Gateway4 {
		list = append(list, map[string]any{"to": defaultRouteIPv4, "via": gateway})
	}
	if gateway6 != "" && !entry.Gateway6 {
		// A link-local gateway needs the interface named: fe80:: addresses are
		// ambiguous without one, and that is the ordinary way an IPv6 router
		// announces itself.
		route := map[string]any{"to": defaultRouteIPv6, "via": gateway6}
		if strings.HasPrefix(strings.ToLower(gateway6), "fe80:") {
			route["on-link"] = true
		}
		list = append(list, route)
	}
	for _, route := range append(append([]string(nil), routes...), routes6...) {
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

// netplanIPv6Keys writes the second family of the address profile.
func netplanIPv6Keys(definition map[string]any, current, desired Profile) error {
	for _, address := range desired.Addresses6 {
		if err := ValidateIPv6Address(address); err != nil {
			return err
		}
	}
	if desired.Gateway6 != "" {
		if err := ValidateIPv6Gateway(desired.Gateway6); err != nil {
			return fmt.Errorf("IPv6 gateway: %w", err)
		}
	}
	// The addresses of both families live in one netplan key, so the key is
	// written from both lists at once or the other family is dropped.
	switch desired.Method6 {
	case "":
	case "auto":
		definition["dhcp6"] = true
	case "manual":
		if len(desired.Addresses6) == 0 {
			return fmt.Errorf("the manual IPv6 method requires at least one address")
		}
		definition["dhcp6"] = false
	case "disabled":
		definition["dhcp6"] = false
		definition["link-local"] = []any{}
	default:
		return fmt.Errorf("netplan cannot express the IPv6 method %q", desired.Method6)
	}
	// The addresses key was written from the first family alone a moment ago; the
	// second family is appended to it here.
	addresses, _ := definition["addresses"].([]any)
	if desired.Method6 != "disabled" {
		for _, address := range desired.Addresses6 {
			addresses = append(addresses, address)
		}
	}
	definition["addresses"] = addresses
	if current.AcceptRA != desired.AcceptRA && desired.AcceptRA != "" {
		switch desired.AcceptRA {
		case AcceptRAOff:
			definition["accept-ra"] = false
		case AcceptRAOn, AcceptRAForwarding:
			definition["accept-ra"] = true
		default:
			return fmt.Errorf("unsupported router advertisement setting %q", desired.AcceptRA)
		}
	}
	if current.Privacy != desired.Privacy && desired.Privacy != "" {
		switch desired.Privacy {
		case PrivacyOff:
			definition["ipv6-privacy"] = false
		case PrivacyPreferTemporary:
			definition["ipv6-privacy"] = true
		case PrivacyPreferPublic:
			return fmt.Errorf("netplan has one switch for the IPv6 privacy extensions, on or off; it cannot say that temporary addresses exist but public ones are preferred")
		default:
			return fmt.Errorf("unsupported IPv6 privacy setting %q", desired.Privacy)
		}
	}
	return nil
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

// NetplanTryArguments applies the configuration under netplan's own revert:
// without a confirmation on its standard input within the timeout netplan
// returns the host to the previous running state.
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

// NetplanPromptSeen says whether "netplan try" has finished applying and is
// waiting for the confirmation.
func NetplanPromptSeen(output string) bool {
	lower := strings.ToLower(output)
	return strings.Contains(lower, "press enter") || strings.Contains(lower, "keep these settings")
}

// The netplan sections that hold layered interfaces, by the kind the panel
// names them with.
var netplanLayerSections = map[string]string{
	LinkBond:   "bonds",
	LinkBridge: "bridges",
	LinkVLAN:   "vlans",
}

// netplanLayer reads the layering of one netplan definition.
func netplanLayer(section string, definition map[string]any) *LinkState {
	kind := ""
	for name, held := range netplanLayerSections {
		if held == section {
			kind = name
		}
	}
	if kind == "" {
		return nil
	}
	state := &LinkState{Kind: kind, Present: true, Members: stringList(definition["interfaces"])}
	parameters, _ := definition["parameters"].(map[string]any)
	switch kind {
	case LinkBond:
		state.Mode, _ = parameters["mode"].(string)
		if value, ok := netplanNumber(parameters["mii-monitor-interval"]); ok {
			state.MIIMonMS = value
		}
		state.Primary, _ = parameters["primary"].(string)
		state.LACPRate, _ = parameters["lacp-rate"].(string)
	case LinkBridge:
		if stp, ok := parameters["stp"].(bool); ok {
			state.STP = stp
		}
	case LinkVLAN:
		state.Parent, _ = definition["link"].(string)
		if value, ok := netplanNumber(definition["id"]); ok {
			state.VLANID = value
		}
		// netplan has no key for the VLAN protocol: every VLAN it defines
		// is an 802.1Q one.
		state.Protocol = "802.1Q"
	}
	if mtu, ok := netplanNumber(definition["mtu"]); ok && mtu > 0 {
		state.MTU = strconv.Itoa(mtu)
	}
	return state
}

// NetplanManagedLinkDocument assembles the panel's file after a layered
// change: a bond, a bridge or a VLAN created, changed or taken away.
func NetplanManagedLinkDocument(managed string, config NetplanConfig, plan Plan) (string, error) {
	if plan.CurrentLink == nil || plan.DesiredLink == nil {
		return "", fmt.Errorf("a layered netplan document without the link states")
	}
	name := plan.DesiredLink.Name
	if err := ValidateInterfaceName(name); err != nil {
		return "", err
	}
	tree, err := netplanTree(managed)
	if err != nil {
		return "", fmt.Errorf("the panel's netplan file: %w", err)
	}

	if !plan.DesiredLink.Present {
		sectionName := netplanLayerSections[plan.CurrentLink.Kind]
		if sectionName == "" {
			return "", fmt.Errorf("netplan keeps no section for a layer of the kind %q", plan.CurrentLink.Kind)
		}
		section, _ := tree[sectionName].(map[string]any)
		if _, ours := section[name]; !ours {
			return "", &LinkRefusal{Code: CodeLinkNotLayered,
				Reason: "the interface " + name + " is not defined in the panel's netplan file; a later file cannot remove a definition the distribution made, so removing it here would change nothing"}
		}
		delete(section, name)
		if len(section) == 0 {
			delete(tree, sectionName)
		} else {
			tree[sectionName] = section
		}
		return netplanDocumentText(tree)
	}

	desired := *plan.DesiredLink
	sectionName := netplanLayerSections[desired.Kind]
	if sectionName == "" {
		return "", fmt.Errorf("netplan keeps no section for a layer of the kind %q", desired.Kind)
	}
	// A definition the distribution already made for this name would be amended
	// rather than replaced, and the result would be two halves of two layers.
	if existing, ok := config.Interfaces[name]; ok && existing.Section != sectionName {
		return "", &LinkRefusal{Code: CodeLinkKindMismatch,
			Reason: "netplan already describes " + name + " under " + existing.Section +
				"; the panel does not move a definition between sections"}
	}
	section, _ := tree[sectionName].(map[string]any)
	if section == nil {
		section = map[string]any{}
	}
	definition, _ := section[name].(map[string]any)
	if definition == nil {
		definition = map[string]any{}
	}

	switch desired.Kind {
	case LinkBond:
		definition["interfaces"] = anyList(desired.Members)
		parameters := map[string]any{"mode": desired.Mode, "mii-monitor-interval": desired.MIIMonMS}
		if desired.Primary != "" {
			parameters["primary"] = desired.Primary
		}
		if desired.LACPRate != "" {
			parameters["lacp-rate"] = desired.LACPRate
		}
		definition["parameters"] = parameters
	case LinkBridge:
		if desired.VLANFiltering {
			return "", fmt.Errorf("netplan has no key for VLAN filtering on a bridge; build the bridge without it and filter on the switch")
		}
		definition["interfaces"] = anyList(desired.Members)
		definition["parameters"] = map[string]any{"stp": desired.STP}
	case LinkVLAN:
		if desired.Protocol != "" && desired.Protocol != "802.1Q" {
			return "", fmt.Errorf("netplan defines 802.1Q VLANs only; it cannot express the protocol %q", desired.Protocol)
		}
		definition["id"] = desired.VLANID
		definition["link"] = desired.Parent
	default:
		return "", fmt.Errorf("netplan cannot build a layer of the kind %q", desired.Kind)
	}
	if desired.MTU != "" && desired.MTU != MTUAuto {
		mtu, err := strconv.Atoi(desired.MTU)
		if err != nil {
			return "", fmt.Errorf("the MTU %q of the layer %s is not a number", desired.MTU, name)
		}
		definition["mtu"] = mtu
	}
	section[name] = definition
	tree[sectionName] = section
	return netplanDocumentText(tree)
}

// netplanDocumentText writes the tree back as the panel's file.
func netplanDocumentText(tree map[string]any) (string, error) {
	tree["version"] = 2
	encoded, err := yaml.Marshal(map[string]any{"network": tree})
	if err != nil {
		return "", err
	}
	return string(encoded), nil
}
