package firewall

import (
	"fmt"
	"regexp"
	"strings"
)

// FirewallCmdPath points at the firewalld tool.
const FirewallCmdPath = "/usr/bin/firewall-cmd"

var zoneHeader = regexp.MustCompile(`^(\S+)(?:\s+\(([^)]*)\))?$`)

// ParseZones reads the output of "firewall-cmd --list-all-zones".
//
// firewalld describes access with zones, not rules: the operator's question
// is "what is open on this interface", not "which rule matches first".
// Rewriting that into a rule list would lose the difference.
func ParseZones(output, defaultZone string) []Zone {
	var zones []Zone
	var current *Zone

	for _, raw := range strings.Split(output, "\n") {
		if strings.TrimSpace(raw) == "" {
			continue
		}
		// A zone header starts at the beginning of the row; the zone fields
		// are indented. That is the only thing telling them apart in this
		// format.
		if !strings.HasPrefix(raw, " ") && !strings.HasPrefix(raw, "\t") {
			fields := zoneHeader.FindStringSubmatch(strings.TrimSpace(raw))
			if fields == nil {
				continue
			}
			markers := fields[2]
			zones = append(zones, Zone{
				Name:    fields[1],
				Active:  strings.Contains(markers, "active"),
				Default: strings.Contains(markers, "default") || fields[1] == defaultZone,
			})
			current = &zones[len(zones)-1]
			continue
		}
		if current == nil {
			continue
		}
		key, value, ok := strings.Cut(strings.TrimSpace(raw), ":")
		if !ok {
			continue
		}
		value = strings.TrimSpace(value)
		switch key {
		case "target":
			current.Target = value
		case "interfaces":
			current.Interfaces = strings.Fields(value)
		case "sources":
			current.Sources = strings.Fields(value)
		case "services":
			current.Services = strings.Fields(value)
		case "ports":
			current.Ports = strings.Fields(value)
		}
	}
	return zones
}

// PortArguments assembles the command opening a port in a zone.
//
// The change is permanent and reloaded at once: firewalld keeps the runtime
// and the permanent state separately, and a change in only one of them
// vanishes after a reboot or after a reload - each time at a different
// moment.
func PortArguments(zone, port, protocol string, open bool) ([][]string, error) {
	if err := validateZone(zone); err != nil {
		return nil, err
	}
	if err := validatePort(port); err != nil {
		return nil, err
	}
	if protocol != "tcp" && protocol != "udp" {
		return nil, fmt.Errorf("a port concerns tcp or udp, not %q", protocol)
	}
	operation := "--add-port=" + port + "/" + protocol
	if !open {
		operation = "--remove-port=" + port + "/" + protocol
	}
	return [][]string{
		{FirewallCmdPath, "--permanent", "--zone=" + zone, operation},
		{FirewallCmdPath, "--reload"},
	}, nil
}

// ServiceArguments assembles the command enabling a service in a zone.
func ServiceArguments(zone, service string, enable bool) ([][]string, error) {
	if err := validateZone(zone); err != nil {
		return nil, err
	}
	if !serviceName.MatchString(service) {
		return nil, fmt.Errorf("invalid service name %q", service)
	}
	operation := "--add-service=" + service
	if !enable {
		operation = "--remove-service=" + service
	}
	return [][]string{
		{FirewallCmdPath, "--permanent", "--zone=" + zone, operation},
		{FirewallCmdPath, "--reload"},
	}, nil
}

var (
	zoneName    = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9_-]{0,16}$`)
	serviceName = regexp.MustCompile(`^[a-z0-9][a-z0-9_.-]{0,31}$`)
)

func validateZone(zone string) error {
	if !zoneName.MatchString(zone) {
		return fmt.Errorf("invalid zone name %q", zone)
	}
	return nil
}
