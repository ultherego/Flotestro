package firewall

import (
	"fmt"
	"regexp"
	"strconv"
	"strings"
)

// FirewallCmdPath points at the firewalld tool.
const FirewallCmdPath = "/usr/bin/firewall-cmd"

// PermanentFlag names the configuration a zone change writes. firewalld keeps
// the running configuration and the permanent one apart, so the flag is spelled
// once here and every reader and writer of that configuration takes it from
// here.
const PermanentFlag = "--permanent"

// ZoneWriteArguments is the command that writes one operation into the
// permanent configuration of a zone: the only place the panel writes a zone.
// ZoneListArguments(true) reads back what this writes.
func ZoneWriteArguments(zone, operation string) []string {
	return []string{FirewallCmdPath, PermanentFlag, "--zone=" + zone, operation}
}

// ReloadArguments makes the permanent configuration the running one. It
// replaces the whole runtime configuration and not only the zone the change
// touched, so it carries every pending difference with it.
func ReloadArguments() []string {
	return []string{FirewallCmdPath, "--reload"}
}

// ZoneListArguments lists the zones of one configuration: the permanent one a
// change writes, or the running one the host filters with now.
func ZoneListArguments(permanent bool) []string {
	if permanent {
		return []string{FirewallCmdPath, PermanentFlag, "--list-all-zones"}
	}
	return []string{FirewallCmdPath, "--list-all-zones"}
}

// DefaultZoneArguments asks which zone an unassigned interface lands in.
// firewalld keeps that name in firewalld.conf and uses it for both
// configurations, so it is asked for once and attributed to both.
func DefaultZoneArguments() []string {
	return []string{FirewallCmdPath, "--get-default-zone"}
}

// ServicePortsArguments asks which ports a service name stands for in the
// configuration a zone change writes.
func ServicePortsArguments(service string) []string {
	return []string{FirewallCmdPath, PermanentFlag, "--service=" + service, "--get-ports"}
}

var zoneHeader = regexp.MustCompile(`^(\S+)(?:\s+\(([^)]*)\))?$`)

// ParseZones reads the output of "firewall-cmd --list-all-zones".
func ParseZones(output, defaultZone string) []Zone {
	var zones []Zone
	var current *Zone

	for _, raw := range strings.Split(output, "\n") {
		if strings.TrimSpace(raw) == "" {
			continue
		}
		// A zone header starts at the beginning of the row; the zone fields are
		// indented.
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
	// The write goes into the permanent configuration and the reload makes it
	// the running one. Both steps are built from one place, so the reader of
	// that configuration cannot drift away from the writer of it.
	steps := [][]string{ZoneWriteArguments(zone, operation), ReloadArguments()}
	return steps, nil
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
	steps := [][]string{ZoneWriteArguments(zone, operation), ReloadArguments()}
	return steps, nil
}

// ParseServicePorts reads the answer of "firewall-cmd --service=X --get-ports":
// entries of the form 443/tcp separated by spaces. A word that is not a port
// is left out rather than guessed at.
func ParseServicePorts(output string) []int {
	var ports []int
	for _, field := range strings.Fields(output) {
		number, _, _ := strings.Cut(field, "/")
		if value, err := strconv.Atoi(number); err == nil && value > 0 && value <= 65535 {
			ports = append(ports, value)
		}
	}
	return ports
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
