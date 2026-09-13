package dns

import (
	"strconv"
	"strings"
)

// ParseResolvConf reads the classic resolver file.
func ParseResolvConf(content string) (servers, domains []string) {
	for _, line := range strings.Split(content, "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") || strings.HasPrefix(line, ";") {
			continue
		}
		fields := strings.Fields(line)
		switch fields[0] {
		case "nameserver":
			if len(fields) > 1 {
				servers = append(servers, fields[1])
			}
		case "search":
			domains = append(domains, fields[1:]...)
		case "domain":
			// "domain" is the older form of a single search domain.
			if len(fields) > 1 {
				domains = append(domains, fields[1])
			}
		}
	}
	return servers, domains
}

// ResolvConfOwner decides who writes the resolver file.
//
// The owner decides whether the panel may change anything: a file belonging
// to a service is overwritten on the next network event, so writing into it
// would be a change that vanishes on its own.
func ResolvConfOwner(linkTarget, content string) string {
	switch {
	case strings.Contains(linkTarget, "/systemd/resolve/"):
		return OwnerResolved
	case strings.Contains(linkTarget, "/NetworkManager/"):
		return OwnerNetworkManager
	}
	header := strings.ToLower(firstLines(content, 5))
	switch {
	case strings.Contains(header, "systemd-resolved"):
		return OwnerResolved
	case strings.Contains(header, "networkmanager"):
		return OwnerNetworkManager
	case strings.Contains(header, "dhcpcd"), strings.Contains(header, "dhclient"),
		strings.Contains(header, "resolvconf"):
		return OwnerDHCP
	case content == "":
		// An empty file says nothing about the owner, and guessing "manual"
		// would encourage the panel to write over something it does not
		// understand.
		return OwnerUnknown
	}
	return OwnerManual
}

func firstLines(content string, count int) string {
	lines := strings.Split(content, "\n")
	if len(lines) > count {
		lines = lines[:count]
	}
	return strings.Join(lines, "\n")
}

// ParseResolvectl reads the output of "resolvectl status".
//
// The format is meant for humans, so the parser sticks strictly to the labels
// systemd has printed for years and assumes no section order. Values it does
// not understand are simply skipped - better to show less than to invent a
// per-link DNS the operator will later rely on.
func ParseResolvectl(output string) Snapshot {
	snapshot := Snapshot{}
	var current *Link

	for _, line := range strings.Split(output, "\n") {
		trimmed := strings.TrimSpace(line)
		if trimmed == "" {
			continue
		}
		if trimmed == "Global" {
			current = nil
			continue
		}
		if strings.HasPrefix(trimmed, "Link ") {
			snapshot.Links = append(snapshot.Links, parseLinkHeader(trimmed))
			current = &snapshot.Links[len(snapshot.Links)-1]
			continue
		}

		key, value, ok := strings.Cut(trimmed, ":")
		if !ok {
			// Continuation of the previous row: systemd wraps the protocol
			// list onto two rows when it is long.
			if strings.Contains(trimmed, "DNSSEC=") {
				if current != nil {
					assignProtocols(current, trimmed)
				} else {
					snapshot.DNSSEC, snapshot.DNSOverTLS = fromProtocols(trimmed, snapshot.DNSSEC, snapshot.DNSOverTLS)
				}
			}
			continue
		}
		key = strings.TrimSpace(key)
		value = strings.TrimSpace(value)

		switch key {
		case "Protocols":
			if current != nil {
				assignProtocols(current, value)
			} else {
				snapshot.DNSSEC, snapshot.DNSOverTLS = fromProtocols(value, snapshot.DNSSEC, snapshot.DNSOverTLS)
			}
		case "resolv.conf mode":
			snapshot.Mode = value
		case "DNS Servers":
			if current != nil {
				current.Servers = append(current.Servers, strings.Fields(value)...)
			} else {
				snapshot.Servers = append(snapshot.Servers, strings.Fields(value)...)
			}
		case "Current DNS Server":
			// The current server is one of the list; it is not added twice.
		case "DNS Domain":
			domains := strings.Fields(value)
			if current != nil {
				current.Domains = append(current.Domains, domains...)
			} else {
				snapshot.SearchDomains = append(snapshot.SearchDomains, domains...)
			}
		case "Default Route":
			if current != nil {
				flag := value == "yes"
				current.DefaultRoute = &flag
			}
		}
	}
	return snapshot
}

func parseLinkHeader(line string) Link {
	// Format: "Link 2 (enp0s3)".
	link := Link{}
	fields := strings.Fields(line)
	if len(fields) >= 2 {
		if index, err := strconv.Atoi(fields[1]); err == nil {
			link.Index = index
		}
	}
	if start := strings.Index(line, "("); start >= 0 {
		if end := strings.Index(line[start:], ")"); end > 0 {
			link.Name = line[start+1 : start+end]
		}
	}
	return link
}

func assignProtocols(link *Link, value string) {
	if link == nil {
		return
	}
	link.DNSSEC, link.DNSOverTLS = fromProtocols(value, link.DNSSEC, link.DNSOverTLS)
}

// fromProtocols extracts the DNSSEC and DNS-over-TLS state from a protocol
// row.
//
// systemd writes them as "DNSSEC=no/unsupported" and "-DNSOverTLS" or
// "+DNSOverTLS". Minus and plus mean disabled and enabled; a missing entry
// leaves the state undetermined, because older versions do not print it at
// all.
func fromProtocols(value, dnssec, dot string) (string, string) {
	for _, field := range strings.Fields(value) {
		switch {
		case strings.HasPrefix(field, "DNSSEC="):
			dnssec = strings.TrimPrefix(field, "DNSSEC=")
		case field == "+DNSOverTLS":
			dot = "yes"
		case field == "-DNSOverTLS":
			dot = "no"
		case strings.HasPrefix(field, "DNSOverTLS="):
			dot = strings.TrimPrefix(field, "DNSOverTLS=")
		}
	}
	return dnssec, dot
}

// ValidTestName checks a name requested for resolution.
//
// The name goes to the command as an argument, so it has to be a name and
// not anything else: an address, a flag and a path are not a query here.
func ValidTestName(name string) bool {
	if name == "" || len(name) > 253 || strings.HasPrefix(name, "-") {
		return false
	}
	labels := strings.Split(strings.TrimSuffix(name, "."), ".")
	for _, label := range labels {
		if label == "" || len(label) > 63 {
			return false
		}
		for _, r := range label {
			allowed := (r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') ||
				(r >= '0' && r <= '9') || r == '-' || r == '_'
			if !allowed {
				return false
			}
		}
	}
	return true
}
