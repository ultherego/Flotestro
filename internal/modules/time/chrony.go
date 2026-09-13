package hosttime

import (
	"strconv"
	"strings"
	"time"
)

// sourceModes and sourceStates translate the chrony symbols into words.
//
// The operator is not meant to remember that "^*" means "selected server"
// and "x" - "a source that lies". The symbol stays in the result only when
// its meaning is unknown: an unknown state is not an empty state here.
var sourceModes = map[string]string{
	"^": "server",
	"=": "peer",
	"#": "local clock",
}

var sourceStates = map[string]string{
	"*": "selected",
	"+": "candidate",
	"-": "not combined",
	"?": "unreachable",
	"x": "false ticker",
	"~": "too variable",
}

// ParseTracking reads the output of "chronyc -c tracking".
//
// The CSV mode is a deliberate choice: the plain chrony output is a table
// for humans, and its headers and units change between versions. The field
// order in CSV is part of the tool's contract.
func ParseTracking(output string) Snapshot {
	snapshot := Snapshot{Service: DaemonChrony}
	line := strings.TrimSpace(output)
	if line == "" {
		return snapshot
	}
	fields := strings.Split(strings.Split(line, "\n")[0], ",")
	if len(fields) < 14 {
		return snapshot
	}

	// The reference "0.0.0.0" or an empty identifier means a daemon that
	// has not selected a source yet. That is not a source with a zero name.
	name := strings.TrimSpace(fields[1])
	if name != "" && name != "0.0.0.0" && fields[0] != "00000000" {
		snapshot.ReferenceName = name
	}
	if stratum, err := strconv.ParseUint(strings.TrimSpace(fields[2]), 10, 32); err == nil && stratum > 0 {
		value := uint32(stratum)
		snapshot.Stratum = &value
	}
	if seconds, err := strconv.ParseFloat(strings.TrimSpace(fields[3]), 64); err == nil && seconds > 0 {
		moment := time.Unix(int64(seconds), 0).UTC()
		snapshot.LastSyncAt = &moment
	}
	snapshot.OffsetSeconds = number(fields[4])
	snapshot.FrequencyPPM = number(fields[7])
	snapshot.RootDelaySeconds = number(fields[10])
	snapshot.RootDispersionSeconds = number(fields[11])
	snapshot.LeapStatus = strings.TrimSpace(fields[13])

	// A daemon without a selected source is not synchronised, although it
	// runs.
	synchronized := snapshot.ReferenceName != "" && snapshot.Stratum != nil
	snapshot.Synchronized = &synchronized
	return snapshot
}

// ParseSources reads the output of "chronyc -c sources".
func ParseSources(output string) []Source {
	var sources []Source
	for _, line := range strings.Split(output, "\n") {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		fields := strings.Split(line, ",")
		if len(fields) < 10 {
			continue
		}
		source := Source{
			Address:      strings.TrimSpace(fields[2]),
			Mode:         nameOrSymbol(sourceModes, fields[0]),
			State:        nameOrSymbol(sourceStates, fields[1]),
			Reachability: strings.TrimSpace(fields[5]),
		}
		if source.Address == "" {
			continue
		}
		if stratum, err := strconv.ParseUint(strings.TrimSpace(fields[3]), 10, 32); err == nil {
			value := uint32(stratum)
			source.Stratum = &value
		}
		// Chrony reports the polling interval as a base-2 logarithm of
		// seconds.
		if poll, err := strconv.Atoi(strings.TrimSpace(fields[4])); err == nil && poll >= 0 && poll < 24 {
			seconds := 1 << uint(poll)
			source.PollSeconds = &seconds
		}
		if last, err := strconv.ParseInt(strings.TrimSpace(fields[6]), 10, 64); err == nil {
			source.LastRxSeconds = &last
		}
		source.OffsetSeconds = number(fields[7])
		source.ErrorSeconds = number(fields[9])
		sources = append(sources, source)
	}
	return sources
}

// DropInDir points at the directory the panel writes the servers to.
//
// The panel does not rewrite the main chrony file: it holds platform
// decisions (keys, access, clock drivers) whose change does not belong to
// the "set time servers" operation. Instead it reads which directory the
// daemon itself includes, and writes only there. A host without such a
// directory gets a refusal with a reason, not a file chrony never reads.
func DropInDir(configuration string) (dir, kind string) {
	for _, line := range strings.Split(configuration, "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") || strings.HasPrefix(line, "!") ||
			strings.HasPrefix(line, ";") || strings.HasPrefix(line, "%") {
			continue
		}
		directive, rest, ok := strings.Cut(line, " ")
		if !ok {
			continue
		}
		path := strings.TrimSpace(rest)
		switch strings.ToLower(directive) {
		case "confdir":
			// The directive accepts several space-separated directories;
			// the first is written to, because it takes precedence.
			if first := firstPath(path); first != "" {
				return first, KindConfiguration
			}
		case "sourcedir":
			if first := firstPath(path); first != "" && !strings.HasPrefix(first, "/run") {
				// A directory in /run vanishes after a reboot - it is the
				// place for DHCP sources, not for the panel's desired state.
				return first, KindSources
			}
		case "include":
			// The pattern "include /etc/chrony.d/*.conf" points at a
			// configuration directory just like confdir, only in the older
			// syntax.
			if dir := dirFromPattern(firstPath(path)); dir != "" {
				return dir, KindConfiguration
			}
		}
	}
	return "", ""
}

// ParseServers reads the time servers from a chrony configuration file.
func ParseServers(content, source string, managed bool) []Server {
	var servers []Server
	for _, line := range strings.Split(content, "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") || strings.HasPrefix(line, ";") {
			continue
		}
		directive, rest, ok := strings.Cut(line, " ")
		if !ok {
			continue
		}
		directive = strings.ToLower(directive)
		if directive != "server" && directive != "pool" && directive != "peer" {
			continue
		}
		fields := strings.Fields(rest)
		if len(fields) == 0 {
			continue
		}
		servers = append(servers, Server{
			Address: fields[0],
			Source:  source,
			Pool:    directive == "pool",
			Managed: managed,
		})
	}
	return servers
}

// ParseTimesyncdNTP reads the server list from a timesyncd file.
func ParseTimesyncdNTP(content, source string, managed bool) []Server {
	var servers []Server
	for _, line := range strings.Split(content, "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") || strings.HasPrefix(line, ";") {
			continue
		}
		key, value, ok := strings.Cut(line, "=")
		if !ok || !strings.EqualFold(strings.TrimSpace(key), "NTP") {
			continue
		}
		for _, address := range strings.Fields(value) {
			servers = append(servers, Server{Address: address, Source: source, Managed: managed})
		}
	}
	return servers
}

func firstPath(value string) string {
	fields := strings.Fields(value)
	if len(fields) == 0 {
		return ""
	}
	return fields[0]
}

// dirFromPattern turns "/etc/chrony.d/*.conf" into a directory.
func dirFromPattern(pattern string) string {
	if !strings.Contains(pattern, "*") {
		return ""
	}
	dir := pattern[:strings.LastIndex(pattern, "/")+1]
	return strings.TrimSuffix(dir, "/")
}

func nameOrSymbol(dictionary map[string]string, field string) string {
	symbol := strings.TrimSpace(field)
	if name, ok := dictionary[symbol]; ok {
		return name
	}
	return symbol
}

// number reads a floating-point field. An unreadable field stays a nil
// pointer: no measurement is not a measurement equal to zero.
func number(field string) *float64 {
	value, err := strconv.ParseFloat(strings.TrimSpace(field), 64)
	if err != nil {
		return nil
	}
	return &value
}
