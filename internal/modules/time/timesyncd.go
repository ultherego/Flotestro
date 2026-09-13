package hosttime

import (
	"strconv"
	"strings"
)

// TimesyncdState is the state of the systemd-timesyncd daemon.
//
// timesyncd does not report the clock offset: it says whom it talked to
// and what it got in reply, but does not compute how late the host is. That
// is why the offset field stays empty and the panel measures it with its
// own query - that is the whole difference between "the daemon runs" and
// "the clock is good".
type TimesyncdState struct {
	ServerName     string
	ServerAddress  string
	Servers        []Server
	Stratum        *uint32
	RootDelay      *float64
	RootDispersion *float64
	LeapStatus     string
	FrequencyPPM   *float64
}

// ParseTimedatectl reads the output of "timedatectl show".
//
// The host time is not taken from here: the agent stands on the same host,
// so its own clock is the same clock, and "TimeUSec" is text for humans
// that changes its form with the zone and the language.
func ParseTimedatectl(output string) Snapshot {
	snapshot := Snapshot{}
	for _, line := range strings.Split(output, "\n") {
		key, value, ok := strings.Cut(strings.TrimSpace(line), "=")
		if !ok {
			continue
		}
		value = strings.TrimSpace(value)
		switch key {
		case "Timezone":
			snapshot.Timezone = value
		case "LocalRTC":
			snapshot.RTCInLocalTime = yes(value)
		case "NTP":
			snapshot.NTPEnabled = yes(value)
		case "NTPSynchronized":
			snapshot.Synchronized = yes(value)
		}
	}
	return snapshot
}

// ParseTimesync reads the output of "timedatectl show-timesync --all".
func ParseTimesync(output, source string) TimesyncdState {
	state := TimesyncdState{}
	for _, line := range strings.Split(output, "\n") {
		key, value, ok := strings.Cut(strings.TrimSpace(line), "=")
		if !ok {
			continue
		}
		value = strings.TrimSpace(value)
		switch key {
		case "ServerName":
			state.ServerName = value
		case "ServerAddress":
			state.ServerAddress = value
		case "SystemNTPServers", "LinkNTPServers", "RuntimeNTPServers", "FallbackNTPServers":
			// The entry source answers the question "where did it come
			// from": a link server comes from DHCP, a fallback one from the
			// systemd build.
			origin := source
			switch key {
			case "LinkNTPServers":
				origin = "DHCP"
			case "RuntimeNTPServers":
				origin = "runtime"
			case "FallbackNTPServers":
				origin = "systemd fallback"
			}
			for _, address := range strings.Fields(value) {
				state.Servers = append(state.Servers, Server{Address: address, Source: origin})
			}
		case "Frequency":
			// Systemd reports the frequency in units of 2^-16 ppm.
			if raw, err := strconv.ParseFloat(value, 64); err == nil {
				ppm := raw / 65536
				state.FrequencyPPM = &ppm
			}
		case "NTPMessage":
			readNTPMessage(value, &state)
		}
	}
	return state
}

// readNTPMessage takes apart the NTPMessage={ Leap=0, Stratum=2, ... }
// field.
func readNTPMessage(value string, state *TimesyncdState) {
	value = strings.TrimSpace(strings.TrimSuffix(strings.TrimPrefix(strings.TrimSpace(value), "{"), "}"))
	for _, field := range strings.Split(value, ",") {
		key, data, ok := strings.Cut(strings.TrimSpace(field), "=")
		if !ok {
			continue
		}
		data = strings.TrimSpace(data)
		switch key {
		case "Leap":
			state.LeapStatus = leapSecondState(data)
		case "Stratum":
			if stratum, err := strconv.ParseUint(data, 10, 32); err == nil && stratum > 0 {
				n := uint32(stratum)
				state.Stratum = &n
			}
		case "RootDelay":
			state.RootDelay = duration(data)
		case "RootDispersion":
			state.RootDispersion = duration(data)
		}
	}
}

// leapSecondState translates the Leap field into a word.
func leapSecondState(value string) string {
	switch value {
	case "0":
		return "Normal"
	case "1":
		return "Insert second"
	case "2":
		return "Delete second"
	case "3":
		return "Not synchronised"
	}
	return value
}

// duration reads a time in the form systemd writes it: "1.907ms", "5s",
// "1min 4s". An unreadable value stays a nil pointer.
func duration(value string) *float64 {
	value = strings.TrimSpace(value)
	if value == "" {
		return nil
	}
	sum := 0.0
	recognised := false
	for _, part := range strings.Fields(value) {
		n, unit := splitUnit(part)
		if unit == "" {
			continue
		}
		factor, ok := units[unit]
		if !ok {
			continue
		}
		sum += n * factor
		recognised = true
	}
	if !recognised {
		return nil
	}
	return &sum
}

var units = map[string]float64{
	"us": 1e-6, "µs": 1e-6, "ms": 1e-3, "s": 1, "min": 60, "h": 3600,
}

func splitUnit(part string) (float64, string) {
	boundary := 0
	for boundary < len(part) {
		c := part[boundary]
		if (c >= '0' && c <= '9') || c == '.' || c == '-' || c == '+' {
			boundary++
			continue
		}
		break
	}
	n, err := strconv.ParseFloat(part[:boundary], 64)
	if err != nil {
		return 0, ""
	}
	return n, strings.TrimSpace(part[boundary:])
}

// yes turns a tool answer into a boolean. An answer that is not understood
// stays a nil pointer, not false.
func yes(value string) *bool {
	switch strings.ToLower(value) {
	case "yes", "true", "1", "on":
		t := true
		return &t
	case "no", "false", "0", "off":
		f := false
		return &f
	}
	return nil
}
