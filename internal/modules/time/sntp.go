package hosttime

import (
	"context"
	"crypto/rand"
	"encoding/binary"
	"math"
	"net"
	"time"
)

// The SNTP query is our own code here, not a tool call, for three reasons.
// First, it needs no root and changes nothing on the host, so a server test
// can go without the helper. Second, no host is sure to have ntpdate or
// sntp, and chronyd -Q works only where chrony is. Third, exactly what the
// operator asks is measured: whether this server answers and by how much
// the host clock differs from it.
const (
	ntpPort = "123"
	// ntpEpoch is the difference between the NTP epoch (1900) and the Unix
	// epoch (1970).
	ntpEpoch = 2208988800
	// secondFraction scales the 32-bit fractional part of a timestamp.
	secondFraction = 1 << 32
)

// Query asks one SNTP question and describes the answer.
//
// The result never lies about what it did not measure: an unreachable
// server has an empty offset, not a zero one.
func Query(ctx context.Context, server string, timeout time.Duration) Probe {
	probe := Probe{Server: server}
	if err := ValidateServer(server); err != nil {
		probe.Error = err.Error()
		return probe
	}
	if timeout <= 0 {
		timeout = 5 * time.Second
	}

	dialer := net.Dialer{Timeout: timeout}
	conn, err := dialer.DialContext(ctx, "udp", net.JoinHostPort(server, ntpPort))
	if err != nil {
		probe.Error = err.Error()
		return probe
	}
	defer func() { _ = conn.Close() }()
	if address, ok := conn.RemoteAddr().(*net.UDPAddr); ok {
		probe.Address = address.IP.String()
	}
	if err := conn.SetDeadline(time.Now().Add(timeout)); err != nil {
		probe.Error = err.Error()
		return probe
	}

	request := make([]byte, 48)
	// LI = 0, version 4, mode 3 (client).
	request[0] = 0x23
	// The transmit timestamp is random, not clock-based: the reply echoes
	// it untouched, so only we can recognise our own question. The host
	// clock stays on our side, where it is more precise anyway.
	transmit := make([]byte, 8)
	if _, err := rand.Read(transmit); err != nil {
		probe.Error = err.Error()
		return probe
	}
	copy(request[40:48], transmit)

	t1 := time.Now()
	if _, err := conn.Write(request); err != nil {
		probe.Error = err.Error()
		return probe
	}
	reply := make([]byte, 48)
	n, err := conn.Read(reply)
	t4 := time.Now()
	if err != nil {
		probe.Error = "the server did not answer: " + err.Error()
		return probe
	}
	if n < 48 {
		probe.Error = "the reply is shorter than an NTP packet"
		return probe
	}
	// The reply must echo our transmit timestamp. Without this check a
	// packet from the side would be enough for the panel to believe
	// somebody else's time.
	for i := 0; i < 8; i++ {
		if reply[24+i] != transmit[i] {
			probe.Error = "the reply does not match the question"
			return probe
		}
	}
	if mode := reply[0] & 0x07; mode != 4 {
		probe.Error = "the reply is not a server reply"
		return probe
	}
	stratum := uint32(reply[1])
	if stratum == 0 {
		// Stratum 0 carries a refusal message ("kiss of death") in the
		// reference field: the server answered, but tells us to stop
		// asking.
		probe.Error = "the server refused service: " + string(reply[12:16])
		return probe
	}
	if stratum > 15 {
		probe.Error = "the server reports itself as unsynchronised"
		return probe
	}

	t2 := timestamp(reply[32:40])
	t3 := timestamp(reply[40:48])
	offset := (t2.Sub(t1).Seconds() + t3.Sub(t4).Seconds()) / 2
	delay := t4.Sub(t1).Seconds() - t3.Sub(t2).Seconds()
	if delay < 0 {
		delay = 0
	}

	probe.Reachable = true
	probe.Stratum = &stratum
	probe.OffsetSeconds = &offset
	probe.DelaySeconds = &delay
	probe.LeapStatus = leapSecondState(string(rune('0' + (reply[0] >> 6))))
	return probe
}

// QueryMany queries the given servers one after another.
func QueryMany(ctx context.Context, servers []string, timeout time.Duration) []Probe {
	probes := make([]Probe, 0, len(servers))
	for _, server := range servers {
		probes = append(probes, Query(ctx, server, timeout))
	}
	return probes
}

// Reachable counts the servers that answered.
func Reachable(probes []Probe) int {
	count := 0
	for _, probe := range probes {
		if probe.Reachable {
			count++
		}
	}
	return count
}

// BestProbe picks the reply with the shortest path.
//
// An offset measured over a slow link is less trustworthy than the same
// offset measured over a fast one, so the time step is judged by the
// measurement with the smallest delay, not by the first at hand.
func BestProbe(probes []Probe) *Probe {
	var best *Probe
	for i := range probes {
		if !probes[i].Reachable || probes[i].OffsetSeconds == nil {
			continue
		}
		if best == nil || smallerDelay(probes[i], *best) {
			best = &probes[i]
		}
	}
	return best
}

func smallerDelay(candidate, current Probe) bool {
	if candidate.DelaySeconds == nil {
		return false
	}
	if current.DelaySeconds == nil {
		return true
	}
	return *candidate.DelaySeconds < *current.DelaySeconds
}

// Steps says whether the measured offset will step the clock.
func Steps(probe *Probe) bool {
	return probe != nil && probe.OffsetSeconds != nil &&
		math.Abs(*probe.OffsetSeconds) >= StepThresholdSeconds
}

// timestamp turns a 64-bit NTP timestamp into a time.
//
// The seconds counter overflows in 2036 and then the eras will have to be
// told apart; until then subtracting the epoch is enough and no more is
// pretended.
func timestamp(field []byte) time.Time {
	seconds := binary.BigEndian.Uint32(field[0:4])
	fraction := binary.BigEndian.Uint32(field[4:8])
	nanoseconds := int64(float64(fraction) / secondFraction * 1e9)
	return time.Unix(int64(seconds)-ntpEpoch, nanoseconds)
}
