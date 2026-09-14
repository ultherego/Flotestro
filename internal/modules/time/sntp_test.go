package hosttime

import (
	"context"
	"net"
	"sync/atomic"
	"testing"
	"time"
)

// A server answering on a loopback socket: it drops the first questions
// and answers the one after them, the way a lossy path does.
func lossyServer(t *testing.T, drop int) (string, *atomic.Int32) {
	t.Helper()
	conn, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = conn.Close() })
	seen := new(atomic.Int32)
	go func() {
		request := make([]byte, 48)
		for {
			n, from, err := conn.ReadFromUDP(request)
			if err != nil {
				return
			}
			if int(seen.Add(1)) <= drop || n < 48 {
				continue
			}
			reply := make([]byte, 48)
			reply[0] = 0x24 // LI 0, version 4, mode 4 (server)
			reply[1] = 2    // stratum
			copy(reply[24:32], request[40:48])
			now := uint64(time.Now().Unix()+ntpEpoch) << 32
			for i := 0; i < 8; i++ {
				reply[32+i] = byte(now >> (56 - 8*i))
				reply[40+i] = byte(now >> (56 - 8*i))
			}
			_, _ = conn.WriteToUDP(reply, from)
		}
	}()
	return conn.LocalAddr().String(), seen
}

func TestQueryAsksAgainWhenADatagramIsLost(t *testing.T) {
	address, seen := lossyServer(t, queryAttempts-1)
	host, port, _ := net.SplitHostPort(address)
	probe := queryAt(context.Background(), host, port, 300*time.Millisecond)
	if !probe.Reachable {
		t.Fatalf("the server answered the %dth question, yet the probe says %q", queryAttempts, probe.Error)
	}
	if int(seen.Load()) != queryAttempts {
		t.Fatalf("questions asked = %d, want %d", seen.Load(), queryAttempts)
	}
}

func TestQueryGivesUpAfterTheLastAttempt(t *testing.T) {
	address, seen := lossyServer(t, queryAttempts)
	host, port, _ := net.SplitHostPort(address)
	probe := queryAt(context.Background(), host, port, 200*time.Millisecond)
	if probe.Reachable || probe.Error == "" {
		t.Fatalf("a silent server counts as reachable: %+v", probe)
	}
	if int(seen.Load()) != queryAttempts {
		t.Fatalf("questions asked = %d, want %d", seen.Load(), queryAttempts)
	}
}
