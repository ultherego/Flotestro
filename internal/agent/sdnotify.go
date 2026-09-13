package agent

import (
	"context"
	"net"
	"os"
	"strconv"
	"time"
)

// Notify sends a state to the service manager over NOTIFY_SOCKET. Without
// the variable - outside systemd, in a test - it does nothing and says so
// with false. The protocol is a datagram of "KEY=VALUE" lines; no library
// is needed for that.
func Notify(state string) bool {
	path := os.Getenv("NOTIFY_SOCKET")
	if path == "" {
		return false
	}
	conn, err := net.DialUnix("unixgram", nil, &net.UnixAddr{Name: path, Net: "unixgram"})
	if err != nil {
		return false
	}
	defer conn.Close()
	_, err = conn.Write([]byte(state))
	return err == nil
}

// WatchdogInterval returns how often the service manager expects a sign
// of life, halved so that one late ping does not end the process, and
// zero when no watchdog is set. WATCHDOG_PID names the process the setting
// is for; a child that inherited the variable must not answer for its
// parent.
func WatchdogInterval() time.Duration {
	if pid := os.Getenv("WATCHDOG_PID"); pid != "" && pid != strconv.Itoa(os.Getpid()) {
		return 0
	}
	usec, err := strconv.ParseInt(os.Getenv("WATCHDOG_USEC"), 10, 64)
	if err != nil || usec <= 0 {
		return 0
	}
	return time.Duration(usec) * time.Microsecond / 2
}

// KeepWatchdogFed pings the service manager until the context ends. The
// ping says that the process is alive and its scheduler is not deadlocked
// - not that the host is connected: a host waiting out a network outage
// is healthy and must not be restarted for it.
func KeepWatchdogFed(ctx context.Context, interval time.Duration) {
	if interval <= 0 {
		return
	}
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			Notify("WATCHDOG=1")
		}
	}
}
