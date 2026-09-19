package agent

import (
	"context"
	"net"
	"os"
	"strconv"
	"time"
)

// Notify sends a state to the service manager over NOTIFY_SOCKET.
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

// WatchdogInterval returns how often the service manager expects a sign of
// life, halved so that one late ping does not end the process, and zero when
// no watchdog is set.
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

// KeepWatchdogFed pings the service manager until the context ends.
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
