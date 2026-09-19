// Command container-healthcheck answers one question from inside an image that
// has no shell: is the process in this container healthy.
package main

import (
	"context"
	"flag"
	"fmt"
	"net"
	"net/http"
	"os"
	"time"

	"github.com/ultherego/flotestro/internal/config"
)

// defaultTimeout bounds the whole check.
const defaultTimeout = 3 * time.Second

// defaultAdminAddr repeats the default of the control plane deliberately.
const defaultAdminAddr = "127.0.0.1:8080"

func main() {
	address := flag.String("addr", config.Env("FLOTESTRO_ADMIN_ADDR", defaultAdminAddr),
		"the address to check; by default the admin listener of the control plane")
	// The relay terminates TLS with client certificates and has no health
	// endpoint yet, so the only thing that can be asked about it from inside its
	// own container is whether its listener accepts a connection.
	tcpOnly := flag.Bool("tcp", false,
		"check that the address accepts a connection instead of asking /healthz")
	timeout := flag.Duration("timeout", defaultTimeout, "the limit for the whole check")
	flag.Parse()

	if err := check(*address, *tcpOnly, *timeout); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

func check(address string, tcpOnly bool, timeout time.Duration) error {
	target, err := reachableAddress(address)
	if err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	if tcpOnly {
		return connect(ctx, target)
	}
	return askHealthz(ctx, target, timeout)
}

// reachableAddress turns the address a listener is bound to into an address it
// can be dialled at.
func reachableAddress(address string) (string, error) {
	host, port, err := net.SplitHostPort(address)
	if err != nil {
		return "", fmt.Errorf("the address %q is not host:port: %w", address, err)
	}
	if port == "" {
		return "", fmt.Errorf("the address %q names no port", address)
	}
	switch host {
	case "", "0.0.0.0":
		host = "127.0.0.1"
	case "::", "[::]":
		host = "::1"
	}
	return net.JoinHostPort(host, port), nil
}

// connect is the liveness check: the listener is there and accepts.
func connect(ctx context.Context, target string) error {
	dialer := net.Dialer{}
	conn, err := dialer.DialContext(ctx, "tcp", target)
	if err != nil {
		return fmt.Errorf("the listener at %s does not accept connections: %w", target, err)
	}
	// The connection was the answer; a failure to close it afterwards says
	// nothing about the health of the listener.
	_ = conn.Close()
	return nil
}

// askHealthz asks the control plane the question it answers itself: the
// endpoint pings the database, so a panel whose database is gone reports
// service unavailable and this check fails - which is what an operator means.
func askHealthz(ctx context.Context, target string, timeout time.Duration) error {
	url := "http://" + target + "/healthz"
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return fmt.Errorf("the request for %s was not built: %w", url, err)
	}
	client := &http.Client{
		Timeout: timeout,
		// A redirect is not an answer to this question: the endpoint either replies
		// or it does not, and following a redirect would let a misconfigured
		// installation report the health of somewhere else.
		CheckRedirect: func(*http.Request, []*http.Request) error {
			return http.ErrUseLastResponse
		},
		// No proxy, whatever the environment says.
		Transport: &http.Transport{Proxy: nil, DisableKeepAlives: true},
	}
	response, err := client.Do(request)
	if err != nil {
		return fmt.Errorf("%s did not answer: %w", url, err)
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		return fmt.Errorf("%s answered %s", url, response.Status)
	}
	return nil
}
