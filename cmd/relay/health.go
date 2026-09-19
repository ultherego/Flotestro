package main

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"time"

	"github.com/ultherego/flotestro/internal/relay"
)

// This file puts the health of the relay on a listener of its own.
//
// The listener of the agents cannot carry it: it terminates TLS and asks
// for a certificate of the fleet, and a health check inside the image has
// neither a certificate nor a shell to fetch one with. The health
// listener is plain HTTP on the loopback by default, so the answer stays
// inside the machine or the container, and health_listen in relay.yaml
// moves it where a probe from outside - a kubelet, a load balancer -
// can reach it.

// healthHeaderTimeout bounds the wait for the request line of a probe. A
// health check sends its request at once; anything that does not is not a
// probe, and the relay is not the place to hold a connection open for it.
const healthHeaderTimeout = 5 * time.Second

// healthShutdownTimeout bounds the wait for the health listener on the way
// out. It is short on purpose: the answers are single requests, and the
// spool is what the shutdown time belongs to.
const healthShutdownTimeout = 2 * time.Second

// startHealthListener starts the liveness and readiness of the relay on
// the configured address. An empty address is an operator who turned the
// listener off, which is said once and is no error.
//
// A listener that cannot be bound is: the operator asked for a health
// answer and would get none, while the container runtime would read the
// silence as a relay to restart.
func startHealthListener(address string, health *relay.Health, log *slog.Logger) (*http.Server, error) {
	if address == "" {
		log.Info("the health listener of the relay is turned off by the configuration")
		return nil, nil
	}
	listener, err := net.Listen("tcp", address)
	if err != nil {
		return nil, fmt.Errorf("the health listener of the relay at %s: %w", address, err)
	}
	server := &http.Server{
		Handler:           health.Handler(),
		ReadHeaderTimeout: healthHeaderTimeout,
	}
	go func() {
		if err := server.Serve(listener); err != nil && !errors.Is(err, http.ErrServerClosed) {
			// The relay keeps working without its health answers: a site
			// that carries results is worth more than the answer to a
			// probe. The operator reads the line and the runtime sees the
			// probe fail.
			log.Error("the health listener of the relay ended", "address", address, "err", err)
		}
	}()
	log.Info("the health listener of the relay is up", "address", address,
		"liveness", relay.HealthPathLive, "readiness", relay.HealthPathReady)
	return server, nil
}

// stopHealthListener closes the health listener, if there is one.
func stopHealthListener(server *http.Server) {
	if server == nil {
		return
	}
	ctx, cancel := context.WithTimeout(context.Background(), healthShutdownTimeout)
	defer cancel()
	_ = server.Shutdown(ctx)
}
