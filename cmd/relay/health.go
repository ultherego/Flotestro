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

// healthHeaderTimeout bounds the wait for the request line of a probe.
const healthHeaderTimeout = 5 * time.Second

// healthShutdownTimeout bounds the wait for the health listener on the way
// out.
const healthShutdownTimeout = 2 * time.Second

// startHealthListener starts the liveness and readiness of the relay on the
// configured address.
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
			// The relay keeps working without its health answers: a site that carries
			// results is worth more than the answer to a probe.
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
