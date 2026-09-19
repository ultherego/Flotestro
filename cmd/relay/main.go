// Command flotestro-relay mediates between the agents of one site and the
// centre.
package main

import (
	"context"
	"crypto/tls"
	"errors"
	"flag"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"golang.org/x/net/http2"

	"github.com/ultherego/flotestro/internal/agent"
	"github.com/ultherego/flotestro/internal/buildinfo"
	"github.com/ultherego/flotestro/internal/config"
	"github.com/ultherego/flotestro/internal/ctl"
	"github.com/ultherego/flotestro/internal/relay"
	"github.com/ultherego/flotestro/internal/relayconfig"
)

// the version of the relay is the version of the whole release: the relay and
// the agent come from one source and must not drift apart in their number.
var version = buildinfo.Version

func main() {
	log := slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelInfo}))
	if err := run(os.Args[1:], log); err != nil {
		log.Error("the relay ended with an error", "err", err)
		os.Exit(1)
	}
}

func run(args []string, log *slog.Logger) error {
	if len(args) == 0 {
		return fmt.Errorf("usage: flotestro-relay <run|enroll|config|version>")
	}
	switch args[0] {
	case "run":
		return runCommand(args[1:], log)
	case "enroll":
		return enrollCommand(args[1:], log)
	case "config":
		return configCommand(args[1:])
	case "version":
		fmt.Println(buildinfo.Describe("flotestro-relay"))
		return nil
	default:
		return fmt.Errorf("unknown command %q", args[0])
	}
}

// configCommand checks the configuration file and shows what follows from it.
func configCommand(args []string) error {
	flags := flag.NewFlagSet("config", flag.ContinueOnError)
	path := flags.String("config", relayconfig.DefaultPath, "the configuration file of the relay")
	if err := flags.Parse(args); err != nil {
		return err
	}
	action := "validate"
	if flags.NArg() > 0 {
		action = flags.Arg(0)
	}
	cfg, err := relayconfig.Load(*path)
	if err != nil {
		return err
	}
	switch action {
	case "validate":
		fmt.Printf("the configuration is correct: %s\n", *path)
		return nil
	case "show":
		fmt.Printf("name:            %s\n", cfg.Relay.Name)
		fmt.Printf("site:            %s\n", cfg.Relay.Site)
		fmt.Printf("listen:          %s\n", cfg.Relay.Listen)
		fmt.Printf("network names:   %s\n", strings.Join(cfg.Relay.AdvertisedNames, ", "))
		fmt.Printf("state directory: %s\n", cfg.Relay.StateDir)
		if address := cfg.HealthListen(); address != "" {
			fmt.Printf("health:          %s%s (liveness), %s%s (readiness)\n",
				address, relay.HealthPathLive, address, relay.HealthPathReady)
		} else {
			fmt.Printf("health:          turned off\n")
		}
		fmt.Printf("buffer (bytes):  %d\n", cfg.Buffer())
		spoolDir, spoolOptions := spoolSettings(cfg)
		fmt.Printf("spool:           %s\n", spoolDir)
		fmt.Printf("spool (bytes):   %d, reserve %d, free floor %d\n",
			spoolOptions.MaxBytes, spoolOptions.CriticalReserveBytes, spoolOptions.MinFreeBytes)
		fmt.Printf("spool ack:       %s, at most %d in flight per host\n",
			spoolOptions.AckTimeout, spoolOptions.MaxInflightPerHost)
		fmt.Printf("enrollment:      %s\n", cfg.Upstream.EnrollmentURL)
		fmt.Printf("gateways:        %s\n", strings.Join(cfg.Upstream.GatewayURLs, ", "))
		return nil
	default:
		return fmt.Errorf("unknown action %q; use validate or show", action)
	}
}

// enrollCommand registers the relay with a token and finishes.
func enrollCommand(args []string, log *slog.Logger) error {
	flags := flag.NewFlagSet("enroll", flag.ContinueOnError)
	path := flags.String("config", relayconfig.DefaultPath, "the configuration file of the relay")
	tokenFile := flags.String("token-file", "", "the file with the enrollment token")
	if err := flags.Parse(args); err != nil {
		return err
	}
	cfg, err := relayconfig.Load(*path)
	if err != nil {
		return err
	}
	token, err := readToken(*tokenFile)
	if err != nil {
		return err
	}

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()
	identity, err := register(ctx, cfg, token)
	if err != nil {
		return err
	}
	log.Info("the relay was registered", "relay_id", identity.RelayID,
		"name", cfg.Relay.Name, "expires", identity.NotAfter.Format(time.RFC3339))
	return nil
}

// readToken takes the token from a file or from the standard input.
func readToken(file string) (string, error) {
	if file != "" {
		content, err := os.ReadFile(file)
		if err != nil {
			return "", fmt.Errorf("token: %w", err)
		}
		return strings.TrimSpace(string(content)), nil
	}
	if token := strings.TrimSpace(config.Env("FLOTESTRO_ENROLLMENT_TOKEN", "")); token != "" {
		return token, nil
	}
	info, err := os.Stdin.Stat()
	if err == nil && info.Mode()&os.ModeCharDevice == 0 {
		content, err := os.ReadFile("/dev/stdin")
		if err == nil && strings.TrimSpace(string(content)) != "" {
			return strings.TrimSpace(string(content)), nil
		}
	}
	return "", errors.New("no enrollment token: give -token-file or pass it through a pipe")
}

// register creates the identity of the relay out of the configuration and
// the token.
func register(ctx context.Context, cfg relayconfig.Config, token string) (relay.Identity, error) {
	identity, err := agent.EnsureIdentityFor(ctx, agent.IdentityRequest{
		StateDir:        cfg.Relay.StateDir,
		EnrollmentURL:   cfg.Upstream.EnrollmentURL,
		Token:           token,
		BootstrapCAPath: cfg.Upstream.BootstrapCA,
		MachineID:       cfg.Relay.Name,
		Hostname:        cfg.Relay.Name,
		Advertised:      strings.Join(cfg.Relay.AdvertisedNames, ","),
	})
	if err != nil {
		return relay.Identity{}, fmt.Errorf("the identity of the relay: %w", err)
	}
	return relay.Identity{
		RelayID:     identity.HostID,
		Certificate: identity.Certificate,
		CAPool:      identity.CAPool,
		NotAfter:    identity.NotAfter,
		TrustPEM:    identity.TrustPEM,
	}, nil
}

// runCommand starts the relay from the configuration file.
func runCommand(args []string, log *slog.Logger) error {
	flags := flag.NewFlagSet("run", flag.ContinueOnError)
	path := flags.String("config", relayconfig.DefaultPath, "the configuration file of the relay")
	if err := flags.Parse(args); err != nil {
		return err
	}
	cfg, err := relayconfig.Load(*path)
	if err != nil {
		return err
	}
	log.Info("the configuration was read", "file", *path,
		"name", cfg.Relay.Name, "gateways", len(cfg.Upstream.GatewayURLs))

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	// A relay without an identity does not come up.
	identity, err := register(ctx, cfg, "")
	if err != nil {
		return fmt.Errorf("%w; register the relay: flotestro-relay enroll", err)
	}
	log.Info("the identity of the relay is ready", "relay_id", identity.RelayID,
		"name", cfg.Relay.Name, "cert_not_after", identity.NotAfter.Format(time.RFC3339))

	live := relay.NewLive(identity)
	gateway := cfg.Upstream.GatewayURLs[0]
	// The spool before anything else: a relay that cannot write its spool must
	// not take the messages of the site, because it would lose them at the first
	// break of the link.
	spoolDir, spoolOptions := spoolSettings(cfg)
	if err := prepareSpoolDir(spoolDir); err != nil {
		return err
	}
	// The state file is what the tool on the machine reads: whether the relay
	// reaches the centre, how full its buffer is and when its certificate ends.
	state := ctl.NewRelayStateWriter(cfg.Relay.StateDir, identity.RelayID, version)
	state.Update(func(s *ctl.RelayState) {
		s.Gateway = gateway
		s.Listen = cfg.Relay.Listen
		s.BufferMaxBytes = spoolOptions.MaxBytes
		s.CertificateNotAfter = identity.NotAfter
	})
	proxy, err := relay.New(relay.Options{
		UpstreamURL:  gateway,
		UpstreamURLs: cfg.Upstream.GatewayURLs,
		// The enrollment address enables the mediation of registrations.
		EnrollmentURL: cfg.Upstream.EnrollmentURL,
		Identity:      identity.Certificate,
		TrustPool:     identity.CAPool,
		SpoolDir:      spoolDir,
		Spool:         spoolOptions,
		Log:           log,
	})
	if err != nil {
		return err
	}
	// The spool is flushed and closed on the way out: what the relay took
	// and has not sent on is on disk when the process ends.
	defer func() {
		if err := proxy.Close(); err != nil {
			log.Error("the spool was not closed cleanly", "err", err)
		}
	}()
	// What waits in the spool at the start is the backlog of the site, and
	// the operator has to see it before anything else the relay logs.
	logSpoolBacklog(log, spoolDir, spoolOptions, readSpoolBacklog(proxy, spoolDir))
	// A host has no certificate before its registration, so the handshake must
	// not demand one.
	live.MediatesRegistration(cfg.Upstream.EnrollmentURL != "")

	// The agents connect to the relay with the same protocol as to the centre, so
	// a client certificate issued by the CA of the fleet is required.
	server := &http.Server{
		Addr:    cfg.Relay.Listen,
		Handler: relay.WithClientCertificate(proxy.Handler()),
		TLSConfig: &tls.Config{
			GetCertificate:     live.Certificate,
			GetConfigForClient: live.ClientConfiguration,
			ClientCAs:          identity.CAPool,
			MinVersion:         tls.VersionTLS13,
			NextProtos:         []string{"h2"},
		},
		ReadHeaderTimeout: 15 * time.Second,
	}
	if err := http2.ConfigureServer(server, &http2.Server{}); err != nil {
		return err
	}

	go relay.KeepCertificate(ctx, live, relay.RenewalOptions{
		StateDir:   cfg.Relay.StateDir,
		GatewayURL: gateway,
		Names:      cfg.Relay.AdvertisedNames,
		Version:    version,
		Log:        log,
		AfterRenewal: func(renewed relay.Identity) {
			proxy.RefreshIdentity(renewed.Certificate, renewed.CAPool)
			state.Update(func(s *ctl.RelayState) { s.CertificateNotAfter = renewed.NotAfter })
		},
	})

	// After a failure of the link the relay has to notice on its own that the
	// centre is back.
	go proxy.WatchUpstream(ctx, 15*time.Second)
	go report(ctx, proxy, log)
	// The heartbeat tells the centre the relay is alive and how full its
	// buffer is, and leaves the same picture in the state file.
	go heartbeat(ctx, proxy, live, state, log)

	listener, err := net.Listen("tcp", cfg.Relay.Listen)
	if err != nil {
		return err
	}
	// The accepts of the listener are watched, because that is what the liveness
	// answer is about: a relay that has stopped taking the connections of its
	// site is the wedged one a runtime should restart, and a dial of the socket.
	watched := relay.WatchListener(listener)
	health := relay.NewHealth(relay.HealthOptions{
		Relay:    proxy,
		Listener: watched,
		Identity: live.Current,
		Version:  version,
	})
	healthServer, err := startHealthListener(cfg.HealthListen(), health, log)
	if err != nil {
		return err
	}
	defer stopHealthListener(healthServer)

	log.Info("the relay is listening", "address", cfg.Relay.Listen,
		"centre", proxy.Gateway(), "gateways", len(cfg.Upstream.GatewayURLs),
		"spool", spoolDir, "spool_max_bytes", spoolOptions.MaxBytes,
		"health", cfg.HealthListen())

	errCh := make(chan error, 1)
	go func() { errCh <- server.ServeTLS(watched, "", "") }()

	select {
	case <-ctx.Done():
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		return server.Shutdown(shutdownCtx)
	case err := <-errCh:
		return err
	}
}

// report empties the buffer after the link is back and shows the state of the
// relay.
func report(ctx context.Context, proxy *relay.Relay, log *slog.Logger) {
	ticker := time.NewTicker(30 * time.Second)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			sessions, buffer, connectivity := proxy.Stats()
			log.Info("the state of the relay", "sessions", sessions,
				"buffer_messages", buffer.Messages, "buffer_bytes", buffer.Bytes,
				"dropped", buffer.Dropped, "connectivity_with_the_centre", connectivity)
		}
	}
}
