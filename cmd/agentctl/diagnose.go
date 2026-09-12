package main

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"io"
	"net"
	"net/url"
	"os"
	"time"

	"github.com/ultherego/flotestro/internal/agent"
	"github.com/ultherego/flotestro/internal/agentconfig"
)

// diagnoseCommand checks the path from the host to the panel step by step.
//
// The steps are deliberately separate. "It does not work" is not an answer:
// one thing is fixed when a name does not resolve, another when a port is
// closed, and another still when the chain of certificates does not match.
func diagnoseCommand(args []string, out, errOut io.Writer) int {
	path, ok := configurationPath("diagnose", args, errOut)
	if !ok {
		return 2
	}
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	cfg, err := agentconfig.Load(path)
	if err != nil {
		fmt.Fprintf(out, "config      ERROR %s: %v\n", path, err)
		return 1
	}
	fmt.Fprintf(out, "config      ok    %s\n", path)

	problems := 0
	identity := agent.OdczytajTozsamosc(cfg.Agent.StateDir)
	if identity.Obecna {
		fmt.Fprintf(out, "identity    ok    host/%s, the certificate until %s\n",
			identity.HostID, identity.NotAfter.UTC().Format(time.RFC3339))
	} else {
		fmt.Fprintf(out, "identity    none  %s\n", identity.Blad)
		problems++
	}

	// The trust is checked with the same bundle the agent uses. The system
	// bundle would say something other than the truth about this fleet.
	pool := caPool(cfg, identity)

	addresses := append([]string{cfg.Connection.EnrollmentURL}, cfg.Connection.GatewayURLs...)
	for _, address := range addresses {
		problems += checkAddress(ctx, out, address, pool, cfg.Connection.ConnectTimeout)
	}

	if cfg.Agent.Mode == agentconfig.ModeReadOnly {
		fmt.Fprintf(out, "helper      -     disabled (mode %s)\n", cfg.Agent.Mode)
	} else if err := socketWorks(cfg.Helper.Socket); err != nil {
		fmt.Fprintf(out, "helper      ERROR %v\n", err)
		problems++
	} else {
		fmt.Fprintf(out, "helper      ok    %s\n", cfg.Helper.Socket)
	}

	capabilities := agent.DetectCapabilities()
	available := 0
	for _, capability := range capabilities {
		if capability.Available {
			available++
		}
	}
	fmt.Fprintf(out, "capabilities ok   %d of %d available\n", available, len(capabilities))

	if problems > 0 {
		return 1
	}
	return 0
}

// caPool assembles the trust for checking the connection.
func caPool(cfg agentconfig.Config, identity agent.StanTozsamosci) *x509.CertPool {
	pool := x509.NewCertPool()
	added := false
	for _, path := range []string{identity.Sciezki.CA, cfg.Connection.BootstrapCA} {
		if path == "" {
			continue
		}
		if content, err := os.ReadFile(path); err == nil && pool.AppendCertsFromPEM(content) {
			added = true
		}
	}
	if !added {
		return nil
	}
	return pool
}

// checkAddress goes through in order: the name, the port, TLS and the clock.
func checkAddress(ctx context.Context, out io.Writer, raw string,
	pool *x509.CertPool, timeout time.Duration) int {
	address, err := url.Parse(raw)
	if err != nil {
		fmt.Fprintf(out, "url         ERROR %s: %v\n", raw, err)
		return 1
	}
	host := address.Hostname()
	port := address.Port()
	if port == "" {
		port = "443"
	}

	addresses, err := net.DefaultResolver.LookupHost(ctx, host)
	if err != nil {
		fmt.Fprintf(out, "dns         ERROR %s: %v\n", host, err)
		return 1
	}
	fmt.Fprintf(out, "dns         ok    %s -> %v\n", host, addresses)

	conn, err := (&net.Dialer{Timeout: timeout}).DialContext(ctx, "tcp", net.JoinHostPort(host, port))
	if err != nil {
		fmt.Fprintf(out, "tcp         ERROR %s:%s: %v\n", host, port, err)
		return 1
	}
	fmt.Fprintf(out, "tcp         ok    %s:%s\n", host, port)

	// The verification is not turned off even in diagnostics: we show the
	// error of the chain and the expected name, but we do not pretend the
	// connection is good.
	client := tls.Client(conn, &tls.Config{ServerName: host, RootCAs: pool, MinVersion: tls.VersionTLS12})
	defer client.Close()
	if err := client.HandshakeContext(ctx); err != nil {
		fmt.Fprintf(out, "tls         ERROR %s: %v\n", host, err)
		return 1
	}
	state := client.ConnectionState()
	description := "without a server certificate"
	if len(state.PeerCertificates) > 0 {
		server := state.PeerCertificates[0]
		description = fmt.Sprintf("%s, valid until %s", server.Subject.CommonName,
			server.NotAfter.UTC().Format(time.RFC3339))
	}
	fmt.Fprintf(out, "tls         ok    %s (%s)\n", description, tlsVersion(state.Version))
	return 0
}

func tlsVersion(version uint16) string {
	switch version {
	case tls.VersionTLS13:
		return "TLS 1.3"
	case tls.VersionTLS12:
		return "TLS 1.2"
	}
	return fmt.Sprintf("0x%04x", version)
}
