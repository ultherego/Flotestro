package main

import (
	"bytes"
	"context"
	"flag"
	"fmt"
	"io"
	"os"
	"time"

	"golang.org/x/term"

	"github.com/ultherego/flotestro/internal/agent"
	"github.com/ultherego/flotestro/internal/agentconfig"
)

// enrollmentCommand carries out the one-time admission of a host into the
// fleet.
//
// A separate command rather than a side effect of the start of the daemon:
// enrollment is a one-time decision of the operator and requires a secret
// that has no right to lie in the environment file of a service. The daemon
// starts only once the identity is there - and then it needs no token at
// all.
func enrollmentCommand(args []string, in_ io.Reader, out, errOut io.Writer) int {
	flags := flag.NewFlagSet("enroll", flag.ContinueOnError)
	flags.SetOutput(errOut)
	path := flags.String("config", agentconfig.DefaultPath, "the configuration file of the agent")
	tokenFile := flags.String("token-file", "", "the file with the enrollment token")
	name := flags.String("hostname", "", "the name of the host reported to the panel")
	timeout := flags.Duration("timeout", 2*time.Minute, "the time timeout for the enrollment")
	if err := flags.Parse(args); err != nil {
		return 2
	}

	cfg, err := agentconfig.Load(*path)
	if err != nil {
		fmt.Fprintf(errOut, "config: %s\n  %v\n", *path, err)
		return 1
	}
	if err := cfg.CheckBootstrapCA(); err != nil {
		fmt.Fprintf(errOut, "bootstrap_ca_file: %v\n", err)
		return 1
	}

	// An identity that already works must not be replaced in passing.
	// Replacing an existing identity is a separate decision and goes through
	// a recovery request in the panel.
	state := agent.OdczytajTozsamosc(cfg.Agent.StateDir)
	if state.Obecna && !state.Wygasl {
		fmt.Fprintf(errOut, "the host is already registered as host/%s (the certificate is valid until %s)\n",
			state.HostID, state.NotAfter.UTC().Format(time.RFC3339))
		fmt.Fprintln(errOut, "a replacement of the identity is requested in the panel: POST /hosts/{id}/identity-recovery")
		return 1
	}

	token, err := readToken(*tokenFile, in_, errOut)
	if err != nil {
		fmt.Fprintf(errOut, "the enrollment token: %v\n", err)
		return 1
	}
	defer wipe(token)
	if len(token) == 0 {
		fmt.Fprintln(errOut, "the enrollment token is empty")
		return 1
	}

	ctx, cancel := context.WithTimeout(context.Background(), *timeout)
	defer cancel()

	if *name == "" {
		*name, _ = os.Hostname()
	}
	identity, err := agent.EnsureIdentity(ctx, cfg.Agent.StateDir,
		cfg.Connection.EnrollmentURL, string(token), cfg.Connection.BootstrapCA)
	if err != nil {
		fmt.Fprintf(errOut, "the enrollment failed: %v\n", err)
		return 1
	}

	fmt.Fprintf(out, "Registered:   host/%s\n", identity.HostID)
	fmt.Fprintf(out, "Certificate:  valid until %s\n",
		identity.NotAfter.UTC().Format(time.RFC3339))
	fmt.Fprintln(out, "Start the service: systemctl start flotestro-agent.service")
	return 0
}

// readToken takes the token without leaving it in the arguments or in the
// environment of the process.
//
// Every user of the host sees a command line argument in the process list,
// and an environment variable stays in the file of the service. What is left
// is a file with narrowed permissions, a pipe or a question with the echo
// turned off.
func readToken(path string, in_ io.Reader, errOut io.Writer) ([]byte, error) {
	if path != "" {
		content, err := os.ReadFile(path)
		if err != nil {
			return nil, err
		}
		return bytes.TrimSpace(content), nil
	}
	if file, ok := in_.(*os.File); ok && term.IsTerminal(int(file.Fd())) {
		fmt.Fprint(errOut, "Enrollment token: ")
		value, err := term.ReadPassword(int(file.Fd()))
		fmt.Fprintln(errOut)
		return bytes.TrimSpace(value), err
	}
	content, err := io.ReadAll(io.LimitReader(in_, 4096))
	if err != nil {
		return nil, err
	}
	return bytes.TrimSpace(content), nil
}

// wipe overwrites the token in memory.
//
// Without illusions: the runtime and the kernel may hold copies of their own,
// and the only real protection is a short validity, a single use and a
// revocation after the registration. This is cleaning up after oneself rather
// than a guarantee.
func wipe(value []byte) {
	for i := range value {
		value[i] = 0
	}
}
