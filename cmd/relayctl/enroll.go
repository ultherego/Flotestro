package main

import (
	"context"
	"flag"
	"fmt"
	"io"
	"os"
	"strings"
	"time"

	"github.com/ultherego/flotestro/internal/agent"
	"github.com/ultherego/flotestro/internal/ctl"
	"github.com/ultherego/flotestro/internal/relayconfig"
)

// enrollmentCommand carries out the one-time admission of a relay into the
// fleet.
func enrollmentCommand(args []string, in_ io.Reader, out, errOut io.Writer) int {
	flags := flag.NewFlagSet("enroll", flag.ContinueOnError)
	flags.SetOutput(errOut)
	path := flags.String("config", relayconfig.DefaultPath, "the configuration file of the relay")
	tokenFile := flags.String("token-file", "", "the file with the enrollment token")
	timeout := flags.Duration("timeout", 2*time.Minute, "the time limit for the enrollment")
	if err := flags.Parse(args); err != nil {
		return 2
	}

	cfg, err := relayconfig.Load(*path)
	if err != nil {
		fmt.Fprintf(errOut, "config: %s\n  %v\n", *path, err)
		return 1
	}
	if cfg.Upstream.BootstrapCA != "" {
		if _, err := os.Stat(cfg.Upstream.BootstrapCA); err != nil {
			fmt.Fprintf(errOut, "bootstrap_ca_file: %v\n", err)
			return 1
		}
	}

	// An identity that already works must not be replaced in passing.
	state := readIdentity(cfg.Relay.StateDir)
	if state.Present && !state.Expired {
		fmt.Fprintf(errOut, "%s: the relay is already registered as relay/%s (the certificate is valid until %s)\n",
			agent.CodeAlreadyEnrolled, state.RelayID, state.NotAfter.UTC().Format(time.RFC3339))
		fmt.Fprintln(errOut, "a new identity requires revoking the relay in the panel and a new enrollment token")
		return 1
	}
	if err := sameOwner(cfg.Relay.StateDir, "enroll"); err != nil {
		fmt.Fprintf(errOut, "%v\n", err)
		return 1
	}

	token, err := ctl.ReadToken(*tokenFile, in_, errOut)
	if err != nil {
		fmt.Fprintf(errOut, "the enrollment token: %v\n", err)
		return 1
	}
	defer ctl.Wipe(token)
	if len(token) == 0 {
		fmt.Fprintln(errOut, "the enrollment token is empty")
		return 1
	}

	ctx, cancel := context.WithTimeout(context.Background(), *timeout)
	defer cancel()

	// The same request the daemon makes: the name of the relay stands for the
	// machine-id, and the network names go into the certificate so that the
	// agents of the site can verify the relay by name.
	identity, err := agent.Enroll(ctx, agent.IdentityRequest{
		StateDir:        cfg.Relay.StateDir,
		EnrollmentURL:   cfg.Upstream.EnrollmentURL,
		Token:           string(token),
		BootstrapCAPath: cfg.Upstream.BootstrapCA,
		MachineID:       cfg.Relay.Name,
		Hostname:        cfg.Relay.Name,
		Advertised:      strings.Join(cfg.Relay.AdvertisedNames, ","),
	})
	if err != nil {
		// The code goes first: it is what the operator matches against the
		// table of errors, and the cause after it is for reading.
		fmt.Fprintf(errOut, "the enrollment failed: %v\n", err)
		fmt.Fprintln(errOut, enrollmentHint(err))
		return 1
	}

	fmt.Fprintf(out, "Registered:   relay/%s (%s, site %s)\n", identity.HostID, cfg.Relay.Name, cfg.Relay.Site)
	fmt.Fprintf(out, "Certificate:  valid until %s\n", identity.NotAfter.UTC().Format(time.RFC3339))
	fmt.Fprintln(out, "Start the service: systemctl start flotestro-relay.service")
	return 0
}

// enrollmentHint says what to do next for a refused enrollment.
func enrollmentHint(err error) string {
	switch agent.ErrorCode(err) {
	case agent.CodeTokenInvalid:
		return "the token was refused: the reason is in the enrollment order in the panel (expired, revoked, used up or not a relay token); a new order gives a new token"
	case agent.CodeRequestReused:
		return "the attempt number is known to the panel with another request; ask for a new token"
	case agent.CodeIdentityRejected:
		return "the certificate from the panel was not accepted - it does not fit the key or the trust bundle; nothing was switched"
	case agent.CodeCommitFailed:
		return "the identity was not written; check the state directory and its filesystem"
	case agent.CodeConnectFailed, agent.CodeConnectTimeout:
		return "the endpoint did not answer: flotestro-relayctl diagnose"
	case agent.CodeUnknownAuthority, agent.CodeNameMismatch:
		return "the endpoint failed the check against the bootstrap CA: flotestro-relayctl diagnose"
	}
	return "see flotestro-relayctl diagnose"
}

// sameOwner refuses to write the identity as somebody other than its owner.
func sameOwner(stateDir, command string) error {
	return ctl.SameOwner(stateDir, "flotestro-relay", "flotestro-relayctl", command)
}
