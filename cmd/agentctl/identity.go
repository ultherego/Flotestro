package main

import (
	"context"
	"flag"
	"fmt"
	"io"
	"os"
	"time"

	"github.com/ultherego/flotestro/internal/agent"
	"github.com/ultherego/flotestro/internal/agentconfig"
	"github.com/ultherego/flotestro/internal/endpoints"
)

// identityCommands routes the subcommands that touch the identity of the
// host.
func identityCommands(args []string, in_ io.Reader, out, errOut io.Writer) int {
	if len(args) == 0 {
		fmt.Fprintln(errOut, "identity needs a subcommand: reset")
		return 2
	}
	switch args[0] {
	case "reset":
		return identityResetCommand(args[1:], in_, out, errOut)
	default:
		fmt.Fprintf(errOut, "unknown identity subcommand: %s\n", args[0])
		return 2
	}
}

// identityResetCommand replaces the identity of the host with a recovery
// token.
func identityResetCommand(args []string, in_ io.Reader, out, errOut io.Writer) int {
	flags := flag.NewFlagSet("identity reset", flag.ContinueOnError)
	flags.SetOutput(errOut)
	path := flags.String("config", agentconfig.DefaultPath, "the configuration file of the agent")
	confirm := flags.String("confirm", "", "the name of this host, typed as the confirmation")
	tokenFile := flags.String("token-file", "", "the file with the recovery token")
	revokeOld := flags.Bool("revoke-old", false, "ask for the previous certificate to be revoked (a decision of the panel)")
	discardPending := flags.Bool("discard-pending", false, "abandon the record of an unfinished attempt")
	timeout := flags.Duration("timeout", 2*time.Minute, "the time limit for the recovery")
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
	ctx, cancel := context.WithTimeout(context.Background(), *timeout)
	defer cancel()

	r := identityReset{
		StateDir:       cfg.Agent.StateDir,
		Confirm:        *confirm,
		RevokeOld:      *revokeOld,
		DiscardPending: *discardPending,
		Hostname:       func() string { name, _ := os.Hostname(); return name },
		Now:            time.Now,
		Identity:       agent.ReadIdentity,
		ReadToken:      func() ([]byte, error) { return readToken(*tokenFile, in_, errOut) },
		// A recovery is the way back for a host whose identity is gone, so it may
		// not hang on one address: the new certificate is verified against whichever
		// gateway of the configuration answers.
		Gateways: cfg.Connection.GatewayURLs,
		Recover: func(ctx context.Context, token []byte, gatewayURL string) (*agent.Identity, error) {
			request, err := agent.LocalIdentityRequest(cfg.Agent.StateDir,
				cfg.Connection.EnrollmentURL, string(token), cfg.Connection.BootstrapCA)
			if err != nil {
				return nil, err
			}
			return agent.Recover(ctx, request, gatewayURL)
		},
	}
	return r.run(ctx, out, errOut)
}

// identityReset gathers what a reset touches, so that a test can run it on
// a temporary directory with a name, a clock and a recovery of its own.
type identityReset struct {
	StateDir       string
	Confirm        string
	RevokeOld      bool
	DiscardPending bool
	Hostname       func() string
	Now            func() time.Time
	Identity       func(stateDir string) agent.StoredIdentity
	ReadToken      func() ([]byte, error)
	// Gateways are the addresses the new certificate is verified against,
	// in order of priority.
	Gateways []string
	Recover  func(ctx context.Context, token []byte, gatewayURL string) (*agent.Identity, error)
}

// run carries the reset out.
func (r identityReset) run(ctx context.Context, out, errOut io.Writer) int {
	if r.DiscardPending {
		discarded, err := agent.DiscardPendingAttempt(r.StateDir)
		if err != nil {
			fmt.Fprintf(errOut, "%s: the record of the attempt was not removed: %v\n", agent.CodePendingInvalid, err)
			return 1
		}
		if discarded {
			fmt.Fprintln(out, "Discarded:    the record of the unfinished attempt; the next attempt starts with a new key")
		} else {
			fmt.Fprintln(out, "Discarded:    nothing - there was no unfinished attempt")
		}
		if r.Confirm == "" {
			// Discarding alone is a housekeeping act and needs no token: the
			// reset itself starts only with the confirmation.
			return 0
		}
	}

	// The confirmation is the name of this host, typed out.
	if r.Confirm == "" {
		fmt.Fprintln(errOut, "confirmation_required: identity reset replaces the identity of this host; repeat the command with --confirm <hostname>")
		return 2
	}
	if hostname := r.Hostname(); r.Confirm != hostname {
		fmt.Fprintf(errOut, "confirmation_mismatch: --confirm %q does not name this host (%s)\n", r.Confirm, hostname)
		return 2
	}
	if err := sameOwner(r.StateDir, "identity reset"); err != nil {
		fmt.Fprintf(errOut, "%v\n", err)
		return 1
	}

	current := r.Identity(r.StateDir)
	switch {
	case current.Present:
		fmt.Fprintf(out, "Current:      host/%s, valid until %s - kept until the new identity is verified\n",
			current.HostID, current.NotAfter.UTC().Format(time.RFC3339))
	default:
		// A lost identity is exactly the case a recovery exists for.
		fmt.Fprintf(out, "Current:      none (%s)\n", current.Err)
	}
	if pending := agent.ReadPendingAttempt(r.StateDir, r.Now()); pending != nil && pending.Err == "" && !pending.Stale {
		fmt.Fprintf(out, "Pending:      repeating the attempt %s started %s ago\n", pending.ClientRequestID, rounded(pending.Age))
	}

	token, err := r.ReadToken()
	if err != nil {
		fmt.Fprintf(errOut, "the recovery token: %v\n", err)
		return 1
	}
	defer wipe(token)
	if len(token) == 0 {
		fmt.Fprintln(errOut, "the recovery token is empty")
		return 1
	}

	// The gateways are tried in order: the identity the panel issued is one for
	// the whole fleet, so any of them may verify it, and the one that did is
	// printed next to the new certificate.
	var identity *agent.Identity
	answered, err := endpoints.New(r.Gateways, 0, 0).Try(ctx,
		func(ctx context.Context, gatewayURL string) error {
			recovered, err := r.Recover(ctx, token, gatewayURL)
			if err != nil {
				return err
			}
			identity = recovered
			return nil
		})
	if err != nil {
		fmt.Fprintf(errOut, "the reset failed: %v\n", err)
		if current.Present {
			fmt.Fprintf(errOut, "the current identity host/%s was kept\n", current.HostID)
		}
		fmt.Fprintln(errOut, enrollmentHint(err))
		return 1
	}

	fmt.Fprintf(out, "Replaced:     host/%s\n", identity.HostID)
	fmt.Fprintf(out, "Gateway:      %s\n", answered)
	fmt.Fprintf(out, "Certificate:  valid until %s\n", identity.NotAfter.UTC().Format(time.RFC3339))
	if current.Present && current.HostID != identity.HostID {
		// A recovery token names one host; another answer means the order in the
		// panel was for a different one.
		fmt.Fprintf(errOut, "warning: the panel answered with host/%s, this host was host/%s - check the recovery order\n",
			identity.HostID, current.HostID)
	}
	// Revocation is a decision of the panel.
	if r.RevokeOld {
		fmt.Fprintln(out, "Revocation:   the previous certificate is revoked by the panel, not by this host; the recovery order carries revoke_old_immediately")
	} else {
		fmt.Fprintln(out, "Revocation:   the previous certificate stays valid until the panel revokes it (revoke_old_immediately on the recovery order)")
	}
	fmt.Fprintln(out, "The running agent keeps its session on the previous certificate; to switch: systemctl restart flotestro-agent.service")
	return 0
}
