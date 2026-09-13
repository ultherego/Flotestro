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
//
// Not an enrollment: the host already is in the fleet, and the panel issued
// the token for exactly this host after an operator's decision. What the
// command guards is the moment of the switch - the current generation works
// until the new certificate has been received and has opened a session
// with the gateway. A typed confirmation stands in for the "are you sure"
// of the panel: the command line has no second person to approve.
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
		Recover: func(ctx context.Context, token []byte) (*agent.Identity, error) {
			request, err := agent.LocalIdentityRequest(cfg.Agent.StateDir,
				cfg.Connection.EnrollmentURL, string(token), cfg.Connection.BootstrapCA)
			if err != nil {
				return nil, err
			}
			return agent.Recover(ctx, request, cfg.Connection.GatewayURLs[0])
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
	Recover        func(ctx context.Context, token []byte) (*agent.Identity, error)
}

// run carries the reset out.
//
// The exit codes follow the tool: 0 replaced, 1 a problem to fix, 2 a
// refusal of the request itself - no confirmation or the wrong one.
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

	// The confirmation is the name of this host, typed out. Not a flag that
	// says "yes": the operator has to look at which machine the command is
	// being run on.
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

	identity, err := r.Recover(ctx, token)
	if err != nil {
		fmt.Fprintf(errOut, "the reset failed: %v\n", err)
		if current.Present {
			fmt.Fprintf(errOut, "the current identity host/%s was kept\n", current.HostID)
		}
		fmt.Fprintln(errOut, enrollmentHint(err))
		return 1
	}

	fmt.Fprintf(out, "Replaced:     host/%s\n", identity.HostID)
	fmt.Fprintf(out, "Certificate:  valid until %s\n", identity.NotAfter.UTC().Format(time.RFC3339))
	if current.Present && current.HostID != identity.HostID {
		// A recovery token names one host; another answer means the order
		// in the panel was for a different one. The switch has happened
		// already, so the operator needs to know rather than be stopped.
		fmt.Fprintf(errOut, "warning: the panel answered with host/%s, this host was host/%s - check the recovery order\n",
			identity.HostID, current.HostID)
	}
	// Revocation is a decision of the panel. This host has no way of
	// revoking anything, and must have none: a host that could revoke
	// certificates could revoke somebody else's.
	if r.RevokeOld {
		fmt.Fprintln(out, "Revocation:   the previous certificate is revoked by the panel, not by this host; the recovery order carries revoke_old_immediately")
	} else {
		fmt.Fprintln(out, "Revocation:   the previous certificate stays valid until the panel revokes it (revoke_old_immediately on the recovery order)")
	}
	fmt.Fprintln(out, "The running agent keeps its session on the previous certificate; to switch: systemctl restart flotestro-agent.service")
	return 0
}
