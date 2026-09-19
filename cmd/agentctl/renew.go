package main

import (
	"context"
	"flag"
	"fmt"
	"io"
	"time"

	"github.com/ultherego/flotestro/internal/agent"
	"github.com/ultherego/flotestro/internal/agentconfig"
	"github.com/ultherego/flotestro/internal/ctl"
	"github.com/ultherego/flotestro/internal/endpoints"
)

// The limit on forced renewals is shared with the tool of the relay: the
// record lies in the state directory next to the identity, so a reinstall of
// the tool does not reset it.
const (
	forcedRenewalFile     = ctl.ForcedRenewalFile
	forcedRenewalInterval = ctl.ForcedRenewalInterval
)

// renewCommand forces a renewal of the certificate of the host.
func renewCommand(args []string, out, errOut io.Writer) int {
	flags := flag.NewFlagSet("renew", flag.ContinueOnError)
	flags.SetOutput(errOut)
	path := flags.String("config", agentconfig.DefaultPath, "the configuration file of the agent")
	timeout := flags.Duration("timeout", 2*time.Minute, "the time limit for the renewal")
	if err := flags.Parse(args); err != nil {
		return 2
	}

	cfg, err := agentconfig.Load(*path)
	if err != nil {
		fmt.Fprintf(errOut, "config: %s\n  %v\n", *path, err)
		return 1
	}
	ctx, cancel := context.WithTimeout(context.Background(), *timeout)
	defer cancel()

	r := renewal{
		StateDir: cfg.Agent.StateDir,
		// Every gateway of the configuration, in its order of priority: a
		// certificate close to its term must not depend on one instance of the panel
		// being up, and the host already knows where the others are.
		Gateways: cfg.Connection.GatewayURLs,
		Now:      time.Now,
		Identity: agent.ReadIdentity,
		Renew:    agent.RenewNow,
	}
	return r.run(ctx, out, errOut)
}

// renewal gathers what a forced renewal touches, so that a test can run it
// on a temporary directory with a clock of its own and without a gateway.
type renewal struct {
	StateDir string
	// Gateways are the addresses of the panel in order of priority, the
	// same list the daemon's session uses.
	Gateways []string
	Now      func() time.Time
	Identity func(stateDir string) agent.StoredIdentity
	Renew    func(ctx context.Context, stateDir, gatewayURL string) (*agent.Identity, error)
}

// run carries the renewal out.
func (r renewal) run(ctx context.Context, out, errOut io.Writer) int {
	now := r.Now()
	throttle := ctl.Throttle{StateDir: r.StateDir}
	if last, wait, tooSoon := throttle.TooSoon(now); tooSoon {
		fmt.Fprintf(errOut, "the last forced renewal was %s ago; the next one is allowed in %s (at %s)\n",
			rounded(now.Sub(last)), rounded(wait), last.Add(forcedRenewalInterval).UTC().Format(time.RFC3339))
		return 2
	}

	identity := r.Identity(r.StateDir)
	if !identity.Present {
		fmt.Fprintf(errOut, "identity_missing: %s\n", identity.Err)
		fmt.Fprintln(errOut, "a renewal needs a certificate to renew with; enroll the host: sudo -u flotestro-agent flotestro-agentctl enroll")
		return 1
	}
	if identity.Expired {
		// An expired certificate proves nothing over mTLS, so there is no
		// path but a new enrollment.
		fmt.Fprintf(errOut, "identity_expired: the certificate of host/%s expired at %s\n",
			identity.HostID, identity.NotAfter.UTC().Format(time.RFC3339))
		fmt.Fprintln(errOut, "a renewal needs a valid certificate; enroll the host again")
		return 1
	}
	if err := sameOwner(r.StateDir, "renew"); err != nil {
		fmt.Fprintf(errOut, "%v\n", err)
		return 1
	}

	// The attempt is recorded before it is made: a refusal by the gateway counts
	// as much as a success, and a script must not be able to hammer the gateway
	// by retrying a failure.
	if err := throttle.Record(now); err != nil {
		fmt.Fprintf(errOut, "the renewal record was not written: %v\n", err)
		return 1
	}

	// The gateways are tried in order until one answers; which one did is
	// printed, because an operator repeating the command after an outage wants to
	// know whether they are talking to the main panel or to the standby.
	var renewed *agent.Identity
	answered, err := endpoints.New(r.Gateways, 0, 0).Try(ctx,
		func(ctx context.Context, gatewayURL string) error {
			identity, err := r.Renew(ctx, r.StateDir, gatewayURL)
			if err != nil {
				return err
			}
			renewed = identity
			return nil
		})
	if err != nil {
		fmt.Fprintf(errOut, "the renewal failed: %v\n", err)
		return 1
	}
	fmt.Fprintf(out, "Renewed:      host/%s\n", renewed.HostID)
	fmt.Fprintf(out, "Gateway:      %s\n", answered)
	fmt.Fprintf(out, "Certificate:  valid until %s\n", renewed.NotAfter.UTC().Format(time.RFC3339))
	// The daemon has no local channel to be told about the new generation, and
	// the previous certificate stays valid until its term - so the session goes
	// on, and the switch happens at the next start.
	fmt.Fprintln(out, "The running agent keeps its session on the previous certificate; to switch: systemctl restart flotestro-agent.service")
	return 0
}

// sameOwner refuses to write the identity as somebody other than its owner.
// The store writes the new generation as the calling user.
func sameOwner(stateDir, command string) error {
	return ctl.SameOwner(stateDir, "flotestro-agent", "flotestro-agentctl", command)
}
