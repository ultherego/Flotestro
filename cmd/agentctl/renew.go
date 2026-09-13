package main

import (
	"context"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"github.com/ultherego/flotestro/internal/agent"
	"github.com/ultherego/flotestro/internal/agentconfig"
)

// forcedRenewalFile records when the operator last forced a renewal.
//
// It lies in the state directory next to the identity: the limit is a
// property of the host, and a reinstall of the tool must not reset it.
const forcedRenewalFile = "renew-forced-at"

// forcedRenewalInterval is the least time between two forced renewals.
//
// The gateway rate-limits renewals as well, but the refusal has to come
// before the network: a renewal repeated in a loop by a script is exactly
// what the limit is for, and every attempt costs a new key pair.
const forcedRenewalInterval = 10 * time.Minute

// renewCommand forces a renewal of the certificate of the host.
//
// The daemon renews on its own when a third of the validity is left; this is
// for the moment the operator does not want to wait - after a rotation of the
// CA, or when the key is to be replaced today. The path is the same one the
// daemon takes: the current certificate proves the identity over mTLS, the
// enrollment token takes no part.
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
		StateDir:   cfg.Agent.StateDir,
		GatewayURL: cfg.Connection.GatewayURLs[0],
		Now:        time.Now,
		Identity:   agent.ReadIdentity,
		Renew:      agent.RenewNow,
	}
	return r.run(ctx, out, errOut)
}

// renewal gathers what a forced renewal touches, so that a test can run it
// on a temporary directory with a clock of its own and without a gateway.
type renewal struct {
	StateDir   string
	GatewayURL string
	Now        func() time.Time
	Identity   func(stateDir string) agent.StoredIdentity
	Renew      func(ctx context.Context, stateDir, gatewayURL string) (*agent.Identity, error)
}

// run carries the renewal out.
//
// The exit codes follow the tool: 0 renewed, 1 a problem to fix, 2 a refusal
// of the request itself - too soon after the previous one.
func (r renewal) run(ctx context.Context, out, errOut io.Writer) int {
	now := r.Now()
	if last, ok := r.lastForced(); ok && now.Sub(last) < forcedRenewalInterval {
		wait := forcedRenewalInterval - now.Sub(last)
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

	// The attempt is recorded before it is made: a refusal by the gateway
	// counts as much as a success, and a script must not be able to hammer
	// the gateway by retrying a failure.
	if err := r.recordForced(now); err != nil {
		fmt.Fprintf(errOut, "the renewal record was not written: %v\n", err)
		return 1
	}

	renewed, err := r.Renew(ctx, r.StateDir, r.GatewayURL)
	if err != nil {
		fmt.Fprintf(errOut, "the renewal failed: %v\n", err)
		return 1
	}
	fmt.Fprintf(out, "Renewed:      host/%s\n", renewed.HostID)
	fmt.Fprintf(out, "Certificate:  valid until %s\n", renewed.NotAfter.UTC().Format(time.RFC3339))
	// The daemon has no local channel to be told about the new generation,
	// and the previous certificate stays valid until its term - so the
	// session goes on, and the switch happens at the next start.
	fmt.Fprintln(out, "The running agent keeps its session on the previous certificate; to switch: systemctl restart flotestro-agent.service")
	return 0
}

// lastForced reads the time of the previous forced renewal.
//
// An unreadable record counts as none: the file is a courtesy to the
// operator, not a lock, and a damaged one must not block the renewal for
// good.
func (r renewal) lastForced() (time.Time, bool) {
	content, err := os.ReadFile(filepath.Join(r.StateDir, forcedRenewalFile))
	if err != nil {
		return time.Time{}, false
	}
	last, err := time.Parse(time.RFC3339, strings.TrimSpace(string(content)))
	if err != nil {
		return time.Time{}, false
	}
	return last, true
}

// recordForced writes the time of this forced renewal.
func (r renewal) recordForced(now time.Time) error {
	return os.WriteFile(filepath.Join(r.StateDir, forcedRenewalFile),
		[]byte(now.UTC().Format(time.RFC3339)+"\n"), 0o600)
}

// sameOwner refuses to write the identity as somebody other than its owner.
//
// The store writes the new generation as the calling user. Run as root, it
// would leave a key the daemon cannot read - and the host would drop out of
// the fleet at the next restart, not now, when the operator is looking. The
// command is named in the hint so that the operator can repeat it as the
// right user. A directory that does not exist yet has no owner to compare
// with: the caller creates it as itself.
func sameOwner(stateDir, command string) error {
	info, err := os.Stat(stateDir)
	if err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		return fmt.Errorf("the state directory: %w", err)
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok {
		return nil
	}
	if int(stat.Uid) != os.Geteuid() {
		return fmt.Errorf("%s belongs to uid %d and this process runs as uid %d; run the command as the agent: sudo -u flotestro-agent flotestro-agentctl %s",
			stateDir, stat.Uid, os.Geteuid(), command)
	}
	return nil
}
