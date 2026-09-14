package main

import (
	"context"
	"flag"
	"fmt"
	"io"
	"os"
	"strings"
	"time"

	"github.com/ultherego/flotestro/internal/ctl"
	"github.com/ultherego/flotestro/internal/relayconfig"
)

// The thresholds of the local checks.
//
// The buffer alert of the document fires at seventy percent: from there a
// cut-off site has minutes of results left, not hours. The free space is
// what the state directory needs for a new generation of the identity and
// the state file - a handful of kilobytes - with a margin for the machine
// as a whole.
const (
	bufferWarnAbove    = 0.7
	freeSpaceWarnBelow = 64 << 20
)

// silentAfter is how long without a contact makes the panel count the
// relay as silent. The same ten minutes as in the panel: the tool is to
// say the same thing the dashboard says.
const silentAfter = 10 * time.Minute

// diagnoseCommand checks the path from the relay to the centre step by
// step.
//
// The steps are deliberately separate and independent, as with the agent:
// one thing is fixed when a name does not resolve, another when a port is
// closed, and another still when the chain of certificates does not match.
// A failed step stops the rest only when it makes them meaningless - and
// then they say so instead of failing a second time for the same reason.
//
// Nothing here changes the machine. The diagnosis reads, connects and
// reports; the fix is always a separate, explicit command.
func diagnoseCommand(args []string, out, errOut io.Writer) int {
	flags := flag.NewFlagSet("diagnose", flag.ContinueOnError)
	flags.SetOutput(errOut)
	path := flags.String("config", relayconfig.DefaultPath, "the configuration file of the relay")
	asJSON := flags.Bool("json", false, "print the report as JSON")
	if err := flags.Parse(args); err != nil {
		return 2
	}
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	report := newDiagnostics(*path).run(ctx)
	if *asJSON {
		if err := ctl.RenderJSON(out, report); err != nil {
			fmt.Fprintf(errOut, "the report was not written: %v\n", err)
			return 1
		}
	} else {
		ctl.RenderText(out, report)
	}
	if !report.OK {
		return 1
	}
	return 0
}

// diagnostics gathers everything a diagnosis touches outside the process.
//
// The clock, the paths and the network are fields rather than calls to the
// packages, so that a test can run the whole diagnosis on a temporary
// directory without a network and without a daemon.
type diagnostics struct {
	ConfigPath string
	Now        func() time.Time
	Network    ctl.Network
	Identity   func(stateDir string) storedIdentity
	State      func(stateDir string) (ctl.RelayState, error)
	Listener   func(address string) error
	ReadFile   func(path string) ([]byte, error)
	FreeSpace  func(path string) (int64, error)
	Writable   func(dir string) error
}

// newDiagnostics wires the diagnosis to the real machine.
func newDiagnostics(configPath string) diagnostics {
	return diagnostics{
		ConfigPath: configPath,
		Now:        time.Now,
		Network:    ctl.RealNetwork(),
		Identity:   readIdentity,
		State:      ctl.ReadRelayState,
		Listener:   listenerWorks,
		ReadFile:   os.ReadFile,
		FreeSpace:  ctl.FreeSpace,
		Writable:   ctl.Writable,
	}
}

// endpointsOf lists the addresses of the centre in the order the relay uses
// them.
func endpointsOf(cfg relayconfig.Config) []ctl.Endpoint {
	var endpoints []ctl.Endpoint
	if enrollment, ok := ctl.ParseEndpoint("enrollment", cfg.Upstream.EnrollmentURL); ok {
		endpoints = append(endpoints, enrollment)
	}
	return append(endpoints, ctl.GatewayEndpoints(cfg.Upstream.GatewayURLs)...)
}

// run carries out every check and gathers the report.
func (d diagnostics) run(ctx context.Context) ctl.Report {
	report := ctl.Report{OK: true}

	cfg, configCheck, usable := d.checkConfiguration()
	report.Add(configCheck)
	if !usable {
		why := "the configuration did not load; see config"
		for _, name := range []string{"identity", "clock", "dns.enrollment", "dns.gateway",
			"tls.enrollment", "tls.gateway", "state_dir", "buffer", "upstream", "listener"} {
			report.Add(ctl.NotRun(name, why))
		}
		report.Add(d.checkPacnew())
		return report
	}

	identity := d.Identity(cfg.Relay.StateDir)
	report.Add(d.checkIdentity(identity))

	pool, poolErr := ctl.TrustPool(identity.TrustPEM, cfg.Upstream.BootstrapCA, d.ReadFile)
	endpoints := endpointsOf(cfg)

	// The names are resolved first: a name that does not resolve makes
	// every dial to it meaningless, and the checks that would dial say so
	// instead of failing a second time for the same reason. The report
	// still lists the clock before the names, as read.
	resolved := map[string]bool{}
	dns := make([]ctl.Check, 0, len(endpoints))
	for _, target := range endpoints {
		check := d.Network.CheckDNS(ctx, target)
		resolved[target.Host] = check.Status == ctl.StatusPass
		dns = append(dns, check)
	}
	switch {
	case len(endpoints) == 0:
		report.Add(ctl.NotRun("clock", "no endpoint to compare with"))
	case !resolved[endpoints[0].Host]:
		report.Add(ctl.NotRun("clock", "the name "+endpoints[0].Host+" did not resolve (see dns."+endpoints[0].Name+")"))
	default:
		report.Add(d.Network.CheckClock(ctx, endpoints[0], pool))
	}
	for _, check := range dns {
		report.Add(check)
	}
	for _, target := range endpoints {
		report.Add(d.Network.CheckTLS(ctx, target, pool, poolErr, resolved[target.Host]))
	}

	report.Add(d.checkStateDir(cfg.Relay.StateDir))
	state, stateErr := d.State(cfg.Relay.StateDir)
	report.Add(d.checkBuffer(cfg, state, stateErr))
	report.Add(d.checkUpstream(state, stateErr))
	report.Add(d.checkListener(cfg.Relay.Listen))
	report.Add(d.checkPacnew())
	return report
}

// checkConfiguration reads the file and its permissions.
//
// The relay has no environment file and no legacy layout to fall back to:
// the YAML is the only source, so a file that does not load is the end of
// the diagnosis of everything that depends on it.
func (d diagnostics) checkConfiguration() (relayconfig.Config, ctl.Check, bool) {
	cfg, err := relayconfig.Load(d.ConfigPath)
	if err != nil {
		if _, statErr := os.Stat(d.ConfigPath); os.IsNotExist(statErr) {
			return cfg, ctl.Fail("config", "config_missing",
				fmt.Sprintf("%s does not exist: fill in the file", d.ConfigPath)), false
		}
		return cfg, ctl.Fail("config", ctl.CodeOf(err, "config_decode"),
			fmt.Sprintf("%s: %v", d.ConfigPath, err)), false
	}
	if err := ctl.FilePermissions(d.ConfigPath); err != nil {
		return cfg, ctl.Fail("config", "config_permissions_open", err.Error()), false
	}
	return cfg, ctl.Pass("config", d.ConfigPath), true
}

// checkIdentity reads the identity without any connection.
func (d diagnostics) checkIdentity(identity storedIdentity) ctl.Check {
	if !identity.Present {
		return ctl.Fail("identity", "identity_missing",
			fmt.Sprintf("%s; enroll the relay: sudo -u flotestro-relay flotestro-relayctl enroll", identity.Err))
	}
	until := identity.NotAfter.UTC().Format(time.RFC3339)
	if identity.Expired {
		return ctl.Fail("identity", "identity_expired",
			fmt.Sprintf("relay/%s; the certificate expired at %s", identity.RelayID, until))
	}
	left := identity.NotAfter.Sub(d.Now())
	days := int(left.Hours() / 24)
	detail := fmt.Sprintf("relay/%s, the certificate until %s (%s)", identity.RelayID, until, ctl.Rounded(left))
	check := ctl.Pass("identity", detail)
	// A relay certificate lives about a week and renews at a third left,
	// so one with less than a day is a renewal that has been failing since
	// yesterday - and a site about to be cut off.
	if left < 24*time.Hour {
		check = ctl.Warn("identity", "identity_expiring", detail+"; the renewal is late: see the journal of the relay")
	}
	check.DaysLeft = &days
	return check
}

// checkStateDir makes sure the relay can write where it keeps its identity
// and its state.
//
// A new generation of the identity is written next to the old one, and a
// directory the relay cannot write to means the next renewal fails - at a
// moment nobody is looking. The check runs as the caller, so it says
// something only when the caller is the service user or root.
func (d diagnostics) checkStateDir(dir string) ctl.Check {
	info, err := os.Stat(dir)
	if err != nil {
		return ctl.Fail("state_dir", "state_dir_missing", fmt.Sprintf("%s: %v", dir, err))
	}
	if !info.IsDir() {
		return ctl.Fail("state_dir", "state_dir_missing", fmt.Sprintf("%s is not a directory", dir))
	}
	if err := d.Writable(dir); err != nil {
		return ctl.Fail("state_dir", "state_dir_unwritable", fmt.Sprintf("%s: %v", dir, err))
	}
	free, err := d.FreeSpace(dir)
	if err != nil {
		return ctl.Warn("state_dir", "state_dir_space_unknown", fmt.Sprintf("%s is writable; free space: %v", dir, err))
	}
	check := ctl.Pass("state_dir", fmt.Sprintf("%s is writable, %s free", dir, ctl.Bytes(free)))
	if free < freeSpaceWarnBelow {
		check = ctl.Warn("state_dir", "state_dir_low_space",
			fmt.Sprintf("%s is writable, only %s free: the next renewal may fail to write", dir, ctl.Bytes(free)))
	}
	check.FreeBytes = &free
	return check
}

// checkBuffer judges the fill of the buffer from the state file.
//
// The buffer lives in the memory of the relay, so the tool sees it only
// through what the daemon wrote down. A full buffer is an operational
// event: from that moment the site loses results.
func (d diagnostics) checkBuffer(cfg relayconfig.Config, state ctl.RelayState, stateErr error) ctl.Check {
	if stateErr != nil {
		return ctl.NotRun("buffer", fmt.Sprintf("no state file in %s: the relay has not run yet", cfg.Relay.StateDir))
	}
	limit := state.BufferMaxBytes
	if limit <= 0 {
		limit = cfg.Buffer()
	}
	used := state.BufferBytes
	detail := fmt.Sprintf("%s of %s, %d items", ctl.Bytes(used), ctl.Bytes(limit), state.BufferedItems)
	if state.BufferedItems > 0 && state.BufferingSince != nil {
		detail += fmt.Sprintf(", oldest up to %s", ctl.Rounded(d.Now().Sub(*state.BufferingSince)))
	}
	check := ctl.Pass("buffer", detail)
	switch {
	case state.BufferDropped > 0:
		check = ctl.Warn("buffer", "relay_buffer_dropping",
			fmt.Sprintf("%s; %d results were dropped since the start: the site loses results", detail, state.BufferDropped))
	case limit > 0 && float64(used) > bufferWarnAbove*float64(limit):
		check = ctl.Warn("buffer", "relay_buffer_high", detail+"; the buffer is nearly full: see upstream")
	}
	check.UsedBytes = &used
	check.MaxBytes = &limit
	return check
}

// checkUpstream says whether the relay reaches the centre, from the state
// file: the daemon holds the mTLS identity, and the tool asks it rather
// than the centre.
func (d diagnostics) checkUpstream(state ctl.RelayState, stateErr error) ctl.Check {
	if stateErr != nil {
		return ctl.NotRun("upstream", "no state file: the relay has not run yet")
	}
	if state.LastUpstreamAt == nil {
		reason := state.LastUpstreamError
		if reason == "" {
			reason = "no contact recorded"
		}
		return ctl.Fail("upstream", "relay_upstream_unreached",
			fmt.Sprintf("%s was never reached: %s", state.Gateway, reason))
	}
	since := d.Now().Sub(*state.LastUpstreamAt)
	detail := fmt.Sprintf("%s, last contact %s ago", state.Gateway, ctl.Rounded(since))
	if state.LastUpstreamError != "" {
		detail += "; last error: " + state.LastUpstreamError
	}
	if since > silentAfter || !state.UpstreamOK {
		return ctl.Warn("upstream", "relay_upstream_stale", detail+"; the panel counts the relay as silent")
	}
	return ctl.Pass("upstream", detail)
}

// checkListener says whether the relay accepts connections from the agents.
func (d diagnostics) checkListener(address string) ctl.Check {
	if err := d.Listener(address); err != nil {
		return ctl.Fail("listener", "listener_unavailable",
			fmt.Sprintf("%s: %v; is flotestro-relay.service running?", address, err))
	}
	return ctl.Pass("listener", address)
}

// unmergedSuffixes are the names the package managers give a new version of
// a configuration file they did not dare to overwrite.
var unmergedSuffixes = []string{".pacnew", ".rpmnew", ".dpkg-dist"}

// checkPacnew looks for a configuration the package update did not merge.
func (d diagnostics) checkPacnew() ctl.Check {
	var found []string
	for _, suffix := range unmergedSuffixes {
		candidate := d.ConfigPath + suffix
		if _, err := os.Stat(candidate); err == nil {
			found = append(found, candidate)
		}
	}
	if len(found) == 0 {
		return ctl.Pass("pacnew", "no unmerged configuration")
	}
	return ctl.Warn("pacnew", "config_unmerged_update",
		fmt.Sprintf("the package update left %s: merge it into %s", strings.Join(found, ", "), d.ConfigPath))
}
