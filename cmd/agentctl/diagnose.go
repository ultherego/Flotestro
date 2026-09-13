package main

import (
	"context"
	"crypto/x509"
	"flag"
	"fmt"
	"io"
	"net"
	"net/url"
	"os"
	"regexp"
	"strings"
	"time"

	"github.com/ultherego/flotestro/internal/agent"
	"github.com/ultherego/flotestro/internal/agentconfig"
)

// diagnoseCommand checks the path from the host to the panel step by step.
//
// The steps are deliberately separate and independent. "It does not work" is
// not an answer: one thing is fixed when a name does not resolve, another
// when a port is closed, and another still when the chain of certificates
// does not match. A failed step stops the rest only when it makes them
// meaningless - and then they say so instead of failing a second time for
// the same reason.
//
// Nothing here changes the host. The diagnosis reads, connects and reports;
// the fix is always a separate, explicit command.
func diagnoseCommand(args []string, out, errOut io.Writer) int {
	flags := flag.NewFlagSet("diagnose", flag.ContinueOnError)
	flags.SetOutput(errOut)
	path := flags.String("config", agentconfig.DefaultPath, "the configuration file of the agent")
	environment := flags.String("env-file", DefaultEnvironmentPath, "the environment file of the service")
	asJSON := flags.Bool("json", false, "print the report as JSON")
	if err := flags.Parse(args); err != nil {
		return 2
	}
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	d := newDiagnostics(*path)
	d.EnvironmentPath = *environment
	report := d.run(ctx)

	if *asJSON {
		if err := renderJSON(out, report); err != nil {
			fmt.Fprintf(errOut, "the report was not written: %v\n", err)
			return 1
		}
	} else {
		renderText(out, report)
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
// directory without a network and without root.
type diagnostics struct {
	ConfigPath      string
	EnvironmentPath string
	MachineIDPath   string
	// Environ is the environment of the process; nil means the real one.
	Environ map[string]string

	Now     func() time.Time
	Timeout time.Duration
	// Dial opens the TCP connection for the TLS and clock checks.
	Dial func(ctx context.Context, network, address string) (net.Conn, error)
	// LookupHost resolves a name for the DNS checks.
	LookupHost func(ctx context.Context, host string) ([]string, error)
	// Socket says whether the helper answers on its socket.
	Socket       func(path string) error
	Capabilities func() agent.Capabilities
	Identity     func(stateDir string) agent.StoredIdentity
}

// newDiagnostics wires the diagnosis to the real host.
func newDiagnostics(configPath string) diagnostics {
	return diagnostics{
		ConfigPath:      configPath,
		EnvironmentPath: DefaultEnvironmentPath,
		MachineIDPath:   "/etc/machine-id",
		Now:             time.Now,
		Timeout:         15 * time.Second,
		Dial:            (&net.Dialer{}).DialContext,
		LookupHost:      net.DefaultResolver.LookupHost,
		Socket:          socketWorks,
		Capabilities:    agent.DetectCapabilities,
		Identity:        agent.ReadIdentity,
	}
}

// endpoint is one address of the panel the host connects to.
type endpoint struct {
	// Name labels the checks: "enrollment", "gateway", "gateway.2"...
	Name string
	URL  string
	Host string
	Port string
}

// endpointsOf lists the addresses in the order the agent uses them.
func endpointsOf(cfg agentconfig.Config) []endpoint {
	var endpoints []endpoint
	add := func(name, raw string) {
		address, err := url.Parse(raw)
		if err != nil {
			return
		}
		port := address.Port()
		if port == "" {
			port = "443"
		}
		endpoints = append(endpoints, endpoint{Name: name, URL: raw, Host: address.Hostname(), Port: port})
	}
	add("enrollment", cfg.Connection.EnrollmentURL)
	for i, raw := range cfg.Connection.GatewayURLs {
		name := "gateway"
		if i > 0 {
			// The further gateways are backups: they get a number rather
			// than a name of their own.
			name = fmt.Sprintf("gateway.%d", i+1)
		}
		add(name, raw)
	}
	return endpoints
}

// run carries out every check and gathers the report.
func (d diagnostics) run(ctx context.Context) Report {
	report := Report{OK: true}

	cfg, configCheck, usable := d.checkConfiguration()
	report.add(configCheck)
	report.add(d.checkMachineID())

	if !usable {
		why := "the configuration did not load; see config"
		for _, name := range []string{"clock", "dns.enrollment", "dns.gateway",
			"tls.enrollment", "tls.gateway", "identity", "helper.socket"} {
			report.add(notRun(name, why))
		}
	} else {
		endpoints := endpointsOf(cfg)
		identity := d.Identity(cfg.Agent.StateDir)
		pool, poolErr := trustPool(cfg, identity)

		// The names are resolved first: a name that does not resolve makes
		// every dial to it meaningless, and the checks that would dial say
		// so instead of failing a second time for the same reason. The
		// report still lists the clock before the names, as read.
		resolved := map[string]bool{}
		dns := make([]Check, 0, len(endpoints))
		for _, target := range endpoints {
			check := d.checkDNS(ctx, target)
			resolved[target.Host] = check.Status == StatusPass
			dns = append(dns, check)
		}
		switch {
		case len(endpoints) == 0:
			report.add(notRun("clock", "no endpoint to compare with"))
		case !resolved[endpoints[0].Host]:
			report.add(notRun("clock", "the name "+endpoints[0].Host+" did not resolve (see dns."+endpoints[0].Name+")"))
		default:
			report.add(d.checkClock(ctx, endpoints[0], pool))
		}
		for _, check := range dns {
			report.add(check)
		}
		for _, target := range endpoints {
			report.add(d.checkTLS(ctx, target, pool, poolErr, resolved[target.Host]))
		}

		report.add(d.checkIdentity(identity))
		report.add(d.checkHelper(cfg))
	}

	report.add(d.checkCapabilities())
	report.add(d.checkPacnew())
	return report
}

// checkConfiguration reads the file and says which overrides apply to it.
//
// Three outcomes: the file loads, the file is missing but the environment
// file still carries the settings from before the YAML was introduced, or
// nothing usable is there. The second is a warning rather than a failure -
// the daemon still starts on it - but it is the state the host has to leave.
func (d diagnostics) checkConfiguration() (agentconfig.Config, Check, bool) {
	fileValues, fileErr := readEnvironmentFile(d.EnvironmentPath)
	if fileErr != nil {
		fileValues = map[string]string{}
	}
	environ := d.Environ
	if environ == nil {
		environ = processEnvironment()
	}
	// The daemon sees the environment file through systemd as its own
	// environment; a variable given to the process directly wins over the
	// file, the way a flag would win over both.
	effective := map[string]string{}
	for key, value := range fileValues {
		effective[key] = value
	}
	for key, value := range environ {
		effective[key] = value
	}
	list := overrides(environ, fileValues, d.EnvironmentPath)

	cfg, err := agentconfig.Load(d.ConfigPath)
	if err != nil {
		if _, statErr := os.Stat(d.ConfigPath); os.IsNotExist(statErr) {
			if !legacySettings(effective) {
				return cfg, fail("config", "config_missing",
					fmt.Sprintf("%s does not exist and %s carries no settings: fill in the file",
						d.ConfigPath, d.EnvironmentPath)), false
			}
			cfg, err = configurationFromEnvironment(effective)
			if err != nil {
				check := fail("config", codeOf(err, "config_decode"),
					fmt.Sprintf("the settings in %s: %v", d.EnvironmentPath, err))
				check.Overrides = list
				return cfg, check, false
			}
			check := warn("config", "config_legacy_env",
				fmt.Sprintf("%s does not exist; the daemon runs on %s: convert it with flotestro-agentctl config migrate",
					d.ConfigPath, d.EnvironmentPath))
			check.Overrides = list
			return cfg, check, true
		}
		return cfg, fail("config", codeOf(err, "config_decode"), fmt.Sprintf("%s: %v", d.ConfigPath, err)), false
	}

	if err := cfg.CheckBootstrapCA(); err != nil {
		return cfg, fail("config", codeOf(err, "bootstrap_ca_invalid"), err.Error()), false
	}
	if err := filePermissions(d.ConfigPath); err != nil {
		return cfg, fail("config", "config_permissions_open", err.Error()), false
	}

	// What the daemon connects to is the file with the overrides on top: a
	// diagnosis of the file alone would pass while the daemon goes
	// elsewhere.
	effectiveCfg, err := overlayEnvironment(cfg, effective)
	if err != nil {
		check := fail("config", codeOf(err, "config_decode"),
			fmt.Sprintf("the overrides in %s: %v", d.EnvironmentPath, err))
		check.Overrides = list
		return cfg, check, false
	}
	check := pass("config", d.ConfigPath)
	check.Overrides = list
	if fileErr != nil {
		check = warn("config", "env_file_unreadable", fmt.Sprintf("%s; %s: %v", d.ConfigPath, d.EnvironmentPath, fileErr))
		check.Overrides = list
	}
	if fileValues["FLOTESTRO_ENROLLMENT_TOKEN"] != "" {
		// The token is used once; a line that stays after the enrollment
		// keeps a secret in a file that survives package updates and ends
		// up in backups.
		check = warn("config", "enrollment_token_lingering",
			fmt.Sprintf("%s; the enrollment token is still in %s: remove the line once the host is enrolled",
				d.ConfigPath, d.EnvironmentPath))
		check.Overrides = list
	}
	return effectiveCfg, check, true
}

// codeOf takes the stable code out of an error of the configuration.
//
// The errors of the parser start with their code ("config_decode: ..."), so
// the text up to the first colon is the code - as long as it looks like one.
func codeOf(err error, fallback string) string {
	text := err.Error()
	code, _, _ := strings.Cut(text, ":")
	code = strings.TrimSpace(code)
	if code == "" || strings.ContainsAny(code, " \t/") {
		return fallback
	}
	return code
}

var machineIDPattern = regexp.MustCompile(`^[0-9a-f]{32}$`)

// checkMachineID makes sure the host has the identifier the enrollment is
// bound to.
//
// A host cloned from an image often carries the machine-id of the image, and
// two hosts with one identifier look like one host to the panel. The check
// cannot see the clone, but it can see the missing or the malformed file.
func (d diagnostics) checkMachineID() Check {
	content, err := os.ReadFile(d.MachineIDPath)
	if err != nil {
		return fail("machine_id", "machine_id_missing", fmt.Sprintf("%s: %v", d.MachineIDPath, err))
	}
	id := strings.TrimSpace(string(content))
	if !machineIDPattern.MatchString(id) {
		return fail("machine_id", "machine_id_invalid",
			fmt.Sprintf("%s does not hold 32 hexadecimal characters", d.MachineIDPath))
	}
	return pass("machine_id", d.MachineIDPath)
}

// trustPool assembles the trust for checking the connections.
//
// The same bundle the agent uses: the trust bundle of the identity when the
// host has one, and the bootstrap CA from the configuration. Nothing
// configured means the system roots, which is the public-CA variant of the
// bootstrap. A configured bundle that cannot be read or parsed is an error
// of its own, not a silent fall back to the system roots.
func trustPool(cfg agentconfig.Config, identity agent.StoredIdentity) (*x509.CertPool, error) {
	pool := x509.NewCertPool()
	added := false
	if identity.Present && identity.Paths.CA != "" {
		if content, err := os.ReadFile(identity.Paths.CA); err == nil && pool.AppendCertsFromPEM(content) {
			added = true
		}
	}
	if path := cfg.Connection.BootstrapCA; path != "" {
		content, err := os.ReadFile(path)
		if err != nil {
			return nil, fmt.Errorf("%s: %v", path, err)
		}
		if !pool.AppendCertsFromPEM(content) {
			return nil, fmt.Errorf("%s holds no certificate", path)
		}
		added = true
	}
	if !added {
		return nil, nil
	}
	return pool, nil
}

// checkIdentity reads the identity without any connection.
func (d diagnostics) checkIdentity(identity agent.StoredIdentity) Check {
	if !identity.Present {
		return fail("identity", "identity_missing",
			fmt.Sprintf("%s; enroll the host: sudo -u flotestro-agent flotestro-agentctl enroll", identity.Err))
	}
	until := identity.NotAfter.UTC().Format(time.RFC3339)
	if identity.Expired {
		return fail("identity", "identity_expired",
			fmt.Sprintf("host/%s; the certificate expired at %s", identity.HostID, until))
	}
	days := int(identity.NotAfter.Sub(d.Now()).Hours() / 24)
	detail := fmt.Sprintf("host/%s, the certificate until %s (%d days)", identity.HostID, until, days)
	check := pass("identity", detail)
	if days < 7 {
		// The daemon renews at a third of the validity left, so a
		// certificate this close to the end means the renewal has been
		// failing for days.
		check = warn("identity", "identity_expiring", detail+"; the renewal is late: see the journal of the agent")
	}
	check.DaysLeft = &days
	return check
}

// checkHelper says whether the privileged part answers.
func (d diagnostics) checkHelper(cfg agentconfig.Config) Check {
	if cfg.Agent.Mode == agentconfig.ModeReadOnly {
		// In the read-only mode the helper has no right to run: its absence
		// is then an answer rather than a fault.
		return notRun("helper.socket", fmt.Sprintf("disabled in mode %s", cfg.Agent.Mode))
	}
	if err := d.Socket(cfg.Helper.Socket); err != nil {
		return fail("helper.socket", "helper_socket_unavailable", err.Error())
	}
	return pass("helper.socket", cfg.Helper.Socket)
}

// checkCapabilities counts what the host can do.
func (d diagnostics) checkCapabilities() Check {
	capabilities := d.Capabilities()
	available := 0
	for _, capability := range capabilities {
		if capability.Available {
			available++
		}
	}
	total := len(capabilities)
	check := pass("capabilities", fmt.Sprintf("%d of %d available", available, total))
	check.Available = &available
	check.Total = &total
	return check
}

// unmergedSuffixes are the names the package managers give a new version of
// a configuration file they did not dare to overwrite.
var unmergedSuffixes = []string{".pacnew", ".rpmnew", ".dpkg-dist"}

// checkPacnew looks for a configuration the package update did not merge.
//
// The new version lies next to the file and waits; until somebody merges it
// the host runs on the old settings and nothing says so.
func (d diagnostics) checkPacnew() Check {
	var found []string
	for _, suffix := range unmergedSuffixes {
		candidate := d.ConfigPath + suffix
		if _, err := os.Stat(candidate); err == nil {
			found = append(found, candidate)
		}
	}
	if len(found) == 0 {
		return pass("pacnew", "no unmerged configuration")
	}
	return warn("pacnew", "config_unmerged_update",
		fmt.Sprintf("the package update left %s: merge it into %s", strings.Join(found, ", "), d.ConfigPath))
}
