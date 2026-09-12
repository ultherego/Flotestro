// Command agent connects a host to the Flotestro control plane.
// The process runs without root privileges; mutations are handed over to the
// helper.
package main

import (
	"context"
	"flag"
	"log/slog"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"
	"time"

	"github.com/ultherego/flotestro/internal/agent"
	"github.com/ultherego/flotestro/internal/agentconfig"
	"github.com/ultherego/flotestro/internal/config"
	"github.com/ultherego/flotestro/internal/packages"
)

func main() {
	var (
		stateDir = flag.String("state-dir",
			config.Env("FLOTESTRO_AGENT_STATE_DIR", "/var/lib/flotestro-agent"), "the state directory of the agent")
		enrollmentURL = flag.String("enrollment-url",
			config.Env("FLOTESTRO_ENROLLMENT_URL", ""), "the address of the enrollment endpoint")
		gatewayURL = flag.String("gateway-url",
			config.Env("FLOTESTRO_GATEWAY_URL", ""),
			"the address of the agent gateway; it overrides the whole list from the file")
		token = flag.String("enrollment-token",
			config.Env("FLOTESTRO_ENROLLMENT_TOKEN", ""), "the enrollment token (the first start only)")
		caFile = flag.String("ca-file",
			config.Env("FLOTESTRO_CA_FILE", ""), "the CA bundle for bootstrapping the trust")
		inventoryMinutes = flag.Int("inventory-minutes",
			config.EnvInt("FLOTESTRO_INVENTORY_MINUTES", 15), "the interval of a full inventory")
		helperSocket = flag.String("helper-socket",
			config.Env("FLOTESTRO_HELPER_SOCKET", "/run/flotestro/helper.sock"),
			"the socket of the root helper")
		maxTasks = flag.Int("max-concurrent-tasks",
			config.EnvInt("FLOTESTRO_MAX_CONCURRENT_TASKS", 2), "the limit of concurrent jobs")
		once = flag.Bool("collect-once", false, "print the collected facts and finish")
		// The YAML file is the canonical source of the settings; the flags and
		// the environment variables stay as an override for images and
		// tests.
		configPath = flag.String("config",
			config.Env("FLOTESTRO_AGENT_CONFIG", agentconfig.DefaultPath),
			"the configuration file of the agent")
		mode = flag.String("mode", config.Env("FLOTESTRO_AGENT_MODE", ""),
			"the mode of work: full or read_only")
	)
	flag.Parse()

	// What the operator set and what came from the defaults - that
	// distinction is the whole content of the precedence: a file must not
	// override what somebody gave explicitly, and the default value of a flag
	// must not pretend to be a decision.
	explicit := map[string]bool{}
	flag.Visit(func(f *flag.Flag) { explicit[f.Name] = true })

	log := slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelInfo}))
	slog.SetDefault(log)

	// The gateways in order of priority. An empty list means "only what was
	// given by a flag or a variable" - and it is then filled in below with a
	// single address.
	var gateways []string

	cfg, fromFile, err := readConfiguration(*configPath)
	if err != nil {
		log.Error("the configuration of the agent", "file", *configPath, "err", err)
		os.Exit(1)
	}
	if fromFile {
		apply(cfg, explicit, settings{
			stateDir: stateDir, enrollmentURL: enrollmentURL, gatewayURL: gatewayURL,
			gateways: &gateways, caFile: caFile, helperSocket: helperSocket,
			inventoryMinutes: inventoryMinutes, maxTasks: maxTasks, mode: mode,
		})
		log.Info("the configuration was read", "file", *configPath,
			"gateways", len(cfg.Connection.GatewayURLs), "mode", *mode)
	} else {
		// Backwards compatibility: a host set up before the YAML file was
		// introduced goes on working with the environment variables. It has
		// to know it is taking the old path, though - otherwise it stays on
		// it for good.
		log.Warn("no configuration file, using the environment variables",
			"file", *configPath)
	}

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	// The system tools need a writable HOME. The agent has no home directory,
	// so we point them at the state directory; without that dnf ends with an
	// error that is easy to mistake for a result.
	runtimeDir := filepath.Join(*stateDir, "run")
	if err := agent.SetRuntimeDir(runtimeDir); err != nil {
		log.Error("the working directory was not prepared", "err", err)
		os.Exit(1)
	}
	if err := packages.SetRuntimeDir(runtimeDir); err != nil {
		log.Error("the working directory of the package adapter was not prepared", "err", err)
		os.Exit(1)
	}

	if *once {
		if err := printFacts(ctx); err != nil {
			log.Error("the facts were not collected", "err", err)
			os.Exit(1)
		}
		return
	}

	if len(gateways) == 0 && *gatewayURL != "" {
		gateways = []string{*gatewayURL}
	}
	if *enrollmentURL == "" || len(gateways) == 0 {
		log.Error("--enrollment-url and --gateway-url are required")
		os.Exit(1)
	}

	identity, err := agent.EnsureIdentity(ctx, *stateDir, *enrollmentURL, *token, *caFile)
	if err != nil {
		log.Error("no identity of the agent", "err", err)
		os.Exit(1)
	}
	log.Info("the identity of the agent is ready",
		"host_id", identity.HostID, "cert_not_after", identity.NotAfter.Format(time.RFC3339))

	// The idempotency journal survives a restart of the agent: a job delivered
	// again has to return the previous result rather than carry the mutation
	// out a second time.
	journal, err := agent.NewIdempotencyJournal(filepath.Join(*stateDir, "tasks"), 24*time.Hour)
	if err != nil {
		log.Error("the idempotency journal was not opened", "err", err)
		os.Exit(1)
	}

	executor := agent.NewTaskExecutor(
		agent.NewHelperClient(*helperSocket), journal, func() agent.Facts { return agent.Facts{} }, log)
	// The observation mode is a decision of the owner of the host rather than
	// a missing capability: the agent reports facts but carries out no
	// change.
	if *mode == agentconfig.ModeReadOnly {
		executor.UstawTrybOdczytu(true)
		log.Info("the agent works in the observation mode", "mode", *mode)
	}

	// The privileged part of the domain state goes through the helper; the
	// agent has access neither to the keytab of the host nor to the cache
	// database of SSSD.
	agent.SetPrivilegedIdentityProbe(executor.ProbePrivilegedIdentity)
	agent.SetPrivilegedAccountProbe(executor.ProbeLocalAccounts)
	agent.SetDockerProbe(executor.ProbeDocker)
	agent.SetScheduleProbe(executor.ProbeSchedules)
	// The network module checks after a change whether the host still reaches
	// the panel. One gateway is enough: the question is whether the host has
	// a path to the centre at all, not which of them serves the current
	// session.
	agent.SetGatewayURL(gateways[0])
	agent.SetFirewallProbe(executor.ProbeFirewall)
	agent.SetLVMProbe(executor.ProbeLVM)
	agent.SetSSHProbe(executor.ProbeSSH)
	agent.SetKernelProbe(executor.ProbeKernel)
	agent.SetFileProbe(executor.ProbeFiles)
	agent.SetSecurityProbe(executor.ProbeSecurity)
	agent.SetCertificateProbe(executor.ProbeCertificates)

	// The certificate of the agent is short-lived. Without renewal the whole
	// host would drop out of the fleet on the day it expires, because the
	// enrollment token is no longer on it.
	renewals := make(chan struct{}, 1)
	go agent.KeepCertificateFresh(ctx, identity, agent.RenewalOptions{
		StateDir: *stateDir,
		// The renewal goes to the gateway of first choice. It is not urgent to
		// the minute: a third of the life of the certificate is still left
		// then, so a failure of that one gateway does not cut the host off.
		GatewayURL: gateways[0],
		Log:        log,
		OnRenewed: func() {
			select {
			case renewals <- struct{}{}:
			default:
			}
		},
	})

	if err := agent.Run(ctx, agent.SessionOptions{
		GatewayURLs:        gateways,
		Identity:           identity,
		InventoryInterval:  time.Duration(*inventoryMinutes) * time.Minute,
		Executor:           executor,
		MaxConcurrentTasks: *maxTasks,
		Log:                log,
		Renewed:            renewals,
		// The state on disk is the only source agentctl on a host without the
		// panel learns from whether the agent really speaks to the gateway.
		Stan: agent.NowyPisarzStanu(*stateDir, identity.HostID),
	}); err != nil {
		log.Error("the agent ended with an error", "err", err)
		os.Exit(1)
	}
}

func printFacts(ctx context.Context) error {
	facts, err := agent.Collect(ctx)
	if err != nil {
		return err
	}
	_, raw, err := facts.Revision()
	if err != nil {
		return err
	}
	_, err = os.Stdout.Write(append(raw, '\n'))
	return err
}

// settings gathers the pointers to the values the file can give.
type settings struct {
	stateDir         *string
	enrollmentURL    *string
	gatewayURL       *string
	gateways         *[]string
	caFile           *string
	helperSocket     *string
	inventoryMinutes *int
	maxTasks         *int
	mode             *string
}

// readConfiguration reads the YAML file if it exists.
//
// A missing file is not an error: a host set up before it was introduced is to
// go on working. A file that is there and is wrong is an error - an agent that
// started with the default settings instead of the recorded ones would connect
// somewhere other than the operator wrote down.
func readConfiguration(path string) (agentconfig.Config, bool, error) {
	if path == "" {
		return agentconfig.Config{}, false, nil
	}
	if _, err := os.Stat(path); err != nil {
		if os.IsNotExist(err) {
			return agentconfig.Config{}, false, nil
		}
		return agentconfig.Config{}, false, err
	}
	cfg, err := agentconfig.Load(path)
	if err != nil {
		return agentconfig.Config{}, false, err
	}
	if err := cfg.CheckBootstrapCA(); err != nil {
		return agentconfig.Config{}, false, err
	}
	return cfg, true, nil
}

// apply writes the values from the file wherever nobody gave their own.
//
// The precedence: an explicit flag > an environment variable > the file > the
// defaults.
func apply(cfg agentconfig.Config, explicit map[string]bool, target settings) {
	set := func(flagName, variable string, value string, destination *string) {
		if value == "" || explicit[flagName] || os.Getenv(variable) != "" {
			return
		}
		*destination = value
	}
	set("state-dir", "FLOTESTRO_AGENT_STATE_DIR", cfg.Agent.StateDir, target.stateDir)
	set("enrollment-url", "FLOTESTRO_ENROLLMENT_URL", cfg.Connection.EnrollmentURL, target.enrollmentURL)
	// The list of gateways is ordered by priority and goes to the agent as a
	// whole: switching to a backup gateway must not be a manual act of the
	// operator at the moment the centre fails. An explicit flag or an
	// environment variable replaces the whole list - whoever gives one address
	// wants exactly that one.
	if len(cfg.Connection.GatewayURLs) > 0 {
		set("gateway-url", "FLOTESTRO_GATEWAY_URL", cfg.Connection.GatewayURLs[0], target.gatewayURL)
		if !explicit["gateway-url"] && os.Getenv("FLOTESTRO_GATEWAY_URL") == "" {
			*target.gateways = append([]string{}, cfg.Connection.GatewayURLs...)
		}
	}
	set("ca-file", "FLOTESTRO_CA_FILE", cfg.Connection.BootstrapCA, target.caFile)
	set("helper-socket", "FLOTESTRO_HELPER_SOCKET", cfg.Helper.Socket, target.helperSocket)
	set("mode", "FLOTESTRO_AGENT_MODE", cfg.Agent.Mode, target.mode)

	if !explicit["inventory-minutes"] && os.Getenv("FLOTESTRO_INVENTORY_MINUTES") == "" {
		*target.inventoryMinutes = int(cfg.Agent.InventoryInterval / time.Minute)
	}
	if !explicit["max-concurrent-tasks"] && os.Getenv("FLOTESTRO_MAX_CONCURRENT_TASKS") == "" {
		*target.maxTasks = cfg.Agent.MaxConcurrentTasks
	}
}
