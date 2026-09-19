package main

import (
	"flag"
	"fmt"
	"io"

	"github.com/ultherego/flotestro/internal/agentconfig"
	"github.com/ultherego/flotestro/internal/ctl"
)

// configurationCommands handles "config validate", "config show" and "config
// migrate".
func configurationCommands(args []string, out, errOut io.Writer) int {
	if len(args) == 0 {
		fmt.Fprintln(errOut, "usage: agentctl config validate|show|migrate [--config FILE]")
		return 2
	}
	switch args[0] {
	case "validate":
		return checkConfiguration(args[1:], out, errOut, false)
	case "show":
		return checkConfiguration(args[1:], out, errOut, true)
	case "migrate":
		return migrateConfiguration(args[1:], out, errOut)
	default:
		fmt.Fprintf(errOut, "unknown config command: %s\n", args[0])
		return 2
	}
}

// configurationPath reads the shared --config flag.
func configurationPath(name string, args []string, errOut io.Writer) (string, bool) {
	flags := flag.NewFlagSet(name, flag.ContinueOnError)
	flags.SetOutput(errOut)
	path := flags.String("config", agentconfig.DefaultPath, "the configuration file of the agent")
	if err := flags.Parse(args); err != nil {
		return "", false
	}
	return *path, true
}

// checkConfiguration reads the file and says what is wrong with it.
func checkConfiguration(args []string, out, errOut io.Writer, show bool) int {
	path, ok := configurationPath("config", args, errOut)
	if !ok {
		return 2
	}

	cfg, err := agentconfig.Load(path)
	if err != nil {
		fmt.Fprintf(errOut, "config: %s\n  %v\n", path, err)
		return 1
	}
	problems := 0
	if err := cfg.CheckBootstrapCA(); err != nil {
		fmt.Fprintf(errOut, "bootstrap_ca_file: %v\n", err)
		problems++
	}
	if err := filePermissions(path); err != nil {
		fmt.Fprintf(errOut, "file permissions: %v\n", err)
		problems++
	}
	if problems > 0 {
		return 1
	}

	fmt.Fprintf(out, "Config:       correct (%s)\n", path)
	if !show {
		return 0
	}
	fmt.Fprintf(out, "Enrollment:   %s\n", cfg.Connection.EnrollmentURL)
	for i, address := range cfg.Connection.GatewayURLs {
		label := "Gateway:     "
		if i > 0 {
			// The further gateways are backups: we show them under the first
			// one without repeating the label.
			label = "             "
		}
		fmt.Fprintf(out, "%s %s\n", label, address)
	}
	if cfg.Connection.BootstrapCA != "" {
		fmt.Fprintf(out, "Bootstrap CA: %s\n", cfg.Connection.BootstrapCA)
	}
	fmt.Fprintf(out, "Timeouts:     connect %s, reconnect %s-%s\n",
		cfg.Connection.ConnectTimeout, cfg.Connection.ReconnectMin, cfg.Connection.ReconnectMax)
	fmt.Fprintf(out, "Agent:        state %s, inventory every %s, jobs %d, mode %s\n",
		cfg.Agent.StateDir, cfg.Agent.InventoryInterval, cfg.Agent.MaxConcurrentTasks, cfg.Agent.Mode)
	fmt.Fprintf(out, "Helper:       %s\n", cfg.Helper.Socket)
	return 0
}

// filePermissions makes sure that not just anybody can swap the configuration
// out.
func filePermissions(path string) error { return ctl.FilePermissions(path) }
