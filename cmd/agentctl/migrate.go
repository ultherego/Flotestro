package main

import (
	"flag"
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/ultherego/flotestro/internal/agentconfig"
)

// migrateConfiguration turns the environment file into agent.yaml.
//
// A host set up before the YAML file was introduced keeps its settings in
// the environment file of the service, and the daemon still reads them. The
// conversion writes the same settings in the canonical form - without the
// enrollment token, which has no place in a file that survives package
// updates and ends up in backups.
//
// Without --write nothing is touched: the command shows the file it would
// write. With it, the file is created and never overwritten - an existing
// agent.yaml is the canonical configuration and is edited, not regenerated.
func migrateConfiguration(args []string, out, errOut io.Writer) int {
	flags := flag.NewFlagSet("config migrate", flag.ContinueOnError)
	flags.SetOutput(errOut)
	target := flags.String("config", agentconfig.DefaultPath, "the configuration file to write")
	source := flags.String("env-file", DefaultEnvironmentPath, "the environment file to convert")
	write := flags.Bool("write", false, "write the file instead of showing it")
	if err := flags.Parse(args); err != nil {
		return 2
	}

	if _, err := os.Stat(*source); err != nil {
		fmt.Fprintf(errOut, "nothing to migrate: %s: %v\n", *source, err)
		return 1
	}
	values, err := readEnvironmentFile(*source)
	if err != nil {
		fmt.Fprintf(errOut, "%s: %v\n", *source, err)
		return 1
	}
	if !legacySettings(values) {
		fmt.Fprintf(out, "Nothing to migrate: %s carries no host settings.\n", *source)
		return 0
	}
	cfg, err := configurationFromEnvironment(values)
	if err != nil {
		fmt.Fprintf(errOut, "the settings in %s do not make a valid configuration: %v\n", *source, err)
		return 1
	}
	content := renderConfiguration(cfg, values)

	if !*write {
		fmt.Fprintf(out, "Would write %s from %s:\n\n%s\n", *target, *source, content)
		printMigrationNotes(out, *source, values)
		fmt.Fprintln(out, "Run again with --write to create the file.")
		return 0
	}

	// Exclusive creation: an existing file is somebody's decision, and the
	// conversion has no right to overrule it.
	file, err := os.OpenFile(*target, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o640)
	if err != nil {
		if os.IsExist(err) {
			fmt.Fprintf(errOut, "%s already exists; it is the canonical configuration - edit it rather than regenerate it\n", *target)
		} else {
			fmt.Fprintf(errOut, "%s: %v\n", *target, err)
		}
		return 1
	}
	if _, err := file.WriteString(content); err != nil {
		file.Close()
		fmt.Fprintf(errOut, "%s: %v\n", *target, err)
		return 1
	}
	if err := file.Close(); err != nil {
		fmt.Fprintf(errOut, "%s: %v\n", *target, err)
		return 1
	}
	fmt.Fprintf(out, "Created:      %s (0640)\n", *target)
	printMigrationNotes(out, *source, values)
	fmt.Fprintf(out, "Validate it: flotestro-agentctl config validate --config %s\n", *target)
	return 0
}

// printMigrationNotes says what the conversion deliberately left alone.
func printMigrationNotes(out io.Writer, source string, values map[string]string) {
	if values["FLOTESTRO_ENROLLMENT_TOKEN"] != "" {
		fmt.Fprintln(out, "The enrollment token was not copied: it is a one-time secret and has no place in the file.")
	}
	// The variables win over the file in the daemon, so the file decides
	// nothing until they are emptied - and emptying them before the service
	// runs on the file would cut a working host off.
	fmt.Fprintf(out, "The variables in %s still take precedence over the file: empty them once the service runs on it.\n", source)
}

// renderConfiguration writes the YAML form by hand.
//
// By hand rather than through a marshaller: the file is meant to be read and
// edited by a person, and only the entries the environment gave are written
// - the defaults stay defaults, so a later change of a default reaches the
// host.
func renderConfiguration(cfg agentconfig.Config, values map[string]string) string {
	var b strings.Builder
	b.WriteString("# Converted from the environment file of the service.\n")
	b.WriteString("# The enrollment token is deliberately absent: the identity of the host\n")
	b.WriteString("# is its certificate, and a token is used once.\n")
	fmt.Fprintf(&b, "schema_version: %d\n\n", agentconfig.SchemaVersion)

	b.WriteString("connection:\n")
	fmt.Fprintf(&b, "  enrollment_url: %q\n", cfg.Connection.EnrollmentURL)
	b.WriteString("  gateway_urls:\n")
	for _, address := range cfg.Connection.GatewayURLs {
		fmt.Fprintf(&b, "    - %q\n", address)
	}
	if cfg.Connection.BootstrapCA != "" {
		fmt.Fprintf(&b, "  bootstrap_ca_file: %q\n", cfg.Connection.BootstrapCA)
	}

	var agentLines []string
	if values["FLOTESTRO_AGENT_STATE_DIR"] != "" {
		agentLines = append(agentLines, fmt.Sprintf("  state_dir: %q", cfg.Agent.StateDir))
	}
	if values["FLOTESTRO_INVENTORY_MINUTES"] != "" {
		agentLines = append(agentLines, fmt.Sprintf("  inventory_interval: %q", cfg.Agent.InventoryInterval.String()))
	}
	if values["FLOTESTRO_MAX_CONCURRENT_TASKS"] != "" {
		agentLines = append(agentLines, fmt.Sprintf("  max_concurrent_tasks: %d", cfg.Agent.MaxConcurrentTasks))
	}
	if values["FLOTESTRO_AGENT_MODE"] != "" {
		agentLines = append(agentLines, fmt.Sprintf("  mode: %q", cfg.Agent.Mode))
	}
	if len(agentLines) > 0 {
		fmt.Fprintf(&b, "\nagent:\n%s\n", strings.Join(agentLines, "\n"))
	}
	if values["FLOTESTRO_HELPER_SOCKET"] != "" {
		fmt.Fprintf(&b, "\nhelper:\n  socket: %q\n", cfg.Helper.Socket)
	}
	return b.String()
}
