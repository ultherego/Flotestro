package main

import (
	"bufio"
	"fmt"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/ultherego/flotestro/internal/agentconfig"
)

// DefaultEnvironmentPath is the environment file of the service.
//
// It is the legacy form of the configuration: a host set up before agent.yaml
// was introduced keeps its settings here, and the daemon still reads the
// variables. The file also used to carry the enrollment token, which is why
// nothing here ever prints its value.
const DefaultEnvironmentPath = "/etc/flotestro/agent.env"

// environmentSetting ties a variable of the environment file to the entry of
// agent.yaml it stands for.
type environmentSetting struct {
	Variable string
	// Field names the YAML entry; empty when the variable has no place in the
	// file at all.
	Field string
	// Secret marks a value that is never shown, only reported as set.
	Secret bool
}

// environmentSettings lists the variables in the order the daemon applies them.
//
// This mirrors the precedence in the daemon: an explicit flag, then a
// variable, then the file, then the defaults. The tool sees no flags of the
// daemon - the service unit passes none - so a variable is the only override
// it can report.
var environmentSettings = []environmentSetting{
	{Variable: "FLOTESTRO_ENROLLMENT_TOKEN", Secret: true},
	{Variable: "FLOTESTRO_ENROLLMENT_URL", Field: "connection.enrollment_url"},
	{Variable: "FLOTESTRO_GATEWAY_URL", Field: "connection.gateway_urls"},
	{Variable: "FLOTESTRO_CA_FILE", Field: "connection.bootstrap_ca_file"},
	{Variable: "FLOTESTRO_AGENT_STATE_DIR", Field: "agent.state_dir"},
	{Variable: "FLOTESTRO_INVENTORY_MINUTES", Field: "agent.inventory_interval"},
	{Variable: "FLOTESTRO_MAX_CONCURRENT_TASKS", Field: "agent.max_concurrent_tasks"},
	{Variable: "FLOTESTRO_AGENT_MODE", Field: "agent.mode"},
	{Variable: "FLOTESTRO_HELPER_SOCKET", Field: "helper.socket"},
	{Variable: "FLOTESTRO_AGENT_CONFIG"},
}

// readEnvironmentFile reads the variables of a systemd environment file.
//
// A missing file is an empty set rather than an error: the Arch package does
// not carry one, and the service unit marks it optional too.
func readEnvironmentFile(path string) (map[string]string, error) {
	file, err := os.Open(path)
	if err != nil {
		if os.IsNotExist(err) {
			return map[string]string{}, nil
		}
		return nil, err
	}
	defer file.Close()

	values := map[string]string{}
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") || strings.HasPrefix(line, ";") {
			continue
		}
		line = strings.TrimPrefix(line, "export ")
		key, value, found := strings.Cut(line, "=")
		if !found {
			continue
		}
		key = strings.TrimSpace(key)
		value = strings.TrimSpace(value)
		// systemd accepts single and double quotes around a value; the
		// daemon sees the text between them.
		if len(value) >= 2 && (value[0] == '"' || value[0] == '\'') && value[len(value)-1] == value[0] {
			value = value[1 : len(value)-1]
		}
		values[key] = value
	}
	if err := scanner.Err(); err != nil {
		return nil, err
	}
	return values, nil
}

// legacySettings says whether the file carries any host setting - anything
// besides the one-time token.
func legacySettings(values map[string]string) bool {
	for _, setting := range environmentSettings {
		if setting.Field != "" && values[setting.Variable] != "" {
			return true
		}
	}
	return false
}

// configurationFromEnvironment builds the configuration the daemon would run
// with from the variables alone.
func configurationFromEnvironment(values map[string]string) (agentconfig.Config, error) {
	return overlayEnvironment(agentconfig.Defaults(), values)
}

// overlayEnvironment puts the variables on top of a configuration the way
// the daemon does.
//
// A gateway variable replaces the whole list: whoever gives one address
// wants exactly that one. The token is deliberately left out: it has no
// place in a file that survives package updates and ends up in backups.
func overlayEnvironment(cfg agentconfig.Config, values map[string]string) (agentconfig.Config, error) {
	if !legacySettings(values) {
		return cfg, nil
	}
	if value := values["FLOTESTRO_ENROLLMENT_URL"]; value != "" {
		cfg.Connection.EnrollmentURL = value
	}
	if value := values["FLOTESTRO_GATEWAY_URL"]; value != "" {
		cfg.Connection.GatewayURLs = []string{value}
	}
	if value := values["FLOTESTRO_CA_FILE"]; value != "" {
		cfg.Connection.BootstrapCA = value
	}
	if value := values["FLOTESTRO_AGENT_STATE_DIR"]; value != "" {
		cfg.Agent.StateDir = value
	}
	if value := values["FLOTESTRO_INVENTORY_MINUTES"]; value != "" {
		parsed, err := strconv.Atoi(value)
		if err != nil {
			return cfg, fmt.Errorf("FLOTESTRO_INVENTORY_MINUTES: %q is not a number", value)
		}
		cfg.Agent.InventoryInterval = time.Duration(parsed) * time.Minute
	}
	if value := values["FLOTESTRO_MAX_CONCURRENT_TASKS"]; value != "" {
		parsed, err := strconv.Atoi(value)
		if err != nil {
			return cfg, fmt.Errorf("FLOTESTRO_MAX_CONCURRENT_TASKS: %q is not a number", value)
		}
		cfg.Agent.MaxConcurrentTasks = parsed
	}
	if value := values["FLOTESTRO_AGENT_MODE"]; value != "" {
		cfg.Agent.Mode = value
	}
	if value := values["FLOTESTRO_HELPER_SOCKET"]; value != "" {
		cfg.Helper.Socket = value
	}
	if err := cfg.Check(); err != nil {
		return cfg, err
	}
	return cfg, nil
}

// overrides lists the variables that take precedence over the file, in the
// order the daemon applies them and without a single secret value.
//
// Two sources: the process environment - the way a container or a test gives
// its settings - and the environment file of the service, which the daemon
// sees through systemd and this tool does not.
func overrides(environ map[string]string, file map[string]string, filePath string) []string {
	var lines []string
	for _, setting := range environmentSettings {
		for _, source := range []struct {
			values map[string]string
			label  string
		}{{environ, "environment"}, {file, filePath}} {
			value := source.values[setting.Variable]
			if value == "" {
				continue
			}
			if setting.Secret {
				lines = append(lines, fmt.Sprintf("%s set (%s; value withheld)", setting.Variable, source.label))
				continue
			}
			lines = append(lines, fmt.Sprintf("%s=%s (%s)", setting.Variable, value, source.label))
		}
	}
	return lines
}

// processEnvironment picks the variables of the agent out of the environment
// of this process.
func processEnvironment() map[string]string {
	values := map[string]string{}
	for _, setting := range environmentSettings {
		if value := os.Getenv(setting.Variable); value != "" {
			values[setting.Variable] = value
		}
	}
	return values
}
