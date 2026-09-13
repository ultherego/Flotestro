package main

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/ultherego/flotestro/internal/agentconfig"
)

const legacyEnvironment = `# The environment of the service.
FLOTESTRO_ENROLLMENT_TOKEN=flt_secret_value
FLOTESTRO_ENROLLMENT_URL=https://enroll.example.com
FLOTESTRO_GATEWAY_URL="https://gw.example.com:8443"
FLOTESTRO_INVENTORY_MINUTES=30
FLOTESTRO_CA_FILE=
`

func TestConfigMigrateShowsTheFileWithoutWritingIt(t *testing.T) {
	directory := t.TempDir()
	source := filepath.Join(directory, "agent.env")
	target := filepath.Join(directory, "agent.yaml")
	if err := os.WriteFile(source, []byte(legacyEnvironment), 0o640); err != nil {
		t.Fatal(err)
	}
	var out, errOut bytes.Buffer
	code := run([]string{"config", "migrate", "--env-file", source, "--config", target}, &out, &errOut)
	if code != 0 {
		t.Fatalf("code = %d: %s", code, errOut.String())
	}
	if _, err := os.Stat(target); !os.IsNotExist(err) {
		t.Fatalf("the file was written without --write: %v", err)
	}
	content := out.String()
	for _, want := range []string{
		`enrollment_url: "https://enroll.example.com"`,
		`- "https://gw.example.com:8443"`,
		`inventory_interval: "30m0s"`,
		"token was not copied",
		"still take precedence",
	} {
		if !strings.Contains(content, want) {
			t.Fatalf("the output has no %q:\n%s", want, content)
		}
	}
	// The token is the reason the file exists at all, and it must not move
	// into the file that survives package updates.
	if strings.Contains(content, "flt_secret_value") {
		t.Fatalf("the output carries the token:\n%s", content)
	}
	// An empty variable is no setting: the default stays a default.
	if strings.Contains(content, "bootstrap_ca_file") {
		t.Fatalf("an empty variable became an entry:\n%s", content)
	}
}

func TestConfigMigrateWritesAFileTheParserAccepts(t *testing.T) {
	directory := t.TempDir()
	source := filepath.Join(directory, "agent.env")
	target := filepath.Join(directory, "agent.yaml")
	if err := os.WriteFile(source, []byte(legacyEnvironment), 0o640); err != nil {
		t.Fatal(err)
	}
	var out, errOut bytes.Buffer
	code := run([]string{"config", "migrate", "--write", "--env-file", source, "--config", target}, &out, &errOut)
	if code != 0 {
		t.Fatalf("code = %d: %s", code, errOut.String())
	}
	info, err := os.Stat(target)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm()&0o022 != 0 {
		t.Fatalf("permissions = %04o", info.Mode().Perm())
	}
	cfg, err := agentconfig.Load(target)
	if err != nil {
		t.Fatalf("the written file does not load: %v", err)
	}
	if cfg.Connection.EnrollmentURL != "https://enroll.example.com" ||
		len(cfg.Connection.GatewayURLs) != 1 || cfg.Connection.GatewayURLs[0] != "https://gw.example.com:8443" {
		t.Fatalf("connection = %+v", cfg.Connection)
	}
	if cfg.Agent.InventoryInterval != 30*time.Minute {
		t.Fatalf("inventory = %s", cfg.Agent.InventoryInterval)
	}
	raw, err := os.ReadFile(target)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(raw), "flt_secret_value") {
		t.Fatal("the token was written into the file")
	}

	// An existing file is somebody's decision: the second run refuses.
	out.Reset()
	errOut.Reset()
	code = run([]string{"config", "migrate", "--write", "--env-file", source, "--config", target}, &out, &errOut)
	if code != 1 || !strings.Contains(errOut.String(), "already exists") {
		t.Fatalf("code = %d: %s", code, errOut.String())
	}
}

func TestConfigMigrateWithNothingToMigrate(t *testing.T) {
	directory := t.TempDir()
	source := filepath.Join(directory, "agent.env")
	// Only the token and empty lines: the host is on the YAML already.
	if err := os.WriteFile(source, []byte("FLOTESTRO_ENROLLMENT_TOKEN=flt_x\nFLOTESTRO_GATEWAY_URL=\n"), 0o640); err != nil {
		t.Fatal(err)
	}
	var out, errOut bytes.Buffer
	code := run([]string{"config", "migrate", "--env-file", source, "--config", filepath.Join(directory, "agent.yaml")}, &out, &errOut)
	if code != 0 || !strings.Contains(out.String(), "Nothing to migrate") {
		t.Fatalf("code = %d: %s%s", code, out.String(), errOut.String())
	}

	// A missing file is a problem to report rather than a silent success:
	// the operator asked for a conversion of something.
	code = run([]string{"config", "migrate", "--env-file", filepath.Join(directory, "missing.env")}, &out, &errOut)
	if code != 1 {
		t.Fatalf("code = %d: %s", code, errOut.String())
	}
}

func TestConfigMigrateRefusesSettingsThatDoNotMakeAConfiguration(t *testing.T) {
	directory := t.TempDir()
	source := filepath.Join(directory, "agent.env")
	// A gateway without an enrollment address: the daemon would refuse it
	// too, and the file must not be written only to fail validation.
	if err := os.WriteFile(source, []byte("FLOTESTRO_GATEWAY_URL=https://gw.example.com:8443\n"), 0o640); err != nil {
		t.Fatal(err)
	}
	var out, errOut bytes.Buffer
	code := run([]string{"config", "migrate", "--write", "--env-file", source,
		"--config", filepath.Join(directory, "agent.yaml")}, &out, &errOut)
	if code != 1 || !strings.Contains(errOut.String(), "enrollment_invalid_url") {
		t.Fatalf("code = %d: %s", code, errOut.String())
	}
}
