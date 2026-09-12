package agentconfig

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

const fullExample = `
schema_version: 1

connection:
  enrollment_url: "https://enroll.flotestro.example.com"
  gateway_urls:
    - "https://relay-waw-01.example.com:8453"
    - "https://relay-waw-02.example.com:8453"
  connect_timeout: "15s"
  reconnect_min: "2s"
  reconnect_max: "2m"

agent:
  state_dir: "/var/lib/flotestro-agent"
  inventory_interval: "15m"
  max_concurrent_tasks: 2
  mode: "full"

helper:
  socket: "/run/flotestro/helper.sock"
`

func TestAFullFilePasses(t *testing.T) {
	cfg, err := Read(strings.NewReader(fullExample))
	if err != nil {
		t.Fatalf("the configuration was rejected: %v", err)
	}
	if len(cfg.Connection.GatewayURLs) != 2 {
		t.Fatalf("gateways = %v", cfg.Connection.GatewayURLs)
	}
	if cfg.Connection.ConnectTimeout != 15*time.Second ||
		cfg.Connection.ReconnectMax != 2*time.Minute {
		t.Fatalf("durations = %s / %s", cfg.Connection.ConnectTimeout, cfg.Connection.ReconnectMax)
	}
	if cfg.Agent.InventoryInterval != 15*time.Minute {
		t.Fatalf("inventory interval = %s", cfg.Agent.InventoryInterval)
	}
}

func TestMissingFieldsTakeTheDefaults(t *testing.T) {
	minimal := `
schema_version: 1
connection:
  enrollment_url: "https://enroll.example.com"
  gateway_urls: ["https://gw.example.com:8443"]
`
	cfg, err := Read(strings.NewReader(minimal))
	if err != nil {
		t.Fatalf("the configuration was rejected: %v", err)
	}
	defaults := Defaults()
	if cfg.Agent.StateDir != defaults.Agent.StateDir ||
		cfg.Agent.MaxConcurrentTasks != defaults.Agent.MaxConcurrentTasks ||
		cfg.Agent.Mode != defaults.Agent.Mode ||
		cfg.Helper.Socket != defaults.Helper.Socket ||
		cfg.Agent.InventoryInterval != defaults.Agent.InventoryInterval {
		t.Fatalf("the defaults were not filled in: %+v", cfg)
	}
}

// TestTheFileRejectsErrors goes through the cases from the document. Each of
// them once ended in a silent start with a setting other than the one the
// operator wrote - and that is worse than a host that does not come up.
func TestTheFileRejectsErrors(t *testing.T) {
	cases := []struct {
		name   string
		file   string
		expect error
	}{
		{"unknown field", `
schema_version: 1
connection:
  enrollment_url: "https://enroll.example.com"
  gateway_url: "https://gw.example.com:8443"
`, ErrDecode},
		{"http instead of https", `
schema_version: 1
connection:
  enrollment_url: "https://enroll.example.com"
  gateway_urls: ["http://gw.example.com:8443"]
`, nil},
		{"credentials in the address", `
schema_version: 1
connection:
  enrollment_url: "https://user:password@enroll.example.com"
  gateway_urls: ["https://gw.example.com:8443"]
`, nil},
		{"second document", `
schema_version: 1
connection:
  enrollment_url: "https://enroll.example.com"
  gateway_urls: ["https://gw.example.com:8443"]
---
schema_version: 1
`, ErrMultipleDocs},
		{"task limit zero", `
schema_version: 1
connection:
  enrollment_url: "https://enroll.example.com"
  gateway_urls: ["https://gw.example.com:8443"]
agent:
  max_concurrent_tasks: 0
`, ErrTaskLimit},
		{"task limit of a thousand", `
schema_version: 1
connection:
  enrollment_url: "https://enroll.example.com"
  gateway_urls: ["https://gw.example.com:8443"]
agent:
  max_concurrent_tasks: 1000
`, ErrTaskLimit},
		{"duplicate gateway", `
schema_version: 1
connection:
  enrollment_url: "https://enroll.example.com"
  gateway_urls: ["https://gw.example.com:8443", "https://gw.example.com:8443"]
`, ErrGatewayDuplicate},
		{"unknown schema", `
schema_version: 2
connection:
  enrollment_url: "https://enroll.example.com"
  gateway_urls: ["https://gw.example.com:8443"]
`, ErrSchema},
		{"no gateway", `
schema_version: 1
connection:
  enrollment_url: "https://enroll.example.com"
`, ErrGatewayMissing},
		{"unknown mode", `
schema_version: 1
connection:
  enrollment_url: "https://enroll.example.com"
  gateway_urls: ["https://gw.example.com:8443"]
agent:
  mode: "halfway"
`, ErrMode},
		{"inventory interval of a minute", `
schema_version: 1
connection:
  enrollment_url: "https://enroll.example.com"
  gateway_urls: ["https://gw.example.com:8443"]
agent:
  inventory_interval: "1m"
`, nil},
		{"reconnect bounds reversed", `
schema_version: 1
connection:
  enrollment_url: "https://enroll.example.com"
  gateway_urls: ["https://gw.example.com:8443"]
  reconnect_min: "5m"
  reconnect_max: "10s"
`, ErrReconnectOrder},
		{"relative state directory", `
schema_version: 1
connection:
  enrollment_url: "https://enroll.example.com"
  gateway_urls: ["https://gw.example.com:8443"]
agent:
  state_dir: "state"
`, ErrStateDir},
	}

	for _, testCase := range cases {
		t.Run(testCase.name, func(t *testing.T) {
			_, err := Read(strings.NewReader(testCase.file))
			if err == nil {
				t.Fatal("the file passed although it should not have")
			}
			if testCase.expect != nil && !errors.Is(err, testCase.expect) {
				t.Fatalf("error = %v, want %v", err, testCase.expect)
			}
		})
	}

	// A missing entry is something else than an explicit zero: the first
	// takes the default value, the second is an error.
	cfg, err := Read(strings.NewReader(`
schema_version: 1
connection:
  enrollment_url: "https://enroll.example.com"
  gateway_urls: ["https://gw.example.com:8443"]
`))
	if err != nil {
		t.Fatalf("a file without a limit was rejected: %v", err)
	}
	if cfg.Agent.MaxConcurrentTasks != Defaults().Agent.MaxConcurrentTasks {
		t.Fatalf("task limit after filling in = %d", cfg.Agent.MaxConcurrentTasks)
	}
}

func TestTheBootstrapCAHasToBeAnOrdinaryFile(t *testing.T) {
	dir := t.TempDir()
	file := filepath.Join(dir, "ca.pem")
	if err := os.WriteFile(file, []byte("-----BEGIN CERTIFICATE-----\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	cfg := Defaults()
	cfg.Connection.BootstrapCA = file
	if err := cfg.CheckBootstrapCA(); err != nil {
		t.Fatalf("an ordinary file was rejected: %v", err)
	}

	// A symlink can point into a directory writable by somebody else, and
	// replacing the CA bundle means replacing the host's whole trust.
	link := filepath.Join(dir, "ca-link.pem")
	if err := os.Symlink(file, link); err != nil {
		t.Fatal(err)
	}
	cfg.Connection.BootstrapCA = link
	if err := cfg.CheckBootstrapCA(); !errors.Is(err, ErrBootstrapCA) {
		t.Fatalf("a symlink passed: %v", err)
	}

	writable := filepath.Join(dir, "ca-open.pem")
	if err := os.WriteFile(writable, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	// We set the permissions after writing: the process umask would trim the
	// mode given at creation anyway, and the test is to check a file that is
	// really open.
	if err := os.Chmod(writable, 0o666); err != nil {
		t.Fatal(err)
	}
	cfg.Connection.BootstrapCA = writable
	if err := cfg.CheckBootstrapCA(); !errors.Is(err, ErrBootstrapCA) {
		t.Fatalf("a world-writable file passed: %v", err)
	}
}

func TestLoadFromAFile(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "agent.yaml")
	if err := os.WriteFile(path, []byte(fullExample), 0o640); err != nil {
		t.Fatal(err)
	}
	if _, err := Load(path); err != nil {
		t.Fatalf("the file was rejected: %v", err)
	}
	if _, err := Load(filepath.Join(dir, "missing.yaml")); !errors.Is(err, ErrOpen) {
		t.Fatalf("a missing file = %v", err)
	}
}
