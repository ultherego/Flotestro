package agentconfig

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// TestEquivalentFilesShareAFingerprint: the fingerprint is of what the agent
// runs on.
func TestEquivalentFilesShareAFingerprint(t *testing.T) {
	reference, err := Read(strings.NewReader(fullExample))
	if err != nil {
		t.Fatal(err)
	}
	if len(reference.Fingerprint()) != 64 {
		t.Fatalf("the fingerprint is %q, expected a hex sha256", reference.Fingerprint())
	}

	rearranged := `
# The same configuration, written by somebody else.
helper: {socket: /run/flotestro/helper.sock}
agent:
  mode: full
  max_concurrent_tasks: 2
  inventory_interval: 15m
  state_dir: /var/lib/flotestro-agent
connection:
  reconnect_max: 120s
  reconnect_min: 2s
  connect_timeout: 15s
  gateway_urls: ["https://relay-waw-01.example.com:8453", "https://relay-waw-02.example.com:8453"]
  enrollment_url: https://enroll.flotestro.example.com
schema_version: 1
`
	same, err := Read(strings.NewReader(rearranged))
	if err != nil {
		t.Fatal(err)
	}
	if same.Fingerprint() != reference.Fingerprint() {
		t.Errorf("the rearranged file has another fingerprint:\n%s\n%s", same.Fingerprint(), reference.Fingerprint())
	}

	// The defaults left to the parser configure the same agent as the
	// defaults written out.
	withDefaultsLeftOut := `
schema_version: 1
connection:
  enrollment_url: "https://enroll.flotestro.example.com"
  gateway_urls: ["https://relay-waw-01.example.com:8453", "https://relay-waw-02.example.com:8453"]
`
	implicit, err := Read(strings.NewReader(withDefaultsLeftOut))
	if err != nil {
		t.Fatal(err)
	}
	if implicit.Fingerprint() != reference.Fingerprint() {
		t.Errorf("a file relying on the defaults has another fingerprint than one writing them out")
	}

	reordered := `
schema_version: 1
connection:
  enrollment_url: "https://enroll.flotestro.example.com"
  gateway_urls: ["https://relay-waw-02.example.com:8453", "https://relay-waw-01.example.com:8453"]
`
	other, err := Read(strings.NewReader(reordered))
	if err != nil {
		t.Fatal(err)
	}
	if other.Fingerprint() == reference.Fingerprint() {
		t.Error("the gateways in another order of priority share the fingerprint")
	}

	readOnly := strings.Replace(fullExample, `mode: "full"`, `mode: "read_only"`, 1)
	observed, err := Read(strings.NewReader(readOnly))
	if err != nil {
		t.Fatal(err)
	}
	if observed.Fingerprint() == reference.Fingerprint() {
		t.Error("a host in the observation mode shares the fingerprint of a managed one")
	}
}

// TestLoadIsWhatCurrentReports: the file the process loaded is the one the
// session tells the panel about, with its schema and fingerprint; a process
// that loaded none reports none.
func TestLoadIsWhatCurrentReports(t *testing.T) {
	loadedMu.Lock()
	loaded = nil
	loadedMu.Unlock()
	if _, ok := Current(); ok {
		t.Fatal("a process that loaded no file reports one")
	}

	path := filepath.Join(t.TempDir(), "agent.yaml")
	if err := os.WriteFile(path, []byte(fullExample), 0o600); err != nil {
		t.Fatal(err)
	}
	cfg, err := Load(path)
	if err != nil {
		t.Fatal(err)
	}
	current, ok := Current()
	if !ok {
		t.Fatal("the loaded file is not reported")
	}
	if current.Path != path || current.SchemaVersion != SchemaVersion || current.Fingerprint != cfg.Fingerprint() {
		t.Errorf("Current() = %+v, expected the file %s with schema %d and the fingerprint %s",
			current, path, SchemaVersion, cfg.Fingerprint())
	}

	// A file that does not pass is not the one the process runs on.
	broken := filepath.Join(t.TempDir(), "broken.yaml")
	if err := os.WriteFile(broken, []byte("schema_version: 2\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := Load(broken); err == nil {
		t.Fatal("a file of an unknown schema was loaded")
	}
	if after, _ := Current(); after.Path != path {
		t.Errorf("a rejected file replaced the loaded one: %+v", after)
	}
}
