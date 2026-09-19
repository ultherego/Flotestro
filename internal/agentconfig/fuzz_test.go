package agentconfig

import (
	"bytes"
	"reflect"
	"testing"

	"gopkg.in/yaml.v3"
)

// FuzzRead feeds the configuration reader what an operator, a template or a
// broken editor may leave in agent.
func FuzzRead(f *testing.F) {
	f.Add(`
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
`)
	f.Add(`
schema_version: 1
connection:
  enrollment_url: "https://enroll.example.com"
  gateway_urls: ["https://gw.example.com:8443"]
`)
	f.Add(`
schema_version: 1
connection:
  enrollment_url: "https://enroll.example.com"
  gateway_url: "https://gw.example.com:8443"
`)
	f.Add(`
schema_version: 1
connection:
  enrollment_url: "https://enroll.example.com"
  gateway_urls: ["https://gw.example.com:8443"]
---
schema_version: 1
`)
	f.Add("")
	f.Add("schema_version: 1\nagent:\n  max_concurrent_tasks: 0\n")
	f.Add("schema_version: [1]\n")
	f.Add("connection: &a\n  x: *a\n")
	f.Add("agent: {state_dir: \"\\0\"}\n")

	f.Fuzz(func(t *testing.T, text string) {
		cfg, err := Read(bytes.NewReader([]byte(text)))
		if err != nil {
			return
		}
		if err := cfg.Check(); err != nil {
			t.Fatalf("a configuration that was read does not pass its own check: %v", err)
		}
		encoded, err := yaml.Marshal(cfg)
		if err != nil {
			t.Fatalf("a configuration that was read cannot be written: %v", err)
		}
		again, err := Read(bytes.NewReader(encoded))
		if err != nil {
			t.Fatalf("a configuration that was written cannot be read again: %v\n%s", err, encoded)
		}
		if !reflect.DeepEqual(cfg, again) {
			t.Fatalf("the configuration changed on the way through the file:\n%+v\n%+v\n%s", cfg, again, encoded)
		}
	})
}
