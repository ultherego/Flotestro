package relayconfig

import (
	"errors"
	"strings"
	"testing"
)

const validConfig = `
schema_version: 1
relay:
  name: "relay-waw-01"
  site: "warsaw"
  listen: "0.0.0.0:8453"
  advertised_names:
    - "relay-waw-01.example.com"
  state_dir: "/var/lib/flotestro-relay"
  buffer_max_bytes: 268435456
upstream:
  enrollment_url: "https://enroll.flotestro.example.com"
  gateway_urls:
    - "https://gateway-a.flotestro.example.com:8443"
    - "https://gateway-b.flotestro.example.com:8443"
  bootstrap_ca_file: "/etc/flotestro/bootstrap-ca.pem"
`

func TestAValidConfigurationGoesThrough(t *testing.T) {
	cfg, err := Read(strings.NewReader(validConfig))
	if err != nil {
		t.Fatalf("the configuration from the document was rejected: %v", err)
	}
	if cfg.Relay.Name != "relay-waw-01" || cfg.Relay.Site != "warsaw" {
		t.Fatalf("read %+v", cfg.Relay)
	}
	if len(cfg.Upstream.GatewayURLs) != 2 {
		t.Fatalf("gateways = %v", cfg.Upstream.GatewayURLs)
	}
	if cfg.Buffer() != 268435456 {
		t.Fatalf("buffer = %d", cfg.Buffer())
	}
}

// TestATypoIsNotADetail guards the property this parser is strict for: a
// relay that comes up despite an unrecognised field looks configured and works
// differently than the file says.
func TestATypoIsNotADetail(t *testing.T) {
	_, err := Read(strings.NewReader(strings.Replace(validConfig,
		"gateway_urls:", "gateway_url:", 1)))
	if !errors.Is(err, ErrDecode) {
		t.Fatalf("a typo in the name of a field gave %v", err)
	}
}

func TestTheConfigurationRejectsErrors(t *testing.T) {
	cases := []struct {
		name   string
		change func(string) string
		code   error
	}{
		{"a different schema version", func(s string) string {
			return strings.Replace(s, "schema_version: 1", "schema_version: 2", 1)
		}, ErrSchema},
		{"a missing name", func(s string) string {
			return strings.Replace(s, `  name: "relay-waw-01"`, `  name: ""`, 1)
		}, ErrNameMissing},
		{"a privileged port", func(s string) string {
			return strings.Replace(s, "0.0.0.0:8453", "0.0.0.0:443", 1)
		}, ErrPrivilegedPort},
		{"a listen address without a port", func(s string) string {
			return strings.Replace(s, `"0.0.0.0:8453"`, `"0.0.0.0"`, 1)
		}, ErrListen},
		{"without a network name", func(s string) string {
			return strings.Replace(s, `    - "relay-waw-01.example.com"`, "", 1)
		}, ErrAdvertisedMissing},
		{"a relative directory", func(s string) string {
			return strings.Replace(s, `"/var/lib/flotestro-relay"`, `"state"`, 1)
		}, ErrStateDir},
		{"a buffer over the limit", func(s string) string {
			return strings.Replace(s, "buffer_max_bytes: 268435456",
				"buffer_max_bytes: 999999999999", 1)
		}, ErrBuffer},
		{"the same gateway twice", func(s string) string {
			return strings.Replace(s,
				`    - "https://gateway-b.flotestro.example.com:8443"`,
				`    - "https://gateway-a.flotestro.example.com:8443"`, 1)
		}, ErrGatewayDuplicate},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			_, err := Read(strings.NewReader(c.change(validConfig)))
			if !errors.Is(err, c.code) {
				t.Fatalf("error = %v, expected %v", err, c.code)
			}
		})
	}
}

// TestNoBufferIsAChoice guards the difference between "nothing was written"
// and "zero was written": a relay without a buffer loses results while the
// link is down, and that is to be a decision of the operator rather than the
// result of a skipped entry.
func TestNoBufferIsAChoice(t *testing.T) {
	without := strings.Replace(validConfig, "  buffer_max_bytes: 268435456\n", "", 1)
	cfg, err := Read(strings.NewReader(without))
	if err != nil {
		t.Fatalf("a configuration without a buffer was rejected: %v", err)
	}
	if cfg.Buffer() != DefaultBuffer {
		t.Fatalf("the buffer without an entry = %d, expected %d", cfg.Buffer(), DefaultBuffer)
	}

	zero := strings.Replace(validConfig, "buffer_max_bytes: 268435456", "buffer_max_bytes: 0", 1)
	cfg, err = Read(strings.NewReader(zero))
	if err != nil {
		t.Fatalf("an explicit zero was rejected: %v", err)
	}
	if cfg.Buffer() != 0 {
		t.Fatalf("an explicit zero gave the buffer %d", cfg.Buffer())
	}
}

func TestASecondDocumentIsAnError(t *testing.T) {
	_, err := Read(strings.NewReader(validConfig + "\n---\nschema_version: 1\n"))
	if !errors.Is(err, ErrMultipleDocuments) {
		t.Fatalf("a second document gave %v", err)
	}
}

// TestTheHealthListenerHasADefaultAndCanBeTurnedOff guards the
// difference between a file that says nothing about the health listener
// and one that turns it off: an installation upgraded from a release
// without the listener gets it on the loopback, and only an operator who
// wrote an empty entry loses the answers a container runtime asks for.
func TestTheHealthListenerHasADefaultAndCanBeTurnedOff(t *testing.T) {
	cfg, err := Read(strings.NewReader(validConfig))
	if err != nil {
		t.Fatalf("the configuration without a health entry was rejected: %v", err)
	}
	if cfg.HealthListen() != DefaultHealthListen {
		t.Fatalf("the health listener without an entry = %q, expected %q",
			cfg.HealthListen(), DefaultHealthListen)
	}

	moved := strings.Replace(validConfig, `  listen: "0.0.0.0:8453"`,
		"  listen: \"0.0.0.0:8453\"\n  health_listen: \"0.0.0.0:8454\"", 1)
	cfg, err = Read(strings.NewReader(moved))
	if err != nil {
		t.Fatalf("a health listener on another address was rejected: %v", err)
	}
	if cfg.HealthListen() != "0.0.0.0:8454" {
		t.Fatalf("the health listener = %q", cfg.HealthListen())
	}

	off := strings.Replace(validConfig, `  listen: "0.0.0.0:8453"`,
		"  listen: \"0.0.0.0:8453\"\n  health_listen: \"\"", 1)
	cfg, err = Read(strings.NewReader(off))
	if err != nil {
		t.Fatalf("a health listener turned off was rejected: %v", err)
	}
	if cfg.HealthListen() != "" {
		t.Fatalf("an empty entry gave the health listener %q", cfg.HealthListen())
	}
}

// TestTheHealthListenerIsNotThePortOfTheFleet guards the one mistake that
// would turn a convenience into a leak: the health answer goes out
// without a client certificate, and on the port of the agents it would
// hand the state of the site to whoever reaches the relay.
func TestTheHealthListenerIsNotThePortOfTheFleet(t *testing.T) {
	cases := []struct {
		name    string
		address string
	}{
		{"the port of the agents", "127.0.0.1:8453"},
		{"a privileged port", "127.0.0.1:443"},
		{"not an address at all", "8454"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			text := strings.Replace(validConfig, `  listen: "0.0.0.0:8453"`,
				"  listen: \"0.0.0.0:8453\"\n  health_listen: \""+c.address+"\"", 1)
			if _, err := Read(strings.NewReader(text)); !errors.Is(err, ErrHealthListen) {
				t.Fatalf("the health listener %s gave %v", c.address, err)
			}
		})
	}
}
