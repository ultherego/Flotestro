// Package relayconfig reads the configuration of a relay from a YAML file.
//
// A relay is a separate trust boundary and has a separate file. A file shared
// with the agent would look more economical and would mean that one setting
// describes two roles with different permissions - and that a mistake in one
// of them touches the other.
//
// The parser is strict just like the parser of the agent: a typo in the name
// of a field must not end with a silent start on a default setting. A relay
// listening on a port other than the operator thinks is worse than a relay
// that did not come up.
//
// What is not in this file: the enrollment token and the identity. The token
// is a one-time secret and must not survive an upgrade of the package; the
// identity of a relay comes from its certificate rather than from text in a
// file.
package relayconfig

import (
	"errors"
	"fmt"
	"io"
	"net"
	"net/url"
	"os"
	"path/filepath"
	"strings"

	"gopkg.in/yaml.v3"
)

// DefaultPath names the canonical configuration file of a relay.
const DefaultPath = "/etc/flotestro/relay.yaml"

// SchemaVersion is the only version this parser understands.
const SchemaVersionSupported = 1

// MaxSize limits the read of the configuration file.
const MaxSize = 1 << 20

// Config is the full configuration of a relay.
type Config struct {
	SchemaVersion int      `yaml:"schema_version"`
	Relay         Relay    `yaml:"relay"`
	Upstream      Upstream `yaml:"upstream"`
}

// Relay describes the node of the site itself.
type Relay struct {
	Name string `yaml:"name"`
	// Site is an expected value rather than a granted one: the scope of a
	// relay is granted by the enrollment token and it is the token that
	// settles it. A divergence between the file and the certificate is a
	// configuration error and is to be visible.
	Site            string   `yaml:"site"`
	Listen          string   `yaml:"listen"`
	AdvertisedNames []string `yaml:"advertised_names"`
	StateDir        string   `yaml:"state_dir"`
	// BufferMaxBytes is a pointer so that a missing entry can be told from an
	// explicit zero. Zero means "buffer nothing" and is a choice rather than
	// an absence: a relay without a buffer loses every result while the link
	// is down.
	BufferMaxBytes *int64 `yaml:"buffer_max_bytes"`
}

// Upstream describes the path of the relay to the centre.
type Upstream struct {
	EnrollmentURL string   `yaml:"enrollment_url"`
	GatewayURLs   []string `yaml:"gateway_urls"`
	BootstrapCA   string   `yaml:"bootstrap_ca_file"`
}

// The error codes of the configuration of a relay. Just as with the agent
// they are part of the contract with the operator: they are what shows up on a
// machine without a connection to the panel.
var (
	ErrOpen              = errors.New("relay_config_open")
	ErrDecode            = errors.New("relay_config_decode")
	ErrMultipleDocuments = errors.New("relay_config_multiple_documents")
	ErrSchema            = errors.New("relay_config_schema_unsupported")
	ErrNameMissing       = errors.New("relay_config_name_missing")
	ErrListen            = errors.New("relay_config_listen_invalid")
	ErrPrivilegedPort    = errors.New("relay_config_listen_privileged")
	ErrAdvertisedMissing = errors.New("relay_config_advertised_missing")
	ErrNetworkName       = errors.New("relay_config_advertised_invalid")
	ErrStateDir          = errors.New("relay_config_state_dir_invalid")
	ErrGatewayMissing    = errors.New("relay_config_gateway_missing")
	ErrGatewayDuplicate  = errors.New("relay_config_gateway_duplicate")
	ErrBuffer            = errors.New("relay_config_buffer_out_of_range")
)

// The limits of the buffer. The bottom is deliberately zero: a relay without
// a buffer is a choice as well. The top protects the machine of the site - a
// buffer growing without end turns a failure of the link into a failure of the
// relay.
const (
	DefaultBuffer int64 = 256 << 20
	MaxBuffer     int64 = 4 << 30
)

// Defaults returns the settings that hold without an entry in the file.
func Defaults() Config {
	buffer := DefaultBuffer
	return Config{
		SchemaVersion: SchemaVersionSupported,
		Relay: Relay{
			Listen:         "0.0.0.0:8453",
			StateDir:       "/var/lib/flotestro-relay",
			BufferMaxBytes: &buffer,
		},
	}
}

// Load reads and checks the configuration from a file.
func Load(path string) (Config, error) {
	file, err := os.Open(filepath.Clean(path))
	if err != nil {
		return Config{}, fmt.Errorf("%w: %v", ErrOpen, err)
	}
	defer file.Close()
	return Read(file)
}

// Read reads the configuration from a stream.
func Read(source io.Reader) (Config, error) {
	decoder := yaml.NewDecoder(io.LimitReader(source, MaxSize))
	decoder.KnownFields(true)

	var cfg Config
	if err := decoder.Decode(&cfg); err != nil {
		return Config{}, fmt.Errorf("%w: %v", ErrDecode, err)
	}
	var extra any
	if err := decoder.Decode(&extra); !errors.Is(err, io.EOF) {
		if err == nil {
			return Config{}, ErrMultipleDocuments
		}
		return Config{}, fmt.Errorf("%w: %v", ErrDecode, err)
	}

	fillDefaults(&cfg)
	if err := cfg.Check(); err != nil {
		return Config{}, err
	}
	return cfg, nil
}

// fillDefaults puts the default values wherever the file says nothing.
func fillDefaults(cfg *Config) {
	defaults := Defaults()
	if cfg.Relay.Listen == "" {
		cfg.Relay.Listen = defaults.Relay.Listen
	}
	if cfg.Relay.StateDir == "" {
		cfg.Relay.StateDir = defaults.Relay.StateDir
	}
	if cfg.Relay.BufferMaxBytes == nil {
		buffer := DefaultBuffer
		cfg.Relay.BufferMaxBytes = &buffer
	}
}

// Buffer returns the limit of the buffer of results.
func (c Config) Buffer() int64 {
	if c.Relay.BufferMaxBytes == nil {
		return DefaultBuffer
	}
	return *c.Relay.BufferMaxBytes
}

// Check guards the contract of the configuration file of a relay.
func (c Config) Check() error {
	if c.SchemaVersion != SchemaVersionSupported {
		return fmt.Errorf("%w: %d", ErrSchema, c.SchemaVersion)
	}
	if strings.TrimSpace(c.Relay.Name) == "" {
		return ErrNameMissing
	}
	if err := listenAddress(c.Relay.Listen); err != nil {
		return err
	}
	// Without a name the relay is visible under, its server certificate has
	// nothing to attest and the agents reject a connection to an unknown name.
	// Better to say so at the start than with every agent separately.
	if len(c.Relay.AdvertisedNames) == 0 {
		return ErrAdvertisedMissing
	}
	seen := map[string]bool{}
	for _, name := range c.Relay.AdvertisedNames {
		if err := networkName(name); err != nil {
			return err
		}
		if seen[name] {
			return fmt.Errorf("%w: %s was given twice", ErrNetworkName, name)
		}
		seen[name] = true
	}
	if !filepath.IsAbs(c.Relay.StateDir) {
		return fmt.Errorf("%w: %s", ErrStateDir, c.Relay.StateDir)
	}
	if err := httpsAddress("enrollment", c.Upstream.EnrollmentURL); err != nil {
		return err
	}
	if len(c.Upstream.GatewayURLs) == 0 {
		return ErrGatewayMissing
	}
	gateways := map[string]bool{}
	for _, address := range c.Upstream.GatewayURLs {
		if err := httpsAddress("gateway", address); err != nil {
			return err
		}
		if gateways[address] {
			return fmt.Errorf("%w: %s", ErrGatewayDuplicate, address)
		}
		gateways[address] = true
	}
	if buffer := c.Buffer(); buffer < 0 || buffer > MaxBuffer {
		return fmt.Errorf("%w: %d", ErrBuffer, buffer)
	}
	return nil
}

// listenAddress guards that the listen address is an address and that the
// port does not require root.
//
// A relay runs without root privileges and is to stay that way: a process
// terminating the TLS of a whole site is not the place for extra
// permissions.
func listenAddress(address string) error {
	host, port, err := net.SplitHostPort(address)
	if err != nil {
		return fmt.Errorf("%w: %s", ErrListen, address)
	}
	if host != "" && net.ParseIP(host) == nil {
		return fmt.Errorf("%w: %s is not an IP address", ErrListen, host)
	}
	number, err := net.LookupPort("tcp", port)
	if err != nil || number == 0 {
		return fmt.Errorf("%w: %s", ErrListen, address)
	}
	if number < 1024 {
		return fmt.Errorf("%w: %d", ErrPrivilegedPort, number)
	}
	return nil
}

// networkName accepts a DNS name or an IP address.
func networkName(name string) error {
	if name == "" {
		return fmt.Errorf("%w: an empty name", ErrNetworkName)
	}
	if net.ParseIP(name) != nil {
		return nil
	}
	if strings.ContainsAny(name, " \t/:") || strings.HasPrefix(name, ".") ||
		strings.HasSuffix(name, ".") {
		return fmt.Errorf("%w: %s", ErrNetworkName, name)
	}
	for _, label := range strings.Split(name, ".") {
		if label == "" || len(label) > 63 {
			return fmt.Errorf("%w: %s", ErrNetworkName, name)
		}
	}
	return nil
}

// httpsAddress guards that the address of the centre is what it looks like.
func httpsAddress(name, raw string) error {
	address, err := url.Parse(raw)
	if err != nil || address.Scheme != "https" || address.Host == "" {
		return fmt.Errorf("%s_invalid_url: %s", name, raw)
	}
	if address.User != nil || address.RawQuery != "" || address.Fragment != "" {
		return fmt.Errorf("%s_forbidden_url_parts: %s", name, raw)
	}
	return nil
}
