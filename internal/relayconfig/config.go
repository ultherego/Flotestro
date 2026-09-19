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
	"time"

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
	Spool         Spool    `yaml:"spool"`
}

// Spool bounds the durable spool of the relay: the messages of the
// agents the centre has not yet confirmed it consumed. Every limit is a
// pointer so that a missing entry can be told from an explicit value.
type Spool struct {
	// Path is the directory of the segment files; empty means the spool
	// directory under state_dir. Root-owned and private.
	Path string `yaml:"path"`
	// MaxBytes is the room the waiting records may take together.
	MaxBytes *int64 `yaml:"max_bytes"`
	// CriticalReserveBytes is the part of max_bytes only control and job
	// results may enter; inventory, metrics and logs stop before it.
	CriticalReserveBytes *int64 `yaml:"critical_reserve_bytes"`
	// MinFreeBytes is the floor of free space on the filesystem of the
	// spool below which nothing is appended, whatever the class.
	MinFreeBytes *int64 `yaml:"min_free_bytes"`
	// AckTimeout is how long a sent record waits for the panel's
	// acknowledgement before it is sent again.
	AckTimeout *time.Duration `yaml:"ack_timeout"`
	// MaxInflightPerHost bounds the records of one host sent and not yet
	// acknowledged.
	MaxInflightPerHost *int `yaml:"max_inflight_per_host"`
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
	// HealthListen is the address of the health listener: plain HTTP,
	// without a client certificate, answering liveness and readiness so
	// that a container runtime can ask them without a shell in the image.
	// It is deliberately not the listener of the agents: that one
	// terminates TLS and demands a certificate of the fleet, which a
	// health check inside the container does not have.
	//
	// A pointer so that a missing entry can be told from an explicit
	// empty one: no entry means the default on the loopback, an empty
	// string means the operator turned the listener off.
	HealthListen *string `yaml:"health_listen"`
	// BufferMaxBytes is the limit of the memory buffer of the releases
	// before the spool. It is still read: a file that names it and says
	// nothing under spool.max_bytes gets the same limit for the spool, so
	// an upgraded relay keeps the room the operator gave it. A pointer so
	// that a missing entry can be told from an explicit zero.
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
	ErrSpoolPath         = errors.New("relay_config_spool_path_invalid")
	ErrSpoolLimit        = errors.New("relay_config_spool_out_of_range")
	ErrHealthListen      = errors.New("relay_config_health_listen_invalid")
)

// DefaultHealthListen is where the health listener stands when the file
// says nothing: the loopback of the machine, on the port next to the one
// the agents use.
//
// The loopback rather than every address, because the answer says how
// full the spool is and when the certificate ends - facts for the
// operator of the machine and for the runtime that starts the container,
// not for the network of the site. An installation whose probe comes
// from outside the container, a kubelet for instance, names an address
// of its own in health_listen.
const DefaultHealthListen = "127.0.0.1:8454"

// The limits of the buffer. The bottom is deliberately zero: a relay without
// a buffer is a choice as well. The top protects the machine of the site - a
// buffer growing without end turns a failure of the link into a failure of the
// relay.
const (
	DefaultBuffer int64 = 256 << 20
	MaxBuffer     int64 = 4 << 30
)

// The defaults of the spool. The floor of free space is what the state
// directory needs for the identity and the segment being written; the
// reserve is what a site's results take over an outage of a day while
// its samples are dropped. Both are configurable in relay.yaml.
const (
	DefaultSpoolMaxBytes        int64 = 1 << 30
	DefaultSpoolCriticalReserve int64 = 128 << 20
	DefaultSpoolMinFree         int64 = 256 << 20
	DefaultSpoolAckTimeout            = 30 * time.Second
	DefaultSpoolMaxInflight           = 64
	MaxSpoolBytes               int64 = 64 << 30
	// SpoolDirName is the directory of the spool under state_dir when the
	// file names no path.
	SpoolDirName = "spool"
)

// Defaults returns the settings that hold without an entry in the file.
func Defaults() Config {
	buffer := DefaultBuffer
	health := DefaultHealthListen
	return Config{
		SchemaVersion: SchemaVersionSupported,
		Relay: Relay{
			Listen:         "0.0.0.0:8453",
			StateDir:       "/var/lib/flotestro-relay",
			HealthListen:   &health,
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
	if cfg.Relay.HealthListen == nil {
		health := DefaultHealthListen
		cfg.Relay.HealthListen = &health
	}
	fillSpoolDefaults(cfg)
}

// fillSpoolDefaults completes the spool section. A file from before the
// spool names buffer_max_bytes alone: that limit becomes the spool's, so
// the upgrade keeps the room the operator gave the site. The reserve is
// capped at the limit, so a small limit still leaves room for control
// and results.
func fillSpoolDefaults(cfg *Config) {
	if cfg.Spool.MaxBytes == nil {
		limit := DefaultSpoolMaxBytes
		if cfg.Relay.BufferMaxBytes != nil && *cfg.Relay.BufferMaxBytes > 0 {
			limit = *cfg.Relay.BufferMaxBytes
		}
		cfg.Spool.MaxBytes = &limit
	}
	if cfg.Spool.CriticalReserveBytes == nil {
		reserve := DefaultSpoolCriticalReserve
		if reserve > *cfg.Spool.MaxBytes/2 {
			reserve = *cfg.Spool.MaxBytes / 2
		}
		cfg.Spool.CriticalReserveBytes = &reserve
	}
	if cfg.Spool.MinFreeBytes == nil {
		free := DefaultSpoolMinFree
		cfg.Spool.MinFreeBytes = &free
	}
	if cfg.Spool.AckTimeout == nil {
		timeout := DefaultSpoolAckTimeout
		cfg.Spool.AckTimeout = &timeout
	}
	if cfg.Spool.MaxInflightPerHost == nil {
		inflight := DefaultSpoolMaxInflight
		cfg.Spool.MaxInflightPerHost = &inflight
	}
}

// SpoolPath returns the directory of the spool: the one named in the
// file, or the spool directory under state_dir.
func (c Config) SpoolPath() string {
	if c.Spool.Path != "" {
		return c.Spool.Path
	}
	return filepath.Join(c.Relay.StateDir, SpoolDirName)
}

// SpoolLimits returns the limits of the spool with the defaults filled.
func (c Config) SpoolLimits() (maxBytes, reserve, minFree int64, ackTimeout time.Duration, maxInflight int) {
	cfg := c
	fillSpoolDefaults(&cfg)
	return *cfg.Spool.MaxBytes, *cfg.Spool.CriticalReserveBytes, *cfg.Spool.MinFreeBytes,
		*cfg.Spool.AckTimeout, *cfg.Spool.MaxInflightPerHost
}

// HealthListen returns the address of the health listener: the default
// for a file that says nothing, and an empty string for one that turned
// the listener off.
func (c Config) HealthListen() string {
	if c.Relay.HealthListen == nil {
		return DefaultHealthListen
	}
	return strings.TrimSpace(*c.Relay.HealthListen)
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
	if err := c.checkHealthListen(); err != nil {
		return err
	}
	return c.checkSpool()
}

// checkHealthListen guards the address of the health listener. It shares
// the port rule of the listener of the agents - a relay takes no
// privileged port - and it must not be the port of that listener: the
// health answer goes out without a client certificate, and putting it on
// the port of the fleet would hand the state of the site to anybody who
// reaches it.
func (c Config) checkHealthListen() error {
	address := c.HealthListen()
	if address == "" {
		return nil
	}
	if err := listenAddress(address); err != nil {
		return fmt.Errorf("%w: %s", ErrHealthListen, address)
	}
	_, health, err := net.SplitHostPort(address)
	if err != nil {
		return fmt.Errorf("%w: %s", ErrHealthListen, address)
	}
	_, agents, err := net.SplitHostPort(c.Relay.Listen)
	if err == nil && health == agents {
		return fmt.Errorf("%w: %s uses the port of the listener of the agents", ErrHealthListen, address)
	}
	return nil
}

// checkSpool guards the spool section. The limits have a floor of one
// megabyte: a spool smaller than a single inventory report would refuse
// every result and say critical from the first minute.
func (c Config) checkSpool() error {
	if c.Spool.Path != "" && !filepath.IsAbs(c.Spool.Path) {
		return fmt.Errorf("%w: %s", ErrSpoolPath, c.Spool.Path)
	}
	maxBytes, reserve, minFree, ackTimeout, maxInflight := c.SpoolLimits()
	if maxBytes < 1<<20 || maxBytes > MaxSpoolBytes {
		return fmt.Errorf("%w: max_bytes %d", ErrSpoolLimit, maxBytes)
	}
	if reserve < 0 || reserve > maxBytes {
		return fmt.Errorf("%w: critical_reserve_bytes %d", ErrSpoolLimit, reserve)
	}
	if minFree < 0 {
		return fmt.Errorf("%w: min_free_bytes %d", ErrSpoolLimit, minFree)
	}
	if ackTimeout < time.Second || ackTimeout > time.Hour {
		return fmt.Errorf("%w: ack_timeout %s", ErrSpoolLimit, ackTimeout)
	}
	if maxInflight < 1 || maxInflight > 10000 {
		return fmt.Errorf("%w: max_inflight_per_host %d", ErrSpoolLimit, maxInflight)
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
