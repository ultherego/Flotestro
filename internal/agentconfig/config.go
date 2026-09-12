// Package agentconfig reads the agent's configuration from a YAML file.
//
// The file is the canonical source of the host's settings. Environment
// variables and flags remain only as a limited override for images and tests.
//
// The parser is strict on purpose. A typo in a field name must not end in a
// silent start with a default setting: the host would then look configured
// while connecting somewhere else or nowhere at all. Every error has its own
// code, because that is what reaches diagnostics on a host without a panel.
//
// What is not in this file and will not be: the enrollment token and the
// identity. The token is a single-use secret and must not lie in a file that
// survives a package upgrade; the host's identity comes from its certificate
// rather than from text anyone can copy.
package agentconfig

import (
	"errors"
	"fmt"
	"io"
	"net/url"
	"os"
	"path/filepath"
	"time"

	"gopkg.in/yaml.v3"
)

// DefaultPath points at the canonical configuration file.
const DefaultPath = "/etc/flotestro/agent.yaml"

// SchemaVersion is the only version this parser understands.
const SchemaVersion = 1

// MaxSize bounds the read of the configuration file.
const MaxSize = 1 << 20

// Config is the agent's complete configuration.
type Config struct {
	SchemaVersion int        `yaml:"schema_version"`
	Connection    Connection `yaml:"connection"`
	Agent         Agent      `yaml:"agent"`
	Helper        Helper     `yaml:"helper"`
}

// Connection describes where and how the agent connects.
type Connection struct {
	EnrollmentURL string   `yaml:"enrollment_url"`
	GatewayURLs   []string `yaml:"gateway_urls"`
	BootstrapCA   string   `yaml:"bootstrap_ca_file"`
	// The times arrive as text ("15s"), because that is readable in a file.
	ConnectRaw      string `yaml:"connect_timeout"`
	ReconnectMinRaw string `yaml:"reconnect_min"`
	ReconnectMaxRaw string `yaml:"reconnect_max"`

	ConnectTimeout time.Duration `yaml:"-"`
	ReconnectMin   time.Duration `yaml:"-"`
	ReconnectMax   time.Duration `yaml:"-"`
}

// Agent describes the behaviour of the agent itself.
type Agent struct {
	StateDir     string `yaml:"state_dir"`
	InventoryRaw string `yaml:"inventory_interval"`
	// MaxRaw is a pointer so as to tell "there is no entry" from "zero was
	// written". A missing entry takes the default value, and an explicit zero
	// is an error: an agent that runs no task at all is not an agent.
	MaxRaw *int `yaml:"max_concurrent_tasks"`
	// The "read_only" mode does not start the helper: the host is then
	// observed rather than managed.
	Mode string `yaml:"mode"`

	MaxConcurrentTasks int           `yaml:"-"`
	InventoryInterval  time.Duration `yaml:"-"`
}

// Helper describes the connection with the privileged part.
type Helper struct {
	Socket string `yaml:"socket"`
}

// The agent's modes of work.
const (
	ModeFull     = "full"
	ModeReadOnly = "read_only"
)

// The configuration error codes. They are part of the contract with the
// operator: they are what shows up on a host that has no connection with the
// panel yet.
var (
	ErrOpen             = errors.New("config_open")
	ErrDecode           = errors.New("config_decode")
	ErrMultipleDocs     = errors.New("config_multiple_documents")
	ErrSchema           = errors.New("config_schema_unsupported")
	ErrGatewayMissing   = errors.New("config_gateway_missing")
	ErrGatewayDuplicate = errors.New("config_gateway_duplicate")
	ErrTaskLimit        = errors.New("config_task_limit_out_of_range")
	ErrMode             = errors.New("config_mode_invalid")
	ErrStateDir         = errors.New("config_state_dir_invalid")
	ErrHelperSocket     = errors.New("config_helper_socket_invalid")
	ErrConnectTimeout   = errors.New("config_connect_timeout_out_of_range")
	ErrReconnectRange   = errors.New("config_reconnect_out_of_range")
	ErrReconnectOrder   = errors.New("config_reconnect_order")
	ErrBootstrapCA      = errors.New("bootstrap_ca_unsafe")
)

// Defaults returns the settings that apply without an entry in the file.
func Defaults() Config {
	return Config{
		SchemaVersion: SchemaVersion,
		Connection: Connection{
			ConnectTimeout: 15 * time.Second,
			ReconnectMin:   2 * time.Second,
			ReconnectMax:   2 * time.Minute,
		},
		Agent: Agent{
			StateDir:           "/var/lib/flotestro-agent",
			InventoryInterval:  15 * time.Minute,
			MaxConcurrentTasks: 2,
			Mode:               ModeFull,
		},
		Helper: Helper{Socket: "/run/flotestro/helper.sock"},
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
	// An unknown field is an error rather than a detail: "gateway_url"
	// instead of "gateway_urls" would leave the agent without an address and
	// without a word.
	decoder.KnownFields(true)

	var cfg Config
	if err := decoder.Decode(&cfg); err != nil {
		return Config{}, fmt.Errorf("%w: %v", ErrDecode, err)
	}
	// A second document in the file means somebody added configuration after
	// "---" and is convinced it works. It does not - and they have to see
	// that.
	var extra any
	if err := decoder.Decode(&extra); !errors.Is(err, io.EOF) {
		if err == nil {
			return Config{}, ErrMultipleDocs
		}
		return Config{}, fmt.Errorf("%w: %v", ErrDecode, err)
	}

	fillIn(&cfg)
	if err := durations(&cfg); err != nil {
		return Config{}, err
	}
	if err := cfg.Check(); err != nil {
		return Config{}, err
	}
	return cfg, nil
}

// fillIn puts in the default values wherever the file is silent.
func fillIn(cfg *Config) {
	defaults := Defaults()
	if cfg.Agent.StateDir == "" {
		cfg.Agent.StateDir = defaults.Agent.StateDir
	}
	if cfg.Agent.MaxRaw == nil {
		cfg.Agent.MaxConcurrentTasks = defaults.Agent.MaxConcurrentTasks
	} else {
		cfg.Agent.MaxConcurrentTasks = *cfg.Agent.MaxRaw
	}
	if cfg.Agent.Mode == "" {
		cfg.Agent.Mode = defaults.Agent.Mode
	}
	if cfg.Helper.Socket == "" {
		cfg.Helper.Socket = defaults.Helper.Socket
	}
}

// durations turns the textual entries into durations and guards their ranges.
func durations(cfg *Config) error {
	defaults := Defaults()
	var err error
	if cfg.Connection.ConnectTimeout, err = duration(cfg.Connection.ConnectRaw,
		defaults.Connection.ConnectTimeout); err != nil {
		return err
	}
	if cfg.Connection.ReconnectMin, err = duration(cfg.Connection.ReconnectMinRaw,
		defaults.Connection.ReconnectMin); err != nil {
		return err
	}
	if cfg.Connection.ReconnectMax, err = duration(cfg.Connection.ReconnectMaxRaw,
		defaults.Connection.ReconnectMax); err != nil {
		return err
	}
	if cfg.Agent.InventoryInterval, err = duration(cfg.Agent.InventoryRaw,
		defaults.Agent.InventoryInterval); err != nil {
		return err
	}
	return nil
}

func duration(text string, fallback time.Duration) (time.Duration, error) {
	if text == "" {
		return fallback, nil
	}
	value, err := time.ParseDuration(text)
	if err != nil {
		return 0, fmt.Errorf("%w: %q is not a duration", ErrDecode, text)
	}
	return value, nil
}

// Check guards the contract of the configuration file.
func Check(cfg Config) error { return cfg.Check() }

// Check guards the contract of the configuration file.
func (c Config) Check() error {
	if c.SchemaVersion != SchemaVersion {
		return fmt.Errorf("%w: %d", ErrSchema, c.SchemaVersion)
	}
	if err := httpsAddress("enrollment", c.Connection.EnrollmentURL); err != nil {
		return err
	}
	if len(c.Connection.GatewayURLs) == 0 {
		return ErrGatewayMissing
	}
	seen := map[string]bool{}
	for _, address := range c.Connection.GatewayURLs {
		if err := httpsAddress("gateway", address); err != nil {
			return err
		}
		if seen[address] {
			return fmt.Errorf("%w: %s", ErrGatewayDuplicate, address)
		}
		seen[address] = true
	}
	if !filepath.IsAbs(c.Agent.StateDir) {
		return fmt.Errorf("%w: %s", ErrStateDir, c.Agent.StateDir)
	}
	if !filepath.IsAbs(c.Helper.Socket) {
		return fmt.Errorf("%w: %s", ErrHelperSocket, c.Helper.Socket)
	}
	if c.Agent.MaxConcurrentTasks < 1 || c.Agent.MaxConcurrentTasks > 16 {
		return fmt.Errorf("%w: %d", ErrTaskLimit, c.Agent.MaxConcurrentTasks)
	}
	if c.Agent.Mode != ModeFull && c.Agent.Mode != ModeReadOnly {
		return fmt.Errorf("%w: %s", ErrMode, c.Agent.Mode)
	}
	if c.Connection.ConnectTimeout < time.Second || c.Connection.ConnectTimeout > 2*time.Minute {
		return fmt.Errorf("%w: %s", ErrConnectTimeout, c.Connection.ConnectTimeout)
	}
	if err := reconnectRange(c.Connection.ReconnectMin); err != nil {
		return err
	}
	if err := reconnectRange(c.Connection.ReconnectMax); err != nil {
		return err
	}
	if c.Connection.ReconnectMin > c.Connection.ReconnectMax {
		return fmt.Errorf("%w: %s > %s", ErrReconnectOrder,
			c.Connection.ReconnectMin, c.Connection.ReconnectMax)
	}
	if c.Agent.InventoryInterval < 5*time.Minute || c.Agent.InventoryInterval > 24*time.Hour {
		return fmt.Errorf("%w: %s", ErrDecode, c.Agent.InventoryInterval)
	}
	return nil
}

func reconnectRange(value time.Duration) error {
	if value < time.Second || value > 15*time.Minute {
		return fmt.Errorf("%w: %s", ErrReconnectRange, value)
	}
	return nil
}

// httpsAddress guards that an address is what it looks like.
//
// Without HTTPS the whole bootstrap of trust is make-believe, and userinfo, a
// query and a fragment in the panel's address mean nothing beyond somebody
// having pasted the wrong thing - or trying to smuggle credentials into the
// logs.
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

// CheckBootstrapCA guards that the named CA bundle is an ordinary file.
//
// Separate from the rest of the validation, because it touches the
// filesystem: the configuration parser has to work also when we check a file
// from another machine. A symlink leading into a directory writable by anyone
// is dangerous here: replacing the CA bundle means replacing the host's whole
// trust.
func (c Config) CheckBootstrapCA() error {
	if c.Connection.BootstrapCA == "" {
		return nil
	}
	path := c.Connection.BootstrapCA
	if !filepath.IsAbs(path) {
		return fmt.Errorf("%w: %s is not an absolute path", ErrBootstrapCA, path)
	}
	info, err := os.Lstat(path)
	if err != nil {
		return fmt.Errorf("%w: %v", ErrBootstrapCA, err)
	}
	if info.Mode()&os.ModeSymlink != 0 {
		return fmt.Errorf("%w: %s is a symlink", ErrBootstrapCA, path)
	}
	if !info.Mode().IsRegular() {
		return fmt.Errorf("%w: %s is not an ordinary file", ErrBootstrapCA, path)
	}
	if info.Mode().Perm()&0o022 != 0 {
		return fmt.Errorf("%w: %s is writable by the group or by others", ErrBootstrapCA, path)
	}
	return nil
}
