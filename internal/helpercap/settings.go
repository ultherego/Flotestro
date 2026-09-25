package helpercap

import (
	"errors"
	"fmt"
	"os"

	"gopkg.in/yaml.v3"

	"github.com/ultherego/flotestro/internal/config"
)

// DefaultConfigPath is where a packaged helper reads its file from.
const DefaultConfigPath = "/etc/flotestro/helper.yaml"

// helperConfig is the part of /etc/flotestro/helper. yaml the helper reads.
type helperConfig struct {
	SchemaVersion int `yaml:"schema_version"`
	Identity      struct {
		HostIDFile string `yaml:"host_id_file"`
	} `yaml:"identity"`
	Capabilities struct {
		// Mode is observe, prefer or enforce (the document also spells the
		// first "audit").
		Mode string `yaml:"mode"`
		// Bootstrap is tofu or pinned: what the helper does with the first
		// bundle, when it trusts nothing yet.
		Bootstrap      string `yaml:"bootstrap"`
		PinFile        string `yaml:"pin_file"`
		TrustedKeysDir string `yaml:"trusted_keys_dir"`
		ReplayDir      string `yaml:"replay_dir"`
	} `yaml:"capabilities"`
}

// Settings is what the helper runs with after the file and the environment
// were read.
type Settings struct {
	Mode Mode
	// Bootstrap decides the first bundle; PinPath is where the keys the
	// operator wrote down are read from.
	Bootstrap  Bootstrap
	PinPath    string
	TrustDir   string
	ReplayDir  string
	HostIDPath string
	// Source says where the mode came from, for the start-up log.
	Source string
}

// LoadSettings reads the file when it exists and lets the environment override
// it: FLOTESTRO_HELPER_CAPABILITY_MODE, FLOTESTRO_HELPER_TRUST_DIR,
// FLOTESTRO_HELPER_REPLAY_DIR and FLOTESTRO_HELPER_HOST_ID_FILE.
func LoadSettings(path string) (Settings, error) {
	settings := Settings{
		Mode:       ModePrefer,
		Bootstrap:  BootstrapTOFU,
		PinPath:    DefaultPinPath,
		TrustDir:   DefaultTrustDir,
		ReplayDir:  DefaultReplayDir,
		HostIDPath: DefaultHostIDPath,
		Source:     "default",
	}
	raw, err := os.ReadFile(path)
	switch {
	case err == nil:
		var file helperConfig
		if err := yaml.Unmarshal(raw, &file); err != nil {
			return settings, fmt.Errorf("%s: %w", path, err)
		}
		if file.Capabilities.Mode != "" {
			mode, err := ParseMode(file.Capabilities.Mode)
			if err != nil {
				return settings, fmt.Errorf("%s: capabilities.mode: %w", path, err)
			}
			settings.Mode = mode
			settings.Source = path
		}
		if file.Capabilities.Bootstrap != "" {
			bootstrap, err := ParseBootstrap(file.Capabilities.Bootstrap)
			if err != nil {
				return settings, fmt.Errorf("%s: capabilities.bootstrap: %w", path, err)
			}
			settings.Bootstrap = bootstrap
		}
		if file.Capabilities.PinFile != "" {
			settings.PinPath = file.Capabilities.PinFile
		}
		if file.Capabilities.TrustedKeysDir != "" {
			settings.TrustDir = file.Capabilities.TrustedKeysDir
		}
		if file.Capabilities.ReplayDir != "" {
			settings.ReplayDir = file.Capabilities.ReplayDir
		}
		if file.Identity.HostIDFile != "" {
			settings.HostIDPath = file.Identity.HostIDFile
		}
	case errors.Is(err, os.ErrNotExist):
	default:
		return settings, fmt.Errorf("%s: %w", path, err)
	}
	if value := os.Getenv("FLOTESTRO_HELPER_CAPABILITY_MODE"); value != "" {
		mode, err := ParseMode(value)
		if err != nil {
			return settings, fmt.Errorf("FLOTESTRO_HELPER_CAPABILITY_MODE: %w", err)
		}
		settings.Mode = mode
		settings.Source = "FLOTESTRO_HELPER_CAPABILITY_MODE"
	}
	if value := os.Getenv("FLOTESTRO_HELPER_BOOTSTRAP"); value != "" {
		bootstrap, err := ParseBootstrap(value)
		if err != nil {
			return settings, fmt.Errorf("FLOTESTRO_HELPER_BOOTSTRAP: %w", err)
		}
		settings.Bootstrap = bootstrap
	}
	settings.PinPath = config.Env("FLOTESTRO_HELPER_PIN_FILE", settings.PinPath)
	settings.TrustDir = config.Env("FLOTESTRO_HELPER_TRUST_DIR", settings.TrustDir)
	settings.ReplayDir = config.Env("FLOTESTRO_HELPER_REPLAY_DIR", settings.ReplayDir)
	settings.HostIDPath = config.Env("FLOTESTRO_HELPER_HOST_ID_FILE", settings.HostIDPath)
	return settings, nil
}
