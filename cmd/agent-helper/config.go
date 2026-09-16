package main

import (
	"errors"
	"fmt"
	"os"

	"gopkg.in/yaml.v3"

	"github.com/ultherego/flotestro/internal/config"
	"github.com/ultherego/flotestro/internal/helpercap"
)

// DefaultConfigPath is where a packaged helper reads its file from. The
// file is optional: a helper without one runs on the environment and the
// defaults, which is what every host from before the file does.
const DefaultConfigPath = "/etc/flotestro/helper.yaml"

// helperConfig is the part of /etc/flotestro/helper.yaml the helper reads.
// The file belongs to root and is not writable by the agent's user, so
// what it says about the mode and the trust directory is the owner's
// decision and not something a compromised agent can lower.
type helperConfig struct {
	SchemaVersion int `yaml:"schema_version"`
	Identity      struct {
		HostIDFile string `yaml:"host_id_file"`
	} `yaml:"identity"`
	Capabilities struct {
		// Mode is observe, prefer or enforce (the document also spells the
		// first "audit").
		Mode           string `yaml:"mode"`
		TrustedKeysDir string `yaml:"trusted_keys_dir"`
		ReplayDir      string `yaml:"replay_dir"`
	} `yaml:"capabilities"`
}

// capabilitySettings is what the helper runs with after the file and the
// environment were read.
type capabilitySettings struct {
	Mode       helpercap.Mode
	TrustDir   string
	ReplayDir  string
	HostIDPath string
	// Source says where the mode came from, for the start-up log.
	Source string
}

// loadCapabilitySettings reads the file when it exists and lets the
// environment override it: FLOTESTRO_HELPER_CAPABILITY_MODE,
// FLOTESTRO_HELPER_TRUST_DIR, FLOTESTRO_HELPER_REPLAY_DIR and
// FLOTESTRO_HELPER_HOST_ID_FILE. A file that cannot be parsed is an error
// rather than a fallback to the defaults: the owner wrote a decision down
// and the helper must not run on another one.
func loadCapabilitySettings(path string) (capabilitySettings, error) {
	settings := capabilitySettings{
		Mode:       helpercap.ModePrefer,
		TrustDir:   helpercap.DefaultTrustDir,
		ReplayDir:  helpercap.DefaultReplayDir,
		HostIDPath: helpercap.DefaultHostIDPath,
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
			mode, err := helpercap.ParseMode(file.Capabilities.Mode)
			if err != nil {
				return settings, fmt.Errorf("%s: capabilities.mode: %w", path, err)
			}
			settings.Mode = mode
			settings.Source = path
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
		mode, err := helpercap.ParseMode(value)
		if err != nil {
			return settings, fmt.Errorf("FLOTESTRO_HELPER_CAPABILITY_MODE: %w", err)
		}
		settings.Mode = mode
		settings.Source = "FLOTESTRO_HELPER_CAPABILITY_MODE"
	}
	settings.TrustDir = config.Env("FLOTESTRO_HELPER_TRUST_DIR", settings.TrustDir)
	settings.ReplayDir = config.Env("FLOTESTRO_HELPER_REPLAY_DIR", settings.ReplayDir)
	settings.HostIDPath = config.Env("FLOTESTRO_HELPER_HOST_ID_FILE", settings.HostIDPath)
	return settings, nil
}
