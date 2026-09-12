// Package config gathers the configuration of the control plane and of the
// agent from environment variables and flags.
package config

import (
	"fmt"
	"os"
	"strconv"
	"time"
)

// ControlPlane describes the configuration of the server.
type ControlPlane struct {
	DatabaseURL      string
	StateDir         string
	GatewayAddr      string
	EnrollmentAddr   string
	AdminAddr        string
	AdvertisedHosts  []string
	HeartbeatSeconds int
	HeartbeatJitter  int
	StaleAfter       time.Duration
	GatewayID        string
}

// Monitoring describes the connections to the metric and alert systems.
//
// Each of them is optional: an installation without monitoring works the same,
// and the panel says outright that no sources were named - instead of drawing
// empty charts.
type Monitoring struct {
	PrometheusURL   string
	AlertmanagerURL string
	Timeout         time.Duration
	// HostLabel and HostValue translate a host of the panel into a label at
	// the sources.
	HostLabel        string
	HostValue        string
	SiteLabel        string
	EnvironmentLabel string
	// DashboardURL and LogsURL are templates of links: the panel leads to
	// somebody else's screens instead of recreating them.
	DashboardURL string
	LogsURL      string
	Window       time.Duration
}

// Vulnerabilities describes the CVE correlator.
//
// The tracker of the distribution vendor settles the matter; upstream feeds
// may later add a description and a CVSS, but they must not change the answer
// "vulnerable / not vulnerable".
type Vulnerabilities struct {
	Enabled bool
	// SyncInterval says how often the panel asks the trackers about changes.
	SyncInterval time.Duration
	// MaxSnapshotAge is the age above which the data are stale. It does not
	// stop the assessment, but it has to be visible next to the result.
	MaxSnapshotAge time.Duration
	// DebianURL names the dump of the Debian tracker; empty disables this
	// source.
	DebianURL string
	// UbuntuURL names the directory with the OVAL data of Canonical; empty
	// disables this source.
	UbuntuURL string
	// RedHatURL names the directory with the CSAF/VEX data of Red Hat; empty
	// disables this source.
	RedHatURL string
	// RedHatCache is the directory the panel keeps the Red Hat findings it
	// has read in between cycles. The full data are a three hundred megabyte
	// archive, so without a memory every cycle would fetch them anew.
	RedHatCache string
	// NVDURL wskazuje API bazy NVD; pusty wylacza wzbogacanie. To zrodlo
	// settles nothing - it only adds the CVSS score and the description of a
	// vulnerability.
	NVDURL string
	// NVDKey is the API key for NVD. Without a key five requests per thirty
	// seconds are allowed, so the first read takes around twenty minutes; with
	// a key a few minutes.
	NVDKey string
	// NVDInterval says how often the panel asks NVD about changes. Less often
	// than about vulnerabilities: these data do not change a single answer
	// about hosts.
	NVDInterval time.Duration
}

// Env reads an environment variable with a default value.
func Env(key, fallback string) string {
	if value, ok := os.LookupEnv(key); ok && value != "" {
		return value
	}
	return fallback
}

// EnvInt reads a numeric environment variable.
func EnvInt(key string, fallback int) int {
	value, ok := os.LookupEnv(key)
	if !ok || value == "" {
		return fallback
	}
	parsed, err := strconv.Atoi(value)
	if err != nil {
		return fallback
	}
	return parsed
}

// EnvDuration reads an environment variable expressed as a duration, for
// example "5m". An unreadable value must not silently switch a safeguard off,
// so the default value stays.
func EnvDuration(key string, fallback time.Duration) time.Duration {
	value, ok := os.LookupEnv(key)
	if !ok || value == "" {
		return fallback
	}
	parsed, err := time.ParseDuration(value)
	if err != nil || parsed < 0 {
		return fallback
	}
	return parsed
}

// Validate checks the minimal set of required settings.
func (c ControlPlane) Validate() error {
	if c.DatabaseURL == "" {
		return fmt.Errorf("FLOTESTRO_DATABASE_URL is missing")
	}
	if c.StateDir == "" {
		return fmt.Errorf("the state directory is missing")
	}
	return nil
}
