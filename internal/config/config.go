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

// Vulnerabilities describes the CVE correlator.
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
	// RedHatCache is the directory the panel keeps the Red Hat findings it has
	// read in between cycles.
	RedHatCache string
	// NVDURL points at the NVD API; empty disables enrichment.
	NVDURL string
	// NVDKey is the API key for NVD.
	NVDKey string
	// NVDInterval says how often the panel asks NVD about changes.
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
// example "5m".
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

// Effective is the configuration the control plane resolved at start, as the
// settings screen shows it: every value after the defaults, the environment
// and the flags had their say.
type Effective struct {
	Version   string
	Commit    string
	BuildDate string
	Protocol  int

	// The listeners and how the fleet and the browser reach them.
	GatewayAddr          string
	EnrollmentAddr       string
	AdminAddr            string
	Advertised           []string
	GatewayID            string
	PublicURL            string
	WebRoot              string
	StateDir             string
	PackageRepositoryURL string

	// The agent contract.
	HeartbeatSeconds int
	HeartbeatJitter  int
	StaleAfter       time.Duration
	AgentCertTTL     time.Duration

	Identity  EffectiveIdentity
	Directory EffectiveDirectory
	StepUp    EffectiveStepUp
	// The browser session lifetimes and the environments a change in
	// which asks for a second person.
	SessionIdle            time.Duration
	SessionAbsolute        time.Duration
	ProductionEnvironments []string

	Webhook         EffectiveWebhook
	Vulnerabilities EffectiveVulnerabilities

	// The retentions: the resource samples of the hosts, their rollups and
	// the trail. Zero for the trail means forever.
	MetricsRawRetention    time.Duration
	MetricsRollupRetention time.Duration
	AuditRetention         time.Duration
	// SecretsKeyFile is where the key of the secret store lies; the key
	// itself is not here.
	SecretsKeyFile string

	// DatabasePool is the shape of the connection pool of this replica, as it was
	// resolved.
	DatabasePool DatabasePool
	// Migration says how this process treats the schema: whether it
	// brings it forward itself, and under which role it would.
	Migration Migration
}

// EffectiveIdentity describes the identity provider the operators sign in
// through.
type EffectiveIdentity struct {
	IssuerURL       string
	ClientID        string
	ClientSecretSet bool
	GroupsClaim     string
}

// EffectiveDirectory describes the directory connector.
type EffectiveDirectory struct {
	Configured   bool
	ServerURL    string
	Principal    string
	KeytabPath   string
	CACertPath   string
	Realm        string
	WriteEnabled bool
}

// EffectiveStepUp is the policy of the operations of the greatest impact.
type EffectiveStepUp struct {
	MaxAge time.Duration
	ACR    string
	// Tokens is "allow" or "refuse": whether an API token may carry such
	// an operation out.
	Tokens string
}

// EffectiveWebhook describes the delivery of the durable trail.
type EffectiveWebhook struct {
	URL       string
	SecretSet bool
	Events    []string
}

// EffectiveVulnerabilities describes the correlator and its sources.
type EffectiveVulnerabilities struct {
	Enabled        bool
	SyncInterval   time.Duration
	MaxSnapshotAge time.Duration
	DebianURL      string
	UbuntuURL      string
	RedHatURL      string
	NVDURL         string
	NVDKeySet      bool
	NVDInterval    time.Duration
}
