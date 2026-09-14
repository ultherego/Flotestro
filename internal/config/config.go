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
	// NVDURL points at the NVD API; empty disables enrichment. This source
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

// Effective is the configuration the control plane resolved at start, as
// the settings screen shows it: every value after the defaults, the
// environment and the flags had their say. It carries no secret - only
// whether one is set - so nothing that reads it can leak one, whatever it
// renders.
//
// The values are set in /etc/flotestro/control-plane.env; the screen shows
// them and changes nothing. A panel that let its own configuration be
// edited over the API would let a stolen session redirect the login to a
// provider of the thief's choosing.
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
