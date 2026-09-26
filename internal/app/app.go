// Package app assembles the control plane: it reads the configuration, opens
// the database, brings up the crypto state, the API, the agent gateway, the
// enrollment endpoint and the background passes, and shuts them down again.
//
// It lives here and not in cmd/control-plane because a command is an entry
// point and this is the product. The command was 1500 lines of assembly, which
// meant nothing else could reach any of it - not a test, not a second entry
// point - and a package under cmd is the one place in a Go tree that nothing
// can import.
package app

import (
	"connectrpc.com/connect"
	"context"
	"crypto/tls"
	"errors"
	"flag"
	"fmt"
	"log/slog"
	"math"
	"net"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	"golang.org/x/net/http2"
	"golang.org/x/net/http2/h2c"

	"github.com/ultherego/flotestro/internal/adminapi"
	"github.com/ultherego/flotestro/internal/audit"
	"github.com/ultherego/flotestro/internal/authz"
	"github.com/ultherego/flotestro/internal/budgets"
	"github.com/ultherego/flotestro/internal/buildinfo"
	"github.com/ultherego/flotestro/internal/campaigns"
	"github.com/ultherego/flotestro/internal/config"
	"github.com/ultherego/flotestro/internal/cryptostate"
	"github.com/ultherego/flotestro/internal/database"
	"github.com/ultherego/flotestro/internal/enrollment"
	"github.com/ultherego/flotestro/internal/events"
	managedfiles "github.com/ultherego/flotestro/internal/files"
	"github.com/ultherego/flotestro/internal/freeipa"
	"github.com/ultherego/flotestro/internal/gateway"
	"github.com/ultherego/flotestro/internal/genproto/flotestro/agent/v1/agentv1connect"
	"github.com/ultherego/flotestro/internal/helpercap"
	"github.com/ultherego/flotestro/internal/hosts"
	"github.com/ultherego/flotestro/internal/housekeeping"
	"github.com/ultherego/flotestro/internal/identity"
	"github.com/ultherego/flotestro/internal/inventory"
	"github.com/ultherego/flotestro/internal/issuer"
	"github.com/ultherego/flotestro/internal/jobs"
	"github.com/ultherego/flotestro/internal/metrics"
	"github.com/ultherego/flotestro/internal/monitoring"
	"github.com/ultherego/flotestro/internal/notify"
	"github.com/ultherego/flotestro/internal/oidc"
	"github.com/ultherego/flotestro/internal/opspec"
	"github.com/ultherego/flotestro/internal/outbox"
	"github.com/ultherego/flotestro/internal/pki"
	"github.com/ultherego/flotestro/internal/policy"
	"github.com/ultherego/flotestro/internal/relays"
	"github.com/ultherego/flotestro/internal/remediation"
	"github.com/ultherego/flotestro/internal/scheduler"
	"github.com/ultherego/flotestro/internal/secrets"
	"github.com/ultherego/flotestro/internal/selector"
	"github.com/ultherego/flotestro/internal/vuln"
	debiansource "github.com/ultherego/flotestro/internal/vuln/sources/debian"
	nvdsource "github.com/ultherego/flotestro/internal/vuln/sources/nvd"
	redhatsource "github.com/ultherego/flotestro/internal/vuln/sources/redhat"
	ubuntusource "github.com/ultherego/flotestro/internal/vuln/sources/ubuntu"
)

const staleCheckInterval = 30 * time.Second

// sessionAbsolute ends a panel session a day after the login whatever the
// activity; the idle window within it is a setting.
const sessionAbsolute = 24 * time.Hour

func Run() error {
	// Which of the three things this process is, before anything else: the
	// serving control plane, the migrator, or the check that answers whether the
	// schema is the one this binary expects.
	cmd, args, err := parseCommand(os.Args[1:])
	if err != nil {
		return err
	}
	cfg := config.ControlPlane{}
	// The secrets are read before the flags are defined, so that an installation
	// can mount each of them as a file instead of putting the value into the
	// environment of the process - where the container engine's inspection, the.
	databaseURL, err := config.OptionalSecretValue("FLOTESTRO_DATABASE_URL")
	if err != nil {
		return err
	}
	oidcClientSecret, err := config.OptionalSecretValue("FLOTESTRO_OIDC_CLIENT_SECRET")
	if err != nil {
		return err
	}
	webhookSecretValue, err := config.OptionalSecretValue("FLOTESTRO_WEBHOOK_SECRET")
	if err != nil {
		return err
	}
	nvdKey, err := config.OptionalSecretValue("FLOTESTRO_VULN_NVD_KEY")
	if err != nil {
		return err
	}
	// The DSN of the migrator.
	migrationURL, err := config.OptionalSecretValue(config.EnvMigrationDatabaseURL)
	if err != nil {
		return err
	}
	flag.StringVar(&cfg.DatabaseURL, "database-url", databaseURL, "the PostgreSQL DSN")
	flag.StringVar(&cfg.StateDir, "state-dir",
		config.Env("FLOTESTRO_STATE_DIR", "/var/lib/flotestro"), "the state directory (CA)")
	flag.StringVar(&cfg.GatewayAddr, "gateway-addr",
		config.Env("FLOTESTRO_GATEWAY_ADDR", ":8443"), "the address of the agent gateway (mTLS)")
	flag.StringVar(&cfg.EnrollmentAddr, "enrollment-addr",
		config.Env("FLOTESTRO_ENROLLMENT_ADDR", ":8444"), "the address of the enrollment endpoint (TLS)")
	flag.StringVar(&cfg.AdminAddr, "admin-addr",
		config.Env("FLOTESTRO_ADMIN_ADDR", "127.0.0.1:8080"), "the address of the REST API")
	advertised := flag.String("advertise",
		config.Env("FLOTESTRO_ADVERTISE", "127.0.0.1"),
		"the addresses and names the agents see the control plane under (comma separated)")
	flag.IntVar(&cfg.HeartbeatSeconds, "heartbeat-seconds",
		config.EnvInt("FLOTESTRO_HEARTBEAT_SECONDS", 60), "the base interval of the heartbeat")
	flag.IntVar(&cfg.HeartbeatJitter, "heartbeat-jitter",
		config.EnvInt("FLOTESTRO_HEARTBEAT_JITTER", 30), "the random spread of the heartbeat")
	issuerURL := flag.String("oidc-issuer",
		config.Env("FLOTESTRO_OIDC_ISSUER", ""),
		"the address of the OIDC issuer, e.g. https://ipa:8081/realms/flotestro")
	clientID := flag.String("oidc-client-id",
		config.Env("FLOTESTRO_OIDC_CLIENT_ID", "flotestro-panel"), "the OIDC client identifier")
	clientSecret := flag.String("oidc-client-secret", oidcClientSecret, "the OIDC client secret")
	directoryWrite := flag.Bool("directory-write",
		config.Env("FLOTESTRO_DIRECTORY_WRITE", "") == "true",
		"enables changes in the identity directory; by default the panel only reads it")
	agentCertTTL := flag.Duration("agent-cert-ttl",
		config.EnvDuration("FLOTESTRO_AGENT_CERT_TTL", pki.AgentCertTTL),
		"the lifetime of an agent certificate; the agent renews it after two thirds have passed")
	stepUpMaxAge := flag.Duration("stepup-max-age",
		config.EnvDuration("FLOTESTRO_STEPUP_MAX_AGE", 5*time.Minute),
		"the acceptable age of an authentication for the operations of the greatest impact")
	stepUpACR := flag.String("stepup-acr",
		config.Env("FLOTESTRO_STEPUP_ACR", ""),
		"the required level of authentication (acr) for the operations of the greatest impact")
	sessionIdle := flag.Duration("session-idle",
		config.EnvDuration("FLOTESTRO_SESSION_IDLE", 8*time.Hour),
		"how long a panel session survives without a request; the absolute limit of a day stands regardless")
	sessionGroupRefresh := flag.Duration("session-group-refresh",
		config.EnvDuration("FLOTESTRO_SESSION_GROUP_REFRESH", 5*time.Minute),
		"how often the groups of a live panel session are confirmed with the identity provider; 0 turns it off")
	// The key of the store lies in the state directory next to the CA key: that
	// is the only place the service is allowed to write to, and the only one
	// whose permissions are narrow enough to keep cryptographic material in.
	secretsKeyFile := flag.String("secrets-key-file",
		config.Env("FLOTESTRO_SECRETS_KEY_FILE", ""),
		"the key file of a secret store from before the key provider; adopted as the key \"legacy\" at the first start")
	secretsKeyCredential := flag.String("secrets-key-credential",
		config.Env("FLOTESTRO_SECRETS_KEY_CREDENTIAL", ""),
		"the name of a systemd credential (LoadCredential) that holds a key of the secret store under that key id")
	secretsKeyRotateTo := flag.String("secrets-key-rotate-to",
		config.Env("FLOTESTRO_SECRETS_KEY_ROTATE_TO", ""),
		"the id of the key the secret store switches to at this start; created when missing, a no-op once active")
	webRoot := flag.String("web-root",
		config.Env("FLOTESTRO_WEB_ROOT", ""), "the directory with the built panel")
	publicURL := flag.String("public-url",
		config.Env("FLOTESTRO_PUBLIC_URL", ""), "the address of the panel as the browser sees it")
	packageRepositoryURL := flag.String("package-repository-url",
		config.Env("FLOTESTRO_PACKAGE_REPOSITORY_URL", ""),
		"the base address of the signed package repository the installation instructions point the hosts at")
	groupsClaim := flag.String("oidc-groups-claim",
		config.Env("FLOTESTRO_OIDC_GROUPS_CLAIM", "groups"), "the field of the token with the list of groups")
	// Off by default: it needs a Keycloak realm and a service account with
	// the realm management roles, and the local denial holds without it.
	oidcAdminLogout := flag.Bool("oidc-admin-logout",
		config.Env("FLOTESTRO_OIDC_ADMIN_LOGOUT", "") == "true",
		"end a disabled user's sessions at the identity provider through the Keycloak admin API")
	// The name of the variable has to match the configuration file the
	// installation gets in the package: a divergence meant that a filled in
	// FLOTESTRO_IPA_URL enabled nothing while the panel said nothing about the.
	ipaServer := flag.String("ipa-server",
		config.Env("FLOTESTRO_IPA_URL", config.Env("FLOTESTRO_IPA_SERVER", "")),
		"the address of the FreeIPA server, e.g. https://ipa.example.org")
	ipaPrincipal := flag.String("ipa-principal",
		config.Env("FLOTESTRO_IPA_PRINCIPAL", ""), "the service principal of the directory connector")
	ipaKeytab := flag.String("ipa-keytab",
		config.Env("FLOTESTRO_IPA_KEYTAB", "/etc/flotestro/ipa.keytab"), "the keytab of the connector")
	ipaCACert := flag.String("ipa-ca-cert",
		config.Env("FLOTESTRO_IPA_CA_CERT", "/etc/flotestro/ipa-ca.crt"), "the CA certificate of the directory")
	ipaRealm := flag.String("ipa-realm",
		config.Env("FLOTESTRO_IPA_REALM", ""), "the Kerberos realm of the directory")
	// The built-in monitoring keeps the raw samples for a week and the
	// quarter-hour rollups for a quarter of a year. These are the initial
	// values of an installation: once it stores its own from the panel, the
	// stored ones decide and these stay the fallback of a cleared field.
	metricsRetention := monitoring.Options{}
	flag.DurationVar(&metricsRetention.RawRetention, "metrics-retention-raw",
		config.EnvDuration("FLOTESTRO_METRICS_RETENTION_RAW", monitoring.DefaultRawRetention),
		"how long the raw resource samples of the hosts are kept")
	flag.DurationVar(&metricsRetention.RollupRetention, "metrics-retention-rollup",
		config.EnvDuration("FLOTESTRO_METRICS_RETENTION_ROLLUP", monitoring.DefaultRollupRetention),
		"how long the quarter-hour rollups of the resource samples are kept")
	flag.DurationVar(&metricsRetention.MaxLateness, "metrics-max-lateness",
		config.EnvDuration("FLOTESTRO_METRICS_MAX_LATENESS", monitoring.DefaultMaxLateness),
		"how late a resource sample may arrive and still be stored")
	flag.DurationVar(&metricsRetention.RawQueryWindow, "metrics-query-window",
		config.EnvDuration("FLOTESTRO_METRICS_QUERY_WINDOW", monitoring.DefaultRawQueryWindow),
		"how far back the panel offers the raw samples at full resolution")
	flag.DurationVar(&metricsRetention.ClockSkewLimit, "metrics-clock-skew",
		config.EnvDuration("FLOTESTRO_METRICS_CLOCK_SKEW", monitoring.DefaultClockSkewLimit),
		"how far ahead of the panel a host's clock may be before its sample is stamped with the panel's time")
	flag.IntVar(&metricsRetention.PartitionsAhead, "metrics-partitions-ahead",
		config.EnvInt("FLOTESTRO_METRICS_PARTITIONS_AHEAD", monitoring.DefaultPartitionsAhead),
		"how many days of raw sample partitions exist ahead of today")
	flag.DurationVar(&metricsRetention.EvaluatorLease, "metrics-evaluator-lease",
		config.EnvDuration("FLOTESTRO_METRICS_EVALUATOR_LEASE", monitoring.DefaultEvaluatorLease),
		"how long one control-plane instance holds the right to evaluate the alert rules")
	// The buffer history of the relays: a week of raw reports and a quarter of a
	// year of quarter-hour rollups.
	relayRetention := relays.Options{}
	flag.DurationVar(&relayRetention.RawRetention, "relay-buffer-retention-raw",
		config.EnvDuration("FLOTESTRO_RELAY_BUFFER_RETENTION_RAW", relays.DefaultRawRetention),
		"how long the raw buffer reports of the relays are kept")
	flag.DurationVar(&relayRetention.RollupRetention, "relay-buffer-retention-rollup",
		config.EnvDuration("FLOTESTRO_RELAY_BUFFER_RETENTION_ROLLUP", relays.DefaultRollupRetention),
		"how long the quarter-hour rollups of the relay buffer reports are kept")
	// How much of the snapshot in force a feed fetch may lose and still be
	// activated.
	vulnShrinkShare := vuln.DefaultShrinkShare
	if raw := config.Env("FLOTESTRO_VULN_SHRINK_SHARE", ""); raw != "" {
		if parsed, err := strconv.ParseFloat(raw, 64); err == nil {
			vulnShrinkShare = parsed
		}
	}
	// The lifecycle orders between the control-plane instances: an order written
	// for the instance that holds a host's session.
	commandOptions := gateway.CommandOptions{}
	flag.DurationVar(&commandOptions.Poll, "command-poll",
		config.EnvDuration("FLOTESTRO_COMMAND_POLL", gateway.DefaultCommandPoll),
		"how often an instance looks for lifecycle orders addressed to the sessions it holds")
	flag.DurationVar(&commandOptions.Expiry, "command-expiry",
		config.EnvDuration("FLOTESTRO_COMMAND_EXPIRY", gateway.DefaultCommandExpiry),
		"how long an unclaimed lifecycle order stands before it is settled as expired")

	// The notification queue.
	notifyOptions := notify.Options{}
	flag.DurationVar(&notifyOptions.Poll, "notify-poll",
		config.EnvDuration("FLOTESTRO_NOTIFY_POLL", notify.DefaultPoll),
		"how often a notification worker looks for rows that are due")
	flag.IntVar(&notifyOptions.Batch, "notify-batch",
		config.EnvInt("FLOTESTRO_NOTIFY_BATCH", notify.DefaultBatch),
		"how many notification deliveries one claim takes")
	flag.IntVar(&notifyOptions.MaxAttempts, "notify-max-attempts",
		config.EnvInt("FLOTESTRO_NOTIFY_MAX_ATTEMPTS", notify.DefaultMaxAttempts),
		"how many attempts a notification gets before it is a dead letter")
	flag.DurationVar(&notifyOptions.BaseBackoff, "notify-backoff-base",
		config.EnvDuration("FLOTESTRO_NOTIFY_BACKOFF_BASE", notify.DefaultBaseBackoff),
		"the pause before the second attempt; every attempt after it doubles the pause, with full jitter")
	flag.DurationVar(&notifyOptions.MaxBackoff, "notify-backoff-max",
		config.EnvDuration("FLOTESTRO_NOTIFY_BACKOFF_MAX", notify.DefaultMaxBackoff),
		"the ceiling of that pause")
	flag.DurationVar(&notifyOptions.Lease, "notify-lease",
		config.EnvDuration("FLOTESTRO_NOTIFY_LEASE", notify.DefaultLease),
		"how long a claimed notification delivery belongs to one worker")
	// The trail is evidence and is kept forever unless the installation decides
	// otherwise; the ended agent sessions are swept after a month on their own,
	// because nothing reads an older one.
	auditRetention := flag.Duration("audit-retention",
		config.EnvDuration("FLOTESTRO_AUDIT_RETENTION", 0),
		"how long the audit trail is kept; zero keeps it forever")
	// The working record of the fleet, unlike the trail, is always swept: a
	// finished job, a finished campaign and a delivered event are read for a
	// while and then only take room.
	jobRetention := flag.Duration("job-retention",
		config.EnvDuration("FLOTESTRO_JOB_RETENTION", housekeeping.JobRetention),
		"how long finished jobs are kept")
	campaignRetention := flag.Duration("campaign-retention",
		config.EnvDuration("FLOTESTRO_CAMPAIGN_RETENTION", housekeeping.CampaignRetention),
		"how long finished campaigns are kept, with their targets, steps and approvals")
	outboxRetention := flag.Duration("outbox-retention",
		config.EnvDuration("FLOTESTRO_OUTBOX_RETENTION", housekeeping.OutboxRetention),
		"how long the delivered events of the durable trail are kept")
	// The dispatch rate of the document: a queue of thousands after an outage
	// drains at a pace the fleet and the panel carry, rather than in one wave.
	dispatchRate := flag.Int("dispatch-rate",
		config.EnvInt("FLOTESTRO_DISPATCH_RATE", 100),
		"how many task envelopes this gateway sends per second; zero sends every leased task at once")
	// The reaction to a copied identity. Read strictly: a word other than
	// the two is a misconfiguration, not the default.
	clonePolicyValue := flag.String("clone-policy",
		config.Env("FLOTESTRO_CLONE_POLICY", ""),
		"what to do with the same identity alive on two boots: report or quarantine (the default)")
	// What the gateway does with a session through a relay that names the host
	// without the certificate it presented: observe and prefer let it in - prefer
	// marks the host as weakly identified - and enforce refuses it until the.
	relayIdentityValue := flag.String("relay-identity",
		config.Env("FLOTESTRO_RELAY_IDENTITY", ""),
		"a relayed session without the host's certificate: observe, prefer (the default) or enforce")
	// How strictly a campaign order is held to the preview it was placed from:
	// observe records the difference, prefer refuses an order whose preview no
	// longer describes what the order resolves, enforce also refuses an order.
	campaignPreviewValue := flag.String("campaign-preview",
		config.Env("FLOTESTRO_CAMPAIGN_PREVIEW", ""),
		"how a campaign order is held to its preview: observe, prefer (the default) or enforce")
	stepUpTokens := flag.String("stepup-tokens",
		config.Env("FLOTESTRO_STEPUP_TOKENS", "allow"),
		"whether an API token may carry out the operations of the greatest impact: allow or refuse")
	// The rollout stage of the root helper's signed capability on the panel's
	// side: observe and prefer dispatch to every host, prefer reports a host
	// whose agent forwards no capability, enforce holds a mutating task back.
	helperCapabilityModeValue := flag.String("helper-capability-mode",
		config.Env("FLOTESTRO_HELPER_CAPABILITY_MODE", "prefer"),
		"the stage of the helper capability rollout: observe, prefer (the default) or enforce")
	helperSigningKey := flag.String("helper-signing-key",
		config.Env("FLOTESTRO_HELPER_SIGNING_KEY", ""),
		"the Ed25519 key that signs helper capabilities; the default is helper-signing.key in the state directory")
	vulnerabilities := config.Vulnerabilities{}
	flag.BoolVar(&vulnerabilities.Enabled, "vulnerability-correlator",
		config.Env("FLOTESTRO_VULN_ENABLED", "true") == "true",
		"enables the vulnerability correlator based on the trackers of the distributions")
	flag.DurationVar(&vulnerabilities.SyncInterval, "vulnerability-sync-interval",
		config.EnvDuration("FLOTESTRO_VULN_SYNC_INTERVAL", 30*time.Minute),
		"how often the panel asks the trackers about changes")
	flag.DurationVar(&vulnerabilities.MaxSnapshotAge, "vulnerability-max-snapshot-age",
		config.EnvDuration("FLOTESTRO_VULN_MAX_SNAPSHOT_AGE", 6*time.Hour),
		"the age above which the data of a feed are described as stale")
	flag.StringVar(&vulnerabilities.DebianURL, "vulnerability-debian-url",
		config.EnvMeaningfullyEmpty("FLOTESTRO_VULN_DEBIAN_URL", debiansource.DefaultURL),
		"the dump of the Debian security tracker (https:// or file://); empty disables this source")
	flag.StringVar(&vulnerabilities.UbuntuURL, "vulnerability-ubuntu-url",
		config.EnvMeaningfullyEmpty("FLOTESTRO_VULN_UBUNTU_URL", ubuntusource.DefaultURL),
		"the directory with the OVAL data of Canonical (https:// or file://); empty disables this source")
	flag.StringVar(&vulnerabilities.RedHatURL, "vulnerability-redhat-url",
		config.EnvMeaningfullyEmpty("FLOTESTRO_VULN_REDHAT_URL", redhatsource.DefaultURL),
		"the directory with the CSAF/VEX data of Red Hat (https:// or file://); empty disables this source")
	flag.StringVar(&vulnerabilities.RedHatCache, "vulnerability-redhat-cache",
		config.Env("FLOTESTRO_VULN_REDHAT_CACHE", redhatsource.DefaultDirectory),
		"the directory for the Red Hat findings that were read")
	flag.StringVar(&vulnerabilities.NVDURL, "vulnerability-nvd-url",
		config.EnvMeaningfullyEmpty("FLOTESTRO_VULN_NVD_URL", nvdsource.DefaultURL),
		"the API of the NVD database for enriching the descriptions (https:// or file://); empty disables it")
	flag.StringVar(&vulnerabilities.NVDKey, "vulnerability-nvd-key", nvdKey,
		"the API key for NVD; without it the first read takes around twenty minutes")
	flag.DurationVar(&vulnerabilities.NVDInterval, "vulnerability-nvd-interval",
		config.EnvDuration("FLOTESTRO_VULN_NVD_INTERVAL", 6*time.Hour),
		"how often the panel asks NVD about changes to the descriptions")
	webhookURL := flag.String("webhook-url",
		config.Env("FLOTESTRO_WEBHOOK_URL", ""),
		"the address the events of the durable trail are posted to; empty disables the webhook")
	webhookSecret := flag.String("webhook-secret", webhookSecretValue,
		"the secret the webhook deliveries are signed with (HMAC-SHA256)")
	webhookEvents := flag.String("webhook-events",
		config.Env("FLOTESTRO_WEBHOOK_EVENTS", ""),
		"the prefixes of the event types to deliver, comma separated; empty means every event")
	productionList := flag.String("production-environments",
		config.Env("FLOTESTRO_PRODUCTION_ENVIRONMENTS", "prod,production"),
		"the environments where a change has to be approved by a second person")
	// The deprecated spelling of the migrate command.
	migrateOnly := flag.Bool("migrate-only",
		config.Env("FLOTESTRO_MIGRATE_ONLY", "") != "",
		"deprecated: the old spelling of the migrate command")
	// The shape of the connection pool of this replica and the contract of the
	// schema.
	dbPool, err := config.DatabasePoolFromEnv()
	if err != nil {
		return err
	}
	migration, err := config.MigrationFromEnv()
	if err != nil {
		return err
	}
	dbMaxConns := flag.Int("db-max-conns", int(dbPool.MaxConns),
		"how many connections this replica may open; every replica takes its own share of max_connections")
	dbMinConns := flag.Int("db-min-conns", int(dbPool.MinConns),
		"how many connections the pool keeps open while the fleet is quiet")
	dbMaxConnLifetime := flag.Duration("db-max-conn-lifetime", dbPool.MaxConnLifetime,
		"how long a connection is used before it is retired while healthy")
	dbMaxConnIdleTime := flag.Duration("db-max-conn-idle-time", dbPool.MaxConnIdleTime,
		"how long an unused connection is kept before it is given back")
	dbHealthCheckPeriod := flag.Duration("db-health-check-period", dbPool.HealthCheckPeriod,
		"how often the pool looks at the connections it holds")
	dbConnectTimeout := flag.Duration("db-connect-timeout", dbPool.ConnectTimeout,
		"how long one attempt to open a connection may take; it stays under the start-up wait")
	autoMigrate := flag.Bool("auto-migrate", migration.AutoMigrate,
		"let the serving process bring the schema forward itself; the quick start does, "+
			"a deployment with a migration job sets it to false")
	migrationRole := flag.String("migration-role", migration.Role,
		"the role the migrator takes on after connecting, usually the NOLOGIN owner of the schema")
	migrationLockWait := flag.Duration("migration-lock-wait", migration.LockWait,
		"how long a migrator waits for another one that already holds the schema lock")
	if err := flag.CommandLine.Parse(args); err != nil {
		return err
	}

	// The whole numbers of the pool are the int32 the pool driver takes; a value
	// that would wrap around is refused rather than turned into a pool of a
	// different size than the one that was asked for.
	if *dbMaxConns < 0 || *dbMaxConns > math.MaxInt32 || *dbMinConns < 0 || *dbMinConns > math.MaxInt32 {
		return fmt.Errorf("the connection counts are whole numbers between 0 and %d", math.MaxInt32)
	}
	dbPool.MaxConns = int32(*dbMaxConns)
	dbPool.MinConns = int32(*dbMinConns)
	dbPool.MaxConnLifetime = *dbMaxConnLifetime
	dbPool.MaxConnIdleTime = *dbMaxConnIdleTime
	dbPool.HealthCheckPeriod = *dbHealthCheckPeriod
	dbPool.ConnectTimeout = *dbConnectTimeout
	// A connect timeout named on the command line counts as named: it wins
	// against a connect_timeout the DSN carries, exactly as the variable does.
	if flagWasSet("db-connect-timeout") {
		dbPool.ConnectTimeoutSet = true
	}
	if err := dbPool.Validate(); err != nil {
		return err
	}
	migration.AutoMigrate = *autoMigrate
	migration.Role = strings.TrimSpace(*migrationRole)
	migration.LockWait = *migrationLockWait
	if migration.LockWait <= 0 {
		return fmt.Errorf("-migration-lock-wait is %s; a migrator that does not wait for the one "+
			"already running is a migrator that races it", migration.LockWait)
	}

	// A raw retention shorter than the window the panel offers plus the longest a
	// sample may take to arrive deletes a reading a relay is still carrying, by
	// definition and without anybody ordering it.
	if err := metricsRetention.Validate(); err != nil {
		return fmt.Errorf("the monitoring settings would delete samples before they can arrive: %w", err)
	}

	// An operation without an explicit decision on what a cancel, a retry or a
	// rollback means is a reason not to start: the panel would draw a promise the
	// host cannot keep.
	if err := opspec.ValidateContracts(); err != nil {
		return err
	}

	productionEnvironments := splitList(*productionList)
	if *stepUpTokens != "allow" && *stepUpTokens != "refuse" {
		return fmt.Errorf("FLOTESTRO_STEPUP_TOKENS must be allow or refuse, not %q", *stepUpTokens)
	}
	// A zero would fall back to the built-in window in silence, and a window past
	// the absolute limit never applies; neither is a setting anybody meant.
	if *sessionIdle < time.Minute || *sessionIdle > sessionAbsolute {
		return fmt.Errorf("FLOTESTRO_SESSION_IDLE must be between 1m and %s, not %s", sessionAbsolute, *sessionIdle)
	}
	// Zero is the switch that turns the refresh off; anything shorter than a
	// minute would turn the provider's token endpoint into a heartbeat.
	if *sessionGroupRefresh != 0 && (*sessionGroupRefresh < time.Minute || *sessionGroupRefresh > sessionAbsolute) {
		return fmt.Errorf("FLOTESTRO_SESSION_GROUP_REFRESH must be 0 or between 1m and %s, not %s",
			sessionAbsolute, *sessionGroupRefresh)
	}

	cfg.GatewayID = config.Env("FLOTESTRO_GATEWAY_ID", defaultGatewayID())
	cfg.StaleAfter = time.Duration(cfg.HeartbeatSeconds+cfg.HeartbeatJitter) * 3 * time.Second

	log := slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelInfo}))
	slog.SetDefault(log)

	if *migrateOnly {
		if cmd == commandServe {
			cmd = commandMigrate
		}
		log.Warn("-migrate-only is the deprecated spelling of the migrate command",
			"call_instead", "flotestro-control-plane migrate")
	}
	// A migration job has no CA, no listeners and no state directory of its
	// own, so only the serving process is held to the whole contract.
	if cmd == commandServe {
		if err := cfg.Validate(); err != nil {
			return err
		}
	}
	// The migrator uses the DSN of its own role where the deployment gives
	// it one; everything else runs on the runtime DSN.
	dsn := cfg.DatabaseURL
	if cmd == commandMigrate && migrationURL != "" {
		dsn = migrationURL
	}
	if dsn == "" {
		return fmt.Errorf("no database is configured: set FLOTESTRO_DATABASE_URL_FILE, or %s_FILE for the %s command",
			config.EnvMigrationDatabaseURL, commandMigrate)
	}
	// What kind of database this is, as the installation declares it rather than
	// as the shape of the DSN suggests. An installation on a database somebody
	// else runs is held to the connection such an installation promises.
	databaseMode, err := config.DatabaseModeSetting()
	if err != nil {
		return err
	}
	if err := config.CheckDatabaseDSN(databaseMode, dsn); err != nil {
		return fmt.Errorf("%s=%s: %w", config.EnvDatabaseMode, databaseMode, err)
	}
	if config.DatabaseTrustsSystemRoots(databaseMode, dsn) {
		log.Info("the database certificate is checked against the system root store; " +
			"an installation with its own authority names it with sslrootcert in the DSN")
	}

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	pool, err := database.Open(ctx, dsn, dbPool)
	if err != nil {
		return err
	}
	defer pool.Close()
	// What answered. A standby accepts the connection and refuses every write,
	// and a role without the rights the schema needs fails in the middle of a
	// migration rather than here.
	if err := database.Preflight(ctx, pool, log); err != nil {
		return err
	}
	log.Info("the connection pool is open", "command", string(cmd),
		"max_conns", dbPool.MaxConns, "min_conns", dbPool.MinConns,
		"max_conn_lifetime", dbPool.MaxConnLifetime.String(),
		"max_conn_idle_time", dbPool.MaxConnIdleTime.String(),
		"health_check_period", dbPool.HealthCheckPeriod.String(),
		"connect_timeout", dbPool.ConnectTimeout.String())

	migrateOptions := database.MigrateOptions{
		Role: migration.Role, LockWait: migration.LockWait, Log: log,
	}
	switch cmd {
	case commandMigrate:
		if err := database.Migrate(ctx, pool, migrateOptions); err != nil {
			return err
		}
		report, err := database.CheckSchema(ctx, pool)
		if err != nil {
			return err
		}
		// A migrator that carries fewer migrations than the database already has is
		// an older image pointed at an upgraded database.
		if report.Code() == database.CodeSchemaAhead {
			return schemaRefusal(log, report, "the migration changed nothing")
		}
		log.Info("the schema was brought forward", "level", report.Level, "applied", report.Applied)
		return nil
	case commandSchemaCheck:
		report, err := database.CheckSchema(ctx, pool)
		if err != nil {
			return err
		}
		if !report.Current() {
			return schemaRefusal(log, report, "the schema of the database is not the one this binary expects")
		}
		log.Info("the schema of the database is the one this binary expects",
			"level", report.Level, "applied", report.Applied)
		return nil
	}

	// Serving. Bringing the schema forward at the start is the quick start: one
	// DSN owns the schema and serves the fleet.
	if migration.AutoMigrate {
		log.Info("the schema is brought forward at this start", "migration_mode", "auto",
			"note", "set FLOTESTRO_AUTO_MIGRATE=false and run the migrate command as its own job "+
				"where the serving replicas must not hold the rights to change the schema")
		if err := database.Migrate(ctx, pool, migrateOptions); err != nil {
			return err
		}
	} else {
		log.Info("the schema is not touched at this start", "migration_mode", "none",
			"note", "the migrate command brings it forward")
	}
	report, err := database.CheckSchema(ctx, pool)
	if err != nil {
		return err
	}
	if !report.Current() {
		return schemaRefusal(log, report, "the control plane refuses to start")
	}
	log.Info("the database schema is current", "level", report.Level, "applied", report.Applied)

	// Two replicas must not answer under one gateway identifier; a record
	// nobody renews is taken over, which is an ordinary restart.
	hostname, _ := os.Hostname()
	registration, err := database.ClaimInstance(ctx, pool, database.Claim{
		GatewayID:    cfg.GatewayID,
		InstanceID:   jobs.InstanceID(),
		Hostname:     hostname,
		Version:      buildinfo.Version,
		PoolMaxConns: dbPool.MaxConns,
		Log:          log,
	})
	if err != nil {
		var inUse *database.InstanceInUseError
		if errors.As(err, &inUse) {
			log.Error("the control plane refuses to start: another instance answers under this gateway identifier",
				"code", inUse.Code(), "gateway_id", inUse.GatewayID,
				"holder_instance_id", inUse.Holder.InstanceID, "holder_hostname", inUse.Holder.Hostname,
				"holder_started_at", inUse.Holder.StartedAt.Format(time.RFC3339),
				"hint", "every replica has a FLOTESTRO_GATEWAY_ID of its own and they share one database; "+
					"never scale with a copied identifier")
			return fmt.Errorf("%s: %s", inUse.Code(), inUse.Error())
		}
		return err
	}
	defer func() {
		// An orderly stop gives the identifier back, so the next replica
		// starts at once instead of waiting for the record to age out.
		releaseCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		if err := database.ReleaseInstance(releaseCtx, pool, registration); err != nil {
			log.Warn("the gateway identifier was not released; the next start waits for the record to age out",
				"err", err, "gateway_id", registration.GatewayID)
		}
	}()

	// The cryptographic identity of the installation is checked before anything
	// touches the secret store or the CA.
	legacyKeyPath := *secretsKeyFile
	if legacyKeyPath == "" {
		legacyKeyPath = filepath.Join(cfg.StateDir, "secrets.key")
	}
	keyProvider, err := cryptostate.NewLocalProvider(filepath.Join(cfg.StateDir, cryptostate.KeysDir),
		*secretsKeyCredential)
	if err != nil {
		return fmt.Errorf("the key provider: %w", err)
	}
	cryptoRuntime, err := cryptostate.Open(ctx, cryptostate.Options{
		Storage:       cryptostate.NewPostgres(pool),
		Provider:      keyProvider,
		CADir:         cfg.StateDir,
		LegacyKeyPath: legacyKeyPath,
		RotateTo:      *secretsKeyRotateTo,
		Log:           log,
	})
	if err != nil {
		var fatal *cryptostate.FatalError
		if errors.As(err, &fatal) {
			// The code is what the runbook indexes; the reason names the file or row;
			// the hint is the one line that stops somebody from "fixing" it by
			// generating material.
			log.Error("the control plane refuses to start: the cryptographic state of the installation is not usable",
				"code", fatal.Code, "reason", fatal.Reason, "detail", errorText(fatal.Err),
				"hint", cryptostate.RunbookHint)
			return fmt.Errorf("%s: %s", fatal.Code, fatal.Reason)
		}
		return err
	}
	trust := cryptoRuntime.Trust()
	ca := trust.Active()
	ca.AgentTTL = *agentCertTTL
	// The names of the panel are reserved: a relay certificate carrying one of
	// them would let the relay stand in for the panel towards the agents of its
	// site.
	ca.ReservedNames = splitList(*advertised)
	log.Info("the CA is ready", "subject", ca.Certificate.Subject.CommonName,
		"not_after", ca.Certificate.NotAfter.Format(time.RFC3339),
		"agent_cert_ttl", ca.AgentTTL.String(),
		"trusted_cas", len(trust.Authorities()))

	// Certificates from before the introduction of the CA exchange carry no
	// recorded issuer.
	if len(trust.Authorities()) == 1 {
		filledIn, err := hosts.NewStore(pool).AdoptCertificateIssuer(ctx,
			ca.Certificate.Subject.CommonName, ca.Certificate.SerialNumber.String())
		if err != nil {
			return fmt.Errorf("filling in the issuer of the certificates: %w", err)
		}
		if filledIn > 0 {
			log.Info("the issuer of the agent certificates was filled in", "rows", filledIn)
		}
	}

	// A panel available under localhost alone will serve no fleet: the
	// certificate of the gateway will not match the address the agent connects to
	// the panel under.
	if *advertised == "127.0.0.1" {
		log.Warn("the panel presents itself to the agents as 127.0.0.1, so only a host " +
			"on this machine can enrol; set FLOTESTRO_ADVERTISE to an address the fleet reaches")
	}
	dnsNames, ips := splitAdvertised(*advertised)
	serverCertPEM, serverKeyPEM, err := ca.IssueServerCert(dnsNames, ips)
	if err != nil {
		return err
	}
	serverCert, err := tls.X509KeyPair(serverCertPEM, serverKeyPEM)
	if err != nil {
		return err
	}

	// The trust set changes when the CA is exchanged, so the verification of a
	// client reads it at every handshake instead of holding a copy from the
	// moment of the start.
	var clientVerifier *gateway.ClientVerifier
	clientTrust := func(*tls.ClientHelloInfo) (*tls.Config, error) {
		config := &tls.Config{
			Certificates: []tls.Certificate{serverCert},
			ClientAuth:   tls.RequireAndVerifyClientCert,
			ClientCAs:    trust.Pool(),
			MinVersion:   tls.VersionTLS13,
			// The configuration returned here replaces the one of the server as a
			// whole, so it has to declare HTTP/2 itself.
			NextProtos: []string{"h2"},
		}
		if clientVerifier != nil {
			clientVerifier.Apply(config)
		}
		return config, nil
	}

	hostStore := hosts.NewStore(pool)
	inventoryStore := inventory.NewStore(pool)
	jobStore := jobs.NewStore(pool)
	campaignStore := campaigns.NewStore(pool)
	budgetStore := budgets.NewStore(pool, log)
	tokenStore := enrollment.NewTokenStore(pool)
	relayStore := relays.NewStore(pool)
	authzStore := authz.NewStore(pool)
	recorder := audit.NewRecorder(pool, log)
	clientVerifier = gateway.NewClientVerifier(trust.Pool, hostStore, recorder, log)
	registry := gateway.NewRegistry()

	// The agent gateway: mTLS is mandatory, the identity comes from the
	// certificate alone.
	if err := bootstrapAdmin(ctx, authzStore, cfg.StateDir, log); err != nil {
		return err
	}
	warnAboutBootstrapToken(ctx, authzStore, log)

	// The identity provider is optional: without it only the API tokens work,
	// which is enough for automation but does not meet the requirement of a login
	// with MFA.
	var identityProvider *oidc.Provider
	if *issuerURL != "" {
		identityProvider, err = oidc.Discover(ctx, oidc.Config{
			IssuerURL:    *issuerURL,
			ClientID:     *clientID,
			ClientSecret: *clientSecret,
			RedirectURL:  strings.TrimSuffix(*publicURL, "/") + "/auth/callback",
			GroupsClaim:  *groupsClaim,
			AdminLogout:  *oidcAdminLogout,
		})
		if err != nil {
			return fmt.Errorf("the identity provider: %w", err)
		}
		log.Info("the identity provider is ready", "issuer", identityProvider.Issuer())
	} else {
		log.Warn("no identity provider; the operators can log in with API tokens alone")
	}

	// The directory connector is optional. Its absence means a panel without
	// the identity view rather than a panel that does not work.
	var directory *freeipa.Client
	if *ipaServer != "" && *ipaPrincipal != "" {
		// The keytab is a credential of the directory: readable by anyone on the
		// machine, it hands the connector's identity to anyone.
		if err := config.CheckSecretFile(*ipaKeytab); err != nil {
			return fmt.Errorf("the directory connector: %w", err)
		}
		directory, err = freeipa.New(freeipa.Config{
			ServerURL:  *ipaServer,
			Realm:      *ipaRealm,
			Principal:  *ipaPrincipal,
			KeytabPath: *ipaKeytab,
			CACertPath: *ipaCACert,
			CacheTTL:   30 * time.Second,
		})
		if err != nil {
			return fmt.Errorf("the directory connector: %w", err)
		}
		log.Info("the directory connector is ready", "principal", directory.Principal(), "server", *ipaServer)
	} else {
		log.Info("the directory connector is not configured")
	}

	changeStore := identity.NewStore(pool)
	if directory != nil && *directoryWrite {
		// The executor of directory changes runs next to the scheduler of host
		// jobs: a change in the directory is not an operation on a host.
		executor := identity.NewExecutor(changeStore, directory, authzStore, recorder,
			log, 3*time.Second)
		// A disable ends the provider's sessions too when the installation
		// turned that on; a nil provider must not become a non-nil interface.
		if identityProvider != nil && *oidcAdminLogout {
			executor.WithProviderLogout(identityProvider)
		}
		go executor.Run(ctx)
	}

	// A membership taken away in Keycloak or FreeIPA behind the panel's back
	// reaches a live session through this loop rather than at the next login.
	if identityProvider != nil && *sessionGroupRefresh > 0 {
		go identity.NewSessionGroupRefresher(authzStore, identityProvider, recorder,
			log, *sessionGroupRefresh).Run(ctx)
		log.Info("the group snapshots of the panel sessions are refreshed",
			"interval", sessionGroupRefresh.String())
	}

	// The issuer stands between the services and the certificate authority.
	certIssuer := issuer.FromTrust(trust)

	agentService := gateway.NewAgentService(pool, hostStore, inventoryStore, jobStore, recorder,
		registry, certIssuer, relayStore, log, cfg.GatewayID, cfg.HeartbeatSeconds, cfg.HeartbeatJitter)
	clonePolicy, err := gateway.ParseClonePolicy(*clonePolicyValue)
	if err != nil {
		return fmt.Errorf("FLOTESTRO_CLONE_POLICY: %w", err)
	}
	agentService.SetClonePolicy(clonePolicy)
	log.Info("a copied identity is handled by policy", "clone_policy", string(clonePolicy))
	relayIdentity, err := gateway.ParseRelayIdentityMode(*relayIdentityValue)
	if err != nil {
		return fmt.Errorf("FLOTESTRO_RELAY_IDENTITY: %w", err)
	}
	agentService.SetRelayIdentityMode(relayIdentity)
	log.Info("a relayed session without the host's certificate is handled by mode",
		"relay_identity", string(relayIdentity))
	// A word other than the three is a misconfiguration: an installation
	// that meant to enforce the binding must not start observing it.
	campaignPreview, err := campaigns.ParsePreviewMode(*campaignPreviewValue)
	if err != nil {
		return fmt.Errorf("FLOTESTRO_CAMPAIGN_PREVIEW: %w", err)
	}
	log.Info("a campaign order is held to its preview by mode",
		"campaign_preview", string(campaignPreview))

	// The key that signs the root helper's capabilities lies in the state
	// directory next to the CA key and the secret store key, and nowhere else: a
	// copy of the database must not be enough to mint an authorization for root.
	helperCapabilityMode, err := helpercap.ParseMode(*helperCapabilityModeValue)
	if err != nil {
		return fmt.Errorf("FLOTESTRO_HELPER_CAPABILITY_MODE: %w", err)
	}
	signingKeyPath := *helperSigningKey
	if signingKeyPath == "" {
		signingKeyPath = filepath.Join(cfg.StateDir, "helper-signing.key")
	}
	helperSigner, created, err := helpercap.LoadOrGenerateSigner(signingKeyPath)
	if err != nil {
		return fmt.Errorf("the helper signing key: %w", err)
	}
	if created {
		log.Warn("the helper signing key was generated; the hosts learn it at their next session",
			"path", signingKeyPath, "key_id", helperSigner.KeyID())
	}
	// The fingerprints are what an operator writes into a host's pin file, so
	// that the host enrolls with this panel and with no other.
	log.Info("the helper capability policy of the panel",
		"mode", string(helperCapabilityMode), "key_id", helperSigner.KeyID(),
		"trusted_keys", len(helperSigner.TrustedKeys()),
		"signing_fingerprints", strings.Join(helperSigner.Fingerprints(), ","))
	agentService.SetHelperSigner(helperSigner)
	// The session rows stay open after a crash of the process and inflate
	// every measurement that counts connections from the database.
	go agentService.ReapOrphanSessions(ctx, time.Minute)
	// Expired renewal challenges and the sequences of long-silent relayed
	// sessions are swept hourly.
	go func() {
		ticker := time.NewTicker(time.Hour)
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				if err := agentService.SweepRelayProofs(ctx); err != nil {
					log.Error("the relay proofs were not swept", "err", err)
				}
			}
		}
	}()
	// A host switching between gateways leaves a session on the previous one that
	// still looks alive.
	go gateway.WatchEpochs(ctx, pool, registry, cfg.GatewayID, log)

	// The relay has a service of its own on the same listener: its certificate is
	// a certificate of the fleet, only of a different kind, so it goes through
	// the same mTLS handshake.
	enrollmentService := gateway.NewEnrollmentService(certIssuer, hostStore, relayStore,
		tokenStore, recorder, log)
	enrollmentService.SetHelperSigner(helperSigner)
	enrollmentService.SetAdvertised(splitList(*advertised))
	relayService := gateway.NewRelayService(relayStore, certIssuer, recorder, registry,
		enrollmentService, log)

	gatewayMux := http.NewServeMux()
	// Every message from a host has a ceiling.
	gatewayMux.Handle(agentv1connect.NewAgentServiceHandler(agentService,
		connect.WithReadMaxBytes(8<<20)))
	gatewayMux.Handle(agentv1connect.NewRelayServiceHandler(relayService,
		connect.WithReadMaxBytes(8<<20)))
	gatewayServer := &http.Server{
		Addr:    cfg.GatewayAddr,
		Handler: gateway.WithClientCertificate(gatewayMux),
		TLSConfig: &tls.Config{
			Certificates: []tls.Certificate{serverCert},
			ClientAuth:   tls.RequireAndVerifyClientCert,
			// The trust set is read at every handshake: after an exchange of the CA the
			// new agent certificates have to be accepted without a restart of the
			// panel.
			GetConfigForClient: clientTrust,
			MinVersion:         tls.VersionTLS13,
			NextProtos:         []string{"h2"},
		},
		ReadHeaderTimeout: 15 * time.Second,
		IdleTimeout:       5 * time.Minute,
		MaxHeaderBytes:    64 << 10,
	}

	// Enrollment: TLS without a client certificate, because the host has no
	// identity yet.
	enrollmentMux := http.NewServeMux()
	// The enrollment listener answers strangers: a request is a token and
	// a CSR, and nothing legitimate is larger than a few kilobytes.
	enrollmentMux.Handle(agentv1connect.NewEnrollmentServiceHandler(enrollmentService,
		connect.WithReadMaxBytes(256<<10)))
	enrollmentServer := &http.Server{
		Addr:    cfg.EnrollmentAddr,
		Handler: enrollmentMux,
		TLSConfig: &tls.Config{
			Certificates: []tls.Certificate{serverCert},
			MinVersion:   tls.VersionTLS12,
			NextProtos:   []string{"h2", "http/1.1"},
		},
		ReadHeaderTimeout: 15 * time.Second,
		ReadTimeout:       30 * time.Second,
		IdleTimeout:       time.Minute,
		MaxHeaderBytes:    16 << 10,
	}

	// The event bus wakes the open screens when the state of an operation changes
	// and when a running operation reports progress.
	eventBus := events.NewBus(pool)
	go eventBus.Run(ctx, log)
	agentService.SetEvents(eventBus)
	// The cancel relay: sends the open cancel requests to the hosts this
	// instance holds and settles the ones nobody answered in time.
	go agentService.RunCancelRelay(ctx)
	// The lifecycle orders of the other instances: a decommission or a quarantine
	// that landed on an instance which does not hold the host's session is
	// carried out here, by the instance that does.
	commandOptions.Registry = registry
	commandOptions.Decommissioner = gateway.NewDecommissioner(pool, hostStore, jobStore, recorder, registry, log)
	commandOptions.Decommissioner.SetHelperSigner(helperSigner)
	commandOptions.Audit = recorder
	commandOptions.Events = eventBus
	go gateway.NewCommands(pool, log, commandOptions).RunCommandLoop(ctx)

	// The publisher of the durable trail: the triggers write the events, this
	// hands them on at least once and marks them published.
	trailPublisher := outbox.NewPublisher(pool, outbox.NotifySink{}, log, 2*time.Second)
	go trailPublisher.Run(ctx)
	// The webhook is a consumer of the trail with a cursor of its own: it moves
	// only after the receiver took the batch, so a receiver that is down loses
	// nothing and shows as a growing lag.
	var webhook *outbox.Consumer
	if *webhookURL != "" {
		if *webhookSecret == "" {
			log.Warn("the webhook has no secret; the deliveries are not signed in a way the receiver can verify")
		}
		webhook = outbox.NewConsumer(pool, "webhook", outbox.Webhook{
			URL: *webhookURL, Secret: *webhookSecret, Prefixes: splitList(*webhookEvents),
		}, log, 2*time.Second)
		go webhook.Run(ctx)
	} else if err := outbox.Retire(ctx, pool, "webhook"); err != nil {
		// A consumer this installation no longer runs must not hold the whole
		// trail back: its cursor pinned the retention for ever.
		log.Warn("the webhook consumer was not retired", "err", err)
	}
	go func() {
		wakes, unsubscribe := eventBus.Subscribe(func(event events.Event) bool {
			return event.CampaignID != ""
		})
		defer unsubscribe()
		for {
			select {
			case <-ctx.Done():
				return
			case event := <-wakes:
				if event.Outbox == nil {
					trailPublisher.Wake()
				} else if webhook != nil {
					webhook.Wake()
				}
			}
		}
	}()

	panelServer := adminapi.NewServer(pool, hostStore, inventoryStore, jobStore, campaignStore,
		tokenStore, authzStore, recorder, registry, identityProvider, directory,
		changeStore, log,
		adminapi.Options{
			ProductionEnvironments: productionEnvironments,
			SessionIdle:            *sessionIdle,
			SessionAbsolute:        sessionAbsolute,
			PublicURL:              *publicURL,
			WebRoot:                *webRoot,
			DirectoryWrite:         *directoryWrite,
			StepUpMaxAge:           *stepUpMaxAge,
			StepUpACR:              *stepUpACR,
			StepUpRefuseTokens:     *stepUpTokens == "refuse",
			CampaignPreview:        campaignPreview,
			// The metric of the validity of the CA is to show the signing CA, after an
			// exchange as well, so it reads the whole trust set.
			Metrics: metrics.NewCollector(pool, registry, trust, cfg.GatewayID).
				WithAuthorities(trust.Authorities).WithRelays(relayStore),
			Trust: trust,
		})
	panelServer.SetEvents(eventBus)
	// The installation profile: the addresses the hosts connect to are the
	// advertised ones, because those alone are in the gateway certificate.
	panelServer.SetInstallation(adminapi.Installation{
		AdvertisedAddresses:  splitList(*advertised),
		GatewayAddr:          cfg.GatewayAddr,
		EnrollmentAddr:       cfg.EnrollmentAddr,
		PackageRepositoryURL: *packageRepositoryURL,
	})
	panelServer.SetRelays(relayStore)
	// The buffer history of the relays: the gateway writes a point at every
	// heartbeat, this loop rolls them up, applies the retention and evaluates the
	// built-in rules over the newest reading.
	relayStore.SetRetention(relayRetention)
	go relayStore.Run(ctx, log)
	log.Info("the relay buffer history is running",
		"raw_retention", relayRetention.RawRetention.String(),
		"rollup_retention", relayRetention.RollupRetention.String())

	// The built-in monitoring: the agents send their resource samples down the
	// same stream as the heartbeat, the store keeps them, rolls them up and
	// evaluates the alert rules over them.
	monitoringStore := monitoring.NewStore(pool, log, metricsRetention)
	// FLOTESTRO_METRICS_* above is the initial value of an installation that
	// never set its own. What the installation stored takes over from it here,
	// and again on its own tick while the panel runs. A row that cannot be read
	// or does not validate leaves the environment's values in force - they were
	// validated at start - rather than stopping the panel an operator would
	// have to use to correct it.
	if err := monitoringStore.RefreshSettings(ctx); err != nil {
		log.Error("the stored monitoring settings were not applied; this replica runs on its environment",
			"err", err)
	}
	metricsInForce := monitoringStore.Settings()
	agentService.SetMetrics(monitoringStore)
	panelServer.SetMonitoring(monitoringStore)
	go monitoringStore.Run(ctx)
	log.Info("the built-in monitoring is running",
		"sampling_interval", monitoring.SamplingInterval.String(),
		"raw_retention", metricsInForce.RawRetention.String(),
		"rollup_retention", metricsInForce.RollupRetention.String(),
		"max_lateness", metricsInForce.MaxLateness.String(),
		"raw_query_window", metricsInForce.RawQueryWindow.String(),
		"partitions_ahead_days", metricsInForce.PartitionsAhead,
		"evaluator_lease", metricsRetention.EvaluatorLease.String())

	// The budgets are visible in the panel: a host standing on capacity is to
	// show which budget it waits for rather than stand without a reason.
	panelServer.SetBudgets(budgetStore)

	// The remediation plans: the panel creates them, the runner carries them
	// out step by step.
	remediationStore := remediation.NewStore(pool)
	panelServer.SetRemediation(remediationStore)

	// The vulnerability correlator holds the feed snapshots, the vendor
	// findings and the package lists of the hosts.
	vulnStore := vuln.NewStore(pool)
	packageStore := vuln.NewPackageStore(pool)
	panelServer.SetVulnerabilities(vulnStore, packageStore, vulnerabilities.MaxSnapshotAge)

	// The secret store.
	secretStore := secrets.NewStore(pool, keyProvider)
	cryptoRuntime.SetSecrets(secretStore)
	// Readiness asks the crypto runtime whether this instance is current: one
	// behind the record signs with an authority the installation may have
	// retired, and answers every query while it does.
	panelServer.SetCryptoState(cryptoRuntime)
	panelServer.SetHelperSigner(helperSigner)
	go cryptoRuntime.Maintain(ctx)
	panelServer.SetSecrets(secretStore)
	agentService.SetSecrets(secretStore)
	agentService.SetSecretLeases(secretStore)

	// The notification channels: a second consumer of the durable trail, with a
	// cursor of its own beside the webhook from the environment, so the legacy
	// webhook keeps working as an implicit channel and neither holds the other.
	notificationStore := notify.NewStore(pool, secretStore)
	// The credentials of the channels written by the previous release are moved
	// into the secret store once, here: only this process holds the key that
	// seals a version, so the migration could add the columns but not fill them.
	if moved, err := notificationStore.MigrateSecrets(ctx); err != nil {
		return fmt.Errorf("moving the notification channel credentials into the secret store: %w", err)
	} else if moved > 0 {
		log.Info("the credentials of the notification channels were moved into the secret store", "channels", moved)
	}
	notifier := notify.NewRouter(pool, notificationStore, secretStore, *publicURL, log)
	panelServer.SetNotifications(notificationStore, notifier)
	notifications := outbox.NewConsumer(pool, "notifications", notifier, log, 2*time.Second)
	go notifications.Run(ctx)
	// The queue is what actually sends: the consumer writes a row per channel in
	// the transaction of the event, and the worker of every instance takes the
	// rows that are due.
	notificationWorker := notify.NewWorker(notificationStore, notifier, notifyOptions, log)
	panelServer.SetNotificationQueue(notificationWorker)
	go notificationWorker.Run(ctx)
	go func() {
		wakes, unsubscribe := eventBus.Subscribe(events.ForOutbox())
		defer unsubscribe()
		for {
			select {
			case <-ctx.Done():
				return
			case <-wakes:
				notifications.Wake()
			}
		}
	}()
	// The settings screen shows what this process resolved, with the secrets
	// reduced to "set" or "not set": the values themselves stay in the
	// environment file.
	panelServer.SetSettings(config.Effective{
		Version: buildinfo.Version, Commit: buildinfo.ShortCommit(), BuildDate: buildinfo.Date,
		Protocol:             buildinfo.AgentProtocol,
		GatewayAddr:          cfg.GatewayAddr,
		EnrollmentAddr:       cfg.EnrollmentAddr,
		AdminAddr:            cfg.AdminAddr,
		Advertised:           splitList(*advertised),
		GatewayID:            cfg.GatewayID,
		PublicURL:            *publicURL,
		WebRoot:              *webRoot,
		StateDir:             cfg.StateDir,
		PackageRepositoryURL: *packageRepositoryURL,
		HeartbeatSeconds:     cfg.HeartbeatSeconds,
		HeartbeatJitter:      cfg.HeartbeatJitter,
		StaleAfter:           cfg.StaleAfter,
		AgentCertTTL:         *agentCertTTL,
		Identity: config.EffectiveIdentity{
			IssuerURL: *issuerURL, ClientID: *clientID,
			ClientSecretSet: *clientSecret != "", GroupsClaim: *groupsClaim,
		},
		Directory: config.EffectiveDirectory{
			Configured: directory != nil, ServerURL: *ipaServer, Principal: *ipaPrincipal,
			KeytabPath: *ipaKeytab, CACertPath: *ipaCACert, Realm: *ipaRealm,
			WriteEnabled: directory != nil && *directoryWrite,
		},
		StepUp:                 config.EffectiveStepUp{MaxAge: *stepUpMaxAge, ACR: *stepUpACR, Tokens: *stepUpTokens},
		SessionIdle:            *sessionIdle,
		SessionAbsolute:        sessionAbsolute,
		ProductionEnvironments: productionEnvironments,
		Webhook: config.EffectiveWebhook{
			URL: *webhookURL, SecretSet: *webhookSecret != "", Events: splitList(*webhookEvents),
		},
		Vulnerabilities: config.EffectiveVulnerabilities{
			Enabled:        vulnerabilities.Enabled,
			SyncInterval:   vulnerabilities.SyncInterval,
			MaxSnapshotAge: vulnerabilities.MaxSnapshotAge,
			DebianURL:      vulnerabilities.DebianURL,
			UbuntuURL:      vulnerabilities.UbuntuURL,
			RedHatURL:      vulnerabilities.RedHatURL,
			NVDURL:         vulnerabilities.NVDURL,
			NVDKeySet:      vulnerabilities.NVDKey != "",
			NVDInterval:    vulnerabilities.NVDInterval,
		},
		MetricsRawRetention:    metricsRetention.RawRetention,
		MetricsRollupRetention: metricsRetention.RollupRetention,
		AuditRetention:         *auditRetention,
		SecretsKeyFile:         keyProvider.Dir(),
		DatabasePool:           dbPool,
		Migration:              migration,
	})

	adminServer := &http.Server{
		Addr:              cfg.AdminAddr,
		Handler:           h2c.NewHandler(panelServer.Routes(), &http2.Server{}),
		ReadHeaderTimeout: 15 * time.Second,
		IdleTimeout:       5 * time.Minute,
		MaxHeaderBytes:    64 << 10,
	}

	errCh := make(chan error, 4)
	// A heartbeat that finds the row taken means two processes answer under
	// one identifier; this one stops rather than carrying on.
	go func() {
		if err := database.KeepInstanceAlive(ctx, pool, registration, log); err != nil {
			errCh <- err
		}
	}()
	go serveTLS(gatewayServer, "the agent gateway", log, errCh)
	go serveTLS(enrollmentServer, "enrollment", log, errCh)
	go func() {
		log.Info("the REST API is listening", "addr", adminServer.Addr)
		if err := adminServer.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			errCh <- fmt.Errorf("REST API: %w", err)
		}
	}()

	go markStaleHosts(ctx, pool, cfg.StaleAfter, log)

	// The retention sweep: the ended sessions of the agents go after a month, the
	// trail after the configured retention if there is one, and the expired
	// browser sessions with their abandoned logins alongside.
	sweeper := housekeeping.New(pool, log, housekeeping.Options{
		Audit:     *auditRetention,
		Jobs:      *jobRetention,
		Campaigns: *campaignRetention,
		Outbox:    *outboxRetention,
	}).
		WithAudit(recorder).
		Also("web sessions", authzStore.PurgeExpired).
		// A host whose owner stopped renewing - an instance that died without
		// releasing it - is forgotten by its row on the same clock; the token stays,
		// so the dead instance's writes stay refused.
		Also("campaign previews", func(ctx context.Context) error {
			swept, err := campaignStore.SweepPreviews(ctx, time.Now().Add(-24*time.Hour))
			if swept > 0 {
				log.Info("spent campaign previews were removed", "previews", swept)
			}
			return err
		}).
		Also("session owners", func(ctx context.Context) error {
			swept, err := jobStore.SweepExpiredOwners(ctx)
			if swept > 0 {
				log.Info("expired session owners were forgotten", "hosts", swept)
			}
			return err
		}).
		// A host whose recovery order expired unused comes back to active on
		// the same clock: nobody revoked the order, so nothing else would.
		Also("lapsed recoveries", func(ctx context.Context) error {
			lapsed, err := hostStore.LapseRecoveries(ctx)
			if len(lapsed) > 0 {
				log.Info("hosts came back from a lapsed recovery", "hosts", len(lapsed))
			}
			return err
		})
	go sweeper.Run(ctx)
	if *auditRetention > 0 {
		log.Info("the audit trail has a retention", "retention", auditRetention.String())
	}
	log.Info("the working record has a retention",
		"jobs", sweeper.Options().Jobs.String(),
		"campaigns", sweeper.Options().Campaigns.String(),
		"outbox_events", sweeper.Options().Outbox.String())
	// The status and settings screens read the loops and the switches of
	// this process that the effective configuration does not carry.
	panelServer.SetProcess(adminapi.Process{
		Crypto:              cryptoRuntime,
		Housekeeping:        sweeper,
		DispatchRate:        max(*dispatchRate, 0),
		ClonePolicy:         string(clonePolicy),
		RelayIdentity:       string(relayIdentity),
		SessionGroupRefresh: *sessionGroupRefresh,
		OIDCAdminLogout:     *oidcAdminLogout,
	})

	// The scheduler delivers approved jobs to the hosts connected to this
	// gateway and watches over the leases and the TTLs.
	dispatcher := scheduler.New(jobStore, registry, recorder, directory, log, scheduler.Options{
		GatewayID:     cfg.GatewayID,
		LeaseDuration: 5 * time.Minute,
		DispatchRate:  float64(max(*dispatchRate, 0)),
	})
	if *dispatchRate > 0 {
		log.Info("the dispatch is paced", "envelopes_per_second", *dispatchRate)
	} else {
		log.Warn("the dispatch is not paced: every leased task goes out at once")
	}
	// The leases of the secrets are created at the moment a job is delivered:
	// the short window starts when the host starts working.
	dispatcher.SetSecrets(secretStore)
	// The root helper's capability is minted at the same moment, with the
	// grants of whoever created the task.
	dispatcher.SetHelperCapabilities(scheduler.HelperCapabilities{
		Signer: helperSigner, Mode: helperCapabilityMode,
		Permissions: subjectPermissions{store: authzStore},
	})
	// The same budget store the campaigns lease from: a single job and a
	// campaign target compete for the same tokens.
	dispatcher.SetBudgets(budgetStore)
	go dispatcher.Run(ctx)

	// The budgets answer a question other than the limit of a campaign: not how
	// many hosts are to move in this change, but how many changes the fleet and
	// the site will carry.
	go budgetStore.Run(ctx)

	// The orchestrator carries the campaigns through the canary and the waves,
	// creating the jobs the scheduler delivers.
	orchestrator := campaigns.NewOrchestrator(campaignStore, jobStore, hostStore, recorder,
		budgetStore, log, 5*time.Second)
	orchestrator.Authorizer = authzStore
	log.Info("the campaign orchestrator drives campaigns under a runner lease",
		"runner_id", orchestrator.Runner(), "lease", campaigns.RunnerLeaseTerm.String())
	go orchestrator.Run(ctx)

	// The scheduled campaigns: the loop places the stored orders at their moments
	// through the same door a request takes, under the rights of whoever wrote
	// the schedule; each campaign then waits for its approval like any other.
	go campaigns.NewScheduleLoop(campaignStore, panelServer, log, 5*time.Second).Run(ctx)

	// The runner carries the remediation plans out step by step: every step is an
	// ordinary job of a module, and the next one starts only once the previous
	// one has succeeded.
	go remediation.NewRunner(remediationStore, jobStore, hostStore, recorder,
		log, 5*time.Second).Run(ctx)

	// The desired-state policies: judged from the inventory at their own
	// intervals, never by reading a host; a drift becomes a remediation campaign
	// where the policy's mode asks for one.
	policyStore := policy.NewStore(pool)
	go policy.NewLoop(policyStore, policy.NewEvaluator(policyStore, hostStore, inventoryStore,
		selector.NewStore(pool), packageStore, managedfiles.NewStore(pool), campaignStore,
		recorder, authzStore, log), log, time.Minute).Run(ctx)

	// The vulnerability correlator: the trackers of the distribution vendors
	// settle whether the installed version is vulnerable.
	if vulnerabilities.Enabled {
		var sources []vuln.Source
		if vulnerabilities.DebianURL != "" {
			sources = append(sources, debiansource.New(vulnerabilities.DebianURL, 10*time.Minute))
		}
		if vulnerabilities.UbuntuURL != "" {
			sources = append(sources, ubuntusource.New(vulnerabilities.UbuntuURL, 10*time.Minute))
		}
		if vulnerabilities.RedHatURL != "" {
			sources = append(sources, redhatsource.New(vulnerabilities.RedHatURL,
				vulnerabilities.RedHatCache, 30*time.Minute))
		}
		if len(sources) == 0 {
			log.Warn("the vulnerability correlator is enabled, but there is no source at all")
		} else {
			names := make([]string, 0, len(sources))
			for _, source := range sources {
				names = append(names, source.Name())
			}
			log.Info("the vulnerability correlator has started", "sources", names,
				"interval", vulnerabilities.SyncInterval, "max_age", vulnerabilities.MaxSnapshotAge)
			vulnScheduler := vuln.NewScheduler(vulnStore, packageStore, hostStore,
				inventoryStore, jobStore, sources, vuln.Settings{
					Interval:       vulnerabilities.SyncInterval,
					MaxSnapshotAge: vulnerabilities.MaxSnapshotAge,
					ShrinkShare:    vulnShrinkShare,
				}, log)
			// A host that has just sent its package list or the findings of its
			// repositories gets a recomputation at once.
			agentService.SetAssessmentRefresh(vulnScheduler.Refresh)
			go vulnScheduler.Run(ctx)
		}
		// The enrichment runs in a separate, rarer cycle and by a separate path: the
		// descriptions from NVD do not change a single answer about hosts, so their
		// absence must not hold the assessment back.
		if vulnerabilities.NVDURL != "" {
			log.Info("the enrichment of the vulnerability descriptions has started",
				"source", nvdsource.Provider, "interval", vulnerabilities.NVDInterval,
				"api_key", vulnerabilities.NVDKey != "")
			go vuln.NewEnricher(vulnStore,
				nvdsource.New(vulnerabilities.NVDURL, vulnerabilities.NVDKey, 5*time.Minute),
				vulnerabilities.NVDInterval, log).Run(ctx)
		}
	}

	select {
	case err := <-errCh:
		return err
	case <-ctx.Done():
		log.Info("shutting the control plane down")
	}

	shutdownCtx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	_ = gatewayServer.Shutdown(shutdownCtx)
	_ = enrollmentServer.Shutdown(shutdownCtx)
	_ = adminServer.Shutdown(shutdownCtx)
	return nil
}

func serveTLS(server *http.Server, name string, log *slog.Logger, errCh chan<- error) {
	log.Info(name+" is listening", "addr", server.Addr)
	if err := server.ListenAndServeTLS("", ""); err != nil && !errors.Is(err, http.ErrServerClosed) {
		errCh <- fmt.Errorf("%s: %w", name, err)
	}
}

// markStaleHosts marks the hosts that have stopped speaking.
func markStaleHosts(ctx context.Context, pool *pgxpool.Pool, staleAfter time.Duration, log *slog.Logger) {
	ticker := time.NewTicker(staleCheckInterval)
	defer ticker.Stop()
	const query = `
		update hosts set connection_state = 'stale', updated_at = now()
		where connection_state = 'online'
		  and (last_seen_at is null or last_seen_at < now() - $1::interval)`
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			interval := fmt.Sprintf("%d seconds", int(staleAfter.Seconds()))
			if _, err := pool.Exec(ctx, query, interval); err != nil && ctx.Err() == nil {
				log.Error("the hosts were not marked as stale", "err", err)
			}
		}
	}
}

// bootstrapAdmin creates the first identity when the system is empty.
func bootstrapAdmin(ctx context.Context, store *authz.Store, stateDir string, log *slog.Logger) error {
	count, err := store.CountPrincipals(ctx)
	if err != nil {
		return fmt.Errorf("checking the identities: %w", err)
	}
	if count > 0 {
		return nil
	}

	tx, err := store.Pool().Begin(ctx)
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback(ctx) }()

	principalID, err := store.EnsurePrincipal(ctx, tx, authz.BootstrapSubject, "Bootstrap administrator", "user")
	if err != nil {
		return err
	}
	if err := store.GrantRole(ctx, tx, principalID, authz.RolePlatformAdmin,
		authz.GlobalScope, nil, "system"); err != nil {
		return err
	}
	// The token lives a month: long enough to create the proper identities,
	// short enough that a forgotten one does not stay a key to the fleet.
	token, err := store.IssueToken(ctx, tx, principalID, "the bootstrap token",
		bootstrapTokenTTL, "system")
	if err != nil {
		return err
	}
	if err := tx.Commit(ctx); err != nil {
		return err
	}

	// The token also lands in a file in the state directory so that it can be
	// read after the log has been rotated.
	tokenPath := filepath.Join(stateDir, "bootstrap-token")
	if err := os.WriteFile(tokenPath, []byte(token.Value+"\n"), 0o600); err != nil {
		log.Error("the bootstrap token was not written", "path", tokenPath, "err", err)
	}

	log.Warn("a bootstrap identity was created; delete the token file once the proper accounts exist",
		"subject", authz.BootstrapSubject, "token_file", tokenPath)
	return nil
}

// bootstrapTokenTTL is the lifetime of the first token of an installation.
const bootstrapTokenTTL = 30 * 24 * time.Hour

// warnAboutBootstrapToken says at every start that the bootstrap token is
// still usable although the installation has other administrators.
func warnAboutBootstrapToken(ctx context.Context, store *authz.Store, log *slog.Logger) {
	live, others, err := store.BootstrapTokenState(ctx)
	if err != nil {
		log.Error("the state of the bootstrap token was not checked", "err", err)
		return
	}
	if live && others {
		log.Warn("the bootstrap token is still valid although other administrators exist; " +
			"revoke it in the access screen or with DELETE /api/v1/principals/{id}/tokens/{token}")
	}
}

// errorText renders an optional error for a log line.
func errorText(err error) string {
	if err == nil {
		return ""
	}
	return err.Error()
}

// schemaRefusal reports a schema that is not the one this binary expects and
// turns it into the exit of the process.
func schemaRefusal(log *slog.Logger, report database.SchemaReport, headline string) error {
	hint := "run the migrate command as its own job, with the credentials of the migrator, " +
		"before the serving replicas start"
	if report.Code() == database.CodeSchemaAhead {
		hint = "deploy the version that migrated this database, or restore the backup of the database " +
			"and of the state directory taken before the upgrade; a schema does not come back by swapping the image"
	}
	log.Error(headline, "code", report.Code(), "reason", report.Summary(),
		"level", report.Level, "expected", report.Expected,
		"pending", len(report.Pending), "ahead", len(report.Ahead), "hint", hint)
	return fmt.Errorf("%s: %s", report.Code(), report.Summary())
}

func splitList(value string) []string {
	var items []string
	for _, part := range strings.Split(value, ",") {
		if trimmed := strings.TrimSpace(part); trimmed != "" {
			items = append(items, trimmed)
		}
	}
	return items
}

func splitAdvertised(value string) ([]string, []net.IP) {
	var (
		dnsNames []string
		ips      = []net.IP{net.ParseIP("127.0.0.1")}
	)
	for _, part := range strings.Split(value, ",") {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}
		if ip := net.ParseIP(part); ip != nil {
			ips = append(ips, ip)
			continue
		}
		dnsNames = append(dnsNames, part)
	}
	dnsNames = append(dnsNames, "localhost")
	return dnsNames, ips
}

func defaultGatewayID() string {
	name, err := os.Hostname()
	if err != nil || name == "" {
		return "gateway-1"
	}
	return name
}

// subjectPermissions reads the permissions of a task's creator for the grants
// of a helper capability.
type subjectPermissions struct {
	store *authz.Store
}

func (p subjectPermissions) PermissionsOfSubject(ctx context.Context, subject string) ([]string, error) {
	principal, err := p.store.PrincipalBySubject(ctx, subject)
	if errors.Is(err, authz.ErrNotFound) || errors.Is(err, authz.ErrUnauthenticated) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	return principal.Permissions(), nil
}
