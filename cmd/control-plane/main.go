// Command control-plane runs the API, the agent gateway and the enrollment
// endpoint.
package main

import (
	"connectrpc.com/connect"
	"context"
	"crypto/tls"
	"errors"
	"flag"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
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
	"github.com/ultherego/flotestro/internal/database"
	"github.com/ultherego/flotestro/internal/enrollment"
	"github.com/ultherego/flotestro/internal/events"
	managedfiles "github.com/ultherego/flotestro/internal/files"
	"github.com/ultherego/flotestro/internal/freeipa"
	"github.com/ultherego/flotestro/internal/gateway"
	"github.com/ultherego/flotestro/internal/genproto/flotestro/agent/v1/agentv1connect"
	"github.com/ultherego/flotestro/internal/hosts"
	"github.com/ultherego/flotestro/internal/housekeeping"
	"github.com/ultherego/flotestro/internal/identity"
	"github.com/ultherego/flotestro/internal/inventory"
	"github.com/ultherego/flotestro/internal/issuer"
	"github.com/ultherego/flotestro/internal/jobs"
	"github.com/ultherego/flotestro/internal/metrics"
	"github.com/ultherego/flotestro/internal/monitoring"
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

func main() {
	if err := run(); err != nil {
		slog.Error("the control plane ended with an error", "err", err)
		os.Exit(1)
	}
}

func run() error {
	cfg := config.ControlPlane{}
	flag.StringVar(&cfg.DatabaseURL, "database-url",
		config.Env("FLOTESTRO_DATABASE_URL", ""), "the PostgreSQL DSN")
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
	clientSecret := flag.String("oidc-client-secret",
		config.Env("FLOTESTRO_OIDC_CLIENT_SECRET", ""), "the OIDC client secret")
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
	// The key of the store lies in the state directory next to the CA key:
	// that is the only place the service is allowed to write to, and the only
	// one whose permissions are narrow enough to keep cryptographic material
	// in.
	secretsKeyFile := flag.String("secrets-key-file",
		config.Env("FLOTESTRO_SECRETS_KEY_FILE", ""),
		"the file with the key of the secret store; without a copy of it the secrets cannot be recovered")
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
	// FLOTESTRO_IPA_URL enabled nothing while the panel said nothing about
	// the reason.
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
	// The built-in monitoring keeps the raw samples for two days and the
	// quarter-hour rollups for a month. Longer keeps more history on the
	// charts at the cost of the database; shorter is for a large fleet.
	metricsRetention := monitoring.Options{}
	flag.DurationVar(&metricsRetention.RawRetention, "metrics-retention-raw",
		config.EnvDuration("FLOTESTRO_METRICS_RETENTION_RAW", monitoring.DefaultRawRetention),
		"how long the raw resource samples of the hosts are kept")
	flag.DurationVar(&metricsRetention.RollupRetention, "metrics-retention-rollup",
		config.EnvDuration("FLOTESTRO_METRICS_RETENTION_ROLLUP", monitoring.DefaultRollupRetention),
		"how long the quarter-hour rollups of the resource samples are kept")
	// The trail is evidence and is kept forever unless the installation
	// decides otherwise; the ended agent sessions are swept after a month
	// on their own, because nothing reads an older one.
	auditRetention := flag.Duration("audit-retention",
		config.EnvDuration("FLOTESTRO_AUDIT_RETENTION", 0),
		"how long the audit trail is kept; zero keeps it forever")
	// The dispatch rate of the document: a queue of thousands after an
	// outage drains at a pace the fleet and the panel carry, rather than
	// in one wave. Zero turns the pacing off.
	dispatchRate := flag.Int("dispatch-rate",
		config.EnvInt("FLOTESTRO_DISPATCH_RATE", 100),
		"how many task envelopes this gateway sends per second; zero sends every leased task at once")
	// The reaction to a copied identity. Read strictly: a word other than
	// the two is a misconfiguration, not the default.
	clonePolicyValue := flag.String("clone-policy",
		config.Env("FLOTESTRO_CLONE_POLICY", ""),
		"what to do with the same identity alive on two boots: report or quarantine (the default)")
	stepUpTokens := flag.String("stepup-tokens",
		config.Env("FLOTESTRO_STEPUP_TOKENS", "allow"),
		"whether an API token may carry out the operations of the greatest impact: allow or refuse")
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
		config.Env("FLOTESTRO_VULN_DEBIAN_URL", debiansource.DefaultURL),
		"the dump of the Debian security tracker (https:// or file://); empty disables this source")
	flag.StringVar(&vulnerabilities.UbuntuURL, "vulnerability-ubuntu-url",
		config.Env("FLOTESTRO_VULN_UBUNTU_URL", ubuntusource.DefaultURL),
		"the directory with the OVAL data of Canonical (https:// or file://); empty disables this source")
	flag.StringVar(&vulnerabilities.RedHatURL, "vulnerability-redhat-url",
		config.Env("FLOTESTRO_VULN_REDHAT_URL", redhatsource.DefaultURL),
		"the directory with the CSAF/VEX data of Red Hat (https:// or file://); empty disables this source")
	flag.StringVar(&vulnerabilities.RedHatCache, "vulnerability-redhat-cache",
		config.Env("FLOTESTRO_VULN_REDHAT_CACHE", redhatsource.DefaultDirectory),
		"the directory for the Red Hat findings that were read")
	flag.StringVar(&vulnerabilities.NVDURL, "vulnerability-nvd-url",
		config.Env("FLOTESTRO_VULN_NVD_URL", nvdsource.DefaultURL),
		"the API of the NVD database for enriching the descriptions (https:// or file://); empty disables it")
	flag.StringVar(&vulnerabilities.NVDKey, "vulnerability-nvd-key",
		config.Env("FLOTESTRO_VULN_NVD_KEY", ""),
		"the API key for NVD; without it the first read takes around twenty minutes")
	flag.DurationVar(&vulnerabilities.NVDInterval, "vulnerability-nvd-interval",
		config.EnvDuration("FLOTESTRO_VULN_NVD_INTERVAL", 6*time.Hour),
		"how often the panel asks NVD about changes to the descriptions")
	webhookURL := flag.String("webhook-url",
		config.Env("FLOTESTRO_WEBHOOK_URL", ""),
		"the address the events of the durable trail are posted to; empty disables the webhook")
	webhookSecret := flag.String("webhook-secret",
		config.Env("FLOTESTRO_WEBHOOK_SECRET", ""),
		"the secret the webhook deliveries are signed with (HMAC-SHA256)")
	webhookEvents := flag.String("webhook-events",
		config.Env("FLOTESTRO_WEBHOOK_EVENTS", ""),
		"the prefixes of the event types to deliver, comma separated; empty means every event")
	productionList := flag.String("production-environments",
		config.Env("FLOTESTRO_PRODUCTION_ENVIRONMENTS", "prod,production"),
		"the environments where a change has to be approved by a second person")
	flag.Parse()

	// An operation without an explicit decision on what a cancel, a retry
	// or a rollback means is a reason not to start: the panel would draw a
	// promise the host cannot keep.
	if err := opspec.ValidateContracts(); err != nil {
		return err
	}

	productionEnvironments := splitList(*productionList)
	if *stepUpTokens != "allow" && *stepUpTokens != "refuse" {
		return fmt.Errorf("FLOTESTRO_STEPUP_TOKENS must be allow or refuse, not %q", *stepUpTokens)
	}
	// A zero would fall back to the built-in window in silence, and a
	// window past the absolute limit never applies; neither is a setting
	// anybody meant.
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
	if err := cfg.Validate(); err != nil {
		return err
	}

	log := slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelInfo}))
	slog.SetDefault(log)

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	pool, err := database.Open(ctx, cfg.DatabaseURL)
	if err != nil {
		return err
	}
	defer pool.Close()

	if err := database.Migrate(ctx, pool); err != nil {
		return err
	}
	log.Info("the database schema is current")

	trust, err := pki.EnsureTrust(cfg.StateDir)
	if err != nil {
		return err
	}
	ca := trust.Active()
	ca.AgentTTL = *agentCertTTL
	// The names of the panel are reserved: a relay certificate carrying one
	// of them would let the relay stand in for the panel towards the
	// agents of its site.
	ca.ReservedNames = splitList(*advertised)
	log.Info("the CA is ready", "subject", ca.Certificate.Subject.CommonName,
		"not_after", ca.Certificate.NotAfter.Format(time.RFC3339),
		"agent_cert_ttl", ca.AgentTTL.String(),
		"trusted_cas", len(trust.Authorities()))

	// Certificates from before the introduction of the CA exchange carry no
	// recorded issuer. We fill it in only when there is exactly one CA: with
	// more of them the issuer cannot be established other than by guessing.
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
	// certificate of the gateway will not match the address the agent
	// connects to the panel under. Silence here costs an installation where
	// everything looks started and not a single host registers.
	if *advertised == "127.0.0.1" {
		log.Warn("the panel presents itself to the agents as 127.0.0.1; " +
			"set FLOTESTRO_ADVERTISE to an address visible to the hosts of the fleet")
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

	// The trust set changes when the CA is exchanged, so the verification of
	// a client reads it at every handshake instead of holding a copy from the
	// moment of the start.
	// The verifier takes the place of the built-in check: it verifies the
	// chain the same way, and it also names the host behind an expired
	// certificate on the host's row, which the built-in check cannot do.
	// It is built once the stores exist and read at every handshake.
	var clientVerifier *gateway.ClientVerifier
	clientTrust := func(*tls.ClientHelloInfo) (*tls.Config, error) {
		config := &tls.Config{
			Certificates: []tls.Certificate{serverCert},
			ClientAuth:   tls.RequireAndVerifyClientCert,
			ClientCAs:    trust.Pool(),
			MinVersion:   tls.VersionTLS13,
			// The configuration returned here replaces the one of the server
			// as a whole, so it has to declare HTTP/2 itself. Without that
			// the negotiation ends at HTTP/1.1 and a bidirectional stream has
			// no way of working.
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
	// which is enough for automation but does not meet the requirement of a
	// login with MFA.
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
		// The keytab is a credential of the directory: readable by anyone on
		// the machine, it hands the connector's identity to anyone.
		if err := checkKeytabPermissions(*ipaKeytab); err != nil {
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
	// reaches a live session through this loop rather than at the next
	// login. Without a provider there is nobody to ask, and the token-only
	// deployment stays as it is.
	if identityProvider != nil && *sessionGroupRefresh > 0 {
		go identity.NewSessionGroupRefresher(authzStore, identityProvider, recorder,
			log, *sessionGroupRefresh).Run(ctx)
		log.Info("the group snapshots of the panel sessions are refreshed",
			"interval", sessionGroupRefresh.String())
	}

	// The issuer stands between the services and the certificate authority.
	// Today the CA key lies in a file of the panel; moving it into an HSM is
	// to change this one line alone rather than the protocol of the agent.
	certIssuer := issuer.FromTrust(trust)

	agentService := gateway.NewAgentService(pool, hostStore, inventoryStore, jobStore, recorder,
		registry, certIssuer, relayStore, log, cfg.GatewayID, cfg.HeartbeatSeconds, cfg.HeartbeatJitter)
	clonePolicy, err := gateway.ParseClonePolicy(*clonePolicyValue)
	if err != nil {
		return fmt.Errorf("FLOTESTRO_CLONE_POLICY: %w", err)
	}
	agentService.SetClonePolicy(clonePolicy)
	log.Info("a copied identity is handled by policy", "clone_policy", string(clonePolicy))
	// The session rows stay open after a crash of the process and inflate
	// every measurement that counts connections from the database.
	go agentService.ReapOrphanSessions(ctx, time.Minute)
	// A host switching between gateways leaves a session on the previous one
	// that still looks alive. Without this listener both gateways would
	// consider themselves the right one and the same job would go out twice.
	go gateway.WatchEpochs(ctx, pool, registry, cfg.GatewayID, log)

	// The relay has a service of its own on the same listener: its certificate
	// is a certificate of the fleet, only of a different kind, so it goes
	// through the same mTLS handshake. A separate RPC makes sure the
	// operations of a host stay out of its reach.
	// Enrollment is one service for both paths: the direct one and the one
	// through a relay. A second instance would mean two sets of the same rules
	// that drift apart silently over time.
	enrollmentService := gateway.NewEnrollmentService(certIssuer, hostStore, relayStore,
		tokenStore, recorder, log)
	relayService := gateway.NewRelayService(relayStore, certIssuer, recorder, registry,
		enrollmentService, log)

	gatewayMux := http.NewServeMux()
	// Every message from a host has a ceiling. An inventory of a large host
	// fits in a few megabytes; anything beyond that is not an inventory,
	// whatever the certificate says.
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
			// The trust set is read at every handshake: after an exchange of
			// the CA the new agent certificates have to be accepted without a
			// restart of the panel.
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

	// The event bus wakes the open screens when the state of an operation
	// changes and when a running operation reports progress. Without it the
	// panel works as before - the progress is visible after refreshing the
	// page.
	eventBus := events.NewBus(pool)
	go eventBus.Run(ctx, log)
	agentService.SetEvents(eventBus)

	// The publisher of the durable trail: the triggers write the events,
	// this hands them on at least once and marks them published. The
	// campaign notifications wake it, so a screen sees a state change with
	// the delay of one round trip rather than of the polling interval.
	trailPublisher := outbox.NewPublisher(pool, outbox.NotifySink{}, log, 2*time.Second)
	go trailPublisher.Run(ctx)
	// The webhook is a consumer of the trail with a cursor of its own: it
	// moves only after the receiver took the batch, so a receiver that is
	// down loses nothing and shows as a growing lag.
	var webhook *outbox.Consumer
	if *webhookURL != "" {
		if *webhookSecret == "" {
			log.Warn("the webhook has no secret; the deliveries are not signed in a way the receiver can verify")
		}
		webhook = outbox.NewConsumer(pool, "webhook", outbox.Webhook{
			URL: *webhookURL, Secret: *webhookSecret, Prefixes: splitList(*webhookEvents),
		}, log, 2*time.Second)
		go webhook.Run(ctx)
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
			// The metric of the validity of the CA is to show the signing CA,
			// after an exchange as well, so it reads the whole trust set.
			// The relay buffers come from the heartbeats the registry keeps in
			// memory; without the source the collector says nothing about
			// them rather than reporting empty buffers.
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

	// The built-in monitoring: the agents send their resource samples down
	// the same stream as the heartbeat, the store keeps them, rolls them up
	// and evaluates the alert rules over them. Nothing outside the panel is
	// asked for a chart or an alert.
	monitoringStore := monitoring.NewStore(pool, log, metricsRetention)
	agentService.SetMetrics(monitoringStore)
	panelServer.SetMonitoring(monitoringStore)
	go monitoringStore.Run(ctx)
	log.Info("the built-in monitoring is running",
		"sampling_interval", monitoring.SamplingInterval.String(),
		"raw_retention", metricsRetention.RawRetention.String(),
		"rollup_retention", metricsRetention.RollupRetention.String())

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

	// The secret store. The key lies in a file outside the database: a copy of
	// the database without it is not enough to read anything.
	keyPath := *secretsKeyFile
	if keyPath == "" {
		keyPath = filepath.Join(cfg.StateDir, "secrets.key")
	}
	cipher, created, err := secrets.OpenCipher(keyPath)
	if err != nil {
		return fmt.Errorf("the secret store: %w", err)
	}
	if created {
		log.Warn("the key of the secret store was generated; without a copy of "+
			"this file the secrets cannot be recovered", "path", keyPath)
	}
	secretStore := secrets.NewStore(pool, cipher)
	panelServer.SetSecrets(secretStore)
	agentService.SetSecrets(secretStore)
	agentService.SetSecretLeases(secretStore)
	// The settings screen shows what this process resolved, with the
	// secrets reduced to "set" or "not set": the values themselves stay in
	// the environment file.
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
		SecretsKeyFile:         keyPath,
	})

	adminServer := &http.Server{
		Addr:              cfg.AdminAddr,
		Handler:           h2c.NewHandler(panelServer.Routes(), &http2.Server{}),
		ReadHeaderTimeout: 15 * time.Second,
		IdleTimeout:       5 * time.Minute,
		MaxHeaderBytes:    64 << 10,
	}

	errCh := make(chan error, 3)
	go serveTLS(gatewayServer, "the agent gateway", log, errCh)
	go serveTLS(enrollmentServer, "enrollment", log, errCh)
	go func() {
		log.Info("the REST API is listening", "addr", adminServer.Addr)
		if err := adminServer.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			errCh <- fmt.Errorf("REST API: %w", err)
		}
	}()

	go markStaleHosts(ctx, pool, cfg.StaleAfter, log)

	// The retention sweep: the ended sessions of the agents go after a
	// month, the trail after the configured retention if there is one, and
	// the expired browser sessions with their abandoned logins alongside.
	// A role binding past its validity is noted on the trail by the same
	// sweep; it stopped granting anything the moment it expired.
	go housekeeping.New(pool, log, housekeeping.Options{Audit: *auditRetention}).
		WithAudit(recorder).
		Also("web sessions", authzStore.PurgeExpired).
		// A host whose recovery order expired unused comes back to active on
		// the same clock: nobody revoked the order, so nothing else would.
		Also("lapsed recoveries", func(ctx context.Context) error {
			lapsed, err := hostStore.LapseRecoveries(ctx)
			if len(lapsed) > 0 {
				log.Info("hosts came back from a lapsed recovery", "hosts", len(lapsed))
			}
			return err
		}).Run(ctx)
	if *auditRetention > 0 {
		log.Info("the audit trail has a retention", "retention", auditRetention.String())
	}

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
	// The same budget store the campaigns lease from: a single job and a
	// campaign target compete for the same tokens.
	dispatcher.SetBudgets(budgetStore)
	go dispatcher.Run(ctx)

	// The budgets answer a question other than the limit of a campaign: not
	// how many hosts are to move in this change, but how many changes the
	// fleet and the site will carry.
	go budgetStore.Run(ctx)

	// The orchestrator carries the campaigns through the canary and the
	// waves, creating the jobs the scheduler delivers.
	orchestrator := campaigns.NewOrchestrator(campaignStore, jobStore, hostStore, recorder,
		budgetStore, log, 5*time.Second)
	orchestrator.Authorizer = authzStore
	go orchestrator.Run(ctx)

	// The scheduled campaigns: the loop places the stored orders at their
	// moments through the same door a request takes, under the rights of
	// whoever wrote the schedule; each campaign then waits for its
	// approval like any other.
	go campaigns.NewScheduleLoop(campaignStore, panelServer, log, 5*time.Second).Run(ctx)

	// The runner carries the remediation plans out step by step: every step is
	// an ordinary job of a module, and the next one starts only once the
	// previous one has succeeded.
	go remediation.NewRunner(remediationStore, jobStore, hostStore, recorder,
		log, 5*time.Second).Run(ctx)

	// The desired-state policies: judged from the inventory at their own
	// intervals, never by reading a host; a drift becomes a remediation
	// campaign where the policy's mode asks for one.
	policyStore := policy.NewStore(pool)
	go policy.NewLoop(policyStore, policy.NewEvaluator(policyStore, hostStore, inventoryStore,
		selector.NewStore(pool), packageStore, managedfiles.NewStore(pool), campaignStore,
		recorder, authzStore, log), log, time.Minute).Run(ctx)

	// The vulnerability correlator: the trackers of the distribution vendors
	// settle whether the installed version is vulnerable. The panel guesses
	// nothing - a host without a feed or without a package list gets an
	// undetermined state with a reason rather than zero findings.
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
				}, log)
			// A host that has just sent its package list or the findings of
			// its repositories gets a recomputation at once. Otherwise it
			// would show up for half an hour as a host the panel knows
			// nothing about - although it has just answered it.
			agentService.SetAssessmentRefresh(vulnScheduler.Refresh)
			go vulnScheduler.Run(ctx)
		}
		// The enrichment runs in a separate, rarer cycle and by a separate
		// path: the descriptions from NVD do not change a single answer about
		// hosts, so their absence must not hold the assessment back.
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

// markStaleHosts marks the hosts that have stopped speaking. A session can
// disappear without the stream being closed, so the online state must not rest
// on it alone.
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

// bootstrapAdmin creates the first identity when the system is empty. Without
// it no operation can be carried out, because every endpoint requires
// permissions. The token is shown once, in the log, and cannot be read later.
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
	// read after the log has been rotated. The file should be deleted once the
	// proper identities have been created - as long as it exists it is a
	// secret lying on disk.
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
// still usable although the installation has other administrators. The
// token was meant for the first hour; once there is somebody to revoke it,
// it should be revoked.
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

// checkKeytabPermissions refuses a keytab anyone on the machine can read.
// The owner has to be root or the account the service runs as, and the
// mode must not grant reading to the group or to others.
func checkKeytabPermissions(path string) error {
	info, err := os.Stat(path)
	if err != nil {
		return fmt.Errorf("keytab %s: %w", path, err)
	}
	if info.Mode().Perm()&0o044 != 0 {
		return fmt.Errorf("keytab %s is readable by the group or by others (mode %04o); "+
			"chmod 600 it", path, info.Mode().Perm())
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok {
		return nil
	}
	if owner := int(stat.Uid); owner != 0 && owner != os.Geteuid() {
		return fmt.Errorf("keytab %s belongs to uid %d rather than to root or to the service user",
			path, owner)
	}
	return nil
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
