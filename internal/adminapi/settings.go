package adminapi

import (
	"net/http"
	"time"

	"github.com/ultherego/flotestro/internal/audit"
	"github.com/ultherego/flotestro/internal/authz"
	"github.com/ultherego/flotestro/internal/config"
	"github.com/ultherego/flotestro/internal/housekeeping"
)

// The settings screen: what this panel was started with, read-only.

// settingsSource is where the values are set. The screen names it, so
// whoever wants a change knows where to make it.
const settingsSource = "/etc/flotestro/control-plane.env"

// maskedSecret stands in for every secret. The screen never shows one,
// whoever asks; it shows whether one is set.
const maskedSecret = "********"

// SetSettings hands the resolved configuration to the screen.
func (s *Server) SetSettings(effective config.Effective) {
	s.settings = &effective
}

// settingsFact is one row of a fact grid. The value is a string, a number,
// a boolean or a list; a secret is masked and says whether it is set.
type settingsFact struct {
	Key   string `json:"key"`
	Value any    `json:"value"`
	// Secret marks a masked value; Configured says whether one is set.
	Secret     bool  `json:"secret,omitempty"`
	Configured *bool `json:"configured,omitempty"`
}

// settingsArea groups the facts of one concern.
type settingsArea struct {
	Key   string         `json:"key"`
	Title string         `json:"title"`
	Facts []settingsFact `json:"facts"`
}

func fact(key string, value any) settingsFact {
	return settingsFact{Key: key, Value: value}
}

func secretFact(key string, set bool) settingsFact {
	value := ""
	if set {
		value = maskedSecret
	}
	configured := set
	return settingsFact{Key: key, Value: value, Secret: true, Configured: &configured}
}

// switchable renders a duration whose zero is a switch turned off, so
// the screen says "off" rather than leaving the row empty as if unset.
func switchable(value time.Duration) string {
	if value <= 0 {
		return "off"
	}
	return value.String()
}

func durationFact(key string, value time.Duration) settingsFact {
	if value <= 0 {
		return fact(key, "")
	}
	return fact(key, value.String())
}

// handleSettings returns the effective configuration with the secrets masked.
// The permission is settings.
func (s *Server) handleSettings(w http.ResponseWriter, r *http.Request) {
	principal := authz.FromContext(r.Context())
	if !principal.Authenticated() || !principal.Can(authz.PermSettingsRead, authz.GlobalScope) {
		if _, ok := s.authorize(w, r, authz.PermPrincipalManage, authz.GlobalScope, "settings", ""); !ok {
			return
		}
	}
	if s.settings == nil {
		problem(w, http.StatusNotFound, "settings_unavailable",
			"this panel was started without the settings screen")
		return
	}
	effective := *s.settings

	// The migration level and the feed ages are read now rather than at
	// start: both move while the panel runs.
	migration := ""
	if err := s.pool.QueryRow(r.Context(),
		`select coalesce(max(version), '') from schema_migrations`).Scan(&migration); err != nil {
		s.fail(w, err)
		return
	}
	feedAges := map[string]any{}
	if s.vulnerabilities != nil {
		snapshots, err := s.vulnerabilities.Snapshots(r.Context())
		if err != nil {
			s.fail(w, err)
			return
		}
		for _, snapshot := range snapshots {
			checked := snapshot.FetchedAt
			if snapshot.CheckedAt != nil && snapshot.CheckedAt.After(checked) {
				checked = *snapshot.CheckedAt
			}
			feedAges[snapshot.Provider] = time.Since(checked).Round(time.Second).String()
		}
	}
	feedAge := func(provider, url string) settingsFact {
		if url == "" {
			return fact(provider+"_snapshot_age", "")
		}
		if age, ok := feedAges[provider]; ok {
			return fact(provider+"_snapshot_age", age)
		}
		return fact(provider+"_snapshot_age", nil)
	}

	s.audit.Record(r.Context(), audit.Event{
		ActorType: audit.ActorUser, ActorID: principal.Subject,
		Action: "settings.read", TargetType: "settings", TargetID: "",
		RequestID: requestIDOf(r), Outcome: audit.OutcomeSuccess,
		Detail: map[string]any{},
	})

	// The switches the gateway, the scheduler and the sweeper run with come from
	// the process rather than from the effective configuration; a panel started
	// without them shows the rows empty rather than made up.
	var process Process
	if s.process != nil {
		process = *s.process
	}
	var sweeps housekeeping.Options
	if process.Housekeeping != nil {
		sweeps = process.Housekeeping.Options()
	}

	vulnerabilities := effective.Vulnerabilities
	areas := []settingsArea{
		{Key: "build", Title: "Build", Facts: []settingsFact{
			fact("version", effective.Version),
			fact("commit", effective.Commit),
			fact("build_date", effective.BuildDate),
			fact("agent_protocol", effective.Protocol),
			fact("migration_level", migration),
		}},
		{Key: "listeners", Title: "Listeners and addresses", Facts: []settingsFact{
			fact("gateway_addr", effective.GatewayAddr),
			fact("enrollment_addr", effective.EnrollmentAddr),
			fact("admin_addr", effective.AdminAddr),
			fact("advertised", effective.Advertised),
			fact("gateway_id", effective.GatewayID),
			fact("public_url", effective.PublicURL),
			fact("package_repository_url", effective.PackageRepositoryURL),
			fact("web_root", effective.WebRoot),
			fact("state_dir", effective.StateDir),
		}},
		{Key: "agents", Title: "Agents", Facts: []settingsFact{
			fact("heartbeat_seconds", effective.HeartbeatSeconds),
			fact("heartbeat_jitter", effective.HeartbeatJitter),
			durationFact("stale_after", effective.StaleAfter),
			durationFact("agent_cert_ttl", effective.AgentCertTTL),
			fact("clone_policy", process.ClonePolicy),
			fact("relay_identity", process.RelayIdentity),
			fact("dispatch_rate", process.DispatchRate),
		}},
		{Key: "identity", Title: "Identity provider", Facts: []settingsFact{
			fact("issuer", effective.Identity.IssuerURL),
			fact("client_id", effective.Identity.ClientID),
			secretFact("client_secret", effective.Identity.ClientSecretSet),
			fact("groups_claim", effective.Identity.GroupsClaim),
			durationFact("session_idle", effective.SessionIdle),
			durationFact("session_absolute", effective.SessionAbsolute),
			fact("session_group_refresh", switchable(process.SessionGroupRefresh)),
			fact("oidc_admin_logout", process.OIDCAdminLogout),
		}},
		{Key: "directory", Title: "Directory", Facts: []settingsFact{
			fact("configured", effective.Directory.Configured),
			fact("server", effective.Directory.ServerURL),
			fact("principal", effective.Directory.Principal),
			fact("keytab", effective.Directory.KeytabPath),
			fact("ca_certificate", effective.Directory.CACertPath),
			fact("realm", effective.Directory.Realm),
			fact("write_enabled", effective.Directory.WriteEnabled),
		}},
		{Key: "stepup", Title: "Step-up policy", Facts: []settingsFact{
			durationFact("max_age", effective.StepUp.MaxAge),
			fact("acr", effective.StepUp.ACR),
			fact("tokens", effective.StepUp.Tokens),
			fact("production_environments", effective.ProductionEnvironments),
		}},
		{Key: "webhook", Title: "Webhook", Facts: []settingsFact{
			fact("url", effective.Webhook.URL),
			secretFact("secret", effective.Webhook.SecretSet),
			fact("events", effective.Webhook.Events),
		}},
		{Key: "vulnerabilities", Title: "Vulnerability feeds", Facts: []settingsFact{
			fact("enabled", vulnerabilities.Enabled),
			durationFact("sync_interval", vulnerabilities.SyncInterval),
			durationFact("max_snapshot_age", vulnerabilities.MaxSnapshotAge),
			fact("debian_url", vulnerabilities.DebianURL),
			feedAge("debian", vulnerabilities.DebianURL),
			fact("ubuntu_url", vulnerabilities.UbuntuURL),
			feedAge("ubuntu", vulnerabilities.UbuntuURL),
			fact("redhat_url", vulnerabilities.RedHatURL),
			feedAge("redhat", vulnerabilities.RedHatURL),
			fact("nvd_url", vulnerabilities.NVDURL),
			secretFact("nvd_key", vulnerabilities.NVDKeySet),
			durationFact("nvd_interval", vulnerabilities.NVDInterval),
			feedAge("nvd", vulnerabilities.NVDURL),
		}},
		// The audit retention stands apart from the working record: the trail is
		// evidence and is kept forever unless the installation decides otherwise,
		// while the jobs, the campaigns and the delivered events are always swept.
		{Key: "retention", Title: "Retention", Facts: []settingsFact{
			durationFact("metrics_raw", effective.MetricsRawRetention),
			durationFact("metrics_rollup", effective.MetricsRollupRetention),
			durationFact("audit", effective.AuditRetention),
			durationFact("agent_sessions", sweeps.Sessions),
			durationFact("jobs", sweeps.Jobs),
			durationFact("campaigns", sweeps.Campaigns),
			durationFact("outbox_events", sweeps.Outbox),
			fact("secrets_key_file", effective.SecretsKeyFile),
		}},
		// The shape of the connection pool and how the schema is brought forward:
		// the two settings an operator compares with what the database server allows
		// and with how the deployment migrates.
		{Key: "database", Title: "Database", Facts: []settingsFact{
			fact("pool_max_conns", effective.DatabasePool.MaxConns),
			fact("pool_min_conns", effective.DatabasePool.MinConns),
			fact("pool_max_conn_lifetime", effective.DatabasePool.MaxConnLifetime.String()),
			fact("pool_max_conn_idle_time", effective.DatabasePool.MaxConnIdleTime.String()),
			fact("pool_health_check_period", effective.DatabasePool.HealthCheckPeriod.String()),
			fact("pool_connect_timeout", effective.DatabasePool.ConnectTimeout.String()),
			fact("auto_migrate", effective.Migration.AutoMigrate),
			fact("migration_role", effective.Migration.Role),
		}},
	}
	for i := range areas {
		for j := range areas[i].Facts {
			if list, ok := areas[i].Facts[j].Value.([]string); ok && list == nil {
				areas[i].Facts[j].Value = []string{}
			}
		}
	}
	note := "The values are set in " + settingsSource +
		" and read when the control plane starts; this screen shows them and changes nothing."
	writeJSON(w, http.StatusOK, map[string]any{
		"source": settingsSource,
		"note":   note,
		"areas":  areas,
	})
}
