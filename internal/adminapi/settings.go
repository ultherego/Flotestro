package adminapi

import (
	"encoding/json"
	"errors"
	"net/http"
	"strings"
	"time"

	"github.com/ultherego/flotestro/internal/audit"
	"github.com/ultherego/flotestro/internal/authz"
	"github.com/ultherego/flotestro/internal/config"
	"github.com/ultherego/flotestro/internal/housekeeping"
	"github.com/ultherego/flotestro/internal/monitoring"
)

// The settings screen: what this panel was started with, plus the few
// settings the installation itself holds and an operator may change.

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
			// The two monitoring retentions are the installation's own setting,
			// so the screen shows what is in force now and not what this
			// process happened to start with.
			durationFact("metrics_raw", metricsRetention(s, effective.MetricsRawRetention, true)),
			durationFact("metrics_rollup", metricsRetention(s, effective.MetricsRollupRetention, false)),
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
		" and read when the control plane starts. The monitoring retentions and windows are the" +
		" exception: the installation stores them and this screen changes them without a restart."
	writeJSON(w, http.StatusOK, map[string]any{
		"source": settingsSource,
		"note":   note,
		"areas":  areas,
	})
}

// metricsRetention is what the monitoring runs on now, falling back to the
// value of the process for a panel started without the monitoring.
func metricsRetention(s *Server, started time.Duration, raw bool) time.Duration {
	if s.monitoring == nil {
		return started
	}
	options := s.monitoring.Settings()
	if raw {
		return options.RawRetention
	}
	return options.RollupRetention
}

// The monitoring settings as their own resource: the values in force, where
// each one comes from, and the write that changes them while the panel runs.

// monitoringSettingsBody is the shape read and written. A duration is a Go
// duration string; an empty one clears the field, which hands it back to the
// environment of the control plane.
type monitoringSettingsBody struct {
	RawRetention    string `json:"raw_retention"`
	RollupRetention string `json:"rollup_retention"`
	MaxLateness     string `json:"max_lateness"`
	RawQueryWindow  string `json:"raw_query_window"`
	ClockSkewLimit  string `json:"clock_skew_limit"`
	PartitionsAhead int    `json:"partitions_ahead"`
}

// monitoringSettingsWrite is the body of the write: the values plus the two
// things a change of retention needs and a change of capacity does not.
type monitoringSettingsWrite struct {
	monitoringSettingsBody
	// AcknowledgeDataLoss is the operator saying they have read what goes.
	// Shrinking a retention is their decision, but it is made once and cannot
	// be undone, so it is not made by leaving a field at its default.
	AcknowledgeDataLoss bool `json:"acknowledge_data_loss"`
	// Reason goes on the audit trail beside the values.
	Reason string `json:"reason"`
}

// settingsOf renders options for the API.
func settingsOf(options monitoring.Options) monitoringSettingsBody {
	return monitoringSettingsBody{
		RawRetention:    options.RawRetention.String(),
		RollupRetention: options.RollupRetention.String(),
		MaxLateness:     options.MaxLateness.String(),
		RawQueryWindow:  options.RawQueryWindow.String(),
		ClockSkewLimit:  options.ClockSkewLimit.String(),
		PartitionsAhead: options.PartitionsAhead,
	}
}

// storedSettingsOf renders only the fields the installation set; an empty one
// is not zero, it is a field the environment still decides.
func storedSettingsOf(options monitoring.Options) map[string]any {
	set := map[string]any{}
	for key, value := range map[string]time.Duration{
		"raw_retention":    options.RawRetention,
		"rollup_retention": options.RollupRetention,
		"max_lateness":     options.MaxLateness,
		"raw_query_window": options.RawQueryWindow,
		"clock_skew_limit": options.ClockSkewLimit,
	} {
		if value > 0 {
			set[key] = value.String()
		}
	}
	if options.PartitionsAhead > 0 {
		set["partitions_ahead"] = options.PartitionsAhead
	}
	return set
}

// parseMonitoringSettings turns the body into options. An empty duration is a
// cleared field, not a zero one; a malformed one is named.
func parseMonitoringSettings(body monitoringSettingsBody) (monitoring.Options, string, error) {
	var options monitoring.Options
	fields := []struct {
		key  string
		text string
		into *time.Duration
	}{
		{"raw_retention", body.RawRetention, &options.RawRetention},
		{"rollup_retention", body.RollupRetention, &options.RollupRetention},
		{"max_lateness", body.MaxLateness, &options.MaxLateness},
		{"raw_query_window", body.RawQueryWindow, &options.RawQueryWindow},
		{"clock_skew_limit", body.ClockSkewLimit, &options.ClockSkewLimit},
	}
	for _, field := range fields {
		text := strings.TrimSpace(field.text)
		if text == "" {
			continue
		}
		value, err := time.ParseDuration(text)
		if err != nil {
			return options, field.key, err
		}
		if value <= 0 {
			return options, field.key, errNotPositive
		}
		*field.into = value
	}
	if body.PartitionsAhead < 0 {
		return options, "partitions_ahead", errNotPositive
	}
	options.PartitionsAhead = body.PartitionsAhead
	return options, "", nil
}

// errNotPositive names a duration given as zero or less: an empty field is
// how a setting is cleared, and "-1h" is not a retention.
var errNotPositive = errors.New(
	"a duration must be positive; leave the field empty to let the environment decide it")

// requireMonitoringSettings is the gate and the nil check both writes and the
// read share.
func (s *Server) requireMonitoringSettings(w http.ResponseWriter, r *http.Request,
	permission authz.Permission) (authz.Principal, bool) {
	principal, ok := s.authorize(w, r, permission, authz.GlobalScope, "monitoring_settings", "")
	if !ok {
		return principal, false
	}
	if s.monitoring == nil {
		problem(w, http.StatusServiceUnavailable, "monitoring_disabled",
			"this installation runs without the built-in monitoring")
		return principal, false
	}
	return principal, true
}

// handleMonitoringSettings serves the settings in force, what the
// installation stored and what the process was started with, so the screen
// can say where each value comes from.
func (s *Server) handleMonitoringSettings(w http.ResponseWriter, r *http.Request) {
	if _, ok := s.requireMonitoringSettings(w, r, authz.PermSettingsRead); !ok {
		return
	}
	stored, err := s.monitoring.StoredSettings(r.Context())
	if err != nil {
		s.fail(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"effective":   settingsOf(s.monitoring.Settings()),
		"environment": settingsOf(s.monitoring.Baseline()),
		"stored": map[string]any{
			"present":    stored.Present,
			"updated_at": stored.UpdatedAt,
			"updated_by": stored.UpdatedBy,
			"revision":   stored.Revision,
			"values":     storedSettingsOf(stored.Options),
		},
		"note": "A field left empty is decided by " + settingsSource +
			"; a stored one takes effect on every replica within half a minute, without a restart.",
	})
}

// handleSetMonitoringSettings stores the monitoring settings. With
// ?dry_run=true it stores nothing and answers with what the change would
// throw away, which is what the screen shows before it asks.
func (s *Server) handleSetMonitoringSettings(w http.ResponseWriter, r *http.Request) {
	principal, ok := s.requireMonitoringSettings(w, r, authz.PermMonitoringRulesWrite)
	if !ok {
		return
	}
	var body monitoringSettingsWrite
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		problem(w, http.StatusBadRequest, "invalid_request", err.Error())
		return
	}
	proposed, field, err := parseMonitoringSettings(body.monitoringSettingsBody)
	if err != nil {
		problem(w, http.StatusBadRequest, "invalid_request", field+": "+err.Error())
		return
	}

	impact, err := s.monitoring.RetentionImpact(r.Context(), proposed)
	if err != nil {
		s.fail(w, err)
		return
	}
	dryRun := r.URL.Query().Get("dry_run") == "true"

	// The validation the panel refuses to start on runs here too, and it runs
	// before anything is stored: a retention shorter than the window plus the
	// lateness deletes a reading a relay is still carrying.
	if err := s.monitoring.Baseline().Overlay(proposed).Validate(); err != nil {
		if dryRun {
			writeJSON(w, http.StatusOK, map[string]any{
				"valid":  false,
				"code":   monitoring.ErrorRetentionTooShort,
				"detail": err.Error(),
				"impact": impact,
			})
			return
		}
		s.audit.Record(r.Context(), audit.Event{
			ActorType: audit.ActorUser, ActorID: principal.Subject,
			Action: "settings.monitoring.write", TargetType: "monitoring_settings", TargetID: "",
			RequestID: requestIDOf(r), Outcome: audit.OutcomeFailure,
			Detail: map[string]any{"code": monitoring.ErrorRetentionTooShort, "reason": err.Error()},
		})
		problem(w, http.StatusUnprocessableEntity, monitoring.ErrorRetentionTooShort, err.Error())
		return
	}

	if dryRun {
		writeJSON(w, http.StatusOK, map[string]any{
			"valid":     true,
			"impact":    impact,
			"effective": settingsOf(s.monitoring.Baseline().Overlay(proposed)),
		})
		return
	}
	// What goes is gone. The operator decides it, but not by omission.
	if impact.Destructive && !body.AcknowledgeDataLoss {
		problem(w, http.StatusConflict, monitoring.ErrorRetentionShrinkUnacknowledged,
			"these settings drop readings that are still kept; read what goes and send "+
				"acknowledge_data_loss: true to store them")
		return
	}

	before := settingsOf(s.monitoring.Settings())
	tx, err := s.pool.Begin(r.Context())
	if err != nil {
		s.fail(w, err)
		return
	}
	defer func() { _ = tx.Rollback(r.Context()) }()
	effective, stored, err := s.monitoring.SaveSettingsTx(r.Context(), tx, proposed, principal.Subject)
	if err != nil {
		s.fail(w, err)
		return
	}
	if err := s.audit.RecordTx(r.Context(), tx, audit.Event{
		ActorType: audit.ActorUser, ActorID: principal.Subject,
		Action: "settings.monitoring.write", TargetType: "monitoring_settings", TargetID: "",
		RequestID: requestIDOf(r), Outcome: audit.OutcomeSuccess,
		Detail: map[string]any{
			"reason":               strings.TrimSpace(body.Reason),
			"acknowledged":         body.AcknowledgeDataLoss,
			"dropped_partitions":   impact.DroppedPartitions,
			"raw_samples_estimate": impact.RawSamplesEstimate,
			"rollup_rows":          impact.RollupRows,
			"revision":             stored.Revision,
		},
		Before: map[string]any{"settings": before},
		After:  map[string]any{"settings": settingsOf(effective)},
	}); err != nil {
		s.fail(w, err)
		return
	}
	if err := tx.Commit(r.Context()); err != nil {
		s.fail(w, err)
		return
	}
	// Only now: a retention that is not stored must not be the one this replica
	// sweeps by.
	s.monitoring.PutInForce(effective)
	writeJSON(w, http.StatusOK, map[string]any{
		"effective": settingsOf(effective),
		"stored": map[string]any{
			"present":    true,
			"updated_at": stored.UpdatedAt,
			"updated_by": stored.UpdatedBy,
			"revision":   stored.Revision,
			"values":     storedSettingsOf(proposed),
		},
		"impact": impact,
	})
}
