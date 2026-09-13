// Package adminapi exposes the public REST API of the control plane.
// The handlers map a request onto domain operations and hold no business
// logic.
package adminapi

import (
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"strconv"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/ultherego/flotestro/internal/audit"
	"github.com/ultherego/flotestro/internal/authz"
	backupstore "github.com/ultherego/flotestro/internal/backup"
	"github.com/ultherego/flotestro/internal/budgets"
	"github.com/ultherego/flotestro/internal/campaigns"
	certificatestore "github.com/ultherego/flotestro/internal/certificates"
	"github.com/ultherego/flotestro/internal/enrollment"
	"github.com/ultherego/flotestro/internal/events"
	managedfiles "github.com/ultherego/flotestro/internal/files"
	"github.com/ultherego/flotestro/internal/freeipa"
	"github.com/ultherego/flotestro/internal/gateway"
	"github.com/ultherego/flotestro/internal/hosts"
	"github.com/ultherego/flotestro/internal/identity"
	"github.com/ultherego/flotestro/internal/inventory"
	"github.com/ultherego/flotestro/internal/jobs"
	"github.com/ultherego/flotestro/internal/metrics"
	"github.com/ultherego/flotestro/internal/oidc"
	"github.com/ultherego/flotestro/internal/pki"
	"github.com/ultherego/flotestro/internal/remediation"
	"github.com/ultherego/flotestro/internal/secrets"
	"github.com/ultherego/flotestro/internal/vuln"
)

// Server groups the REST API dependencies.
type Server struct {
	pool      *pgxpool.Pool
	hosts     *hosts.Store
	inventory *inventory.Store
	jobs      *jobs.Store
	campaigns *campaigns.Store
	// budgets show the capacity of the fleet and the sites. Nil means an
	// installation in which nobody enforces the capacity.
	budgets   *budgets.Store
	tokens    *enrollment.Store
	authz     *authz.Store
	audit     *audit.Recorder
	registry  *gateway.Registry
	oidc      *oidc.Provider
	directory *freeipa.Client
	changes   *identity.Store
	// files holds the desired state of configuration files and their history.
	files *managedfiles.Store
	// certificates hold the watch scope and the deployment history. The
	// panel must know them, because the host will not say itself which file
	// is a service certificate.
	certificates *certificatestore.Store
	// monitoring connects the panel with metrics and alerts. Nil means an
	// installation without monitoring - and that is a valid state, not a
	// failure.
	monitoring Monitoring
	// vulnerabilities hold the correlator findings, and hostPackages - the
	// list those findings were based on. A nil correlator means an
	// installation without vulnerability assessment.
	vulnerabilities *vuln.Store
	hostPackages    *vuln.PackageStore
	feedAge         time.Duration
	// backups hold the backup definitions and the run history. The panel
	// does not see the backup data: it flows from the host straight to the
	// repository.
	backups *backupstore.Store
	// directoryWrite enables the directory changes module. Disabled by
	// default: a customer may want the view alone, and make the changes with
	// their own tools.
	directoryWrite bool
	log            *slog.Logger

	// productionEnvironments require a second person at approval.
	productionEnvironments map[string]bool
	sessionLimits          authz.SessionLimits
	publicURL              string
	webRoot                string
	// stepUp describes the conditions of the highest-impact operations.
	stepUp stepUpPolicy
	// metrics exposes the panel state to monitoring.
	metrics *metrics.Collector
	// trust allows reviewing and replacing the fleet CA.
	trust *pki.Trust
	// events broadcasts operation state changes to the open screens.
	events *events.Bus
	// remediation holds the remediation plans. Without it the security
	// module shows the findings, but creates no plans.
	remediation *remediation.Store
	// secrets holds the values that must not pass through tasks. Nil means
	// an installation without a store.
	secrets *secrets.Store
}

// SetSecrets attaches the secret store.
func (s *Server) SetSecrets(store *secrets.Store) { s.secrets = store }

// SetRemediation attaches the remediation plan store.
func (s *Server) SetRemediation(store *remediation.Store) { s.remediation = store }

// SetEvents attaches the event bus. Without it the progress streams are
// inactive, and the panel works as before - after a page refresh.
func (s *Server) SetEvents(bus *events.Bus) { s.events = bus }

// SetBudgets attaches the capacity budgets.
func (s *Server) SetBudgets(store *budgets.Store) { s.budgets = store }

// Options gathers the API server settings that are not dependencies.
type Options struct {
	ProductionEnvironments []string
	SessionIdle            time.Duration
	SessionAbsolute        time.Duration
	// PublicURL is the panel address visible to the browser; used at logout
	// and when deciding about the Secure cookie flag.
	PublicURL string
	// WebRoot points at the directory with the built panel. Empty disables
	// serving.
	WebRoot string
	// DirectoryWrite enables changes in the identity directory.
	DirectoryWrite bool
	// StepUpMaxAge is the allowed authentication age for the highest-impact
	// operations. Zero disables the freshness requirement.
	StepUpMaxAge time.Duration
	// StepUpACR is the required authentication level, if the installation
	// defined it at the identity provider.
	StepUpACR string
	// Metrics exposes the panel state; nil disables the endpoint.
	Metrics *metrics.Collector
	// Trust is the set of fleet CAs; nil disables PKI management.
	Trust *pki.Trust
}

func NewServer(pool *pgxpool.Pool, hostStore *hosts.Store, inventoryStore *inventory.Store,
	jobStore *jobs.Store, campaignStore *campaigns.Store, tokens *enrollment.Store,
	authzStore *authz.Store, recorder *audit.Recorder, registry *gateway.Registry,
	provider *oidc.Provider, directory *freeipa.Client, changes *identity.Store,
	log *slog.Logger, options Options) *Server {
	production := map[string]bool{}
	for _, environment := range options.ProductionEnvironments {
		production[environment] = true
	}
	limits := authz.SessionLimits{Idle: options.SessionIdle, Absolute: options.SessionAbsolute}
	return &Server{pool: pool, hosts: hostStore, inventory: inventoryStore, jobs: jobStore,
		files:        managedfiles.NewStore(pool),
		certificates: certificatestore.NewStore(pool),
		backups:      backupstore.NewStore(pool),
		campaigns:    campaignStore, tokens: tokens, authz: authzStore, audit: recorder,
		registry: registry, oidc: provider, directory: directory, changes: changes, log: log,
		productionEnvironments: production,
		sessionLimits:          limits, publicURL: options.PublicURL,
		webRoot: options.WebRoot, directoryWrite: options.DirectoryWrite,
		stepUp:  stepUpPolicy{MaxAge: options.StepUpMaxAge, ACR: options.StepUpACR},
		metrics: options.Metrics, trust: options.Trust}
}

// Routes builds the API router.
func (s *Server) Routes() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /healthz", s.handleHealth)
	mux.HandleFunc("GET /api/v1/capabilities", s.handleCapabilities)
	mux.HandleFunc("GET /metrics", s.handleMetrics)
	mux.HandleFunc("GET /api/v1/pki", s.handlePKIStatus)
	mux.HandleFunc("POST /api/v1/pki/prepare", s.handlePrepareCA)
	mux.HandleFunc("POST /api/v1/pki/activate", s.handleActivateCA)
	mux.HandleFunc("DELETE /api/v1/pki/{fingerprint}", s.handleRetireCA)

	// Operator login through the identity provider.
	mux.HandleFunc("GET /auth/login", s.handleLogin)
	mux.HandleFunc("GET /auth/callback", s.handleAuthCallback)
	mux.HandleFunc("POST /auth/logout", s.handleLogout)
	mux.HandleFunc("GET /api/v1/fleet/summary", s.handleFleetSummary)
	mux.HandleFunc("GET /api/v1/hosts", s.handleListHosts)
	mux.HandleFunc("GET /api/v1/hosts/{id}", s.handleGetHost)
	mux.HandleFunc("GET /api/v1/hosts/{id}/inventory", s.handleHostInventory)
	mux.HandleFunc("GET /api/v1/hosts/{id}/files", s.handleListManagedFiles)
	mux.HandleFunc("GET /api/v1/hosts/{id}/files/history", s.handleFileHistory)
	mux.HandleFunc("GET /api/v1/files/versions/{sha256}", s.handleFileVersion)
	mux.HandleFunc("GET /api/v1/hosts/{id}/inventory/{module}", s.handleHostInventoryModule)
	// The manifest history of a project. Reverting a change is deploying an
	// earlier version, so there is no separate operation.
	mux.HandleFunc("GET /api/v1/hosts/{id}/compose/{project}/versions", s.handleComposeVersions)
	mux.HandleFunc("GET /api/v1/hosts/{id}/local-accounts", s.handleHostLocalAccounts)
	mux.HandleFunc("GET /api/v1/hosts/{id}/audit", s.handleHostAudit)
	mux.HandleFunc("GET /api/v1/audit", s.handleAudit)
	// An enrollment request is a durable record of a pending installation;
	// the token is only the secret that authorises one attempt.
	mux.HandleFunc("GET /api/v1/enrollment-requests", s.handleListEnrollmentRequests)
	mux.HandleFunc("POST /api/v1/enrollment-requests", s.handleCreateEnrollmentRequest)
	mux.HandleFunc("GET /api/v1/enrollment-requests/{id}", s.handleGetEnrollmentRequest)
	mux.HandleFunc("POST /api/v1/enrollment-requests/{id}/revoke", s.handleRevokeEnrollmentRequest)
	mux.HandleFunc("POST /api/v1/hosts/{id}/identity-recovery", s.handleIdentityRecovery)
	// The host lifecycle: cut-off, release and decommissioning from the fleet.
	mux.HandleFunc("POST /api/v1/hosts/{id}/quarantine", s.handleQuarantineHost)
	mux.HandleFunc("POST /api/v1/hosts/{id}/quarantine/release", s.handleReleaseHost)
	mux.HandleFunc("POST /api/v1/hosts/{id}/decommission", s.handleDecommissionHost)

	// Typed operations: plan, approval, execution, result.
	mux.HandleFunc("GET /api/v1/actions", s.handleListActions)
	mux.HandleFunc("POST /api/v1/hosts/{id}/operations", s.handleCreateOperation)
	// A maintenance window changes what the panel thinks about the host, not
	// the host state, so it has its own entry point instead of a place in
	// the task queue.
	mux.HandleFunc("POST /api/v1/hosts/{id}/maintenance", s.handleSetMaintenance)
	// The fleet view: one bad setting on a hundred hosts is one problem, not
	// a hundred - and that is visible only when the findings stand side by
	// side.
	mux.HandleFunc("GET /api/v1/security", s.handleFleetSecurity)
	// Compliance with the hardening profile is computed by the panel from
	// the facts the host reports anyway; the remediation is a plan and
	// separate module tasks.
	mux.HandleFunc("GET /api/v1/hosts/{id}/security", s.handleHostSecurity)
	mux.HandleFunc("GET /api/v1/hosts/{id}/security/remediation", s.handleListRemediation)
	mux.HandleFunc("POST /api/v1/hosts/{id}/security/remediation", s.handleHostRemediation)
	mux.HandleFunc("POST /api/v1/hosts/{id}/security/remediation/{plan}/stop", s.handleStopRemediation)
	// The secret store: a value goes in and does not come out. The only way
	// out leads through a lease issued to a host for the duration of one
	// task.
	mux.HandleFunc("GET /api/v1/budgets", s.handleListBudgets)
	mux.HandleFunc("PUT /api/v1/budgets/{key...}", s.handleSetBudget)
	mux.HandleFunc("GET /api/v1/vulnerabilities", s.handleFleetVulnerabilities)
	mux.HandleFunc("GET /api/v1/hosts/{id}/vulnerabilities", s.handleHostVulnerabilities)

	mux.HandleFunc("GET /api/v1/monitoring", s.handleFleetMonitoring)
	mux.HandleFunc("GET /api/v1/hosts/{id}/monitoring", s.handleHostMonitoring)
	mux.HandleFunc("POST /api/v1/hosts/{id}/monitoring/silences", s.handleCreateSilence)
	mux.HandleFunc("DELETE /api/v1/hosts/{id}/monitoring/silences/{silence}", s.handleExpireSilence)

	mux.HandleFunc("GET /api/v1/backups", s.handleFleetBackups)
	mux.HandleFunc("GET /api/v1/hosts/{id}/backups", s.handleHostBackups)
	mux.HandleFunc("POST /api/v1/hosts/{id}/backups", s.handleSetBackupDefinition)
	mux.HandleFunc("DELETE /api/v1/hosts/{id}/backups", s.handleDeleteBackupDefinition)
	mux.HandleFunc("GET /api/v1/hosts/{id}/backups/runs", s.handleBackupRuns)

	mux.HandleFunc("GET /api/v1/certificates", s.handleFleetCertificates)
	mux.HandleFunc("GET /api/v1/certificates/trust", s.handleFleetTrust)
	mux.HandleFunc("GET /api/v1/hosts/{id}/certificates", s.handleHostCertificates)
	mux.HandleFunc("GET /api/v1/hosts/{id}/certificates/deployments", s.handleCertificateDeployments)
	mux.HandleFunc("POST /api/v1/hosts/{id}/certificates/targets", s.handleWatchCertificate)
	mux.HandleFunc("DELETE /api/v1/hosts/{id}/certificates/targets", s.handleUnwatchCertificate)

	mux.HandleFunc("GET /api/v1/secrets", s.handleListSecrets)
	mux.HandleFunc("POST /api/v1/secrets", s.handleCreateSecret)
	mux.HandleFunc("GET /api/v1/secrets/{name}", s.handleGetSecret)
	mux.HandleFunc("POST /api/v1/secrets/{name}/rotate", s.handleRotateSecret)
	mux.HandleFunc("POST /api/v1/secrets/{name}/retire", s.handleRetireSecret)
	mux.HandleFunc("DELETE /api/v1/secrets/{name}/versions/{version}", s.handleDestroySecretVersion)
	mux.HandleFunc("GET /api/v1/jobs", s.handleListJobs)
	mux.HandleFunc("GET /api/v1/jobs/{id}", s.handleGetJob)
	mux.HandleFunc("GET /api/v1/jobs/{id}/attempts", s.handleJobAttempts)
	// The event stream of the whole visible fleet. One connection per tab is
	// enough for all the operations in progress.
	mux.HandleFunc("GET /api/v1/events", s.handleFleetEvents)
	// The progress stream of one operation. The result stays durable in the
	// database; the stream only says when it is worth reading again.
	mux.HandleFunc("GET /api/v1/jobs/{id}/events", s.handleJobEvents)
	mux.HandleFunc("POST /api/v1/jobs/{id}/approve", s.handleApproveJob)
	mux.HandleFunc("POST /api/v1/jobs/{id}/cancel", s.handleCancelJob)

	// Campaigns: plan, approval, conduct and report.
	mux.HandleFunc("GET /api/v1/campaigns", s.handleListCampaigns)
	mux.HandleFunc("POST /api/v1/campaigns", s.handleCreateCampaign)
	// The selector preview: the target count comes from the database, not
	// from the length of the first page of the host list.
	mux.HandleFunc("GET /api/v1/campaigns/preview", s.handleCampaignPreview)
	mux.HandleFunc("GET /api/v1/campaigns/{id}", s.handleGetCampaign)
	mux.HandleFunc("GET /api/v1/campaigns/{id}/targets", s.handleCampaignTargets)
	mux.HandleFunc("GET /api/v1/campaigns/{id}/report", s.handleCampaignReport)
	mux.HandleFunc("GET /api/v1/campaigns/{id}/timeline", s.handleCampaignTimeline)
	mux.HandleFunc("GET /api/v1/campaigns/{id}/plans", s.handleCampaignPlans)
	mux.HandleFunc("GET /api/v1/campaigns/{id}/events", s.handleCampaignEvents)
	mux.HandleFunc("POST /api/v1/campaigns/{id}/approve", s.handleApproveCampaign)
	mux.HandleFunc("POST /api/v1/campaigns/{id}/pause", s.handlePauseCampaign)
	mux.HandleFunc("POST /api/v1/campaigns/{id}/resume", s.handleResumeCampaign)
	mux.HandleFunc("POST /api/v1/campaigns/{id}/cancel", s.handleCancelCampaign)

	// Principals and API tokens.
	mux.HandleFunc("GET /api/v1/principals", s.handleListPrincipals)
	mux.HandleFunc("POST /api/v1/principals", s.handleCreatePrincipal)
	mux.HandleFunc("GET /api/v1/whoami", s.handleWhoami)
	mux.HandleFunc("GET /api/v1/roles", s.handleListRoles)
	// The identity directory in read-only mode.
	mux.HandleFunc("GET /api/v1/identity/status", s.handleIdentityStatus)
	mux.HandleFunc("GET /api/v1/identity/users", directoryHandler(s, "users",
		func(s *Server, r *http.Request) ([]freeipa.User, error) {
			return s.directory.Users(r.Context())
		}))
	mux.HandleFunc("GET /api/v1/identity/groups", directoryHandler(s, "groups",
		func(s *Server, r *http.Request) ([]freeipa.Group, error) {
			return s.directory.Groups(r.Context())
		}))
	mux.HandleFunc("GET /api/v1/identity/hosts", directoryHandler(s, "hosts",
		func(s *Server, r *http.Request) ([]freeipa.Host, error) {
			return s.directory.Hosts(r.Context())
		}))
	// The access and sudo rules require a separate permission: they describe
	// who may enter a host and elevate privileges.
	mux.HandleFunc("GET /api/v1/identity/hbac-rules", policyHandler(s, "hbac",
		func(s *Server, r *http.Request) ([]freeipa.HBACRule, error) {
			return s.directory.HBACRules(r.Context())
		}))
	mux.HandleFunc("GET /api/v1/identity/sudo-rules", policyHandler(s, "sudo",
		func(s *Server, r *http.Request) ([]freeipa.SudoRule, error) {
			return s.directory.SudoRules(r.Context())
		}))

	// The directory DNS: zones and records. Reading goes with the same
	// permission as the rest of the directory; writing is a central change
	// with its own permission and its own plan.
	mux.HandleFunc("GET /api/v1/identity/dns/zones", directoryHandler(s, "dns-zones",
		func(s *Server, r *http.Request) ([]freeipa.Zone, error) {
			return s.directory.Zones(r.Context())
		}))
	mux.HandleFunc("GET /api/v1/identity/dns/records", directoryHandler(s, "dns-records",
		func(s *Server, r *http.Request) ([]freeipa.Record, error) {
			zone := r.URL.Query().Get("zone")
			if zone == "" {
				return nil, fmt.Errorf("the zone parameter is required")
			}
			return s.directory.Records(r.Context(), zone)
		}))

	// Directory changes: plan, approval and execution phase by phase.
	mux.HandleFunc("GET /api/v1/identity/changes", s.handleListDirectoryChanges)
	mux.HandleFunc("POST /api/v1/identity/changes", s.handleCreateDirectoryChange)
	mux.HandleFunc("GET /api/v1/identity/changes/{id}", s.handleGetDirectoryChange)
	mux.HandleFunc("POST /api/v1/identity/changes/{id}/approve", s.handleApproveDirectoryChange)
	mux.HandleFunc("POST /api/v1/identity/changes/{id}/cancel", s.handleCancelDirectoryChange)

	mux.HandleFunc("GET /api/v1/group-mappings", s.handleListGroupMappings)
	mux.HandleFunc("POST /api/v1/group-mappings", s.handleCreateGroupMapping)
	mux.HandleFunc("DELETE /api/v1/group-mappings/{id}", s.handleDeleteGroupMapping)

	// The panel is served under the root; the API has its own prefixes, so
	// it does not collide with the browser routes.
	mux.Handle("/", SPAHandler(s.webRoot))

	// Authentication covers the whole router. Authorisation is done by the
	// handlers, because only they know the target scope.
	authenticator := authz.Authenticator{Tokens: s.authz, Sessions: s.authz}
	return authenticator.Middleware(mux)
}

func (s *Server) handleHealth(w http.ResponseWriter, r *http.Request) {
	if err := s.pool.Ping(r.Context()); err != nil {
		problem(w, http.StatusServiceUnavailable, "database_unavailable", "the database is not responding")
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"status":          "ok",
		"active_sessions": s.registry.Count(),
	})
}

// FleetSummary holds only the numbers that require an operator decision.
type FleetSummary struct {
	Hosts            int `json:"hosts"`
	Online           int `json:"online"`
	Offline          int `json:"offline"`
	ActiveSessions   int `json:"active_sessions"`
	RebootRequired   int `json:"reboot_required"`
	WithFailedUnits  int `json:"with_failed_units"`
	PendingSecurity  int `json:"hosts_with_security_updates"`
	QuarantinedHosts int `json:"quarantined_hosts"`
}

func (s *Server) handleFleetSummary(w http.ResponseWriter, r *http.Request) {
	principal, ok := s.authorizeCollection(w, r, authz.PermHostRead, "fleet")
	if !ok {
		return
	}
	// The summary counts only the hosts the principal may see. Otherwise the
	// dashboard of a single-environment operator would show the whole fleet.
	condition, args := scopeFilter(principal.ScopesFor(authz.PermHostRead))
	query := `
		select
			count(*),
			count(*) filter (where connection_state = 'online'),
			count(*) filter (where connection_state <> 'online'),
			count(*) filter (where reboot_required),
			count(*) filter (where failed_units > 0),
			count(*) filter (where pending_security_updates > 0),
			count(*) filter (where lifecycle_state = 'quarantined')
		from hosts `
	var summary FleetSummary
	err := s.pool.QueryRow(r.Context(), query+condition, args...).Scan(
		&summary.Hosts, &summary.Online, &summary.Offline,
		&summary.RebootRequired, &summary.WithFailedUnits, &summary.PendingSecurity, &summary.QuarantinedHosts)
	if err != nil {
		s.fail(w, err)
		return
	}
	summary.ActiveSessions = s.registry.Count()
	writeJSON(w, http.StatusOK, summary)
}

func (s *Server) handleListHosts(w http.ResponseWriter, r *http.Request) {
	// The list is narrowed to the scope the principal may read, so that a
	// single-environment operator does not see the whole fleet.
	principal, ok := s.authorizeCollection(w, r, authz.PermHostRead, "fleet")
	if !ok {
		return
	}
	query := r.URL.Query()
	limit, _ := strconv.Atoi(query.Get("limit"))
	result, err := s.hosts.List(r.Context(), hosts.ListFilter{
		Site:            query.Get("site"),
		Environment:     query.Get("environment"),
		OSFamily:        query.Get("os_family"),
		ConnectionState: query.Get("connection_state"),
		Limit:           limit,
	})
	if err != nil {
		s.fail(w, err)
		return
	}
	visible := make([]hosts.Host, 0, len(result))
	for _, host := range result {
		if principal.Can(authz.PermHostRead, authz.Scope{Site: host.Site, Environment: host.Environment}) {
			visible = append(visible, host)
		}
	}
	writeJSON(w, http.StatusOK, map[string]any{"items": visible, "count": len(visible)})
}

func (s *Server) handleGetHost(w http.ResponseWriter, r *http.Request) {
	hostID := r.PathValue("id")
	host, scope, ok := s.hostScope(w, r, hostID)
	if !ok {
		return
	}
	if _, ok := s.authorize(w, r, authz.PermHostRead, scope, "host", hostID); !ok {
		return
	}
	writeJSON(w, http.StatusOK, host)
}

func (s *Server) handleHostInventory(w http.ResponseWriter, r *http.Request) {
	hostID := r.PathValue("id")
	_, scope, ok := s.hostScope(w, r, hostID)
	if !ok {
		return
	}
	if _, ok := s.authorize(w, r, authz.PermInventoryRead, scope, "host", hostID); !ok {
		return
	}
	revision, err := s.inventory.Latest(r.Context(), hostID)
	if err != nil {
		s.fail(w, err)
		return
	}
	if revision == nil {
		problem(w, http.StatusNotFound, "inventory_not_found", "the host has not reported inventory yet")
		return
	}
	writeJSON(w, http.StatusOK, revision)
}

// handleHostInventoryModule returns the state of one host module.
//
// A tab fetches exactly what it shows, together with its own revision and
// its own observation timestamp. Until now all the tabs shared one date, so
// an operator looking at packages saw the freshness of something else.
func (s *Server) handleHostInventoryModule(w http.ResponseWriter, r *http.Request) {
	hostID := r.PathValue("id")
	_, scope, ok := s.hostScope(w, r, hostID)
	if !ok {
		return
	}
	if _, ok := s.authorize(w, r, authz.PermInventoryRead, scope, "host", hostID); !ok {
		return
	}
	module := r.PathValue("module")
	fragment, err := s.inventory.Fragment(r.Context(), hostID, module)
	if err != nil {
		s.fail(w, err)
		return
	}
	if fragment == nil {
		// A module not reported by the host differs from an empty module, so
		// the answer is a missing resource, not an empty payload.
		problem(w, http.StatusNotFound, "inventory_module_not_found",
			"the host has not reported this inventory module")
		return
	}
	writeJSON(w, http.StatusOK, fragment)
}

func (s *Server) handleHostAudit(w http.ResponseWriter, r *http.Request) {
	hostID := r.PathValue("id")
	_, scope, ok := s.hostScope(w, r, hostID)
	if !ok {
		return
	}
	if _, ok := s.authorize(w, r, authz.PermAuditRead, scope, "host", hostID); !ok {
		return
	}
	limit, _ := strconv.Atoi(r.URL.Query().Get("limit"))
	records, err := s.audit.List(r.Context(), hostID, limit)
	if err != nil {
		s.fail(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"items": records, "count": len(records)})
}

func (s *Server) handleAudit(w http.ResponseWriter, r *http.Request) {
	if _, ok := s.authorize(w, r, authz.PermAuditRead, authz.GlobalScope, "audit", ""); !ok {
		return
	}
	limit, _ := strconv.Atoi(r.URL.Query().Get("limit"))
	records, err := s.audit.List(r.Context(), r.URL.Query().Get("target_id"), limit)
	if err != nil {
		s.fail(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"items": records, "count": len(records)})
}

func (s *Server) fail(w http.ResponseWriter, err error) {
	s.log.Error("API request handling failed", "err", err)
	problem(w, http.StatusInternalServerError, "internal_error", "internal error")
}

func writeJSON(w http.ResponseWriter, status int, body any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(body)
}

// problem returns an error in the Problem Details format with a stable
// machine code.
func problem(w http.ResponseWriter, status int, code, detail string) {
	w.Header().Set("Content-Type", "application/problem+json; charset=utf-8")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(map[string]any{
		"type":   "about:blank",
		"title":  http.StatusText(status),
		"status": status,
		"code":   code,
		"detail": detail,
	})
}
