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
	"strings"
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
	"github.com/ultherego/flotestro/internal/monitoring"
	"github.com/ultherego/flotestro/internal/oidc"
	"github.com/ultherego/flotestro/internal/paging"
	"github.com/ultherego/flotestro/internal/pki"
	"github.com/ultherego/flotestro/internal/relays"
	"github.com/ultherego/flotestro/internal/remediation"
	"github.com/ultherego/flotestro/internal/secrets"
	"github.com/ultherego/flotestro/internal/selector"
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
	budgets  *budgets.Store
	tokens   *enrollment.Store
	authz    *authz.Store
	audit    *audit.Recorder
	registry *gateway.Registry
	// decommissioner drives the handshake that ends a host's membership:
	// it needs the session, so it lives with the gateway rather than here.
	decommissioner *gateway.Decommissioner
	oidc           *oidc.Provider
	directory      *freeipa.Client
	changes        *identity.Store
	// files holds the desired state of configuration files and their history.
	files *managedfiles.Store
	// certificates hold the watch scope and the deployment history. The
	// panel must know them, because the host will not say itself which file
	// is a service certificate.
	certificates *certificatestore.Store
	// monitoring holds the resource samples of the hosts, the alert rules,
	// the alerts and the silences. Nil means an installation without the
	// built-in monitoring - a valid state, not a failure.
	monitoring *monitoring.Store
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
	// contract records every registered route for the OpenAPI document.
	contract []apiRoute
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
	// relays is the registry of the site relays; the installation of a host
	// in an isolated site goes through one of them. Nil means an
	// installation without relays.
	relays *relays.Store
	// installation is what the panel knows about how the hosts reach it.
	installation Installation
	// groups holds the saved host selections: static member lists and
	// dynamic selectors a campaign can name.
	groups *selector.Store
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
	// StepUpRefuseTokens denies the highest-impact operations to API
	// tokens; by default they are allowed and recorded as such.
	StepUpRefuseTokens bool
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
	// The idle window is refreshed on every request by the store, so it has
	// to know the configured one rather than a default of its own.
	if authzStore != nil {
		authzStore.SetSessionIdle(limits.Idle)
	}
	server := &Server{pool: pool, hosts: hostStore, inventory: inventoryStore, jobs: jobStore,
		files:        managedfiles.NewStore(pool),
		certificates: certificatestore.NewStore(pool),
		backups:      backupstore.NewStore(pool),
		groups:       selector.NewStore(pool),
		campaigns:    campaignStore, tokens: tokens, authz: authzStore, audit: recorder,
		registry: registry, oidc: provider, directory: directory, changes: changes, log: log,
		productionEnvironments: production,
		sessionLimits:          limits, publicURL: options.PublicURL,
		webRoot: options.WebRoot, directoryWrite: options.DirectoryWrite,
		stepUp:  stepUpPolicy{MaxAge: options.StepUpMaxAge, ACR: options.StepUpACR, RefuseTokens: options.StepUpRefuseTokens},
		metrics: options.Metrics, trust: options.Trust}
	// The handshake needs the sessions of this gateway and the same stores
	// as the panel, so it is built here rather than handed in.
	server.decommissioner = gateway.NewDecommissioner(pool, hostStore, jobStore, recorder, registry, log)
	return server
}

// Routes builds the API router.
func (s *Server) Routes() http.Handler {
	mux := http.NewServeMux()
	s.route(mux, "GET /healthz", s.handleHealth)
	s.route(mux, "GET /api/v1/openapi.json", s.handleOpenAPI)
	s.route(mux, "GET /api/v1/capabilities", s.handleCapabilities)
	s.route(mux, "GET /metrics", s.handleMetrics)
	s.route(mux, "GET /api/v1/pki", s.handlePKIStatus)
	s.route(mux, "POST /api/v1/pki/prepare", s.handlePrepareCA)
	s.route(mux, "POST /api/v1/pki/activate", s.handleActivateCA)
	s.route(mux, "DELETE /api/v1/pki/{fingerprint}", s.handleRetireCA)

	// Operator login through the identity provider.
	s.route(mux, "GET /auth/login", s.handleLogin)
	s.route(mux, "GET /auth/callback", s.handleAuthCallback)
	s.route(mux, "POST /auth/logout", s.handleLogout)
	s.route(mux, "GET /api/v1/fleet/summary", s.handleFleetSummary)
	s.route(mux, "GET /api/v1/fleet/activity", s.handleFleetActivity)
	s.route(mux, "GET /api/v1/hosts", s.handleListHosts)
	s.route(mux, "GET /api/v1/hosts/{id}", s.handleGetHost)
	s.route(mux, "GET /api/v1/hosts/{id}/inventory", s.handleHostInventory)
	s.route(mux, "GET /api/v1/hosts/{id}/files", s.handleListManagedFiles)
	s.route(mux, "GET /api/v1/hosts/{id}/files/history", s.handleFileHistory)
	s.route(mux, "GET /api/v1/files/versions/{sha256}", s.handleFileVersion)
	s.route(mux, "GET /api/v1/hosts/{id}/inventory/{module}", s.handleHostInventoryModule)
	// The manifest history of a project. Reverting a change is deploying an
	// earlier version, so there is no separate operation.
	s.route(mux, "GET /api/v1/hosts/{id}/compose/{project}/versions", s.handleComposeVersions)
	s.route(mux, "GET /api/v1/hosts/{id}/local-accounts", s.handleHostLocalAccounts)
	s.route(mux, "GET /api/v1/hosts/{id}/audit", s.handleHostAudit)
	// The history of one host from every record the panel keeps: tasks,
	// the trail, sessions, campaigns and alerts, lined up by time.
	s.route(mux, "GET /api/v1/hosts/{id}/timeline", s.handleHostTimeline)
	s.route(mux, "GET /api/v1/audit", s.handleAudit)
	// An enrollment request is a durable record of a pending installation;
	// the token is only the secret that authorises one attempt.
	s.route(mux, "GET /api/v1/enrollment-requests", s.handleListEnrollmentRequests)
	s.route(mux, "POST /api/v1/enrollment-requests", s.handleCreateEnrollmentRequest)
	s.route(mux, "GET /api/v1/enrollment-requests/{id}", s.handleGetEnrollmentRequest)
	s.route(mux, "POST /api/v1/enrollment-requests/{id}/revoke", s.handleRevokeEnrollmentRequest)
	// The ready configuration of an order: the same file the installation
	// profile composes, without the token, fetchable as often as needed.
	s.route(mux, "GET /api/v1/enrollment-requests/{id}/config", s.handleEnrollmentConfig)
	// Everything a host needs before it holds a token: the addresses, the
	// trust, the repository and the commands for its family.
	s.route(mux, "GET /api/v1/installation-profiles", s.handleInstallationProfile)
	s.route(mux, "GET /api/v1/relays", s.handleListRelays)
	s.route(mux, "POST /api/v1/hosts/{id}/identity-recovery", s.handleIdentityRecovery)
	// The host lifecycle: cut-off, release and decommissioning from the fleet.
	s.route(mux, "POST /api/v1/hosts/{id}/quarantine", s.handleQuarantineHost)
	s.route(mux, "POST /api/v1/hosts/{id}/quarantine/release", s.handleReleaseHost)
	s.route(mux, "POST /api/v1/hosts/{id}/decommission", s.handleDecommissionHost)

	// Typed operations: plan, approval, execution, result.
	s.route(mux, "GET /api/v1/actions", s.handleListActions)
	s.route(mux, "GET /api/v1/errors", s.handleListErrors)
	s.route(mux, "POST /api/v1/hosts/{id}/operations", s.handleCreateOperation)
	// A maintenance window changes what the panel thinks about the host, not
	// the host state, so it has its own entry point instead of a place in
	// the task queue.
	s.route(mux, "POST /api/v1/hosts/{id}/maintenance", s.handleSetMaintenance)
	// Tags describe a host in the panel; the host itself is not asked. The
	// list is replaced whole, so the trail shows every change as one write.
	s.route(mux, "PUT /api/v1/hosts/{id}/tags", s.handleSetHostTags)
	// Host groups: a saved answer to "which hosts", either a fixed member
	// list or a selector resolved when read. A campaign names a group in
	// its selector instead of repeating the list.
	s.route(mux, "GET /api/v1/host-groups", s.handleListGroups)
	s.route(mux, "POST /api/v1/host-groups", s.handleCreateGroup)
	s.route(mux, "GET /api/v1/host-groups/{id}", s.handleGetGroup)
	s.route(mux, "PUT /api/v1/host-groups/{id}", s.handleUpdateGroup)
	s.route(mux, "DELETE /api/v1/host-groups/{id}", s.handleDeleteGroup)
	s.route(mux, "PUT /api/v1/host-groups/{id}/members", s.handleSetGroupMembers)
	s.route(mux, "GET /api/v1/host-groups/{id}/hosts", s.handleGroupHosts)
	// The fleet view: one bad setting on a hundred hosts is one problem, not
	// a hundred - and that is visible only when the findings stand side by
	// side.
	s.route(mux, "GET /api/v1/security", s.handleFleetSecurity)
	// A fleet remediation: chosen checks on chosen hosts, every host with
	// its own plan of steps, one approval over the whole set, carried out
	// as a campaign. The preview shows the plans grouped; the order creates
	// the campaign.
	s.route(mux, "POST /api/v1/security/remediation/preview", s.handleFleetRemediationPreview)
	s.route(mux, "POST /api/v1/security/remediation", s.handleFleetRemediation)
	// Compliance with the hardening profile is computed by the panel from
	// the facts the host reports anyway; the remediation is a plan and
	// separate module tasks.
	s.route(mux, "GET /api/v1/hosts/{id}/security", s.handleHostSecurity)
	s.route(mux, "GET /api/v1/hosts/{id}/security/remediation", s.handleListRemediation)
	s.route(mux, "POST /api/v1/hosts/{id}/security/remediation", s.handleHostRemediation)
	s.route(mux, "POST /api/v1/hosts/{id}/security/remediation/{plan}/stop", s.handleStopRemediation)
	// The secret store: a value goes in and does not come out. The only way
	// out leads through a lease issued to a host for the duration of one
	// task.
	s.route(mux, "GET /api/v1/budgets", s.handleListBudgets)
	s.route(mux, "GET /api/v1/budgets/{key...}", s.handleGetBudget)
	s.route(mux, "PUT /api/v1/budgets/{key...}", s.handleSetBudget)
	s.route(mux, "GET /api/v1/vulnerabilities", s.handleFleetVulnerabilities)
	s.route(mux, "GET /api/v1/hosts/{id}/vulnerabilities", s.handleHostVulnerabilities)

	s.monitoringRoutes(mux)

	s.route(mux, "GET /api/v1/backups", s.handleFleetBackups)
	s.route(mux, "GET /api/v1/hosts/{id}/backups", s.handleHostBackups)
	s.route(mux, "POST /api/v1/hosts/{id}/backups", s.handleSetBackupDefinition)
	s.route(mux, "DELETE /api/v1/hosts/{id}/backups", s.handleDeleteBackupDefinition)
	s.route(mux, "GET /api/v1/hosts/{id}/backups/runs", s.handleBackupRuns)

	s.route(mux, "GET /api/v1/certificates", s.handleFleetCertificates)
	s.route(mux, "GET /api/v1/certificates/trust", s.handleFleetTrust)
	s.route(mux, "GET /api/v1/hosts/{id}/certificates", s.handleHostCertificates)
	s.route(mux, "GET /api/v1/hosts/{id}/certificates/deployments", s.handleCertificateDeployments)
	s.route(mux, "POST /api/v1/hosts/{id}/certificates/targets", s.handleWatchCertificate)
	s.route(mux, "DELETE /api/v1/hosts/{id}/certificates/targets", s.handleUnwatchCertificate)

	s.route(mux, "GET /api/v1/secrets", s.handleListSecrets)
	s.route(mux, "POST /api/v1/secrets", s.handleCreateSecret)
	s.route(mux, "GET /api/v1/secrets/{name}", s.handleGetSecret)
	s.route(mux, "POST /api/v1/secrets/{name}/rotate", s.handleRotateSecret)
	s.route(mux, "POST /api/v1/secrets/{name}/retire", s.handleRetireSecret)
	s.route(mux, "DELETE /api/v1/secrets/{name}/versions/{version}", s.handleDestroySecretVersion)
	s.route(mux, "GET /api/v1/jobs", s.handleListJobs)
	s.route(mux, "GET /api/v1/jobs/{id}", s.handleGetJob)
	s.route(mux, "GET /api/v1/jobs/{id}/attempts", s.handleJobAttempts)
	// The event stream of the whole visible fleet. One connection per tab is
	// enough for all the operations in progress.
	s.route(mux, "GET /api/v1/events", s.handleFleetEvents)
	// The progress stream of one operation. The result stays durable in the
	// database; the stream only says when it is worth reading again.
	s.route(mux, "GET /api/v1/jobs/{id}/events", s.handleJobEvents)
	s.route(mux, "POST /api/v1/jobs/{id}/approve", s.handleApproveJob)
	s.route(mux, "POST /api/v1/jobs/{id}/cancel", s.handleCancelJob)

	// Campaigns: plan, approval, conduct and report.
	s.route(mux, "GET /api/v1/campaigns", s.handleListCampaigns)
	s.route(mux, "POST /api/v1/campaigns", s.handleCreateCampaign)
	// The selector preview: the target count comes from the database, not
	// from the length of the first page of the host list.
	s.route(mux, "GET /api/v1/campaigns/preview", s.handleCampaignPreview)
	s.route(mux, "GET /api/v1/campaigns/{id}", s.handleGetCampaign)
	s.route(mux, "GET /api/v1/campaigns/{id}/targets", s.handleCampaignTargets)
	s.route(mux, "GET /api/v1/campaigns/{id}/report", s.handleCampaignReport)
	s.route(mux, "GET /api/v1/campaigns/{id}/timeline", s.handleCampaignTimeline)
	s.route(mux, "GET /api/v1/campaigns/{id}/plans", s.handleCampaignPlans)
	s.route(mux, "GET /api/v1/campaigns/{id}/events", s.handleCampaignEvents)
	s.route(mux, "GET /api/v1/campaigns/{id}/approvals", s.handleCampaignApprovals)
	s.route(mux, "POST /api/v1/campaigns/{id}/approve", s.handleApproveCampaign)
	s.route(mux, "POST /api/v1/campaigns/{id}/pause", s.handlePauseCampaign)
	s.route(mux, "POST /api/v1/campaigns/{id}/resume", s.handleResumeCampaign)
	s.route(mux, "POST /api/v1/campaigns/{id}/cancel", s.handleCancelCampaign)
	s.route(mux, "POST /api/v1/campaigns/{id}/advance", s.handleAdvanceCampaign)

	// Diagnostic read fan-outs: the same read on a handful of hosts at once,
	// one ordinary job per host, merged into one answer. Not a campaign -
	// nothing changes, nothing is approved.
	s.route(mux, "GET /api/v1/reads", s.handleListReads)
	s.route(mux, "POST /api/v1/reads", s.handleCreateRead)
	s.route(mux, "GET /api/v1/reads/{id}", s.handleGetRead)

	// Principals and API tokens.
	s.route(mux, "GET /api/v1/principals", s.handleListPrincipals)
	s.route(mux, "POST /api/v1/principals", s.handleCreatePrincipal)
	// An identity is disabled rather than deleted: the trail keeps naming
	// it. The tokens and the bindings are managed one by one.
	s.route(mux, "DELETE /api/v1/principals/{id}", s.handleDisablePrincipal)
	s.route(mux, "POST /api/v1/principals/{id}/tokens", s.handleIssueToken)
	s.route(mux, "DELETE /api/v1/principals/{id}/tokens/{token}", s.handleRevokeToken)
	s.route(mux, "DELETE /api/v1/principals/{id}/roles/{role}", s.handleRevokeRole)
	s.route(mux, "GET /api/v1/whoami", s.handleWhoami)
	s.route(mux, "GET /api/v1/roles", s.handleListRoles)
	// The identity directory in read-only mode.
	s.route(mux, "GET /api/v1/identity/status", s.handleIdentityStatus)
	s.route(mux, "GET /api/v1/identity/users", directoryHandler(s, "users",
		func(s *Server, r *http.Request) ([]freeipa.User, error) {
			return s.directory.Users(r.Context())
		}))
	s.route(mux, "GET /api/v1/identity/groups", directoryHandler(s, "groups",
		func(s *Server, r *http.Request) ([]freeipa.Group, error) {
			return s.directory.Groups(r.Context())
		}))
	s.route(mux, "GET /api/v1/identity/hosts", directoryHandler(s, "hosts",
		func(s *Server, r *http.Request) ([]freeipa.Host, error) {
			return s.directory.Hosts(r.Context())
		}))
	// The access and sudo rules require a separate permission: they describe
	// who may enter a host and elevate privileges.
	s.route(mux, "GET /api/v1/identity/hbac-rules", policyHandler(s, "hbac",
		func(s *Server, r *http.Request) ([]freeipa.HBACRule, error) {
			return s.directory.HBACRules(r.Context())
		}))
	s.route(mux, "GET /api/v1/identity/sudo-rules", policyHandler(s, "sudo",
		func(s *Server, r *http.Request) ([]freeipa.SudoRule, error) {
			return s.directory.SudoRules(r.Context())
		}))
	s.route(mux, "GET /api/v1/identity/host-groups", directoryHandler(s, "host-groups",
		func(s *Server, r *http.Request) ([]freeipa.HostGroup, error) {
			return s.directory.HostGroups(r.Context())
		}))
	// The effective access: the directory's own simulation for a user and
	// a host, and the projection of the rules onto one host.
	s.route(mux, "POST /api/v1/identity/access/simulate", s.handleSimulateAccess)
	s.route(mux, "GET /api/v1/hosts/{id}/access", s.handleHostAccess)

	// The directory DNS: zones and records. Reading goes with the same
	// permission as the rest of the directory; writing is a central change
	// with its own permission and its own plan.
	s.route(mux, "GET /api/v1/identity/dns/zones", directoryHandler(s, "dns-zones",
		func(s *Server, r *http.Request) ([]freeipa.Zone, error) {
			return s.directory.Zones(r.Context())
		}))
	s.route(mux, "GET /api/v1/identity/dns/records", directoryHandler(s, "dns-records",
		func(s *Server, r *http.Request) ([]freeipa.Record, error) {
			zone := r.URL.Query().Get("zone")
			if zone == "" {
				return nil, fmt.Errorf("the zone parameter is required")
			}
			return s.directory.Records(r.Context(), zone)
		}))

	// Directory changes: plan, approval and execution phase by phase.
	s.route(mux, "GET /api/v1/identity/changes", s.handleListDirectoryChanges)
	s.route(mux, "POST /api/v1/identity/changes", s.handleCreateDirectoryChange)
	s.route(mux, "GET /api/v1/identity/changes/{id}", s.handleGetDirectoryChange)
	s.route(mux, "POST /api/v1/identity/changes/{id}/approve", s.handleApproveDirectoryChange)
	s.route(mux, "POST /api/v1/identity/changes/{id}/cancel", s.handleCancelDirectoryChange)

	s.route(mux, "GET /api/v1/group-mappings", s.handleListGroupMappings)
	s.route(mux, "POST /api/v1/group-mappings", s.handleCreateGroupMapping)
	s.route(mux, "DELETE /api/v1/group-mappings/{id}", s.handleDeleteGroupMapping)

	// The panel is served under the root; the API has its own prefixes, so
	// it does not collide with the browser routes.
	mux.Handle("/", SPAHandler(s.webRoot))

	// Authentication covers the whole router. Authorisation is done by the
	// handlers, because only they know the target scope.
	authenticator := authz.Authenticator{Tokens: s.authz, Sessions: s.authz}
	return securityHeaders(authenticator.Middleware(mux), inlineScriptHashes(s.webRoot))
}

// securityHeaders sets what every browser is told about this origin: the
// panel is never framed, content types are not guessed, the referrer stays
// home, and scripts, styles and connections come only from the panel
// itself. The one inline script in index.html applies the remembered
// theme before the first paint; its hash is the only exception. A page
// that needs an image from a host would have to say so here first.
func securityHeaders(next http.Handler, scriptHashes []string) http.Handler {
	policy := "default-src 'self'; script-src 'self' " + strings.Join(scriptHashes, " ") + "; " +
		"style-src 'self' 'unsafe-inline'; img-src 'self' data:; font-src 'self'; " +
		"connect-src 'self'; frame-ancestors 'none'; base-uri 'self'; form-action 'self'"
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		h := w.Header()
		h.Set("X-Content-Type-Options", "nosniff")
		h.Set("X-Frame-Options", "DENY")
		h.Set("Referrer-Policy", "same-origin")
		h.Set("Content-Security-Policy", policy)
		h.Set("Permissions-Policy", "camera=(), microphone=(), geolocation=()")
		next.ServeHTTP(w, r)
	})
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
//
// The attention counters are computed in the database over the hosts the
// principal may see: the dashboard must not fetch the fleet into the browser
// to count it. A nil counter is one the database cannot answer honestly for
// this view and is left out of the answer rather than shown as zero.
type FleetSummary struct {
	Hosts            int `json:"hosts"`
	Online           int `json:"online"`
	Offline          int `json:"offline"`
	ActiveSessions   int `json:"active_sessions"`
	RebootRequired   int `json:"reboot_required"`
	WithFailedUnits  int `json:"with_failed_units"`
	PendingSecurity  int `json:"hosts_with_security_updates"`
	QuarantinedHosts int `json:"quarantined_hosts"`
	// The attention counters over the hosts that are not retired: a retired
	// host is nobody's concern any more.
	PackageDatabaseBroken int `json:"package_database_broken"`
	SSSDOffline           int `json:"sssd_offline"`
	InMaintenance         int `json:"in_maintenance"`
	// FailedJobs24h counts the tasks that failed or timed out in the last
	// day on the visible hosts.
	FailedJobs24h *int `json:"failed_jobs_24h,omitempty"`
	// PendingEnrollmentRequests counts the installations ordered in the
	// visible scopes that nobody has completed yet.
	PendingEnrollmentRequests *int `json:"pending_enrollment_requests,omitempty"`
	// AgentsBehindLatest counts the hosts running an agent older than the
	// newest version seen in the visible fleet; LatestAgentVersion names
	// that version. Both are missing when no host reports a version the
	// panel can order.
	AgentsBehindLatest *int   `json:"agents_behind_latest,omitempty"`
	LatestAgentVersion string `json:"latest_agent_version,omitempty"`
	// AgentCertificatesExpiring counts the hosts whose current agent
	// certificate runs out within thirty days.
	AgentCertificatesExpiring *int `json:"agent_certificates_expiring,omitempty"`
	// DegradedRelays counts the relays that missed their renewal: a relay
	// certificate lives seven days and renews at a third left, so one with
	// less than a day is a site about to be cut off. A relay serves a site
	// rather than an environment, so the counter exists only for the global
	// view - a narrowed scope cannot say which relays are its own.
	DegradedRelays *int `json:"degraded_relays,omitempty"`
	// AlertsFiring counts the firing alerts on the visible hosts that no
	// silence covers, and AlertsCritical those of them that are critical.
	// A silenced alert already has an operator's decision behind it.
	AlertsFiring   int `json:"alerts_firing"`
	AlertsCritical int `json:"alerts_critical"`
}

func (s *Server) handleFleetSummary(w http.ResponseWriter, r *http.Request) {
	principal, ok := s.authorizeCollection(w, r, authz.PermHostRead, "fleet")
	if !ok {
		return
	}
	// The summary counts only the hosts the principal may see. Otherwise the
	// dashboard of a single-environment operator would show the whole fleet.
	scopes := principal.ScopesFor(authz.PermHostRead)
	condition, args := authz.ScopeSQL(scopes, "h.site", "h.environment", 0)
	visible := "true"
	if condition != "" {
		visible = condition
	}
	ctx := r.Context()

	var summary FleetSummary
	err := s.pool.QueryRow(ctx, `
		select
			count(*),
			count(*) filter (where h.connection_state = 'online'),
			count(*) filter (where h.connection_state <> 'online'),
			count(*) filter (where h.reboot_required),
			count(*) filter (where h.failed_units > 0),
			count(*) filter (where h.pending_security_updates > 0),
			count(*) filter (where h.lifecycle_state = 'quarantined'),
			count(*) filter (where h.package_database_broken and h.lifecycle_state <> 'retired'),
			count(*) filter (where h.identity_enrolled and h.identity_sssd_online = false
			                   and h.lifecycle_state <> 'retired'),
			count(*) filter (where h.maintenance_until > now() and h.lifecycle_state <> 'retired')
		from hosts h where `+visible, args...).Scan(
		&summary.Hosts, &summary.Online, &summary.Offline,
		&summary.RebootRequired, &summary.WithFailedUnits, &summary.PendingSecurity,
		&summary.QuarantinedHosts, &summary.PackageDatabaseBroken, &summary.SSSDOffline,
		&summary.InMaintenance)
	if err != nil {
		s.fail(w, err)
		return
	}
	summary.ActiveSessions = s.registry.Count()

	var failedJobs int
	err = s.pool.QueryRow(ctx, `
		select count(*)
		from jobs j
		where j.state in ('failed', 'timed_out')
		  and j.finished_at >= now() - interval '24 hours'
		  and exists (select 1 from hosts h where h.id = j.host_id and `+visible+`)`,
		args...).Scan(&failedJobs)
	if err != nil {
		s.fail(w, err)
		return
	}
	summary.FailedJobs24h = &failedJobs

	// An order past its deadline is not pending, whatever its status column
	// says: the store reports it as expired for the same reason.
	var pendingEnrollments int
	enrollmentCondition, enrollmentArgs := authz.ScopeSQL(scopes, "e.site", "e.environment", 0)
	if enrollmentCondition == "" {
		enrollmentCondition = "true"
	}
	err = s.pool.QueryRow(ctx, `
		select count(*) from enrollment_requests e
		where e.status = 'pending' and e.revoked_at is null and e.expires_at > now()
		  and `+enrollmentCondition, enrollmentArgs...).Scan(&pendingEnrollments)
	if err != nil {
		s.fail(w, err)
		return
	}
	summary.PendingEnrollmentRequests = &pendingEnrollments

	// The newest version is the newest the fleet reports, not a release the
	// panel knows of: the panel has no release feed, and a made-up "latest"
	// would tell every operator their whole fleet is behind. A version is
	// ordered numerically part by part; a host whose version does not
	// parse is neither behind nor current and stays out of the count.
	var behind, ordered int
	var latest []int32
	err = s.pool.QueryRow(ctx, `
		with versions as (
			select string_to_array(substring(h.agent_version from '^v?(\d+(?:\.\d+)*)'), '.')::int[] as v
			from hosts h
			where h.lifecycle_state <> 'retired'
			  and h.agent_version ~ '^v?\d+(\.\d+)*'
			  and `+visible+`
		)
		select count(*) filter (where v < (select max(v) from versions)), count(*),
		       (select max(v) from versions)
		from versions`, args...).Scan(&behind, &ordered, &latest)
	if err != nil {
		s.fail(w, err)
		return
	}
	if ordered > 0 {
		summary.AgentsBehindLatest = &behind
		summary.LatestAgentVersion = joinVersion(latest)
	}

	// The certificate that counts is the host's newest live one: after a
	// renewal the old certificate stays valid for a while and must not
	// raise an alarm the new one has already answered.
	var expiring int
	err = s.pool.QueryRow(ctx, `
		select count(*)
		from hosts h
		where h.lifecycle_state <> 'retired'
		  and `+visible+`
		  and (select max(c.not_after) from agent_certificates c
		       where c.host_id = h.id and c.revoked_at is null) < now() + interval '30 days'`,
		args...).Scan(&expiring)
	if err != nil {
		s.fail(w, err)
		return
	}
	summary.AgentCertificatesExpiring = &expiring

	if condition == "" {
		var degraded int
		err = s.pool.QueryRow(ctx, `
			select count(*) from relays
			where revoked_at is null and not_after < now() + interval '1 day'`).Scan(&degraded)
		if err != nil {
			s.fail(w, err)
			return
		}
		summary.DegradedRelays = &degraded
	}

	// The firing alerts of the visible hosts, without the silenced ones: a
	// silence is a decision already taken, and the dashboard counts what
	// still waits for one.
	err = s.pool.QueryRow(ctx, `
		select count(*), count(*) filter (where a.severity = 'critical')
		from alerts a join hosts h on h.id = a.host_id
		where a.state = 'firing'
		  and not exists (select 1 from silences s
		                  where s.expired_at is null and s.until > now()
		                    and (s.host_id is null or s.host_id = a.host_id)
		                    and (s.rule_id is null or s.rule_id = a.rule_id))
		  and `+visible, args...).Scan(&summary.AlertsFiring, &summary.AlertsCritical)
	if err != nil {
		s.fail(w, err)
		return
	}
	writeJSON(w, http.StatusOK, summary)
}

// joinVersion renders a version ordered by the database back into text.
func joinVersion(parts []int32) string {
	rendered := make([]string, 0, len(parts))
	for _, part := range parts {
		rendered = append(rendered, strconv.Itoa(int(part)))
	}
	return strings.Join(rendered, ".")
}

func (s *Server) handleListHosts(w http.ResponseWriter, r *http.Request) {
	// The list is narrowed to the scope the principal may read, so that a
	// single-environment operator does not see the whole fleet. The
	// narrowing is part of the query rather than a filter over the fetched
	// page: a page filtered afterwards would report a count and a cursor
	// for rows the caller never sees, and a narrow operator could get an
	// empty page with more to come.
	principal, ok := s.authorizeCollection(w, r, authz.PermHostRead, "fleet")
	if !ok {
		return
	}
	query := r.URL.Query()
	filter := hosts.ListFilter{
		Site:            query.Get("site"),
		Environment:     query.Get("environment"),
		OSFamily:        query.Get("os_family"),
		ConnectionState: query.Get("connection_state"),
		Search:          strings.TrimSpace(query.Get("q")),
		LifecycleState:  query.Get("lifecycle_state"),
		Owner:           query.Get("owner"),
		Capability:      query.Get("capability"),
		Scopes:          principal.ScopesFor(authz.PermHostRead),
	}
	// The tag filter repeats: every given tag has to be on the host. A tag
	// that is not a tag is refused rather than matched to nothing.
	if tags := query["tag"]; len(tags) > 0 {
		normalized, err := hosts.NormalizeTags(tags)
		if err != nil {
			problem(w, http.StatusBadRequest, "invalid_filter", err.Error())
			return
		}
		filter.Tags = normalized
	}
	if value := query.Get("maintenance"); value != "" {
		inWindow, err := strconv.ParseBool(value)
		if err != nil {
			problem(w, http.StatusBadRequest, "invalid_filter", "maintenance must be true or false")
			return
		}
		filter.Maintenance = &inWindow
	}
	cursor, err := hosts.ParseCursor(query.Get("cursor"))
	if err != nil {
		problem(w, http.StatusBadRequest, "invalid_cursor", err.Error())
		return
	}
	limit, _ := strconv.Atoi(query.Get("limit"))
	page, err := s.hosts.ListPaged(r.Context(), filter, cursor,
		paging.Limit(limit, defaultListPage, maxListPage))
	if err != nil {
		s.fail(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"items": page.Items, "count": len(page.Items),
		"total": page.Total, "next_cursor": page.NextCursor,
	})
}

// The page of a fleet list: what a screen gets without asking, and the
// most it may ask for. Beyond that a caller pages on with the cursor.
const (
	defaultListPage = 100
	maxListPage     = 500
)

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
	query := r.URL.Query()
	filter := audit.ListFilter{
		TargetID:   query.Get("target_id"),
		TargetType: query.Get("target_type"),
		Actor:      query.Get("actor"),
		Action:     query.Get("action"),
		Outcome:    query.Get("outcome"),
	}
	var err error
	if filter.Since, err = parseTimeParam(query.Get("since")); err != nil {
		problem(w, http.StatusBadRequest, "invalid_filter", "since must be an RFC 3339 timestamp")
		return
	}
	if filter.Until, err = parseTimeParam(query.Get("until")); err != nil {
		problem(w, http.StatusBadRequest, "invalid_filter", "until must be an RFC 3339 timestamp")
		return
	}
	cursor, err := audit.ParseCursor(query.Get("cursor"))
	if err != nil {
		problem(w, http.StatusBadRequest, "invalid_cursor", err.Error())
		return
	}
	limit, _ := strconv.Atoi(query.Get("limit"))
	page, err := s.audit.ListPaged(r.Context(), filter, cursor,
		paging.Limit(limit, defaultListPage, maxListPage))
	if err != nil {
		s.fail(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"items": page.Items, "count": len(page.Items), "next_cursor": page.NextCursor,
	})
}

// parseTimeParam reads an optional RFC 3339 query parameter. An empty value
// is no bound; a value that is not a timestamp is the caller's mistake and
// must not quietly turn into "no bound".
func parseTimeParam(value string) (*time.Time, error) {
	if value == "" {
		return nil, nil
	}
	parsed, err := time.Parse(time.RFC3339, value)
	if err != nil {
		return nil, err
	}
	return &parsed, nil
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
