// Package adminapi exposes the public REST API of the control plane. The
// handlers map a request onto domain operations and hold no business logic.
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
	"github.com/ultherego/flotestro/internal/buildinfo"
	"github.com/ultherego/flotestro/internal/campaigns"
	certificatestore "github.com/ultherego/flotestro/internal/certificates"
	"github.com/ultherego/flotestro/internal/config"
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
	"github.com/ultherego/flotestro/internal/notify"
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
	// certificates hold the watch scope and the deployment history.
	certificates *certificatestore.Store
	// monitoring holds the resource samples of the hosts, the alert rules, the
	// alerts and the silences.
	monitoring *monitoring.Store
	// vulnerabilities hold the correlator findings, and hostPackages - the list
	// those findings were based on.
	vulnerabilities *vuln.Store
	hostPackages    *vuln.PackageStore
	feedAge         time.Duration
	// backups hold the backup definitions and the run history. The panel does not
	// see the backup data: it flows from the host straight to the repository.
	backups *backupstore.Store
	// directoryWrite enables the directory changes module.
	directoryWrite bool
	log            *slog.Logger

	// productionEnvironments require a second person at approval.
	productionEnvironments map[string]bool
	sessionLimits          authz.SessionLimits
	publicURL              string
	webRoot                string
	// stepUp describes the conditions of the highest-impact operations.
	stepUp stepUpPolicy
	// previewMode is how strictly a campaign order is held to the preview
	// it was placed from.
	previewMode campaigns.PreviewMode
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
	// notifications holds the channels and notifier sends through them.
	// Nil means an installation without notification channels.
	notifications *notify.Store
	notifier      *notify.Router
	// notificationQueue is the worker of this instance, woken when an
	// operator puts a dead letter back in the queue.
	notificationQueue *notify.Worker
	// relays is the registry of the site relays; the installation of a host in an
	// isolated site goes through one of them.
	relays *relays.Store
	// installation is what the panel knows about how the hosts reach it.
	installation Installation
	// groups holds the saved host selections: static member lists and
	// dynamic selectors a campaign can name.
	groups *selector.Store
	// settings is the configuration the panel was started with, for the
	// settings screen. Nil means a panel started without one.
	settings *config.Effective
	// process is what the running process resolved that the effective
	// configuration does not carry: the retention sweeper and the switches of the
	// gateway and the scheduler.
	process *Process
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
	// CampaignPreview is the stage of the preview-binding rollout: observe
	// records what the binding would have decided, prefer refuses an order that
	// does not match the preview it names, and enforce additionally refuses an.
	CampaignPreview campaigns.PreviewMode
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
		stepUp:      stepUpPolicy{MaxAge: options.StepUpMaxAge, ACR: options.StepUpACR, RefuseTokens: options.StepUpRefuseTokens},
		previewMode: options.CampaignPreview,
		metrics:     options.Metrics, trust: options.Trust}
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
	// One question across every kind the caller may read.
	s.route(mux, "GET /api/v1/search", s.handleSearch)
	s.route(mux, "GET /api/v1/fleet/activity", s.handleFleetActivity)
	s.route(mux, "GET /api/v1/hosts", s.handleListHosts)
	s.route(mux, "GET /api/v1/hosts/{id}", s.handleGetHost)
	s.route(mux, "GET /api/v1/hosts/{id}/inventory", s.handleHostInventory)
	s.route(mux, "GET /api/v1/hosts/{id}/files", s.handleListManagedFiles)
	s.route(mux, "GET /api/v1/hosts/{id}/files/history", s.handleFileHistory)
	s.route(mux, "GET /api/v1/files/versions/{sha256}", s.handleFileVersion)
	s.route(mux, "GET /api/v1/hosts/{id}/inventory/{module}", s.handleHostInventoryModule)
	// The installed packages of a host as the store keeps them, with the holds.
	s.route(mux, "GET /api/v1/hosts/{id}/packages", s.handleHostPackages)
	// The kernels and releases the panel has seen the host on; the current
	// platform is the system module of the inventory.
	s.route(mux, "GET /api/v1/hosts/{id}/system/history", s.handleHostSystemHistory)
	// The manifest history of a project. Reverting a change is deploying an
	// earlier version, so there is no separate operation.
	s.route(mux, "GET /api/v1/hosts/{id}/compose/{project}/versions", s.handleComposeVersions)
	s.route(mux, "GET /api/v1/hosts/{id}/local-accounts", s.handleHostLocalAccounts)
	s.route(mux, "GET /api/v1/hosts/{id}/audit", s.handleHostAudit)
	// The history of one host from every record the panel keeps: tasks,
	// the trail, sessions, campaigns and alerts, lined up by time.
	s.route(mux, "GET /api/v1/hosts/{id}/timeline", s.handleHostTimeline)
	s.route(mux, "GET /api/v1/audit", s.handleAudit)
	// The export is the trail as a file with a hash chain, for a copy kept
	// outside the panel; cmd/auditverify checks such a file offline.
	s.route(mux, "GET /api/v1/audit/export", s.handleAuditExport)
	// An enrollment request is a durable record of a pending installation;
	// the token is only the secret that authorises one attempt.
	s.route(mux, "GET /api/v1/enrollment-requests", s.handleListEnrollmentRequests)
	s.route(mux, "POST /api/v1/enrollment-requests", s.handleCreateEnrollmentRequest)
	s.route(mux, "GET /api/v1/enrollment-requests/{id}", s.handleGetEnrollmentRequest)
	s.route(mux, "POST /api/v1/enrollment-requests/{id}/revoke", s.handleRevokeEnrollmentRequest)
	s.route(mux, "POST /api/v1/enrollment-requests/{id}/replace", s.handleReplaceEnrollmentRequest)
	s.route(mux, "GET /api/v1/hosts/{id}/actions", s.handleListHostActions)
	// The ready configuration of an order: the same file the installation
	// profile composes, without the token, fetchable as often as needed.
	s.route(mux, "GET /api/v1/enrollment-requests/{id}/config", s.handleEnrollmentConfig)
	// Everything a host needs before it holds a token: the addresses, the
	// trust, the repository and the commands for its family.
	s.route(mux, "GET /api/v1/installation-profiles", s.handleInstallationProfile)
	// The relays of the sites: the route of an installation for the wizard, the
	// state of a site for the relay page.
	s.route(mux, "GET /api/v1/relays", s.handleListRelays)
	s.route(mux, "GET /api/v1/relays/{id}", s.handleGetRelay)
	s.route(mux, "GET /api/v1/relays/{id}/buffer-history", s.handleRelayBufferHistory)
	s.route(mux, "POST /api/v1/relays/{id}/revoke", s.handleRevokeRelay)
	s.route(mux, "POST /api/v1/hosts/{id}/identity-recovery", s.handleIdentityRecovery)
	// The host lifecycle: cut-off, release and decommissioning from the fleet.
	s.route(mux, "POST /api/v1/hosts/{id}/quarantine", s.handleQuarantineHost)
	s.route(mux, "POST /api/v1/hosts/{id}/quarantine/release", s.handleReleaseHost)
	s.route(mux, "POST /api/v1/hosts/{id}/decommission", s.handleDecommissionHost)

	// Typed operations: plan, approval, execution, result.
	s.route(mux, "GET /api/v1/actions", s.handleListActions)
	s.route(mux, "GET /api/v1/errors", s.handleListErrors)
	s.route(mux, "POST /api/v1/hosts/{id}/operations", s.handleCreateOperation)
	// A maintenance window changes what the panel thinks about the host, not the
	// host state, so it has its own entry point instead of a place in the task
	// queue.
	s.route(mux, "POST /api/v1/hosts/{id}/maintenance", s.handleSetMaintenance)
	// Tags describe a host in the panel; the host itself is not asked. The
	// list is replaced whole, so the trail shows every change as one write.
	s.route(mux, "PUT /api/v1/hosts/{id}/tags", s.handleSetHostTags)
	// The release channel is a policy like a tag: which agent releases the
	// host sees first.
	s.route(mux, "PUT /api/v1/hosts/{id}/channel", s.handleSetHostChannel)
	// The owner and the manual management address are facts the operator records
	// about the host, like a tag; they share its permission and carry an entity
	// tag, because two people correct the same host.
	s.route(mux, "PUT /api/v1/hosts/{id}/owner", s.handleSetHostOwner)
	s.route(mux, "PUT /api/v1/hosts/{id}/management-address", s.handleSetHostManagementAddress)
	s.route(mux, "PUT /api/v1/hosts/{id}/failure-domain", s.handleSetHostFailureDomain)
	s.route(mux, "PUT /api/v1/hosts/{id}/placement", s.handleSetHostPlacement)
	s.route(mux, "PUT /api/v1/hosts/{id}/notes", s.handleSetHostNotes)
	// The tag catalogue of the visible fleet, and a rename across it.
	s.route(mux, "GET /api/v1/tags", s.handleListTags)
	s.route(mux, "POST /api/v1/tags/rename", s.handleRenameTag)
	// What the signed-in identity keeps for itself.
	s.route(mux, "GET /api/v1/me/preferences", s.handleGetPreferences)
	s.route(mux, "PUT /api/v1/me/preferences", s.handleSetPreferences)
	s.route(mux, "GET /api/v1/me/sessions", s.handleMySessions)
	s.route(mux, "GET /api/v1/me/tokens", s.handleMyTokens)
	// One order for the facts of many hosts, answered host by host.
	s.route(mux, "POST /api/v1/hosts/bulk-metadata", s.handleBulkHostMetadata)
	// Host groups: a saved answer to "which hosts", either a fixed member list or
	// a selector resolved when read.
	s.route(mux, "GET /api/v1/host-groups", s.handleListGroups)
	// The selector preview: what a selector under construction resolves
	// to now, for the group form; the same evaluation as the group page.
	s.route(mux, "GET /api/v1/host-groups/preview", s.handleGroupPreview)
	s.route(mux, "POST /api/v1/host-groups", s.handleCreateGroup)
	s.route(mux, "GET /api/v1/host-groups/{id}", s.handleGetGroup)
	s.route(mux, "PUT /api/v1/host-groups/{id}", s.handleUpdateGroup)
	s.route(mux, "DELETE /api/v1/host-groups/{id}", s.handleDeleteGroup)
	s.route(mux, "PUT /api/v1/host-groups/{id}/members", s.handleSetGroupMembers)
	s.route(mux, "GET /api/v1/host-groups/{id}/hosts", s.handleGroupHosts)
	// The fleet view: one bad setting on a hundred hosts is one problem, not a
	// hundred - and that is visible only when the findings stand side by side.
	s.route(mux, "GET /api/v1/security", s.handleFleetSecurity)
	// A fleet remediation: chosen checks on chosen hosts, every host with its own
	// plan of steps, one approval over the whole set, carried out as a campaign.
	s.route(mux, "POST /api/v1/security/remediation/preview", s.handleFleetRemediationPreview)
	s.route(mux, "POST /api/v1/security/remediation", s.handleFleetRemediation)
	// Compliance with the hardening profile is computed by the panel from the
	// facts the host reports anyway; the remediation is a plan and separate
	// module tasks.
	s.route(mux, "GET /api/v1/hosts/{id}/security", s.handleHostSecurity)
	s.route(mux, "GET /api/v1/hosts/{id}/security/remediation", s.handleListRemediation)
	s.route(mux, "POST /api/v1/hosts/{id}/security/remediation", s.handleHostRemediation)
	s.route(mux, "POST /api/v1/hosts/{id}/security/remediation/{plan}/stop", s.handleStopRemediation)
	// The secret store: a value goes in and does not come out. The only way out
	// leads through a lease issued to a host for the duration of one task.
	s.route(mux, "GET /api/v1/budgets", s.handleListBudgets)
	s.route(mux, "GET /api/v1/budgets/{key...}", s.handleGetBudget)
	s.route(mux, "PUT /api/v1/budgets/{key...}", s.handleSetBudget)
	s.route(mux, "DELETE /api/v1/budgets/{key...}", s.handleDeleteBudget)
	s.route(mux, "GET /api/v1/vulnerabilities", s.handleFleetVulnerabilities)
	s.route(mux, "POST /api/v1/vulnerabilities/snapshots/{id}/accept", s.handleAcceptSnapshotCandidate)
	s.route(mux, "GET /api/v1/vulnerabilities/cves", s.handleFleetCVEs)
	s.route(mux, "GET /api/v1/vulnerabilities/cves/{cve}", s.handleCVE)
	s.route(mux, "GET /api/v1/hosts/{id}/vulnerabilities", s.handleHostVulnerabilities)

	s.monitoringRoutes(mux)
	s.notificationRoutes(mux)

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
	// The steps of the targets: which task carried which step of which
	// host, on which attempt, and why a step did not run.
	s.route(mux, "GET /api/v1/campaigns/{id}/steps", s.handleCampaignSteps)
	s.route(mux, "GET /api/v1/campaigns/{id}/events", s.handleCampaignEvents)
	s.route(mux, "GET /api/v1/campaigns/{id}/approvals", s.handleCampaignApprovals)
	s.route(mux, "POST /api/v1/campaigns/{id}/approve", s.handleApproveCampaign)
	s.route(mux, "POST /api/v1/campaigns/{id}/pause", s.handlePauseCampaign)
	s.route(mux, "POST /api/v1/campaigns/{id}/resume", s.handleResumeCampaign)
	s.route(mux, "POST /api/v1/campaigns/{id}/cancel", s.handleCancelCampaign)
	// A retry is a new order for the hosts the campaign lost, under a new
	// approval; the settled campaign itself never changes.
	s.route(mux, "POST /api/v1/campaigns/{id}/retry", s.handleRetryCampaign)
	s.route(mux, "POST /api/v1/campaigns/{id}/targets/{host}/skip", s.handleSkipCampaignTarget)
	// Scheduled campaigns: an order kept for a moment or a rule of moments,
	// placed through the door above under its author's rights; each campaign it
	// places waits for its approval.
	s.route(mux, "GET /api/v1/campaign-schedules", s.handleListCampaignSchedules)
	s.route(mux, "POST /api/v1/campaign-schedules", s.handleCreateCampaignSchedule)
	s.route(mux, "GET /api/v1/campaign-schedules/{id}", s.handleGetCampaignSchedule)
	s.route(mux, "PUT /api/v1/campaign-schedules/{id}", s.handleUpdateCampaignSchedule)
	s.route(mux, "DELETE /api/v1/campaign-schedules/{id}", s.handleDeleteCampaignSchedule)
	s.route(mux, "POST /api/v1/campaign-schedules/{id}/run-now", s.handleRunCampaignScheduleNow)
	s.route(mux, "GET /api/v1/maintenance/calendar", s.handleMaintenanceCalendar)
	s.route(mux, "POST /api/v1/campaigns/{id}/advance", s.handleAdvanceCampaign)

	// Desired-state policies: a draft, its publications, the verdicts the loop
	// writes, and one evaluation on demand.
	s.route(mux, "GET /api/v1/reports/{name}", s.handleReport)
	s.route(mux, "GET /api/v1/policies", s.handleListPolicies)
	s.route(mux, "POST /api/v1/policies", s.handleCreatePolicy)
	s.route(mux, "GET /api/v1/policies/{id}", s.handleGetPolicy)
	s.route(mux, "PUT /api/v1/policies/{id}", s.handleUpdatePolicy)
	s.route(mux, "DELETE /api/v1/policies/{id}", s.handleDeletePolicy)
	s.route(mux, "POST /api/v1/policies/{id}/publish", s.handlePublishPolicy)
	s.route(mux, "POST /api/v1/policies/{id}/evaluate", s.handleEvaluatePolicy)
	s.route(mux, "GET /api/v1/policies/{id}/results", s.handlePolicyResults)
	s.route(mux, "GET /api/v1/policies/{id}/versions", s.handlePolicyVersions)
	s.route(mux, "GET /api/v1/policies/{id}/campaigns", s.handlePolicyCampaigns)
	s.route(mux, "GET /api/v1/hosts/{id}/policies", s.handleHostPolicies)

	// Diagnostic read fan-outs: the same read on a handful of hosts at once, one
	// ordinary job per host, merged into one answer.
	s.route(mux, "GET /api/v1/reads", s.handleListReads)
	s.route(mux, "POST /api/v1/reads", s.handleCreateRead)
	s.route(mux, "GET /api/v1/reads/{id}", s.handleGetRead)

	// Principals and API tokens.
	s.route(mux, "GET /api/v1/principals", s.handleListPrincipals)
	s.route(mux, "POST /api/v1/principals", s.handleCreatePrincipal)
	// An identity is disabled rather than deleted: the trail keeps naming
	// it. The tokens and the bindings are managed one by one.
	s.route(mux, "DELETE /api/v1/principals/{id}", s.handleDisablePrincipal)
	// Enabling gives a disabled identity its roles back; the sessions and
	// the tokens that ended with the disabling stay ended.
	s.route(mux, "POST /api/v1/principals/{id}/enable", s.handleEnablePrincipal)
	// The live browser sessions of an identity, ended one at a time.
	s.route(mux, "GET /api/v1/principals/{id}/sessions", s.handleListSessions)
	s.route(mux, "DELETE /api/v1/principals/{id}/sessions/{sid}", s.handleRevokeSession)
	s.route(mux, "POST /api/v1/principals/{id}/tokens", s.handleIssueToken)
	s.route(mux, "DELETE /api/v1/principals/{id}/tokens/{token}", s.handleRevokeToken)
	// A binding is granted with a validity or without one; granting it
	// again changes the validity alone.
	s.route(mux, "POST /api/v1/principals/{id}/roles", s.handleGrantRole)
	s.route(mux, "DELETE /api/v1/principals/{id}/roles/{role}", s.handleRevokeRole)
	// The access review: every identity with what it can do, when it was
	// last used and what the reviewer should look at.
	s.route(mux, "GET /api/v1/access/review", s.handleAccessReview)
	s.route(mux, "GET /api/v1/whoami", s.handleWhoami)
	s.route(mux, "GET /api/v1/roles", s.handleListRoles)
	// The effective configuration, secrets masked: what this panel was
	// started with, for whoever administers it.
	s.route(mux, "GET /api/v1/settings", s.handleSettings)
	// The first run: what the installation still lacks, and the two
	// connection tests the checklist offers in place.
	s.route(mux, "GET /api/v1/setup", s.handleSetup)
	s.route(mux, "GET /api/v1/status", s.handleStatus)
	s.route(mux, "POST /api/v1/setup/test-oidc", s.handleTestOIDC)
	s.route(mux, "POST /api/v1/setup/test-directory", s.handleTestDirectory)
	// The identity directory in read-only mode.
	s.route(mux, "GET /api/v1/identity/status", s.handleIdentityStatus)
	s.route(mux, "GET /api/v1/identity/users", directoryHandler(s, "users", directoryUsers))
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
	s.route(mux, "GET /api/v1/identity/services", directoryHandler(s, "services", directoryServices))
	// The effective access: the directory's own simulation for a user and
	// a host, and the projection of the rules onto one host.
	s.route(mux, "POST /api/v1/identity/access/simulate", s.handleSimulateAccess)
	s.route(mux, "GET /api/v1/hosts/{id}/access", s.handleHostAccess)

	// The directory DNS: zones and records.
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
	// The one route that changes the directory's own configuration: it gives the
	// connector the right to preserve an account and nothing else, and it is run
	// on purpose rather than by an operation.
	s.route(mux, "GET /api/v1/teams", s.handleListTeams)
	s.route(mux, "POST /api/v1/teams", s.handleCreateTeam)
	s.route(mux, "GET /api/v1/teams/{id}", s.handleGetTeam)
	s.route(mux, "PUT /api/v1/teams/{id}", s.handleUpdateTeam)
	s.route(mux, "DELETE /api/v1/teams/{id}", s.handleDeleteTeam)
	// Putting a host into a team changes who may act on it, so it is a
	// decision of its own rather than a field of its metadata.
	s.route(mux, "PUT /api/v1/hosts/{id}/team", s.handleSetHostTeam)
	// A role over a team, beside the site-scoped bindings.
	s.route(mux, "POST /api/v1/principals/{id}/team-roles", s.handleGrantTeamRole)
	s.route(mux, "DELETE /api/v1/principals/{id}/team-roles/{role}", s.handleRevokeTeamRole)
	s.route(mux, "POST /api/v1/identity/directory/provision-preserve", s.handleProvisionPreserveRights)
	s.route(mux, "POST /api/v1/identity/changes", s.handleCreateDirectoryChange)
	s.route(mux, "GET /api/v1/identity/changes/{id}", s.handleGetDirectoryChange)
	s.route(mux, "POST /api/v1/identity/changes/{id}/approve", s.handleApproveDirectoryChange)
	s.route(mux, "POST /api/v1/identity/changes/{id}/cancel", s.handleCancelDirectoryChange)
	// The one-time value of a change - the password of a reset - read once
	// by the requester and by nobody else.
	s.route(mux, "POST /api/v1/identity/changes/{id}/reveal", s.handleRevealDirectoryChangeSecret)

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

// securityHeaders sets what every browser is told about this origin: the panel
// is never framed, content types are not guessed, the referrer stays home, and
// scripts, styles and connections come only from the panel itself.
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
	// AgentsBehindLatest counts the hosts running an agent older than the newest
	// version seen in the visible fleet; LatestAgentVersion names that version.
	AgentsBehindLatest *int   `json:"agents_behind_latest,omitempty"`
	LatestAgentVersion string `json:"latest_agent_version,omitempty"`
	// AgentCertificatesExpiring counts the hosts whose newest live agent
	// certificate runs out within CertificateWarningDays and is still valid: the
	// agent should have renewed it by now and has not.
	AgentCertificatesExpiring *int `json:"agent_certificates_expiring,omitempty"`
	// AgentCertificatesExpired counts the hosts with no valid agent certificate
	// left, or that the gateway last turned away for an expired one.
	AgentCertificatesExpired *int `json:"agent_certificates_expired,omitempty"`
	// DegradedRelays counts the relays in trouble: those that missed their
	// renewal - a relay certificate lives seven days and renews at a third left,
	// so one with less than a day is a site about to be cut off - and those.
	DegradedRelays *int `json:"degraded_relays,omitempty"`
	// RelaysBufferHigh counts the relays whose buffer of results waiting for the
	// centre is at least RelayBufferHighPercent full, by their latest heartbeat:
	// a site about to lose results.
	RelaysBufferHigh *int `json:"relays_buffer_high,omitempty"`
	// DuplicateIdentities24h counts the sessions the gateway opened in the last
	// day while the same identity was alive on a different boot - a cloned
	// machine or a golden image with the identity left in.
	DuplicateIdentities24h *int `json:"duplicate_identities_24h,omitempty"`
	// EnrollmentRefusals1h counts the enrollments the gateway turned away in the
	// last hour: a burst is a token leaked or an installer pointed at the wrong
	// panel, not a normal rate of typos.
	EnrollmentRefusals1h *int `json:"enrollment_refusals_1h,omitempty"`
	// AgentsUnsupported counts the visible hosts whose reported agent version
	// speaks a protocol this panel does not: newer than the panel, or older than
	// any release with a known protocol.
	AgentsUnsupported *int `json:"agents_unsupported,omitempty"`
	// AlertsFiring counts the firing alerts on the visible hosts that no silence
	// covers, and AlertsCritical those of them that are critical.
	AlertsFiring   int `json:"alerts_firing"`
	AlertsCritical int `json:"alerts_critical"`
	// The counters of what waits for a person, missing for a reader
	// without the right to the list each of them counts.
	PendingDecisions
}

// RelayBufferHighPercent is the fill of a relay's buffer the dashboard counts
// as high.
const RelayBufferHighPercent = 70

// CertificateWarningDays is the window of the expiring-certificates tile.
const CertificateWarningDays = 7

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

	// The newest version is the newest the fleet reports, not a release the panel
	// knows of: the panel has no release feed, and a made-up "latest" would tell
	// every operator their whole fleet is behind.
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

	// The certificate that counts is the host's newest live one: after a renewal
	// the old certificate stays valid for a while and must not raise an alarm the
	// new one has already answered.
	var expiring, expired int
	err = s.pool.QueryRow(ctx, `
		with newest as (
			select h.id, h.last_connection_refusal_code as refusal,
			       (select max(c.not_after) from agent_certificates c
			         where c.host_id = h.id and c.revoked_at is null) as not_after
			from hosts h
			where h.lifecycle_state <> 'retired'
			  and `+visible+`
		)
		select count(*) filter (where not_after >= now()
		                          and not_after < now() + make_interval(days => $`+strconv.Itoa(len(args)+1)+`)
		                          and refusal is distinct from 'certificate_expired'),
		       count(*) filter (where not_after < now() or refusal = 'certificate_expired')
		from newest`,
		append(append([]any{}, args...), CertificateWarningDays)...).Scan(&expiring, &expired)
	if err != nil {
		s.fail(w, err)
		return
	}
	summary.AgentCertificatesExpiring = &expiring
	summary.AgentCertificatesExpired = &expired

	if condition == "" {
		var degraded int
		err = s.pool.QueryRow(ctx, `
			select count(*) from relays
			where revoked_at is null
			  and (not_after < now() + interval '1 day'
			       or last_seen_at < now() - interval '10 minutes')`).Scan(&degraded)
		if err != nil {
			s.fail(w, err)
			return
		}
		summary.DegradedRelays = &degraded

		// The buffer figures live in the heartbeats the registry keeps in memory, so
		// the relays are listed and each is asked for its latest report.
		if s.relays != nil {
			listed, err := s.relays.List(ctx)
			if err != nil {
				s.fail(w, err)
				return
			}
			reported, high := 0, 0
			for _, relay := range listed {
				if relay.RevokedAt != nil {
					continue
				}
				heartbeat, ok := s.relays.LastHeartbeat(relay.ID)
				if !ok || heartbeat.BufferMaxBytes <= 0 {
					continue
				}
				reported++
				if heartbeat.BufferBytes*100 >= heartbeat.BufferMaxBytes*RelayBufferHighPercent {
					high++
				}
			}
			if reported > 0 {
				summary.RelaysBufferHigh = &high
			}
		}
	}

	// The security events of the lifecycle document that the built-in monitoring
	// cannot watch, because they are not a sample of any host: a duplicate
	// identity is the gateway's finding, and an enrollment refusal has no host.
	if principal.Can(authz.PermAuditRead, authz.GlobalScope) {
		var duplicates, refusals int
		err = s.pool.QueryRow(ctx, `
			select count(*) filter (where action = 'security.duplicate_identity'
			                          and occurred_at >= now() - interval '24 hours'),
			       count(*) filter (where action in ('host.enroll', 'relay.enroll') and outcome = 'denied'
			                          and occurred_at >= now() - interval '1 hour')
			from audit_events
			where occurred_at >= now() - interval '24 hours'
			  and action in ('security.duplicate_identity', 'host.enroll', 'relay.enroll')`).
			Scan(&duplicates, &refusals)
		if err != nil {
			s.fail(w, err)
			return
		}
		summary.DuplicateIdentities24h = &duplicates
		summary.EnrollmentRefusals1h = &refusals
	}

	// The protocol table lives in the binary, not in the database, so the
	// versions are grouped in the database and judged here.
	unsupported := 0
	versions, err := s.pool.Query(ctx, `
		select h.agent_version, h.agent_protocol_min, h.agent_protocol_max, count(*)
		from hosts h
		where h.lifecycle_state <> 'retired'
		  and (h.agent_version ~ '^v?\d+(\.\d+)*' or h.agent_protocol_max is not null)
		  and `+visible+`
		group by 1, 2, 3`, args...)
	if err != nil {
		s.fail(w, err)
		return
	}
	for versions.Next() {
		var version *string
		var protocolMin, protocolMax *int
		var count int
		if err := versions.Scan(&version, &protocolMin, &protocolMax, &count); err != nil {
			versions.Close()
			s.fail(w, err)
			return
		}
		announced := func(value *int) int {
			if value == nil {
				return 0
			}
			return *value
		}
		reported := ""
		if version != nil {
			reported = *version
		}
		if buildinfo.CheckProtocolRange(reported, announced(protocolMin), announced(protocolMax)) != nil {
			unsupported += count
		}
	}
	versions.Close()
	if err := versions.Err(); err != nil {
		s.fail(w, err)
		return
	}
	summary.AgentsUnsupported = &unsupported

	// The firing alerts of the visible hosts, without the silenced ones: a
	// silence is a decision already taken, and the dashboard counts what still
	// waits for one.
	err = s.pool.QueryRow(ctx, `
		select count(*), count(*) filter (where a.severity = 'critical')
		from alerts a join hosts h on h.id = a.host_id
		where a.state = 'firing'
		  and a.acknowledged_at is null
		  and not exists (select 1 from silences s
		                  where s.expired_at is null and s.until > now()
		                    -- A global silence is written for the security alerts;
		                    -- it is not a silence of every alert of every host.
		                    and not s.global
		                    and (s.host_id is null or s.host_id = a.host_id)
		                    and (s.rule_id is null or s.rule_id = a.rule_id))
		  and `+visible, args...).Scan(&summary.AlertsFiring, &summary.AlertsCritical)
	if err != nil {
		s.fail(w, err)
		return
	}
	if err := s.countPendingDecisions(ctx, principal, &summary.PendingDecisions); err != nil {
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
	// single-environment operator does not see the whole fleet.
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
		IdentityDomain:  query.Get("identity_domain"),
		Capability:      query.Get("capability"),
		// The refusal code narrows to the hosts the gateway last turned away for
		// that reason - the dashboard's expired-certificates tile leads here.
		ConnectionRefusal: query.Get("connection_refusal"),
		Scopes:            principal.ScopesFor(authz.PermHostRead),
	}
	// A channel that is not a channel is refused rather than matched to
	// nothing.
	if channel := query.Get("channel"); channel != "" {
		normalized, err := hosts.NormalizeChannel(channel)
		if err != nil {
			problem(w, http.StatusBadRequest, "invalid_filter", err.Error())
			return
		}
		filter.Channel = normalized
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
	// The two "needs attention" filters: a dashboard tile counts the hosts
	// that need a reboot or carry a security update, and leads here.
	if value := query.Get("reboot_required"); value != "" {
		required, err := strconv.ParseBool(value)
		if err != nil {
			problem(w, http.StatusBadRequest, "invalid_filter", "reboot_required must be true or false")
			return
		}
		filter.RebootRequired = &required
	}
	if value := query.Get("security_updates"); value != "" {
		waiting, err := strconv.ParseBool(value)
		if err != nil {
			problem(w, http.StatusBadRequest, "invalid_filter", "security_updates must be true or false")
			return
		}
		filter.SecurityUpdates = &waiting
	}
	if !attentionFilters(w, query, &filter) {
		return
	}
	// The order of the list: one of the columns the store whitelists, ascending
	// unless the value says :desc.
	order, err := hosts.ParseSort(query.Get("sort"))
	if err != nil {
		problem(w, http.StatusBadRequest, "invalid_sort", err.Error())
		return
	}
	filter.Sort = order
	asCSV, ok := exportFormat(w, r)
	if !ok {
		return
	}
	if asCSV {
		s.writeHostsCSV(w, r, filter)
		return
	}
	cursor, err := hosts.ParseCursor(query.Get("cursor"))
	if err != nil {
		problem(w, http.StatusBadRequest, "invalid_cursor", err.Error())
		return
	}
	// A cursor carries the order it was issued under; one handed back with
	// another sort would start the page from a key of the wrong kind.
	if !cursor.Matches(filter.Sort) {
		problem(w, http.StatusBadRequest, "invalid_cursor", "the cursor was issued for another sort order")
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

// hostsCSVColumns is the header of the fleet export. The order is fixed:
// a sheet built against one export reads the next one.
var hostsCSVColumns = []string{
	"hostname", "id", "site", "environment", "owner", "failure_domain", "lifecycle_state",
	"connection_state", "last_seen_at", "os_family", "os_distribution", "os_version", "architecture",
	"agent_version", "release_channel", "management_address", "tags", "reboot_required",
	"failed_units", "pending_updates", "pending_security_updates", "package_database_broken",
	"maintenance_until", "identity_domain", "last_connection_refusal", "enrolled_at",
}

// writeHostsCSV streams the fleet list as a file: the same filter and the same
// scope as the JSON list, every page of it, in the order of the list.
func (s *Server) writeHostsCSV(w http.ResponseWriter, r *http.Request, filter hosts.ListFilter) {
	s.writeCSV(w, r, exportFileName("hosts", time.Now()), hostsCSVColumns, func(yield func([]string) bool) error {
		cursor := hosts.Cursor{}
		for {
			page, err := s.hosts.ListPaged(r.Context(), filter, cursor, maxListPage)
			if err != nil {
				return err
			}
			for _, host := range page.Items {
				if !yield(hostCSVRow(host)) {
					return nil
				}
			}
			if page.NextCursor == "" {
				return nil
			}
			if cursor, err = hosts.ParseCursor(page.NextCursor); err != nil {
				return err
			}
		}
	})
}

// hostCSVRow renders one host in the order of hostsCSVColumns. A fact the
// host has not reported is an empty cell, not a zero or a false.
func hostCSVRow(host hosts.Host) []string {
	maintenance, refusal := "", ""
	if host.Maintenance != nil {
		maintenance = csvInstant(host.Maintenance.Until)
	}
	if host.LastConnectionRefusal != nil {
		refusal = host.LastConnectionRefusal.Code
	}
	return []string{
		host.Hostname, host.ID, host.Site, host.Environment, host.Owner, host.FailureDomain, host.LifecycleState,
		host.ConnectionState, formatTime(host.LastSeenAt), host.OSFamily, host.OSDistribution, host.OSVersion, host.Architecture,
		host.AgentVersion, host.ReleaseChannel, host.ManagementAddress, csvList(host.Tags), csvBool(host.RebootRequired),
		csvInt(host.FailedUnits), csvInt(host.PendingUpdates), csvInt(host.PendingSecurityUpdates), strconv.FormatBool(host.PackageDatabaseBroken),
		maintenance, host.Identity.Domain, refusal, csvInstant(host.EnrolledAt),
	}
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
	// The tag names the version of the hand-recorded facts, so an editor
	// of the owner or the address writes back on what they read.
	setETag(w, hostFactsTag(host))
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

// parseTimeParam reads an optional RFC 3339 query parameter.
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
