// Package adminapi wystawia publiczne REST API control plane.
// Handlery mapuja zadanie na operacje domenowe i nie zawieraja logiki biznesowej.
package adminapi

import (
	"encoding/json"
	"log/slog"
	"net/http"
	"strconv"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/ultherego/flotestro/internal/audit"
	"github.com/ultherego/flotestro/internal/authz"
	"github.com/ultherego/flotestro/internal/campaigns"
	"github.com/ultherego/flotestro/internal/enrollment"
	"github.com/ultherego/flotestro/internal/freeipa"
	"github.com/ultherego/flotestro/internal/gateway"
	"github.com/ultherego/flotestro/internal/hosts"
	"github.com/ultherego/flotestro/internal/identity"
	"github.com/ultherego/flotestro/internal/inventory"
	"github.com/ultherego/flotestro/internal/jobs"
	"github.com/ultherego/flotestro/internal/metrics"
	"github.com/ultherego/flotestro/internal/oidc"
	"github.com/ultherego/flotestro/internal/pki"
)

// Server grupuje zaleznosci REST API.
type Server struct {
	pool      *pgxpool.Pool
	hosts     *hosts.Store
	inventory *inventory.Store
	jobs      *jobs.Store
	campaigns *campaigns.Store
	tokens    *enrollment.TokenStore
	authz     *authz.Store
	audit     *audit.Recorder
	registry  *gateway.Registry
	oidc      *oidc.Provider
	directory *freeipa.Client
	changes   *identity.Store
	// directoryWrite wlacza modul zmian w katalogu. Domyslnie wylaczony:
	// klient moze chciec samego widoku, a zmiany robic swoimi narzedziami.
	directoryWrite bool
	log            *slog.Logger

	// productionEnvironments wymagaja drugiej osoby przy zatwierdzaniu.
	productionEnvironments map[string]bool
	sessionLimits          authz.SessionLimits
	publicURL              string
	webRoot                string
	// stepUp opisuje warunki operacji o najwiekszym wplywie.
	stepUp stepUpPolicy
	// metrics wystawia stan panelu do monitoringu.
	metrics *metrics.Collector
	// trust pozwala przejrzec i wymienic CA floty.
	trust *pki.Trust
}

// Options zbiera ustawienia serwera API, ktore nie sa zaleznosciami.
type Options struct {
	ProductionEnvironments []string
	SessionIdle            time.Duration
	SessionAbsolute        time.Duration
	// PublicURL jest adresem panelu widocznym dla przegladarki; uzywany przy
	// wylogowaniu i przy decyzji o fladze Secure ciasteczek.
	PublicURL string
	// WebRoot wskazuje katalog ze zbudowanym panelem. Pusty wylacza serwowanie.
	WebRoot string
	// DirectoryWrite wlacza zmiany w katalogu tozsamosci.
	DirectoryWrite bool
	// StepUpMaxAge jest dopuszczalnym wiekiem uwierzytelnienia dla operacji
	// o najwiekszym wplywie. Zero wylacza wymaganie swiezosci.
	StepUpMaxAge time.Duration
	// StepUpACR jest wymaganym poziomem uwierzytelnienia, jesli instalacja
	// go zdefiniowala u dostawcy tozsamosci.
	StepUpACR string
	// Metrics wystawia stan panelu; pusty wylacza endpoint.
	Metrics *metrics.Collector
	// Trust jest zbiorem CA floty; pusty wylacza zarzadzanie PKI.
	Trust *pki.Trust
}

func NewServer(pool *pgxpool.Pool, hostStore *hosts.Store, inventoryStore *inventory.Store,
	jobStore *jobs.Store, campaignStore *campaigns.Store, tokens *enrollment.TokenStore,
	authzStore *authz.Store, recorder *audit.Recorder, registry *gateway.Registry,
	provider *oidc.Provider, directory *freeipa.Client, changes *identity.Store,
	log *slog.Logger, options Options) *Server {
	production := map[string]bool{}
	for _, environment := range options.ProductionEnvironments {
		production[environment] = true
	}
	limits := authz.SessionLimits{Idle: options.SessionIdle, Absolute: options.SessionAbsolute}
	return &Server{pool: pool, hosts: hostStore, inventory: inventoryStore, jobs: jobStore,
		campaigns: campaignStore, tokens: tokens, authz: authzStore, audit: recorder,
		registry: registry, oidc: provider, directory: directory, changes: changes, log: log,
		productionEnvironments: production,
		sessionLimits:          limits, publicURL: options.PublicURL,
		webRoot: options.WebRoot, directoryWrite: options.DirectoryWrite,
		stepUp:  stepUpPolicy{MaxAge: options.StepUpMaxAge, ACR: options.StepUpACR},
		metrics: options.Metrics, trust: options.Trust}
}

// Routes buduje router API.
func (s *Server) Routes() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /healthz", s.handleHealth)
	mux.HandleFunc("GET /api/v1/capabilities", s.handleCapabilities)
	mux.HandleFunc("GET /metrics", s.handleMetrics)
	mux.HandleFunc("GET /api/v1/pki", s.handlePKIStatus)
	mux.HandleFunc("POST /api/v1/pki/prepare", s.handlePrepareCA)
	mux.HandleFunc("POST /api/v1/pki/activate", s.handleActivateCA)
	mux.HandleFunc("DELETE /api/v1/pki/{fingerprint}", s.handleRetireCA)

	// Logowanie operatorow przez dostawce tozsamosci.
	mux.HandleFunc("GET /auth/login", s.handleLogin)
	mux.HandleFunc("GET /auth/callback", s.handleAuthCallback)
	mux.HandleFunc("POST /auth/logout", s.handleLogout)
	mux.HandleFunc("GET /api/v1/fleet/summary", s.handleFleetSummary)
	mux.HandleFunc("GET /api/v1/hosts", s.handleListHosts)
	mux.HandleFunc("GET /api/v1/hosts/{id}", s.handleGetHost)
	mux.HandleFunc("GET /api/v1/hosts/{id}/inventory", s.handleHostInventory)
	mux.HandleFunc("GET /api/v1/hosts/{id}/local-accounts", s.handleHostLocalAccounts)
	mux.HandleFunc("GET /api/v1/hosts/{id}/audit", s.handleHostAudit)
	mux.HandleFunc("GET /api/v1/audit", s.handleAudit)
	mux.HandleFunc("GET /api/v1/enrollment-tokens", s.handleListTokens)
	mux.HandleFunc("POST /api/v1/enrollment-tokens", s.handleCreateToken)

	// Operacje typowane: plan, zatwierdzenie, wykonanie, wynik.
	mux.HandleFunc("GET /api/v1/actions", s.handleListActions)
	mux.HandleFunc("POST /api/v1/hosts/{id}/operations", s.handleCreateOperation)
	mux.HandleFunc("GET /api/v1/jobs", s.handleListJobs)
	mux.HandleFunc("GET /api/v1/jobs/{id}", s.handleGetJob)
	mux.HandleFunc("GET /api/v1/jobs/{id}/attempts", s.handleJobAttempts)
	mux.HandleFunc("POST /api/v1/jobs/{id}/approve", s.handleApproveJob)
	mux.HandleFunc("POST /api/v1/jobs/{id}/cancel", s.handleCancelJob)

	// Kampanie: plan, zatwierdzenie, prowadzenie i raport.
	mux.HandleFunc("GET /api/v1/campaigns", s.handleListCampaigns)
	mux.HandleFunc("POST /api/v1/campaigns", s.handleCreateCampaign)
	mux.HandleFunc("GET /api/v1/campaigns/{id}", s.handleGetCampaign)
	mux.HandleFunc("GET /api/v1/campaigns/{id}/targets", s.handleCampaignTargets)
	mux.HandleFunc("GET /api/v1/campaigns/{id}/report", s.handleCampaignReport)
	mux.HandleFunc("POST /api/v1/campaigns/{id}/approve", s.handleApproveCampaign)
	mux.HandleFunc("POST /api/v1/campaigns/{id}/pause", s.handlePauseCampaign)
	mux.HandleFunc("POST /api/v1/campaigns/{id}/resume", s.handleResumeCampaign)
	mux.HandleFunc("POST /api/v1/campaigns/{id}/cancel", s.handleCancelCampaign)

	// Tozsamosci i tokeny API.
	mux.HandleFunc("GET /api/v1/principals", s.handleListPrincipals)
	mux.HandleFunc("POST /api/v1/principals", s.handleCreatePrincipal)
	mux.HandleFunc("GET /api/v1/whoami", s.handleWhoami)
	mux.HandleFunc("GET /api/v1/roles", s.handleListRoles)
	// Katalog tozsamosci w trybie tylko do odczytu.
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
	// Reguly dostepu i sudo wymagaja osobnego uprawnienia: opisuja, kto moze
	// wejsc na hosta i podniesc uprawnienia.
	mux.HandleFunc("GET /api/v1/identity/hbac-rules", policyHandler(s, "hbac",
		func(s *Server, r *http.Request) ([]freeipa.HBACRule, error) {
			return s.directory.HBACRules(r.Context())
		}))
	mux.HandleFunc("GET /api/v1/identity/sudo-rules", policyHandler(s, "sudo",
		func(s *Server, r *http.Request) ([]freeipa.SudoRule, error) {
			return s.directory.SudoRules(r.Context())
		}))

	// Zmiany w katalogu: plan, zatwierdzenie i wykonanie faza po fazie.
	mux.HandleFunc("GET /api/v1/identity/changes", s.handleListDirectoryChanges)
	mux.HandleFunc("POST /api/v1/identity/changes", s.handleCreateDirectoryChange)
	mux.HandleFunc("GET /api/v1/identity/changes/{id}", s.handleGetDirectoryChange)
	mux.HandleFunc("POST /api/v1/identity/changes/{id}/approve", s.handleApproveDirectoryChange)
	mux.HandleFunc("POST /api/v1/identity/changes/{id}/cancel", s.handleCancelDirectoryChange)

	mux.HandleFunc("GET /api/v1/group-mappings", s.handleListGroupMappings)
	mux.HandleFunc("POST /api/v1/group-mappings", s.handleCreateGroupMapping)
	mux.HandleFunc("DELETE /api/v1/group-mappings/{id}", s.handleDeleteGroupMapping)

	// Panel jest serwowany pod korzeniem; API ma wlasne prefiksy, wiec nie
	// koliduje z trasami przegladarki.
	mux.Handle("/", SPAHandler(s.webRoot))

	// Uwierzytelnienie obejmuje caly router. Autoryzacje robia handlery, bo
	// tylko one znaja zakres celu.
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

// FleetSummary zawiera wylacznie liczby wymagajace decyzji operatora.
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
	// Podsumowanie liczy tylko te hosty, ktore tozsamosc moze widziec.
	// Inaczej pulpit operatora jednego srodowiska pokazywalby cala flote.
	warunek, args := scopeFilter(principal.ScopesFor(authz.PermHostRead))
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
	err := s.pool.QueryRow(r.Context(), query+warunek, args...).Scan(
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
	// Lista jest zawezana do zakresu, w ktorym tozsamosc ma prawo odczytu,
	// zeby operator jednego srodowiska nie widzial calej floty.
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

func (s *Server) handleListTokens(w http.ResponseWriter, r *http.Request) {
	if _, ok := s.authorize(w, r, authz.PermEnrollmentToken, authz.GlobalScope, "enrollment_token", ""); !ok {
		return
	}
	tokens, err := s.tokens.List(r.Context())
	if err != nil {
		s.fail(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"items": tokens, "count": len(tokens)})
}

type createTokenRequest struct {
	Description string `json:"description"`
	Site        string `json:"site"`
	Environment string `json:"environment"`
	// Kind rozstrzyga, co wolno zarejestrowac tym tokenem: agenta czy relay.
	// Puste znaczy agenta, bo taki byl jedyny rodzaj przed wprowadzeniem
	// relayow i istniejaca automatyzacja nie moze przez to przestac dzialac.
	Kind       string `json:"kind"`
	MaxUses    int    `json:"max_uses"`
	TTLMinutes int    `json:"ttl_minutes"`
}

func (s *Server) handleCreateToken(w http.ResponseWriter, r *http.Request) {
	principal, ok := s.authorize(w, r, authz.PermEnrollmentToken, authz.GlobalScope, "enrollment_token", "")
	if !ok {
		return
	}
	var req createTokenRequest
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<16)).Decode(&req); err != nil {
		problem(w, http.StatusBadRequest, "invalid_body", "the request body is not valid JSON")
		return
	}
	if req.Site == "" {
		req.Site = "default"
	}
	if req.Environment == "" {
		req.Environment = "unassigned"
	}
	if req.TTLMinutes <= 0 {
		req.TTLMinutes = 60
	}

	token, err := s.tokens.Create(r.Context(), req.Description, req.Site, req.Environment,
		req.Kind, req.MaxUses, time.Duration(req.TTLMinutes)*time.Minute, principal.Subject)
	if err != nil {
		problem(w, http.StatusBadRequest, "invalid_kind", err.Error())
		return
	}
	s.audit.Record(r.Context(), audit.Event{
		ActorType: audit.ActorUser, ActorID: principal.Subject,
		Action: "enrollment_token.create", TargetType: "enrollment_token", TargetID: token.ID,
		Outcome: audit.OutcomeSuccess,
		Detail: map[string]any{
			"site": token.Site, "environment": token.Environment, "max_uses": token.MaxUses,
		},
	})
	// Wartosc tokenu jest widoczna wylacznie w tej odpowiedzi.
	writeJSON(w, http.StatusCreated, token)
}

func (s *Server) fail(w http.ResponseWriter, err error) {
	s.log.Error("blad obslugi zadania API", "err", err)
	problem(w, http.StatusInternalServerError, "internal_error", "internal error")
}

func writeJSON(w http.ResponseWriter, status int, body any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(body)
}

// problem zwraca blad w formacie Problem Details ze stabilnym kodem maszynowym.
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
