package adminapi

import (
	"encoding/json"
	"errors"
	"net/http"
	"strconv"
	"time"

	"github.com/ultherego/flotestro/internal/audit"
	"github.com/ultherego/flotestro/internal/authz"
	"github.com/ultherego/flotestro/internal/campaigns"
	"github.com/ultherego/flotestro/internal/hosts"
	"github.com/ultherego/flotestro/internal/opspec"
)

type createCampaignRequest struct {
	Name     string          `json:"name"`
	Action   string          `json:"action"`
	Payload  json.RawMessage `json:"payload"`
	Selector struct {
		Site        string   `json:"site,omitempty"`
		Environment string   `json:"environment,omitempty"`
		OSFamily    string   `json:"os_family,omitempty"`
		HostIDs     []string `json:"host_ids,omitempty"`
	} `json:"selector"`
	CanarySize               *int       `json:"canary_size,omitempty"`
	WaveSize                 *int       `json:"wave_size,omitempty"`
	MaxConcurrent            *int       `json:"max_concurrent,omitempty"`
	FailureThresholdPercent  *int       `json:"failure_threshold_percent,omitempty"`
	FailureThresholdAbsolute *int       `json:"failure_threshold_absolute,omitempty"`
	MaintenanceStart         *time.Time `json:"maintenance_start,omitempty"`
	MaintenanceEnd           *time.Time `json:"maintenance_end,omitempty"`
	RebootPolicy             string     `json:"reboot_policy,omitempty"`
	HealthCheckUnits         []string   `json:"health_check_units,omitempty"`
	JobTimeoutSeconds        *int       `json:"job_timeout_seconds,omitempty"`
	RequiresApproval         *bool      `json:"requires_approval,omitempty"`
}

// handleCreateCampaign planuje kampanie. Selektor jest natychmiast zamieniany
// na niemutowalna migawke hostow; samo utworzenie niczego nie zmienia.
func (s *Server) handleCreateCampaign(w http.ResponseWriter, r *http.Request) {
	var request createCampaignRequest
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<18)).Decode(&request); err != nil {
		problem(w, http.StatusBadRequest, "invalid_body", "cialo zadania nie jest poprawnym JSON")
		return
	}

	action := opspec.ActionType(request.Action)
	if !action.Known() || !action.Mutating() {
		problem(w, http.StatusBadRequest, "unknown_action",
			"kampania wymaga operacji zmieniajacej stan hosta")
		return
	}

	var payload opspec.Payload
	if len(request.Payload) > 0 {
		if err := json.Unmarshal(request.Payload, &payload); err != nil {
			problem(w, http.StatusBadRequest, "invalid_payload", "payload nie jest poprawnym JSON")
			return
		}
	}
	if err := opspec.Validate(action, payload); err != nil {
		problem(w, http.StatusBadRequest, "invalid_payload", err.Error())
		return
	}

	selector := campaigns.Selector{
		Site:        request.Selector.Site,
		Environment: request.Selector.Environment,
		OSFamily:    request.Selector.OSFamily,
		HostIDs:     request.Selector.HostIDs,
	}
	candidates, err := s.resolveTargets(r, selector)
	if err != nil {
		s.fail(w, err)
		return
	}
	if len(candidates) == 0 {
		problem(w, http.StatusBadRequest, "no_targets", "selektor nie wskazal zadnego hosta")
		return
	}

	// Uprawnienie sprawdzamy dla kazdego hosta z migawki. Kampania obejmujaca
	// jeden host poza zakresem nie moze przejsc dlatego, ze reszta jest w nim.
	principal := authz.FromContext(r.Context())
	for _, host := range candidates {
		scope := authz.Scope{Site: host.Site, Environment: host.Environment}
		if _, ok := s.authorize(w, r, authz.PermCampaignCreate, scope, "host", host.ID); !ok {
			return
		}
		if _, ok := s.authorize(w, r, authz.Permission(action.Permission()), scope, "host", host.ID); !ok {
			return
		}
	}

	spec := campaigns.Spec{
		Name:                     request.Name,
		ActionType:               string(action),
		Payload:                  request.Payload,
		Selector:                 selector,
		CanarySize:               valueOr(request.CanarySize, 1),
		WaveSize:                 valueOr(request.WaveSize, 10),
		MaxConcurrent:            valueOr(request.MaxConcurrent, 5),
		FailureThresholdPercent:  valueOr(request.FailureThresholdPercent, 20),
		FailureThresholdAbsolute: valueOr(request.FailureThresholdAbsolute, 0),
		MaintenanceStart:         request.MaintenanceStart,
		MaintenanceEnd:           request.MaintenanceEnd,
		RebootPolicy:             campaigns.RebootPolicy(orDefault(request.RebootPolicy, "never")),
		HealthCheckUnits:         request.HealthCheckUnits,
		JobTimeoutSeconds:        valueOr(request.JobTimeoutSeconds, action.DefaultTimeout()),
		RequiresApproval:         request.RequiresApproval == nil || *request.RequiresApproval,
		CreatedBy:                principal.Subject,
		RequestID:                requestIDOf(r),
	}

	targets := make([]campaigns.TargetHost, 0, len(candidates))
	for _, host := range candidates {
		targets = append(targets, campaigns.TargetHost{ID: host.ID, BootID: host.BootID})
	}

	tx, err := s.campaigns.Pool().Begin(r.Context())
	if err != nil {
		s.fail(w, err)
		return
	}
	defer func() { _ = tx.Rollback(r.Context()) }()

	campaign, err := s.campaigns.Create(r.Context(), tx, spec, targets)
	if err != nil {
		problem(w, http.StatusBadRequest, "invalid_campaign", err.Error())
		return
	}
	if err := s.audit.RecordTx(r.Context(), tx, audit.Event{
		ActorType: audit.ActorUser, ActorID: principal.Subject,
		Action: "campaign.create", TargetType: "campaign", TargetID: campaign.ID,
		RequestID: campaign.RequestID, Outcome: audit.OutcomeSuccess,
		Detail: map[string]any{
			"name": campaign.Name, "action_type": campaign.ActionType,
			"targets": len(targets), "canary_size": campaign.CanarySize,
			"wave_size": campaign.WaveSize, "reboot_policy": string(campaign.RebootPolicy),
		},
	}); err != nil {
		s.fail(w, err)
		return
	}
	if err := tx.Commit(r.Context()); err != nil {
		s.fail(w, err)
		return
	}
	writeJSON(w, http.StatusCreated, campaign)
}

// resolveTargets zamienia selektor na liste hostow.
func (s *Server) resolveTargets(r *http.Request, selector campaigns.Selector) ([]hosts.Host, error) {
	if len(selector.HostIDs) > 0 {
		result := make([]hosts.Host, 0, len(selector.HostIDs))
		for _, hostID := range selector.HostIDs {
			host, err := s.hosts.Get(r.Context(), hostID)
			if errors.Is(err, hosts.ErrNotFound) {
				continue
			}
			if err != nil {
				return nil, err
			}
			result = append(result, *host)
		}
		return result, nil
	}
	return s.hosts.List(r.Context(), hosts.ListFilter{
		Site:        selector.Site,
		Environment: selector.Environment,
		OSFamily:    selector.OSFamily,
		Limit:       500,
	})
}

func (s *Server) handleListCampaigns(w http.ResponseWriter, r *http.Request) {
	if _, ok := s.authorize(w, r, authz.PermCampaignRead, authz.GlobalScope, "campaign", ""); !ok {
		return
	}
	limit, _ := strconv.Atoi(r.URL.Query().Get("limit"))
	items, err := s.campaigns.List(r.Context(), r.URL.Query().Get("state"), limit)
	if err != nil {
		s.fail(w, err)
		return
	}
	if items == nil {
		items = []campaigns.Campaign{}
	}
	writeJSON(w, http.StatusOK, map[string]any{"items": items, "count": len(items)})
}

func (s *Server) handleGetCampaign(w http.ResponseWriter, r *http.Request) {
	campaign, ok := s.campaignFor(w, r, authz.PermCampaignRead)
	if !ok {
		return
	}
	writeJSON(w, http.StatusOK, campaign)
}

func (s *Server) handleCampaignTargets(w http.ResponseWriter, r *http.Request) {
	campaign, ok := s.campaignFor(w, r, authz.PermCampaignRead)
	if !ok {
		return
	}
	targets, err := s.campaigns.Targets(r.Context(), campaign.ID)
	if err != nil {
		s.fail(w, err)
		return
	}
	if targets == nil {
		targets = []campaigns.Target{}
	}
	writeJSON(w, http.StatusOK, map[string]any{"items": targets, "count": len(targets)})
}

// handleCampaignReport buduje raport koncowy: wersje stanu, podzial na fale
// i liste hostow, ktore wymagaja uwagi.
func (s *Server) handleCampaignReport(w http.ResponseWriter, r *http.Request) {
	campaign, ok := s.campaignFor(w, r, authz.PermCampaignRead)
	if !ok {
		return
	}
	targets, err := s.campaigns.Targets(r.Context(), campaign.ID)
	if err != nil {
		s.fail(w, err)
		return
	}

	report := campaigns.Report{
		CampaignID: campaign.ID,
		State:      campaign.State,
		Totals:     map[string]int{},
		Failures:   []campaigns.Target{},
	}
	waveTotals := map[int]map[string]int{}
	waveOpen := map[int]bool{}
	for _, target := range targets {
		report.Totals[string(target.State)]++
		if waveTotals[target.Wave] == nil {
			waveTotals[target.Wave] = map[string]int{}
		}
		waveTotals[target.Wave][string(target.State)]++
		if !target.State.Finished() {
			waveOpen[target.Wave] = true
		}
		if target.State == campaigns.TargetFailed {
			report.Failures = append(report.Failures, target)
		}
		if target.State == campaigns.TargetRebooting || target.State == campaigns.TargetVerifying {
			report.RebootPending = append(report.RebootPending, target.HostID)
		}
	}
	for wave := 0; wave < len(waveTotals); wave++ {
		totals, exists := waveTotals[wave]
		if !exists {
			continue
		}
		report.Waves = append(report.Waves, campaigns.WaveSummary{
			Wave:      wave,
			IsCanary:  wave == 0,
			Totals:    totals,
			Completed: !waveOpen[wave],
		})
	}
	writeJSON(w, http.StatusOK, report)
}

func (s *Server) handleApproveCampaign(w http.ResponseWriter, r *http.Request) {
	campaign, ok := s.campaignFor(w, r, authz.PermCampaignApprove)
	if !ok {
		return
	}
	principal := authz.FromContext(r.Context())

	// Zasada drugiej osoby obowiazuje takze kampanie, i to tym bardziej:
	// jedno zatwierdzenie uruchamia zmiane na wielu hostach.
	if s.campaignNeedsSecondPerson(r, campaign) && campaign.CreatedBy == principal.Subject {
		s.audit.Record(r.Context(), audit.Event{
			ActorType: audit.ActorUser, ActorID: principal.Subject,
			Action: "campaign.approve", TargetType: "campaign", TargetID: campaign.ID,
			Outcome: audit.OutcomeDenied, Detail: map[string]any{"reason": "self_approval"},
		})
		problem(w, http.StatusForbidden, "self_approval",
			"kampanie produkcyjna musi zatwierdzic druga osoba")
		return
	}

	tx, err := s.campaigns.Pool().Begin(r.Context())
	if err != nil {
		s.fail(w, err)
		return
	}
	defer func() { _ = tx.Rollback(r.Context()) }()

	approved, err := s.campaigns.Approve(r.Context(), tx, campaign.ID, principal.Subject)
	if errors.Is(err, campaigns.ErrConflict) {
		problem(w, http.StatusConflict, "invalid_state",
			"kampania nie oczekuje na zatwierdzenie (stan "+string(campaign.State)+")")
		return
	}
	if err != nil {
		s.fail(w, err)
		return
	}
	if err := s.audit.RecordTx(r.Context(), tx, audit.Event{
		ActorType: audit.ActorUser, ActorID: principal.Subject,
		Action: "campaign.approve", TargetType: "campaign", TargetID: campaign.ID,
		RequestID: campaign.RequestID, Outcome: audit.OutcomeSuccess,
		Detail: map[string]any{"name": campaign.Name, "created_by": campaign.CreatedBy},
	}); err != nil {
		s.fail(w, err)
		return
	}
	if err := tx.Commit(r.Context()); err != nil {
		s.fail(w, err)
		return
	}
	writeJSON(w, http.StatusOK, approved)
}

func (s *Server) handlePauseCampaign(w http.ResponseWriter, r *http.Request) {
	s.controlCampaign(w, r, "pause")
}

func (s *Server) handleResumeCampaign(w http.ResponseWriter, r *http.Request) {
	s.controlCampaign(w, r, "resume")
}

func (s *Server) handleCancelCampaign(w http.ResponseWriter, r *http.Request) {
	s.controlCampaign(w, r, "cancel")
}

func (s *Server) controlCampaign(w http.ResponseWriter, r *http.Request, operation string) {
	campaign, ok := s.campaignFor(w, r, authz.PermCampaignControl)
	if !ok {
		return
	}
	principal := authz.FromContext(r.Context())

	var request struct {
		Reason string `json:"reason,omitempty"`
	}
	if r.ContentLength > 0 {
		_ = json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<16)).Decode(&request)
	}

	var (
		updated *campaigns.Campaign
		err     error
	)
	switch operation {
	case "pause":
		updated, err = s.campaigns.Pause(r.Context(), campaign.ID, principal.Subject, request.Reason)
	case "resume":
		updated, err = s.campaigns.Resume(r.Context(), campaign.ID, principal.Subject)
	default:
		updated, err = s.campaigns.Cancel(r.Context(), campaign.ID, principal.Subject, request.Reason)
	}
	if errors.Is(err, campaigns.ErrConflict) {
		problem(w, http.StatusConflict, "invalid_state",
			"operacja niedozwolona w stanie "+string(campaign.State))
		return
	}
	if err != nil {
		s.fail(w, err)
		return
	}

	s.audit.Record(r.Context(), audit.Event{
		ActorType: audit.ActorUser, ActorID: principal.Subject,
		Action: "campaign." + operation, TargetType: "campaign", TargetID: campaign.ID,
		RequestID: campaign.RequestID, Outcome: audit.OutcomeSuccess,
		Detail: map[string]any{"reason": request.Reason, "state": string(updated.State)},
	})
	writeJSON(w, http.StatusOK, updated)
}

// campaignFor wczytuje kampanie i sprawdza uprawnienie w zakresie jej celow.
func (s *Server) campaignFor(w http.ResponseWriter, r *http.Request,
	permission authz.Permission) (*campaigns.Campaign, bool) {
	campaignID := r.PathValue("id")
	campaign, err := s.campaigns.Get(r.Context(), campaignID)
	if errors.Is(err, campaigns.ErrNotFound) {
		problem(w, http.StatusNotFound, "campaign_not_found", "kampania nie istnieje")
		return nil, false
	}
	if err != nil {
		s.fail(w, err)
		return nil, false
	}

	scope, err := s.campaignScope(r, campaign.ID)
	if err != nil {
		s.fail(w, err)
		return nil, false
	}
	if _, ok := s.authorize(w, r, permission, scope, "campaign", campaignID); !ok {
		return nil, false
	}
	return campaign, true
}

// campaignScope zwraca zakres obejmujacy wszystkie cele kampanii. Gdy cele leza
// w roznych zakresach, wymagane jest uprawnienie globalne: kampania jest
// operacja na calej wskazanej czesci floty.
func (s *Server) campaignScope(r *http.Request, campaignID string) (authz.Scope, error) {
	targets, err := s.campaigns.Targets(r.Context(), campaignID)
	if err != nil {
		return authz.Scope{}, err
	}
	scope := authz.Scope{}
	for index, target := range targets {
		host, err := s.hosts.Get(r.Context(), target.HostID)
		if err != nil {
			continue
		}
		if index == 0 {
			scope = authz.Scope{Site: host.Site, Environment: host.Environment}
			continue
		}
		if scope.Site != host.Site {
			scope.Site = authz.Wildcard
		}
		if scope.Environment != host.Environment {
			scope.Environment = authz.Wildcard
		}
	}
	return scope, nil
}

// campaignNeedsSecondPerson mowi, czy kampania dotyka srodowiska produkcyjnego.
func (s *Server) campaignNeedsSecondPerson(r *http.Request, campaign *campaigns.Campaign) bool {
	targets, err := s.campaigns.Targets(r.Context(), campaign.ID)
	if err != nil {
		// Brak wiedzy o celach nie moze oslabiac kontroli.
		return true
	}
	for _, target := range targets {
		host, err := s.hosts.Get(r.Context(), target.HostID)
		if err != nil {
			continue
		}
		if s.requiresSecondPerson(host.Environment) {
			return true
		}
	}
	return false
}

func valueOr(value *int, fallback int) int {
	if value == nil || *value <= 0 {
		return fallback
	}
	return *value
}

func orDefault(value, fallback string) string {
	if value == "" {
		return fallback
	}
	return value
}
