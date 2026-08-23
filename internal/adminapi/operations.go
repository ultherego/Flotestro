package adminapi

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/ultherego/flotestro/internal/audit"
	"github.com/ultherego/flotestro/internal/authz"
	agentv1 "github.com/ultherego/flotestro/internal/genproto/flotestro/agent/v1"
	"github.com/ultherego/flotestro/internal/hosts"
	"github.com/ultherego/flotestro/internal/jobs"
	"github.com/ultherego/flotestro/internal/opspec"
)

// createOperationRequest opisuje zlecenie operacji na hoscie.
type createOperationRequest struct {
	Action          string          `json:"action"`
	Payload         json.RawMessage `json:"payload"`
	RequiresApprova *bool           `json:"requires_approval,omitempty"`
	// TargetConfirmation jest nazwa hosta wpisana przez operatora. Wymagana
	// przy operacjach nieodwracalnych.
	TargetConfirmation string `json:"target_confirmation,omitempty"`
	// Reason uzasadnia operacje o najwyzszym ryzyku i trafia do audytu.
	Reason         string `json:"reason,omitempty"`
	TimeoutSeconds int    `json:"timeout_seconds,omitempty"`
	MaxOutputBytes int    `json:"max_output_bytes,omitempty"`
	TTLSeconds     int    `json:"ttl_seconds,omitempty"`
	IdempotencyKey string `json:"idempotency_key,omitempty"`
	// PinBootID wiaze zadanie z obecnym uruchomieniem hosta. Po restarcie
	// zadanie zostanie odrzucone zamiast wykonac sie na innym stanie.
	PinBootID bool `json:"pin_boot_id,omitempty"`
}

// handleCreateOperation tworzy plan operacji. Mutacja domyslnie wymaga
// zatwierdzenia; samo zlecenie niczego jeszcze nie zmienia na hoscie.
func (s *Server) handleCreateOperation(w http.ResponseWriter, r *http.Request) {
	hostID := r.PathValue("id")
	host, scope, ok := s.hostScope(w, r, hostID)
	if !ok {
		return
	}
	principal, ok := s.authorize(w, r, authz.PermJobCreate, scope, "host", hostID)
	if !ok {
		return
	}
	actor := principal.Subject

	var request createOperationRequest
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<18)).Decode(&request); err != nil {
		problem(w, http.StatusBadRequest, "invalid_body", "the request body is not valid JSON")
		return
	}

	action := opspec.ActionType(request.Action)
	if !action.Known() {
		problem(w, http.StatusBadRequest, "unknown_action",
			"unknown operation type; allowed: "+joinActions())
		return
	}

	// Poza prawem zlecania czegokolwiek potrzebne jest uprawnienie tej
	// konkretnej operacji: restart uslugi to inny poziom zaufania niz odczyt
	// dziennika.
	if _, ok := s.authorize(w, r, authz.Permission(action.Permission()), scope, "host", hostID); !ok {
		return
	}

	var payload opspec.Payload
	if len(request.Payload) > 0 {
		if err := json.Unmarshal(request.Payload, &payload); err != nil {
			problem(w, http.StatusBadRequest, "invalid_payload", "the payload is not valid JSON")
			return
		}
	}
	if err := opspec.Validate(action, payload); err != nil {
		problem(w, http.StatusBadRequest, "invalid_payload", err.Error())
		return
	}

	// Host z uszkodzona baza pakietow nie moze dostawac kolejnych operacji
	// pakietowych, dopoki ktos tego nie wyjasni.
	if host.PackageDatabaseBroken && blockedByBrokenDatabase(action) {
		s.audit.Record(r.Context(), audit.Event{
			ActorType: audit.ActorUser, ActorID: actor,
			Action: "job.create", TargetType: "host", TargetID: hostID,
			Outcome: audit.OutcomeDenied,
			Detail:  map[string]any{"reason": "package_database_broken", "action_type": string(action)},
		})
		problem(w, http.StatusConflict, "package_database_broken",
			"the host's package database needs repair; run packages.repair first")
		return
	}

	if host.LifecycleState == "quarantined" {
		s.audit.Record(r.Context(), audit.Event{
			ActorType: audit.ActorUser, ActorID: actor,
			Action: "job.create", TargetType: "host", TargetID: hostID,
			Outcome: audit.OutcomeDenied, Detail: map[string]any{"reason": "quarantined"},
		})
		problem(w, http.StatusConflict, "host_quarantined", "the host is quarantined")
		return
	}

	// Zdolnosc hosta sprawdzamy juz przy planowaniu, zeby nie kolejkowac
	// operacji, ktorej ten host nigdy nie wykona.
	if capability := action.RequiredCapability(); !hostHasCapability(host, capability) {
		problem(w, http.StatusConflict, "capability_missing",
			"the host lacks capability "+capability)
		return
	}

	// Operacja o najwyzszym ryzyku wymaga swiezego uwierzytelnienia: taka,
	// ktora moze odciac dostep do hosta albo skasowac dane, nie moze isc
	// z sesji sprzed godziny.
	var dowodStepUp map[string]any
	if action.RequiresFreshAuth() {
		dowod, ok := s.requireStepUp(w, r, principal, request.Reason,
			string(action), "host", hostID)
		if !ok {
			return
		}
		dowodStepUp = dowod
	}

	// Operacja niszczaca wymaga wpisania nazwy celu. Klikniecie nie jest
	// wystarczajaca decyzja przy zmianie, ktorej nie da sie cofnac - a lista
	// hostow bywa dluga i podobna.
	if action.RequiresTargetConfirmation() && request.TargetConfirmation != host.Hostname {
		s.audit.Record(r.Context(), audit.Event{
			ActorType: audit.ActorUser, ActorID: actor,
			Action: "job.create", TargetType: "host", TargetID: hostID,
			Outcome: audit.OutcomeDenied,
			Detail: map[string]any{
				"reason": "target_confirmation_mismatch", "action": string(action),
			},
		})
		problem(w, http.StatusBadRequest, "target_confirmation_required",
			"this operation is irreversible; repeat the hostname in target_confirmation")
		return
	}

	requiresApproval := action.Mutating()
	if request.RequiresApprova != nil {
		requiresApproval = *request.RequiresApprova
	}

	preconditions := jobs.Preconditions{
		OSFamily:             host.OSFamily,
		RequiredCapabilities: []string{action.RequiredCapability()},
	}
	if request.PinBootID {
		preconditions.ExpectedBootID = host.BootID
	}

	tx, err := s.jobs.Pool().Begin(r.Context())
	if err != nil {
		s.fail(w, err)
		return
	}
	defer func() { _ = tx.Rollback(r.Context()) }()

	job, err := s.jobs.Create(r.Context(), tx, jobs.Spec{
		HostID:          hostID,
		Action:          action,
		Payload:         payload,
		IdempotencyKey:  request.IdempotencyKey,
		RequiresApprova: requiresApproval,
		TimeoutSeconds:  request.TimeoutSeconds,
		MaxOutputBytes:  request.MaxOutputBytes,
		TTL:             time.Duration(request.TTLSeconds) * time.Second,
		CreatedBy:       actor,
		RequestID:       requestIDOf(r),
		Preconditions:   preconditions,
	})
	if err != nil {
		problem(w, http.StatusBadRequest, "invalid_operation", err.Error())
		return
	}

	if err := s.audit.RecordTx(r.Context(), tx, audit.Event{
		ActorType: audit.ActorUser, ActorID: actor,
		Action: "job.create", TargetType: "job", TargetID: job.ID,
		RequestID: job.RequestID, Outcome: audit.OutcomeSuccess,
		Detail: map[string]any{
			"host_id": hostID, "action_type": job.ActionType,
			"payload_hash": job.PayloadHash, "requires_approval": job.RequiresApprova,
			"step_up": dowodStepUp,
			"state":   string(job.State),
		},
	}); err != nil {
		s.fail(w, err)
		return
	}
	if err := tx.Commit(r.Context()); err != nil {
		s.fail(w, err)
		return
	}

	writeJSON(w, http.StatusCreated, job)
}

func (s *Server) handleApproveJob(w http.ResponseWriter, r *http.Request) {
	s.transitionJob(w, r, "approve")
}

func (s *Server) handleCancelJob(w http.ResponseWriter, r *http.Request) {
	s.transitionJob(w, r, "cancel")
}

type transitionRequest struct {
	Reason string `json:"reason,omitempty"`
	// PayloadHash pozwala zatwierdzajacemu potwierdzic, ze zatwierdza dokladnie
	// ten plan, ktory widzial. Niezgodnosc oznacza podmiane miedzy obejrzeniem
	// a zatwierdzeniem.
	PayloadHash string `json:"payload_hash,omitempty"`
}

func (s *Server) transitionJob(w http.ResponseWriter, r *http.Request, operation string) {
	jobID := r.PathValue("id")

	var request transitionRequest
	if r.ContentLength > 0 {
		if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<16)).Decode(&request); err != nil {
			problem(w, http.StatusBadRequest, "invalid_body", "the request body is not valid JSON")
			return
		}
	}

	current, err := s.jobs.Get(r.Context(), jobID)
	if errors.Is(err, jobs.ErrNotFound) {
		problem(w, http.StatusNotFound, "job_not_found", "no such job")
		return
	}
	if err != nil {
		s.fail(w, err)
		return
	}

	scope := s.jobScope(r, current.HostID)
	permission := authz.PermJobApprove
	if operation != "approve" {
		permission = authz.PermJobCancel
	}
	principal, ok := s.authorize(w, r, permission, scope, "job", jobID)
	if !ok {
		return
	}
	actor := principal.Subject

	// Zasada drugiej osoby: w srodowisku produkcyjnym zlecajacy nie moze
	// zatwierdzic wlasnej zmiany. Rozdzial rol nie wystarcza, bo jedna osoba
	// moze miec obie role.
	if operation == "approve" && s.requiresSecondPerson(scope.Environment) && current.CreatedBy == actor {
		s.audit.Record(r.Context(), audit.Event{
			ActorType: audit.ActorUser, ActorID: actor,
			Action: "job.approve", TargetType: "job", TargetID: jobID,
			RequestID: requestIDOf(r), Outcome: audit.OutcomeDenied,
			Detail: map[string]any{
				"reason": "self_approval", "environment": scope.Environment,
				"created_by": current.CreatedBy,
			},
		})
		problem(w, http.StatusForbidden, "self_approval",
			" in environment "+scope.Environment+" changes require approval by a second person")
		return
	}

	if operation == "approve" && request.PayloadHash != "" && request.PayloadHash != current.PayloadHash {
		s.audit.Record(r.Context(), audit.Event{
			ActorType: audit.ActorUser, ActorID: actor,
			Action: "job.approve", TargetType: "job", TargetID: jobID,
			Outcome: audit.OutcomeDenied,
			Detail:  map[string]any{"reason": "payload_hash_mismatch", "expected": current.PayloadHash},
		})
		problem(w, http.StatusConflict, "payload_hash_mismatch",
			"the plan changed since you reviewed it")
		return
	}

	tx, err := s.jobs.Pool().Begin(r.Context())
	if err != nil {
		s.fail(w, err)
		return
	}
	defer func() { _ = tx.Rollback(r.Context()) }()

	var (
		job    *jobs.Job
		action string
	)
	switch operation {
	case "approve":
		action = "job.approve"
		job, err = s.jobs.Approve(r.Context(), tx, jobID, actor)
	default:
		action = "job.cancel"
		job, err = s.jobs.Cancel(r.Context(), tx, jobID, actor, request.Reason)
	}
	if errors.Is(err, jobs.ErrConflict) {
		s.audit.Record(r.Context(), audit.Event{
			ActorType: audit.ActorUser, ActorID: actor,
			Action: action, TargetType: "job", TargetID: jobID,
			Outcome: audit.OutcomeDenied,
			Detail:  map[string]any{"reason": "invalid_state", "state": string(current.State)},
		})
		problem(w, http.StatusConflict, "invalid_state",
			"operation not allowed in state "+string(current.State))
		return
	}
	if err != nil {
		s.fail(w, err)
		return
	}

	if err := s.audit.RecordTx(r.Context(), tx, audit.Event{
		ActorType: audit.ActorUser, ActorID: actor,
		Action: action, TargetType: "job", TargetID: jobID,
		RequestID: job.RequestID, Outcome: audit.OutcomeSuccess,
		Detail: map[string]any{
			"host_id": job.HostID, "action_type": job.ActionType,
			"payload_hash": job.PayloadHash, "state": string(job.State),
			"reason": request.Reason,
		},
	}); err != nil {
		s.fail(w, err)
		return
	}
	if err := tx.Commit(r.Context()); err != nil {
		s.fail(w, err)
		return
	}

	// Anulowanie zapisane w bazie nie zatrzymuje pracy na hoscie. Operacja
	// juz dostarczona trwa dalej - podglad dziennika trzymalby proces przez
	// caly swoj limit czasu, mimo ze nikt juz nie patrzy. Prosba o przerwanie
	// idzie wiec takze do agenta; agent przerwie to, co da sie przerwac
	// bezpiecznie, a reszte odnotuje.
	if operation == "cancel" {
		s.poprosOPrzerwanie(r.Context(), job)
	}

	writeJSON(w, http.StatusOK, job)
}

// requiresSecondPerson mowi, czy srodowisko wymaga zatwierdzenia przez inna
// osobe niz zlecajaca.
func (s *Server) requiresSecondPerson(environment string) bool {
	return s.productionEnvironments[environment]
}

func (s *Server) handleListJobs(w http.ResponseWriter, r *http.Request) {
	principal, ok := s.authorizeCollection(w, r, authz.PermJobRead, "job")
	if !ok {
		return
	}
	limit, _ := strconv.Atoi(r.URL.Query().Get("limit"))
	// Zawezenie robi baza: sprawdzanie zakresu po pobraniu oznaczalo zapytanie
	// o hosta dla kazdego zadania z osobna.
	scopes := principal.ScopesFor(authz.PermJobRead)
	filtr := jobs.ListFilter{
		HostID: r.URL.Query().Get("host_id"),
		State:  r.URL.Query().Get("state"),
		Limit:  limit,
	}
	for _, scope := range scopes {
		filtr.Scopes = append(filtr.Scopes, jobs.Scope{Site: scope.Site, Environment: scope.Environment})
	}
	visible, err := s.jobs.List(r.Context(), filtr)
	if err != nil {
		s.fail(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"items": visible, "count": len(visible)})
}

func (s *Server) handleGetJob(w http.ResponseWriter, r *http.Request) {
	jobID := r.PathValue("id")
	job, err := s.jobs.Get(r.Context(), jobID)
	if errors.Is(err, jobs.ErrNotFound) {
		problem(w, http.StatusNotFound, "job_not_found", "no such job")
		return
	}
	if err != nil {
		s.fail(w, err)
		return
	}
	if _, ok := s.authorize(w, r, authz.PermJobRead, s.jobScope(r, job.HostID), "job", jobID); !ok {
		return
	}
	writeJSON(w, http.StatusOK, job)
}

func (s *Server) handleJobAttempts(w http.ResponseWriter, r *http.Request) {
	jobID := r.PathValue("id")
	job, err := s.jobs.Get(r.Context(), jobID)
	if errors.Is(err, jobs.ErrNotFound) {
		problem(w, http.StatusNotFound, "job_not_found", "no such job")
		return
	}
	if err != nil {
		s.fail(w, err)
		return
	}
	if _, ok := s.authorize(w, r, authz.PermJobRead, s.jobScope(r, job.HostID), "job", jobID); !ok {
		return
	}
	attempts, err := s.jobs.Attempts(r.Context(), jobID)
	if err != nil {
		s.fail(w, err)
		return
	}
	if attempts == nil {
		attempts = []jobs.Attempt{}
	}
	writeJSON(w, http.StatusOK, map[string]any{"items": attempts, "count": len(attempts)})
}

// handleListActions opisuje katalog operacji obslugiwanych przez control plane.
func (s *Server) handleListActions(w http.ResponseWriter, r *http.Request) {
	if principal := authz.FromContext(r.Context()); !principal.Authenticated() {
		w.Header().Set("WWW-Authenticate", `Bearer realm="flotestro"`)
		problem(w, http.StatusUnauthorized, "unauthenticated", "no valid token")
		return
	}
	type actionInfo struct {
		Action             string `json:"action"`
		Mutating           bool   `json:"mutating"`
		RequiredCapability string `json:"required_capability"`
		Permission         string `json:"permission"`
		DefaultTimeout     int    `json:"default_timeout_seconds"`
	}
	items := make([]actionInfo, 0)
	for _, action := range opspec.AllActions() {
		items = append(items, actionInfo{
			Action:             string(action),
			Mutating:           action.Mutating(),
			RequiredCapability: action.RequiredCapability(),
			Permission:         action.Permission(),
			DefaultTimeout:     action.DefaultTimeout(),
		})
	}
	writeJSON(w, http.StatusOK, map[string]any{"items": items, "version": opspec.ActionVersion})
}

// hostHasCapability rozstrzyga wymaganie operacji wobec rejestru adapterow
// hosta. Rozstrzygniecie nalezy do rejestru, a nie do tego pliku: operacja
// podaje wymaganie logiczne, host mowi, jakie ma adaptery.
func hostHasCapability(host *hosts.Host, capability string) bool {
	return host.Capabilities.Spelnia(capability)
}

func joinActions() string {
	result := ""
	for i, action := range opspec.AllActions() {
		if i > 0 {
			result += ", "
		}
		result += string(action)
	}
	return result
}

func requestIDOf(r *http.Request) string {
	return r.Header.Get("X-Request-Id")
}

// blockedByBrokenDatabase mowi, ktore operacje pakietowe nie maja sensu na
// hoscie z uszkodzona baza pakietow.
//
// Naprawa i plan sa z tego wylaczone, i to nie jest wyjatek dla wygody:
// naprawa jest jedynym sposobem wyjscia z tego stanu, wiec zablokowanie jej
// zamykaloby hosta w petli bez wyjscia z poziomu panelu. Plan niczego nie
// zmienia i wlasnie na zablokowanym hoscie jest najbardziej potrzebny, bo
// pokazuje, co blokuje.
func blockedByBrokenDatabase(action opspec.ActionType) bool {
	switch action {
	case opspec.ActionPackageRepair, opspec.ActionPackagePlan:
		return false
	}
	return strings.HasPrefix(string(action), "packages.")
}

// poprosOPrzerwanie wysyla agentowi prosbe o przerwanie trwajacej proby.
//
// Brak sesji nie jest bledem: host moze byc offline, a zadanie i tak jest juz
// anulowane w bazie i nie zostanie dostarczone ponownie.
func (s *Server) poprosOPrzerwanie(ctx context.Context, job *jobs.Job) {
	attemptID, err := s.jobs.LastAttempt(ctx, job.ID)
	if err != nil || attemptID == "" {
		return
	}
	if _, err := s.registry.Dispatch(job.HostID, &agentv1.ServerMessage{
		Payload: &agentv1.ServerMessage_CancelTask{
			CancelTask: &agentv1.CancelTask{
				TaskId: attemptID,
				Reason: "operacja anulowana z panelu",
			},
		},
	}, 5*time.Second); err != nil {
		s.log.Debug("nie wyslano prosby o przerwanie",
			"job_id", job.ID, "host_id", job.HostID, "err", err)
	}
}
