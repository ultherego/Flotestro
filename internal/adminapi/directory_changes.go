package adminapi

import (
	"encoding/json"
	"errors"
	"net/http"
	"strconv"

	"github.com/ultherego/flotestro/internal/audit"
	"github.com/ultherego/flotestro/internal/authz"
	"github.com/ultherego/flotestro/internal/identity"
)

type createChangeRequest struct {
	Action           string          `json:"action"`
	Payload          json.RawMessage `json:"payload"`
	RequiresApproval *bool           `json:"requires_approval,omitempty"`
}

// handleCreateDirectoryChange planuje zmiane w katalogu. Samo zlecenie
// niczego nie zmienia: liczy plan i czeka na zatwierdzenie.
func (s *Server) handleCreateDirectoryChange(w http.ResponseWriter, r *http.Request) {
	if s.directory == nil || s.changes == nil || !s.directoryWrite {
		problem(w, http.StatusNotImplemented, "directory_write_disabled",
			"the directory write module is disabled in this installation")
		return
	}

	var request createChangeRequest
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<18)).Decode(&request); err != nil {
		problem(w, http.StatusBadRequest, "invalid_body", "the request body is not valid JSON")
		return
	}

	action := identity.ActionType(request.Action)
	if !action.Known() {
		problem(w, http.StatusBadRequest, "unknown_action", "unknown change type "+request.Action)
		return
	}
	// Zmiana katalogu obejmuje cala flote, wiec wymaga uprawnienia globalnego.
	principal, ok := s.authorize(w, r, authz.Permission(action.Permission()),
		authz.GlobalScope, "directory_change", "")
	if !ok {
		return
	}

	var payload identity.Payload
	if len(request.Payload) > 0 {
		if err := json.Unmarshal(request.Payload, &payload); err != nil {
			problem(w, http.StatusBadRequest, "invalid_payload", "the payload is not valid JSON")
			return
		}
	}
	if err := identity.Validate(action, payload); err != nil {
		problem(w, http.StatusBadRequest, "invalid_payload", err.Error())
		return
	}

	plan, err := identity.NewPlanner(s.directory).Build(r.Context(), action, payload)
	if err != nil {
		problem(w, http.StatusBadGateway, "directory_unavailable", err.Error())
		return
	}

	tx, err := s.changes.Pool().Begin(r.Context())
	if err != nil {
		s.fail(w, err)
		return
	}
	defer func() { _ = tx.Rollback(r.Context()) }()

	requiresApproval := true
	if request.RequiresApproval != nil {
		requiresApproval = *request.RequiresApproval
	}
	change, err := s.changes.Create(r.Context(), tx, identity.Spec{
		Action:           action,
		Payload:          payload,
		Plan:             plan,
		RequiresApproval: requiresApproval,
		CreatedBy:        principal.Subject,
		RequestID:        requestIDOf(r),
	})
	if err != nil {
		problem(w, http.StatusBadRequest, "invalid_change", err.Error())
		return
	}
	if err := s.audit.RecordTx(r.Context(), tx, audit.Event{
		ActorType: audit.ActorUser, ActorID: principal.Subject,
		Action: "directory_change.create", TargetType: "directory_change", TargetID: change.ID,
		RequestID: change.RequestID, Outcome: audit.OutcomeSuccess,
		Detail: map[string]any{
			"action_type": change.ActionType, "payload_hash": change.PayloadHash,
			"conflicts": plan.Conflicts, "warnings": plan.Warnings,
		},
	}); err != nil {
		s.fail(w, err)
		return
	}
	if err := tx.Commit(r.Context()); err != nil {
		s.fail(w, err)
		return
	}
	writeJSON(w, http.StatusCreated, change)
}

// handleApproveDirectoryChange zatwierdza zmiane i dopuszcza ja do wykonania.
func (s *Server) handleApproveDirectoryChange(w http.ResponseWriter, r *http.Request) {
	change, principal, ok := s.changeFor(w, r, authz.PermIdentityPolicyWrite)
	if !ok {
		return
	}

	var request struct {
		PayloadHash string `json:"payload_hash,omitempty"`
	}
	if r.ContentLength > 0 {
		_ = json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<16)).Decode(&request)
	}
	if request.PayloadHash != "" && request.PayloadHash != change.PayloadHash {
		s.audit.Record(r.Context(), audit.Event{
			ActorType: audit.ActorUser, ActorID: principal.Subject,
			Action: "directory_change.approve", TargetType: "directory_change", TargetID: change.ID,
			Outcome: audit.OutcomeDenied, Detail: map[string]any{"reason": "payload_hash_mismatch"},
		})
		problem(w, http.StatusConflict, "payload_hash_mismatch", "the plan changed since you reviewed it")
		return
	}

	// Zmiana w katalogu jest zawsze operacja o podwyzszonym ryzyku, wiec
	// zasada drugiej osoby obowiazuje niezaleznie od srodowiska.
	if change.CreatedBy == principal.Subject {
		s.audit.Record(r.Context(), audit.Event{
			ActorType: audit.ActorUser, ActorID: principal.Subject,
			Action: "directory_change.approve", TargetType: "directory_change", TargetID: change.ID,
			Outcome: audit.OutcomeDenied, Detail: map[string]any{"reason": "self_approval"},
		})
		problem(w, http.StatusForbidden, "self_approval",
			"a directory change must be approved by a second person")
		return
	}

	var plan identity.Plan
	if err := json.Unmarshal(change.Plan, &plan); err == nil && plan.Blocked() {
		problem(w, http.StatusConflict, "plan_blocked",
			"the plan has conflicts: "+joinStrings(plan.Conflicts))
		return
	}

	tx, err := s.changes.Pool().Begin(r.Context())
	if err != nil {
		s.fail(w, err)
		return
	}
	defer func() { _ = tx.Rollback(r.Context()) }()

	approved, err := s.changes.Approve(r.Context(), tx, change.ID, principal.Subject)
	if errors.Is(err, identity.ErrConflict) {
		problem(w, http.StatusConflict, "invalid_state",
			"the change is not awaiting approval (state "+string(change.State)+")")
		return
	}
	if err != nil {
		s.fail(w, err)
		return
	}
	if err := s.audit.RecordTx(r.Context(), tx, audit.Event{
		ActorType: audit.ActorUser, ActorID: principal.Subject,
		Action: "directory_change.approve", TargetType: "directory_change", TargetID: change.ID,
		RequestID: change.RequestID, Outcome: audit.OutcomeSuccess,
		Detail: map[string]any{"action_type": change.ActionType, "created_by": change.CreatedBy},
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

// handleCancelDirectoryChange anuluje zmiane, ktora jeszcze nie ruszyla.
func (s *Server) handleCancelDirectoryChange(w http.ResponseWriter, r *http.Request) {
	change, principal, ok := s.changeFor(w, r, authz.PermIdentityUserWrite)
	if !ok {
		return
	}
	var request struct {
		Reason string `json:"reason,omitempty"`
	}
	if r.ContentLength > 0 {
		_ = json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<16)).Decode(&request)
	}

	canceled, err := s.changes.Cancel(r.Context(), change.ID, principal.Subject, request.Reason)
	if errors.Is(err, identity.ErrConflict) {
		problem(w, http.StatusConflict, "invalid_state",
			"the change cannot be canceled in state "+string(change.State))
		return
	}
	if err != nil {
		s.fail(w, err)
		return
	}
	s.audit.Record(r.Context(), audit.Event{
		ActorType: audit.ActorUser, ActorID: principal.Subject,
		Action: "directory_change.cancel", TargetType: "directory_change", TargetID: change.ID,
		Outcome: audit.OutcomeSuccess, Detail: map[string]any{"reason": request.Reason},
	})
	writeJSON(w, http.StatusOK, canceled)
}

func (s *Server) handleListDirectoryChanges(w http.ResponseWriter, r *http.Request) {
	if _, ok := s.authorize(w, r, authz.PermIdentityRead, authz.GlobalScope, "directory_change", ""); !ok {
		return
	}
	if s.changes == nil {
		writeJSON(w, http.StatusOK, map[string]any{"items": []any{}, "count": 0})
		return
	}
	limit, _ := strconv.Atoi(r.URL.Query().Get("limit"))
	items, err := s.changes.List(r.Context(), r.URL.Query().Get("state"), limit)
	if err != nil {
		s.fail(w, err)
		return
	}
	if items == nil {
		items = []identity.Change{}
	}
	writeJSON(w, http.StatusOK, map[string]any{"items": items, "count": len(items)})
}

func (s *Server) handleGetDirectoryChange(w http.ResponseWriter, r *http.Request) {
	change, _, ok := s.changeFor(w, r, authz.PermIdentityRead)
	if !ok {
		return
	}
	writeJSON(w, http.StatusOK, change)
}

// changeFor wczytuje zmiane i sprawdza uprawnienie.
func (s *Server) changeFor(w http.ResponseWriter, r *http.Request,
	permission authz.Permission) (*identity.Change, authz.Principal, bool) {
	if s.changes == nil || !s.directoryWrite {
		problem(w, http.StatusNotImplemented, "directory_write_disabled",
			"the directory write module is disabled in this installation")
		return nil, authz.Anonymous, false
	}
	principal, ok := s.authorize(w, r, permission, authz.GlobalScope, "directory_change", r.PathValue("id"))
	if !ok {
		return nil, principal, false
	}
	change, err := s.changes.Get(r.Context(), r.PathValue("id"))
	if errors.Is(err, identity.ErrNotFound) {
		problem(w, http.StatusNotFound, "change_not_found", "no such change")
		return nil, principal, false
	}
	if err != nil {
		s.fail(w, err)
		return nil, principal, false
	}
	return change, principal, true
}

func joinStrings(values []string) string {
	result := ""
	for index, value := range values {
		if index > 0 {
			result += "; "
		}
		result += value
	}
	return result
}
