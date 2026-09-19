package adminapi

import (
	"encoding/json"
	"errors"
	"net/http"
	"strconv"
	"strings"

	"github.com/ultherego/flotestro/internal/audit"
	"github.com/ultherego/flotestro/internal/authz"
	"github.com/ultherego/flotestro/internal/identity"
)

type createChangeRequest struct {
	Action           string          `json:"action"`
	Payload          json.RawMessage `json:"payload"`
	RequiresApproval *bool           `json:"requires_approval,omitempty"`
	// Reason is required for a change of access: it is part of the
	// evidence recorded with the fresh authentication.
	Reason string `json:"reason,omitempty"`
}

// handleCreateDirectoryChange plans a change in the directory. The order
// itself changes nothing: it computes the plan and waits for approval.
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
	// A directory change covers the whole fleet, so it requires the global
	// permission.
	principal, ok := s.authorize(w, r, authz.Permission(action.Permission()),
		authz.GlobalScope, "directory_change", "")
	if !ok {
		return
	}

	// A change of access in the directory reaches every host that trusts it, so
	// it is taken with fresh authentication, like the same change on one host -
	// and all the more.
	var stepUpEvidence map[string]any
	if action.ChangesAccess() {
		evidence, ok := s.requireStepUp(w, r, principal, request.Reason,
			"directory_change.create", "directory_change", "")
		if !ok {
			return
		}
		stepUpEvidence = evidence
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

	// A directory change reaches every host that trusts the directory; it
	// is always approved by a second person, and a request cannot waive it.
	requiresApproval := true
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
		Detail: withStepUp(map[string]any{
			"action_type": change.ActionType, "payload_hash": change.PayloadHash,
			"conflicts": plan.Conflicts, "warnings": plan.Warnings,
			"reason": strings.TrimSpace(request.Reason),
		}, stepUpEvidence),
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

// handleApproveDirectoryChange approves the change and admits it for
// execution.
func (s *Server) handleApproveDirectoryChange(w http.ResponseWriter, r *http.Request) {
	change, principal, ok := s.changeFor(w, r, authz.PermIdentityPolicyWrite)
	if !ok {
		return
	}

	var request struct {
		PayloadHash string `json:"payload_hash,omitempty"`
		Reason      string `json:"reason,omitempty"`
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

	// A directory change is always an elevated-risk operation, so the
	// second-person rule binds regardless of the environment.
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

	// The consent is what admits the change, so the fresh authentication
	// belongs immediately before it.
	var stepUpEvidence map[string]any
	if identity.ActionType(change.ActionType).ChangesAccess() {
		evidence, ok := s.requireStepUp(w, r, principal, request.Reason,
			"directory_change.approve", "directory_change", change.ID)
		if !ok {
			return
		}
		stepUpEvidence = evidence
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
		Detail: withStepUp(map[string]any{
			"action_type": change.ActionType, "created_by": change.CreatedBy,
			"reason": strings.TrimSpace(request.Reason),
		}, stepUpEvidence),
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

// handleCancelDirectoryChange cancels a change that has not started yet.
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
	principal, ok := s.authorize(w, r, authz.PermIdentityRead, authz.GlobalScope, "directory_change", "")
	if !ok {
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
	// Whether a one-time value waits is told to its requester alone.
	for index := range items {
		items[index].SecretAvailable = s.changes.SecretWaiting(items[index].ID, principal.Subject)
	}
	writeJSON(w, http.StatusOK, map[string]any{"items": items, "count": len(items)})
}

func (s *Server) handleGetDirectoryChange(w http.ResponseWriter, r *http.Request) {
	change, principal, ok := s.changeFor(w, r, authz.PermIdentityRead)
	if !ok {
		return
	}
	// Whether a one-time value waits is told to its requester alone; for
	// anybody else the flag stays down, as if there were nothing.
	change.SecretAvailable = s.changes.SecretWaiting(change.ID, principal.Subject)
	writeJSON(w, http.StatusOK, change)
}

// handleRevealDirectoryChangeSecret hands the one-time value of a change - the
// password the directory generated on a reset - to the person who ordered the
// change, once.
func (s *Server) handleRevealDirectoryChangeSecret(w http.ResponseWriter, r *http.Request) {
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
	if change.CreatedBy != principal.Subject {
		s.audit.Record(r.Context(), audit.Event{
			ActorType: audit.ActorUser, ActorID: principal.Subject,
			Action: "directory_change.reveal", TargetType: "directory_change", TargetID: change.ID,
			Outcome: audit.OutcomeDenied, Detail: map[string]any{"reason": "not_requester"},
		})
		problem(w, http.StatusForbidden, "not_requester",
			"the one-time value of a change is read by the person who ordered it")
		return
	}
	if identity.ActionType(change.ActionType) != identity.ActionUserPasswordReset {
		problem(w, http.StatusNotFound, "no_secret", "this change has no one-time value")
		return
	}
	// Reading a password is a change of access in its own right: it is
	// taken with the same fresh authentication and reason as ordering it.
	evidence, ok := s.requireStepUp(w, r, principal, request.Reason,
		"directory_change.reveal", "directory_change", change.ID)
	if !ok {
		return
	}

	value, handedOut, consumed := s.changes.TakeSecret(change.ID, principal.Subject)
	if consumed {
		problem(w, http.StatusGone, "secret_consumed",
			"the one-time value was already read; order a new reset for a new one")
		return
	}
	if !handedOut {
		problem(w, http.StatusNotFound, "no_secret",
			"no one-time value waits for this change: it was not carried out yet, it failed, or the value went away with its deadline or a restart of the panel")
		return
	}

	var payload identity.Payload
	uid := ""
	if err := json.Unmarshal(change.Payload, &payload); err == nil && payload.Reference != nil {
		uid = payload.Reference.UID
	}
	s.audit.Record(r.Context(), audit.Event{
		ActorType: audit.ActorUser, ActorID: principal.Subject,
		Action: "directory_change.reveal", TargetType: "directory_change", TargetID: change.ID,
		RequestID: requestIDOf(r), Outcome: audit.OutcomeSuccess,
		Detail: withStepUp(map[string]any{
			"action_type": change.ActionType, "uid": uid,
			"reason": strings.TrimSpace(request.Reason),
		}, evidence),
	})
	// The value goes out once and is not cached anywhere on the way.
	w.Header().Set("Cache-Control", "no-store")
	writeJSON(w, http.StatusOK, map[string]any{
		"uid":                    uid,
		"one_time_password":      value,
		"expires_on_first_login": true,
	})
}

// changeFor loads the change and checks the permission.
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
