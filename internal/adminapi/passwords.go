package adminapi

import (
	"encoding/json"
	"errors"
	"net/http"
	"strings"

	"github.com/jackc/pgx/v5"

	"github.com/ultherego/flotestro/internal/audit"
	"github.com/ultherego/flotestro/internal/authz"
)

// Who sets a password, and on whom.
//
// An administrator sets one for somebody else and the panel insists the
// owner replaces it: a password two people know is not a password. A person
// changes their own by giving the old one, because a session left open on a
// desk must not be enough to take an account over.

type setPasswordRequest struct {
	Password string `json:"password"`
	// MustChange defaults to true for a password somebody else chose; an
	// administrator setting their own may say otherwise.
	MustChange *bool  `json:"must_change"`
	Reason     string `json:"reason"`
}

func (s *Server) handleSetPassword(w http.ResponseWriter, r *http.Request) {
	actor, ok := s.authorize(w, r, authz.PermPrincipalManage, authz.GlobalScope, "principal", r.PathValue("id"))
	if !ok {
		return
	}
	target, ok := s.principalTarget(w, r)
	if !ok {
		return
	}
	var request setPasswordRequest
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<14)).Decode(&request); err != nil {
		problem(w, http.StatusBadRequest, "invalid_body", "the request body is not valid JSON")
		return
	}
	mustChange := true
	if request.MustChange != nil {
		mustChange = *request.MustChange
	}
	evidence, ok := s.requireStepUp(w, r, actor, request.Reason, "principal.password.set", "principal", target.ID)
	if !ok {
		return
	}

	tx, err := s.authz.Pool().Begin(r.Context())
	if err != nil {
		s.fail(w, err)
		return
	}
	defer func() { _ = tx.Rollback(r.Context()) }()

	if err := s.authz.SetPassword(r.Context(), tx, target.ID, target.Subject,
		request.Password, actor.Subject, mustChange); err != nil {
		if errors.Is(err, authz.ErrWeakPassword) {
			problem(w, http.StatusBadRequest, "weak_password", err.Error())
			return
		}
		s.fail(w, err)
		return
	}
	ended, err := s.endPasswordSessions(r, tx, actor, target.ID, "the password was reset by an administrator")
	if err != nil {
		s.fail(w, err)
		return
	}
	if err := s.audit.RecordTx(r.Context(), tx, audit.Event{
		ActorType: audit.ActorUser, ActorID: actor.Subject,
		Action: "principal.password.set", TargetType: "principal", TargetID: target.ID,
		RequestID: requestIDOf(r), Outcome: audit.OutcomeSuccess,
		// The password itself appears nowhere, here least of all.
		Detail: withStepUp(map[string]any{
			"subject": target.Subject, "must_change": mustChange, "sessions_ended": ended,
		}, evidence),
	}); err != nil {
		s.fail(w, err)
		return
	}
	if err := tx.Commit(r.Context()); err != nil {
		s.fail(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"subject": target.Subject, "must_change": mustChange,
	})
}

// handleClearPassword takes a password away: the identity then signs in
// through the provider, or not at all.
func (s *Server) handleClearPassword(w http.ResponseWriter, r *http.Request) {
	actor, ok := s.authorize(w, r, authz.PermPrincipalManage, authz.GlobalScope, "principal", r.PathValue("id"))
	if !ok {
		return
	}
	target, ok := s.principalTarget(w, r)
	if !ok {
		return
	}
	var request setPasswordRequest
	reason, ok := requestReason(w, r, &request)
	if !ok {
		return
	}
	evidence, ok := s.requireStepUp(w, r, actor, reason, "principal.password.clear", "principal", target.ID)
	if !ok {
		return
	}
	tx, err := s.authz.Pool().Begin(r.Context())
	if err != nil {
		s.fail(w, err)
		return
	}
	defer func() { _ = tx.Rollback(r.Context()) }()

	had, err := s.authz.ClearPassword(r.Context(), tx, target.ID)
	if err != nil {
		s.fail(w, err)
		return
	}
	if !had {
		problem(w, http.StatusNotFound, "no_password", "this identity signs in with no password here")
		return
	}
	ended, err := s.endPasswordSessions(r, tx, actor, target.ID, "the password was removed by an administrator")
	if err != nil {
		s.fail(w, err)
		return
	}
	if err := s.audit.RecordTx(r.Context(), tx, audit.Event{
		ActorType: audit.ActorUser, ActorID: actor.Subject,
		Action: "principal.password.clear", TargetType: "principal", TargetID: target.ID,
		RequestID: requestIDOf(r), Outcome: audit.OutcomeSuccess,
		Detail: withStepUp(map[string]any{"subject": target.Subject, "sessions_ended": ended}, evidence),
	}); err != nil {
		s.fail(w, err)
		return
	}
	if err := tx.Commit(r.Context()); err != nil {
		s.fail(w, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

type changePasswordRequest struct {
	Current string `json:"current"`
	New     string `json:"new"`
}

// handleChangeOwnPassword lets a person replace their own password.
//
// The old one is required even though the session is already theirs: a
// session left open on a desk should not be enough to lock its owner out of
// their own account.
func (s *Server) handleChangeOwnPassword(w http.ResponseWriter, r *http.Request) {
	principal := authz.FromContext(r.Context())
	if !principal.Authenticated() {
		problem(w, http.StatusUnauthorized, "unauthenticated", "changing a password needs a sign-in")
		return
	}
	var request changePasswordRequest
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<14)).Decode(&request); err != nil {
		problem(w, http.StatusBadRequest, "invalid_body", "the request body is not valid JSON")
		return
	}
	if strings.TrimSpace(request.New) == "" {
		problem(w, http.StatusBadRequest, "invalid_body", "the new password is missing")
		return
	}
	if _, err := s.authz.SignInWithPassword(r.Context(), principal.Subject, request.Current); err != nil {
		// The same counting as a sign-in: changing a password is a place to
		// guess the old one, so it costs an attempt like any other.
		s.refusePasswordSignIn(w, r, principal.Subject, err)
		return
	}

	tx, err := s.authz.Pool().Begin(r.Context())
	if err != nil {
		s.fail(w, err)
		return
	}
	defer func() { _ = tx.Rollback(r.Context()) }()

	if err := s.authz.SetPassword(r.Context(), tx, principal.ID, principal.Subject,
		request.New, principal.Subject, false); err != nil {
		if errors.Is(err, authz.ErrWeakPassword) {
			problem(w, http.StatusBadRequest, "weak_password", err.Error())
			return
		}
		s.fail(w, err)
		return
	}
	// The person's other password sessions end with the old password; this
	// one, which just proved it, stays.
	current := ""
	if session, ok := authz.SessionFromContext(r.Context()); ok && session != nil {
		current = session.ID
	}
	ended, err := s.authz.RevokePasswordSessionsOf(r.Context(), tx, principal.ID, current,
		"the password was changed")
	if err != nil {
		s.fail(w, err)
		return
	}
	if err := s.audit.RecordTx(r.Context(), tx, audit.Event{
		ActorType: audit.ActorUser, ActorID: principal.Subject,
		Action: "principal.password.change", TargetType: "principal", TargetID: principal.ID,
		RequestID: requestIDOf(r), Outcome: audit.OutcomeSuccess,
		Detail: map[string]any{"by": "the owner", "other_sessions_ended": ended},
	}); err != nil {
		s.fail(w, err)
		return
	}
	if err := tx.Commit(r.Context()); err != nil {
		s.fail(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"changed": true})
}

// endPasswordSessions ends the password sessions of the identity whose password
// an administrator just set or removed. An administrator changing their own
// password keeps the session they are acting from.
func (s *Server) endPasswordSessions(r *http.Request, tx pgx.Tx, actor authz.Principal, targetID, reason string) (int64, error) {
	keep := ""
	if actor.ID == targetID {
		if session, ok := authz.SessionFromContext(r.Context()); ok && session != nil {
			keep = session.ID
		}
	}
	return s.authz.RevokePasswordSessionsOf(r.Context(), tx, targetID, keep, reason)
}
