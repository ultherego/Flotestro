package adminapi

import (
	"errors"
	"net/http"

	"github.com/ultherego/flotestro/internal/audit"
	"github.com/ultherego/flotestro/internal/authz"
	"github.com/ultherego/flotestro/internal/hosts"
)

// authorize checks the permission in the target scope.
func (s *Server) authorize(w http.ResponseWriter, r *http.Request, permission authz.Permission,
	scope authz.Scope, targetType, targetID string) (authz.Principal, bool) {
	principal := authz.FromContext(r.Context())

	if !principal.Authenticated() {
		s.audit.Record(r.Context(), audit.Event{
			ActorType: audit.ActorUser, ActorID: "anonymous",
			Action: string(permission), TargetType: targetType, TargetID: targetID,
			RequestID: requestIDOf(r), Outcome: audit.OutcomeDenied,
			Detail: map[string]any{"reason": "unauthenticated", "path": r.URL.Path},
		})
		w.Header().Set("WWW-Authenticate", `Bearer realm="flotestro"`)
		problem(w, http.StatusUnauthorized, "unauthenticated",
			"a token is required; header Authorization: Bearer <token>")
		return principal, false
	}

	if !principal.Can(permission, scope) {
		s.audit.Record(r.Context(), audit.Event{
			ActorType: audit.ActorUser, ActorID: principal.Subject,
			Action: string(permission), TargetType: targetType, TargetID: targetID,
			RequestID: requestIDOf(r), Outcome: audit.OutcomeDenied,
			Detail: map[string]any{
				"reason": "permission_denied", "permission": string(permission),
				"scope": scope.String(), "roles": principal.Roles(),
			},
		})
		problem(w, http.StatusForbidden, "permission_denied",
			"missing permission "+string(permission)+" in scope "+scope.String())
		return principal, false
	}
	return principal, true
}

// authorizeCollection authorises reading a collection that has no single
// scope: the lists of hosts, tasks, campaigns or the fleet summary.
func (s *Server) authorizeCollection(w http.ResponseWriter, r *http.Request,
	permission authz.Permission, targetType string) (authz.Principal, bool) {
	principal := authz.FromContext(r.Context())

	if !principal.Authenticated() {
		s.audit.Record(r.Context(), audit.Event{
			ActorType: audit.ActorUser, ActorID: "anonymous",
			Action: string(permission), TargetType: targetType,
			RequestID: requestIDOf(r), Outcome: audit.OutcomeDenied,
			Detail: map[string]any{"reason": "unauthenticated", "path": r.URL.Path},
		})
		w.Header().Set("WWW-Authenticate", `Bearer realm="flotestro"`)
		problem(w, http.StatusUnauthorized, "unauthenticated",
			"a token is required; header Authorization: Bearer <token>")
		return principal, false
	}

	if !principal.CanAnywhere(permission) {
		s.audit.Record(r.Context(), audit.Event{
			ActorType: audit.ActorUser, ActorID: principal.Subject,
			Action: string(permission), TargetType: targetType,
			RequestID: requestIDOf(r), Outcome: audit.OutcomeDenied,
			Detail: map[string]any{
				"reason": "permission_denied", "permission": string(permission),
				"roles": principal.Roles(),
			},
		})
		problem(w, http.StatusForbidden, "permission_denied",
			"missing permission "+string(permission)+" in any scope")
		return principal, false
	}
	return principal, true
}

// hostScope returns the authorisation scope of a host. A host that does not
// exist cannot be the target of any operation.
func (s *Server) hostScope(w http.ResponseWriter, r *http.Request, hostID string) (*hosts.Host, authz.Scope, bool) {
	host, err := s.hosts.Get(r.Context(), hostID)
	if errors.Is(err, hosts.ErrNotFound) {
		problem(w, http.StatusNotFound, "host_not_found", "no such host")
		return nil, authz.Scope{}, false
	}
	if err != nil {
		s.fail(w, err)
		return nil, authz.Scope{}, false
	}
	return host, hosts.ScopeOf(host), true
}

// jobScope returns the authorisation scope of a task, that is the scope of
// the host the task concerns.
func (s *Server) jobScope(r *http.Request, hostID string) authz.Scope {
	host, err := s.hosts.Get(r.Context(), hostID)
	if err != nil {
		// An unknown scope cannot be matched by a narrow binding, so an empty
		// scope is a safe default.
		return authz.Scope{}
	}
	return hosts.ScopeOf(host)
}

// beganChange writes the beginning of a change and commits it, before anything
// happens. It answers false when the change must not be made: with no entry
// nobody could say afterwards who began what, and a change to what the fleet
// trusts cannot be undone.
//
// The key is the caller's, so that a retry of a request whose answer was lost
// does not make the change a second time. It is required for exactly that
// reason: a beginning nobody can recognise again is not idempotent.
func (s *Server) beganChange(w http.ResponseWriter, r *http.Request, event audit.Event,
	body string) (string, bool) {
	key := idempotencyKeyOf(r, body)
	if key == "" {
		problem(w, http.StatusBadRequest, "idempotency_key_required",
			"this change needs an Idempotency-Key header (or an idempotency_key field): "+
				"it is what tells a repeated request from a second change")
		return "", false
	}
	if event.Detail == nil {
		event.Detail = map[string]any{}
	}
	event.Detail[audit.IntentKey] = key
	err := s.audit.RecordIntent(r.Context(), event)
	switch {
	case errors.Is(err, audit.ErrIntentExists):
		problem(w, http.StatusConflict, "change_already_started",
			"a change has already begun under this key; read the state of the installation "+
				"rather than repeating the request")
		return "", false
	case err != nil:
		problem(w, http.StatusInternalServerError, "audit_unavailable",
			"the beginning of this change could not be written, so nothing was changed: "+err.Error())
		return "", false
	}
	return key, true
}

// finishedChange writes the outcome of a change that has been made, under the
// key of its beginning. The beginning is durable, so a failure here leaves a
// trail that names who began what; the answer says so, and the reconciler
// closes the entry at the next start by reading the real state.
func (s *Server) finishedChange(w http.ResponseWriter, r *http.Request,
	event audit.Event, key, made string) bool {
	if event.Detail == nil {
		event.Detail = map[string]any{}
	}
	event.Detail[audit.IntentKey] = key
	err := s.audit.RecordOutcome(r.Context(), event)
	if errors.Is(err, audit.ErrOutcomeRecorded) {
		// Another replica, or the reconciler at a start in between, closed this
		// change already. The trail has its answer, which is what was wanted.
		return true
	}
	if err != nil {
		problem(w, http.StatusInternalServerError, "audit_unavailable",
			made+", and the outcome could not be written to the trail: "+err.Error()+
				". The beginning of the change is on the trail; read the state of the installation.")
		return false
	}
	return true
}
