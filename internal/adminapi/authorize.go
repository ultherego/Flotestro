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

// recordedChange writes the trail of a change that has already been made and
// says whether it was written. The changes it guards - what the fleet trusts,
// who may do what, a credential that went out - are the ones nobody can account
// for afterwards without an entry, so the answer names the situation rather than
// reporting a plain success: the operator is to know that the change happened
// and that nothing recorded it.
func (s *Server) recordedChange(w http.ResponseWriter, r *http.Request,
	event audit.Event, made string) bool {
	if err := s.audit.RecordNow(r.Context(), event); err != nil {
		problem(w, http.StatusInternalServerError, "audit_unavailable",
			made+", and the audit trail of it could not be written: "+err.Error()+
				". Read the state of the installation before ordering anything further.")
		return false
	}
	return true
}
