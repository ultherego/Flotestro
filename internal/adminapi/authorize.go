package adminapi

import (
	"errors"
	"net/http"

	"github.com/ultherego/flotestro/internal/audit"
	"github.com/ultherego/flotestro/internal/authz"
	"github.com/ultherego/flotestro/internal/hosts"
)

// authorize checks the permission in the target scope. Every refusal goes
// to the audit log: a trail showing only successful operations is useless
// in an incident analysis.
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
//
// A permission in any scope is enough, and the handlers narrow the result
// to what the principal can actually see. Requiring the global scope turned
// ordinary panel browsing into a refusal for everyone with a role limited
// to one environment - that is, for a typical operator.
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

// hostScope returns the authorisation scope of a host. A host that does
// not exist cannot be the target of any operation.
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
	return host, authz.Scope{Site: host.Site, Environment: host.Environment}, true
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
	return authz.Scope{Site: host.Site, Environment: host.Environment}
}

// scopeFilter builds the WHERE clause narrowing the hosts to the principal
// scopes. The narrowing rule itself lives in the authz package, together
// with the authorisation: two separate implementations of the same
// semantics have drifted apart once already.
func scopeFilter(scopes []authz.Scope) (string, []any) {
	condition, args := authz.ScopeSQL(scopes, "site", "environment", 0)
	if condition == "" {
		return "", nil
	}
	return " where " + condition, args
}
