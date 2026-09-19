package adminapi

import (
	"net/http"

	"github.com/ultherego/flotestro/internal/audit"
	"github.com/ultherego/flotestro/internal/authz"
	"github.com/ultherego/flotestro/internal/opspec"
)

// authorizePayload checks the permissions the content of an order asks for
// beyond the operation's own: an entry for root, a write allowed to skip its
// validator.
func (s *Server) authorizePayload(w http.ResponseWriter, r *http.Request, action opspec.ActionType,
	payload opspec.Payload, scope authz.Scope, targetType, targetID string) (authz.Principal, bool) {
	principal := authz.FromContext(r.Context())
	for _, name := range opspec.PayloadPermissions(action, payload) {
		permission := authz.Permission(name)
		if principal.Can(permission, scope) {
			continue
		}
		s.audit.Record(r.Context(), audit.Event{
			ActorType: audit.ActorUser, ActorID: principal.Subject,
			Action: string(permission), TargetType: targetType, TargetID: targetID,
			RequestID: requestIDOf(r), Outcome: audit.OutcomeDenied,
			Detail: map[string]any{
				"reason": "payload_permission_missing", "permission": string(permission),
				"action_type": string(action), "scope": scope.String(), "roles": principal.Roles(),
			},
		})
		problem(w, http.StatusForbidden, "payload_permission_missing",
			"the content of this order needs the permission "+string(permission)+
				" in scope "+scope.String())
		return principal, false
	}
	return principal, true
}
