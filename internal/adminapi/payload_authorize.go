package adminapi

import (
	"context"
	"net/http"
	"time"

	"github.com/ultherego/flotestro/internal/audit"
	"github.com/ultherego/flotestro/internal/authz"
	"github.com/ultherego/flotestro/internal/inventory"
	"github.com/ultherego/flotestro/internal/opspec"
)

// accountObservationMaxAge is how long the host's word on an account still
// describes it; an agent reports every half hour, so older is a host gone quiet.
const accountObservationMaxAge = 36 * time.Hour

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
	if !s.authorizeAccountAccess(w, r, principal, action, payload, scope, targetType, targetID) {
		return principal, false
	}
	return principal, true
}

// authorizeAccountAccess checks the orders that hand over an account's own
// access: the payload names no group, so the host is asked what the account is.
func (s *Server) authorizeAccountAccess(w http.ResponseWriter, r *http.Request,
	principal authz.Principal, action opspec.ActionType, payload opspec.Payload,
	scope authz.Scope, targetType, targetID string) bool {
	if !opspec.HandsOverAccountAccess(action, payload) {
		return true
	}
	// The permission is the one a membership in sudo asks for: whoever may grant
	// root may also hand over an account that already has it, so nothing is read.
	if principal.Can(authz.PermAccountsPrivilegedGroups, scope) {
		return true
	}
	name := payload.LocalUser.Name
	privilege := s.accountPrivilege(r.Context(), targetID, name)
	if !opspec.GrantsPrivilegedAccess(action, payload, privilege) {
		return true
	}

	code := "payload_permission_missing"
	status := http.StatusForbidden
	message := "the account " + name + " is privileged on this host, so this order grants root by" +
		" another name; it needs the permission " + string(authz.PermAccountsPrivilegedGroups) +
		" in scope " + scope.String()
	if privilege == opspec.AccountPrivilegeUnknown {
		code = "account_privilege_unknown"
		status = http.StatusConflict
		message = "this host has not reported which groups the account " + name + " belongs to, so the" +
			" panel cannot tell whether this order opens an account that is root by another name;" +
			" order again once the host has reported, or have a principal holding " +
			string(authz.PermAccountsPrivilegedGroups) + " place it"
	}
	s.audit.Record(r.Context(), audit.Event{
		ActorType: audit.ActorUser, ActorID: principal.Subject,
		Action: string(authz.PermAccountsPrivilegedGroups), TargetType: targetType, TargetID: targetID,
		RequestID: requestIDOf(r), Outcome: audit.OutcomeDenied,
		Detail: map[string]any{
			"reason": code, "permission": string(authz.PermAccountsPrivilegedGroups),
			"action_type": string(action), "account": name, "account_privilege": string(privilege),
			"scope": scope.String(), "roles": principal.Roles(),
		},
	})
	problem(w, status, code, message)
	return false
}

// requiresFreshAuth asks whether the order needs the operator to confirm
// their identity, with the host's word on the account the order names.
func (s *Server) requiresFreshAuth(ctx context.Context, hostID string,
	action opspec.ActionType, payload opspec.Payload) bool {
	privilege := opspec.AccountPrivilegeOrdinary
	if opspec.HandsOverAccountAccess(action, payload) {
		privilege = s.accountPrivilege(ctx, hostID, payload.LocalUser.Name)
	}
	return opspec.PayloadRequiresFreshAuthForAccount(action, payload, privilege)
}

// accountPrivilege asks the host's inventory what the named account is.
func (s *Server) accountPrivilege(ctx context.Context, hostID, name string) opspec.AccountPrivilege {
	if s.inventory == nil || hostID == "" || name == "" {
		return opspec.AccountPrivilegeUnknown
	}
	observed, err := s.inventory.LocalAccounts(ctx, hostID)
	if err != nil {
		// A store that did not answer leaves the account unclassified; it does
		// not leave it ordinary.
		return opspec.AccountPrivilegeUnknown
	}
	return accountPrivilegeOf(observed, name, time.Now())
}

// accountPrivilegeOf classifies the account the order names against the last
// report of the host. Anything the report does not establish is unknown.
func accountPrivilegeOf(observed []inventory.LocalAccount, name string, now time.Time) opspec.AccountPrivilege {
	for _, account := range observed {
		if account.Name != name {
			continue
		}
		// Every account has at least its primary group, so an empty list is a
		// read that failed on the host, not an account outside every group.
		if account.UnavailableReason != "" || len(account.Groups) == 0 ||
			account.ObservedAt.IsZero() || now.Sub(account.ObservedAt) > accountObservationMaxAge {
			return opspec.AccountPrivilegeUnknown
		}
		if len(opspec.PrivilegedGroupsIn(account.Groups)) > 0 {
			return opspec.AccountPrivilegePrivileged
		}
		return opspec.AccountPrivilegeOrdinary
	}
	return opspec.AccountPrivilegeUnknown
}
