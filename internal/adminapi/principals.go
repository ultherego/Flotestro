package adminapi

import (
	"encoding/json"
	"errors"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/google/uuid"

	"github.com/ultherego/flotestro/internal/audit"
	"github.com/ultherego/flotestro/internal/authz"
)

// handleWhoami returns the request principal and its roles. The endpoint
// needs no permission: everyone may check who they are.
func (s *Server) handleWhoami(w http.ResponseWriter, r *http.Request) {
	principal := authz.FromContext(r.Context())
	if !principal.Authenticated() {
		w.Header().Set("WWW-Authenticate", `Bearer realm="flotestro"`)
		problem(w, http.StatusUnauthorized, "unauthenticated", "no valid token")
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"subject":      principal.Subject,
		"display_name": principal.DisplayName,
		"kind":         principal.Kind,
		"roles":        principal.Roles(),
		"bindings":     principal.Bindings,
		"permissions":  principal.Permissions(),
	})
}

// handleListRoles describes the role catalogue and its permissions.
func (s *Server) handleListRoles(w http.ResponseWriter, r *http.Request) {
	if _, ok := s.authorize(w, r, authz.PermHostRead, authz.GlobalScope, "role", ""); !ok {
		return
	}
	type roleInfo struct {
		Role        string   `json:"role"`
		Permissions []string `json:"permissions"`
	}
	items := make([]roleInfo, 0)
	for _, role := range authz.AllRoles() {
		permissions := make([]string, 0)
		for _, permission := range role.Permissions() {
			permissions = append(permissions, string(permission))
		}
		items = append(items, roleInfo{Role: string(role), Permissions: permissions})
	}
	writeJSON(w, http.StatusOK, map[string]any{"items": items, "count": len(items)})
}

// principalView is an identity as the access screen shows it: with the
// live tokens, so that one of them can be revoked by its identifier, and
// with the moment it was disabled when it was.
type principalView struct {
	authz.Principal
	Tokens     []authz.Token `json:"tokens"`
	DisabledAt *time.Time    `json:"disabled_at,omitempty"`
}

// handleListPrincipals lists the enabled identities, or with disabled=true
// the disabled ones: the two are different questions - who can act, and
// who could be let back in - and a screen asks one at a time.
func (s *Server) handleListPrincipals(w http.ResponseWriter, r *http.Request) {
	if _, ok := s.authorize(w, r, authz.PermPrincipalManage, authz.GlobalScope, "principal", ""); !ok {
		return
	}
	if disabled, _ := strconv.ParseBool(r.URL.Query().Get("disabled")); disabled {
		principals, err := s.authz.ListDisabledPrincipals(r.Context())
		if err != nil {
			s.fail(w, err)
			return
		}
		items := make([]principalView, 0, len(principals))
		for _, principal := range principals {
			disabledAt := principal.DisabledAt
			// A disabled identity has no live token: they ended with it.
			items = append(items, principalView{Principal: principal.Principal, Tokens: []authz.Token{}, DisabledAt: &disabledAt})
		}
		writeJSON(w, http.StatusOK, map[string]any{"items": items, "count": len(items)})
		return
	}
	principals, err := s.authz.ListPrincipals(r.Context())
	if err != nil {
		s.fail(w, err)
		return
	}
	items := make([]principalView, 0, len(principals))
	for _, principal := range principals {
		tokens, err := s.authz.ListTokens(r.Context(), principal.ID)
		if err != nil {
			s.fail(w, err)
			return
		}
		items = append(items, principalView{Principal: principal, Tokens: tokens})
	}
	writeJSON(w, http.StatusOK, map[string]any{"items": items, "count": len(items)})
}

// principalTarget resolves the identity named in the path. A missing one is
// a 404 whatever the caller's permission - the permission was checked
// before, so the answer does not reveal anything to a stranger.
func (s *Server) principalTarget(w http.ResponseWriter, r *http.Request) (*authz.Principal, bool) {
	id := r.PathValue("id")
	if _, err := uuid.Parse(id); err != nil {
		problem(w, http.StatusNotFound, "principal_not_found", "no such identity")
		return nil, false
	}
	principal, err := s.authz.PrincipalByID(r.Context(), id)
	if errors.Is(err, authz.ErrNotFound) {
		problem(w, http.StatusNotFound, "principal_not_found", "no such identity")
		return nil, false
	}
	if err != nil {
		s.fail(w, err)
		return nil, false
	}
	return principal, true
}

// handleDisablePrincipal takes the access of an identity away. The row
// stays: the trail names the identity, and a deleted one would leave
// events pointing at nothing. The sessions and the tokens end with it.
func (s *Server) handleDisablePrincipal(w http.ResponseWriter, r *http.Request) {
	actor, ok := s.authorize(w, r, authz.PermPrincipalManage, authz.GlobalScope, "principal", r.PathValue("id"))
	if !ok {
		return
	}
	target, ok := s.principalTarget(w, r)
	if !ok {
		return
	}
	reason, ok := requestReason(w, r, nil)
	if !ok {
		return
	}
	// An administrator disabling themselves would lock the panel with the
	// last key inside; the refusal is cheaper than the recovery.
	if target.ID == actor.ID {
		problem(w, http.StatusConflict, "self_disable", "an identity cannot disable itself")
		return
	}
	evidence, ok := s.requireStepUp(w, r, actor, reason, "principal.disable", "principal", target.ID)
	if !ok {
		return
	}

	tx, err := s.authz.Pool().Begin(r.Context())
	if err != nil {
		s.fail(w, err)
		return
	}
	defer func() { _ = tx.Rollback(r.Context()) }()
	if err := s.authz.DisablePrincipal(r.Context(), tx, target.ID, "disabled: "+reason); err != nil {
		if errors.Is(err, authz.ErrNotFound) {
			problem(w, http.StatusConflict, "principal_disabled", "the identity is already disabled")
			return
		}
		s.fail(w, err)
		return
	}
	if err := s.audit.RecordTx(r.Context(), tx, audit.Event{
		ActorType: audit.ActorUser, ActorID: actor.Subject,
		Action: "principal.disable", TargetType: "principal", TargetID: target.ID,
		RequestID: requestIDOf(r), Outcome: audit.OutcomeSuccess,
		Detail: withStepUp(map[string]any{
			"subject": target.Subject, "roles": target.Roles(),
		}, evidence),
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

// handleEnablePrincipal gives a disabled identity its access back. The
// bindings it had are still on the row, so it holds what it held; the
// sessions and the tokens that ended with the disabling stay ended, and
// the identity is issued new ones. Enabling what is not disabled is a
// conflict, not a no-op: the caller believed something that is not so.
func (s *Server) handleEnablePrincipal(w http.ResponseWriter, r *http.Request) {
	actor, ok := s.authorize(w, r, authz.PermPrincipalManage, authz.GlobalScope, "principal", r.PathValue("id"))
	if !ok {
		return
	}
	target, ok := s.principalTarget(w, r)
	if !ok {
		return
	}
	reason, ok := requestReason(w, r, nil)
	if !ok {
		return
	}
	evidence, ok := s.requireStepUp(w, r, actor, reason, "principal.enable", "principal", target.ID)
	if !ok {
		return
	}

	tx, err := s.authz.Pool().Begin(r.Context())
	if err != nil {
		s.fail(w, err)
		return
	}
	defer func() { _ = tx.Rollback(r.Context()) }()
	if err := s.authz.EnablePrincipal(r.Context(), tx, target.ID); err != nil {
		if errors.Is(err, authz.ErrNotFound) {
			problem(w, http.StatusConflict, "principal_enabled", "the identity is not disabled")
			return
		}
		s.fail(w, err)
		return
	}
	if err := s.audit.RecordTx(r.Context(), tx, audit.Event{
		ActorType: audit.ActorUser, ActorID: actor.Subject,
		Action: "principal.enable", TargetType: "principal", TargetID: target.ID,
		RequestID: requestIDOf(r), Outcome: audit.OutcomeSuccess,
		Detail: withStepUp(map[string]any{
			"subject": target.Subject, "roles": target.Roles(),
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
		"id": target.ID, "subject": target.Subject, "kind": target.Kind, "bindings": target.Bindings,
	})
}

// handleListSessions lists the live browser sessions of an identity. A
// token is not a session: an identity that only ever used tokens has none,
// and the empty list says so.
func (s *Server) handleListSessions(w http.ResponseWriter, r *http.Request) {
	if _, ok := s.authorize(w, r, authz.PermPrincipalManage, authz.GlobalScope, "principal", r.PathValue("id")); !ok {
		return
	}
	target, ok := s.principalTarget(w, r)
	if !ok {
		return
	}
	sessions, err := s.authz.ListSessionsOf(r.Context(), target.ID)
	if err != nil {
		s.fail(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"items": sessions, "count": len(sessions), "principal_id": target.ID, "subject": target.Subject,
	})
}

// handleRevokeSession ends one browser session of an identity. The
// identity in the path has to own it; a session identifier alone ends
// nothing. The next request on that cookie is refused.
func (s *Server) handleRevokeSession(w http.ResponseWriter, r *http.Request) {
	actor, ok := s.authorize(w, r, authz.PermPrincipalManage, authz.GlobalScope, "principal", r.PathValue("id"))
	if !ok {
		return
	}
	target, ok := s.principalTarget(w, r)
	if !ok {
		return
	}
	sessionID := r.PathValue("sid")
	if _, err := uuid.Parse(sessionID); err != nil {
		problem(w, http.StatusNotFound, "session_not_found", "no such session")
		return
	}
	reason, ok := requestReason(w, r, nil)
	if !ok {
		return
	}
	evidence, ok := s.requireStepUp(w, r, actor, reason, "principal.session.revoke", "principal", target.ID)
	if !ok {
		return
	}

	tx, err := s.authz.Pool().Begin(r.Context())
	if err != nil {
		s.fail(w, err)
		return
	}
	defer func() { _ = tx.Rollback(r.Context()) }()
	revoked, err := s.authz.RevokeSessionOf(r.Context(), tx, target.ID, sessionID, "revoked: "+reason)
	if err != nil {
		s.fail(w, err)
		return
	}
	if !revoked {
		problem(w, http.StatusNotFound, "session_not_found", "no such live session of this identity")
		return
	}
	if err := s.audit.RecordTx(r.Context(), tx, audit.Event{
		ActorType: audit.ActorUser, ActorID: actor.Subject,
		Action: "principal.session.revoke", TargetType: "principal", TargetID: target.ID,
		RequestID: requestIDOf(r), Outcome: audit.OutcomeSuccess,
		Detail: withStepUp(map[string]any{
			"subject": target.Subject, "session_id": sessionID,
		}, evidence),
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

type issueTokenRequest struct {
	Description   string `json:"description"`
	TokenTTLHours int    `json:"token_ttl_hours"`
	Reason        string `json:"reason"`
}

// maxTokenTTL bounds the lifetime of a token issued through the API. A
// token that never expires is a key that is never looked at again.
const maxTokenTTL = 365 * 24 * time.Hour

// handleIssueToken issues another token for an identity. The value is in
// this answer and nowhere else.
func (s *Server) handleIssueToken(w http.ResponseWriter, r *http.Request) {
	actor, ok := s.authorize(w, r, authz.PermPrincipalManage, authz.GlobalScope, "principal", r.PathValue("id"))
	if !ok {
		return
	}
	target, ok := s.principalTarget(w, r)
	if !ok {
		return
	}
	var request issueTokenRequest
	reason, ok := requestReason(w, r, &request)
	if !ok {
		return
	}
	ttl := time.Duration(request.TokenTTLHours) * time.Hour
	if ttl <= 0 {
		ttl = 30 * 24 * time.Hour
	}
	if ttl > maxTokenTTL {
		problem(w, http.StatusBadRequest, "invalid_ttl",
			"a token lives at most a year (token_ttl_hours up to 8760)")
		return
	}
	evidence, ok := s.requireStepUp(w, r, actor, reason, "principal.token.issue", "principal", target.ID)
	if !ok {
		return
	}

	tx, err := s.authz.Pool().Begin(r.Context())
	if err != nil {
		s.fail(w, err)
		return
	}
	defer func() { _ = tx.Rollback(r.Context()) }()
	description := request.Description
	if description == "" {
		description = "token for " + target.Subject
	}
	token, err := s.authz.IssueToken(r.Context(), tx, target.ID, description, ttl, actor.Subject)
	if err != nil {
		s.fail(w, err)
		return
	}
	if err := s.audit.RecordTx(r.Context(), tx, audit.Event{
		ActorType: audit.ActorUser, ActorID: actor.Subject,
		Action: "principal.token.issue", TargetType: "principal", TargetID: target.ID,
		RequestID: requestIDOf(r), Outcome: audit.OutcomeSuccess,
		Detail: withStepUp(map[string]any{
			"subject": target.Subject, "token_id": token.ID,
			"description": description, "expires_at": token.ExpiresAt,
		}, evidence),
	}); err != nil {
		s.fail(w, err)
		return
	}
	if err := tx.Commit(r.Context()); err != nil {
		s.fail(w, err)
		return
	}
	writeJSON(w, http.StatusCreated, map[string]any{
		"id": token.ID, "principal_id": target.ID, "subject": target.Subject,
		"token": token.Value, "token_expires_at": token.ExpiresAt,
		"description": description,
	})
}

// handleRevokeToken ends one token. The identity in the path has to own
// it; a token identifier alone revokes nothing.
func (s *Server) handleRevokeToken(w http.ResponseWriter, r *http.Request) {
	actor, ok := s.authorize(w, r, authz.PermPrincipalManage, authz.GlobalScope, "principal", r.PathValue("id"))
	if !ok {
		return
	}
	target, ok := s.principalTarget(w, r)
	if !ok {
		return
	}
	tokenID := r.PathValue("token")
	if _, err := uuid.Parse(tokenID); err != nil {
		problem(w, http.StatusNotFound, "token_not_found", "no such token")
		return
	}
	reason, ok := requestReason(w, r, nil)
	if !ok {
		return
	}
	evidence, ok := s.requireStepUp(w, r, actor, reason, "principal.token.revoke", "principal", target.ID)
	if !ok {
		return
	}

	tx, err := s.authz.Pool().Begin(r.Context())
	if err != nil {
		s.fail(w, err)
		return
	}
	defer func() { _ = tx.Rollback(r.Context()) }()
	revoked, err := s.authz.RevokeToken(r.Context(), tx, target.ID, tokenID)
	if err != nil {
		s.fail(w, err)
		return
	}
	if !revoked {
		problem(w, http.StatusNotFound, "token_not_found", "no such live token of this identity")
		return
	}
	if err := s.audit.RecordTx(r.Context(), tx, audit.Event{
		ActorType: audit.ActorUser, ActorID: actor.Subject,
		Action: "principal.token.revoke", TargetType: "principal", TargetID: target.ID,
		RequestID: requestIDOf(r), Outcome: audit.OutcomeSuccess,
		Detail: withStepUp(map[string]any{
			"subject": target.Subject, "token_id": tokenID,
		}, evidence),
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

type revokeRoleRequest struct {
	Site        string `json:"site"`
	Environment string `json:"environment"`
	Reason      string `json:"reason"`
}

// handleRevokeRole removes one binding: the role in the path, the scope
// from the body. The scope is part of the key, because an operator of two
// sites loses one and keeps the other.
func (s *Server) handleRevokeRole(w http.ResponseWriter, r *http.Request) {
	actor, ok := s.authorize(w, r, authz.PermPrincipalManage, authz.GlobalScope, "principal", r.PathValue("id"))
	if !ok {
		return
	}
	target, ok := s.principalTarget(w, r)
	if !ok {
		return
	}
	role := authz.Role(r.PathValue("role"))
	if !authz.KnownRole(role) {
		problem(w, http.StatusBadRequest, "unknown_role", "unknown role "+string(role))
		return
	}
	var request revokeRoleRequest
	reason, ok := requestReason(w, r, &request)
	if !ok {
		return
	}
	scope := authz.Scope{Site: strings.TrimSpace(request.Site), Environment: strings.TrimSpace(request.Environment)}
	evidence, ok := s.requireStepUp(w, r, actor, reason, "principal.role.revoke", "principal", target.ID)
	if !ok {
		return
	}
	// The binding as it was: the trail keeps what the revocation removed,
	// its validity included.
	before := findBinding(target.Bindings, role, scope)

	tx, err := s.authz.Pool().Begin(r.Context())
	if err != nil {
		s.fail(w, err)
		return
	}
	defer func() { _ = tx.Rollback(r.Context()) }()
	removed, err := s.authz.RevokeRole(r.Context(), tx, target.ID, role, scope)
	if err != nil {
		s.fail(w, err)
		return
	}
	if !removed {
		problem(w, http.StatusNotFound, "binding_not_found",
			"the identity has no binding "+string(role)+" in scope "+scope.String())
		return
	}
	if err := s.audit.RecordTx(r.Context(), tx, audit.Event{
		ActorType: audit.ActorUser, ActorID: actor.Subject,
		Action: "principal.role.revoke", TargetType: "principal", TargetID: target.ID,
		RequestID: requestIDOf(r), Outcome: audit.OutcomeSuccess,
		Detail: withStepUp(map[string]any{
			"subject": target.Subject, "role": string(role), "scope": scope.String(),
		}, evidence),
		Before: before,
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

type createPrincipalRequest struct {
	Subject     string        `json:"subject"`
	DisplayName string        `json:"display_name"`
	Kind        string        `json:"kind"`
	Roles       []roleRequest `json:"roles"`
	// IssueToken issues an API token together with the principal. The value
	// is visible only in this response.
	IssueToken    bool `json:"issue_token"`
	TokenTTLHours int  `json:"token_ttl_hours"`
	// Reason describes what the access is granted for. The operation moves
	// the access rules of the whole fleet, so the reason is part of the
	// audit trail.
	Reason string `json:"reason"`
}

// roleRequest names one binding to grant: the role, the scope and, when
// the access is meant to end by itself, until when.
type roleRequest struct {
	Role        string `json:"role"`
	Site        string `json:"site"`
	Environment string `json:"environment"`
	// ValidUntil is an RFC 3339 moment; empty means until revoked. A moment
	// already past is accepted and means "expired at once": a way to end
	// an access without removing its record.
	ValidUntil string `json:"valid_until"`
}

// parse checks the role and reads the validity.
func (request roleRequest) parse() (authz.Role, authz.Scope, *time.Time, error) {
	role := authz.Role(request.Role)
	if !authz.KnownRole(role) {
		return "", authz.Scope{}, nil, errors.New("unknown role " + request.Role)
	}
	scope := authz.Scope{Site: strings.TrimSpace(request.Site), Environment: strings.TrimSpace(request.Environment)}
	validUntil, err := parseTimeParam(strings.TrimSpace(request.ValidUntil))
	if err != nil {
		return "", authz.Scope{}, nil, errors.New("valid_until must be an RFC 3339 timestamp")
	}
	return role, scope, validUntil, nil
}

// bindingRecord is a binding as the trail describes it.
func bindingRecord(role authz.Role, scope authz.Scope, validUntil *time.Time) map[string]any {
	record := map[string]any{"role": string(role), "scope": scope.String()}
	if validUntil != nil {
		record["valid_until"] = validUntil.UTC().Format(time.RFC3339)
	}
	return record
}

// findBinding returns the binding of the role in the scope as the trail
// describes it, or nil when the identity has none.
func findBinding(bindings []authz.Binding, role authz.Role, scope authz.Scope) map[string]any {
	wanted := authz.Scope{Site: orWildcard(scope.Site), Environment: orWildcard(scope.Environment)}
	for _, binding := range bindings {
		if binding.Role == role && binding.Scope == wanted {
			return bindingRecord(binding.Role, binding.Scope, binding.ValidUntil)
		}
	}
	return nil
}

func orWildcard(value string) string {
	if value == "" {
		return authz.Wildcard
	}
	return value
}

type grantRoleRequest struct {
	roleRequest
	Reason string `json:"reason"`
}

// handleGrantRole adds one binding to an identity, or changes the validity
// of one it already has. The same operation of the greatest impact as
// creating the identity with roles: it moves who can do what.
func (s *Server) handleGrantRole(w http.ResponseWriter, r *http.Request) {
	actor, ok := s.authorize(w, r, authz.PermPrincipalManage, authz.GlobalScope, "principal", r.PathValue("id"))
	if !ok {
		return
	}
	target, ok := s.principalTarget(w, r)
	if !ok {
		return
	}
	var request grantRoleRequest
	reason, ok := requestReason(w, r, &request)
	if !ok {
		return
	}
	role, scope, validUntil, err := request.parse()
	if err != nil {
		problem(w, http.StatusBadRequest, "invalid_binding", err.Error())
		return
	}
	evidence, ok := s.requireStepUp(w, r, actor, reason, "principal.role.grant", "principal", target.ID)
	if !ok {
		return
	}
	before := findBinding(target.Bindings, role, scope)
	after := bindingRecord(role, scope, validUntil)

	tx, err := s.authz.Pool().Begin(r.Context())
	if err != nil {
		s.fail(w, err)
		return
	}
	defer func() { _ = tx.Rollback(r.Context()) }()
	if err := s.authz.GrantRole(r.Context(), tx, target.ID, role, scope, validUntil, actor.Subject); err != nil {
		s.fail(w, err)
		return
	}
	if err := s.audit.RecordTx(r.Context(), tx, audit.Event{
		ActorType: audit.ActorUser, ActorID: actor.Subject,
		Action: "principal.role.grant", TargetType: "principal", TargetID: target.ID,
		RequestID: requestIDOf(r), Outcome: audit.OutcomeSuccess,
		Detail: withStepUp(map[string]any{
			"subject": target.Subject, "role": string(role), "scope": scope.String(),
			"valid_until": validUntil,
		}, evidence),
		Before: before, After: after,
	}); err != nil {
		s.fail(w, err)
		return
	}
	if err := tx.Commit(r.Context()); err != nil {
		s.fail(w, err)
		return
	}
	writeJSON(w, http.StatusCreated, map[string]any{
		"principal_id": target.ID, "subject": target.Subject,
		"role": string(role), "scope": scope, "valid_until": validUntil,
	})
}

// handleCreatePrincipal creates a principal together with its role
// bindings.
func (s *Server) handleCreatePrincipal(w http.ResponseWriter, r *http.Request) {
	actor, ok := s.authorize(w, r, authz.PermPrincipalManage, authz.GlobalScope, "principal", "")
	if !ok {
		return
	}

	var request createPrincipalRequest
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<16)).Decode(&request); err != nil {
		problem(w, http.StatusBadRequest, "invalid_body", "the request body is not valid JSON")
		return
	}
	if request.Subject == "" {
		problem(w, http.StatusBadRequest, "invalid_subject", "missing identity subject")
		return
	}
	// The kind is what the row admits; a value the table would refuse is
	// the caller's mistake, not a failure of the store.
	if request.Kind != "" && request.Kind != "user" && request.Kind != "service" {
		problem(w, http.StatusBadRequest, "invalid_kind", "kind must be user or service")
		return
	}
	tokenTTL := time.Duration(request.TokenTTLHours) * time.Hour
	if tokenTTL <= 0 {
		tokenTTL = 30 * 24 * time.Hour
	}
	if request.IssueToken && tokenTTL > maxTokenTTL {
		problem(w, http.StatusBadRequest, "invalid_ttl",
			"a token lives at most a year (token_ttl_hours up to 8760)")
		return
	}
	type parsedBinding struct {
		role       authz.Role
		scope      authz.Scope
		validUntil *time.Time
	}
	bindings := make([]parsedBinding, 0, len(request.Roles))
	for _, binding := range request.Roles {
		role, scope, validUntil, err := binding.parse()
		if err != nil {
			problem(w, http.StatusBadRequest, "invalid_binding", err.Error())
			return
		}
		bindings = append(bindings, parsedBinding{role: role, scope: scope, validUntil: validUntil})
	}

	// Granting permissions is a highest-impact operation: it moves who can
	// do anything on the fleet.
	evidence, ok := s.requireStepUp(w, r, actor, request.Reason,
		"principal.create", "principal", request.Subject)
	if !ok {
		return
	}

	tx, err := s.authz.Pool().Begin(r.Context())
	if err != nil {
		s.fail(w, err)
		return
	}
	defer func() { _ = tx.Rollback(r.Context()) }()

	principalID, err := s.authz.EnsurePrincipal(r.Context(), tx,
		request.Subject, request.DisplayName, request.Kind)
	if err != nil {
		s.fail(w, err)
		return
	}
	granted := make([]map[string]any, 0, len(bindings))
	for _, binding := range bindings {
		if err := s.authz.GrantRole(r.Context(), tx, principalID,
			binding.role, binding.scope, binding.validUntil, actor.Subject); err != nil {
			s.fail(w, err)
			return
		}
		granted = append(granted, bindingRecord(binding.role, binding.scope, binding.validUntil))
	}

	response := map[string]any{
		"id": principalID, "subject": request.Subject, "roles": granted,
	}
	if request.IssueToken {
		token, err := s.authz.IssueToken(r.Context(), tx, principalID,
			"token for "+request.Subject, tokenTTL, actor.Subject)
		if err != nil {
			s.fail(w, err)
			return
		}
		response["token"] = token.Value
		response["token_expires_at"] = token.ExpiresAt
	}

	if err := s.audit.RecordTx(r.Context(), tx, audit.Event{
		ActorType: audit.ActorUser, ActorID: actor.Subject,
		Action: "principal.create", TargetType: "principal", TargetID: principalID,
		RequestID: requestIDOf(r), Outcome: audit.OutcomeSuccess,
		Detail: withStepUp(map[string]any{
			"subject": request.Subject, "roles": granted,
			"token_issued": request.IssueToken,
		}, evidence),
		After: map[string]any{"subject": request.Subject, "bindings": granted},
	}); err != nil {
		s.fail(w, err)
		return
	}
	if err := tx.Commit(r.Context()); err != nil {
		s.fail(w, err)
		return
	}
	writeJSON(w, http.StatusCreated, response)
}

type createGroupMappingRequest struct {
	Issuer      string `json:"issuer"`
	GroupName   string `json:"group_name"`
	Role        string `json:"role"`
	Site        string `json:"site"`
	Environment string `json:"environment"`
	Reason      string `json:"reason"`
}

// handleListGroupMappings returns the mappings of external groups to
// roles.
func (s *Server) handleListGroupMappings(w http.ResponseWriter, r *http.Request) {
	if _, ok := s.authorize(w, r, authz.PermPrincipalManage, authz.GlobalScope, "group_mapping", ""); !ok {
		return
	}
	mappings, err := s.authz.ListGroupMappings(r.Context())
	if err != nil {
		s.fail(w, err)
		return
	}
	if mappings == nil {
		mappings = []authz.GroupMapping{}
	}
	setETag(w, groupMappingsTag(mappings))
	writeJSON(w, http.StatusOK, map[string]any{"items": mappings, "count": len(mappings)})
}

// groupMappingsTag is the entity tag of the access mappings as a set. A
// mapping is created or removed, never edited, so the set of identifiers
// is its version. The list comes in a fixed order from the store.
func groupMappingsTag(mappings []authz.GroupMapping) string {
	parts := make([]string, 0, len(mappings))
	for _, mapping := range mappings {
		parts = append(parts, mapping.ID)
	}
	return etagOf(parts...)
}

// requireGroupMappingsMatch enforces If-Match against the current set of
// mappings: an administrator who adds or removes a rule decides against
// the list they read, and the list may have changed under them.
func (s *Server) requireGroupMappingsMatch(w http.ResponseWriter, r *http.Request) bool {
	if r.Header.Get("If-Match") == "" {
		return true
	}
	mappings, err := s.authz.ListGroupMappings(r.Context())
	if err != nil {
		s.fail(w, err)
		return false
	}
	return requireMatch(w, r, groupMappingsTag(mappings))
}

// setGroupMappingsTag puts the tag of the set after a write on the answer.
func (s *Server) setGroupMappingsTag(w http.ResponseWriter, r *http.Request) {
	if mappings, err := s.authz.ListGroupMappings(r.Context()); err == nil {
		setETag(w, groupMappingsTag(mappings))
	}
}

// handleCreateGroupMapping adds a mapping of a group to a role in a scope.
// The group grants only a candidate role; the scope remains the panel
// policy.
func (s *Server) handleCreateGroupMapping(w http.ResponseWriter, r *http.Request) {
	actor, ok := s.authorize(w, r, authz.PermPrincipalManage, authz.GlobalScope, "group_mapping", "")
	if !ok {
		return
	}

	var request createGroupMappingRequest
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<16)).Decode(&request); err != nil {
		problem(w, http.StatusBadRequest, "invalid_body", "the request body is not valid JSON")
		return
	}
	if request.Issuer == "" && s.oidc != nil {
		request.Issuer = s.oidc.Issuer()
	}
	if !authz.KnownRole(authz.Role(request.Role)) {
		problem(w, http.StatusBadRequest, "unknown_role", "unknown role "+request.Role)
		return
	}

	// The mapping of a group to a role decides whom the identity provider
	// lets in and with what permissions; it is a change of the access rule
	// itself.
	evidence, ok := s.requireStepUp(w, r, actor, request.Reason,
		"group_mapping.create", "group_mapping", request.GroupName)
	if !ok {
		return
	}
	if !s.requireGroupMappingsMatch(w, r) {
		return
	}

	tx, err := s.authz.Pool().Begin(r.Context())
	if err != nil {
		s.fail(w, err)
		return
	}
	defer func() { _ = tx.Rollback(r.Context()) }()

	mapping, err := s.authz.CreateGroupMapping(r.Context(), tx, request.Issuer, request.GroupName,
		authz.Role(request.Role), authz.Scope{Site: request.Site, Environment: request.Environment},
		actor.Subject)
	if err != nil {
		problem(w, http.StatusBadRequest, "invalid_mapping", err.Error())
		return
	}
	if err := s.audit.RecordTx(r.Context(), tx, audit.Event{
		ActorType: audit.ActorUser, ActorID: actor.Subject,
		Action: "group_mapping.create", TargetType: "group_mapping", TargetID: mapping.ID,
		RequestID: requestIDOf(r), Outcome: audit.OutcomeSuccess,
		Detail: withStepUp(map[string]any{
			"issuer": mapping.Issuer, "group": mapping.GroupName, "role": string(mapping.Role),
			"site": mapping.Site, "environment": mapping.Environment,
		}, evidence),
		After: mapping,
	}); err != nil {
		s.fail(w, err)
		return
	}
	if err := tx.Commit(r.Context()); err != nil {
		s.fail(w, err)
		return
	}
	s.setGroupMappingsTag(w, r)
	writeJSON(w, http.StatusCreated, mapping)
}

// handleDeleteGroupMapping removes a mapping.
func (s *Server) handleDeleteGroupMapping(w http.ResponseWriter, r *http.Request) {
	actor, ok := s.authorize(w, r, authz.PermPrincipalManage, authz.GlobalScope, "group_mapping", "")
	if !ok {
		return
	}
	mappingID := r.PathValue("id")
	// The reason at removal is passed as a parameter: a DELETE request has
	// no body, and the condition is the same as at mapping creation.
	evidence, ok := s.requireStepUp(w, r, actor, r.URL.Query().Get("reason"),
		"group_mapping.delete", "group_mapping", mappingID)
	if !ok {
		return
	}
	if !s.requireGroupMappingsMatch(w, r) {
		return
	}
	// The mapping as it was, for the trail: once it is gone, nothing else
	// says which group lost which role.
	var before *authz.GroupMapping
	if mappings, err := s.authz.ListGroupMappings(r.Context()); err == nil {
		for i := range mappings {
			if mappings[i].ID == mappingID {
				before = &mappings[i]
			}
		}
	}
	removed, err := s.authz.DeleteGroupMapping(r.Context(), mappingID)
	if err != nil {
		s.fail(w, err)
		return
	}
	if !removed {
		problem(w, http.StatusNotFound, "mapping_not_found", "no such mapping")
		return
	}
	event := audit.Event{
		ActorType: audit.ActorUser, ActorID: actor.Subject,
		Action: "group_mapping.delete", TargetType: "group_mapping", TargetID: mappingID,
		RequestID: requestIDOf(r), Outcome: audit.OutcomeSuccess,
		Detail: withStepUp(map[string]any{}, evidence),
	}
	if before != nil {
		event.Detail["group"] = before.GroupName
		event.Detail["role"] = string(before.Role)
		event.Before = before
	}
	s.audit.Record(r.Context(), event)
	s.setGroupMappingsTag(w, r)
	w.WriteHeader(http.StatusNoContent)
}

// accessReviewColumns is the header of the review file. The order is
// fixed: an auditor's sheet built against one review reads the next one.
var accessReviewColumns = []string{
	"subject", "display_name", "kind", "roles", "last_login_at", "last_token_use_at",
	"days_since_use", "earliest_expiry", "tokens", "flags",
}

// accessReviewRow renders one identity in the order of accessReviewColumns.
// A role is written with its scope and, where it has one, its end, so the
// sheet says not only what an identity may do but for how long.
func accessReviewRow(principal authz.ReviewedPrincipal) []string {
	roles := make([]string, 0, len(principal.Bindings))
	for _, binding := range principal.Bindings {
		role := string(binding.Role) + "@" + binding.Scope.Site + "/" + binding.Scope.Environment
		if binding.ValidUntil != nil {
			role += " until " + binding.ValidUntil.UTC().Format(time.RFC3339)
		}
		if binding.Expired {
			role += " (expired)"
		}
		roles = append(roles, role)
	}
	return []string{
		principal.Subject, principal.DisplayName, principal.Kind, strings.Join(roles, "; "),
		formatTime(principal.LastLoginAt), formatTime(principal.LastTokenUseAt),
		csvInt(principal.DaysSinceUse), formatTime(principal.EarliestExpiry),
		strconv.Itoa(len(principal.Tokens)), strings.Join(principal.Flags, " "),
	}
}

// handleAccessReview lists every enabled identity with what it can do,
// when it was last used and what the reviewer should look at. The review
// is a compliance artefact, so making one is on the trail: an auditor asks
// "when was access last reviewed, and by whom" before anything else.
func (s *Server) handleAccessReview(w http.ResponseWriter, r *http.Request) {
	actor, ok := s.authorize(w, r, authz.PermPrincipalManage, authz.GlobalScope, "principal", "")
	if !ok {
		return
	}
	asCSV, ok := exportFormat(w, r)
	if !ok {
		return
	}
	format := "json"
	if asCSV {
		format = "csv"
	}
	now := time.Now()
	principals, err := s.authz.ReviewAccess(r.Context(), now)
	if err != nil {
		s.fail(w, err)
		return
	}
	flagged := 0
	for _, principal := range principals {
		if len(principal.Flags) > 0 {
			flagged++
		}
	}
	s.audit.Record(r.Context(), audit.Event{
		ActorType: audit.ActorUser, ActorID: actor.Subject,
		Action: "access.review", TargetType: "principal", TargetID: "",
		RequestID: requestIDOf(r), Outcome: audit.OutcomeSuccess,
		Detail: map[string]any{
			"format": format, "principals": len(principals), "flagged": flagged,
		},
	})

	if format == "csv" {
		s.writeCSV(w, r, "access-review-"+now.UTC().Format("20060102")+".csv", accessReviewColumns,
			func(yield func([]string) bool) error {
				for _, principal := range principals {
					if !yield(accessReviewRow(principal)) {
						return nil
					}
				}
				return nil
			})
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"items": principals, "count": len(principals), "flagged": flagged,
		"reviewed_at": now.UTC(),
		"thresholds": map[string]any{
			"unused_days":       int(authz.ReviewUnusedAfter.Hours() / 24),
			"expires_soon_days": int(authz.ReviewExpiringSoon.Hours() / 24),
			"token_max_days":    int(authz.ReviewTokenMaxAge.Hours() / 24),
		},
	})
}
