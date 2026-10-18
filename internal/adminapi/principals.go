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
	"github.com/ultherego/flotestro/internal/paging"
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
	// The identifier goes with the subject: it is what the principal routes are
	// keyed by, and the profile screen needs it to name its own identity there.
	writeJSON(w, http.StatusOK, map[string]any{
		"id":           principal.ID,
		"subject":      principal.Subject,
		"display_name": principal.DisplayName,
		"kind":         principal.Kind,
		"roles":        principal.Roles(),
		"bindings":     principal.Bindings,
		"permissions":  principal.Permissions(),
		// How this caller got in. The panel asks because the two doors need
		// different things of somebody whose authentication has gone stale:
		// a provider session is sent back to the provider, and a password
		// session is asked for the password again - sending it to a provider
		// that may not exist is how a refusal becomes a dead end.
		"authentication": authenticationOf(r),
	})
}

// authenticationOf says how the caller of this request got in: "password",
// "provider" or "token".
func authenticationOf(r *http.Request) string {
	session, ok := authz.SessionFromContext(r.Context())
	if !ok {
		return "token"
	}
	for _, method := range session.Auth.AMR {
		if method == "pwd" {
			return "password"
		}
	}
	return "provider"
}

// principalView is an identity as the access screen shows it: with the live
// tokens, so that one of them can be revoked by its identifier, with the
// moment it was disabled when it was, and with what is known about its
// password - never the password itself, which no screen has a use for.
type principalView struct {
	authz.Principal
	Tokens     []authz.Token `json:"tokens"`
	DisabledAt *time.Time    `json:"disabled_at,omitempty"`
	// Password is absent for an identity that has none: that identity signs
	// in through the provider, or not at all. Absent is not "empty".
	Password *authz.Credential `json:"password,omitempty"`
}

// handleListPrincipals lists the enabled identities, or with disabled=true the
// disabled ones: the two are different questions - who can act, and who could
// be let back in - and a screen asks one at a time.
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
	query := r.URL.Query()
	limit, _ := strconv.Atoi(query.Get("limit"))
	limit = paging.Limit(limit, defaultListPage, maxListPage)
	offset, _ := strconv.Atoi(query.Get("offset"))
	if offset < 0 {
		offset = 0
	}
	filter := authz.PrincipalFilter{Query: query.Get("q"), Limit: limit, Offset: offset}
	page, err := s.authz.ListPrincipals(r.Context(), filter)
	if err != nil {
		s.fail(w, err)
		return
	}
	// The tokens of this page, in one query rather than one per identity.
	tokens, err := s.authz.TokensOfMany(r.Context(), principalIDs(page.Items))
	if err != nil {
		s.fail(w, err)
		return
	}
	credentials, err := s.authz.CredentialsOfMany(r.Context(), principalIDs(page.Items))
	if err != nil {
		s.fail(w, err)
		return
	}
	items := make([]principalView, 0, len(page.Items))
	for _, principal := range page.Items {
		held := tokens[principal.ID]
		if held == nil {
			held = []authz.Token{}
		}
		view := principalView{Principal: principal, Tokens: held}
		if credential, has := credentials[principal.ID]; has {
			kept := credential
			view.Password = &kept
		}
		items = append(items, view)
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"items": items, "count": len(items),
		"total": page.Total, "limit": limit, "offset": offset,
		// Counted over everything the filter matches rather than over the
		// page: a screen that pages and then counts what it drew tells an
		// administrator there are four services in a fleet with eighteen.
		"by_kind": page.ByKind, "by_role": page.ByRole,
		"without_bindings": page.WithoutBindings,
	})
}

func principalIDs(principals []authz.Principal) []string {
	ids := make([]string, 0, len(principals))
	for _, principal := range principals {
		ids = append(ids, principal.ID)
	}
	return ids
}

// principalTarget resolves the identity named in the path.
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

// linkDirectoryAccountRequest names the directory account, or clears the link
// with an empty uid.
type linkDirectoryAccountRequest struct {
	DirectoryUID string `json:"directory_uid"`
}

// handleLinkDirectoryAccount writes down which directory account an identity
// is. Only a linked identity is asked about at the directory: a uid that looks
// like somebody's username is not evidence of the same person, and the groups
// of the directory are not the groups of the identity provider.
func (s *Server) handleLinkDirectoryAccount(w http.ResponseWriter, r *http.Request) {
	actor, ok := s.authorize(w, r, authz.PermPrincipalManage, authz.GlobalScope, "principal", r.PathValue("id"))
	if !ok {
		return
	}
	target, ok := s.principalTarget(w, r)
	if !ok {
		return
	}
	var request linkDirectoryAccountRequest
	reason, ok := requestReason(w, r, &request)
	if !ok {
		return
	}
	uid := strings.TrimSpace(request.DirectoryUID)
	evidence, ok := s.requireStepUp(w, r, actor, reason, "principal.directory_link", "principal", target.ID)
	if !ok {
		return
	}

	tx, err := s.authz.Pool().Begin(r.Context())
	if err != nil {
		s.fail(w, err)
		return
	}
	defer func() { _ = tx.Rollback(r.Context()) }()
	if err := s.authz.LinkDirectoryAccount(r.Context(), tx, target.ID, uid); err != nil {
		if errors.Is(err, authz.ErrNotFound) {
			problem(w, http.StatusNotFound, "principal_not_found", "no such identity")
			return
		}
		s.fail(w, err)
		return
	}
	if err := s.audit.RecordTx(r.Context(), tx, audit.Event{
		ActorType: audit.ActorUser, ActorID: actor.Subject,
		Action: "principal.directory_link", TargetType: "principal", TargetID: target.ID,
		RequestID: requestIDOf(r), Outcome: audit.OutcomeSuccess,
		Detail: withStepUp(map[string]any{
			"subject": target.Subject, "directory_uid": uid,
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
		"principal_id": target.ID, "subject": target.Subject, "directory_uid": uid,
	})
}

// handleDisablePrincipal takes the access of an identity away.
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

// handleEnablePrincipal gives a disabled identity its access back.
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

// handleListSessions lists the live browser sessions of an identity.
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

// handleRevokeSession ends one browser session of an identity. The identity in
// the path has to own it; a session identifier alone ends nothing.
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

// handleRevokeRole removes one binding: the role in the path, the scope from
// the body.
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
	if _, ok := s.resolveRole(w, r, role); !ok {
		return
	}
	var request revokeRoleRequest
	reason, ok := requestReason(w, r, &request)
	if !ok {
		return
	}
	scope := authz.Placement(strings.TrimSpace(request.Site), strings.TrimSpace(request.Environment))
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
	// Reason describes what the access is granted for. The operation moves the
	// access rules of the whole fleet, so the reason is part of the audit trail.
	Reason string `json:"reason"`
}

// roleRequest names one binding to grant: the role, the scope and, when
// the access is meant to end by itself, until when.
type roleRequest struct {
	Role        string `json:"role"`
	Site        string `json:"site"`
	Environment string `json:"environment"`
	// TeamScope says whether the binding is narrowed by team, in words rather
	// than by the presence of a field: a request that leaves it out is refused,
	// because a team omitted by accident would widen the grant in silence.
	TeamScope *teamScopeRequest `json:"team_scope"`
	// Owners and Tags narrow it further. A single "*" is every value; an empty
	// list reaches none, which is what a caller gets for saying nothing.
	Owners []string `json:"owners"`
	Tags   []string `json:"tags"`
	// ValidUntil is an RFC 3339 moment; empty means until revoked.
	ValidUntil string `json:"valid_until"`
}

// teamScopeRequest is the one field that cannot say "any" by being empty: the
// team is a foreign key, so the mode is spelled out.
type teamScopeRequest struct {
	// Mode is "any" or "exact".
	Mode   string `json:"mode"`
	TeamID string `json:"team_id"`
}

// scope reads the team, the owners and the tags, refusing every shape that
// would leave the binding wider than the caller wrote down.
func (request roleRequest) scope() (authz.Scope, error) {
	scope := authz.Scope{
		Site:        strings.TrimSpace(request.Site),
		Environment: strings.TrimSpace(request.Environment),
		Owners:      trimmedList(request.Owners),
		Tags:        trimmedList(request.Tags),
	}
	if request.TeamScope == nil {
		return scope, errors.New("team_scope is required: say {\"mode\":\"any\"} or " +
			"{\"mode\":\"exact\",\"team_id\":\"...\"}")
	}
	team := strings.TrimSpace(request.TeamScope.TeamID)
	switch strings.ToLower(strings.TrimSpace(request.TeamScope.Mode)) {
	case "any":
		if team != "" {
			return scope, errors.New("team_scope mode any takes no team_id")
		}
		scope.TeamAny = true
	case "exact":
		if team == "" {
			return scope, errors.New("team_scope mode exact needs a team_id")
		}
		scope.Team = team
	default:
		return scope, errors.New("team_scope mode has to be any or exact")
	}
	if len(scope.Owners) == 0 {
		scope.Owners = []string{authz.Wildcard}
	}
	if len(scope.Tags) == 0 {
		scope.Tags = []string{authz.Wildcard}
	}
	return scope, nil
}

// trimmedList drops the blanks a hand-written list collects.
func trimmedList(values []string) []string {
	out := make([]string, 0, len(values))
	for _, value := range values {
		if trimmed := strings.TrimSpace(value); trimmed != "" {
			out = append(out, trimmed)
		}
	}
	return out
}

// mayGrant refuses a binding wider than the one the acting identity holds
// itself. It reads every permission the role carries and asks whether the actor
// has that permission in a scope containing the one being granted: the
// comparison is on what a binding reaches, not on columns that happen to match,
// so "any team" cannot be handed out by somebody bound to one team.
//
// The permissions are passed in rather than read off the role, and that is the
// whole of it: a role an installation defined carries nothing in the compiled
// map, so a guard that asked the role would have found an empty list, found
// nothing to object to, and let anybody holding principal.manage hand out a
// role they had just defined with every permission in the product. The caller
// resolves the role against the store, which answers for both kinds and
// refuses a name that is neither.
func mayGrant(actor authz.Principal, role authz.Role, permissions []authz.Permission, scope authz.Scope) error {
	if len(permissions) == 0 {
		// Not "nothing to check": a role resolved to nothing is a role nobody
		// read, and handing one out is the thing this refuses.
		return errors.New("the role " + string(role) + " carries no permission that could be checked against yours")
	}
	for _, permission := range permissions {
		if !holdsInScope(actor, permission, scope) {
			return errors.New("the role " + string(role) + " carries " + string(permission) +
				", which you do not hold in " + scope.String())
		}
	}
	return nil
}

// resolveRole answers what a role carries - the product's own from the code,
// an installation's own from its database - and writes the refusal itself for
// a name that is neither.
//
// Every caller that used to ask authz.KnownRole asks this instead. The
// difference matters in both directions: the compiled list would refuse a
// role the installation defined, and an empty answer for an unresolvable name
// would be read by the escalation guard as a role carrying nothing.
func (s *Server) resolveRole(w http.ResponseWriter, r *http.Request, role authz.Role) ([]authz.Permission, bool) {
	permissions, err := s.authz.RolePermissions(r.Context(), role)
	if errors.Is(err, authz.ErrUnknownRole) {
		problem(w, http.StatusBadRequest, "unknown_role", "unknown role "+string(role))
		return nil, false
	}
	if err != nil {
		s.fail(w, err)
		return nil, false
	}
	return permissions, true
}

func holdsInScope(actor authz.Principal, permission authz.Permission, scope authz.Scope) bool {
	for _, own := range actor.ScopesFor(permission) {
		if own.Contains(scope) {
			return true
		}
	}
	return false
}

// refuseEscalation answers the attempt and records it: somebody trying to widen
// access beyond their own is worth reading in the trail afterwards.
func (s *Server) refuseEscalation(w http.ResponseWriter, r *http.Request,
	actor authz.Principal, action, target string, err error) {
	s.audit.Record(r.Context(), audit.Event{
		ActorType: audit.ActorUser, ActorID: actor.Subject,
		Action: action, TargetType: "principal", TargetID: target,
		RequestID: requestIDOf(r), Outcome: audit.OutcomeDenied,
		Detail: map[string]any{"reason": "scope_escalation", "message": err.Error()},
	})
	problem(w, http.StatusForbidden, "scope_escalation", err.Error())
}

// parse reads the scope and the validity. Whether the name is a role at all
// is not answered here: an installation defines roles of its own, so that
// question belongs to the store, and the caller asks it with resolveRole.
func (request roleRequest) parse() (authz.Role, authz.Scope, *time.Time, error) {
	role := authz.Role(request.Role)
	if strings.TrimSpace(request.Role) == "" {
		return "", authz.Scope{}, nil, errors.New("a binding names a role")
	}
	scope, err := request.scope()
	if err != nil {
		return "", authz.Scope{}, nil, err
	}
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
	// A binding is one row per role, site and environment; the owners and the tags
	// live on that row. So the row is found by its placement and reported with the
	// scope it actually carries, which is what a grant narrowed by owner replaced.
	for _, binding := range bindings {
		if binding.Role != role || !binding.Scope.TeamAny {
			continue
		}
		if samePlacement(binding.Scope.Site, scope.Site) &&
			samePlacement(binding.Scope.Environment, scope.Environment) {
			return bindingRecord(binding.Role, binding.Scope, binding.ValidUntil)
		}
	}
	return nil
}

// samePlacement compares one part of a placement, where an empty request and a
// stored asterisk mean the same thing.
func samePlacement(stored, requested string) bool {
	if requested == "" {
		return stored == authz.Wildcard || stored == ""
	}
	return stored == requested
}

type grantRoleRequest struct {
	roleRequest
	Reason string `json:"reason"`
}

// handleGrantRole adds one binding to an identity, or changes the validity of
// one it already has.
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
	carried, ok := s.resolveRole(w, r, role)
	if !ok {
		return
	}
	if err := mayGrant(actor, role, carried, scope); err != nil {
		s.refuseEscalation(w, r, actor, "principal.role.grant", target.ID, err)
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
		carried, ok := s.resolveRole(w, r, role)
		if !ok {
			return
		}
		if err := mayGrant(actor, role, carried, scope); err != nil {
			s.refuseEscalation(w, r, actor, "principal.create", request.Subject, err)
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
	// Owners and Tags narrow the mapping as they narrow a binding made by
	// hand. Left out they mean every one of that category; sent empty they
	// reach none, and the store refuses that rather than writing a rule
	// somebody would read as granting something.
	Owners []string `json:"owners"`
	Tags   []string `json:"tags"`
	Reason string   `json:"reason"`
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

// groupMappingsTag is the entity tag of the access mappings as a set.
func groupMappingsTag(mappings []authz.GroupMapping) string {
	parts := make([]string, 0, len(mappings))
	for _, mapping := range mappings {
		parts = append(parts, mapping.ID)
	}
	return etagOf(parts...)
}

// requireGroupMappingsMatch enforces If-Match against the current set of
// mappings: an administrator who adds or removes a rule decides against the
// list they read, and the list may have changed under them.
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

// handleCreateGroupMapping adds a mapping of a group to a role in a scope. The
// group grants only a candidate role; the scope remains the panel policy.
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
	if _, ok := s.resolveRole(w, r, authz.Role(request.Role)); !ok {
		return
	}

	// The mapping of a group to a role decides whom the identity provider lets in
	// and with what permissions; it is a change of the access rule itself.
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
		authz.Role(request.Role),
		authz.PlacementWithin(request.Site, request.Environment, request.Owners, request.Tags),
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
	// The reason at removal is read from the parameter or from the body,
	// like every other change: a client that sends it the way the roles
	// take it is not answered with "a reason is required".
	reason, ok := requestReason(w, r, nil)
	if !ok {
		return
	}
	evidence, ok := s.requireStepUp(w, r, actor, reason,
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

// handleAccessReview lists every enabled identity with what it can do, when it
// was last used and what the reviewer should look at.
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
