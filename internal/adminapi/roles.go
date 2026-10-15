package adminapi

import (
	"encoding/json"
	"errors"
	"net/http"
	"sort"
	"strings"

	"github.com/ultherego/flotestro/internal/audit"
	"github.com/ultherego/flotestro/internal/authz"
)

// The roles of an installation: the six the product defines, which nobody
// here may edit, and the ones this installation defined for itself.
//
// Why a role of one's own is worth having at all: the product's six are a
// guess at how a fleet is run, and they are either too wide or too narrow for
// most of the people who have to be given access. "Restart a service and read
// the journal, nothing else" is a real job on a real rota, and until this it
// could only be had by handing somebody operator - which also reboots hosts,
// installs packages and decommissions machines.

// roleRequestBody is a role as the screen defines it.
type roleRequestBody struct {
	Role        string   `json:"role"`
	Description string   `json:"description"`
	Permissions []string `json:"permissions"`
	Reason      string   `json:"reason"`
}

// handleListRoles describes the role catalogue and its permissions: both the
// product's roles and this installation's own, with how much each is used.
func (s *Server) handleListRoles(w http.ResponseWriter, r *http.Request) {
	if _, ok := s.authorize(w, r, authz.PermHostRead, authz.GlobalScope, "role", ""); !ok {
		return
	}
	roles, err := s.authz.ListRoles(r.Context())
	if err != nil {
		s.fail(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"items": roles, "count": len(roles)})
}

// handleListPermissions is the vocabulary a role is written in: every
// permission this product defines, so a screen offering them does not have to
// keep a copy that drifts from the server's.
func (s *Server) handleListPermissions(w http.ResponseWriter, r *http.Request) {
	if _, ok := s.authorize(w, r, authz.PermHostRead, authz.GlobalScope, "role", ""); !ok {
		return
	}
	type permissionInfo struct {
		Permission string `json:"permission"`
		// Group is the first part of the name, which is how the panel sorts
		// 188 of these into something a person can read.
		Group string `json:"group"`
	}
	items := make([]permissionInfo, 0)
	for _, permission := range authz.AllPermissions() {
		name := string(permission)
		group := name
		if cut := strings.IndexByte(name, '.'); cut > 0 {
			group = name[:cut]
		}
		items = append(items, permissionInfo{Permission: name, Group: group})
	}
	writeJSON(w, http.StatusOK, map[string]any{"items": items, "count": len(items)})
}

// handleCreateRole defines a role of this installation's own.
func (s *Server) handleCreateRole(w http.ResponseWriter, r *http.Request) {
	actor, ok := s.authorize(w, r, authz.PermPrincipalManage, authz.GlobalScope, "role", "")
	if !ok {
		return
	}
	request, permissions, ok := s.readRoleRequest(w, r, actor)
	if !ok {
		return
	}
	name := strings.TrimSpace(request.Role)

	// Defining a role is a change to the access rules themselves, so it is
	// settled the same way a group mapping is.
	evidence, ok := s.requireStepUp(w, r, actor, request.Reason, "role.create", "role", name)
	if !ok {
		return
	}
	tx, err := s.authz.Pool().Begin(r.Context())
	if err != nil {
		s.fail(w, err)
		return
	}
	defer func() { _ = tx.Rollback(r.Context()) }()

	if err := s.authz.CreateRole(r.Context(), tx, name, request.Description, permissions, actor.Subject); err != nil {
		s.refuseRole(w, err)
		return
	}
	if err := s.audit.RecordTx(r.Context(), tx, audit.Event{
		ActorType: audit.ActorUser, ActorID: actor.Subject,
		Action: "role.create", TargetType: "role", TargetID: name,
		RequestID: requestIDOf(r), Outcome: audit.OutcomeSuccess,
		Detail: withStepUp(map[string]any{
			"role": name, "permissions": namesOf(permissions),
		}, evidence),
		After: map[string]any{"role": name, "description": request.Description,
			"permissions": namesOf(permissions)},
	}); err != nil {
		s.fail(w, err)
		return
	}
	if err := tx.Commit(r.Context()); err != nil {
		s.fail(w, err)
		return
	}
	writeJSON(w, http.StatusCreated, map[string]any{
		"role": name, "built_in": false, "description": request.Description,
		"permissions": namesOf(permissions),
	})
}

// handleReplaceRole sets what a role of this installation's own carries.
//
// The permissions are replaced whole, and the trail keeps what they were: a
// role narrowed takes something away from everybody bound to it, and the only
// way to see that afterwards is to have written down both sides.
func (s *Server) handleReplaceRole(w http.ResponseWriter, r *http.Request) {
	actor, ok := s.authorize(w, r, authz.PermPrincipalManage, authz.GlobalScope, "role", r.PathValue("role"))
	if !ok {
		return
	}
	name := r.PathValue("role")
	if authz.BuiltIn(authz.Role(name)) {
		problem(w, http.StatusConflict, "built_in_role",
			"the role "+name+" is defined by the product and its permissions are in the code")
		return
	}
	request, permissions, ok := s.readRoleRequest(w, r, actor)
	if !ok {
		return
	}
	before, err := s.roleBefore(r, name)
	if err != nil {
		s.refuseRole(w, err)
		return
	}
	evidence, ok := s.requireStepUp(w, r, actor, request.Reason, "role.update", "role", name)
	if !ok {
		return
	}
	tx, err := s.authz.Pool().Begin(r.Context())
	if err != nil {
		s.fail(w, err)
		return
	}
	defer func() { _ = tx.Rollback(r.Context()) }()

	if err := s.authz.ReplaceRole(r.Context(), tx, name, request.Description, permissions); err != nil {
		s.refuseRole(w, err)
		return
	}
	if err := s.audit.RecordTx(r.Context(), tx, audit.Event{
		ActorType: audit.ActorUser, ActorID: actor.Subject,
		Action: "role.update", TargetType: "role", TargetID: name,
		RequestID: requestIDOf(r), Outcome: audit.OutcomeSuccess,
		Detail: withStepUp(map[string]any{
			"role": name, "permissions": namesOf(permissions),
			// What everybody bound to this role loses, named rather than left
			// to a reader to work out by comparing two lists.
			"removed": removed(before.Permissions, namesOf(permissions)),
		}, evidence),
		Before: before,
		After: map[string]any{"role": name, "description": request.Description,
			"permissions": namesOf(permissions)},
	}); err != nil {
		s.fail(w, err)
		return
	}
	if err := tx.Commit(r.Context()); err != nil {
		s.fail(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"role": name, "built_in": false, "description": request.Description,
		"permissions": namesOf(permissions),
	})
}

// handleDeleteRole removes a role of this installation's own. A role somebody
// is bound to is refused rather than quietly stripping their access.
func (s *Server) handleDeleteRole(w http.ResponseWriter, r *http.Request) {
	actor, ok := s.authorize(w, r, authz.PermPrincipalManage, authz.GlobalScope, "role", r.PathValue("role"))
	if !ok {
		return
	}
	name := r.PathValue("role")
	if authz.BuiltIn(authz.Role(name)) {
		problem(w, http.StatusConflict, "built_in_role",
			"the role "+name+" is defined by the product and cannot be deleted")
		return
	}
	var request roleRequestBody
	reason, ok := requestReason(w, r, &request)
	if !ok {
		return
	}
	before, err := s.roleBefore(r, name)
	if err != nil {
		s.refuseRole(w, err)
		return
	}
	evidence, ok := s.requireStepUp(w, r, actor, reason, "role.delete", "role", name)
	if !ok {
		return
	}
	tx, err := s.authz.Pool().Begin(r.Context())
	if err != nil {
		s.fail(w, err)
		return
	}
	defer func() { _ = tx.Rollback(r.Context()) }()

	if err := s.authz.DeleteRole(r.Context(), tx, name); err != nil {
		s.refuseRole(w, err)
		return
	}
	if err := s.audit.RecordTx(r.Context(), tx, audit.Event{
		ActorType: audit.ActorUser, ActorID: actor.Subject,
		Action: "role.delete", TargetType: "role", TargetID: name,
		RequestID: requestIDOf(r), Outcome: audit.OutcomeSuccess,
		Detail: withStepUp(map[string]any{"role": name}, evidence),
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

// readRoleRequest reads the body and refuses a definition the actor could not
// hold themselves.
//
// The guard is deliberately the strict one: every permission of the new role
// has to be held by its author in the global scope. A role is a global
// object - anybody with principal.manage may later bind it anywhere - so a
// definition written by somebody who holds those powers on one site only
// would be a way of handing them out everywhere else.
func (s *Server) readRoleRequest(w http.ResponseWriter, r *http.Request,
	actor authz.Principal) (roleRequestBody, []authz.Permission, bool) {
	var request roleRequestBody
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<16)).Decode(&request); err != nil {
		problem(w, http.StatusBadRequest, "invalid_body", "the request body is not valid JSON")
		return request, nil, false
	}
	permissions := make([]authz.Permission, 0, len(request.Permissions))
	for _, name := range request.Permissions {
		name = strings.TrimSpace(name)
		if name == "" {
			continue
		}
		permission := authz.Permission(name)
		if !authz.KnownPermission(permission) {
			problem(w, http.StatusBadRequest, "unknown_permission",
				"this product defines no permission called "+name)
			return request, nil, false
		}
		permissions = append(permissions, permission)
	}
	if len(permissions) == 0 {
		problem(w, http.StatusBadRequest, "empty_role", "a role carries at least one permission")
		return request, nil, false
	}
	sort.Slice(permissions, func(i, j int) bool { return permissions[i] < permissions[j] })
	for _, permission := range permissions {
		if !holdsInScope(actor, permission, authz.GlobalScope) {
			s.refuseEscalation(w, r, actor, "role.define", strings.TrimSpace(request.Role),
				errors.New("the role would carry "+string(permission)+
					", which you do not hold everywhere"))
			return request, nil, false
		}
	}
	return request, permissions, true
}

// roleBefore reads a role as it stands, for the trail and for the refusal of
// a name that is not there.
func (s *Server) roleBefore(r *http.Request, name string) (authz.RoleDefinition, error) {
	roles, err := s.authz.ListRoles(r.Context())
	if err != nil {
		return authz.RoleDefinition{}, err
	}
	for _, role := range roles {
		if role.Name == name {
			return role, nil
		}
	}
	return authz.RoleDefinition{}, errors.New("no such role: " + name)
}

// refuseRole turns the store's answers into the four different things there
// are to say, rather than one 500 for all of them.
func (s *Server) refuseRole(w http.ResponseWriter, err error) {
	switch {
	case errors.Is(err, authz.ErrRoleExists):
		problem(w, http.StatusConflict, "role_exists", err.Error())
	case errors.Is(err, authz.ErrBuiltInRole):
		problem(w, http.StatusConflict, "built_in_role", err.Error())
	case errors.Is(err, authz.ErrRoleInUse):
		problem(w, http.StatusConflict, "role_in_use",
			err.Error()+"; revoke the bindings and the group mappings that name it first")
	case errors.Is(err, authz.ErrUnknownRole), strings.HasPrefix(err.Error(), "no such role"):
		problem(w, http.StatusNotFound, "unknown_role", err.Error())
	default:
		problem(w, http.StatusBadRequest, "invalid_role", err.Error())
	}
}

func namesOf(permissions []authz.Permission) []string {
	names := make([]string, 0, len(permissions))
	for _, permission := range permissions {
		names = append(names, string(permission))
	}
	return names
}

// removed is what the old definition had and the new one does not.
func removed(before, after []string) []string {
	keeps := map[string]bool{}
	for _, name := range after {
		keeps[name] = true
	}
	gone := make([]string, 0)
	for _, name := range before {
		if !keeps[name] {
			gone = append(gone, name)
		}
	}
	return gone
}
