package adminapi

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strconv"
	"strings"

	"github.com/google/uuid"

	"github.com/ultherego/flotestro/internal/audit"
	"github.com/ultherego/flotestro/internal/authz"
	"github.com/ultherego/flotestro/internal/hosts"
	"github.com/ultherego/flotestro/internal/paging"
	"github.com/ultherego/flotestro/internal/selector"
)

// groupRequest is the body of a group to create or to change.
type groupRequest struct {
	Name        string               `json:"name"`
	Description string               `json:"description,omitempty"`
	Kind        string               `json:"kind,omitempty"`
	Selector    *selector.Expression `json:"selector,omitempty"`
	// HostIDs is the member list of a static group, given at creation so
	// that a group and its members come into being in one order.
	HostIDs []string `json:"host_ids,omitempty"`
}

type groupMembersRequest struct {
	// HostIDs is the whole member list: a host left out is a host removed.
	HostIDs []string `json:"host_ids"`
}

// handleListGroups lists the saved groups with their sizes.
//
// A static group is counted in the database; a dynamic one is counted
// against the caller's scope, because its size is the answer of its
// selector for whoever asks. A dynamic group whose selector no longer
// resolves - a referenced group was deleted - is listed with the reason
// rather than with a zero.
func (s *Server) handleListGroups(w http.ResponseWriter, r *http.Request) {
	principal, ok := s.authorizeCollection(w, r, authz.PermHostRead, "host_group")
	if !ok {
		return
	}
	groups, err := s.groups.List(r.Context())
	if err != nil {
		s.fail(w, err)
		return
	}
	scopes := principal.ScopesFor(authz.PermHostRead)
	items := make([]groupView, 0, len(groups))
	for _, group := range groups {
		items = append(items, s.groupView(r.Context(), group, scopes))
	}
	writeJSON(w, http.StatusOK, map[string]any{"items": items, "count": len(items)})
}

// groupView is a group as the list shows it: the record and, when the
// selector does not resolve, why.
type groupView struct {
	selector.SavedGroup
	Unresolvable string `json:"unresolvable,omitempty"`
}

// groupView counts a dynamic group for the caller. A static group already
// carries its count from the store.
func (s *Server) groupView(ctx context.Context, group selector.SavedGroup, scopes []authz.Scope) groupView {
	view := groupView{SavedGroup: group}
	if group.Kind != selector.KindDynamic {
		return view
	}
	expanded, err := selector.Expand(ctx, group.Selector, s.groups)
	if err != nil {
		view.Unresolvable = err.Error()
		return view
	}
	count, err := s.hosts.Count(ctx, hosts.ListFilter{Expression: expanded, Scopes: scopes})
	if err != nil {
		// The count is left empty rather than made up; the list still says
		// the group exists.
		s.log.Error("counting a dynamic group failed", "group", group.Name, "err", err)
		return view
	}
	view.MemberCount = &count
	return view
}

func (s *Server) handleGetGroup(w http.ResponseWriter, r *http.Request) {
	principal, ok := s.authorizeCollection(w, r, authz.PermHostRead, "host_group")
	if !ok {
		return
	}
	group, err := s.groups.Get(r.Context(), r.PathValue("id"))
	if s.groupProblem(w, err) {
		return
	}
	// The tag names the version of the record; a member change moves
	// updated_at too, so it covers the list as well as the definition.
	setETag(w, etagOfTime(group.UpdatedAt))
	writeJSON(w, http.StatusOK, s.groupView(r.Context(), *group, principal.ScopesFor(authz.PermHostRead)))
}

// handleCreateGroup records a group. A static group may come with its
// members; a dynamic one has to come with a selector, which is validated
// and resolved once here, so a group that can never answer is refused at
// creation rather than at the first campaign.
func (s *Server) handleCreateGroup(w http.ResponseWriter, r *http.Request) {
	principal, ok := s.authorizeCollection(w, r, authz.PermHostGroupWrite, "host_group")
	if !ok {
		return
	}
	var request groupRequest
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<20)).Decode(&request); err != nil {
		problem(w, http.StatusBadRequest, "invalid_body", "the request body is not valid JSON")
		return
	}
	kind := selector.Kind(orDefault(request.Kind, string(selector.KindStatic)))
	if kind == selector.KindDynamic && request.Selector != nil {
		if err := request.Selector.Validate(); err != nil {
			s.selectorProblem(w, err)
			return
		}
		if _, err := selector.Expand(r.Context(), request.Selector, s.groups); err != nil {
			s.selectorProblem(w, err)
			return
		}
	}
	if kind == selector.KindDynamic && len(request.HostIDs) > 0 {
		problem(w, http.StatusBadRequest, "invalid_group",
			"a dynamic group has no member list; its selector decides")
		return
	}
	var visible []hosts.Host
	if len(request.HostIDs) > 0 {
		if visible, ok = s.visibleHosts(w, r, principal, request.HostIDs); !ok {
			return
		}
	}

	group, err := s.groups.Create(r.Context(), selector.SavedGroup{
		Name:        strings.TrimSpace(request.Name),
		Description: strings.TrimSpace(request.Description),
		Kind:        kind,
		Selector:    request.Selector,
		CreatedBy:   principal.Subject,
	})
	if s.groupProblem(w, err) {
		return
	}
	if len(visible) > 0 {
		if err := s.groups.SetMembers(r.Context(), group.ID, hostIDs(visible)); s.groupProblem(w, err) {
			return
		}
		group, err = s.groups.Get(r.Context(), group.ID)
		if s.groupProblem(w, err) {
			return
		}
	}
	s.audit.Record(r.Context(), audit.Event{
		ActorType: audit.ActorUser, ActorID: principal.Subject,
		Action: "host_group.create", TargetType: "host_group", TargetID: group.ID,
		RequestID: requestIDOf(r), Outcome: audit.OutcomeSuccess,
		Detail: map[string]any{
			"name": group.Name, "kind": string(group.Kind),
			"selector": group.Selector.Describe(), "members": len(visible),
		},
	})
	writeJSON(w, http.StatusCreated, s.groupView(r.Context(), *group, principal.ScopesFor(authz.PermHostRead)))
}

// handleUpdateGroup changes the name, the description and the selector.
// The kind stays: turning a list into a selector is a new group.
func (s *Server) handleUpdateGroup(w http.ResponseWriter, r *http.Request) {
	principal, ok := s.authorizeCollection(w, r, authz.PermHostGroupWrite, "host_group")
	if !ok {
		return
	}
	current, err := s.groups.Get(r.Context(), r.PathValue("id"))
	if s.groupProblem(w, err) {
		return
	}
	if !requireMatch(w, r, etagOfTime(current.UpdatedAt)) {
		return
	}
	var request groupRequest
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<20)).Decode(&request); err != nil {
		problem(w, http.StatusBadRequest, "invalid_body", "the request body is not valid JSON")
		return
	}
	if request.Kind != "" && selector.Kind(request.Kind) != current.Kind {
		problem(w, http.StatusBadRequest, "invalid_group",
			"the kind of a group does not change; create a new group instead")
		return
	}
	if current.Kind == selector.KindDynamic && request.Selector != nil {
		if err := request.Selector.Validate(); err != nil {
			s.selectorProblem(w, err)
			return
		}
		// A group that names itself, however indirectly, is refused here
		// and not at the first campaign that tries to resolve it.
		if _, err := selector.Expand(r.Context(), request.Selector,
			groupsWithout(s.groups, current.ID, request.Selector)); err != nil {
			s.selectorProblem(w, err)
			return
		}
	}
	updated, err := s.groups.Update(r.Context(), current.ID, selector.SavedGroup{
		Name:        strings.TrimSpace(orDefault(request.Name, current.Name)),
		Description: strings.TrimSpace(request.Description),
		Selector:    orSelector(request.Selector, current.Selector),
	})
	if s.groupProblem(w, err) {
		return
	}
	s.audit.Record(r.Context(), audit.Event{
		ActorType: audit.ActorUser, ActorID: principal.Subject,
		Action: "host_group.update", TargetType: "host_group", TargetID: updated.ID,
		RequestID: requestIDOf(r), Outcome: audit.OutcomeSuccess,
		Detail: map[string]any{
			"name": updated.Name, "previous_name": current.Name,
			"selector": updated.Selector.Describe(), "previous_selector": current.Selector.Describe(),
		},
	})
	setETag(w, etagOfTime(updated.UpdatedAt))
	writeJSON(w, http.StatusOK, s.groupView(r.Context(), *updated, principal.ScopesFor(authz.PermHostRead)))
}

func (s *Server) handleDeleteGroup(w http.ResponseWriter, r *http.Request) {
	principal, ok := s.authorizeCollection(w, r, authz.PermHostGroupWrite, "host_group")
	if !ok {
		return
	}
	group, err := s.groups.Get(r.Context(), r.PathValue("id"))
	if s.groupProblem(w, err) {
		return
	}
	if err := s.groups.Delete(r.Context(), group.ID); s.groupProblem(w, err) {
		return
	}
	s.audit.Record(r.Context(), audit.Event{
		ActorType: audit.ActorUser, ActorID: principal.Subject,
		Action: "host_group.delete", TargetType: "host_group", TargetID: group.ID,
		RequestID: requestIDOf(r), Outcome: audit.OutcomeSuccess,
		Detail: map[string]any{"name": group.Name, "kind": string(group.Kind)},
	})
	w.WriteHeader(http.StatusNoContent)
}

// handleSetGroupMembers replaces the member list of a static group.
//
// Every named host has to exist and be visible to the caller: a group is
// a way of naming campaign targets, and it must not let anybody name a
// host they could not see on the list.
func (s *Server) handleSetGroupMembers(w http.ResponseWriter, r *http.Request) {
	principal, ok := s.authorizeCollection(w, r, authz.PermHostGroupWrite, "host_group")
	if !ok {
		return
	}
	group, err := s.groups.Get(r.Context(), r.PathValue("id"))
	if s.groupProblem(w, err) {
		return
	}
	// The list is replaced whole, so a stale copy would drop the members
	// somebody else added since it was read.
	if !requireMatch(w, r, etagOfTime(group.UpdatedAt)) {
		return
	}
	var request groupMembersRequest
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<20)).Decode(&request); err != nil {
		problem(w, http.StatusBadRequest, "invalid_body", "the request body is not valid JSON")
		return
	}
	visible, ok := s.visibleHosts(w, r, principal, request.HostIDs)
	if !ok {
		return
	}
	if err := s.groups.SetMembers(r.Context(), group.ID, hostIDs(visible)); s.groupProblem(w, err) {
		return
	}
	updated, err := s.groups.Get(r.Context(), group.ID)
	if s.groupProblem(w, err) {
		return
	}
	s.audit.Record(r.Context(), audit.Event{
		ActorType: audit.ActorUser, ActorID: principal.Subject,
		Action: "host_group.members", TargetType: "host_group", TargetID: group.ID,
		RequestID: requestIDOf(r), Outcome: audit.OutcomeSuccess,
		Detail: map[string]any{
			"name": group.Name, "members": len(visible),
			"sample": hostNames(visible[:min(len(visible), previewSampleSize)]),
		},
	})
	setETag(w, etagOfTime(updated.UpdatedAt))
	writeJSON(w, http.StatusOK, s.groupView(r.Context(), *updated, principal.ScopesFor(authz.PermHostRead)))
}

// handleGroupHosts lists the hosts a group resolves to, page by page like
// the host list and narrowed to what the caller may read.
func (s *Server) handleGroupHosts(w http.ResponseWriter, r *http.Request) {
	principal, ok := s.authorizeCollection(w, r, authz.PermHostRead, "host_group")
	if !ok {
		return
	}
	group, err := s.groups.Get(r.Context(), r.PathValue("id"))
	if s.groupProblem(w, err) {
		return
	}
	expanded, err := selector.Expand(r.Context(), &selector.Expression{Group: group.ID}, s.groups)
	if err != nil {
		s.selectorProblem(w, err)
		return
	}
	query := r.URL.Query()
	filter := hosts.ListFilter{
		Search:          strings.TrimSpace(query.Get("q")),
		ConnectionState: query.Get("connection_state"),
		Expression:      expanded,
		Scopes:          principal.ScopesFor(authz.PermHostRead),
	}
	cursor, err := hosts.ParseCursor(query.Get("cursor"))
	if err != nil {
		problem(w, http.StatusBadRequest, "invalid_cursor", err.Error())
		return
	}
	limit, _ := strconv.Atoi(query.Get("limit"))
	page, err := s.hosts.ListPaged(r.Context(), filter, cursor,
		paging.Limit(limit, defaultListPage, maxListPage))
	if err != nil {
		s.fail(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"items": page.Items, "count": len(page.Items),
		"total": page.Total, "next_cursor": page.NextCursor,
	})
}

// visibleHosts reads the named hosts, narrowed to the caller's scope. A
// host that is missing or out of scope ends the request with the names of
// what was not found; the caller must not learn which of the two it was.
// The answer has already been written when the second result is false.
func (s *Server) visibleHosts(w http.ResponseWriter, r *http.Request, principal authz.Principal,
	ids []string) ([]hosts.Host, bool) {
	if len(ids) > selector.MaxMembers {
		problem(w, http.StatusBadRequest, "invalid_group",
			fmt.Sprintf("a group holds at most %d hosts", selector.MaxMembers))
		return nil, false
	}
	wanted := make([]string, 0, len(ids))
	for _, id := range ids {
		id = strings.TrimSpace(id)
		if id == "" {
			continue
		}
		if _, err := uuid.Parse(id); err != nil {
			problem(w, http.StatusBadRequest, "unknown_hosts", id+" is not a host identifier")
			return nil, false
		}
		wanted = append(wanted, id)
	}
	if len(wanted) == 0 {
		return []hosts.Host{}, true
	}
	found, err := s.pageHosts(r.Context(), hosts.ListFilter{
		IDs: wanted, Scopes: principal.ScopesFor(authz.PermHostRead),
	})
	if err != nil {
		s.fail(w, err)
		return nil, false
	}
	seen := map[string]bool{}
	for _, host := range found {
		seen[host.ID] = true
	}
	var missing []string
	for _, id := range wanted {
		if !seen[id] && len(missing) < previewSampleSize {
			missing = append(missing, id)
		}
	}
	if len(missing) > 0 {
		problem(w, http.StatusBadRequest, "unknown_hosts",
			"these hosts do not exist or are outside your scope: "+strings.Join(missing, ", "))
		return nil, false
	}
	return found, true
}

// pageHosts reads every host matching the filter, page by page and with
// the explicit bound of one campaign: a list bigger than that is usually
// a wrong selector, and it ends in an error rather than a trimmed list.
func (s *Server) pageHosts(ctx context.Context, filter hosts.ListFilter) ([]hosts.Host, error) {
	result := make([]hosts.Host, 0, hosts.PageSize)
	afterName, afterID := "", ""
	for {
		page, err := s.hosts.Page(ctx, filter, afterName, afterID, hosts.PageSize)
		if err != nil {
			return nil, err
		}
		result = append(result, page...)
		if len(page) < hosts.PageSize {
			return result, nil
		}
		if len(result) > maxCampaignSnapshot {
			return nil, fmt.Errorf("%w: the selector covers more than %d hosts",
				ErrSelectorTooBroad, maxCampaignSnapshot)
		}
		last := page[len(page)-1]
		afterName, afterID = last.Hostname, last.ID
	}
}

func hostIDs(list []hosts.Host) []string {
	ids := make([]string, 0, len(list))
	for _, host := range list {
		ids = append(ids, host.ID)
	}
	return ids
}

// groupProblem translates a store error into an answer. It returns true
// when the request is over.
func (s *Server) groupProblem(w http.ResponseWriter, err error) bool {
	switch {
	case err == nil:
		return false
	case errors.Is(err, selector.ErrGroupNotFound):
		problem(w, http.StatusNotFound, "group_not_found", "no such group")
	case errors.Is(err, selector.ErrNameTaken):
		problem(w, http.StatusConflict, "group_name_taken", err.Error())
	case errors.Is(err, selector.ErrNotStatic):
		problem(w, http.StatusBadRequest, "group_not_static", err.Error())
	case errors.Is(err, selector.ErrUnknownHosts):
		problem(w, http.StatusBadRequest, "unknown_hosts", err.Error())
	case errors.Is(err, selector.ErrInvalid):
		problem(w, http.StatusBadRequest, "invalid_group", err.Error())
	default:
		s.fail(w, err)
	}
	return true
}

// selectorProblem answers a selector that does not resolve: a shape that
// does not hold together, a group that does not exist, or a group that
// refers to itself.
func (s *Server) selectorProblem(w http.ResponseWriter, err error) {
	switch {
	case errors.Is(err, selector.ErrCycle):
		problem(w, http.StatusBadRequest, "selector_cycle", err.Error())
	case errors.Is(err, selector.ErrUnknownGroup):
		problem(w, http.StatusBadRequest, "unknown_group", err.Error())
	case errors.Is(err, selector.ErrInvalid), errors.Is(err, selector.ErrUnexpanded):
		problem(w, http.StatusBadRequest, "invalid_selector", err.Error())
	default:
		s.fail(w, err)
	}
}

// groupsWithout resolves references as the store does, except that the
// group being edited answers with the selector under review rather than
// with the one recorded. Without it a group could be edited into a cycle:
// the check would read the old, harmless definition from the database.
func groupsWithout(store selector.Groups, id string, pending *selector.Expression) selector.Groups {
	return groupOverlay{Groups: store, id: id, pending: pending}
}

type groupOverlay struct {
	selector.Groups
	id      string
	pending *selector.Expression
}

func (o groupOverlay) Lookup(ctx context.Context, ref string) (*selector.Group, error) {
	group, err := o.Groups.Lookup(ctx, ref)
	if err != nil || group == nil {
		return group, err
	}
	if group.ID == o.id {
		replaced := *group
		replaced.Selector = o.pending
		return &replaced, nil
	}
	return group, nil
}

func orSelector(value, fallback *selector.Expression) *selector.Expression {
	if value == nil {
		return fallback
	}
	return value
}
