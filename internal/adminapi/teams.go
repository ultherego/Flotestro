package adminapi

import (
	"errors"
	"net/http"

	"github.com/ultherego/flotestro/internal/audit"
	"github.com/ultherego/flotestro/internal/authz"
	"github.com/ultherego/flotestro/internal/hosts"
)

// Teams: the register of the groups a role binding may name.
//
// The security document decides which of the three words a fleet is
// described with may be an authorisation boundary, and only one of them
// may: not a tag, because an operator edits tags and would be editing
// their own authority; not an owner, because it is a name typed into a
// field; a team, because it is a row with an identifier that outlives
// every rename.
//
// The register is therefore a small thing on purpose. It holds names and
// descriptions, and the two operations that matter happen elsewhere: a
// host is put into a team by the placement route, and a role is granted
// over a team by the access route. Both are separate decisions with
// separate permissions, and both are in the trail.

// teamRequest is the whole of a team as a caller writes it. The name is
// sent even when only the description changes, so a write reads as "the
// team is this" rather than as a patch two operators can interleave.
type teamRequest struct {
	Name        string `json:"name"`
	Description string `json:"description"`
	// Reason is why the register changes; creating, renaming and deleting
	// a team all move who may touch what, so the trail requires one.
	Reason string `json:"reason"`
}

// handleListTeams returns the teams with the number of hosts in each.
//
// The list is not narrowed: a team name is not a secret, it is printed on
// every host row that belongs to one, and somebody choosing a filter has
// to see the names to choose from. What the teams contain is narrowed -
// that is the host list's business, not this one's.
func (s *Server) handleListTeams(w http.ResponseWriter, r *http.Request) {
	if _, ok := s.authorizeCollection(w, r, authz.PermHostRead, "team"); !ok {
		return
	}
	teams, err := s.hosts.ListTeams(r.Context())
	if err != nil {
		s.fail(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"items": teams, "count": len(teams)})
}

// handleGetTeam returns one team.
func (s *Server) handleGetTeam(w http.ResponseWriter, r *http.Request) {
	if _, ok := s.authorizeCollection(w, r, authz.PermHostRead, "team"); !ok {
		return
	}
	team, err := s.hosts.Team(r.Context(), r.PathValue("id"))
	if errors.Is(err, hosts.ErrTeamNotFound) {
		problem(w, http.StatusNotFound, "team_not_found", "no such team")
		return
	}
	if err != nil {
		s.fail(w, err)
		return
	}
	writeJSON(w, http.StatusOK, team)
}

// handleCreateTeam adds a team to the register. It creates a boundary
// nobody is on either side of yet: no host is in the new team and no
// binding names it, so the operation grants nothing by itself. It still
// takes the binding permission, a reason and fresh authentication,
// because the two operations it makes possible are the ones that move
// access.
func (s *Server) handleCreateTeam(w http.ResponseWriter, r *http.Request) {
	actor, ok := s.authorize(w, r, authz.PermTeamBindingWrite, authz.GlobalScope, "team", "")
	if !ok {
		return
	}
	var request teamRequest
	reason, ok := requestReason(w, r, &request)
	if !ok {
		return
	}
	evidence, ok := s.requireStepUp(w, r, actor, reason, "team.create", "team", request.Name)
	if !ok {
		return
	}

	team, err := s.hosts.CreateTeam(r.Context(), request.Name, request.Description, actor.Subject)
	if errors.Is(err, hosts.ErrInvalidTeam) {
		problem(w, http.StatusBadRequest, "invalid_team", err.Error())
		return
	}
	if errors.Is(err, hosts.ErrTeamNameTaken) {
		problem(w, http.StatusConflict, "team_name_taken", "another team already answers to that name")
		return
	}
	if err != nil {
		s.fail(w, err)
		return
	}

	s.audit.Record(r.Context(), audit.Event{
		ActorType: audit.ActorUser, ActorID: actor.Subject,
		Action: "team.create", TargetType: "team", TargetID: team.ID,
		RequestID: requestIDOf(r), Outcome: audit.OutcomeSuccess,
		Detail: withStepUp(map[string]any{"name": team.Name}, evidence),
		After:  map[string]any{"name": team.Name, "description": team.Description},
	})
	writeJSON(w, http.StatusCreated, team)
}

// handleUpdateTeam renames a team or rewrites its description. Nothing
// moves: the identifier is the boundary, so every binding and every host
// stay exactly where they were. That is the whole reason the document
// refuses a name as a scope and accepts a row.
func (s *Server) handleUpdateTeam(w http.ResponseWriter, r *http.Request) {
	actor, ok := s.authorize(w, r, authz.PermTeamBindingWrite, authz.GlobalScope, "team", r.PathValue("id"))
	if !ok {
		return
	}
	before, err := s.hosts.Team(r.Context(), r.PathValue("id"))
	if errors.Is(err, hosts.ErrTeamNotFound) {
		problem(w, http.StatusNotFound, "team_not_found", "no such team")
		return
	}
	if err != nil {
		s.fail(w, err)
		return
	}
	var request teamRequest
	reason, ok := requestReason(w, r, &request)
	if !ok {
		return
	}
	evidence, ok := s.requireStepUp(w, r, actor, reason, "team.update", "team", before.ID)
	if !ok {
		return
	}

	team, err := s.hosts.UpdateTeam(r.Context(), before.ID, request.Name, request.Description)
	if errors.Is(err, hosts.ErrInvalidTeam) {
		problem(w, http.StatusBadRequest, "invalid_team", err.Error())
		return
	}
	if errors.Is(err, hosts.ErrTeamNameTaken) {
		problem(w, http.StatusConflict, "team_name_taken", "another team already answers to that name")
		return
	}
	if errors.Is(err, hosts.ErrTeamNotFound) {
		problem(w, http.StatusNotFound, "team_not_found", "no such team")
		return
	}
	if err != nil {
		s.fail(w, err)
		return
	}

	s.audit.Record(r.Context(), audit.Event{
		ActorType: audit.ActorUser, ActorID: actor.Subject,
		Action: "team.update", TargetType: "team", TargetID: team.ID,
		RequestID: requestIDOf(r), Outcome: audit.OutcomeSuccess,
		Detail: withStepUp(map[string]any{"name": team.Name}, evidence),
		Before: map[string]any{"name": before.Name, "description": before.Description},
		After:  map[string]any{"name": team.Name, "description": team.Description},
	})
	writeJSON(w, http.StatusOK, team)
}

// handleDeleteTeam removes a team from the register.
//
// It deletes no machines. The hosts of the team stay and become
// unassigned, reachable through their site as they were before anybody
// drew this boundary; the bindings that named the team go with it,
// because an access to a group that no longer exists is an access nobody
// can read. The trail names the hosts that were released, so the person
// who deletes a team of forty hosts can see afterwards which forty went
// back to the site's operators.
func (s *Server) handleDeleteTeam(w http.ResponseWriter, r *http.Request) {
	actor, ok := s.authorize(w, r, authz.PermTeamBindingWrite, authz.GlobalScope, "team", r.PathValue("id"))
	if !ok {
		return
	}
	before, err := s.hosts.Team(r.Context(), r.PathValue("id"))
	if errors.Is(err, hosts.ErrTeamNotFound) {
		problem(w, http.StatusNotFound, "team_not_found", "no such team")
		return
	}
	if err != nil {
		s.fail(w, err)
		return
	}
	reason, ok := requestReason(w, r, nil)
	if !ok {
		return
	}
	evidence, ok := s.requireStepUp(w, r, actor, reason, "team.delete", "team", before.ID)
	if !ok {
		return
	}

	tx, err := s.pool.Begin(r.Context())
	if err != nil {
		s.fail(w, err)
		return
	}
	defer func() { _ = tx.Rollback(r.Context()) }()

	released, err := s.hosts.DeleteTeam(r.Context(), tx, before.ID)
	if errors.Is(err, hosts.ErrTeamNotFound) {
		problem(w, http.StatusNotFound, "team_not_found", "no such team")
		return
	}
	if err != nil {
		s.fail(w, err)
		return
	}
	names := make([]string, 0, len(released))
	for _, host := range released {
		names = append(names, host.Hostname)
	}
	if err := s.audit.RecordTx(r.Context(), tx, audit.Event{
		ActorType: audit.ActorUser, ActorID: actor.Subject,
		Action: "team.delete", TargetType: "team", TargetID: before.ID,
		RequestID: requestIDOf(r), Outcome: audit.OutcomeSuccess,
		Detail: withStepUp(map[string]any{
			"name": before.Name, "released_hosts": len(released), "hostnames": names,
		}, evidence),
		Before: map[string]any{"name": before.Name, "description": before.Description},
	}); err != nil {
		s.fail(w, err)
		return
	}
	if err := tx.Commit(r.Context()); err != nil {
		s.fail(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"deleted": before.ID, "released_hosts": released,
	})
}
