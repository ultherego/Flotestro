package adminapi

import (
	"errors"
	"net/http"

	"github.com/ultherego/flotestro/internal/audit"
	"github.com/ultherego/flotestro/internal/authz"
	"github.com/ultherego/flotestro/internal/hosts"
)

// Teams: the register of the groups a role binding may name.

// teamRequest is the whole of a team as a caller writes it.
type teamRequest struct {
	Name        string `json:"name"`
	Description string `json:"description"`
	// Reason is why the register changes; creating, renaming and deleting
	// a team all move who may touch what, so the trail requires one.
	Reason string `json:"reason"`
}

// handleListTeams returns the teams with the number of hosts in each.
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

// handleCreateTeam adds a team to the register.
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

// handleUpdateTeam renames a team or rewrites its description.
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

// handleDeleteTeam removes a team from the register. It deletes no machines.
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
