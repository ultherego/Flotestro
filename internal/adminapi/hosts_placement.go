package adminapi

import (
	"encoding/json"
	"errors"
	"net/http"
	"strings"

	"github.com/ultherego/flotestro/internal/audit"
	"github.com/ultherego/flotestro/internal/authz"
	"github.com/ultherego/flotestro/internal/hosts"
)

// The placement of a host: the site it stands in and the environment it
// serves.

type hostPlacementRequest struct {
	// Site and Environment are the whole placement: both are sent, the one that
	// stays the same repeated, so the request reads as "this host stands here"
	// rather than as a patch.
	Site        string `json:"site"`
	Environment string `json:"environment"`
	// Reason is why the host moves; a move is rare enough and consequential
	// enough that the trail requires it.
	Reason string `json:"reason"`
}

// handleSetHostPlacement moves a host to a site and an environment. The
// placement is not a label.
func (s *Server) handleSetHostPlacement(w http.ResponseWriter, r *http.Request) {
	hostID := r.PathValue("id")
	host, scope, ok := s.hostScope(w, r, hostID)
	if !ok {
		return
	}
	principal, ok := s.authorize(w, r, authz.PermHostTagWrite, scope, "host", hostID)
	if !ok {
		return
	}
	if !requireMatch(w, r, hostFactsTag(host)) {
		return
	}

	var request hostPlacementRequest
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<12)).Decode(&request); err != nil {
		problem(w, http.StatusBadRequest, "invalid_body", "the request body is not valid JSON")
		return
	}
	request.Reason = strings.TrimSpace(request.Reason)
	if len([]rune(request.Reason)) < minimalStepUpReason {
		problem(w, http.StatusBadRequest, "reason_required",
			"moving a host must state its reason (field reason, min. 8 characters)")
		return
	}
	site, environment, err := hosts.NormalizePlacement(request.Site, request.Environment)
	if errors.Is(err, hosts.ErrInvalidPlacement) {
		problem(w, http.StatusBadRequest, "invalid_placement", err.Error())
		return
	}
	if err != nil {
		s.fail(w, err)
		return
	}
	// The destination is authorised like the origin: the same permission, in the
	// scope the host is about to enter.
	target := authz.Scope{Site: site, Environment: environment, Team: host.TeamID}
	if target != scope {
		if _, ok := s.authorize(w, r, authz.PermHostTagWrite, target, "host", hostID); !ok {
			return
		}
	}
	// The trail describes the move in the vocabulary the move is in.
	placedBefore := authz.Scope{Site: host.Site, Environment: host.Environment}
	placedAfter := authz.Scope{Site: site, Environment: environment}

	updated, err := s.hosts.SetPlacement(r.Context(), hostID, site, environment)
	if errors.Is(err, hosts.ErrNotFound) {
		problem(w, http.StatusNotFound, "host_not_found", "no such host")
		return
	}
	if err != nil {
		s.fail(w, err)
		return
	}

	s.audit.Record(r.Context(), audit.Event{
		ActorType: audit.ActorUser, ActorID: principal.Subject,
		Action: "host.placement", TargetType: "host", TargetID: host.ID,
		RequestID: requestIDOf(r), Outcome: audit.OutcomeSuccess,
		Detail: map[string]any{
			"before": placedBefore.String(), "after": placedAfter.String(), "reason": request.Reason,
		},
		Before: map[string]any{"site": host.Site, "environment": host.Environment},
		After:  map[string]any{"site": updated.Site, "environment": updated.Environment},
	})
	setETag(w, hostFactsTag(updated))
	writeJSON(w, http.StatusOK, updated)
}

// hostTeamRequest names the team a host is to belong to.
type hostTeamRequest struct {
	Team string `json:"team"`
	// Reason is why the host changes hands. A move between teams moves
	// who may act on the machine, so the trail requires one.
	Reason string `json:"reason"`
}

// handleSetHostTeam puts a host into a team or takes it out.
func (s *Server) handleSetHostTeam(w http.ResponseWriter, r *http.Request) {
	hostID := r.PathValue("id")
	host, _, ok := s.hostScope(w, r, hostID)
	if !ok {
		return
	}
	// The scope is read from the host here rather than taken from hostScope,
	// because this route is the one that moves it: it has to see the team the
	// host is in now whatever else a caller sends.
	scope := hosts.ScopeOf(host)
	actor, ok := s.authorize(w, r, authz.PermHostScopeWrite, scope, "host", hostID)
	if !ok {
		return
	}

	var request hostTeamRequest
	reason, ok := requestReason(w, r, &request)
	if !ok {
		return
	}
	request.Team = strings.TrimSpace(request.Team)

	// The destination team has to exist before it is authorised: a scope nobody
	// can name is not a scope, and the refusal should say the team is unknown
	// rather than that the permission is missing.
	var destination *hosts.Team
	if request.Team != "" {
		if !hosts.ValidTeamID(request.Team) {
			problem(w, http.StatusBadRequest, "invalid_team", "team must be a team identifier")
			return
		}
		found, err := s.hosts.Team(r.Context(), request.Team)
		if errors.Is(err, hosts.ErrTeamNotFound) {
			problem(w, http.StatusNotFound, "team_not_found", "no such team")
			return
		}
		if err != nil {
			s.fail(w, err)
			return
		}
		destination = found
	}
	if request.Team == host.TeamID {
		// Nothing moves, so nothing is recorded: a trail of writes that
		// changed nothing hides the ones that did.
		writeJSON(w, http.StatusOK, host)
		return
	}
	target := authz.Scope{Site: host.Site, Environment: host.Environment, Team: request.Team}
	if _, ok := s.authorize(w, r, authz.PermHostScopeWrite, target, "host", hostID); !ok {
		return
	}
	evidence, ok := s.requireStepUp(w, r, actor, reason, "host.scope.write", "host", hostID)
	if !ok {
		return
	}

	updated, err := s.hosts.SetHostTeam(r.Context(), hostID, request.Team)
	if errors.Is(err, hosts.ErrNotFound) {
		problem(w, http.StatusNotFound, "host_not_found", "no such host")
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

	detail := map[string]any{
		"before": scope.String(), "after": target.String(),
		"before_team_name": host.TeamName,
	}
	if destination != nil {
		detail["after_team_name"] = destination.Name
	}
	s.audit.Record(r.Context(), audit.Event{
		ActorType: audit.ActorUser, ActorID: actor.Subject,
		Action: "host.scope.write", TargetType: "host", TargetID: host.ID,
		RequestID: requestIDOf(r), Outcome: audit.OutcomeSuccess,
		Detail: withStepUp(detail, evidence),
		Before: map[string]any{"team_id": host.TeamID, "team": host.TeamName},
		After:  map[string]any{"team_id": updated.TeamID, "team": updated.TeamName},
	})
	writeJSON(w, http.StatusOK, updated)
}
