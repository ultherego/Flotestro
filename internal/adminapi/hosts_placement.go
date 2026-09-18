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
// serves. Both come with the enrollment order and are corrected here when
// the order was wrong or the machine moved. Like the owner and the tags,
// the placement is the panel's knowledge about the host - nothing runs on
// the machine - so it shares their permission and goes straight to the
// row. Unlike them it is load-bearing: see handleSetHostPlacement.

type hostPlacementRequest struct {
	// Site and Environment are the whole placement: both are sent, the
	// one that stays the same repeated, so the request reads as "this
	// host stands here" rather than as a patch.
	Site        string `json:"site"`
	Environment string `json:"environment"`
	// Reason is why the host moves; a move is rare enough and consequential
	// enough that the trail requires it.
	Reason string `json:"reason"`
}

// handleSetHostPlacement moves a host to a site and an environment.
//
// The placement is not a label. Three things key on it and none of them
// is re-evaluated when it changes, so the trail and the host page must
// say when the host moved, and this comment must say what the mover is
// expected to know:
//
//   - the budgets: an operation on the host loads the site:<site>:<family>
//     tokens of the site the host is in at admission time; a transaction
//     admitted under the old site releases its token there, and a campaign
//     already in flight keeps the capacity it was planned with;
//   - the group selectors: a dynamic group with a site or an environment
//     leaf is evaluated when it is read, so the host joins and leaves such
//     groups at the next read, not at the move - a campaign that resolved
//     its targets before the move keeps them;
//   - the scoping: every role binding matches on the host's site and
//     environment, so the operators who can see and change the host
//     change with the move; the mover must hold the permission in both
//     the old and the new scope, so a host cannot be carried out of the
//     scope of the person moving it, nor into a scope the mover does not
//     hold;
//   - the second person: the environment decides whether a change on the
//     host requires fresh authentication and a second approval, from the
//     next order on.
//
// The moment of the move is kept on the host as placement_changed_at.
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
	// The destination is authorised like the origin: the same permission,
	// in the scope the host is about to enter. The team travels with the
	// host - carrying a machine to another rack does not hand it to other
	// people - so the destination scope repeats it, and a mover authorised
	// through the host's team is not asked again for nothing.
	target := authz.Scope{Site: site, Environment: environment, Team: host.TeamID}
	if target != scope {
		if _, ok := s.authorize(w, r, authz.PermHostTagWrite, target, "host", hostID); !ok {
			return
		}
	}
	// The trail describes the move in the vocabulary the move is in. The
	// scope of a host in a team reads as its team, which is right for an
	// authorisation check and says nothing about a change of site, so the
	// two sides are rendered from the placement alone.
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

// hostTeamRequest names the team a host is to belong to. An empty team
// takes the host out of the one it is in; the field is always sent, so
// the request reads as "this host belongs here" rather than as a patch.
type hostTeamRequest struct {
	Team string `json:"team"`
	// Reason is why the host changes hands. A move between teams moves
	// who may act on the machine, so the trail requires one.
	Reason string `json:"reason"`
}

// handleSetHostTeam puts a host into a team or takes it out.
//
// This is a decision of its own and never a side effect of editing tags
// or metadata, which is the point of the security document's chapter 8.3.
// A tag may not be an authorisation boundary precisely because operators
// edit tags; if a host could change hands by having a tag rewritten, the
// boundary would be back where the document refused to put it. So the
// team has its own route, its own permission - host.scope.write, which
// only the platform administrator holds out of the box - its own reason
// and its own line in the trail.
//
// Both sides are authorised, as a move between sites is:
//
//   - in the scope the host is in now, so that nobody can take a machine
//     out of a team they have no rights over; without this check a person
//     holding one team could pull any host in the fleet into it and so
//     grant themselves everything;
//   - in the scope the host is about to enter, so that nobody can hand a
//     machine to a group they hold nothing over and lose sight of it.
//
// What the move changes is the same list a move between sites changes,
// read through the team instead of the site: who may see and change the
// host from the next request on. It re-evaluates nothing that is already
// under way - a campaign that resolved its targets keeps them, and a task
// already admitted runs - because a boundary moved under a running
// operation would be a different operation.
func (s *Server) handleSetHostTeam(w http.ResponseWriter, r *http.Request) {
	hostID := r.PathValue("id")
	host, _, ok := s.hostScope(w, r, hostID)
	if !ok {
		return
	}
	// The scope is read from the host here rather than taken from
	// hostScope, because this route is the one that moves it: it has to
	// see the team the host is in now whatever else a caller sends.
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

	// The destination team has to exist before it is authorised: a scope
	// nobody can name is not a scope, and the refusal should say the team
	// is unknown rather than that the permission is missing.
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
