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
	// in the scope the host is about to enter.
	target := authz.Scope{Site: site, Environment: environment}
	if target != scope {
		if _, ok := s.authorize(w, r, authz.PermHostTagWrite, target, "host", hostID); !ok {
			return
		}
	}

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
			"before": scope.String(), "after": target.String(), "reason": request.Reason,
		},
		Before: map[string]any{"site": host.Site, "environment": host.Environment},
		After:  map[string]any{"site": updated.Site, "environment": updated.Environment},
	})
	setETag(w, hostFactsTag(updated))
	writeJSON(w, http.StatusOK, updated)
}
