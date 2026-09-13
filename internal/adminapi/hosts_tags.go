package adminapi

import (
	"encoding/json"
	"errors"
	"net/http"

	"github.com/ultherego/flotestro/internal/audit"
	"github.com/ultherego/flotestro/internal/authz"
	"github.com/ultherego/flotestro/internal/hosts"
)

type hostTagsRequest struct {
	// Tags is the whole list: a tag left out is a tag removed.
	Tags []string `json:"tags"`
}

// handleSetHostTags replaces the tags of a host.
//
// Tags are facts an operator records about a host in the panel; the host
// itself is not asked and nothing runs on it, so this is not an operation
// and does not go through the task queue - the same reasoning as for a
// maintenance window. It has its own permission, because a tag decides
// which campaigns reach the host.
func (s *Server) handleSetHostTags(w http.ResponseWriter, r *http.Request) {
	hostID := r.PathValue("id")
	host, scope, ok := s.hostScope(w, r, hostID)
	if !ok {
		return
	}
	principal, ok := s.authorize(w, r, authz.PermHostTagWrite, scope, "host", hostID)
	if !ok {
		return
	}

	var request hostTagsRequest
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<16)).Decode(&request); err != nil {
		problem(w, http.StatusBadRequest, "invalid_body", "the request body is not valid JSON")
		return
	}
	tags, err := hosts.NormalizeTags(request.Tags)
	if errors.Is(err, hosts.ErrInvalidTags) {
		problem(w, http.StatusBadRequest, "invalid_tags", err.Error())
		return
	}
	if err != nil {
		s.fail(w, err)
		return
	}

	updated, err := s.hosts.SetTags(r.Context(), hostID, tags)
	if errors.Is(err, hosts.ErrNotFound) {
		problem(w, http.StatusNotFound, "host_not_found", "no such host")
		return
	}
	if err != nil {
		s.fail(w, err)
		return
	}

	// The trail keeps both lists: what the host carried and what it
	// carries now. A diff would be shorter, but the question asked of the
	// trail is "what was on this host on Tuesday", not "what changed".
	s.audit.Record(r.Context(), audit.Event{
		ActorType: audit.ActorUser, ActorID: principal.Subject,
		Action: "host.tags", TargetType: "host", TargetID: host.ID,
		RequestID: requestIDOf(r), Outcome: audit.OutcomeSuccess,
		Detail: map[string]any{"before": host.Tags, "after": tags},
	})
	writeJSON(w, http.StatusOK, updated)
}
