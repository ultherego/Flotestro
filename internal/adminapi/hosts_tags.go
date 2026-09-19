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

	// The trail keeps both lists: what the host carried and what it carries now.
	s.audit.Record(r.Context(), audit.Event{
		ActorType: audit.ActorUser, ActorID: principal.Subject,
		Action: "host.tags", TargetType: "host", TargetID: host.ID,
		RequestID: requestIDOf(r), Outcome: audit.OutcomeSuccess,
		Detail: map[string]any{"before": host.Tags, "after": tags},
		Before: map[string]any{"tags": tagList(host.Tags)},
		After:  map[string]any{"tags": tagList(tags)},
	})
	writeJSON(w, http.StatusOK, updated)
}

type hostChannelRequest struct {
	// Channel is the release channel: stable or beta.
	Channel string `json:"channel"`
}

// handleSetHostChannel moves a host to a release channel.
func (s *Server) handleSetHostChannel(w http.ResponseWriter, r *http.Request) {
	hostID := r.PathValue("id")
	host, scope, ok := s.hostScope(w, r, hostID)
	if !ok {
		return
	}
	principal, ok := s.authorize(w, r, authz.PermHostTagWrite, scope, "host", hostID)
	if !ok {
		return
	}

	var request hostChannelRequest
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<12)).Decode(&request); err != nil {
		problem(w, http.StatusBadRequest, "invalid_body", "the request body is not valid JSON")
		return
	}
	channel, err := hosts.NormalizeChannel(request.Channel)
	if errors.Is(err, hosts.ErrInvalidChannel) {
		problem(w, http.StatusBadRequest, "invalid_channel", err.Error())
		return
	}
	if err != nil {
		s.fail(w, err)
		return
	}

	updated, err := s.hosts.SetChannel(r.Context(), hostID, channel)
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
		Action: "host.channel", TargetType: "host", TargetID: host.ID,
		RequestID: requestIDOf(r), Outcome: audit.OutcomeSuccess,
		Detail: map[string]any{"before": host.ReleaseChannel, "after": channel},
		Before: map[string]any{"release_channel": host.ReleaseChannel},
		After:  map[string]any{"release_channel": channel},
	})
	writeJSON(w, http.StatusOK, updated)
}

// tagList renders a tag list for the trail: a host without tags has an
// empty list, not a missing one - the state was read, and it was empty.
func tagList(tags []string) []string {
	if tags == nil {
		return []string{}
	}
	return tags
}
