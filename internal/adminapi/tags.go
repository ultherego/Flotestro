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

// The tag catalogue: every tag the fleet carries, in one place.

// handleListTags lists the tags of the visible hosts with the number of hosts
// carrying each.
func (s *Server) handleListTags(w http.ResponseWriter, r *http.Request) {
	principal, ok := s.authorizeCollection(w, r, authz.PermHostRead, "tag")
	if !ok {
		return
	}
	catalogue, err := s.hosts.TagCatalogue(r.Context(), principal.ScopesFor(authz.PermHostRead))
	if err != nil {
		s.fail(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"items": catalogue, "count": len(catalogue)})
}

type renameTagRequest struct {
	From string `json:"from"`
	To   string `json:"to"`
	// Reason is why the tag changes its name; a rename touches every host
	// carrying it, so the trail requires one.
	Reason string `json:"reason"`
}

// hostsListedInTrail bounds the hosts a rename names in its own event.
const hostsListedInTrail = 50

// handleRenameTag replaces one tag by another on every visible host.
func (s *Server) handleRenameTag(w http.ResponseWriter, r *http.Request) {
	principal, ok := s.authorizeCollection(w, r, authz.PermHostTagWrite, "tag")
	if !ok {
		return
	}

	var request renameTagRequest
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<12)).Decode(&request); err != nil {
		problem(w, http.StatusBadRequest, "invalid_body", "the request body is not valid JSON")
		return
	}
	request.Reason = strings.TrimSpace(request.Reason)
	if len([]rune(request.Reason)) < minimalStepUpReason {
		problem(w, http.StatusBadRequest, "reason_required",
			"renaming a tag must state its reason (field reason, min. 8 characters)")
		return
	}
	from, err := singleTag(request.From)
	if err != nil {
		problem(w, http.StatusBadRequest, "invalid_tags", "from: "+err.Error())
		return
	}
	to, err := singleTag(request.To)
	if err != nil {
		problem(w, http.StatusBadRequest, "invalid_tags", "to: "+err.Error())
		return
	}
	if from == to {
		problem(w, http.StatusBadRequest, "invalid_tags", "the new name is the old one")
		return
	}

	tx, err := s.pool.Begin(r.Context())
	if err != nil {
		s.fail(w, err)
		return
	}
	defer func() { _ = tx.Rollback(r.Context()) }()

	scopes := principal.ScopesFor(authz.PermHostTagWrite)
	changes, err := s.hosts.RenameTag(r.Context(), tx, from, to, scopes)
	if errors.Is(err, hosts.ErrInvalidTags) {
		problem(w, http.StatusBadRequest, "invalid_tags", err.Error())
		return
	}
	if err != nil {
		s.fail(w, err)
		return
	}
	if len(changes) == 0 {
		problem(w, http.StatusNotFound, "tag_not_found",
			"no host you may change carries the tag "+from)
		return
	}

	// Every host gets the same event a tag edit on its page would leave,
	// so its own trail is complete; the summary names the rename once.
	hostIDs := make([]string, 0, len(changes))
	for _, change := range changes {
		hostIDs = append(hostIDs, change.HostID)
		if err := s.audit.RecordTx(r.Context(), tx, audit.Event{
			ActorType: audit.ActorUser, ActorID: principal.Subject,
			Action: "host.tags", TargetType: "host", TargetID: change.HostID,
			RequestID: requestIDOf(r), Outcome: audit.OutcomeSuccess,
			Detail: map[string]any{
				"before": change.Before, "after": change.After,
				"rename": map[string]string{"from": from, "to": to}, "reason": request.Reason,
			},
			Before: map[string]any{"tags": tagList(change.Before)},
			After:  map[string]any{"tags": tagList(change.After)},
		}); err != nil {
			s.fail(w, err)
			return
		}
	}
	listed := hostIDs
	if len(listed) > hostsListedInTrail {
		listed = listed[:hostsListedInTrail]
	}
	if err := s.audit.RecordTx(r.Context(), tx, audit.Event{
		ActorType: audit.ActorUser, ActorID: principal.Subject,
		Action: "tag.rename", TargetType: "tag", TargetID: from,
		RequestID: requestIDOf(r), Outcome: audit.OutcomeSuccess,
		Detail: map[string]any{
			"from": from, "to": to, "reason": request.Reason,
			"hosts": len(changes), "host_ids": listed,
		},
		Before: map[string]any{"tag": from},
		After:  map[string]any{"tag": to},
	}); err != nil {
		s.fail(w, err)
		return
	}
	if err := tx.Commit(r.Context()); err != nil {
		s.fail(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"from": from, "to": to, "hosts": len(changes), "host_ids": hostIDs,
	})
}

// singleTag normalises one tag the way a host's list is normalised, and
// refuses an empty one: a rename from or to nothing is not a rename.
func singleTag(value string) (string, error) {
	tags, err := hosts.NormalizeTags([]string{value})
	if err != nil {
		return "", err
	}
	if len(tags) != 1 {
		return "", errors.New("a tag is required")
	}
	return tags[0], nil
}
