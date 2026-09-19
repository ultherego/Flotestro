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

// The notes of a host: what an operator wrote about the machine that fits no
// other field.

type hostNotesRequest struct {
	// Notes is the whole text; empty clears it.
	Notes string `json:"notes"`
	// Reason is the note for the trail about the note; it is kept when
	// given.
	Reason string `json:"reason"`
}

// handleSetHostNotes records the notes of a host.
func (s *Server) handleSetHostNotes(w http.ResponseWriter, r *http.Request) {
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

	var request hostNotesRequest
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<16)).Decode(&request); err != nil {
		problem(w, http.StatusBadRequest, "invalid_body", "the request body is not valid JSON")
		return
	}
	notes, err := hosts.NormalizeNotes(request.Notes)
	if errors.Is(err, hosts.ErrInvalidNotes) {
		problem(w, http.StatusBadRequest, "invalid_notes", err.Error())
		return
	}
	if err != nil {
		s.fail(w, err)
		return
	}

	updated, err := s.hosts.SetNotes(r.Context(), hostID, notes)
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
		Action: "host.notes", TargetType: "host", TargetID: host.ID,
		RequestID: requestIDOf(r), Outcome: audit.OutcomeSuccess,
		Detail: map[string]any{"before": host.Notes, "after": notes, "reason": strings.TrimSpace(request.Reason)},
		Before: map[string]any{"notes": host.Notes},
		After:  map[string]any{"notes": notes},
	})
	setETag(w, hostFactsTag(updated))
	writeJSON(w, http.StatusOK, updated)
}
