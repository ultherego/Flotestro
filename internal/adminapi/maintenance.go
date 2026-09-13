package adminapi

import (
	"encoding/json"
	"net/http"
	"strings"
	"time"

	"github.com/ultherego/flotestro/internal/audit"
	"github.com/ultherego/flotestro/internal/authz"
)

// MaxWindow bounds the length of a maintenance window.
//
// A window without an end ends in a host everybody forgot: campaigns skip
// it, its alerts wake nobody, and after half a year nobody remembers why
// this machine gets no patches. The deadline forces a decision.
const MaxWindow = 30 * 24 * time.Hour

type maintenanceWindowRequest struct {
	// Until or DurationMinutes: the interface sends one of them.
	Until           string `json:"until,omitempty"`
	DurationMinutes int    `json:"duration_minutes,omitempty"`
	Reason          string `json:"reason,omitempty"`
	// Clear closes the window early.
	Clear bool `json:"clear,omitempty"`
}

// handleSetMaintenance opens or closes the maintenance window of a host.
//
// This is not an operation on the host and does not go through the task
// queue: it changes only what the panel thinks about the host. A task is
// something the host executes, and the host has nothing to do here - hence
// an entry point, a permission and an audit trail of its own.
func (s *Server) handleSetMaintenance(w http.ResponseWriter, r *http.Request) {
	hostID := r.PathValue("id")
	host, scope, ok := s.hostScope(w, r, hostID)
	if !ok {
		return
	}
	principal, ok := s.authorize(w, r, authz.PermHostMaintenanceWrite, scope, "host", hostID)
	if !ok {
		return
	}

	var request maintenanceWindowRequest
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<16)).Decode(&request); err != nil {
		problem(w, http.StatusBadRequest, "invalid_body", "the request body is not valid JSON")
		return
	}

	var until *time.Time
	reason := strings.TrimSpace(request.Reason)
	if !request.Clear {
		deadline, err := windowDeadline(request)
		if err != nil {
			problem(w, http.StatusBadRequest, "invalid_window", err.Error())
			return
		}
		if reason == "" {
			problem(w, http.StatusBadRequest, "reason_required",
				"a maintenance window needs a reason; it is what the next person on call will read")
			return
		}
		until = &deadline
	}

	updated, err := s.hosts.SetMaintenanceWindow(r.Context(), hostID, until, reason, principal.Subject)
	if err != nil {
		s.fail(w, err)
		return
	}

	detail := map[string]any{"cleared": request.Clear, "reason": reason}
	if until != nil {
		detail["until"] = until.Format(time.RFC3339)
	}
	s.audit.Record(r.Context(), audit.Event{
		ActorType: audit.ActorUser, ActorID: principal.Subject,
		Action: "host.maintenance", TargetType: "host", TargetID: host.ID,
		RequestID: requestIDOf(r), Outcome: audit.OutcomeSuccess, Detail: detail,
	})
	writeJSON(w, http.StatusOK, updated)
}

// windowDeadline computes the end of the window from what the interface
// sent.
func windowDeadline(request maintenanceWindowRequest) (time.Time, error) {
	now := time.Now().UTC()
	deadline := time.Time{}
	switch {
	case request.Until != "":
		parsed, err := time.Parse(time.RFC3339, request.Until)
		if err != nil {
			return time.Time{}, errWindow("until must be an RFC 3339 timestamp")
		}
		deadline = parsed.UTC()
	case request.DurationMinutes > 0:
		deadline = now.Add(time.Duration(request.DurationMinutes) * time.Minute)
	default:
		return time.Time{}, errWindow("a maintenance window needs an end: pass until or duration_minutes")
	}
	if !deadline.After(now) {
		return time.Time{}, errWindow("the window ends in the past")
	}
	if deadline.Sub(now) > MaxWindow {
		return time.Time{}, errWindow("a maintenance window lasts at most 30 days")
	}
	return deadline, nil
}

type windowError string

func (e windowError) Error() string { return string(e) }

func errWindow(message string) error { return windowError(message) }
