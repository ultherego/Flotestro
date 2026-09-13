package adminapi

import (
	"encoding/json"
	"net/http"

	"github.com/ultherego/flotestro/internal/audit"
	"github.com/ultherego/flotestro/internal/authz"
)

// handleListBudgets shows the fleet capacity and how much of it is taken.
//
// Without this screen a host waiting on a budget looks like a forgotten
// host: the campaign does not move forward, and nothing says why. The
// number of waiting hosts matters here as much as the usage - it explains
// why the free tokens do not go to one campaign.
func (s *Server) handleListBudgets(w http.ResponseWriter, r *http.Request) {
	if _, ok := s.authorizeCollection(w, r, authz.PermBudgetRead, "budget"); !ok {
		return
	}
	if s.budgets == nil {
		problem(w, http.StatusNotImplemented, "budgets_disabled",
			"budgets are disabled in this installation")
		return
	}
	states, err := s.budgets.States(r.Context())
	if err != nil {
		s.fail(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"items": states})
}

// handleSetBudget changes the capacity of one budget.
//
// The capacity is an installation policy, not a constant in the code: a
// site with one link carries something else than a server room. The change
// is a separate permission and goes to the audit log, because raised
// quietly it takes the meaning away from every limit below.
func (s *Server) handleSetBudget(w http.ResponseWriter, r *http.Request) {
	principal, ok := s.authorizeCollection(w, r, authz.PermBudgetWrite, "budget")
	if !ok {
		return
	}
	if s.budgets == nil {
		problem(w, http.StatusNotImplemented, "budgets_disabled",
			"budgets are disabled in this installation")
		return
	}
	key := r.PathValue("key")
	if key == "" {
		problem(w, http.StatusBadRequest, "invalid_request", "budget key is required")
		return
	}

	var request struct {
		Capacity int    `json:"capacity"`
		Note     string `json:"note"`
	}
	if err := json.NewDecoder(r.Body).Decode(&request); err != nil {
		problem(w, http.StatusBadRequest, "invalid_request", err.Error())
		return
	}
	// A zero capacity is not a policy, only stopping everything without
	// saying so directly. A budget that is to let nothing through is a
	// campaign pause - and that is what it is called.
	if request.Capacity < 1 {
		problem(w, http.StatusBadRequest, "invalid_request",
			"capacity must be at least 1; to stop work, pause the campaign")
		return
	}

	if err := s.budgets.SetCapacity(r.Context(), key, request.Capacity, request.Note); err != nil {
		s.fail(w, err)
		return
	}
	s.audit.Record(r.Context(), audit.Event{
		ActorType: audit.ActorUser, ActorID: principal.Subject,
		Action: string(authz.PermBudgetWrite), TargetType: "budget", TargetID: key,
		RequestID: requestIDOf(r), Outcome: audit.OutcomeSuccess,
		Detail: map[string]any{"capacity": request.Capacity, "note": request.Note},
	})
	writeJSON(w, http.StatusOK, map[string]any{"key": key, "capacity": request.Capacity})
}
