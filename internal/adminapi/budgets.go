package adminapi

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"time"

	"github.com/jackc/pgx/v5"

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

// budgetLimit is one configured budget as its own resource: the capacity,
// the note and the version an editor holds.
type budgetLimit struct {
	Key       string    `json:"key"`
	Capacity  int       `json:"capacity"`
	Note      string    `json:"note"`
	UpdatedAt time.Time `json:"updated_at"`
}

// configuredBudget reads one configured budget. A missing row is a budget
// nobody configured - the patterns of the installation still apply to it,
// but there is no record to tag.
func (s *Server) configuredBudget(ctx context.Context, key string) (*budgetLimit, error) {
	var limit budgetLimit
	err := s.pool.QueryRow(ctx,
		`select key, capacity, note, updated_at from budget_limits where key = $1`, key).
		Scan(&limit.Key, &limit.Capacity, &limit.Note, &limit.UpdatedAt)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	return &limit, nil
}

// handleGetBudget serves one configured budget with its entity tag, so an
// editor can write it back with If-Match.
func (s *Server) handleGetBudget(w http.ResponseWriter, r *http.Request) {
	if _, ok := s.authorizeCollection(w, r, authz.PermBudgetRead, "budget"); !ok {
		return
	}
	if s.budgets == nil {
		problem(w, http.StatusNotImplemented, "budgets_disabled",
			"budgets are disabled in this installation")
		return
	}
	limit, err := s.configuredBudget(r.Context(), r.PathValue("key"))
	if err != nil {
		s.fail(w, err)
		return
	}
	if limit == nil {
		problem(w, http.StatusNotFound, "budget_not_found", "no budget is configured under this key")
		return
	}
	setETag(w, etagOfTime(limit.UpdatedAt))
	writeJSON(w, http.StatusOK, limit)
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

	// The write is conditional when the caller says so: a capacity raised
	// over somebody else's change a minute ago is a policy nobody decided.
	current, err := s.configuredBudget(r.Context(), key)
	if err != nil {
		s.fail(w, err)
		return
	}
	tag := ""
	if current != nil {
		tag = etagOfTime(current.UpdatedAt)
	}
	if !requireMatch(w, r, tag) {
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
	// The answer carries the tag of what was just written, so an editor
	// can go on editing without reading the record again.
	if saved, err := s.configuredBudget(r.Context(), key); err == nil && saved != nil {
		setETag(w, etagOfTime(saved.UpdatedAt))
	}
	writeJSON(w, http.StatusOK, map[string]any{"key": key, "capacity": request.Capacity})
}
