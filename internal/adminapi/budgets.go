package adminapi

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/ultherego/flotestro/internal/audit"
	"github.com/ultherego/flotestro/internal/authz"
)

// handleListBudgets shows the fleet capacity and how much of it is taken.
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

// configuredBudget reads one configured budget.
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
func (s *Server) handleSetBudget(w http.ResponseWriter, r *http.Request) {
	key := r.PathValue("key")
	if key == "" {
		problem(w, http.StatusBadRequest, "invalid_request", "budget key is required")
		return
	}
	// The scope of the budget is the scope of the change: a site budget is the
	// site's, everything else - the fleet-wide ones, the backends, a pattern over
	// every site - moves the whole fleet.
	principal, ok := s.authorize(w, r, authz.PermBudgetWrite, budgetScope(key), "budget", key)
	if !ok {
		return
	}
	if s.budgets == nil {
		problem(w, http.StatusNotImplemented, "budgets_disabled",
			"budgets are disabled in this installation")
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
	// A zero capacity is not a policy, only stopping everything without saying so
	// directly.
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
	// The event carries both sides of the policy.
	var before map[string]any
	if current != nil {
		before = map[string]any{"capacity": current.Capacity, "note": current.Note}
	}
	s.audit.Record(r.Context(), audit.Event{
		ActorType: audit.ActorUser, ActorID: principal.Subject,
		Action: string(authz.PermBudgetWrite), TargetType: "budget", TargetID: key,
		RequestID: requestIDOf(r), Outcome: audit.OutcomeSuccess,
		Detail: map[string]any{"capacity": request.Capacity, "note": request.Note},
		Before: before,
		After:  map[string]any{"capacity": request.Capacity, "note": request.Note},
	})
	// The answer carries the tag of what was just written, so an editor
	// can go on editing without reading the record again.
	if saved, err := s.configuredBudget(r.Context(), key); err == nil && saved != nil {
		setETag(w, etagOfTime(saved.UpdatedAt))
	}
	writeJSON(w, http.StatusOK, map[string]any{"key": key, "capacity": request.Capacity})
}

// handleDeleteBudget takes a configured budget away.
func (s *Server) handleDeleteBudget(w http.ResponseWriter, r *http.Request) {
	key := r.PathValue("key")
	if key == "" {
		problem(w, http.StatusBadRequest, "invalid_request", "budget key is required")
		return
	}
	principal, ok := s.authorize(w, r, authz.PermBudgetWrite, budgetScope(key), "budget", key)
	if !ok {
		return
	}
	if s.budgets == nil {
		problem(w, http.StatusNotImplemented, "budgets_disabled",
			"budgets are disabled in this installation")
		return
	}
	reason, ok := requestReason(w, r, nil)
	if !ok {
		return
	}
	current, err := s.configuredBudget(r.Context(), key)
	if err != nil {
		s.fail(w, err)
		return
	}
	if current == nil {
		problem(w, http.StatusNotFound, "budget_not_found", "no budget is configured under this key")
		return
	}
	if !requireMatch(w, r, etagOfTime(current.UpdatedAt)) {
		return
	}

	tx, err := s.pool.Begin(r.Context())
	if err != nil {
		s.fail(w, err)
		return
	}
	defer func() { _ = tx.Rollback(r.Context()) }()
	// The row is locked first, so a lease admitted under this capacity
	// while the check runs is seen by the check or waits for the delete.
	if _, err := tx.Exec(r.Context(), `select 1 from budget_limits where key = $1 for update`, key); err != nil {
		s.fail(w, err)
		return
	}
	var held int
	if err := tx.QueryRow(r.Context(), `
		select coalesce(sum(weight), 0) from budget_leases
		 where lease_until > now() and (key = $1 or key like $2)`,
		key, likeOfPattern(key)).Scan(&held); err != nil {
		s.fail(w, err)
		return
	}
	if held > 0 {
		problem(w, http.StatusConflict, "budget_in_use",
			"the budget holds "+strconv.Itoa(held)+" tokens of running work; wait for it to finish or cancel it first")
		return
	}
	if _, err := tx.Exec(r.Context(), `delete from budget_limits where key = $1`, key); err != nil {
		s.fail(w, err)
		return
	}
	if err := s.audit.RecordTx(r.Context(), tx, audit.Event{
		ActorType: audit.ActorUser, ActorID: principal.Subject,
		Action: "budget.delete", TargetType: "budget", TargetID: key,
		RequestID: requestIDOf(r), Outcome: audit.OutcomeSuccess,
		Detail: map[string]any{"capacity": current.Capacity, "note": current.Note, "reason": strings.TrimSpace(reason)},
		Before: map[string]any{"capacity": current.Capacity, "note": current.Note},
	}); err != nil {
		s.fail(w, err)
		return
	}
	if err := tx.Commit(r.Context()); err != nil {
		s.fail(w, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

// likeOfPattern renders a budget key as a LIKE pattern: the asterisk of a
// pattern key stands for any site, and the other characters stand for
// themselves.
func likeOfPattern(key string) string {
	escaped := strings.NewReplacer(`\`, `\\`, `%`, `\%`, `_`, `\_`).Replace(key)
	return strings.ReplaceAll(escaped, "*", "%")
}

// budgetScope is the authorisation scope of a budget key.
func budgetScope(key string) authz.Scope {
	parts := strings.Split(key, ":")
	if len(parts) == 3 && parts[0] == "site" && parts[1] != "" && parts[1] != "*" {
		return authz.Scope{Site: parts[1]}
	}
	return authz.GlobalScope
}
