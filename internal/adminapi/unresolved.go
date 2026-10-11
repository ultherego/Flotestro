package adminapi

import (
	"encoding/json"
	"net/http"
	"strconv"
	"strings"

	"github.com/ultherego/flotestro/internal/audit"
	"github.com/ultherego/flotestro/internal/authz"
	"github.com/ultherego/flotestro/internal/jobs"
)

// The operations whose outcome nobody could confirm, and the operator's
// ruling on them.
//
// The dashboard counts failed tasks of the last 24 hours, so an operation
// that nobody could confirm used to leave the screen because a day had
// passed. For a product whose first rule is that unknown is not zero, that
// is the one place the rule did not hold - and the pilot is judged against
// "no unexplained unknown outcome", which cannot be read off a screen that
// forgets.

// UnresolvedOperations is what the screen reads: the four counts and the
// page of items. The handler writes this type rather than a map, so the
// documented shape and the served one cannot drift apart.
type UnresolvedOperations struct {
	Counts jobs.UnresolvedCounts `json:"counts"`
	Items  []jobs.Unresolved     `json:"items"`
}

// UnresolvedRuling is the answer to recording one.
type UnresolvedRuling struct {
	Ruled bool `json:"ruled"`
}

// handleUnresolved lists what is open, with its counts.
func (s *Server) handleUnresolved(w http.ResponseWriter, r *http.Request) {
	principal, ok := s.authorizeCollection(w, r, authz.PermJobRead, "job")
	if !ok {
		return
	}
	query := r.URL.Query()
	filter := jobs.UnresolvedFilter{
		Scopes: principal.ScopesFor(authz.PermJobRead),
		HostID: query.Get("host_id"),
		Kind:   query.Get("kind"),
	}
	switch filter.Kind {
	case "", jobs.UncertaintyOutcomeUnknown, jobs.UncertaintyAppliedUnverified:
	default:
		problem(w, http.StatusBadRequest, "invalid_filter",
			"kind is outcome_unknown or applied_unverified; they are different questions and are not summed")
		return
	}
	if raw := query.Get("limit"); raw != "" {
		parsed, err := strconv.Atoi(raw)
		if err != nil || parsed < 1 {
			problem(w, http.StatusBadRequest, "invalid_filter", "limit must be a positive number")
			return
		}
		filter.Limit = parsed
	}

	// The counts answer for the whole visible fleet whatever the list shows,
	// so a narrowed list cannot make the fleet look settled.
	counts, err := s.jobs.UnresolvedCount(r.Context(),
		jobs.UnresolvedFilter{Scopes: filter.Scopes, HostID: filter.HostID})
	if err != nil {
		s.fail(w, err)
		return
	}
	list, err := s.jobs.UnresolvedList(r.Context(), filter)
	if err != nil {
		s.fail(w, err)
		return
	}
	if list == nil {
		list = []jobs.Unresolved{}
	}
	writeJSON(w, http.StatusOK, UnresolvedOperations{Counts: counts, Items: list})
}

// handleRuleUnresolved records what an operator concluded about one attempt.
//
// It writes a row beside the attempt. The job keeps the outcome the fleet
// reported: an operator's reading is a second fact about the same attempt,
// not a correction of the first, and a screen that rewrote the outcome would
// make the record unreliable for the audit trail, the campaign report and
// the pilot's evidence alike.
func (s *Server) handleRuleUnresolved(w http.ResponseWriter, r *http.Request) {
	attemptID := r.PathValue("id")
	var body struct {
		Kind   string `json:"kind"`
		Ruling string `json:"ruling"`
		Basis  string `json:"basis"`
	}
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 64<<10)).Decode(&body); err != nil {
		problem(w, http.StatusBadRequest, "invalid_body", "the ruling could not be read")
		return
	}
	if strings.TrimSpace(body.Basis) == "" {
		problem(w, http.StatusBadRequest, "basis_required",
			"say on what basis: what you read, where you looked. A ruling without one is a screen being cleared")
		return
	}

	// The job the attempt belongs to decides who may rule on it, the same
	// way it decides who may read it.
	job, err := s.jobs.JobOfAttempt(r.Context(), attemptID)
	if err != nil {
		s.fail(w, err)
		return
	}
	if job.ID == "" {
		problem(w, http.StatusNotFound, "attempt_not_found", "no such attempt")
		return
	}
	principal, ok := s.authorize(w, r, authz.PermJobRead, s.jobScope(r, job.HostID), "job", job.ID)
	if !ok {
		return
	}

	ruling := jobs.Ruling{
		AttemptID: attemptID,
		Kind:      body.Kind,
		Ruling:    body.Ruling,
		Basis:     strings.TrimSpace(body.Basis),
		RuledBy:   principal.Subject,
	}
	if err := s.jobs.Rule(r.Context(), ruling); err != nil {
		problem(w, http.StatusBadRequest, "invalid_ruling", err.Error())
		return
	}
	s.audit.Record(r.Context(), audit.Event{
		ActorType: audit.ActorUser, ActorID: principal.Subject,
		Action: "job.unresolved.rule", TargetType: "job_attempt", TargetID: attemptID,
		RequestID: requestIDOf(r), Outcome: audit.OutcomeSuccess,
		Detail: map[string]any{
			"job_id": job.ID, "host_id": job.HostID,
			"kind": ruling.Kind, "ruling": ruling.Ruling, "basis": ruling.Basis,
		},
	})
	writeJSON(w, http.StatusOK, UnresolvedRuling{Ruled: true})
}
