package adminapi

import (
	"encoding/json"
	"fmt"
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
	// Total is how many the narrowed list holds, which is what a page number
	// is computed from. It is not one of the counts above: those answer for
	// the whole visible fleet whatever the list shows, so that a narrowed
	// list cannot make the fleet look settled.
	Total int `json:"total"`
}

// UnresolvedRuling is the answer to recording one.
type UnresolvedRuling struct {
	Ruled bool `json:"ruled"`
}

// UnresolvedRulingRefusal says why one attempt of a batch was not ruled on.
type UnresolvedRulingRefusal struct {
	AttemptID string `json:"attempt_id"`
	Code      string `json:"code"`
	Message   string `json:"message"`
}

// UnresolvedRulings is the answer to recording a batch of them.
//
// A batch is not all or nothing. One attempt an operator may not see, or one
// that somebody else ruled on a second earlier, must not undo the decisions
// taken on the rest - and it must not vanish either, so each refusal comes
// back by name.
type UnresolvedRulings struct {
	Ruled    int                       `json:"ruled"`
	Refused  []UnresolvedRulingRefusal `json:"refused,omitempty"`
	Attempts int                       `json:"attempts"`
}

// batchRulingLimit is how many attempts one batch may carry. The same cap as
// the list's, so "rule on all of them" can never mean more than a screen
// could have shown.
const batchRulingLimit = 500

// basisRequired is the refusal both the single ruling and the batch give. It
// is one sentence in one place: a batch that asked for less than the single
// ruling does would be the way round the requirement.
const basisRequired = "say on what basis: what you read, where you looked. " +
	"A ruling without one is a screen being cleared"

// handleUnresolved lists what is open, with its counts.
func (s *Server) handleUnresolved(w http.ResponseWriter, r *http.Request) {
	principal, ok := s.authorizeCollection(w, r, authz.PermJobRead, "job")
	if !ok {
		return
	}
	query := r.URL.Query()
	filter := jobs.UnresolvedFilter{
		Scopes:  principal.ScopesFor(authz.PermJobRead),
		HostID:  query.Get("host_id"),
		Kind:    query.Get("kind"),
		Reading: query.Get("reading"),
		Search:  query.Get("q"),
	}
	switch filter.Kind {
	case "", jobs.UncertaintyOutcomeUnknown, jobs.UncertaintyAppliedUnverified:
	default:
		problem(w, http.StatusBadRequest, "invalid_filter",
			"kind is outcome_unknown or applied_unverified; they are different questions and are not summed")
		return
	}
	switch filter.Reading {
	case "", jobs.ReadingDidNotHold, jobs.ReadingCouldNotRead, jobs.ReadingOutcomeUnknown:
	default:
		problem(w, http.StatusBadRequest, "invalid_filter",
			"reading is did_not_hold, could_not_read or outcome_unknown: a host that answered with "+
				"something else is a conclusion, and a host that could not be read is the absence of one")
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
	if raw := query.Get("offset"); raw != "" {
		parsed, err := strconv.Atoi(raw)
		if err != nil || parsed < 0 {
			problem(w, http.StatusBadRequest, "invalid_filter", "offset must be zero or a positive number")
			return
		}
		filter.Offset = parsed
	}

	// The counts answer for the whole visible fleet whatever the list shows,
	// so a narrowed list cannot make the fleet look settled.
	counts, err := s.jobs.UnresolvedCount(r.Context(),
		jobs.UnresolvedFilter{Scopes: filter.Scopes, HostID: filter.HostID})
	if err != nil {
		s.fail(w, err)
		return
	}
	// The total of the narrowed list, before the page is cut out of it: a page
	// number cannot be computed from the page.
	total, err := s.jobs.UnresolvedTotal(r.Context(), filter)
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
	writeJSON(w, http.StatusOK, UnresolvedOperations{Counts: counts, Items: list, Total: total})
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
		problem(w, http.StatusBadRequest, "basis_required", basisRequired)
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

// handleRuleUnresolvedBatch records one ruling against many attempts.
//
// It exists because the list is long for an honest reason: fifteen attempts of
// the same reload on the same host are fifteen rows, and ruling on them one at
// a time is not diligence, it is typing. What it does not do is ask for less
// than the single ruling asks: the basis is required here too, written once and
// recorded against every attempt separately, because the audit trail of
// thirty-one decisions must not collapse into one line.
//
// The attempts are named by the caller rather than selected by a filter the
// server re-evaluates. A filter read again here would also rule on whatever
// arrived between the screen being drawn and the button being pressed, and
// that is a ruling nobody made.
func (s *Server) handleRuleUnresolvedBatch(w http.ResponseWriter, r *http.Request) {
	var body struct {
		Kind       string   `json:"kind"`
		Ruling     string   `json:"ruling"`
		Basis      string   `json:"basis"`
		AttemptIDs []string `json:"attempt_ids"`
	}
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 256<<10)).Decode(&body); err != nil {
		problem(w, http.StatusBadRequest, "invalid_body", "the ruling could not be read")
		return
	}
	if strings.TrimSpace(body.Basis) == "" {
		problem(w, http.StatusBadRequest, "basis_required", basisRequired)
		return
	}
	// The same identifier twice is one attempt, not two: a screen that sent a
	// duplicate would otherwise report a count nobody can reconcile.
	seen := map[string]bool{}
	attempts := make([]string, 0, len(body.AttemptIDs))
	for _, id := range body.AttemptIDs {
		id = strings.TrimSpace(id)
		if id == "" || seen[id] {
			continue
		}
		seen[id] = true
		attempts = append(attempts, id)
	}
	if len(attempts) == 0 {
		problem(w, http.StatusBadRequest, "invalid_body",
			"name the attempts to rule on in attempt_ids")
		return
	}
	if len(attempts) > batchRulingLimit {
		problem(w, http.StatusBadRequest, "invalid_body",
			fmt.Sprintf("a batch carries at most %d attempts and this one carries %d",
				batchRulingLimit, len(attempts)))
		return
	}

	// Authenticated once and for the collection; the permission is then checked
	// against the host of every attempt, because an operator of one environment
	// must not rule on another's by putting its identifier in a list.
	principal, ok := s.authorizeCollection(w, r, authz.PermJobRead, "job")
	if !ok {
		return
	}

	answer := UnresolvedRulings{Attempts: len(attempts)}
	for _, attemptID := range attempts {
		job, err := s.jobs.JobOfAttempt(r.Context(), attemptID)
		if err != nil {
			// A database that stopped answering is reported against this
			// attempt rather than as a failure of the whole call: the rulings
			// already written are written, and a 500 here would hide them.
			answer.Refused = append(answer.Refused, UnresolvedRulingRefusal{
				AttemptID: attemptID, Code: "unavailable",
				Message: "the attempt could not be read: " + err.Error()})
			continue
		}
		if job.ID == "" {
			answer.Refused = append(answer.Refused, UnresolvedRulingRefusal{
				AttemptID: attemptID, Code: "attempt_not_found", Message: "no such attempt"})
			continue
		}
		scope := s.jobScope(r, job.HostID)
		if !principal.Can(authz.PermJobRead, scope) {
			s.audit.Record(r.Context(), audit.Event{
				ActorType: audit.ActorUser, ActorID: principal.Subject,
				Action: string(authz.PermJobRead), TargetType: "job_attempt", TargetID: attemptID,
				RequestID: requestIDOf(r), Outcome: audit.OutcomeDenied,
				Detail: map[string]any{
					"reason": "permission_denied", "permission": string(authz.PermJobRead),
					"scope": scope.String(), "roles": principal.Roles(),
				},
			})
			answer.Refused = append(answer.Refused, UnresolvedRulingRefusal{
				AttemptID: attemptID, Code: "permission_denied",
				Message: "missing permission " + string(authz.PermJobRead) + " in scope " + scope.String()})
			continue
		}
		ruling := jobs.Ruling{
			AttemptID: attemptID,
			Kind:      body.Kind,
			Ruling:    body.Ruling,
			Basis:     strings.TrimSpace(body.Basis),
			RuledBy:   principal.Subject,
		}
		if err := s.jobs.Rule(r.Context(), ruling); err != nil {
			answer.Refused = append(answer.Refused, UnresolvedRulingRefusal{
				AttemptID: attemptID, Code: "invalid_ruling", Message: err.Error()})
			continue
		}
		// One record per attempt, and it says it was part of a batch: a reader
		// of the trail has to be able to tell thirty-one decisions taken one
		// by one from thirty-one taken at once.
		s.audit.Record(r.Context(), audit.Event{
			ActorType: audit.ActorUser, ActorID: principal.Subject,
			Action: "job.unresolved.rule", TargetType: "job_attempt", TargetID: attemptID,
			RequestID: requestIDOf(r), Outcome: audit.OutcomeSuccess,
			Detail: map[string]any{
				"job_id": job.ID, "host_id": job.HostID,
				"kind": ruling.Kind, "ruling": ruling.Ruling, "basis": ruling.Basis,
				"batch": len(attempts),
			},
		})
		answer.Ruled++
	}
	// 201, because the rulings are rows this call created - and because the
	// served document says 201 for this path. The generator derives that from
	// the path ending in "s" (openapi.go:443), so a handler answering 200 here
	// would make the document lie about itself.
	writeJSON(w, http.StatusCreated, answer)
}
