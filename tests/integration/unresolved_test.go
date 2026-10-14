//go:build integration

package integration

import (
	"context"
	"fmt"
	"net/http"
	"testing"

	"github.com/google/uuid"
)

// The screen of operations nobody could confirm, asked of a real database.
//
// It went out without this and the first person to open the tab got
// "Error: internal error": the query named jobs.action, and the column is
// jobs.action_type. Nothing in the suite had run the SQL - the handler's
// tests build no database, and the panel's tests build no handler - so the
// mistake travelled from a unit test that passed, through a typecheck that
// passed, through a gate stage that passed, to a person looking at a screen.
//
// This runs the two reads and the write against the installation, which is
// the only thing that can say whether the SQL is SQL.
func TestTheUnresolvedScreenAnswersFromTheDatabase(t *testing.T) {
	h := newHarness(t)

	// Both kinds and both shapes of the answer: the counts and the page. A
	// fleet with nothing open is the ordinary case and still has to answer -
	// an empty list is an answer, a 500 is not.
	for _, query := range []string{
		"",
		"?kind=outcome_unknown",
		"?kind=applied_unverified",
		"?limit=5",
	} {
		var answer struct {
			Counts struct {
				OutcomeUnknownOperations    int `json:"outcome_unknown_operations"`
				OutcomeUnknownHosts         int `json:"outcome_unknown_hosts"`
				AppliedUnverifiedOperations int `json:"applied_unverified_operations"`
				AppliedUnverifiedHosts      int `json:"applied_unverified_hosts"`
			} `json:"counts"`
			Items []struct {
				AttemptID string `json:"attempt_id"`
				JobID     string `json:"job_id"`
				HostID    string `json:"host_id"`
				Hostname  string `json:"hostname"`
				Action    string `json:"action"`
				Kind      string `json:"kind"`
				FirstSeen string `json:"first_seen"`
			} `json:"items"`
		}
		h.do(http.MethodGet, "/api/v1/unresolved"+query, nil, &answer, http.StatusOK)

		// Hosts cannot outnumber operations: every host on the list has at
		// least one operation on it, so a count that says otherwise is the
		// two queries having drifted apart.
		if answer.Counts.OutcomeUnknownHosts > answer.Counts.OutcomeUnknownOperations {
			t.Errorf("%s: %d hosts and %d operations are unknown-outcome; a host needs an operation to be on the list",
				query, answer.Counts.OutcomeUnknownHosts, answer.Counts.OutcomeUnknownOperations)
		}
		if answer.Counts.AppliedUnverifiedHosts > answer.Counts.AppliedUnverifiedOperations {
			t.Errorf("%s: %d hosts and %d operations are applied-unverified",
				query, answer.Counts.AppliedUnverifiedHosts, answer.Counts.AppliedUnverifiedOperations)
		}

		for _, item := range answer.Items {
			// Every row is readable: an item with no host or no operation is
			// a join that lost its other half.
			if item.HostID == "" || item.Action == "" || item.AttemptID == "" {
				t.Errorf("%s: an item is missing what it is about: %+v", query, item)
			}
			switch item.Kind {
			case "outcome_unknown", "applied_unverified":
			default:
				t.Errorf("%s: an item has the kind %q, which is neither question", query, item.Kind)
			}
			if query == "?kind=outcome_unknown" && item.Kind != "outcome_unknown" {
				t.Errorf("the list filtered to one kind returned %q", item.Kind)
			}
		}
	}

	// A kind nobody asks about is a refusal and not a server fault: the
	// screen's filter is part of the request, so a wrong one is the
	// caller's mistake.
	h.do(http.MethodGet, "/api/v1/unresolved?kind=whatever", nil, nil, http.StatusBadRequest)

	// And the ruling refuses an empty basis, which is the rule that keeps
	// this list from being cleared rather than answered.
	h.do(http.MethodPost, "/api/v1/unresolved/"+uuid.NewString()+"/ruling",
		map[string]any{"kind": "outcome_unknown", "ruling": "accepted_unknown", "basis": "   "},
		nil, http.StatusBadRequest)
}

// TestTheBadgeAgreesWithTheUnresolvedScreen asks the navigation's counter and
// the screen it leads to in one run.
//
// The badge is a second query over the same rows, and a counter that
// disagrees with its list teaches an operator to trust neither. The summary
// answers with one number because the badge is a queue length; the screen
// keeps the two questions apart. Both have to be the same rows.
func TestTheBadgeAgreesWithTheUnresolvedScreen(t *testing.T) {
	h := newHarness(t)

	var screen struct {
		Counts struct {
			OutcomeUnknownOperations    int `json:"outcome_unknown_operations"`
			AppliedUnverifiedOperations int `json:"applied_unverified_operations"`
		} `json:"counts"`
		Items []struct {
			AttemptID string `json:"attempt_id"`
		} `json:"items"`
	}
	h.get("/api/v1/unresolved", &screen)

	var summary struct {
		OperationsUnconfirmed *int `json:"operations_unconfirmed"`
	}
	h.get("/api/v1/fleet/summary", &summary)
	if summary.OperationsUnconfirmed == nil {
		t.Fatal("the summary carries no operations_unconfirmed, so the navigation has nothing to badge")
	}

	waiting := screen.Counts.OutcomeUnknownOperations + screen.Counts.AppliedUnverifiedOperations
	if *summary.OperationsUnconfirmed != waiting {
		t.Errorf("the badge says %d and the screen counts %d (%d unknown + %d unverified)",
			*summary.OperationsUnconfirmed, waiting,
			screen.Counts.OutcomeUnknownOperations, screen.Counts.AppliedUnverifiedOperations)
	}

	// The default page holds a hundred rows, so a shorter list is the whole
	// list and has to be as long as the number above it.
	if len(screen.Items) < 100 && len(screen.Items) != waiting {
		t.Errorf("the screen lists %d rows and counts %d above them", len(screen.Items), waiting)
	}
}

// TestEveryPageOfTheUnresolvedListHoldsEachAttemptOnce is the pagination the
// screen's page numbers stand on.
//
// The order has to be total. Fifteen attempts of the same reload on the same
// host land in the same second, and an offset over an order that ties repeats
// rows on one page and loses them from the next - so a reader paging through
// thirty-one rows would see some twice and never see others, and the ones
// never seen are the ones nobody rules on.
func TestEveryPageOfTheUnresolvedListHoldsEachAttemptOnce(t *testing.T) {
	h := newHarness(t)

	var whole struct {
		Total int `json:"total"`
		Items []struct {
			AttemptID string `json:"attempt_id"`
		} `json:"items"`
	}
	h.get("/api/v1/unresolved?limit=500", &whole)
	if whole.Total < 2 {
		absent(t, "the installation holds %d unresolved operations; paging needs at least two", whole.Total)
	}
	if whole.Total != len(whole.Items) && len(whole.Items) < 500 {
		t.Fatalf("the list says total %d and returned %d rows in one page of 500", whole.Total, len(whole.Items))
	}

	// A page of one, walked across the whole list: the smallest page is the
	// one that exposes a tie fastest.
	pages := whole.Total
	if pages > 40 {
		pages = 40
	}
	seen := map[string]int{}
	for offset := 0; offset < pages; offset++ {
		var page struct {
			Total int `json:"total"`
			Items []struct {
				AttemptID string `json:"attempt_id"`
			} `json:"items"`
		}
		h.get(fmt.Sprintf("/api/v1/unresolved?limit=1&offset=%d", offset), &page)
		if page.Total != whole.Total {
			t.Errorf("offset %d: the total is %d and was %d for the whole list; the count follows the page",
				offset, page.Total, whole.Total)
		}
		if len(page.Items) != 1 {
			t.Fatalf("offset %d of %d: a page of one returned %d rows", offset, whole.Total, len(page.Items))
		}
		seen[page.Items[0].AttemptID]++
	}
	for id, times := range seen {
		if times > 1 {
			t.Errorf("the attempt %s came back on %d different pages; the order is not total", id, times)
		}
	}
	if len(seen) != pages {
		t.Errorf("walking %d pages of one saw %d different attempts", pages, len(seen))
	}
}

// TestTheTotalOfTheListAgreesWithTheCountsAboveIt keeps the new number from
// drifting away from the four it sits beside.
//
// They answer different questions on purpose - the counts are the whole
// visible fleet, the total is the narrowed list - so with no narrowing they
// have to meet, and under a kind filter the total has to be that kind's count.
func TestTheTotalOfTheListAgreesWithTheCountsAboveIt(t *testing.T) {
	h := newHarness(t)

	var all struct {
		Counts struct {
			OutcomeUnknownOperations    int `json:"outcome_unknown_operations"`
			AppliedUnverifiedOperations int `json:"applied_unverified_operations"`
		} `json:"counts"`
		Total int `json:"total"`
	}
	h.get("/api/v1/unresolved?limit=1", &all)
	open := all.Counts.OutcomeUnknownOperations + all.Counts.AppliedUnverifiedOperations
	if all.Total != open {
		t.Errorf("the unnarrowed list totals %d and the counts above it add to %d", all.Total, open)
	}

	for kind, expected := range map[string]int{
		"outcome_unknown":    all.Counts.OutcomeUnknownOperations,
		"applied_unverified": all.Counts.AppliedUnverifiedOperations,
	} {
		var one struct {
			Total int `json:"total"`
		}
		h.get("/api/v1/unresolved?limit=1&kind="+kind, &one)
		if one.Total != expected {
			t.Errorf("the list of %s totals %d and its count says %d", kind, one.Total, expected)
		}
	}

	// An offset past the end is an empty page, not a refusal: the screen can
	// ask for a page that was there a second ago.
	var past struct {
		Items []struct{} `json:"items"`
		Total int        `json:"total"`
	}
	h.get(fmt.Sprintf("/api/v1/unresolved?limit=5&offset=%d", all.Total+10), &past)
	if len(past.Items) != 0 {
		t.Errorf("a page past the end returned %d rows", len(past.Items))
	}
	if past.Total != all.Total {
		t.Errorf("a page past the end says the total is %d and it is %d", past.Total, all.Total)
	}
	h.do(http.MethodGet, "/api/v1/unresolved?offset=-1", nil, nil, http.StatusBadRequest)
}

// TestABatchRulingAsksForABasisLikeASingleOneDoes is the requirement a batch
// could have been the way round.
func TestABatchRulingAsksForABasisLikeASingleOneDoes(t *testing.T) {
	h := newHarness(t)

	for _, body := range []map[string]any{
		{"kind": "outcome_unknown", "ruling": "accepted_unknown", "basis": "   ",
			"attempt_ids": []string{uuid.NewString()}},
		{"kind": "outcome_unknown", "ruling": "accepted_unknown",
			"attempt_ids": []string{uuid.NewString()}},
	} {
		h.do(http.MethodPost, "/api/v1/unresolved/rulings", body, nil, http.StatusBadRequest)
	}

	// And a batch of nothing is a mistake rather than a ruling on nothing.
	h.do(http.MethodPost, "/api/v1/unresolved/rulings",
		map[string]any{"kind": "outcome_unknown", "ruling": "accepted_unknown",
			"basis": "read the host", "attempt_ids": []string{}},
		nil, http.StatusBadRequest)
}

// TestABatchRulingRulesOnEveryAttemptItNamesAndSaysWhatItCouldNot runs the
// write path over a synthetic attempt of its own.
//
// Its own, and not one of the installation's, for the reason the screen
// exists: nothing ages out of that list, so an item there is evidence, and a
// test that consumed it would be spending the product's record to check
// itself.
func TestABatchRulingRulesOnEveryAttemptItNamesAndSaysWhatItCouldNot(t *testing.T) {
	h := newHarness(t)
	ctx := context.Background()
	pool := h.database(ctx)

	var hostID string
	if err := pool.QueryRow(ctx, "select id from hosts order by created_at limit 1").Scan(&hostID); err != nil {
		absent(t, "no host to hang a synthetic attempt on: %v", err)
	}

	// One job, two attempts of it: both are ruled on by one call, which is the
	// point of the call.
	jobID := uuid.NewString()
	if _, err := pool.Exec(ctx, `
		insert into jobs (id, host_id, action_type, payload, payload_hash, idempotency_key,
		                  state, expires_at, created_by)
		values ($1, $2, 'noop.test', '{}'::jsonb, '\x00', $3, 'failed', now() + interval '1 hour', 'integration-test')`,
		jobID, hostID, "batch-ruling-"+jobID); err != nil {
		t.Fatalf("the synthetic job: %v", err)
	}
	t.Cleanup(func() {
		// The rulings hang off the attempts, which hang off the job: the job
		// going takes the whole of it.
		if _, err := pool.Exec(context.Background(), "delete from jobs where id = $1", jobID); err != nil {
			t.Logf("the synthetic job %s was not cleaned up: %v", jobID, err)
		}
	})
	attempts := []string{uuid.NewString(), uuid.NewString()}
	for n, attemptID := range attempts {
		if _, err := pool.Exec(ctx, `
			insert into job_attempts (id, job_id, attempt_number, status, error_code, message, started_at)
			values ($1, $2, $3, 'failed', 'outcome_unknown', 'a synthetic attempt of the integration suite', now())`,
			attemptID, jobID, n+1); err != nil {
			t.Fatalf("the synthetic attempt: %v", err)
		}
	}

	// A name that is not an attempt goes in with them: a batch is not all or
	// nothing, and what it could not do has to come back by name.
	stranger := uuid.NewString()
	var answer struct {
		Ruled    int `json:"ruled"`
		Attempts int `json:"attempts"`
		Refused  []struct {
			AttemptID string `json:"attempt_id"`
			Code      string `json:"code"`
		} `json:"refused"`
	}
	// The same attempt twice as well: one attempt, not two.
	ids := append(append([]string{}, attempts...), attempts[0], stranger)
	h.do(http.MethodPost, "/api/v1/unresolved/rulings",
		map[string]any{"kind": "outcome_unknown", "ruling": "accepted_unknown",
			"basis":       "read the host by hand; the integration suite wrote these",
			"attempt_ids": ids},
		&answer, http.StatusCreated)

	if answer.Attempts != 3 {
		t.Errorf("the batch carried four names of three attempts and reports %d", answer.Attempts)
	}
	if answer.Ruled != len(attempts) {
		t.Errorf("the batch ruled on %d attempts, want %d", answer.Ruled, len(attempts))
	}
	if len(answer.Refused) != 1 || answer.Refused[0].AttemptID != stranger {
		t.Fatalf("the refusal of the name that is not an attempt did not come back: %+v", answer.Refused)
	}
	if answer.Refused[0].Code != "attempt_not_found" {
		t.Errorf("the stranger was refused as %q, want attempt_not_found", answer.Refused[0].Code)
	}

	// Ruled on means off the list, and the ruling is a row of its own: the
	// attempt keeps the outcome the fleet reported.
	for _, attemptID := range attempts {
		var ruled bool
		if err := pool.QueryRow(ctx,
			"select exists (select 1 from unresolved_operation_rulings where attempt_id = $1)",
			attemptID).Scan(&ruled); err != nil {
			t.Fatalf("reading the ruling back: %v", err)
		}
		if !ruled {
			t.Errorf("the attempt %s has no ruling row after the batch said it ruled on it", attemptID)
		}
		var code string
		if err := pool.QueryRow(ctx,
			"select coalesce(error_code, '') from job_attempts where id = $1", attemptID).Scan(&code); err != nil {
			t.Fatalf("reading the attempt back: %v", err)
		}
		if code != "outcome_unknown" {
			t.Errorf("the ruling changed what the fleet reported: error_code is now %q", code)
		}
	}
}
