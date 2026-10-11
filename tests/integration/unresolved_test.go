//go:build integration

package integration

import (
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
