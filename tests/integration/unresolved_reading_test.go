//go:build integration

package integration

import (
	"context"
	"net/http"
	"testing"

	"github.com/google/uuid"
)

// "Did it hold?" covers two different situations and the screen called them
// one thing: a host that answered and shows something else - where the panel
// KNOWS the change did not hold - and a host the verifier could not read,
// which is the absence of that conclusion. The owner read the screen on 14.10
// and could not tell which he was looking at.
//
// The rule that tells them apart now lives in SQL, because the list is paged
// and counted on the server: a screen that classified on its own would put
// numbers above a list that disagree with it. So this runs the rule where it
// lives, over rows made for the purpose.
func TestTheReadingOfAnAttemptIsDecidedOnTheServer(t *testing.T) {
	h := newHarness(t)
	ctx := context.Background()
	pool := h.database(ctx)

	var hostID string
	if err := pool.QueryRow(ctx, "select id from hosts order by created_at limit 1").Scan(&hostID); err != nil {
		absent(t, "no host to hang a synthetic attempt on: %v", err)
	}

	jobID := uuid.NewString()
	if _, err := pool.Exec(ctx, `
		insert into jobs (id, host_id, action_type, payload, payload_hash, idempotency_key,
		                  state, expires_at, created_by)
		values ($1, $2, 'noop.test', '{}'::jsonb, '\x00', $3, 'failed', now() + interval '1 hour', 'integration-test')`,
		jobID, hostID, "reading-"+jobID); err != nil {
		t.Fatalf("the synthetic job: %v", err)
	}
	t.Cleanup(func() {
		if _, err := pool.Exec(context.Background(), "delete from jobs where id = $1", jobID); err != nil {
			t.Logf("the synthetic job %s was not cleaned up: %v", jobID, err)
		}
	})

	// One attempt per shape the rule has to tell apart.
	want := map[string]string{}
	for n, one := range []struct {
		reading      string
		errorCode    string
		verification any
	}{
		// A host that answered: the panel knows the change did not hold.
		{"did_not_hold", "applied_unverified", `{"verified": false, "expected": "on", "observed": "off"}`},
		// A verifier that could not look. Both shapes of that: the value
		// recorded as unknown, and no verification at all.
		{"could_not_read", "applied_unverified", `{"verified": false, "expected": "on", "observed": "unknown"}`},
		{"could_not_read", "applied_unverified", nil},
		// The other question entirely.
		{"outcome_unknown", "outcome_unknown", nil},
	} {
		attemptID := uuid.NewString()
		if _, err := pool.Exec(ctx, `
			insert into job_attempts (id, job_id, attempt_number, status, error_code, message,
			                          verification, started_at)
			values ($1, $2, $3, 'failed', $4, 'a synthetic attempt of the integration suite',
			        $5::jsonb, now())`,
			attemptID, jobID, n+1, one.errorCode, one.verification); err != nil {
			t.Fatalf("the synthetic attempt: %v", err)
		}
		want[attemptID] = one.reading
	}

	var page struct {
		Items []struct {
			AttemptID string `json:"attempt_id"`
			Reading   string `json:"reading"`
		} `json:"items"`
	}
	h.get("/api/v1/unresolved?limit=500", &page)
	seen := 0
	for _, item := range page.Items {
		expected, mine := want[item.AttemptID]
		if !mine {
			continue
		}
		seen++
		if item.Reading != expected {
			t.Errorf("the attempt %s reads as %q, want %q", item.AttemptID, item.Reading, expected)
		}
	}
	if seen != len(want) {
		t.Fatalf("%d of the %d synthetic attempts came back", seen, len(want))
	}

	// The filter narrows to one reading, and only to one: a row of another
	// reading coming back would make the number above the list a lie.
	for _, reading := range []string{"did_not_hold", "could_not_read", "outcome_unknown"} {
		var narrowed struct {
			Items []struct {
				AttemptID string `json:"attempt_id"`
				Reading   string `json:"reading"`
			} `json:"items"`
			Total int `json:"total"`
		}
		h.get("/api/v1/unresolved?limit=500&reading="+reading, &narrowed)
		for _, item := range narrowed.Items {
			if item.Reading != reading {
				t.Errorf("the list of %s carries an attempt that reads as %s", reading, item.Reading)
			}
		}
		if narrowed.Total != len(narrowed.Items) && len(narrowed.Items) < 500 {
			t.Errorf("the list of %s totals %d over %d rows", reading, narrowed.Total, len(narrowed.Items))
		}
	}

	// A reading nobody defined is a refusal, not an empty list read as good
	// news.
	h.do(http.MethodGet, "/api/v1/unresolved?reading=whatever", nil, nil, http.StatusBadRequest)

	// And the counts tell the two apart, which is what the screen puts above
	// the two ways in.
	var counts struct {
		Counts struct {
			AppliedUnverifiedOperations int `json:"applied_unverified_operations"`
			DidNotHoldOperations        int `json:"did_not_hold_operations"`
			CouldNotReadOperations      int `json:"could_not_read_operations"`
			OutcomeUnknownOperations    int `json:"outcome_unknown_operations"`
		} `json:"counts"`
	}
	h.get("/api/v1/unresolved?limit=1", &counts)
	// Every attempt of the fleet is one of the three, so the two inside the
	// question have to add up to it.
	if sum := counts.Counts.DidNotHoldOperations + counts.Counts.CouldNotReadOperations; sum != counts.Counts.AppliedUnverifiedOperations {
		t.Errorf("did_not_hold %d + could_not_read %d = %d, and applied_unverified is %d",
			counts.Counts.DidNotHoldOperations, counts.Counts.CouldNotReadOperations,
			sum, counts.Counts.AppliedUnverifiedOperations)
	}
	if counts.Counts.DidNotHoldOperations < 1 || counts.Counts.CouldNotReadOperations < 2 {
		t.Errorf("the synthetic attempts are not in the counts: did_not_hold %d, could_not_read %d",
			counts.Counts.DidNotHoldOperations, counts.Counts.CouldNotReadOperations)
	}
}
