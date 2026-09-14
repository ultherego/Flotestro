package jobs

import "testing"

// The status an attempt has when its result arrives decides what the
// result does: a lease the scheduler gave up on is settled and its
// redelivery superseded, a superseded attempt takes nothing, and an
// attempt without a status - or with a result already - is recorded as
// it always was.
func TestWhatALateResultDoesByTheStatusOfItsAttempt(t *testing.T) {
	cases := []struct {
		status             string
		record, supersedes bool
	}{
		{status: "", record: true},
		{status: "succeeded", record: true},
		{status: "released", record: true},
		{status: AttemptStatusLeaseExpired, record: true, supersedes: true},
		{status: AttemptStatusSuperseded},
	}
	for _, c := range cases {
		record, supersedes := lateResultDisposition(c.status)
		if record != c.record || supersedes != c.supersedes {
			t.Errorf("status %q: record=%v supersedes=%v, expected record=%v supersedes=%v",
				c.status, record, supersedes, c.record, c.supersedes)
		}
	}
}

// The typed reasons are part of the contract between the store, the
// gateway and the guide of error codes; the guide test on the API side
// enumerates them by these very strings.
func TestTheAttemptStatusesAreTheirOwnCodes(t *testing.T) {
	if AttemptStatusLeaseExpired != "lease_expired" || AttemptStatusSuperseded != "superseded_by_result" {
		t.Fatalf("the attempt statuses changed: %q, %q", AttemptStatusLeaseExpired, AttemptStatusSuperseded)
	}
}
