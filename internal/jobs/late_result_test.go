package jobs

import "testing"

// The status an attempt has when its result arrives decides what the result
// does: an expired lease is settled, a superseded attempt takes nothing.
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

// The typed reasons are part of the contract between the store, the gateway
// and the guide of error codes; the guide test on the API side enumerates them
// by these very strings.
func TestTheAttemptStatusesAreTheirOwnCodes(t *testing.T) {
	if AttemptStatusLeaseExpired != "lease_expired" || AttemptStatusSuperseded != "superseded_by_result" {
		t.Fatalf("the attempt statuses changed: %q, %q", AttemptStatusLeaseExpired, AttemptStatusSuperseded)
	}
}

// Which attempts hold a result a reader may judge the task by. The three the
// panel closed itself - gave up on, took back, set aside - were never read
// back through, and a result that arrives late replaces the status with its
// own, so an attempt still carrying one of them carries no result.
func TestOnlyAnAttemptAResultReachedCarriesOne(t *testing.T) {
	for _, status := range []string{
		AttemptStatusLeaseExpired, AttemptStatusSuperseded, AttemptStatusReleased,
	} {
		if AttemptCarriesResult(Attempt{Status: status}) {
			t.Errorf("an attempt that ended %q is read as carrying a result", status)
		}
	}
	for _, status := range []string{"succeeded", "failed", "canceled"} {
		if !AttemptCarriesResult(Attempt{Status: status}) {
			t.Errorf("an attempt that ended %q is read as carrying nothing", status)
		}
	}
	// The supersede also travels as the error code of the operation contract.
	if AttemptCarriesResult(Attempt{Status: "failed", ErrorCode: AttemptStatusSuperseded}) {
		t.Error("an attempt set aside by another's result is read as carrying one")
	}
}
