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

// TestTheResultOfAGivenUpAttemptSettlesAJobBackInTheQueue is the half the
// state machine did not have.
//
// Measured on 12.10: a journal follow outlasted its lease, the scheduler put
// the job back in the queue, and the host offered the result it had been
// holding. A queued job may become leased, canceled or expired and nothing
// else, so the result was refused - twice - and two seconds later, after a
// redelivery, the same result was accepted on a new attempt. The attempt that
// did the work ended "lease_expired".
//
// On a laboratory that is one red line in a suite. On a fleet it means the
// same operation handed out again because the answer to the first one arrived
// in the wrong second: the change is carried out twice.
//
// So a result arriving on an attempt the panel itself gave up settles the job
// from any state that is not already final.
func TestTheResultOfAGivenUpAttemptSettlesAJobBackInTheQueue(t *testing.T) {
	// The window between the reclaim and the redelivery, which is where the
	// refusals happened, and the states around it.
	for _, current := range []State{StateQueued, StateLeased, StateDispatched, StateRunning} {
		if fate := fateOfResult(current, StateSucceeded, true); fate != fateSettles {
			t.Errorf("the result of an attempt the panel gave up does not settle a %s job; "+
				"the operation would be handed out again", current)
		}
	}

	// Nothing else changes. Without the lease having expired, a queued or
	// leased job still refuses a result: that is a host answering for work
	// this job has not handed it.
	for _, current := range []State{StateQueued, StateLeased} {
		if fate := fateOfResult(current, StateSucceeded, false); fate != fateUnapplicable {
			t.Errorf("a %s job took a result from an attempt it had not given up", current)
		}
	}

	// And a job already settled stays settled, whatever the attempt's status:
	// the result is written on the attempt and the decision is not undone.
	for _, expired := range []bool{false, true} {
		if fate := fateOfResult(StateSucceeded, StateFailed, expired); fate != fateAfterSettlement {
			t.Errorf("a settled job was reopened by a late result (lease expired: %v)", expired)
		}
	}
}
