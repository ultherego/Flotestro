package jobs

import (
	"strings"
	"testing"
)

// Every state a lease may be renewed in is a state the reclaim looks at.
// A job whose lease is kept alive in a state the sweep does not scan runs out
// of lease and is never taken back: it stands there for ever.
func TestTheReclaimLooksAtEveryStateALeaseIsRenewedIn(t *testing.T) {
	for _, state := range leaseHoldingStates {
		if state.Terminal() {
			t.Errorf("%s is final and holds no lease", state)
		}
		if !strings.Contains(reclaimExpiredLeasesQuery, "'"+string(state)+"'") {
			t.Errorf("the reclaim does not look at %s, so a lease that runs out there is never taken back", state)
		}
	}
	// The cancel that the host never answered is the case this closes: the
	// renewal accepted it and the sweep did not.
	if !StateCancelRequested.HoldsLease() {
		t.Error("a job waiting for the host's answer to a cancel holds its attempt and its lease")
	}
	for _, state := range []State{StatePlanned, StateAwaitingApproval, StateQueued,
		StateSucceeded, StateFailed, StateTimedOut, StateCanceled, StateExpired} {
		if state.HoldsLease() {
			t.Errorf("%s is not carried by an attempt", state)
		}
	}
}

// A job in a state that holds a lease with no open attempt is carried by
// nothing: no lease will ever expire on it and no result can arrive, so the
// reclaim has to find it by the missing attempt rather than by the lease.
func TestAJobWithNoOpenAttemptIsTakenBack(t *testing.T) {
	if !strings.Contains(reclaimExpiredLeasesQuery, "stranded as (") {
		t.Fatal("the reclaim reads nothing but expiring leases, so a job whose attempt was closed under it stays open for ever")
	}
	if !strings.Contains(reclaimExpiredLeasesQuery,
		"not exists (select 1 from job_attempts a\n\t\t\t                   where a.job_id = j.id and a.finished_at is null)") {
		t.Error("the stranded jobs are not the ones without an open attempt")
	}
	if !strings.Contains(reclaimExpiredLeasesQuery, "select job_id from closed\n\t\t\tunion\n\t\t\tselect job_id from stranded") {
		t.Error("the stranded jobs are read and not settled")
	}
}

// The operator asked for the work to stop and the host then went silent:
// sending the task out again would deliver what they stopped, and calling it
// canceled would claim nothing happened on a host nobody reached.
func TestAStoppedJobWhoseLeaseRanOutIsNotSentOutAgain(t *testing.T) {
	stopped, found := branchOf(t, reclaimExpiredLeasesQuery, "stopped as (")
	if !found {
		t.Fatal("a job asked to stop is settled by no branch of the reclaim")
	}
	if !strings.Contains(stopped, "state = 'cancel_requested'") {
		t.Error("the branch does not name the jobs the operator asked to stop")
	}
	if !strings.Contains(stopped, "state = 'failed'") {
		t.Error("a job nobody reached has to end, not wait")
	}
	if !strings.Contains(stopped, "$5") || !strings.Contains(stopped, "$6") {
		t.Error("the outcome and the reason of a stopped job are not written")
	}
	requeued, found := branchOf(t, reclaimExpiredLeasesQuery, "requeued as (")
	if !found {
		t.Fatal("the reclaim no longer queues anything")
	}
	if !strings.Contains(requeued, "state <> 'cancel_requested'") {
		t.Error("a job the operator asked to stop goes back to the queue and is delivered again")
	}
	// What the operator reads is a code the error guide documents and a result
	// status that does not claim to know what the host did.
	if AttemptStatusLeaseExpired != "lease_expired" || ResultStatusUnknown != "unknown_needs_reconciliation" {
		t.Fatalf("the codes of a job nobody reached changed: %q, %q",
			AttemptStatusLeaseExpired, ResultStatusUnknown)
	}
	if !strings.Contains(StoppedHostSilentMessage, "unknown") {
		t.Errorf("the message does not say the outcome on the host is unknown: %q", StoppedHostSilentMessage)
	}
}

// branchOf cuts one named branch out of the query, up to the line that closes
// it, so that a test reads the branch it means and not the whole statement.
func branchOf(t *testing.T, query, head string) (string, bool) {
	t.Helper()
	start := strings.Index(query, head)
	if start < 0 {
		return "", false
	}
	rest := query[start+len(head):]
	end := strings.Index(rest, "\n\t\t)")
	if end < 0 {
		return rest, true
	}
	return rest[:end], true
}

// A result the open job may not take settles nothing, and an attempt closed
// under a job that still holds it leaves the job carried by nothing: the
// lease is gone, so the reclaim never sees it again.
func TestAResultTheJobMayNotTakeLeavesItsAttemptOpen(t *testing.T) {
	// The states the gateway asks for, by the status the agent reported.
	asked := []State{StateSucceeded, StateFailed, StateTimedOut, StateCanceled, StateExpired}
	for _, current := range leaseHoldingStates {
		for _, to := range asked {
			fate := fateOfResult(current, to)
			if current.CanTransition(to) || current == to {
				if fate != fateSettles {
					t.Errorf("%s -> %s is allowed and does not settle the job", current, to)
				}
				continue
			}
			if fate != fateUnapplicable {
				t.Errorf("%s -> %s is forbidden and was not read as such", current, to)
			}
			if fate.closesTheAttempt() {
				t.Errorf("a result asking %s -> %s closes the attempt and strands the job in %s",
					current, to, current)
			}
		}
	}
	// The two the fleet runs into: a host that reports its task expired after it
	// started, and one that finishes before the panel has recorded the delivery.
	if fateOfResult(StateRunning, StateExpired) != fateUnapplicable {
		t.Error("running -> expired is not a move the job may make")
	}
	if fateOfResult(StateLeased, StateSucceeded) != fateUnapplicable {
		t.Error("leased -> succeeded is not a move the job may make")
	}
}

// A result that arrives after the job was settled is written on the attempt:
// the record of what the host did stays, and the settlement stands.
func TestAResultAfterTheSettlementClosesItsAttempt(t *testing.T) {
	for _, current := range []State{StateSucceeded, StateFailed, StateTimedOut, StateCanceled, StateExpired} {
		fate := fateOfResult(current, StateSucceeded)
		if fate != fateAfterSettlement {
			t.Errorf("a result on a job that is already %s is not read as late", current)
		}
		if !fate.closesTheAttempt() {
			t.Errorf("the attempt of a job that is already %s stays open for ever", current)
		}
	}
}
