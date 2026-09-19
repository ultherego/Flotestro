package jobs

import "testing"

func TestTheAgentCannotSkipTheLease(t *testing.T) {
	// The agent cannot move a job to running on its own: a valid lease has to
	// exist, that is, the way through leased and dispatched.
	if StatePlanned.CanTransition(StateRunning) {
		t.Fatal("planned -> running is allowed and should not be")
	}
	if StateQueued.CanTransition(StateRunning) {
		t.Fatal("queued -> running skips the lease")
	}
	if StateQueued.CanTransition(StateSucceeded) {
		t.Fatal("queued -> succeeded skips the execution")
	}
}

func TestAnExpiredLeaseGoesBackToTheQueue(t *testing.T) {
	for _, from := range []State{StateLeased, StateDispatched, StateRunning} {
		if !from.CanTransition(StateQueued) {
			t.Errorf("%s -> queued has to be possible after losing the lease", from)
		}
	}
}

func TestAFinalStateIsFinal(t *testing.T) {
	terminal := []State{StateSucceeded, StateFailed, StateTimedOut, StateCanceled, StateExpired}
	for _, state := range terminal {
		if !state.Terminal() {
			t.Errorf("%s should be a final state", state)
		}
		// There is no way out of a final state; a late result does not
		// overwrite a decision.
		for _, to := range terminal {
			if state != to && state.CanTransition(to) {
				t.Errorf("the final state %s can move to %s", state, to)
			}
		}
		if state.CanTransition(StateRunning) {
			t.Errorf("the final state %s can be resumed", state)
		}
	}
}

func TestValidateAllowsRepeatingTheSameState(t *testing.T) {
	// Delivering a result again is not a transition error.
	if err := StateSucceeded.Validate(StateSucceeded); err != nil {
		t.Fatalf("a repeated final state was rejected: %v", err)
	}
	if err := StateQueued.Validate(StateSucceeded); err == nil {
		t.Fatal("a forbidden transition passed validation")
	}
}

// TestRunningIsReachedFromDispatchedOnly: the agent's word that the operation
// started moves a delivered job to running and nothing else does - a job that
// was never handed over cannot start, and a running job ends the way any
func TestRunningIsReachedFromDispatchedOnly(t *testing.T) {
	if !StateDispatched.CanTransition(StateRunning) {
		t.Fatal("dispatched -> running is the start the agent reports and has to be allowed")
	}
	for _, from := range []State{StatePlanned, StateAwaitingApproval, StateQueued, StateLeased} {
		if from.CanTransition(StateRunning) {
			t.Errorf("%s -> running skips the hand-over", from)
		}
	}
	for _, to := range []State{StateSucceeded, StateFailed, StateTimedOut, StateCanceled} {
		if !StateRunning.CanTransition(to) {
			t.Errorf("running -> %s has to be possible: that is how an executed job ends", to)
		}
	}
	if StateRunning.CanTransition(StateDispatched) {
		t.Error("a running job went back to dispatched")
	}
}

// TestTheLockWaitReasonRoundTrips: the reason a delivered job waits with names
// the blocker the agent reported, under its own prefix, so that a budget wait
// and a lock wait are told apart by the prefix alone.
func TestTheLockWaitReasonRoundTrips(t *testing.T) {
	reason := LockWaitReason("units held by task 7c1e (schedule.run_now)")
	if reason != "awaiting_lock:units held by task 7c1e (schedule.run_now)" {
		t.Fatalf("reason = %q", reason)
	}
	blocker, waited := LockBlocker(reason)
	if !waited || blocker != "units held by task 7c1e (schedule.run_now)" {
		t.Errorf("blocker = %q, waited = %v", blocker, waited)
	}
	for _, other := range []string{"", "awaiting_budget:global:mutations"} {
		if _, waited := LockBlocker(other); waited {
			t.Errorf("%q was read as a lock wait", other)
		}
	}
}
