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
