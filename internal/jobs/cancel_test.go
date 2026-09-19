package jobs

import "testing"

// A cancel of a task the host holds is a question, not a verdict: the job
// enters cancel_requested from the two states in which a host has the task,
// and from nowhere else - a task still in the panel is canceled outright and
func TestACancelRequestIsAskedOnlyOfAHostThatHoldsTheTask(t *testing.T) {
	for _, from := range []State{StateDispatched, StateRunning} {
		if !from.CanTransition(StateCancelRequested) {
			t.Errorf("%s -> cancel_requested has to be possible: the host holds the task", from)
		}
	}
	for _, from := range []State{StatePlanned, StateAwaitingApproval, StateQueued, StateLeased,
		StateSucceeded, StateFailed, StateTimedOut, StateCanceled, StateExpired} {
		if from.CanTransition(StateCancelRequested) {
			t.Errorf("%s -> cancel_requested asks a host that holds nothing", from)
		}
	}
	if StateCancelRequested.Terminal() {
		t.Error("cancel_requested is a question in flight, not an end")
	}
}

// The answer of the host settles the request the way the protocol says:
// canceled when nothing started or the work was cut short, running again when
// the phase has to finish, the result when the host had it already.
func TestTheAnswerOfTheHostSettlesTheCancelRequest(t *testing.T) {
	for _, to := range []State{StateCanceled, StateRunning, StateSucceeded, StateFailed, StateTimedOut} {
		if !StateCancelRequested.CanTransition(to) {
			t.Errorf("cancel_requested -> %s has to be possible", to)
		}
	}
	for _, to := range []State{StateQueued, StateLeased, StateDispatched, StateExpired, StatePlanned} {
		if StateCancelRequested.CanTransition(to) {
			t.Errorf("cancel_requested -> %s delivers a task somebody asked to stop", to)
		}
	}
}

// The outcomes stored on the job are the protocol's words in lower case, and
// nothing else is one: an agent that answers with a word the panel does not
// know is not guessed at.
func TestTheCancelOutcomesAreTheProtocolsWords(t *testing.T) {
	for _, outcome := range []string{"not_started", "interrupted", "not_interruptible", "already_done"} {
		if !KnownCancelOutcome(outcome) {
			t.Errorf("%s is an outcome of the protocol and is not known", outcome)
		}
	}
	for _, other := range []string{"", "NOT_STARTED", "canceled", "done"} {
		if KnownCancelOutcome(other) {
			t.Errorf("%q was taken for an outcome", other)
		}
	}
	// The codes the sweep writes are part of the contract with the error
	// guide and the screens.
	if CancelAckTimeoutCode != "cancel_ack_timeout" || ResultStatusUnknown != "unknown_needs_reconciliation" {
		t.Fatalf("the cancel codes changed: %q, %q", CancelAckTimeoutCode, ResultStatusUnknown)
	}
}
