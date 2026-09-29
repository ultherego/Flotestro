// Package jobs holds the model of typed operations: the state machine, the
// queue with leases and the record of attempts.
package jobs

import (
	"fmt"
	"strings"
)

// State is the state of a job. Transitions are validated in the domain, not
// in a handler.
type State string

const (
	StatePlanned          State = "planned"
	StateAwaitingApproval State = "awaiting_approval"
	StateQueued           State = "queued"
	StateLeased           State = "leased"
	StateDispatched       State = "dispatched"
	StateRunning          State = "running"
	// StateCancelRequested is a cancel asked of a host that holds the task: the
	// request went out, and the job waits for the agent to say what it found.
	StateCancelRequested State = "cancel_requested"
	StateSucceeded       State = "succeeded"
	StateFailed          State = "failed"
	StateTimedOut        State = "timed_out"
	StateCanceled        State = "canceled"
	StateExpired         State = "expired"
)

// transitions describes the allowed transitions. The agent cannot move a job
// from planned to running on its own - it has to go through a lease.
var transitions = map[State][]State{
	StatePlanned:          {StateAwaitingApproval, StateQueued, StateCanceled, StateExpired},
	StateAwaitingApproval: {StateQueued, StateCanceled, StateExpired},
	StateQueued:           {StateLeased, StateCanceled, StateExpired},
	// Going back to queued is the normal path after a lease expires.
	StateLeased:     {StateDispatched, StateQueued, StateCanceled, StateExpired, StateFailed},
	StateDispatched: {StateRunning, StateSucceeded, StateFailed, StateTimedOut, StateCanceled, StateExpired, StateQueued, StateCancelRequested},
	StateRunning:    {StateSucceeded, StateFailed, StateTimedOut, StateCanceled, StateQueued, StateCancelRequested},
	// A requested cancel ends the way the host says: canceled on not_started or
	// interrupted, back to running on not_interruptible, with the result on
	// already_done - and failed by the sweep when no answer came.
	StateCancelRequested: {StateCanceled, StateRunning, StateSucceeded, StateFailed, StateTimedOut},
}

// Terminal says whether the state is final.
func (s State) Terminal() bool {
	switch s {
	case StateSucceeded, StateFailed, StateTimedOut, StateCanceled, StateExpired:
		return true
	default:
		return false
	}
}

// CanTransition checks whether a transition is allowed.
func (s State) CanTransition(to State) bool {
	for _, allowed := range transitions[s] {
		if allowed == to {
			return true
		}
	}
	return false
}

// Validate returns an error describing a forbidden transition.
func (s State) Validate(to State) error {
	if s == to {
		return nil
	}
	if !s.CanTransition(to) {
		return fmt.Errorf("forbidden transition %s -> %s", s, to)
	}
	return nil
}

// leaseHoldingStates are the states in which a job is carried by an open
// attempt: it holds a lease, and only that attempt can bring its result.
var leaseHoldingStates = []State{StateLeased, StateDispatched, StateRunning, StateCancelRequested}

// HoldsLease says whether a job in this state is being carried by an attempt.
func (s State) HoldsLease() bool {
	for _, held := range leaseHoldingStates {
		if held == s {
			return true
		}
	}
	return false
}

// leaseHoldingStateList renders the lease-holding states for the in (...) of a
// query, so that one list answers for every sweep that looks at them.
func leaseHoldingStateList() string {
	quoted := make([]string, 0, len(leaseHoldingStates))
	for _, state := range leaseHoldingStates {
		quoted = append(quoted, "'"+string(state)+"'")
	}
	return strings.Join(quoted, ", ")
}

// resultFate says what a result may do to its job, by the state the job is in
// and the state the result asks for.
type resultFate int

const (
	// fateSettles: the job is open and may make the move the result asks for.
	fateSettles resultFate = iota
	// fateAfterSettlement: the job is already final; the result goes on the
	// attempt and changes nothing.
	fateAfterSettlement
	// fateUnapplicable: the job is open and may not make the move the result
	// asks for, so nothing about the job is settled by it.
	fateUnapplicable
)

// fateOfResult judges a result by the state of its job.
func fateOfResult(current, asked State) resultFate {
	switch {
	case current.Terminal():
		return fateAfterSettlement
	case current.Validate(asked) != nil:
		return fateUnapplicable
	default:
		return fateSettles
	}
}

// closesTheAttempt says whether the store may close the attempt such a result
// came on. An attempt closed under a job that still holds it leaves the job
// carried by nothing and with no lease left to expire.
func (f resultFate) closesTheAttempt() bool { return f == fateAfterSettlement }
