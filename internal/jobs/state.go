// Package jobs holds the model of typed operations: the state machine, the
// queue with leases and the record of attempts. The package knows neither the
// HTTP layer nor the agent protocol.
package jobs

import "fmt"

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
	StateSucceeded        State = "succeeded"
	StateFailed           State = "failed"
	StateTimedOut         State = "timed_out"
	StateCanceled         State = "canceled"
	StateExpired          State = "expired"
)

// transitions describes the allowed transitions. The agent cannot move a job
// from planned to running on its own - it has to go through a lease.
var transitions = map[State][]State{
	StatePlanned:          {StateAwaitingApproval, StateQueued, StateCanceled, StateExpired},
	StateAwaitingApproval: {StateQueued, StateCanceled, StateExpired},
	StateQueued:           {StateLeased, StateCanceled, StateExpired},
	// Going back to queued is the normal path after a lease expires.
	StateLeased:     {StateDispatched, StateQueued, StateCanceled, StateExpired, StateFailed},
	StateDispatched: {StateRunning, StateSucceeded, StateFailed, StateTimedOut, StateCanceled, StateExpired, StateQueued},
	StateRunning:    {StateSucceeded, StateFailed, StateTimedOut, StateCanceled, StateQueued},
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
