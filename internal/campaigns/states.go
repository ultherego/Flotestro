package campaigns

import (
	"slices"
	"strings"
)

// The state sets the SQL of this package shares. Every list was written out in
// each query that needed it, and that is how a campaign standing at the manual
// gate came to be counted by ActiveTargets and driven by nobody: the state was
// added to one literal and not to the other. A query that genuinely means
// something narrower keeps its own list and says why at the call site.

// AllStates lists every state a campaign can be in. The drift test reads the
// declarations and fails when one is missing here, so a new state has to be
// classified rather than quietly left out of every set below.
var AllStates = []State{
	StatePlanning, StatePlanned, StateAwaitingApproval, StateCanary, StateManualGate,
	StateRunning, StatePausing, StatePaused, StateCanceling,
	StateCompleted, StateCompletedWithIssues, StateFailed, StatePlanFailed,
	StateExpired, StateCanceled,
}

// UnfinishedStates are the states of a campaign that is still on the table:
// AllStates without the terminal ones. A campaign in one of these still owns
// its hosts and can still be decided on.
var UnfinishedStates = unfinishedStates()

// DrivenStates are the states in which the orchestrator has a pass to make on
// every tick. StatePaused is left out on purpose: a paused campaign is driven
// only while hosts are still carrying a task, which Store.Active asks for with
// a subquery over the targets rather than with a state.
var DrivenStates = withoutState(UnfinishedStates, StatePaused)

// PausableStates are the states an operator, or a stop threshold, may pause a
// campaign from. The gate is one of them: a campaign waiting for a decision can
// be held back instead of being decided.
var PausableStates = []State{StatePlanned, StateCanary, StateManualGate, StateRunning}

// InFlightTargetStates are the states of a host that is carrying a task of the
// campaign, from the dispatch of the task to the end of its verification. It is
// TargetState.UnderWay as a list, for the queries that ask the same in SQL.
var InFlightTargetStates = []TargetState{
	TargetDispatched, TargetAwaitingLock, TargetRunning, TargetRebooting, TargetVerifying,
}

// UnstartedTargetStates are the states of a host the campaign still owes a
// start to: nothing of the change has reached it yet.
var UnstartedTargetStates = []TargetState{
	TargetPending, TargetPlanning, TargetAwaitingBudget, TargetQueuedOffline,
}

// OpenTargetStates are the states of a host that is not settled: what a runner
// claims when it takes a campaign over, and what it keeps claimed while it
// drives it.
var OpenTargetStates = slices.Concat(UnstartedTargetStates, InFlightTargetStates)

// ClaimedTargetStates are the states in which a host's claim has to be kept
// alive: the ones carrying a task, and the one computing its plan.
var ClaimedTargetStates = slices.Concat([]TargetState{TargetPlanning}, InFlightTargetStates)

// SQLList renders a set of states as an SQL in-list, brackets included, for
// queries that cannot take an array parameter without changing their shape.
func SQLList[S ~string](states []S) string {
	quoted := make([]string, 0, len(states))
	for _, state := range states {
		quoted = append(quoted, "'"+string(state)+"'")
	}
	return "(" + strings.Join(quoted, ", ") + ")"
}

// unfinishedStates is AllStates without the terminal ones, computed rather than
// written out so the two cannot disagree.
func unfinishedStates() []State {
	open := make([]State, 0, len(AllStates))
	for _, state := range AllStates {
		if !state.Terminal() {
			open = append(open, state)
		}
	}
	return open
}

// withoutState returns the set without one state, for a query that deliberately
// asks for less than the whole.
func withoutState(states []State, drop State) []State {
	kept := make([]State, 0, len(states))
	for _, state := range states {
		if state != drop {
			kept = append(kept, state)
		}
	}
	return kept
}
