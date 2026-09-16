package campaigns

import (
	"context"
	"errors"
	"testing"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
)

// casQuerier stands in for the database under a compare-and-swap write:
// it answers every row query with the rows it was told to have - none, for
// a row that moved - and counts what was asked of it.
type casQuerier struct {
	matched  bool
	revision int64
	calls    int
}

func (q *casQuerier) Exec(context.Context, string, ...any) (pgconn.CommandTag, error) {
	q.calls++
	if q.matched {
		return pgconn.NewCommandTag("UPDATE 1"), nil
	}
	return pgconn.NewCommandTag("UPDATE 0"), nil
}

func (q *casQuerier) Query(context.Context, string, ...any) (pgx.Rows, error) {
	q.calls++
	return nil, errors.New("the compare-and-swap does not read rows")
}

func (q *casQuerier) QueryRow(_ context.Context, _ string, args ...any) pgx.Row {
	q.calls++
	if !q.matched {
		return casRow{err: pgx.ErrNoRows}
	}
	// The statement returns the new revision, the state it left, the time
	// spent in it and the action; the fake reports the state written as
	// the one left, so no metric is observed.
	return casRow{revision: q.revision, previous: args[4].(string)}
}

type casRow struct {
	err      error
	revision int64
	previous string
}

func (r casRow) Scan(dest ...any) error {
	if r.err != nil {
		return r.err
	}
	*dest[0].(*int64) = r.revision
	*dest[1].(*string) = r.previous
	*dest[2].(*float64) = 0
	*dest[3].(*string) = "unit.restart"
	return nil
}

// TestAConcurrentTransitionIsRefused guards the compare-and-swap: a write
// against a row whose revision, state or claim token moved touches nothing
// and comes back as ErrConcurrentTransition, so the caller reads the row
// again instead of repeating a decision made on a stale picture. A write
// against the row as it was read moves it and returns the new revision.
func TestAConcurrentTransitionIsRefused(t *testing.T) {
	store := &Store{}
	moved := &casQuerier{matched: false}
	target := &Target{ID: "t1", State: TargetPending, Revision: 3, ClaimToken: 2}
	if _, err := store.updateTarget(context.Background(), moved, target, TargetDispatched, "", ""); !errors.Is(err, ErrConcurrentTransition) {
		t.Fatalf("a write against a moved row returned %v, expected ErrConcurrentTransition", err)
	}
	if target.Revision != 3 || target.State != TargetPending {
		t.Errorf("the refused write changed the target in memory: %+v", target)
	}

	held := &casQuerier{matched: true, revision: 4}
	revision, err := store.updateTarget(context.Background(), held, target, TargetDispatched, "", "")
	if err != nil {
		t.Fatalf("a write against the row as read failed: %v", err)
	}
	if revision != 4 {
		t.Errorf("the write returned revision %d, expected 4", revision)
	}

	// The step writes next to a transition are fenced the same way.
	if err := store.attachJob(context.Background(), moved, target, "job_id", "j1"); !errors.Is(err, ErrConcurrentTransition) {
		t.Errorf("attaching a task to a moved row returned %v", err)
	}
	if err := store.setBootIDBefore(context.Background(), moved, target, "boot"); !errors.Is(err, ErrConcurrentTransition) {
		t.Errorf("recording the boot ID on a moved row returned %v", err)
	}
	if err := store.attachJob(context.Background(), held, target, "job_id", "j1"); err != nil {
		t.Errorf("attaching a task to the row as read failed: %v", err)
	}
}

// TestASettledHostNeverMovesAgain guards the terminal rule of the target
// state machine: a settled host is not written again, whatever state is
// asked for, and the database is not even asked - a late result is an
// observation about the host, not a transition of it.
func TestASettledHostNeverMovesAgain(t *testing.T) {
	store := &Store{}
	for _, from := range []TargetState{TargetSucceeded, TargetNoChange, TargetFailed, TargetUnknown,
		TargetSkipped, TargetCanceled, TargetIneligible, TargetExcluded} {
		for _, to := range []TargetState{TargetPending, TargetDispatched, TargetRunning, TargetSucceeded, TargetCanceled} {
			if from.mayBecome(to) {
				t.Errorf("a %s host may become %s", from, to)
			}
			untouched := &casQuerier{matched: true, revision: 9}
			target := &Target{ID: "t", State: from, Revision: 1}
			_, err := store.updateTarget(context.Background(), untouched, target, to, "", "")
			if !errors.Is(err, ErrIllegalTransition) {
				t.Errorf("moving a %s host to %s returned %v, expected ErrIllegalTransition", from, to, err)
			}
			if untouched.calls != 0 {
				t.Errorf("moving a %s host to %s reached the database", from, to)
			}
		}
	}
	// The course of an open host: the queue, the task, the reboot, the
	// verification, and any end from any open state.
	allowed := [][2]TargetState{
		{TargetPending, TargetDispatched}, {TargetPending, TargetPlanning}, {TargetPending, TargetAwaitingBudget},
		{TargetPending, TargetQueuedOffline}, {TargetAwaitingBudget, TargetDispatched}, {TargetAwaitingBudget, TargetAwaitingBudget},
		{TargetQueuedOffline, TargetPending}, {TargetQueuedOffline, TargetPlanning}, {TargetPlanning, TargetPending},
		{TargetDispatched, TargetAwaitingLock}, {TargetAwaitingLock, TargetRunning}, {TargetRunning, TargetDispatched},
		{TargetRunning, TargetRebooting}, {TargetRunning, TargetVerifying}, {TargetRebooting, TargetVerifying},
		{TargetVerifying, TargetSucceeded}, {TargetDispatched, TargetCanceled}, {TargetPlanning, TargetNoChange},
		{TargetRunning, TargetUnknown},
	}
	for _, move := range allowed {
		if !move[0].mayBecome(move[1]) {
			t.Errorf("a %s host cannot become %s", move[0], move[1])
		}
	}
	refused := [][2]TargetState{
		{TargetVerifying, TargetPending}, {TargetRebooting, TargetDispatched}, {TargetRunning, TargetPlanning},
		{TargetDispatched, TargetQueuedOffline}, {TargetPending, TargetRebooting}, {TargetPending, TargetVerifying},
	}
	for _, move := range refused {
		if move[0].mayBecome(move[1]) {
			t.Errorf("a %s host may become %s, which is not on its course", move[0], move[1])
		}
	}
}

// TestTheCampaignStateMachineHasNoWayOutOfTheEnd guards the campaign
// side: a terminal campaign never runs again, the orchestrator's
// transitions follow the phases, and the pausing state sits between a
// running campaign and a paused one.
func TestTheCampaignStateMachineHasNoWayOutOfTheEnd(t *testing.T) {
	for _, from := range []State{StateCompleted, StateCompletedWithIssues, StateFailed, StatePlanFailed, StateExpired, StateCanceled} {
		for _, to := range []State{StateRunning, StateCanary, StatePaused, StatePausing, StateCanceled, StateCompleted} {
			if from.mayBecome(to) {
				t.Errorf("a %s campaign may become %s", from, to)
			}
		}
	}
	allowed := [][2]State{
		{StatePlanned, StateCanary}, {StatePlanned, StateRunning}, {StateCanary, StateRunning},
		{StateCanary, StateManualGate}, {StatePlanned, StateManualGate},
		{StateRunning, StatePausing}, {StateRunning, StatePaused}, {StatePausing, StatePaused},
		{StateCanary, StatePausing}, {StatePlanned, StatePaused},
		{StateCanceling, StateCanceled}, {StateRunning, StateCompleted}, {StateRunning, StateCompletedWithIssues},
		{StateRunning, StateFailed}, {StatePlanning, StatePlanFailed}, {StateAwaitingApproval, StateExpired},
		{StatePlanned, StateExpired},
	}
	for _, move := range allowed {
		if !move[0].mayBecome(move[1]) {
			t.Errorf("a %s campaign cannot become %s", move[0], move[1])
		}
	}
	refused := [][2]State{
		{StatePaused, StateRunning}, {StatePausing, StateRunning}, {StatePaused, StatePausing},
		{StateRunning, StateCanceled}, {StateCanceling, StateRunning}, {StateCanceling, StatePaused},
		{StateRunning, StateRunning}, {StateManualGate, StateRunning}, {StateAwaitingApproval, StateRunning},
	}
	for _, move := range refused {
		if move[0].mayBecome(move[1]) {
			t.Errorf("a %s campaign may become %s on the orchestrator's word alone", move[0], move[1])
		}
	}
}

// TestAPauseWaitsForTheHostsUnderWay guards the pausing state: a pause
// with hosts still carrying a task is pausing, a pause with none is
// paused, and neither pausing nor paused starts a host - only the planning
// phase, a planned campaign on its first pass, the canary and the waves
// do.
func TestAPauseWaitsForTheHostsUnderWay(t *testing.T) {
	for _, state := range []TargetState{TargetDispatched, TargetAwaitingLock, TargetRunning, TargetRebooting, TargetVerifying} {
		targets := []Target{{State: TargetSucceeded}, {State: state}, {State: TargetPending}}
		if got := pauseState(targets); got != StatePausing {
			t.Errorf("a pause with a %s host gives %s, expected pausing", state, got)
		}
	}
	quiet := []Target{{State: TargetSucceeded}, {State: TargetPending}, {State: TargetAwaitingBudget}, {State: TargetQueuedOffline}}
	if got := pauseState(quiet); got != StatePaused {
		t.Errorf("a pause with no host under way gives %s, expected paused", got)
	}
	if got := pauseState(nil); got != StatePaused {
		t.Errorf("a pause of a campaign without hosts gives %s", got)
	}

	for _, state := range []State{StatePausing, StatePaused, StateCanceling, StateManualGate, StateAwaitingApproval, StateCompleted, StateCanceled} {
		if state.Launching() {
			t.Errorf("a %s campaign starts hosts", state)
		}
	}
	for _, state := range []State{StatePlanning, StatePlanned, StateCanary, StateRunning} {
		if !state.Launching() {
			t.Errorf("a %s campaign starts no host", state)
		}
	}
	// Pausing is neither active nor final, like canceling: nothing starts,
	// and the campaign is not over.
	if StatePausing.Terminal() || StatePausing.Active() {
		t.Error("pausing is classified wrongly")
	}
}
