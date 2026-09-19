package adminapi

import (
	"testing"

	"github.com/ultherego/flotestro/internal/jobs"
	"github.com/ultherego/flotestro/internal/opspec"
)

// A cancel is refused only where it could do nothing: an operation the
// contract says cannot be stopped once started, and only after the host
// reported the start.
func TestACancelIsRefusedOnlyForAStartedNonCancelableOperation(t *testing.T) {
	mode, refused := nonCancelable(jobs.StateRunning, opspec.ActionPackageUpgrade)
	if !refused || mode != opspec.CancelImpossibleAfterStart {
		t.Errorf("a running package upgrade: mode %q, refused %v", mode, refused)
	}
	for _, state := range []jobs.State{jobs.StateQueued, jobs.StateLeased, jobs.StateDispatched, jobs.StateAwaitingApproval} {
		if _, refused := nonCancelable(state, opspec.ActionPackageUpgrade); refused {
			t.Errorf("a package upgrade in %s was refused a cancel; the host has not started it", state)
		}
	}
	for _, action := range []opspec.ActionType{opspec.ActionReadJournal, opspec.ActionFollowJournal} {
		if action.Contract().CancelMode == opspec.CancelImpossibleAfterStart {
			t.Fatalf("%s is not cancellable; the test picked a wrong example", action)
		}
		if _, refused := nonCancelable(jobs.StateRunning, action); refused {
			t.Errorf("a running %s was refused a cancel; its contract says %s", action, action.Contract().CancelMode)
		}
	}
}

// The action_prefix filter takes the beginning of an operation type and
// nothing that could be read as a pattern.
func TestActionPrefixTakesOnlyTheShapeOfAnOperationType(t *testing.T) {
	for _, ok := range []string{"packages.", "packages.upgrade", "unit", "agent.upgrade"} {
		if !actionPrefixPattern.MatchString(ok) {
			t.Errorf("%q was refused", ok)
		}
	}
	for _, bad := range []string{"", "%", "packages.%", "Packages.", "packages.'; drop", " packages"} {
		if actionPrefixPattern.MatchString(bad) {
			t.Errorf("%q was accepted", bad)
		}
	}
}
