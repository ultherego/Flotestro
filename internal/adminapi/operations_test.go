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

// Approving a highest-risk change asks who is approving, the same way ordering
// it asked. It was the one decision path of high consequence that went from an
// hour-old session - and where a second person is required, approving is the
// decision that matters (audit of 6c38561, AUTHZ-03).
func TestApprovingAHighestRiskChangeAsksForFreshAuthentication(t *testing.T) {
	// The rule is the one the creation uses, so the two cannot drift: an
	// action whose risk is critical or destructive needs the confirmation.
	for _, action := range []opspec.ActionType{
		opspec.ActionLocalSSHKeysReplaceAll, opspec.ActionDiskWipe, opspec.ActionHostFinalWipe,
	} {
		if !opspec.PayloadRequiresFreshAuthForAccount(action, opspec.Payload{},
			opspec.AccountPrivilegeOrdinary) {
			t.Errorf("%s does not ask for fresh authentication, so approving it would not either", action)
		}
	}
	// And an ordinary one does not, because then every approval would turn
	// into a second login and the rule would be turned off by whoever has to
	// work with it.
	if opspec.PayloadRequiresFreshAuthForAccount(opspec.ActionUnitRestart, opspec.Payload{},
		opspec.AccountPrivilegeOrdinary) {
		t.Error("restarting a unit asks for fresh authentication")
	}
}
