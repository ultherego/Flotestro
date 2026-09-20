package opspec

import (
	"errors"
	"strings"
	"testing"
)

// TestEveryMutatingOperationDeclaresItsContract guards the start-up check: the
// table is complete and no declaration contradicts the rest of the registry.
func TestEveryMutatingOperationDeclaresItsContract(t *testing.T) {
	if err := ValidateContracts(); err != nil {
		t.Fatalf("the contract table is incomplete or inconsistent: %v", err)
	}
	for _, action := range AllActions() {
		declared := action.Contract()
		if !KnownCancelMode(declared.CancelMode) || !KnownRetryPolicy(declared.RetryClass) ||
			!KnownRollbackClass(declared.Rollback) || !KnownVerification(declared.Verification) {
			t.Errorf("%s has an unknown class in its contract: %+v", action, declared)
		}
		if declared.ResourceClaims == nil {
			t.Errorf("%s has no claims list; an empty list is a declaration, nil is not", action)
		}
		if action.Mutating() {
			if _, ok := contracts[action]; !ok {
				t.Errorf("%s changes the host and is not in the contract table", action)
			}
			continue
		}
		// A read derives its contract: nothing to stop, nothing to repeat
		// carefully, nothing to undo, and only shared claims.
		if declared.CancelMode != CancelSafe || declared.RetryClass != RetryAutomatic ||
			declared.Rollback != RollbackNone || declared.Verification != VerifyNone {
			t.Errorf("%s is a read with the contract %+v", action, declared)
		}
		for _, claim := range declared.ResourceClaims {
			if claim.Mode != ClaimShared || claim.Weight != 1 {
				t.Errorf("%s is a read and takes %s %s with the weight %d", action, claim.Class, claim.Mode, claim.Weight)
			}
		}
	}
}

// TestTheContractClassesAgree spells out the rules the interface relies on,
// on the operations the document uses as its examples.
func TestTheContractClassesAgree(t *testing.T) {
	cases := map[ActionType]Contract{
		ActionUnitRestart: {CancelMode: CancelImpossibleAfterStart, RetryClass: RetryReadState,
			Rollback: RollbackNone, Verification: VerifyUnitHealth,
			ResourceClaims: []ResourceClaim{{Class: LockUnits, Mode: ClaimExclusive, Weight: 1}}},
		ActionPackageUpgrade: {CancelMode: CancelImpossibleAfterStart, RetryClass: RetryReadState,
			Rollback: RollbackCompensating, Verification: VerifyPlanRecheck,
			ResourceClaims: []ResourceClaim{{Class: LockPackages, Mode: ClaimExclusive, Weight: 4}}},
		ActionNetworkProfileApply: {CancelMode: CancelLocalWatchdogOwned, RetryClass: RetryAfterReplan,
			Rollback: RollbackAutomaticLocal, Verification: VerifyConnectivity,
			ResourceClaims: []ResourceClaim{{Class: LockNetwork, Mode: ClaimExclusive, Weight: 1}}},
		ActionFileEnsure: {CancelMode: CancelCheckpointOnly, RetryClass: RetryAfterReplan,
			Rollback: RollbackExactRestore, Verification: VerifyPlanRecheck,
			ResourceClaims: []ResourceClaim{{Class: ClaimFile, Mode: ClaimExclusive, Weight: 1}}},
		// The wipe is verified: its own specification names a verifier that reads
		// the device back, and a catalogue saying "not verified" told the operator
		// less than the host actually does.
		ActionDiskWipe: {CancelMode: CancelImpossibleAfterStart, RetryClass: RetryNever,
			Rollback: RollbackNone, Verification: VerifyCustom,
			ResourceClaims: []ResourceClaim{{Class: LockStorage, Mode: ClaimExclusive, Weight: 3}}},
		ActionSystemReboot: {CancelMode: CancelImpossibleAfterStart, RetryClass: RetryReadState,
			Rollback: RollbackNone, Verification: VerifyCustom,
			ResourceClaims: []ResourceClaim{{Class: ClaimHost, Mode: ClaimExclusive, Weight: 1}}},
		ActionSysctlEnsure: {CancelMode: CancelImpossibleAfterStart, RetryClass: RetryReadState,
			Rollback: RollbackCompensating, Verification: VerifyCustom,
			ResourceClaims: []ResourceClaim{
				{Class: ClaimKernel, Mode: ClaimExclusive, Weight: 1},
				{Class: LockNetwork, Mode: ClaimExclusive, Weight: 1},
			}},
		ActionReadJournal: {CancelMode: CancelSafe, RetryClass: RetryAutomatic,
			Rollback: RollbackNone, Verification: VerifyNone,
			ResourceClaims: []ResourceClaim{{Class: ClaimLogsRead, Mode: ClaimShared, Weight: 1}}},
		ActionPackagePlan: {CancelMode: CancelSafe, RetryClass: RetryAutomatic,
			Rollback: RollbackNone, Verification: VerifyNone,
			ResourceClaims: []ResourceClaim{{Class: LockPackages, Mode: ClaimShared, Weight: 1}}},
	}
	for action, want := range cases {
		t.Run(string(action), func(t *testing.T) {
			got := action.Contract()
			if got.CancelMode != want.CancelMode || got.RetryClass != want.RetryClass ||
				got.Rollback != want.Rollback || got.Verification != want.Verification {
				t.Errorf("contract = %+v, want %+v", got, want)
			}
			if len(got.ResourceClaims) != len(want.ResourceClaims) {
				t.Fatalf("claims = %+v, want %+v", got.ResourceClaims, want.ResourceClaims)
			}
			for i := range want.ResourceClaims {
				if got.ResourceClaims[i] != want.ResourceClaims[i] {
					t.Errorf("claim %d = %+v, want %+v", i, got.ResourceClaims[i], want.ResourceClaims[i])
				}
			}
		})
	}

	// The rules themselves, on declarations that break them: the check has
	// to name every contradiction, not stop at the first.
	broken := Contract{
		CancelMode: CancelImpossibleAfterStart, RetryClass: RetryAutomatic,
		Rollback: RollbackAutomaticLocal, Verification: VerifyPlanRecheck,
		ResourceClaims: []ResourceClaim{{Class: LockUnits, Mode: ClaimShared, Weight: 0}},
	}
	problems := strings.Join(contractProblems(ActionUnitRestart, broken), "\n")
	for _, expected := range []string{
		"impossible_after_start with retry_class automatic",
		"automatic_local and local_watchdog_owned go together",
		"plan_recheck on an operation without a planner",
		"is shared on a mutating operation",
		"has the weight 0",
		"no exclusive claim on the lock class units",
	} {
		if !strings.Contains(problems, expected) {
			t.Errorf("the check did not report %q:\n%s", expected, problems)
		}
	}
	if problems := contractProblems(ActionDiskWipe, Contract{
		CancelMode: CancelSafe, RetryClass: RetryAutomatic, Rollback: RollbackExactRestore,
		Verification: VerifyNone, ResourceClaims: []ResourceClaim{{Class: LockStorage, Mode: ClaimExclusive, Weight: 1}},
	}); len(problems) < 2 {
		t.Errorf("a destructive operation with an exact restore and an automatic retry passed: %v", problems)
	}
	if problems := contractProblems(ActionUnitStart, Contract{
		CancelMode: CancelSafe, RetryClass: RetryReadState, Rollback: RollbackNone,
		Verification: VerifyNone, ResourceClaims: []ResourceClaim{{Class: LockUnits, Mode: ClaimExclusive, Weight: 1}},
	}); len(problems) == 0 {
		t.Error("a safe cancel with a read_state retry passed")
	}
}

// TestAnUndeclaredMutationFailsTheStart guards the shape of the refusal: one
// error naming every operation without a decision, wrapped so the caller can
// tell it from a broken configuration.
func TestAnUndeclaredMutationFailsTheStart(t *testing.T) {
	undeclared := ActionType("test.undeclared.change")
	actionSpecs[undeclared] = actionSpec{mutating: true, permission: "test.change", risk: RiskHigh, lockClass: LockUnits}
	defer delete(actionSpecs, undeclared)

	err := ValidateContracts()
	if !errors.Is(err, ErrContractMissing) {
		t.Fatalf("an undeclared mutation did not fail the check: %v", err)
	}
	if !strings.Contains(err.Error(), string(undeclared)) {
		t.Errorf("the error does not name the operation: %v", err)
	}
	// The strictest reading until somebody decides: nothing stops it once
	// started, nothing repeats it blind, nothing takes it back.
	fallback := undeclared.Contract()
	if fallback.CancelMode != CancelImpossibleAfterStart || fallback.RetryClass != RetryReadState ||
		fallback.Rollback != RollbackNone || fallback.ResourceClaims == nil {
		t.Errorf("an undeclared mutation got the contract %+v", fallback)
	}
	// An extra row for an operation the registry does not know is a typo,
	// not a declaration.
	contracts[ActionType("test.typo")] = contract{cancel: CancelSafe, retry: RetryAutomatic, rollback: RollbackNone, verify: VerifyNone}
	defer delete(contracts, ActionType("test.typo"))
	if err := ValidateContracts(); err == nil || !strings.Contains(err.Error(), "test.typo") {
		t.Errorf("a row for an unknown operation passed: %v", err)
	}
}

// TestCancellableInFollowsTheCancelMode guards what the job page draws: a
// cancel button before the start for everything, after the start only for an
// operation that stops cleanly.
func TestCancellableInFollowsTheCancelMode(t *testing.T) {
	for _, action := range AllActions() {
		declared := action.Contract()
		if !declared.CancellableIn(false) {
			t.Errorf("%s is not cancellable before it started", action)
		}
		if declared.CancellableIn(true) != (declared.CancelMode == CancelSafe) {
			t.Errorf("%s: cancellable after start = %v with the mode %s",
				action, declared.CancellableIn(true), declared.CancelMode)
		}
	}
}

// TestEveryCampaignReadyActionDeclaresClaims guards what the agent relies on:
// the claims a task takes come from the contract, and the agent's own fallback
// list serves only a mutation whose row declares nothing.
func TestEveryCampaignReadyActionDeclaresClaims(t *testing.T) {
	for _, action := range AllActions() {
		if CampaignExclusionReason(action) != "" || !ExecutableMode(action) {
			continue
		}
		claims := action.Contract().ResourceClaims
		if len(claims) == 0 {
			t.Errorf("%s is ready for a campaign and declares no claim", action)
			continue
		}
		for _, claim := range claims {
			if claim.Mode != ClaimExclusive {
				t.Errorf("%s is ready for a campaign and takes %s %s", action, claim.Class, claim.Mode)
			}
		}
	}
}

// TestTheSharedClassesHaveACapacity spells out the ration of the two weighted
// classes, and that a lock class has none: its readers go by the task budget.
func TestTheSharedClassesHaveACapacity(t *testing.T) {
	if SharedCapacity(ClaimLogsRead) < 1 || SharedCapacity(ClaimInventoryHeavy) < 1 {
		t.Errorf("the weighted classes have the capacities logs %d and inventory %d",
			SharedCapacity(ClaimLogsRead), SharedCapacity(ClaimInventoryHeavy))
	}
	if SharedCapacity(LockPackages) != 0 || SharedCapacity(LockUnits) != 0 {
		t.Error("a lock class has a shared capacity; its readers are bounded by the task budget")
	}
	// The claims of a read fit its class: no read is heavier than what
	// its class carries, or it could never run next to anybody.
	for _, action := range AllActions() {
		for _, claim := range action.Contract().ResourceClaims {
			if capacity := SharedCapacity(claim.Class); capacity > 0 && claim.Weight > capacity {
				t.Errorf("%s takes %s with the weight %d, above the capacity %d", action, claim.Class, claim.Weight, capacity)
			}
		}
	}
}
