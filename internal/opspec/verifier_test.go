package opspec

import (
	"strings"
	"testing"
)

// Every mutating operation names the read that confirms it, every read
// names none, and the names are the registry's. The two operations the
// panel settles on the host's return are marked so.
func TestEveryMutatingOperationDeclaresAVerifier(t *testing.T) {
	if err := ValidateVerifiers(); err != nil {
		t.Fatalf("the verifiers do not validate: %v", err)
	}
	for _, action := range AllActions() {
		verifier := action.Verifier()
		if !KnownVerifier(verifier) {
			t.Errorf("%s: verifier %q is not in the registry", action, verifier)
		}
		if !action.Mutating() && verifier != VerifierNone {
			t.Errorf("%s: a read has the verifier %q", action, verifier)
		}
		spec := action.Describe()
		if spec.Verifier != verifier || spec.OnUnverified != action.OnUnverified() {
			t.Errorf("%s: the catalogue says %s/%s, the registry %s/%s",
				action, spec.Verifier, spec.OnUnverified, verifier, action.OnUnverified())
		}
	}
	for action, want := range map[ActionType]Verifier{
		ActionUnitRestart:    VerifierUnitState,
		ActionPackageInstall: VerifierPackageVersions,
		ActionFileEnsure:     VerifierFileContent,
		ActionMountEnsure:    VerifierMountState,
		ActionSystemReboot:   VerifierReboot,
		ActionAgentUpgrade:   VerifierAgentVersion,
		ActionBackupRun:      VerifierBackupRun,
		ActionReadJournal:    VerifierNone,
		ActionPackagePlan:    VerifierNone,
		ActionProcessSignal:  VerifierNone,
	} {
		if got := action.Verifier(); got != want {
			t.Errorf("%s: verifier %s, want %s", action, got, want)
		}
	}
	if !ActionSystemReboot.Verifier().PanelSettled() || ActionUnitRestart.Verifier().PanelSettled() {
		t.Error("the panel settles a reboot and not a unit restart")
	}
}

// A rollback on an unverified change is declared only where the host
// keeps what puts the previous state back; everything else reports.
func TestOnUnverifiedRollbackSitsOnlyOnReversibleChanges(t *testing.T) {
	for _, action := range []ActionType{ActionFileEnsure, ActionFileRollback, ActionSysctlEnsure} {
		if action.OnUnverified() != UnverifiedRollback {
			t.Errorf("%s: on_unverified %s, want rollback", action, action.OnUnverified())
		}
		if action.Contract().Rollback == RollbackNone {
			t.Errorf("%s: a rollback on unverified with no rollback class", action)
		}
	}
	for _, action := range []ActionType{ActionUnitRestart, ActionDiskWipe, ActionSystemReboot, ActionReadJournal, ActionType("nobody.wrote.this")} {
		if action.OnUnverified() != UnverifiedReport {
			t.Errorf("%s: on_unverified %s, want report", action, action.OnUnverified())
		}
	}
}

// A mutating operation that slipped into the table without a verifier
// fails the start with its name in the error, like an undeclared contract.
func TestAMutationWithoutAVerifierFailsTheStart(t *testing.T) {
	const stray ActionType = "test.stray.mutation"
	actionSpecs[stray] = actionSpec{mutating: true, permission: "test", timeoutSeconds: 1, risk: RiskLow}
	defer delete(actionSpecs, stray)
	err := ValidateVerifiers()
	if err == nil || !strings.Contains(err.Error(), string(stray)) {
		t.Fatalf("the stray mutation passed: %v", err)
	}
	actionSpecs[stray] = actionSpec{mutating: true, permission: "test", timeoutSeconds: 1, risk: RiskLow,
		verifier: Verifier("nobody.wrote.this")}
	if err := ValidateVerifiers(); err == nil || !strings.Contains(err.Error(), "not declared") {
		t.Fatalf("an unknown verifier passed: %v", err)
	}
}

// The codes of the verification are in the guide with the verify stage, so
// a job and a campaign host carrying them land on the operator's advice.
func TestTheGuideCoversTheVerificationCodes(t *testing.T) {
	for _, code := range []string{ErrorAppliedUnverified, ErrorRebootNotObserved} {
		guide, ok := ErrorGuideFor(code)
		if !ok {
			t.Errorf("%s has no guide", code)
			continue
		}
		if guide.Stage != "verify" || !guide.CountsAsFailure {
			t.Errorf("%s: stage %s, counts as failure %v", code, guide.Stage, guide.CountsAsFailure)
		}
	}
}
