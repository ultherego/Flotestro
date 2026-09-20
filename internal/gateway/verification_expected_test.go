package gateway

import (
	"testing"

	"github.com/ultherego/flotestro/internal/opspec"
)

// The panel stores the host's reading as it comes and used to require none,
// so a mutating success that arrived without one was recorded as a success.
// The agent always sends the block for these operations, which is why its
// absence is worth refusing: it means the read never happened or the block
// was lost on the way.
func TestWhichOperationsOweAReadOfTheHost(t *testing.T) {
	owes := []opspec.ActionType{
		opspec.ActionUnitRestart,
		opspec.ActionUnitStart,
		opspec.ActionPackageInstall,
		opspec.ActionFileEnsure,
	}
	for _, action := range owes {
		if !verificationExpected(action) {
			t.Errorf("%s changes the host and owes a reading of it", action)
		}
	}

	// A read is its own observation, and a restart is settled when the host
	// comes back with a different boot identifier rather than by anything the
	// result carries.
	exempt := []opspec.ActionType{
		opspec.ActionUnitStatus,
		opspec.ActionSystemReboot,
	}
	for _, action := range exempt {
		if verificationExpected(action) {
			t.Errorf("%s owes no reading and must not be held to one", action)
		}
	}
}

// Every mutating operation declares a verifier - a contract test in opspec
// enforces that - so this must hold for all of them at once rather than for
// the handful named above.
func TestEveryMutatingOperationOwesAReadingUnlessThePanelSettlesIt(t *testing.T) {
	for _, action := range opspec.AllActions() {
		if !action.Mutating() {
			if verificationExpected(action) {
				t.Errorf("%s changes nothing and must owe no reading", action)
			}
			continue
		}
		verifier := action.Verifier()
		want := verifier != opspec.VerifierNone && !verifier.PanelSettled()
		if got := verificationExpected(action); got != want {
			t.Errorf("%s: owes a reading = %v, want %v (verifier %q)", action, got, want, verifier)
		}
	}
}
