package remediation

import (
	"slices"
	"testing"
)

// A plan with nothing left to run is not a plan that succeeded. With
// stop_on_failure off the steps after a failure are carried out and the
// failure stays where it was, so the end of the plan has to say so - the
// runner used to settle it as succeeded and start the path that follows a
// success.
func TestFailedNamesTheStepsThatDidNotGoThrough(t *testing.T) {
	plan := Plan{Steps: []Step{
		{CheckID: "ssh-root-login", State: StepSucceeded},
		{CheckID: "sudo-nopasswd", State: StepFailed},
		{CheckID: "firewall-default-drop", State: StepSucceeded},
		{CheckID: "kernel-dmesg", State: StepFailed},
	}}
	if plan.Current() != nil {
		t.Fatal("a plan with every step settled still named one to run")
	}
	failed := plan.Failed()
	if want := []string{"sudo-nopasswd", "kernel-dmesg"}; !slices.Equal(failed, want) {
		t.Errorf("Failed() = %v, want %v", failed, want)
	}
}

// A plan whose every step went through has nothing to report, and the state
// that follows is the plain success. A check that reported a failure here
// would turn every remediation into a partial one.
func TestAPlanWhereEveryStepWentThroughNamesNoFailure(t *testing.T) {
	plan := Plan{Steps: []Step{
		{CheckID: "ssh-root-login", State: StepSucceeded},
		{CheckID: "sudo-nopasswd", State: StepSkipped},
	}}
	if failed := plan.Failed(); len(failed) != 0 {
		t.Errorf("Failed() = %v over a plan that failed nothing", failed)
	}
}

// The fifth state has to be one the database accepts: the column carries a
// check constraint, and a state outside it is refused at the write, which the
// runner would then retry for ever. Migration 0138 extends it.
func TestThePartialStateIsNotTheSameAsAnyOther(t *testing.T) {
	for _, other := range []string{StateRunning, StateSucceeded, StateFailed, StateStopped} {
		if StatePartial == other {
			t.Fatalf("StatePartial collides with %q", other)
		}
	}
}
