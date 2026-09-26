package campaigns

import "testing"

// TestPlanStepForCollectsAPlanItsTargetNeverMovedTo covers the one case that cost
// four gates: the plan was computed and its result written, the target was never
// moved to planning, and the pass ordered the plan again - for ever, under the same
// idempotency key, so the campaign neither finished nor failed.
func TestPlanStepForCollectsAPlanItsTargetNeverMovedTo(t *testing.T) {
	job := "06d63bea-28df-4fcd-80a1-0aa4df7d675d"
	for name, expected := range map[string]struct {
		target Target
		step   planStep
	}{
		"a fresh target is asked for its plan": {
			target: Target{State: TargetPending},
			step:   planOrder,
		},
		"a target that has a plan job is collected, whatever its state says": {
			target: Target{State: TargetPending, PlanJobID: &job},
			step:   planCollectUnmoved,
		},
		"a target in planning is collected": {
			target: Target{State: TargetPlanning, PlanJobID: &job},
			step:   planCollect,
		},
		"a target held for an absent host is looked at again": {
			target: Target{State: TargetQueuedOffline},
			step:   planRecheckOffline,
		},
		"a settled target is left alone": {
			target: Target{State: TargetSucceeded, PlanJobID: &job},
			step:   planNothing,
		},
	} {
		if step := planStepFor(expected.target); step != expected.step {
			t.Errorf("%s: step %d, expected %d", name, step, expected.step)
		}
	}
}
