package campaigns

import "testing"

func TestARunningTargetSettlesTheStepItCarries(t *testing.T) {
	campaign := Campaign{State: StateRunning}
	cases := []struct {
		state TargetState
		step  StepKey
	}{
		{TargetPlanning, StepPlan},
		{TargetRunning, StepExecute},
		{TargetRebooting, StepReboot},
		{TargetVerifying, StepVerify},
	}
	for _, c := range cases {
		target := &Target{State: c.state}
		outcomes := settledOutcomes(campaign, target, TargetFailed, "boom", "it broke")
		if len(outcomes) != 1 || outcomes[0].Key != c.step {
			t.Fatalf("a target in %s settled %+v, expected its %s step", c.state, outcomes, c.step)
		}
		if outcomes[0].State != StepFailed || outcomes[0].Reason != "boom: it broke" {
			t.Errorf("a failed target closed its step as %+v", outcomes[0])
		}
	}
}

func TestAWaitingTargetRecordsTheStepItNeverReached(t *testing.T) {
	// A host skipped while waiting ran nothing; the step it was waiting for is
	// recorded as skipped so the reason has somewhere to live.
	target := &Target{State: TargetPending}
	planning := settledOutcomes(Campaign{State: StatePlanning}, target, TargetSkipped, "offline", "the host is offline")
	if len(planning) != 1 || planning[0].Key != StepPlan || planning[0].State != StepSkipped {
		t.Fatalf("a host skipped while planning recorded %+v", planning)
	}
	running := settledOutcomes(Campaign{State: StateRunning}, target, TargetSkipped, "maintenance", "")
	if len(running) != 1 || running[0].Key != StepExecute || running[0].Reason != "maintenance" {
		t.Fatalf("a host skipped while waiting for its wave recorded %+v", running)
	}
	// A waiting host settled as succeeded ran nothing: there is no step to
	// credit, and inventing one would claim work that never happened.
	if outcomes := settledOutcomes(Campaign{State: StateRunning}, target, TargetSucceeded, "", ""); len(outcomes) != 0 {
		t.Errorf("a waiting host settled as succeeded recorded %+v", outcomes)
	}
}

func TestAnIneligibleHostRanItsPlanToTheEnd(t *testing.T) {
	// The plan answered "no": that is an outcome of the plan step, not a
	// failure of the read, and the step says so with the reason.
	target := &Target{State: TargetPlanning}
	outcomes := settledOutcomes(Campaign{State: StatePlanning}, target, TargetIneligible, "plan_refused", "the rule cuts the management port")
	if len(outcomes) != 1 || outcomes[0].State != StepSucceeded {
		t.Fatalf("an ineligible host closed its plan step as %+v", outcomes)
	}
	if outcomes[0].Reason != "plan_refused: the rule cuts the management port" {
		t.Errorf("the refusal did not reach the step: %q", outcomes[0].Reason)
	}
}

func TestTheStepDependencyFollowsTheChain(t *testing.T) {
	if dependencyOf(StepPlan, true, false) != "" {
		t.Error("the plan depends on something")
	}
	if dependencyOf(StepExecute, true, false) != StepPlan {
		t.Error("a planned change does not follow the plan")
	}
	if dependencyOf(StepExecute, false, false) != "" {
		t.Error("a change without a planner follows a plan that does not exist")
	}
	if dependencyOf(StepReboot, true, false) != StepExecute {
		t.Error("the reboot does not follow the change")
	}
	if dependencyOf(StepVerify, true, true) != StepReboot {
		t.Error("the verification after a reboot does not follow the reboot")
	}
	if dependencyOf(StepVerify, true, false) != StepExecute {
		t.Error("the verification without a reboot does not follow the change")
	}
}

func TestAStepThatDidNotRunNeedsAReason(t *testing.T) {
	target := Target{ID: "t", CampaignID: "c", HostID: "h"}
	for _, state := range []StepState{StepFailed, StepSkipped, StepCanceled} {
		record := StepRecord{Target: target, Key: StepExecute, State: state}
		if err := record.validate(); err == nil {
			t.Errorf("a %s step without a reason was accepted", state)
		}
		record.Reason = "because"
		if err := record.validate(); err != nil {
			t.Errorf("a %s step with a reason was refused: %v", state, err)
		}
	}
	if err := (StepRecord{Target: target, Key: "deploy", State: StepRunning}).validate(); err == nil {
		t.Error("an unknown step kind was accepted")
	}
	if err := (StepRecord{Key: StepPlan, State: StepRunning}).validate(); err == nil {
		t.Error("a step without its target was accepted")
	}
}

func TestTheStepReasonKeepsTheCode(t *testing.T) {
	// The code alone names what happened; the message adds to it.
	if got := stepReason("offline", ""); got != "offline" {
		t.Errorf("a code without a message gave %q", got)
	}
	if got := stepReason("offline", "the host is offline"); got != "offline: the host is offline" {
		t.Errorf("a code with a message gave %q", got)
	}
	if got := stepReason("", "the plan holds"); got != "the plan holds" {
		t.Errorf("a message without a code gave %q", got)
	}
}
