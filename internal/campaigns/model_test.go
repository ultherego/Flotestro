package campaigns

import (
	"encoding/json"
	"testing"
	"time"
)

func TestTheAbsoluteThresholdWorksFromTheFirstFailure(t *testing.T) {
	// The absolute threshold exists to stop a campaign before it damages many
	// hosts, so it does not wait for statistics.
	exceeded, reason := ThresholdExceeded(1, 1, 100, 0, 1)
	if !exceeded {
		t.Fatal("the absolute threshold of 1 did not stop the campaign after the first failure")
	}
	if reason == "" {
		t.Error("no description of the reason for stopping")
	}
	if exceeded, _ := ThresholdExceeded(1, 1, 100, 0, 2); exceeded {
		t.Error("the threshold of 2 stopped the campaign after one failure")
	}
}

func TestThePercentageThresholdDoesNotWorkWithoutData(t *testing.T) {
	// Without finished hosts there is nothing to compute the share from;
	// computing a percentage of zero would stop every campaign at the start.
	if exceeded, _ := ThresholdExceeded(0, 0, 50, 20, 0); exceeded {
		t.Fatal("the percentage threshold fired without finished hosts")
	}
}

func TestThePercentageThresholdCountsFromTheFinishedOnes(t *testing.T) {
	// 2 failures out of 10 finished is 20%, so a threshold of 20% is reached
	// even though the campaign has 100 targets.
	exceeded, _ := ThresholdExceeded(2, 10, 100, 20, 0)
	if !exceeded {
		t.Fatal("the threshold of 20% did not fire at 2 failures out of 10 finished")
	}
	// The same result counted against the whole would be 2%, so the campaign
	// would roll on even though every fifth host had failed.
	if exceeded, _ := ThresholdExceeded(1, 10, 100, 20, 0); exceeded {
		t.Error("the threshold of 20% fired at 10% of failures")
	}
}

func TestTheMaintenanceWindowLimitsTheTime(t *testing.T) {
	base := time.Date(2026, 8, 22, 12, 0, 0, 0, time.UTC)
	start := base.Add(time.Hour)
	end := base.Add(2 * time.Hour)

	if WithinMaintenanceWindow(base, &start, &end) {
		t.Error("the campaign started before the maintenance window")
	}
	if !WithinMaintenanceWindow(base.Add(90*time.Minute), &start, &end) {
		t.Error("the campaign did not start inside the maintenance window")
	}
	if WithinMaintenanceWindow(base.Add(3*time.Hour), &start, &end) {
		t.Error("the campaign ran after the window closed")
	}
	// No window means no limitation.
	if !WithinMaintenanceWindow(base, nil, nil) {
		t.Error("the absence of a window blocked the campaign")
	}
}

func TestTheCampaignStateTellsActivityFromTheEnd(t *testing.T) {
	for _, state := range []State{StateCanary, StateRunning} {
		if !state.Active() {
			t.Errorf("%s should be an active state", state)
		}
		if state.Terminal() {
			t.Errorf("%s is not a final state", state)
		}
	}
	// A paused campaign is not active, but it is not finished either: it
	// waits for a human decision.
	if StatePaused.Active() || StatePaused.Terminal() {
		t.Error("the paused state is classified wrongly")
	}
	for _, state := range []State{StateCompleted, StateFailed, StateCanceled} {
		if !state.Terminal() || state.Active() {
			t.Errorf("%s should be a final state", state)
		}
	}
}

func TestTheTargetStateTellsTheEndApart(t *testing.T) {
	for _, state := range []TargetState{TargetSucceeded, TargetFailed, TargetSkipped, TargetCanceled} {
		if !state.Finished() {
			t.Errorf("%s should end the host's participation", state)
		}
	}
	for _, state := range []TargetState{TargetPending, TargetRunning, TargetRebooting, TargetVerifying} {
		if state.Finished() {
			t.Errorf("%s does not end the host's participation", state)
		}
	}
}

func TestSpecValidation(t *testing.T) {
	valid := Spec{Name: "test", WaveSize: 10, MaxConcurrent: 5, RebootPolicy: RebootNever}
	if err := valid.Validate(); err != nil {
		t.Fatalf("a valid description was rejected: %v", err)
	}

	cases := map[string]func(*Spec){
		"no name":              func(s *Spec) { s.Name = "" },
		"zero wave":            func(s *Spec) { s.WaveSize = 0 },
		"zero concurrency":     func(s *Spec) { s.MaxConcurrent = 0 },
		"negative canary":      func(s *Spec) { s.CanarySize = -1 },
		"threshold above 100%": func(s *Spec) { s.FailureThresholdPercent = 101 },
		"unknown policy":       func(s *Spec) { s.RebootPolicy = "sometimes" },
	}
	for name, mutate := range cases {
		t.Run(name, func(t *testing.T) {
			spec := valid
			mutate(&spec)
			if err := spec.Validate(); err == nil {
				t.Fatal("an invalid description passed validation")
			}
		})
	}

	t.Run("reversed maintenance window", func(t *testing.T) {
		spec := valid
		start := time.Now().Add(time.Hour)
		end := time.Now()
		spec.MaintenanceStart, spec.MaintenanceEnd = &start, &end
		if err := spec.Validate(); err == nil {
			t.Fatal("a window ending before it starts passed validation")
		}
	})
}

// TestTheFingerprintChangesWithEveryDecision guards what the fingerprint
// exists for: the consent is to concern exactly what the approver saw.
func TestTheFingerprintChangesWithEveryDecision(t *testing.T) {
	base := Spec{
		Name: "restart", ActionType: "unit.restart",
		Payload:       json.RawMessage(`{"unit":{"unit":"cron.service"}}`),
		CanarySize:    1,
		WaveSize:      5,
		MaxConcurrent: 2, FailureThresholdPercent: 20, RebootPolicy: RebootNever,
	}
	hosts := []TargetHost{{ID: "host-b"}, {ID: "host-a"}}

	fingerprint, err := Fingerprint(base, hosts)
	if err != nil {
		t.Fatalf("fingerprint: %v", err)
	}
	if fingerprint == "" {
		t.Fatal("empty fingerprint")
	}

	// The order of the hosts in the snapshot is not a decision.
	reordered, err := Fingerprint(base, []TargetHost{{ID: "host-a"}, {ID: "host-b"}})
	if err != nil {
		t.Fatal(err)
	}
	if reordered != fingerprint {
		t.Error("the order of the hosts changed the fingerprint")
	}

	changes := map[string]func(*Spec, *[]TargetHost){
		"another host": func(_ *Spec, hosts *[]TargetHost) {
			*hosts = append(*hosts, TargetHost{ID: "host-c"})
		},
		"another payload": func(s *Spec, _ *[]TargetHost) {
			s.Payload = json.RawMessage(`{"unit":{"unit":"ssh.service"}}`)
		},
		"another operation":  func(s *Spec, _ *[]TargetHost) { s.ActionType = "unit.stop" },
		"more concurrency":   func(s *Spec, _ *[]TargetHost) { s.MaxConcurrent = 50 },
		"a larger wave":      func(s *Spec, _ *[]TargetHost) { s.WaveSize = 500 },
		"no canary":          func(s *Spec, _ *[]TargetHost) { s.CanarySize = 0 },
		"a higher threshold": func(s *Spec, _ *[]TargetHost) { s.FailureThresholdPercent = 100 },
		"rebooting hosts":    func(s *Spec, _ *[]TargetHost) { s.RebootPolicy = RebootAlways },
		// How long a rebooted host is waited for is part of the risk: a
		// longer wait is a longer outage nobody is told about.
		"a longer reboot wait": func(s *Spec, _ *[]TargetHost) { s.RebootTimeoutSeconds = 3600 },
		// Undoing a named campaign is a different decision from the same
		// change ordered on its own.
		"compensating a campaign": func(s *Spec, _ *[]TargetHost) { s.CompensatesCampaignID = "orig" },
	}
	for name, change := range changes {
		t.Run(name, func(t *testing.T) {
			changed := base
			targets := append([]TargetHost(nil), hosts...)
			change(&changed, &targets)
			other, err := Fingerprint(changed, targets)
			if err != nil {
				t.Fatal(err)
			}
			if other == fingerprint {
				t.Error("the change did not invalidate the approval fingerprint")
			}
		})
	}
}

// TestAHostQueuedOfflineHoldsNeitherASlotNorItsWave guards the two things the
// offline queue exists for: the host takes no slot and holds no wave open.
func TestAHostQueuedOfflineHoldsNeitherASlotNorItsWave(t *testing.T) {
	if !TargetQueuedOffline.Waiting() {
		t.Error("a host queued offline should wait in the queue")
	}
	if TargetQueuedOffline.Finished() {
		t.Error("a host queued offline has not finished")
	}
	if (Target{State: TargetQueuedOffline, Wave: 1}).HoldsWave() {
		t.Error("a host queued offline in a wave holds the wave open")
	}
	if !(Target{State: TargetQueuedOffline, Wave: 0}).HoldsWave() {
		t.Error("an offline canary does not hold the barrier")
	}
	if (Target{State: TargetSkipped, Wave: 0, ErrorCode: SkippedByOperatorCode}).HoldsWave() {
		t.Error("a canary skipped by the operator still holds the barrier")
	}
	for _, state := range []TargetState{TargetPending, TargetRunning, TargetAwaitingBudget, TargetPlanning} {
		if !(Target{State: state, Wave: 1}).HoldsWave() {
			t.Errorf("%s does not hold its wave open", state)
		}
	}
	// A broken session ends the host unknown, and the code says which
	// kind of unknown; a failed change is neither.
	if !(Target{State: TargetUnknown, ErrorCode: ConnectivityLostCode}).ConnectivityLost() {
		t.Error("an unknown host with an expired lease does not count as a lost connection")
	}
	if (Target{State: TargetFailed, ErrorCode: "exec_failed"}).ConnectivityLost() {
		t.Error("a failed change counts as a lost connection")
	}
	if (Target{State: TargetUnknown, ErrorCode: OutcomeUnknownCode}).ConnectivityLost() {
		t.Error("an agent restart counts as a lost connection")
	}
}

// TestTheNewStatesKnowTheirPlace guards the predicates: the in-flight states
// hold their slot and their wave, the terminal ones end the host.
func TestTheNewStatesKnowTheirPlace(t *testing.T) {
	for _, state := range []TargetState{TargetDispatched, TargetAwaitingLock} {
		if state.Finished() || state.Waiting() {
			t.Errorf("%s is neither finished nor waiting in the queue", state)
		}
		if !(Target{State: state, Wave: 1}).HoldsWave() || !state.UnderWay() {
			t.Errorf("%s holds its wave and carries a task", state)
		}
	}
	for _, state := range []TargetState{TargetNoChange, TargetUnknown} {
		if !state.Finished() || state.UnderWay() || (Target{State: state, Wave: 1}).HoldsWave() {
			t.Errorf("%s ends the host's participation", state)
		}
	}
	if !TargetNoChange.Succeeded() || TargetUnknown.Succeeded() {
		t.Error("no change is a success and unknown is not")
	}
	if !TargetSucceeded.Succeeded() || TargetSkipped.Succeeded() {
		t.Error("succeeded is a success and skipped is not")
	}
	for _, state := range []State{StateCompletedWithIssues, StatePlanFailed, StateExpired} {
		if !state.Terminal() || state.Active() {
			t.Errorf("%s should be a final state", state)
		}
	}
	// Canceling is neither active - nothing starts - nor final: hosts are
	// still at work, and a compensation is refused until they settle.
	if StateCanceling.Terminal() || StateCanceling.Active() {
		t.Error("canceling is classified wrongly")
	}
}

// TestTheTallyCountsUnknownAsAFailure guards the document's rule that unknown
// is not a success: the threshold reads it the way it reads a failed host.
func TestTheTallyCountsUnknownAsAFailure(t *testing.T) {
	targets := []Target{
		{State: TargetSucceeded},
		{State: TargetNoChange},
		{State: TargetFailed, ErrorCode: "exec_failed"},
		{State: TargetUnknown, ErrorCode: ConnectivityLostCode},
		{State: TargetUnknown, ErrorCode: OutcomeUnknownCode},
		{State: TargetSkipped, ErrorCode: "maintenance"},
		{State: TargetIneligible, ErrorCode: "plan_refused"},
		{State: TargetRunning},
	}
	counts := tallyTargets(targets)
	want := targetTally{Total: 8, Finished: 7, Succeeded: 2, Failed: 3, Unknown: 2, Skipped: 1, Lost: 1}
	if counts != want {
		t.Fatalf("tally = %+v, expected %+v", counts, want)
	}
	// Three of seven finished did not reach the desired state: 42 %, so a
	// threshold of 40 % fires - and would not if the unknown ones were left out
	// of the count.
	if exceeded, _ := ThresholdExceeded(counts.Failed, counts.Finished, counts.Total, 40, 0); !exceeded {
		t.Error("two unknown hosts and one failure did not cross a 40 % threshold")
	}
}

// TestTheVerdictOnASettledCampaign guards the three ways a campaign ends once
// every host has settled: completed, completed with issues, and failed.
func TestTheVerdictOnASettledCampaign(t *testing.T) {
	cases := []struct {
		name   string
		counts targetTally
		want   State
	}{
		{"every host succeeded", targetTally{Total: 3, Finished: 3, Succeeded: 3}, StateCompleted},
		{"nothing to change anywhere", targetTally{Total: 2, Finished: 2, Succeeded: 2}, StateCompleted},
		{"an ineligible host is no blemish", targetTally{Total: 3, Finished: 3, Succeeded: 2}, StateCompleted},
		{"one host failed under the threshold", targetTally{Total: 4, Finished: 4, Succeeded: 3, Failed: 1}, StateCompletedWithIssues},
		{"one host ended unknown", targetTally{Total: 4, Finished: 4, Succeeded: 3, Failed: 1, Unknown: 1}, StateCompletedWithIssues},
		{"one host was skipped", targetTally{Total: 4, Finished: 4, Succeeded: 3, Skipped: 1}, StateCompleted},
		{"the only host was skipped", targetTally{Total: 1, Finished: 1, Skipped: 1}, StateCompleted},
		{"every host that ran failed", targetTally{Total: 3, Finished: 3, Failed: 3}, StateFailed},
		{"the only host ended unknown", targetTally{Total: 1, Finished: 1, Failed: 1, Unknown: 1}, StateFailed},
		{"failures next to skips and nothing through", targetTally{Total: 3, Finished: 3, Failed: 1, Skipped: 2}, StateFailed},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := settleCampaignState(tc.counts); got != tc.want {
				t.Errorf("verdict = %s, expected %s", got, tc.want)
			}
		})
	}
}

// TestACancelWaitsForTheHostsUnderWay guards the canceling state: a cancel
// with hosts still carrying a task is not over, whatever stage of the task
// they are at, and is over once none does - hosts settled any way at all.
func TestACancelWaitsForTheHostsUnderWay(t *testing.T) {
	for _, state := range []TargetState{TargetDispatched, TargetAwaitingLock, TargetRunning, TargetRebooting, TargetVerifying} {
		targets := []Target{{State: TargetCanceled}, {State: state}, {State: TargetSucceeded}}
		if cancelSettled(targets) {
			t.Errorf("a cancel settled with a host %s", state)
		}
	}
	settled := []Target{{State: TargetCanceled}, {State: TargetSucceeded}, {State: TargetFailed},
		{State: TargetUnknown}, {State: TargetNoChange}, {State: TargetSkipped}}
	if !cancelSettled(settled) {
		t.Error("a cancel with every host settled did not end")
	}
	if !cancelSettled(nil) {
		t.Error("a cancel with no hosts did not end")
	}
}

// TestPlansExpireOnlyBeforeTheStart guards the expiry: a campaign whose oldest
// plan passed the limit expires while nothing has started, not once a host has.
func TestPlansExpireOnlyBeforeTheStart(t *testing.T) {
	computed := time.Date(2026, 9, 13, 10, 0, 0, 0, time.UTC)
	if plansExpired(computed, nil, computed.Add(PlanTTL-time.Minute)) {
		t.Error("plans inside the limit expired")
	}
	if !plansExpired(computed, nil, computed.Add(PlanTTL+time.Minute)) {
		t.Error("plans past the limit did not expire before the start")
	}
	started := computed.Add(time.Hour)
	if plansExpired(computed, &started, computed.Add(PlanTTL+time.Hour)) {
		t.Error("a campaign that started expired as a whole")
	}
	if plansExpired(time.Time{}, nil, computed.Add(48*time.Hour)) {
		t.Error("a campaign without plans expired")
	}
}

// TestTheGateAndTheOfflinePolicyAreValidated guards the rules of the new
// rollout fields: a gate needs a canary, a policy has to be one the registry
// knows, and the bounds cannot be negative.
func TestTheGateAndTheOfflinePolicyAreValidated(t *testing.T) {
	valid := Spec{Name: "test", CanarySize: 1, WaveSize: 10, MaxConcurrent: 5,
		RebootPolicy: RebootNever, ManualGate: true, OfflinePolicy: "wait_until_deadline",
		DeadlineMinutes: 60, ConnectivityLostAbsolute: 1}
	if err := valid.Validate(); err != nil {
		t.Fatalf("a valid description was rejected: %v", err)
	}
	if valid.Deadline() != time.Hour {
		t.Errorf("deadline = %s, expected an hour", valid.Deadline())
	}
	if (Spec{}).Deadline() != DefaultDeadline {
		t.Error("a missing deadline is not the default one")
	}
	cases := map[string]func(*Spec){
		"a gate without a canary":   func(s *Spec) { s.CanarySize = 0 },
		"an unknown offline policy": func(s *Spec) { s.OfflinePolicy = "sometimes" },
		"a negative deadline":       func(s *Spec) { s.DeadlineMinutes = -1 },
		"a negative loss threshold": func(s *Spec) { s.ConnectivityLostAbsolute = -1 },
	}
	for name, mutate := range cases {
		t.Run(name, func(t *testing.T) {
			spec := valid
			mutate(&spec)
			if err := spec.Validate(); err == nil {
				t.Fatal("an invalid description passed validation")
			}
		})
	}
}

// TestTheRebootTimeoutIsBoundedAndDefaulted guards the reboot timeout field:
// zero is the default of fifteen minutes, anything else lies within the bounds.
func TestTheRebootTimeoutIsBoundedAndDefaulted(t *testing.T) {
	valid := Spec{Name: "test", WaveSize: 10, MaxConcurrent: 5, RebootPolicy: RebootNever}
	if valid.RebootTimeout() != DefaultRebootTimeout {
		t.Errorf("a missing reboot timeout is %s, expected %s", valid.RebootTimeout(), DefaultRebootTimeout)
	}
	if (Campaign{}).RebootTimeout() != DefaultRebootTimeout {
		t.Error("a campaign without the field does not wait the default")
	}
	if (Campaign{RebootTimeoutSeconds: 120}).RebootTimeout() != 2*time.Minute {
		t.Error("the campaign does not wait what was recorded")
	}
	for _, seconds := range []int{60, 900, 7200} {
		spec := valid
		spec.RebootTimeoutSeconds = seconds
		if err := spec.Validate(); err != nil {
			t.Errorf("a reboot timeout of %d seconds was rejected: %v", seconds, err)
		}
		if spec.RebootTimeout() != time.Duration(seconds)*time.Second {
			t.Errorf("a reboot timeout of %d seconds became %s", seconds, spec.RebootTimeout())
		}
	}
	for _, seconds := range []int{-1, 1, 59, 7201} {
		spec := valid
		spec.RebootTimeoutSeconds = seconds
		if err := spec.Validate(); err == nil {
			t.Errorf("a reboot timeout of %d seconds passed validation", seconds)
		}
	}
}

// TestACanaryHealthFailureCountsTowardsTheThreshold guards the scenario
// "canary health check negative": a failed canary counts towards the threshold.
func TestACanaryHealthFailureCountsTowardsTheThreshold(t *testing.T) {
	targets := []Target{
		{Wave: 0, State: TargetFailed, ErrorCode: "health_check_failed"},
		{Wave: 1, State: TargetPending},
		{Wave: 1, State: TargetPending},
	}
	counts := tallyTargets(targets)
	if counts.Failed != 1 || counts.Finished != 1 || counts.Lost != 0 {
		t.Fatalf("tally = %+v, expected one finished host that failed", counts)
	}
	// The default threshold of the API is twenty percent: one failed out of
	// one finished is a hundred, and the campaign pauses before wave one.
	if exceeded, _ := ThresholdExceeded(counts.Failed, counts.Finished, len(targets), 20, 0); !exceeded {
		t.Error("a failed canary health check did not cross the threshold before the next wave")
	}
	if exceeded, _ := ThresholdExceeded(counts.Failed, counts.Finished, len(targets), 0, 1); !exceeded {
		t.Error("a failed canary health check did not count towards the absolute threshold")
	}
	// A host closed because the window ended mid-reboot is a failure too.
	if !(Target{State: TargetFailed, ErrorCode: RebootWindowClosedCode}).RebootWindowClosed() {
		t.Error("a host failed with reboot_window_closed is not recognised")
	}
	if (Target{State: TargetSucceeded, ErrorCode: RebootWindowClosedCode}).RebootWindowClosed() {
		t.Error("a succeeded host counts as closed by the window")
	}
}

// TestTheBarrierWaitsForAnOfflineCanaryUntilItIsSkipped: with a host of the
// canary offline wave one does not open, and it opens once that host is skipped.
func TestTheBarrierWaitsForAnOfflineCanaryUntilItIsSkipped(t *testing.T) {
	targets := []Target{
		{HostID: "a", Wave: 0, State: TargetSucceeded},
		{HostID: "b", Wave: 0, State: TargetQueuedOffline},
		{HostID: "c", Wave: 1, State: TargetPending},
		{HostID: "d", Wave: 1, State: TargetQueuedOffline},
	}
	if wave := currentWave(targets); wave != 0 {
		t.Fatalf("the current wave is %d with the canary offline, expected 0", wave)
	}
	if waveFinished(targets, 0) {
		t.Fatal("the canary reads as finished with a host of it offline")
	}
	targets[1].State = TargetSkipped
	targets[1].ErrorCode = SkippedByOperatorCode
	if !waveFinished(targets, 0) {
		t.Fatal("the canary does not read as finished after the offline host was skipped")
	}
	if wave := currentWave(targets); wave != 1 {
		t.Fatalf("the current wave is %d after the skip, expected 1", wave)
	}
	// The offline host of wave one holds nothing: with c settled the
	// wave is finished over it.
	targets[2].State = TargetSucceeded
	if !waveFinished(targets, 1) {
		t.Fatal("an offline host of a wave holds the wave open")
	}
}

// TestTheConcurrencyLimitCountsEveryWave guards max_concurrent as the document
// reads it: the hosts in flight across the whole campaign, not the hosts of
// the wave the scheduler is looking at.
func TestTheConcurrencyLimitCountsEveryWave(t *testing.T) {
	targets := []Target{
		{Wave: 0, State: TargetRunning},
		{Wave: 0, State: TargetSucceeded},
		{Wave: 1, State: TargetDispatched},
		{Wave: 1, State: TargetAwaitingLock},
		{Wave: 1, State: TargetAwaitingBudget},
		{Wave: 2, State: TargetRebooting},
		{Wave: 2, State: TargetPending},
		{Wave: 2, State: TargetQueuedOffline},
	}
	if active := activeTargets(targets); active != 4 {
		t.Fatalf("%d hosts hold a slot, expected 4: the running canary, the dispatched and the locked host of wave one, the rebooting host of wave two", active)
	}
}

// TestALateSuccessDoesNotResurrectACanceledCampaign guards the settle path
// after a cancel: a settled host never moves, and neither does the campaign.
func TestALateSuccessDoesNotResurrectACanceledCampaign(t *testing.T) {
	for _, to := range []TargetState{TargetSucceeded, TargetNoChange, TargetRunning, TargetVerifying} {
		if TargetCanceled.mayBecome(to) {
			t.Errorf("a canceled host may become %s on a late result", to)
		}
	}
	for _, from := range []State{StateCanceled, StateCanceling} {
		for _, to := range []State{StateRunning, StateCanary, StateCompleted, StateCompletedWithIssues} {
			if from.mayBecome(to) {
				t.Errorf("a %s campaign may become %s", from, to)
			}
		}
	}
	// The campaign's own drain reads the hosts: a host whose cancel request is
	// answered as not interruptible is still under way and holds the campaign in
	// canceling; one answered as not started is canceled and holds nothing.
	targets := []Target{{State: TargetRunning, CancelRequestedAt: new(time.Time)}}
	if cancelSettled(targets) {
		t.Fatal("a host running to its end after a cancel request reads as settled")
	}
	targets[0].State = TargetCanceled
	if !cancelSettled(targets) {
		t.Fatal("a host canceled on the agent's word holds the campaign in canceling")
	}
}
