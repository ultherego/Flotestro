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
// exists for: the consent is to concern exactly what the approver saw. Every
// change that shifts the risk has to invalidate it.
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

// TestAHostQueuedOfflineHoldsNeitherASlotNorItsWave guards the two things
// the offline queue exists for: such a host is not working, so it takes no
// concurrency slot, and it is not a verdict, so it does not keep its wave
// open - otherwise one unplugged machine would hold the fleet until the
// deadline.
func TestAHostQueuedOfflineHoldsNeitherASlotNorItsWave(t *testing.T) {
	if !TargetQueuedOffline.Waiting() {
		t.Error("a host queued offline should wait in the queue")
	}
	if TargetQueuedOffline.Finished() {
		t.Error("a host queued offline has not finished")
	}
	if TargetQueuedOffline.HoldsWave() {
		t.Error("a host queued offline holds its wave open")
	}
	for _, state := range []TargetState{TargetPending, TargetRunning, TargetAwaitingBudget, TargetPlanning} {
		if !state.HoldsWave() {
			t.Errorf("%s does not hold its wave open", state)
		}
	}
	if !(Target{State: TargetFailed, ErrorCode: ConnectivityLostCode}).ConnectivityLost() {
		t.Error("a failed host with an expired lease does not count as a lost connection")
	}
	if (Target{State: TargetFailed, ErrorCode: "exec_failed"}).ConnectivityLost() {
		t.Error("a failed change counts as a lost connection")
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

// TestTheRebootTimeoutIsBoundedAndDefaulted guards the reboot timeout
// field: zero is the default of fifteen minutes, so a campaign from before
// the field waits as it always did; anything else has to lie within the
// bounds, and a negative number is a mistake rather than an absence.
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

// TestACanaryHealthFailureCountsTowardsTheThreshold guards the mandatory
// scenario "canary health check negative, wave two stopped": a canary
// whose units did not come up after the change is a failure like any
// other, so the threshold that keeps the next wave from starting fires on
// it the same way it fires on a change that did not run.
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
