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
