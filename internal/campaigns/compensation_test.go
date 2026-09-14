package campaigns

import (
	"strings"
	"testing"

	"github.com/ultherego/flotestro/internal/opspec"
)

// TestACompensationNeedsASettledOriginalAndItsDeclaredReverse guards the
// rules a compensation order is checked against: the original has to be
// finished, the operation has to be the registry's reverse of the
// original's, and every host has to be one the original changed. Each
// refusal carries its own code, because the panel acts on the code and the
// operator reads the sentence.
func TestACompensationNeedsASettledOriginalAndItsDeclaredReverse(t *testing.T) {
	original := Campaign{ID: "orig", Name: "rollout", ActionType: "file.ensure", State: StateCompleted}
	changed := []Target{{HostID: "host-a", State: TargetSucceeded}, {HostID: "host-b", State: TargetFailed}}

	if err := CheckCompensation(original, opspec.ActionFileRollback, changed, []string{"host-a", "host-b"}); err != nil {
		t.Fatalf("a rollback of the changed hosts of a completed campaign was refused: %v", err)
	}
	// A canceled campaign still changed the hosts that ran before the stop;
	// a failed one changed the hosts that succeeded. Both are settled.
	for _, state := range []State{StateFailed, StateCanceled} {
		settled := original
		settled.State = state
		if err := CheckCompensation(settled, opspec.ActionFileRollback, changed, []string{"host-a"}); err != nil {
			t.Errorf("a %s campaign cannot be compensated: %v", state, err)
		}
	}

	cases := []struct {
		name   string
		change func(*Campaign, *opspec.ActionType, *[]Target, *[]string)
		code   string
		words  string
	}{
		{"a running original", func(c *Campaign, _ *opspec.ActionType, _ *[]Target, _ *[]string) {
			c.State = StateRunning
		}, CodeCompensatedCampaignNotSettled, "is running"},
		// A paused campaign can be resumed: its set of changed hosts is not
		// final, and a compensation would race the change it undoes.
		{"a paused original", func(c *Campaign, _ *opspec.ActionType, _ *[]Target, _ *[]string) {
			c.State = StatePaused
		}, CodeCompensatedCampaignNotSettled, "is paused"},
		{"an operation that is not the reverse", func(_ *Campaign, a *opspec.ActionType, _ *[]Target, _ *[]string) {
			*a = opspec.ActionUnitRestart
		}, CodeNotReverseOperation, "not unit.restart"},
		{"an original with no declared reverse", func(c *Campaign, a *opspec.ActionType, _ *[]Target, _ *[]string) {
			c.ActionType = "unit.restart"
			*a = opspec.ActionUnitStop
		}, CodeNotReverseOperation, "declares no reverse"},
		{"an original that changed nothing", func(_ *Campaign, _ *opspec.ActionType, changed *[]Target, _ *[]string) {
			*changed = nil
		}, CodeNothingToCompensate, "nothing to compensate"},
		{"a host the original did not change", func(_ *Campaign, _ *opspec.ActionType, _ *[]Target, hosts *[]string) {
			*hosts = append(*hosts, "host-c")
		}, CodeCompensationTargetUnchanged, "host-c"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			campaign, action := original, opspec.ActionFileRollback
			targets := append([]Target(nil), changed...)
			hosts := []string{"host-a"}
			c.change(&campaign, &action, &targets, &hosts)
			err := CheckCompensation(campaign, action, targets, hosts)
			if err == nil {
				t.Fatal("the order passed")
			}
			if CompensationCode(err) != c.code {
				t.Errorf("the refusal carries the code %q, expected %q", CompensationCode(err), c.code)
			}
			if !strings.Contains(err.Error(), c.words) {
				t.Errorf("the reason %q does not say %q", err.Error(), c.words)
			}
		})
	}
	// The order and the code are two different things: an error that is not
	// a refusal has no code.
	if code := CompensationCode(ErrNotFound); code != "" {
		t.Errorf("a plain error carries the code %q", code)
	}
}

// TestTheCompensateStepEndsAsTheCompensatingHostDid guards the outcome
// written on the original's target: only a change that succeeded
// compensates, and every other end says why - the table refuses a step
// that did not run without a reason.
func TestTheCompensateStepEndsAsTheCompensatingHostDid(t *testing.T) {
	if state, reason := compensationOutcome(TargetSucceeded, "", ""); state != StepSucceeded || reason != "" {
		t.Errorf("a successful compensation closed the step as %s (%q)", state, reason)
	}
	if state, reason := compensationOutcome(TargetFailed, "plan_stale", "computed a day ago"); state != StepFailed ||
		reason != "plan_stale: computed a day ago" {
		t.Errorf("a failed compensation closed the step as %s (%q)", state, reason)
	}
	for _, target := range []TargetState{TargetSkipped, TargetCanceled, TargetFailed} {
		state, reason := compensationOutcome(target, "", "")
		if state == StepSucceeded || state.Open() {
			t.Errorf("a host that ended %s closed the compensate step as %s", target, state)
		}
		if reason == "" {
			t.Errorf("a host that ended %s closed the compensate step with no reason", target)
		}
	}
	if state, _ := compensationOutcome(TargetCanceled, "", ""); state != StepCanceled {
		t.Errorf("a canceled compensation closed the step as %s", state)
	}
}
