package campaigns

import (
	"testing"

	"github.com/ultherego/flotestro/internal/jobs"
)

// A host whose engine answered and has no container of that name is skipped, and the
// reason travels with it; every other way a task fails stays a failure.
func TestAHostWithoutTheNamedContainerIsSkippedNotFailed(t *testing.T) {
	state, code := targetOutcome(jobVerdict{State: jobs.StateFailed, ErrorCode: ContainerNotFoundCode})
	if state != TargetSkipped || code != ContainerNotFoundCode {
		t.Fatalf("a host without the container ended as %s (%s)", state, code)
	}
	for _, other := range []string{"docker_engine_unreadable", "container_identity_mismatch", "exec_failed", ""} {
		if state, _ := targetOutcome(jobVerdict{State: jobs.StateFailed, ErrorCode: other}); state != TargetFailed {
			t.Errorf("a task that failed with %q ended as %s, want failed", other, state)
		}
	}
}

func TestACanaryThatExercisedNothingStopsTheWaves(t *testing.T) {
	campaign := Campaign{CanarySize: 1}
	absent := Target{Wave: 0, State: TargetSkipped, ErrorCode: ContainerNotFoundCode}
	done := Target{Wave: 0, State: TargetSucceeded}
	later := Target{Wave: 1, State: TargetPending}

	if !canaryExercisedNothing(campaign, []Target{absent, later}) {
		t.Error("a canary skipped for want of the container opened the waves")
	}
	if canaryExercisedNothing(campaign, []Target{absent, done, later}) {
		t.Error("a canary on which the change took place was held at the gate")
	}
	if canaryExercisedNothing(campaign, []Target{{Wave: 0, State: TargetFailed}, later}) {
		t.Error("a canary that failed was taken for one that exercised nothing; the threshold has it")
	}
	if canaryExercisedNothing(campaign, []Target{{Wave: 0, State: TargetSkipped, ErrorCode: "offline"}, later}) {
		t.Error("a canary skipped as offline was taken for one without the container")
	}
	if canaryExercisedNothing(Campaign{CanarySize: 0}, []Target{absent, later}) {
		t.Error("a campaign without a canary was held at a gate after it")
	}
}
