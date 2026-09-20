package agent

import (
	"testing"
	"time"
)

// The agent hands its free pages back after a task, and not after every task:
// the collection that returns them is not free. The interval is the ordinary
// case; close to the budget it becomes a floor instead, because a process
// sitting at its ceiling for half a minute is what a fleet-wide budget is
// measured against.
func TestHowSoonAFinishedTaskHandsThePagesBack(t *testing.T) {
	cases := []struct {
		name string
		rss  uint64
		want time.Duration
	}{
		{"just over the threshold", releaseThreshold, taskReleaseEvery},
		{"between the two marks", releaseThreshold + (releaseUrgent-releaseThreshold)/2, taskReleaseEvery},
		{"one byte below urgent", releaseUrgent - 1, taskReleaseEvery},
		{"at the urgent mark", releaseUrgent, taskReleaseFloor},
		{"well past it", releaseUrgent * 2, taskReleaseFloor},
	}
	for _, test := range cases {
		if got := releaseInterval(test.rss); got != test.want {
			t.Errorf("%s (%d bytes): waits %s, want %s", test.name, test.rss, got, test.want)
		}
	}
}

// The marks have to stand in this order, or the urgent case is unreachable
// and the floor never applies - which is exactly the fault it was added for.
func TestTheReleaseMarksStandInOrder(t *testing.T) {
	if releaseThreshold >= releaseUrgent {
		t.Fatalf("the urgent mark %d is not above the threshold %d", releaseUrgent, releaseThreshold)
	}
	if taskReleaseFloor >= taskReleaseEvery {
		t.Fatalf("the floor %s is not shorter than the interval %s", taskReleaseFloor, taskReleaseEvery)
	}
	// Both marks belong under the budget the fleet test holds the agent to,
	// or the agent would only start giving pages back once it had already
	// broken it.
	const fleetBudget = 30 << 20
	if releaseUrgent >= fleetBudget {
		t.Errorf("the urgent mark %d is not below the fleet budget %d", releaseUrgent, fleetBudget)
	}
}
