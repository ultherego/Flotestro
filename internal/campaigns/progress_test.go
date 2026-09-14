package campaigns

import (
	"strings"
	"testing"
	"time"
)

// TestTheRebootJudgementFollowsTheWindowThenTheTimeout guards the
// mandatory scenario "the host does not come back within the maintenance
// window": a host still away when the window ends is closed with the
// window as the reason, whatever the timeout says; without a window, or
// inside it, the campaign's own timeout decides; and until either passes
// the host is waited for.
func TestTheRebootJudgementFollowsTheWindowThenTheTimeout(t *testing.T) {
	ordered := time.Date(2026, 9, 14, 22, 50, 0, 0, time.UTC)
	windowEnd := ordered.Add(10 * time.Minute)
	timeout := 15 * time.Minute

	t.Run("waited for inside the window and the timeout", func(t *testing.T) {
		verdict := judgeReboot(ordered, &windowEnd, timeout, ordered.Add(5*time.Minute))
		if !verdict.Waiting {
			t.Fatalf("the host was closed with %s: %s", verdict.Code, verdict.Message)
		}
	})

	t.Run("closed by the window before the timeout", func(t *testing.T) {
		now := ordered.Add(11 * time.Minute)
		verdict := judgeReboot(ordered, &windowEnd, timeout, now)
		if verdict.Waiting || verdict.Code != RebootWindowClosedCode {
			t.Fatalf("verdict = %+v, expected %s", verdict, RebootWindowClosedCode)
		}
		// The message names the window end and how long the host has
		// been away: the two facts the operator judges the host by.
		if !strings.Contains(verdict.Message, windowEnd.Format(time.RFC3339)) {
			t.Errorf("the message does not name the window end: %s", verdict.Message)
		}
		if !strings.Contains(verdict.Message, "11m0s") {
			t.Errorf("the message does not say how long the host has been away: %s", verdict.Message)
		}
	})

	t.Run("the window wins even once the timeout has passed", func(t *testing.T) {
		verdict := judgeReboot(ordered, &windowEnd, timeout, ordered.Add(time.Hour))
		if verdict.Code != RebootWindowClosedCode {
			t.Fatalf("verdict = %+v, expected the window to be named", verdict)
		}
	})

	t.Run("the timeout decides without a window", func(t *testing.T) {
		if verdict := judgeReboot(ordered, nil, timeout, ordered.Add(14*time.Minute)); !verdict.Waiting {
			t.Fatalf("the host was closed before the timeout: %+v", verdict)
		}
		verdict := judgeReboot(ordered, nil, timeout, ordered.Add(16*time.Minute))
		if verdict.Waiting || verdict.Code != "reboot_timeout" {
			t.Fatalf("verdict = %+v, expected reboot_timeout", verdict)
		}
		if !strings.Contains(verdict.Message, "15m0s") {
			t.Errorf("the message does not name the timeout: %s", verdict.Message)
		}
	})

	t.Run("the timeout decides inside a window that is still open", func(t *testing.T) {
		farEnd := ordered.Add(3 * time.Hour)
		verdict := judgeReboot(ordered, &farEnd, timeout, ordered.Add(16*time.Minute))
		if verdict.Code != "reboot_timeout" {
			t.Fatalf("verdict = %+v, expected reboot_timeout", verdict)
		}
	})

	t.Run("the campaign's own timeout is the one applied", func(t *testing.T) {
		verdict := judgeReboot(ordered, nil, time.Hour, ordered.Add(30*time.Minute))
		if !verdict.Waiting {
			t.Fatalf("a wait of an hour closed the host after thirty minutes: %+v", verdict)
		}
	})
}

// TestTheWaitForARebootIsCountedFromTheReboot guards the moment the wait
// starts from: the last transition of the target, not the start of its
// change. A change that took half an hour must not fail the host the
// moment its reboot is ordered.
func TestTheWaitForARebootIsCountedFromTheReboot(t *testing.T) {
	started := time.Date(2026, 9, 14, 22, 0, 0, 0, time.UTC)
	rebooted := started.Add(30 * time.Minute)

	since, known := rebootOrderedAt(&Target{StartedAt: &started, StateSince: &rebooted})
	if !known || !since.Equal(rebooted) {
		t.Errorf("the wait is counted from %s, expected the reboot at %s", since, rebooted)
	}
	// A target read without its transition time falls back to the start of
	// the change: a bound counted from too early beats no bound at all.
	since, known = rebootOrderedAt(&Target{StartedAt: &started})
	if !known || !since.Equal(started) {
		t.Errorf("without a transition time the wait is counted from %s, expected %s", since, started)
	}
	if _, known := rebootOrderedAt(&Target{}); known {
		t.Error("a target without any time was judged")
	}
}
