package campaigns

import (
	"testing"
)

// TestARetryTakesTheFailedHostsOfAFinishedCampaign guards the rules a
// retry order is checked against: the campaign has to be finished, the
// failed hosts are taken, the unknown ones only on request, and the hosts
// that succeeded or took no part are never run again. Each refusal
// carries its own code, because the panel acts on the code and the
// operator reads the sentence.
func TestARetryTakesTheFailedHostsOfAFinishedCampaign(t *testing.T) {
	original := Campaign{ID: "orig", Name: "rollout", ActionType: "unit.restart", State: StateCompletedWithIssues}
	targets := []Target{
		{HostID: "host-a", State: TargetSucceeded},
		{HostID: "host-b", State: TargetFailed},
		{HostID: "host-c", State: TargetUnknown},
		{HostID: "host-d", State: TargetSkipped},
		{HostID: "host-e", State: TargetCanceled},
		{HostID: "host-f", State: TargetNoChange},
		{HostID: "host-g", State: TargetFailed},
	}

	picked, err := RetryTargets(original, targets, false)
	if err != nil {
		t.Fatalf("a retry of a finished campaign with failed hosts was refused: %v", err)
	}
	if got := hostIDsOf(picked); got != "host-b,host-g" {
		t.Errorf("the retry took %s, expected exactly the failed hosts", got)
	}

	withUnknown, err := RetryTargets(original, targets, true)
	if err != nil {
		t.Fatalf("a retry including the unknown hosts was refused: %v", err)
	}
	if got := hostIDsOf(withUnknown); got != "host-b,host-c,host-g" {
		t.Errorf("the retry with unknown hosts took %s", got)
	}

	// A canceled or failed campaign is finished too: the hosts that failed
	// before the stop stay failed.
	for _, state := range []State{StateFailed, StateCanceled, StateCompleted} {
		finished := original
		finished.State = state
		if _, err := RetryTargets(finished, targets, false); err != nil {
			t.Errorf("a %s campaign cannot be retried: %v", state, err)
		}
	}

	for _, state := range []State{StateRunning, StatePaused, StateAwaitingApproval, StateCanceling, StateManualGate} {
		running := original
		running.State = state
		_, err := RetryTargets(running, targets, false)
		if RetryCode(err) != CodeCampaignNotFinished {
			t.Errorf("a %s campaign was not refused with %s: %v", state, CodeCampaignNotFinished, err)
		}
	}

	// Unknown hosts alone are nothing to retry unless asked for; a clean
	// campaign is nothing to retry at all.
	onlyUnknown := []Target{{HostID: "host-a", State: TargetSucceeded}, {HostID: "host-c", State: TargetUnknown}}
	if _, err := RetryTargets(original, onlyUnknown, false); RetryCode(err) != CodeNothingToRetry {
		t.Errorf("a campaign with only unknown hosts was not refused with %s: %v", CodeNothingToRetry, err)
	}
	if picked, err := RetryTargets(original, onlyUnknown, true); err != nil || hostIDsOf(picked) != "host-c" {
		t.Errorf("the unknown host was not taken on request: %v, %v", picked, err)
	}
	clean := []Target{{HostID: "host-a", State: TargetSucceeded}, {HostID: "host-d", State: TargetSkipped}}
	if _, err := RetryTargets(original, clean, true); RetryCode(err) != CodeNothingToRetry {
		t.Errorf("a clean campaign was not refused with %s: %v", CodeNothingToRetry, err)
	}
	if RetryCode(nil) != "" {
		t.Error("no error carries a retry code")
	}
	if RetryName("rollout") != "rollout (retry)" {
		t.Errorf("the retry is named %q", RetryName("rollout"))
	}
}

// TestProgressTellsUnknownFromFailed guards the list tally: unknown is
// its own number, the hosts that took no part are skipped, and everything
// not settled is pending.
func TestProgressTellsUnknownFromFailed(t *testing.T) {
	var progress Progress
	progress.Add(TargetSucceeded, 3)
	progress.Add(TargetNoChange, 1)
	progress.Add(TargetFailed, 2)
	progress.Add(TargetUnknown, 1)
	progress.Add(TargetSkipped, 1)
	progress.Add(TargetExcluded, 1)
	progress.Add(TargetRunning, 2)
	progress.Add(TargetQueuedOffline, 1)
	want := Progress{Total: 12, Succeeded: 4, Failed: 2, Unknown: 1, Skipped: 2, Pending: 3}
	if progress != want {
		t.Errorf("the tally is %+v, expected %+v", progress, want)
	}
}

func hostIDsOf(targets []Target) string {
	ids := ""
	for i, target := range targets {
		if i > 0 {
			ids += ","
		}
		ids += target.HostID
	}
	return ids
}
