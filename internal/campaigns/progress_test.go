package campaigns

import (
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/ultherego/flotestro/internal/jobs"
	"github.com/ultherego/flotestro/internal/opspec"
)

// TestTheRebootJudgementFollowsTheWindowThenTheTimeout guards the verdict: a
// host still away when the window ends is closed with the window as the reason.
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
// starts from: the last transition of the target, not the start of its change.
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

// TestTheOutcomeOfATaskNamesTheHostState guards the mapping from a settled
// task onto the host, down to a lost session leaving the host unknown.
func TestTheOutcomeOfATaskNamesTheHostState(t *testing.T) {
	cases := []struct {
		name    string
		verdict jobVerdict
		state   TargetState
		code    string
	}{
		{"the change landed", jobVerdict{State: jobs.StateSucceeded}, TargetSucceeded, ""},
		{"the host changed nothing", jobVerdict{State: jobs.StateSucceeded, NoChange: true}, TargetNoChange, ""},
		{"the session broke", jobVerdict{State: jobs.StateTimedOut, Lost: true}, TargetUnknown, ConnectivityLostCode},
		{"the task expired undelivered", jobVerdict{State: jobs.StateExpired, Lost: true}, TargetUnknown, ConnectivityLostCode},
		{"the agent restarted mid-task", jobVerdict{State: jobs.StateFailed, ErrorCode: OutcomeUnknownCode}, TargetUnknown, OutcomeUnknownCode},
		{"the change failed", jobVerdict{State: jobs.StateFailed, ErrorCode: "exec_failed"}, TargetFailed, "exec_failed"},
		{"a timeout with the host still answering", jobVerdict{State: jobs.StateTimedOut}, TargetFailed, "timed_out"},
		{"a cancel of the task", jobVerdict{State: jobs.StateCanceled}, TargetCanceled, "canceled"},
		{"a cancel nobody answered", jobVerdict{State: jobs.StateFailed, ErrorCode: CancelAckTimeoutCode}, TargetUnknown, CancelAckTimeoutCode},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			state, code := targetOutcome(tc.verdict)
			if state != tc.state || code != tc.code {
				t.Errorf("outcome = %s/%q, expected %s/%q", state, code, tc.state, tc.code)
			}
		})
	}
}

// TestTheHostFollowsItsTask guards the stages of an open task on the host:
// dispatched until the agent reports a start, waiting for the lock the agent
// named while it waits, running once it started.
func TestTheHostFollowsItsTask(t *testing.T) {
	for _, state := range []jobs.State{jobs.StateQueued, jobs.StateLeased, jobs.StateDispatched} {
		if got, blocker := taskStanding(state, ""); got != TargetDispatched || blocker != "" {
			t.Errorf("a %s task puts the host in %s with blocker %q, expected dispatched", state, got, blocker)
		}
	}
	got, blocker := taskStanding(jobs.StateDispatched, jobs.LockWaitReason("units held by task abc (schedule.run_now)"))
	if got != TargetAwaitingLock || blocker != "units held by task abc (schedule.run_now)" {
		t.Errorf("a task waiting for a lock puts the host in %s with blocker %q", got, blocker)
	}
	if got, blocker := taskStanding(jobs.StateRunning, ""); got != TargetRunning || blocker != "" {
		t.Errorf("a running task puts the host in %s with blocker %q", got, blocker)
	}
	// A budget wait is the queue's business, not a lock of the host.
	if got, _ := taskStanding(jobs.StateQueued, "awaiting_budget:site:lab:packages"); got != TargetDispatched {
		t.Errorf("a task waiting for a budget puts the host in %s, expected dispatched", got)
	}
}

// TestTheResultSaysWhetherAnythingChanged guards how the campaign reads
// "nothing changed" off a result: a changed flag says it outright, a package
// transaction says it by applying nothing, and anything unreadable says no.
func TestTheResultSaysWhetherAnythingChanged(t *testing.T) {
	cases := map[string]struct {
		detail   string
		noChange bool
	}{
		"a local account already there":     {`{"kind":"local_user","name":"ops","changed":false}`, true},
		"a local account created":           {`{"kind":"local_user","name":"ops","changed":true}`, false},
		"an upgrade with nothing to apply":  {`{"kind":"package_apply","manager":"apt","applied":[]}`, true},
		"an upgrade with no applied list":   {`{"kind":"package_apply","manager":"apt"}`, true},
		"an upgrade that applied a package": {`{"kind":"package_apply","applied":[{"name":"curl"}]}`, false},
		"a unit restart":                    {`{"kind":"unit_detail","units":[]}`, false},
		"a file written":                    {`{"kind":"file","sha256":"abc"}`, false},
		"no result at all":                  {``, false},
		"an unreadable result":              {`{`, false},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			if got := resultNoChange(json.RawMessage(tc.detail)); got != tc.noChange {
				t.Errorf("resultNoChange = %v, expected %v", got, tc.noChange)
			}
		})
	}
}

// TestThePlanSaysWhetherThereIsAnythingToDo guards how the campaign reads
// "nothing to do" off a plan: a plan that names no_change or the removal of an
// absent file, or a package plan with no changes and nothing blocked.
func TestThePlanSaysWhetherThereIsAnythingToDo(t *testing.T) {
	cases := map[string]struct {
		plan     string
		noChange bool
	}{
		"a file already in the desired state": {`{"kind":"file_plan","plan":{"action":"no_change","exists":true},"plan_hash":"h"}`, true},
		"a file to create":                    {`{"kind":"file_plan","plan":{"action":"create"},"plan_hash":"h"}`, false},
		"a file to update":                    {`{"kind":"file_plan","plan":{"action":"update","changes":["content"]}}`, false},
		"a removal of an absent file":         {`{"kind":"file_plan","plan":{"action":"remove_absent"}}`, true},
		"a rule already present":              {`{"kind":"firewall_plan","plan":{"action":"no_change"}}`, true},
		"an upgrade with nothing to upgrade":  {`{"kind":"package_plan","mode":"upgrade","changes":[],"blocked":[]}`, true},
		"an upgrade with no lists at all":     {`{"kind":"package_plan","mode":"upgrade"}`, true},
		"an upgrade with a change":            {`{"kind":"package_plan","changes":[{"name":"curl"}]}`, false},
		"an upgrade with a blocked package":   {`{"kind":"package_plan","changes":[],"blocked":[{"name":"curl"}]}`, false},
		"a compose plan":                      {`{"kind":"compose","payload":{"digest":"abc"}}`, false},
		"a name from the order":               {`{"plan":{"hostname":"web-1","source":"order"}}`, false},
		"no plan":                             {``, false},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			if got := planNoChange(json.RawMessage(tc.plan)); got != tc.noChange {
				t.Errorf("planNoChange = %v, expected %v", got, tc.noChange)
			}
		})
	}
}

// TestTheRebootFollowsThePolicyAndTheResult guards the reboot decision now
// that it reads the result it is handed: never and always answer on their own,
// if_required asks the package transaction, and anything else does not reboot.
func TestTheRebootFollowsThePolicyAndTheResult(t *testing.T) {
	needs := json.RawMessage(`{"kind":"package_apply","reboot_required":true}`)
	if rebootNeeded(Campaign{RebootPolicy: RebootNever}, needs) {
		t.Error("the policy never ordered a reboot")
	}
	if !rebootNeeded(Campaign{RebootPolicy: RebootAlways}, nil) {
		t.Error("the policy always did not order a reboot")
	}
	if !rebootNeeded(Campaign{RebootPolicy: RebootIfRequired}, needs) {
		t.Error("a transaction that requires a reboot did not get one")
	}
	if rebootNeeded(Campaign{RebootPolicy: RebootIfRequired}, json.RawMessage(`{"kind":"package_apply","reboot_required":false}`)) {
		t.Error("a transaction that requires no reboot got one")
	}
	if rebootNeeded(Campaign{RebootPolicy: RebootIfRequired}, json.RawMessage(`{"kind":"file"}`)) {
		t.Error("a file write got a reboot")
	}
	if rebootNeeded(Campaign{RebootPolicy: RebootIfRequired}, nil) {
		t.Error("a task without a result got a reboot")
	}
}

// TestOnlyAConfirmedChangeCarriesTheHostForward: a task that says succeeded
// settles the host succeeded only once the host's own reading confirms it.
func TestOnlyAConfirmedChangeCarriesTheHostForward(t *testing.T) {
	verified := &jobs.Attempt{Verification: json.RawMessage(
		`{"verifier":"unit_state","verified":true,"expected":"active","observed":"active"}`)}
	failed := &jobs.Attempt{Verification: json.RawMessage(
		`{"verifier":"unit_state","verified":false,"expected":"active","observed":"failed",` +
			`"reason":"the unit did not stay active"}`)}
	bare := &jobs.Attempt{Verification: json.RawMessage(
		`{"verifier":"unit_state","verified":false,"expected":"active","observed":"failed"}`)}

	if reason := unverifiedChange(opspec.ActionUnitRestart, verified); reason != "" {
		t.Errorf("a confirmed change was held back: %s", reason)
	}
	reason := unverifiedChange(opspec.ActionUnitRestart, failed)
	if reason == "" {
		t.Fatal("a change nobody observed was taken for a success")
	}
	if !strings.Contains(reason, "the unit did not stay active") {
		t.Errorf("the reason of the verifier was dropped: %s", reason)
	}
	// A verifier that gave no reason still has to say what it looked for
	// and what it found: the operator reads the strip, not the code.
	if said := unverifiedChange(opspec.ActionUnitRestart, bare); !strings.Contains(said, "active") ||
		!strings.Contains(said, "failed") {
		t.Errorf("the observation says nothing: %s", said)
	}
	// A read is its own observation, a restart is settled by the panel on the
	// host's return, and an attempt from an agent before the verifiers sends none
	// at all: none of the three is a failed verification.
	if reason := unverifiedChange(opspec.ActionUnitStatus, failed); reason != "" {
		t.Errorf("an operation without a verifier was held back: %s", reason)
	}
	if reason := unverifiedChange(opspec.ActionSystemReboot, failed); reason != "" {
		t.Errorf("an operation the panel settles was held back: %s", reason)
	}
	if reason := unverifiedChange(opspec.ActionUnitRestart, &jobs.Attempt{}); reason != "" {
		t.Errorf("an attempt without a verification was held back: %s", reason)
	}
	if reason := unverifiedChange(opspec.ActionUnitRestart, nil); reason != "" {
		t.Errorf("a task without an attempt was held back: %s", reason)
	}
}
