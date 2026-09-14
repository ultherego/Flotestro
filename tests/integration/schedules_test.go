//go:build integration

package integration

import (
	"encoding/json"
	"net/http"
	"strings"
	"testing"
	"time"
)

// scheduleView mirrors one entry in the scheduled jobs snapshot.
type scheduleView struct {
	ID          string      `json:"id"`
	Kind        string      `json:"kind"`
	Source      string      `json:"source"`
	Enabled     bool        `json:"enabled"`
	Expression  string      `json:"expression"`
	Command     []string    `json:"command"`
	CommandLine string      `json:"command_line"`
	Path        string      `json:"path"`
	NextRun     *time.Time  `json:"next_run"`
	NextRuns    []time.Time `json:"next_runs"`
}

type schedulesSnapshot struct {
	Schedules         []scheduleView `json:"schedules"`
	Timezone          string         `json:"timezone"`
	UnavailableReason string         `json:"unavailable_reason"`
}

const scheduleReason = "integration test of the schedules module"

// TestManagedEntryLifecycle walks the full path of a panel entry: creation,
// disabling, an out-of-schedule run and removal. Every step is checked on
// the host state, not on what the operation answered.
func TestManagedEntryLifecycle(t *testing.T) {
	h := newHarness(t)
	host := h.hostByFamily("debian")
	const id = "lifecycle-test"

	t.Cleanup(func() {
		h.createOperation(host.ID, map[string]any{
			"action": "schedule.remove", "reason": scheduleReason,
			"payload": map[string]any{"schedule": map[string]any{"id": id}},
		})
	})

	job, attempts := h.runOperation(host.ID, map[string]any{
		"action": "schedule.ensure", "reason": scheduleReason,
		"payload": map[string]any{"schedule": map[string]any{
			"id":         id,
			"expression": "*/5 * * * *",
			"command":    []string{"/usr/bin/true"},
			"user":       "root",
			"enabled":    true,
		}},
	}, 90*time.Second)
	if job.State != "succeeded" {
		t.Fatalf("creating the entry: state = %s, %s", job.State, lastMessage(attempts))
	}

	entry := hostEntry(t, h, host.ID, id)
	if entry.Source != "managed" || !entry.Enabled {
		t.Fatalf("entry after creation = %+v", entry)
	}
	// The panel wrote its own entry itself, so it knows its arguments; a
	// pre-existing entry stays a shell line.
	if len(entry.Command) == 0 {
		t.Errorf("the managed entry has no arguments: %+v", entry)
	}
	if entry.NextRun == nil {
		t.Error("an active entry has no next run")
	}

	// Disabling is not removal: the content stays on the host, but the entry
	// has no next run any more, because it will not fire.
	job, attempts = h.runOperation(host.ID, map[string]any{
		"action": "schedule.disable", "reason": scheduleReason,
		"payload": map[string]any{"schedule": map[string]any{"id": id, "enabled": false}},
	}, 90*time.Second)
	if job.State != "succeeded" {
		t.Fatalf("disabling the entry: state = %s, %s", job.State, lastMessage(attempts))
	}
	entry = hostEntry(t, h, host.ID, id)
	if entry.Enabled {
		t.Error("the entry is still enabled")
	}
	if entry.NextRun != nil {
		t.Errorf("a disabled entry got the run time %v", entry.NextRun)
	}
	if entry.Expression != "*/5 * * * *" {
		t.Errorf("disabling lost the entry content: %+v", entry)
	}

	// An out-of-schedule run also works for a disabled entry: that is
	// exactly how the operator checks whether the command works at all.
	job, attempts = h.runOperation(host.ID, map[string]any{
		"action": "schedule.run_now", "reason": scheduleReason,
		"payload": map[string]any{"schedule": map[string]any{"id": id}},
	}, 120*time.Second)
	if job.State != "succeeded" {
		t.Fatalf("running the entry: state = %s, %s", job.State, lastMessage(attempts))
	}

	job, attempts = h.runOperation(host.ID, map[string]any{
		"action": "schedule.remove", "reason": scheduleReason,
		"payload": map[string]any{"schedule": map[string]any{"id": id}},
	}, 90*time.Second)
	if job.State != "succeeded" {
		t.Fatalf("removing the entry: state = %s, %s", job.State, lastMessage(attempts))
	}
	for _, remaining := range schedulesOf(t, h, host.ID).Schedules {
		if remaining.ID == id {
			t.Fatalf("the entry survived removal: %+v", remaining)
		}
	}
}

// TestPreExistingEntryIsNotOverwritten checks the ownership boundary. An
// entry nobody brought into the panel belongs to the host administrator:
// the first operation from the panel must not quietly replace it.
func TestPreExistingEntryIsNotOverwritten(t *testing.T) {
	h := newHarness(t)
	host := h.hostByFamily("debian")

	var preExisting scheduleView
	for _, entry := range schedulesOf(t, h, host.ID).Schedules {
		if entry.Source == "manual" && entry.Kind == "cron" && strings.HasPrefix(entry.Path, "/etc/cron.d/") {
			preExisting = entry
			break
		}
	}
	if preExisting.Path == "" {
		t.Skip("the host has no pre-existing entry in /etc/cron.d")
	}
	name := preExisting.Path[strings.LastIndex(preExisting.Path, "/")+1:]

	// Without an explicit takeover the operation is to be rejected with a
	// reason, not quietly succeed.
	job, attempts := h.runOperation(host.ID, map[string]any{
		"action": "schedule.ensure", "reason": scheduleReason,
		"payload": map[string]any{"schedule": map[string]any{
			"id":         name,
			"expression": "0 4 * * *",
			"command":    []string{"/usr/bin/true"},
			"user":       "root",
		}},
	}, 90*time.Second)
	if job.State == "succeeded" {
		t.Fatalf("the panel overwrote the pre-existing entry %s", preExisting.Path)
	}
	message := lastMessage(attempts)
	if !strings.Contains(message, "does not belong to the panel") {
		t.Errorf("refusal without a reason: %q", message)
	}
}

// TestBadScheduleBeforeSending checks that an entry cron would not
// understand does not reach the host. An expression error is a defect of
// the order, not an execution failure.
func TestBadScheduleBeforeSending(t *testing.T) {
	h := newHarness(t)
	host := h.hostByFamily("debian")

	for _, tc := range []map[string]any{
		{"id": "bad-time", "expression": "99 * * * *", "command": []string{"/usr/bin/true"}},
		{"id": "bad-time", "expression": "0 4 * * *", "command": []string{"/bin/sh", "-c", "rm -rf / ; echo x"}},
		{"id": "bad-time", "expression": "0 4 * * *", "command": []string{"true"}},
		{"id": "Bad Name", "expression": "0 4 * * *", "command": []string{"/usr/bin/true"}},
	} {
		h.do(http.MethodPost, "/api/v1/hosts/"+host.ID+"/operations",
			map[string]any{"action": "schedule.ensure", "reason": scheduleReason,
				"payload": map[string]any{"schedule": tc}},
			nil, http.StatusBadRequest)
	}
}

// TestTimersAndPlainCronInOneTable checks that both mechanisms land in one
// list. A timer without a calendar expression must not get somebody else's.
func TestTimersAndPlainCronInOneTable(t *testing.T) {
	h := newHarness(t)
	host := h.hostByFamily("debian")

	state := schedulesOf(t, h, host.ID)
	if state.UnavailableReason != "" {
		t.Fatalf("the schedules were not read: %s", state.UnavailableReason)
	}
	// The host zone is a fact about the host: without it "03:00" means
	// nothing.
	if state.Timezone == "" || state.Timezone == "Local" {
		t.Errorf("host zone = %q", state.Timezone)
	}

	var cron, timer int
	for _, entry := range state.Schedules {
		switch entry.Kind {
		case "cron":
			cron++
		case "timer":
			timer++
			// A timer starts a unit, not a command.
			if !strings.HasSuffix(entry.CommandLine, ".service") {
				t.Errorf("timer %s starts %q", entry.ID, entry.CommandLine)
			}
		}
	}
	if cron == 0 || timer == 0 {
		t.Fatalf("cron entries = %d, timers = %d", cron, timer)
	}
}

func schedulesOf(t *testing.T, h *harness, hostID string) schedulesSnapshot {
	t.Helper()
	var fragment inventoryFragment
	h.do(http.MethodGet, "/api/v1/hosts/"+hostID+"/inventory/schedules",
		nil, &fragment, http.StatusOK)
	var state schedulesSnapshot
	if err := json.Unmarshal(fragment.Payload, &state); err != nil {
		t.Fatalf("schedules snapshot: %v", err)
	}
	return state
}

// hostEntry waits for an entry in the host inventory. The operation returns
// the state after the change, but the fragment write is asynchronous with
// respect to the job finishing.
func hostEntry(t *testing.T, h *harness, hostID, id string) scheduleView {
	t.Helper()
	deadline := time.Now().Add(60 * time.Second)
	for {
		for _, entry := range schedulesOf(t, h, hostID).Schedules {
			if entry.ID == id {
				return entry
			}
		}
		if time.Now().After(deadline) {
			t.Fatalf("entry %s did not appear in the host inventory", id)
		}
		time.Sleep(2 * time.Second)
	}
}

func lastMessage(attempts []attemptView) string {
	if len(attempts) == 0 {
		return "no attempts"
	}
	last := attempts[len(attempts)-1]
	return last.ErrorCode + ": " + last.Message
}

// TestNextRunsComeFromTheHost checks that an active entry carries its coming
// runs computed on the host: three of them, in order, the first of them the
// single next run again. The timers get theirs from systemd itself.
func TestNextRunsComeFromTheHost(t *testing.T) {
	h := newHarness(t)
	host := h.hostByFamily("debian")
	const id = "next-runs-test"

	t.Cleanup(func() {
		h.createOperation(host.ID, map[string]any{
			"action": "schedule.remove", "reason": scheduleReason,
			"payload": map[string]any{"schedule": map[string]any{"id": id}},
		})
	})
	job, attempts := h.runOperation(host.ID, map[string]any{
		"action": "schedule.ensure", "reason": scheduleReason,
		"payload": map[string]any{"schedule": map[string]any{
			"id":         id,
			"expression": "30 4 * * *",
			"command":    []string{"/usr/bin/true"},
			"user":       "root",
			"enabled":    true,
		}},
	}, 90*time.Second)
	if job.State != "succeeded" {
		t.Fatalf("creating the entry: state = %s, %s", job.State, lastMessage(attempts))
	}

	entry := hostEntry(t, h, host.ID, id)
	if len(entry.NextRuns) != 3 {
		t.Fatalf("next runs = %v, want three", entry.NextRuns)
	}
	if entry.NextRun == nil || !entry.NextRuns[0].Equal(*entry.NextRun) {
		t.Errorf("the first of the next runs %v is not the next run %v", entry.NextRuns[0], entry.NextRun)
	}
	for i := 1; i < len(entry.NextRuns); i++ {
		if !entry.NextRuns[i].After(entry.NextRuns[i-1]) {
			t.Errorf("the runs are not in order: %v", entry.NextRuns)
		}
		if entry.NextRuns[i].Hour() != 4 || entry.NextRuns[i].Minute() != 30 {
			t.Errorf("run %d = %v, want 04:30 in the host zone", i, entry.NextRuns[i])
		}
	}

	// A timer with a calendar expression gets its runs from systemd. A host
	// without such a timer has nothing to check here, which is not a failure.
	for _, timer := range schedulesOf(t, h, host.ID).Schedules {
		if timer.Kind != "timer" || timer.Expression == "" || !timer.Enabled {
			continue
		}
		if len(timer.NextRuns) == 0 {
			t.Errorf("the timer %s (%s) has no next runs", timer.ID, timer.Expression)
		}
		break
	}
}

// TestSchedulePreviewComesFromTheHost checks the preview the form shows: the
// dates are computed on the host, in its zone, with the zone named, and an
// expression the host does not understand is refused before it is sent.
func TestSchedulePreviewComesFromTheHost(t *testing.T) {
	h := newHarness(t)
	host := h.hostByFamily("debian")

	job, attempts := h.runOperation(host.ID, map[string]any{
		"action":  "schedule.preview",
		"payload": map[string]any{"schedule": map[string]any{"expression": "15 2 * * 1-5"}},
	}, 60*time.Second)
	if job.RequiresApproval {
		t.Error("a preview should not require approval")
	}
	if job.State != "succeeded" {
		t.Fatalf("preview: state = %s, %s", job.State, lastMessage(attempts))
	}
	var preview struct {
		Expression string      `json:"expression"`
		Timezone   string      `json:"timezone"`
		NextRuns   []time.Time `json:"next_runs"`
		Error      string      `json:"error"`
	}
	if err := json.Unmarshal([]byte(attempts[len(attempts)-1].Stdout), &preview); err != nil {
		t.Fatalf("the preview is not a JSON document: %v", err)
	}
	if preview.Error != "" {
		t.Fatalf("the preview reports an error: %s", preview.Error)
	}
	if preview.Timezone == "" {
		t.Error("the preview names no host zone")
	}
	if len(preview.NextRuns) != 3 {
		t.Fatalf("next runs = %v, want three", preview.NextRuns)
	}
	for i, date := range preview.NextRuns {
		if date.Hour() != 2 || date.Minute() != 15 || date.Weekday() == time.Saturday || date.Weekday() == time.Sunday {
			t.Errorf("run %d = %v, want a weekday at 02:15 in the host zone", i, date)
		}
	}

	// The same preview reaches the panel typed, in the detail of the
	// attempt, so the form does not parse stdout; stdout stays for one
	// release for a panel from before the typed detail.
	var typed struct {
		Items []struct {
			Detail struct {
				Kind       string      `json:"kind"`
				Expression string      `json:"expression"`
				Timezone   string      `json:"timezone"`
				Runs       []time.Time `json:"runs"`
				Error      string      `json:"error"`
			} `json:"detail"`
		} `json:"items"`
	}
	h.get("/api/v1/jobs/"+job.ID+"/attempts", &typed)
	if len(typed.Items) == 0 {
		t.Fatalf("job %s has no attempts", job.ID)
	}
	detail := typed.Items[len(typed.Items)-1].Detail
	if detail.Kind != "schedule_preview" || detail.Expression != preview.Expression ||
		detail.Timezone != preview.Timezone || len(detail.Runs) != len(preview.NextRuns) || detail.Error != "" {
		t.Errorf("typed preview = %+v, stdout preview = %+v", detail, preview)
	}

	h.do(http.MethodPost, "/api/v1/hosts/"+host.ID+"/operations",
		map[string]any{"action": "schedule.preview",
			"payload": map[string]any{"schedule": map[string]any{"expression": "0 25 * * *"}}},
		nil, http.StatusBadRequest)
}
