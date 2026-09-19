//go:build integration

package integration

import (
	"encoding/json"
	"net/http"
	"strings"
	"testing"
	"time"
)

// The timers are tested on the Arch host: it runs systemd and, unlike the
// Debian hosts, has no /etc/cron.
const timerReason = "integration test of the managed systemd timers"

// unitDirectory is where a managed timer lives. The agent's own service unit
// lives there too, which is what makes it the file to prove ownership against.
const unitDirectory = "/etc/systemd/system/"

// TestManagedTimerLifecycle walks the whole path of a timer the panel writes:
// the pair of units on the host, the runs systemd computes for it, the same
// order once more changing nothing, and the removal.
func TestManagedTimerLifecycle(t *testing.T) {
	h := newHarness(t)
	host := h.hostByFamily("arch")
	const id = "timer-lifecycle-test"

	t.Cleanup(func() {
		h.createOperation(host.ID, map[string]any{
			"action": "schedule.remove", "reason": timerReason,
			"payload": map[string]any{"schedule": map[string]any{"id": id}},
		})
	})

	order := map[string]any{
		"action": "schedule.ensure", "reason": timerReason,
		"payload": map[string]any{"schedule": map[string]any{
			"id":         id,
			"kind":       "timer",
			"expression": "15 3 * * *",
			"command":    []string{"/usr/bin/true"},
			"user":       "root",
			"enabled":    true,
		}},
	}
	job, attempts := h.runOperation(host.ID, order, 120*time.Second)
	if job.State != "succeeded" {
		t.Fatalf("writing the timer: state = %s, %s", job.State, lastMessage(attempts))
	}

	entry := hostEntry(t, h, host.ID, id)
	if entry.Kind != "timer" || entry.Source != "managed" || !entry.Enabled {
		t.Fatalf("the entry after the write = %+v", entry)
	}
	// The entry reads back in the language the operator typed it in, and the
	// units it lives in are named: the operator has to know where to look when
	// the panel cannot do something.
	if entry.Expression != "15 3 * * *" {
		t.Errorf("the entry runs on %q, want the expression it was ordered with", entry.Expression)
	}
	if !strings.HasPrefix(entry.Path, unitDirectory) || !strings.HasSuffix(entry.Path, ".timer") {
		t.Errorf("the entry lives in %q", entry.Path)
	}
	if len(entry.Command) == 0 || entry.Command[0] != "/usr/bin/true" {
		t.Errorf("the timer does not run the command that was ordered: %+v", entry)
	}
	// The next runs come from the host: systemd computes them from the
	// calendar expression of the unit, in the host's own zone.
	if entry.NextRun == nil || len(entry.NextRuns) == 0 {
		t.Fatalf("the timer has no next run: %+v", entry)
	}
	for i, run := range entry.NextRuns {
		if run.Hour() != 3 || run.Minute() != 15 {
			t.Errorf("run %d = %v, want 03:15 in the host zone", i, run)
		}
	}

	// The same order again is the same state: nothing is written and systemd is
	// not reloaded.
	job, attempts = h.runOperation(host.ID, order, 120*time.Second)
	if job.State != "succeeded" {
		t.Fatalf("writing the timer again: state = %s, %s", job.State, lastMessage(attempts))
	}
	if message := lastMessage(attempts); !strings.Contains(message, "nothing was written") {
		t.Errorf("the second order did something: %q", message)
	}

	job, attempts = h.runOperation(host.ID, map[string]any{
		"action": "schedule.remove", "reason": timerReason,
		"payload": map[string]any{"schedule": map[string]any{"id": id}},
	}, 120*time.Second)
	if job.State != "succeeded" {
		t.Fatalf("removing the timer: state = %s, %s", job.State, lastMessage(attempts))
	}
	for _, remaining := range schedulesOf(t, h, host.ID).Schedules {
		if remaining.ID == id {
			t.Fatalf("the timer survived the removal: %+v", remaining)
		}
	}
}

// TestAnEntryNamedAfterTheProductCannotTouchItsUnits is the ownership boundary
// of the mechanism, and it is drawn by the namespace rather than by a check
// that could be got around.
func TestAnEntryNamedAfterTheProductCannotTouchItsUnits(t *testing.T) {
	h := newHarness(t)
	host := h.hostByFamily("arch")
	const id = "agent"

	t.Cleanup(func() {
		h.runOperation(host.ID, map[string]any{
			"action": "schedule.remove", "reason": timerReason,
			"payload": map[string]any{"schedule": map[string]any{"id": id}},
		}, 120*time.Second)
	})

	job, attempts := h.runOperation(host.ID, map[string]any{
		"action": "schedule.ensure", "reason": timerReason,
		"payload": map[string]any{"schedule": map[string]any{
			"id":         id,
			"kind":       "timer",
			"expression": "15 3 * * *",
			"command":    []string{"/usr/bin/true"},
			"user":       "root",
			"enabled":    true,
		}},
	}, 120*time.Second)
	if job.State != "succeeded" {
		t.Fatalf("the entry was not written: %s %s", job.State, lastMessage(attempts))
	}

	entry := hostEntry(t, h, host.ID, id)
	// The path is the proof: a unit of the product would be named
	// flotestro-agent.service, and this one cannot be.
	if !strings.Contains(entry.Path, "flotestro-entry-"+id) {
		t.Errorf("the entry was written as %q, outside the namespace of managed entries", entry.Path)
	}
	if strings.HasSuffix(entry.Path, "/flotestro-"+id+".service") ||
		strings.HasSuffix(entry.Path, "/flotestro-"+id+".timer") {
		t.Fatalf("the entry took the name of a unit of the product: %q", entry.Path)
	}

	// The host is still there, which is the whole point: the agent runs
	// from the unit the package installed and the entry did not touch it.
	h.awaitConnection(host.ID, 60*time.Second)
}

// TestTheMechanismIsAVisibleDecision checks what a host without /etc/cron. d
// answers to an order that does not name a mechanism.
func TestTheMechanismIsAVisibleDecision(t *testing.T) {
	h := newHarness(t)
	host := h.hostByFamily("arch")
	const id = "timer-kind-test"

	var adapter hostCapability
	for _, capability := range host.Capabilities {
		if capability.Name == "schedules" {
			adapter = capability
		}
	}
	if !adapter.Available {
		t.Skip("the host reports no schedules adapter")
	}
	if !adapter.Features["timers"] {
		t.Skip("the host runs no systemd, so it carries no timers")
	}
	if adapter.Features["cron"] {
		t.Skip("the host has /etc/cron.d, so an order without a kind has somewhere to go")
	}

	t.Cleanup(func() {
		h.createOperation(host.ID, map[string]any{
			"action": "schedule.remove", "reason": timerReason,
			"payload": map[string]any{"schedule": map[string]any{"id": id}},
		})
	})
	order := map[string]any{
		"id":         id,
		"expression": "15 3 * * *",
		"command":    []string{"/usr/bin/true"},
		"user":       "root",
		"enabled":    true,
	}
	job, attempts := h.runOperation(host.ID, map[string]any{
		"action": "schedule.ensure", "reason": timerReason,
		"payload": map[string]any{"schedule": order},
	}, 120*time.Second)
	if job.State == "succeeded" {
		t.Fatal("a host without /etc/cron.d wrote a cron entry")
	}
	message := lastMessage(attempts)
	if !strings.Contains(message, "/etc/cron.d") || !strings.Contains(message, "timer") {
		t.Errorf("the refusal names neither what is missing nor what the host has: %q", message)
	}

	// The same order that leaves the choice to the host is written with
	// what the host has.
	order["kind"] = "any"
	job, attempts = h.runOperation(host.ID, map[string]any{
		"action": "schedule.ensure", "reason": timerReason,
		"payload": map[string]any{"schedule": order},
	}, 120*time.Second)
	if job.State != "succeeded" {
		t.Fatalf("a free choice of mechanism: state = %s, %s", job.State, lastMessage(attempts))
	}
	if entry := hostEntry(t, h, host.ID, id); entry.Kind != "timer" {
		t.Errorf("the host wrote the entry as %q, want a timer", entry.Kind)
	}
}

// TestTheTimerPlanSaysWhatWouldBeWritten checks the preview a form shows
// before anything lands on the host: the calendar expression the cron line
// becomes and the two unit files, with the marker that makes them ours.
func TestTheTimerPlanSaysWhatWouldBeWritten(t *testing.T) {
	h := newHarness(t)
	host := h.hostByFamily("arch")

	job, attempts := h.runOperation(host.ID, map[string]any{
		"action": "schedule.preview",
		"payload": map[string]any{"schedule": map[string]any{
			"id":         "timer-plan-test",
			"kind":       "timer",
			"expression": "15 2 * * 1-5",
			"command":    []string{"/usr/bin/true"},
			"user":       "root",
		}},
	}, 60*time.Second)
	if job.State != "succeeded" {
		t.Fatalf("the preview: state = %s, %s", job.State, lastMessage(attempts))
	}
	var preview struct {
		Kind     string `json:"kind"`
		Calendar string `json:"calendar"`
		Error    string `json:"error"`
		Units    []struct {
			Path    string `json:"path"`
			Content string `json:"content"`
		} `json:"units"`
	}
	if err := json.Unmarshal([]byte(attempts[len(attempts)-1].Stdout), &preview); err != nil {
		t.Fatalf("the preview is not a JSON document: %v", err)
	}
	if preview.Error != "" {
		t.Fatalf("the preview reports an error: %s", preview.Error)
	}
	if preview.Kind != "timer" || preview.Calendar != "Mon,Tue,Wed,Thu,Fri *-*-* 02:15:00" {
		t.Errorf("the plan runs on %q as a %q", preview.Calendar, preview.Kind)
	}
	if len(preview.Units) != 2 {
		t.Fatalf("the plan names %d files, want the two units", len(preview.Units))
	}
	for _, unit := range preview.Units {
		if !strings.HasPrefix(unit.Path, unitDirectory) {
			t.Errorf("the plan would write %q", unit.Path)
		}
		if !strings.Contains(unit.Content, "Managed by Flotestro") {
			t.Errorf("%s would carry no marker of the panel:\n%s", unit.Path, unit.Content)
		}
	}
	if !strings.Contains(preview.Units[0].Content, "OnCalendar=Mon,Tue,Wed,Thu,Fri *-*-* 02:15:00") {
		t.Errorf("the timer unit does not run on the calendar of the plan:\n%s", preview.Units[0].Content)
	}
	if !strings.Contains(preview.Units[1].Content, "User=root") {
		t.Errorf("the service unit names no account:\n%s", preview.Units[1].Content)
	}

	// Cron runs a job when the day of the month or the day of the week matches,
	// systemd only when both do.
	_, body := h.request(http.MethodPost, "/api/v1/hosts/"+host.ID+"/operations",
		map[string]any{"action": "schedule.ensure", "reason": timerReason,
			"payload": map[string]any{"schedule": map[string]any{
				"id": "timer-both-days", "kind": "timer", "expression": "0 4 1 * 1",
				"command": []string{"/usr/bin/true"}, "user": "root",
			}}}, nil)
	if code := problemCode(t, body); code != "timer_calendar_unsupported" {
		t.Errorf("code = %q, want timer_calendar_unsupported; body: %s", code, truncate(body, 300))
	}
}
