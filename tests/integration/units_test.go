//go:build integration

package integration

import (
	"encoding/json"
	"net/http"
	"strings"
	"testing"
	"time"
)

// unitDetailView mirrors the JSON a detail read prints on stdout.
type unitDetailView struct {
	State struct {
		Name        string `json:"name"`
		ActiveState string `json:"active_state"`
		SubState    string `json:"sub_state"`
		NRestarts   uint32 `json:"n_restarts"`
	} `json:"state"`
	Description  string   `json:"description"`
	FragmentPath string   `json:"fragment_path"`
	After        []string `json:"after"`
	Wants        []string `json:"wants"`
	TriggeredBy  []string `json:"triggered_by"`
	DropIns      []struct {
		Path    string `json:"path"`
		Content string `json:"content"`
		Error   string `json:"error"`
	} `json:"drop_ins"`
	ExecMainStart string   `json:"exec_main_start"`
	JournalLines  []string `json:"journal_lines"`
	JournalCursor string   `json:"journal_cursor"`
	JournalError  string   `json:"journal_error"`
}

// unitDetailDocumentView is the document of a detail read: typed in the
// detail of the attempt, and printed on stdout.
type unitDetailDocumentView struct {
	Kind  string           `json:"kind"`
	Units []unitDetailView `json:"units"`
}

// unitDetailDocument reads the typed detail from the last attempt of the job.
func unitDetailDocument(t *testing.T, h *harness, jobID string) unitDetailDocumentView {
	t.Helper()
	var result struct {
		Items []struct {
			Detail unitDetailDocumentView `json:"detail"`
		} `json:"items"`
	}
	h.get("/api/v1/jobs/"+jobID+"/attempts", &result)
	if len(result.Items) == 0 {
		t.Fatalf("job %s has no attempts", jobID)
	}
	return result.Items[len(result.Items)-1].Detail
}

const unitReason = "integration test of the unit detail"

// TestUnitDetailReadsTheWholePicture checks the detail view of a unit: the
// dependencies, the drop-ins, the journal tail and the cursor to continue
// from.
func TestUnitDetailReadsTheWholePicture(t *testing.T) {
	h := newHarness(t)
	host := h.hostByFamily("debian")

	// The full listing first, so that the detail read has something it
	// could wrongly replace.
	job, _ := h.runOperation(host.ID, map[string]any{
		"action":  "unit.status",
		"payload": map[string]any{"unit_status": map[string]any{"all": true}},
	}, 90*time.Second)
	if job.State != "succeeded" {
		t.Fatalf("listing: state = %s, code = %s", job.State, job.ResultErrorCode)
	}
	var before inventoryFragment
	h.do(http.MethodGet, "/api/v1/hosts/"+host.ID+"/inventory/services.full", nil, &before, http.StatusOK)

	job, attempts := h.runOperation(host.ID, map[string]any{
		"action": "unit.status",
		"payload": map[string]any{"unit_status": map[string]any{
			"units": []string{"cron.service"}, "detail": true,
		}},
	}, 90*time.Second)
	if job.RequiresApproval {
		t.Error("a detail read should not require approval")
	}
	if job.State != "succeeded" {
		t.Fatalf("detail: state = %s, %s", job.State, lastMessage(attempts))
	}
	// The detail reaches the panel typed, in the detail of the attempt: the
	// panel reads it without parsing stdout.
	document := unitDetailDocument(t, h, job.ID)
	if document.Kind != "unit_detail" || len(document.Units) != 1 {
		t.Fatalf("typed detail = %+v", document)
	}
	// The same document still goes on stdout for one release: a panel from
	// before the typed detail reads it from there.
	var printed unitDetailDocumentView
	if err := json.Unmarshal([]byte(attempts[len(attempts)-1].Stdout), &printed); err != nil {
		t.Fatalf("the detail is not a JSON document on stdout: %v", err)
	}
	if printed.Kind != "unit_detail" || len(printed.Units) != 1 {
		t.Fatalf("stdout document = %+v", printed)
	}
	if printed.Units[0].State.Name != document.Units[0].State.Name ||
		printed.Units[0].JournalCursor != document.Units[0].JournalCursor {
		t.Errorf("the typed detail and stdout disagree: %+v vs %+v", document.Units[0], printed.Units[0])
	}
	detail := document.Units[0]
	if detail.State.Name != "cron.service" || detail.State.ActiveState == "" {
		t.Errorf("state = %+v", detail.State)
	}
	if detail.FragmentPath == "" || detail.Description == "" {
		t.Errorf("the detail names no unit file or description: %+v", detail)
	}
	// cron is ordered after the basic system target on every distribution;
	// a detail without dependencies would be reading the wrong thing.
	if len(detail.After) == 0 {
		t.Errorf("the detail has no After dependencies: %+v", detail)
	}
	if detail.State.ActiveState == "active" && detail.ExecMainStart == "" {
		t.Error("a running unit has no main process start time")
	}
	if detail.JournalError != "" {
		t.Errorf("the journal could not be read: %s", detail.JournalError)
	}
	if len(detail.JournalLines) > 30 {
		t.Errorf("journal lines = %d, want at most 30", len(detail.JournalLines))
	}
	if len(detail.JournalLines) > 0 && detail.JournalCursor == "" {
		t.Error("the journal tail carries no cursor to continue from")
	}
	for _, dropIn := range detail.DropIns {
		if dropIn.Content == "" && dropIn.Error == "" {
			t.Errorf("drop-in %s has neither content nor a reason", dropIn.Path)
		}
	}

	// The detail of one unit is not a listing of the host.
	var after inventoryFragment
	h.do(http.MethodGet, "/api/v1/hosts/"+host.ID+"/inventory/services.full", nil, &after, http.StatusOK)
	if after.Revision != before.Revision {
		t.Error("the detail read replaced the full listing of the units")
	}

	// The cursor continues the read in the Logs page: the next lines come
	// after the ones the detail showed.
	if detail.JournalCursor != "" {
		job, attempts = h.runOperation(host.ID, map[string]any{
			"action": "journal.read",
			"payload": map[string]any{"journal": map[string]any{
				"unit": "cron.service", "lines": 5, "after_cursor": detail.JournalCursor,
			}},
		}, 60*time.Second)
		if job.State != "succeeded" {
			t.Fatalf("journal read after the cursor: state = %s, %s", job.State, lastMessage(attempts))
		}
		last := detail.JournalLines[len(detail.JournalLines)-1]
		if strings.Contains(attempts[len(attempts)-1].Stdout, last) {
			t.Errorf("the read after the cursor repeats the last line of the detail: %q", last)
		}
	}

	// A detail read of a sweep of units is refused: it serves one open row.
	h.do(http.MethodPost, "/api/v1/hosts/"+host.ID+"/operations",
		map[string]any{"action": "unit.status", "payload": map[string]any{"unit_status": map[string]any{
			"units":  []string{"a.service", "b.service", "c.service", "d.service", "e.service", "f.service"},
			"detail": true,
		}}},
		nil, http.StatusBadRequest)
}

// TestResetFailedClearsTheRecord checks the operation that follows a fix:
// after the unit has been repaired, its failed state is cleared without
// touching any process, and the record reads clean afterwards.
func TestResetFailedClearsTheRecord(t *testing.T) {
	h := newHarness(t)
	host := h.hostByFamily("debian")

	// A unit that does not exist cannot be reset; the refusal names the unit
	// rather than reporting success for nothing.
	job, attempts := h.runOperation(host.ID, map[string]any{
		"action": "unit.reset_failed", "reason": unitReason,
		"payload": unitPayload("no-such-unit-for-flotestro.service"),
	}, 60*time.Second)
	if job.State == "succeeded" {
		t.Fatalf("reset-failed succeeded on a unit that does not exist: %s", lastMessage(attempts))
	}

	// On a real unit the operation is idempotent: clearing a state that is
	// already clean is a success, and the unit stays as it was.
	job, attempts = h.runOperation(host.ID, map[string]any{
		"action": "unit.reset_failed", "reason": unitReason,
		"payload": unitPayload("cron.service"),
	}, 60*time.Second)
	if job.State != "succeeded" {
		t.Fatalf("reset-failed: state = %s, %s", job.State, lastMessage(attempts))
	}
	last := attempts[len(attempts)-1]
	if last.UnitStateBefore == nil {
		t.Error("the result carries no unit state before the operation")
	}
	if last.UnitStateBefore != nil && last.UnitStateBefore.ActiveState == "active" &&
		last.UnitStateBefore.MainPID == 0 {
		t.Error("an active unit reports no main process")
	}

	// A protected unit stays protected for this verb as well.
	job, _ = h.runOperation(host.ID, map[string]any{
		"action": "unit.reset_failed", "reason": unitReason,
		"payload": unitPayload("flotestro-agent.service"),
	}, 60*time.Second)
	if job.State == "succeeded" {
		t.Error("reset-failed touched a protected unit")
	}
}
