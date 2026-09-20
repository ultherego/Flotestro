package adminapi

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/ultherego/flotestro/internal/monitoring"
	"github.com/ultherego/flotestro/internal/paging"
)

// encodedCursor writes a cursor the way the lists do, so a test can hand the
// parser one with a part missing or a part it cannot read.
func encodedCursor(parts ...string) string { return paging.Encode(parts...) }

// The board a request carries is bounded, so the counts beside it are taken
// over every firing alert and not over the rows that fitted.

func TestCountFiringCountsEveryAlertOfAGroup(t *testing.T) {
	var counts alertCounts
	for _, group := range []monitoring.FiringGroup{
		{State: "firing", Severity: "critical", Count: 700},
		{State: "firing", Severity: "warning", Silenced: true, Count: 40},
		{State: "firing", Severity: "info", Count: 3},
		{State: "firing", Severity: "critical", Acknowledged: true, Count: 12},
		{State: "no_data", Severity: "warning", Count: 9},
	} {
		countFiring(&counts, group)
	}
	if counts.Critical != 700 || counts.Warning != 40 || counts.Info != 3 {
		t.Errorf("counts by severity = %+v", counts)
	}
	// A taken alert waits for nobody and a no-data episode is not firing:
	// each is counted apart, a silenced one within its severity.
	if counts.Acknowledged != 12 || counts.NoData != 9 || counts.Silenced != 40 {
		t.Errorf("counts apart = %+v", counts)
	}
}

// A board cut at its limit says so: the counts stay whole, and the answer
// admits the rows are a part of them.
func TestFleetMonitoringMarksABoardCutAtItsLimit(t *testing.T) {
	view := fleetMonitoringView{Firing: make([]monitoring.Alert, monitoring.FiringBoardLimit)}
	countFiring(&view.Counts, monitoring.FiringGroup{State: "firing", Severity: "critical", Count: 1200})
	view.FiringTotal = 1200
	view.bound()
	if !view.Partial || view.PartialReason != partialCapReached {
		t.Errorf("partial = %v (%q), expected the cap", view.Partial, view.PartialReason)
	}
	if view.Counts.Critical != 1200 {
		t.Errorf("critical = %d, expected every firing alert, not the page", view.Counts.Critical)
	}
	whole := fleetMonitoringView{Firing: make([]monitoring.Alert, 3), FiringTotal: 3}
	whole.bound()
	if whole.Partial {
		t.Error("a board that carries every firing alert is marked partial")
	}
	encoded, err := json.Marshal(view)
	if err != nil {
		t.Fatalf("encoding the view: %v", err)
	}
	var decoded map[string]any
	if err := json.Unmarshal(encoded, &decoded); err != nil {
		t.Fatalf("decoding the view: %v", err)
	}
	for _, name := range []string{"firing_total", "partial", "partial_reason"} {
		if _, present := decoded[name]; !present {
			t.Errorf("the view lacks %s", name)
		}
	}
}

// The cursor of the history carries the key of the last row, so the next page
// begins where this one ended rather than at the newest alert again.
func TestAlertCursorRoundTrip(t *testing.T) {
	started := time.Date(2026, 9, 19, 8, 30, 0, 123456000, time.UTC)
	id := "3f2504e0-4f89-11d3-9a0c-0305e82c3301"
	cursor := alertCursor(monitoring.Alert{ID: id, StartedAt: started})

	recorder := httptest.NewRecorder()
	key, ok := parseAlertCursor(recorder, cursor)
	if !ok {
		t.Fatalf("the cursor was refused: %s", recorder.Body)
	}
	if key == nil || key.ID != id || !key.StartedAt.Equal(started) {
		t.Errorf("key = %+v, expected %s at %s", key, id, started)
	}

	// No cursor is the first page, not a refusal.
	empty := httptest.NewRecorder()
	if key, ok := parseAlertCursor(empty, ""); !ok || key != nil {
		t.Errorf("the first page asked for a cursor: key = %+v, ok = %v", key, ok)
	}
}

// A cursor that did not come from this list is refused with a code, not
// answered with the newest page as if nothing was asked.
func TestParseAlertCursorRefusesWhatItDidNotIssue(t *testing.T) {
	for name, cursor := range map[string]string{
		"not base64":      "not-a-cursor!!",
		"one part":        encodedCursor("2026-09-19T08:30:00Z"),
		"unreadable time": encodedCursor("yesterday", "3f2504e0-4f89-11d3-9a0c-0305e82c3301"),
		"no identifier":   encodedCursor("2026-09-19T08:30:00Z", "web-01"),
	} {
		recorder := httptest.NewRecorder()
		if _, ok := parseAlertCursor(recorder, cursor); ok {
			t.Errorf("%s was accepted", name)
			continue
		}
		if recorder.Code != http.StatusBadRequest {
			t.Errorf("%s answered %d, expected 400", name, recorder.Code)
		}
		var body map[string]any
		if err := json.Unmarshal(recorder.Body.Bytes(), &body); err != nil {
			t.Fatalf("%s: decoding the refusal: %v", name, err)
		}
		if body["code"] != "invalid_cursor" {
			t.Errorf("%s was refused as %v, expected invalid_cursor", name, body["code"])
		}
	}
}
