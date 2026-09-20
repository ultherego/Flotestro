package adminapi

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/ultherego/flotestro/internal/hosts"
)

// The head of a fleet view is the part an operator reads before anything else,
// so its arithmetic is checked here rather than through a screen.

func TestModuleCoverageCountsAnUnknownHostUnderItsReason(t *testing.T) {
	head := moduleCoverage(hosts.ModuleCoverage{Hosts: 1001, Observed: 400, Unavailable: 25, Stale: 40})
	if head.TotalHosts != 1001 {
		t.Errorf("total = %d, expected 1001", head.TotalHosts)
	}
	if head.EvaluatedHosts != 360 {
		t.Errorf("evaluated = %d, expected 360", head.EvaluatedHosts)
	}
	if head.UnknownHosts != 641 {
		t.Errorf("unknown = %d, expected 641", head.UnknownHosts)
	}
	if head.EvaluatedHosts+head.UnknownHosts != head.TotalHosts {
		t.Error("the judged and the unknown hosts do not add up to the fleet")
	}
	want := map[string]int{unknownNoObservation: 576, unknownUnavailable: 25, unknownStaleObservation: 40}
	for reason, count := range want {
		if head.UnknownReasons[reason] != count {
			t.Errorf("%s = %d, expected %d", reason, head.UnknownReasons[reason], count)
		}
	}
	if head.Partial {
		t.Error("a count over the whole fleet is not a partial answer")
	}
}

// A reason with nothing under it is not named: a screen that lists
// "0 stale" invites the reader to weigh a group that does not exist.
func TestModuleCoverageNamesOnlyTheReasonsItHas(t *testing.T) {
	head := moduleCoverage(hosts.ModuleCoverage{Hosts: 10, Observed: 10})
	if len(head.UnknownReasons) != 0 {
		t.Errorf("reasons = %v, expected none", head.UnknownReasons)
	}
	if head.UnknownHosts != 0 || head.EvaluatedHosts != 10 {
		t.Errorf("head = %+v", head)
	}
}

// A sweep that stopped at its time budget must not pass the hosts it reached
// off as the fleet: the hosts it never opened are unknown, under a reason of
// their own, and the whole answer is marked partial.
func TestSweepCoverageCountsTheHostsItNeverReached(t *testing.T) {
	head := sweepCoverage(1001, fleetSweep{Swept: 600, Partial: true, Reason: partialTimeBudget}, 550)
	if head.TotalHosts != 1001 || head.EvaluatedHosts != 550 || head.UnknownHosts != 451 {
		t.Fatalf("head = %+v", head)
	}
	if !head.Partial || head.PartialReason != partialTimeBudget {
		t.Errorf("partial = %v (%q), expected the time budget", head.Partial, head.PartialReason)
	}
	if head.UnknownReasons[unknownNotReached] != 401 {
		t.Errorf("not reached = %d, expected 401", head.UnknownReasons[unknownNotReached])
	}
	if head.UnknownReasons[unknownNoObservation] != 50 {
		t.Errorf("reached but silent = %d, expected 50", head.UnknownReasons[unknownNoObservation])
	}
}

// A complete sweep over a fleet where nothing reported anything is not a
// complete answer about the fleet: every host is unknown, and none of them is
// a zero.
func TestSweepCoverageOverASilentFleet(t *testing.T) {
	head := sweepCoverage(7, fleetSweep{Swept: 7}, 0)
	if head.EvaluatedHosts != 0 || head.UnknownHosts != 7 {
		t.Fatalf("head = %+v", head)
	}
	if head.Partial {
		t.Error("a sweep that reached every host is not partial")
	}
	if head.UnknownReasons[unknownNoObservation] != 7 {
		t.Errorf("silent hosts = %d, expected 7", head.UnknownReasons[unknownNoObservation])
	}
}

// The head is what the screens read, so the names of its fields are part
// of the contract of every fleet view.
func TestFleetCoverageAnswersTheNamesTheScreensRead(t *testing.T) {
	encoded, err := json.Marshal(sweepCoverage(3, fleetSweep{Swept: 3}, 2))
	if err != nil {
		t.Fatalf("encoding the head: %v", err)
	}
	var decoded map[string]any
	if err := json.Unmarshal(encoded, &decoded); err != nil {
		t.Fatalf("decoding the head: %v", err)
	}
	for _, name := range []string{"total_hosts", "evaluated_hosts", "unknown_hosts", "partial"} {
		if _, present := decoded[name]; !present {
			t.Errorf("the head lacks %s: %s", name, encoded)
		}
	}
	// An answer that is whole says nothing about why it would not be.
	if _, present := decoded["partial_reason"]; present {
		t.Errorf("a whole answer carries a partial reason: %s", encoded)
	}
}

func TestParseFleetPageBoundsWhatACallerMayAskFor(t *testing.T) {
	for _, test := range []struct {
		query string
		want  int
	}{
		{query: "", want: fleetPageDefault},
		{query: "?limit=25", want: 25},
		{query: "?limit=5000", want: fleetPageMax},
		{query: "?limit=0", want: fleetPageDefault},
	} {
		recorder := httptest.NewRecorder()
		limit, cursor, ok := parseFleetPage(recorder, httptest.NewRequest(http.MethodGet, "/api/v1/security"+test.query, nil))
		if !ok {
			t.Fatalf("%q was refused: %s", test.query, recorder.Body)
		}
		if limit != test.want {
			t.Errorf("%q gives the limit %d, expected %d", test.query, limit, test.want)
		}
		if cursor != "" {
			t.Errorf("%q carries the cursor %q", test.query, cursor)
		}
	}

	recorder := httptest.NewRecorder()
	limit, cursor, ok := parseFleetPage(recorder, httptest.NewRequest(http.MethodGet, "/api/v1/security?limit=50&cursor=abc", nil))
	if !ok || limit != 50 || cursor != "abc" {
		t.Errorf("limit = %d, cursor = %q, ok = %v", limit, cursor, ok)
	}

	// A limit that is not a number is a mistake in the caller, not a
	// reason to answer with a page nobody asked for.
	for _, query := range []string{"?limit=many", "?limit=-1"} {
		recorder := httptest.NewRecorder()
		if _, _, ok := parseFleetPage(recorder, httptest.NewRequest(http.MethodGet, "/api/v1/security"+query, nil)); ok {
			t.Errorf("%q was accepted", query)
		}
		if recorder.Code != http.StatusBadRequest {
			t.Errorf("%q answered %d, expected 400", query, recorder.Code)
		}
	}
}

// An export says in a trailer that it does not carry the whole list: the
// status line is long sent by the time a sweep runs out of its budget, so a
// reader that only looks at the headers still learns the file is short.
func TestWriteCSVFlagsAFileThatStopsEarly(t *testing.T) {
	server := &Server{}
	columns := []string{"hostname", "status"}

	whole := httptest.NewRecorder()
	server.writeCSV(whole, httptest.NewRequest(http.MethodGet, "/api/v1/security?format=csv", nil),
		"flotestro-findings-2026-09-18.csv", columns, func(yield func([]string) bool) error {
			yield([]string{"web-01", "failed"})
			return nil
		})
	if got := whole.Result().Trailer.Get(partialHeader); got != "" {
		t.Errorf("a whole file is flagged partial: %q", got)
	}
	if got := whole.Result().Header.Get(partialHeader); got != "" {
		t.Errorf("a whole file is flagged partial in its head: %q", got)
	}

	cut := httptest.NewRecorder()
	server.writeCSV(cut, httptest.NewRequest(http.MethodGet, "/api/v1/security?format=csv", nil),
		"flotestro-findings-2026-09-18.csv", columns, func(yield func([]string) bool) error {
			yield([]string{"web-01", "failed"})
			return exportPartialError{reason: "the sweep ran out of its time budget after 600 hosts"}
		})
	if got := cut.Result().Trailer.Get(partialHeader); got != "true" {
		t.Errorf("a file cut short is not flagged in its trailer: %q", got)
	}

	// A view that knew its own answer covered a part of the fleet says so
	// before the first row, where a reader of the headers alone sees it.
	known := httptest.NewRecorder()
	markPartial(known)
	server.writeCSV(known, httptest.NewRequest(http.MethodGet, "/api/v1/reports/compliance?format=csv", nil),
		"flotestro-report-2026-09-18.csv", columns, func(yield func([]string) bool) error {
			yield([]string{"ssh.root-login", "failed"})
			return nil
		})
	if got := known.Result().Header.Get(partialHeader); got != "true" {
		t.Errorf("a file whose numbers cover a part of the fleet is not flagged: %q", got)
	}
	rows := strings.Split(strings.TrimSpace(cut.Body.String()), "\n")
	if len(rows) != 3 {
		t.Fatalf("the file has %d lines, expected the header, the row and the marker: %q", len(rows), cut.Body.String())
	}
	if !strings.HasPrefix(rows[2], exportTruncatedMarker+",") {
		t.Errorf("the last row is %q, expected the truncation marker", rows[2])
	}
	if !strings.Contains(rows[2], "time budget") {
		t.Errorf("the last row does not say why the file stops: %q", rows[2])
	}
}
