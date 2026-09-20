package adminapi

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/ultherego/flotestro/internal/paging"
)

// The head of a report and the page of its host rows are what an operator
// reads before the numbers, so they are checked here without a database.

func TestReportPageReadsTheLimitAndTheCursorOfTheHostList(t *testing.T) {
	for _, test := range []struct {
		query string
		want  int
	}{
		{query: "", want: defaultReportHosts},
		{query: "?limit=25", want: 25},
		{query: "?limit=99999", want: maxReportHosts},
		{query: "?limit=0", want: defaultReportHosts},
	} {
		recorder := httptest.NewRecorder()
		limit, afterName, afterID, ok := parseReportPage(recorder,
			httptest.NewRequest(http.MethodGet, "/api/v1/reports/patch-status"+test.query, nil))
		if !ok {
			t.Fatalf("%q was refused: %s", test.query, recorder.Body)
		}
		if limit != test.want {
			t.Errorf("%q gives the limit %d, expected %d", test.query, limit, test.want)
		}
		if afterName != "" || afterID != "" {
			t.Errorf("%q carries the key %q/%q", test.query, afterName, afterID)
		}
	}

	// A cursor this list wrote comes back as the key it stands for.
	cursor := paging.Encode("web-07", "8a2f6c1e-0000-4000-8000-000000000001")
	recorder := httptest.NewRecorder()
	_, afterName, afterID, ok := parseReportPage(recorder,
		httptest.NewRequest(http.MethodGet, "/api/v1/reports/patch-status?cursor="+cursor, nil))
	if !ok || afterName != "web-07" || afterID != "8a2f6c1e-0000-4000-8000-000000000001" {
		t.Errorf("key = %q/%q, ok = %v (%s)", afterName, afterID, ok, recorder.Body)
	}
}

// A page nobody can serve is refused with a reason: a limit that is not a
// number, or a cursor that did not come from this list.
func TestReportPageRefusesWhatItCannotPage(t *testing.T) {
	for _, query := range []string{
		"?limit=many",
		"?limit=-1",
		"?cursor=!!!",
		"?cursor=" + paging.Encode("web-07"),
		"?cursor=" + paging.Encode("web-07", "not-an-identifier"),
	} {
		recorder := httptest.NewRecorder()
		if _, _, _, ok := parseReportPage(recorder,
			httptest.NewRequest(http.MethodGet, "/api/v1/reports/patch-status"+query, nil)); ok {
			t.Errorf("%q was accepted", query)
		}
		if recorder.Code != http.StatusBadRequest {
			t.Errorf("%q answered %d, expected 400", query, recorder.Code)
		}
	}
}

// The rows arrive in the order of the host list, so the page begins at the
// first row past the cursor's host and never repeats it.
func TestAfterCursorOpensThePageAfterTheCursorsHost(t *testing.T) {
	const id = "8a2f6c1e-0000-4000-8000-000000000005"
	const next = "8a2f6c1e-0000-4000-8000-000000000006"
	for _, test := range []struct {
		name               string
		hostname, hostID   string
		afterName, afterID string
		after              bool
	}{
		{name: "no cursor takes the first row", hostname: "app-01", hostID: id, after: true},
		{name: "the cursor's own host is not repeated", hostname: "web-07", hostID: id,
			afterName: "web-07", afterID: id},
		{name: "an earlier host is behind the page", hostname: "app-01", hostID: id,
			afterName: "web-07", afterID: id},
		{name: "a later host opens the page", hostname: "web-08", hostID: id,
			afterName: "web-07", afterID: id, after: true},
		{name: "a namesake is ordered by identifier", hostname: "web-07", hostID: next,
			afterName: "web-07", afterID: id, after: true},
	} {
		got := afterCursor(test.hostname, test.hostID, test.afterName, test.afterID)
		if got != test.after {
			t.Errorf("%s: %s/%s after %s/%s = %v", test.name, test.hostname, test.hostID,
				test.afterName, test.afterID, got)
		}
	}
}

// The security section of the compliance report answers with the same head as
// the fleet screens: a share of failing hosts is unreadable without the fleet
// it is a share of, and a fleet nobody finished sweeping must not read as a
// clean one.
func TestSecuritySummaryCarriesTheCoverageHead(t *testing.T) {
	summary := &securitySummary{
		BySeverity: []severityView{}, Checks: []checkSummary{}, EvaluatedAt: time.Now().UTC(),
		Hosts: 600, HostsWithFindings: 40,
	}
	summary.fleetCoverage = sweepCoverage(1001, fleetSweep{Swept: 600, Partial: true, Reason: partialTimeBudget}, 550)

	encoded, err := json.Marshal(summary)
	if err != nil {
		t.Fatalf("encoding the section: %v", err)
	}
	var decoded map[string]any
	if err := json.Unmarshal(encoded, &decoded); err != nil {
		t.Fatalf("decoding the section: %v", err)
	}
	for name, want := range map[string]float64{
		"total_hosts": 1001, "evaluated_hosts": 550, "unknown_hosts": 451,
		"hosts": 600, "hosts_with_findings": 40,
	} {
		if decoded[name] != want {
			t.Errorf("%s = %v, expected %v", name, decoded[name], want)
		}
	}
	if decoded["partial"] != true || decoded["partial_reason"] != partialTimeBudget {
		t.Errorf("partial = %v (%v), expected the time budget", decoded["partial"], decoded["partial_reason"])
	}
	reasons, _ := decoded["unknown_reasons"].(map[string]any)
	if reasons[unknownNotReached] != float64(401) {
		t.Errorf("not reached = %v, expected 401", reasons[unknownNotReached])
	}
}
