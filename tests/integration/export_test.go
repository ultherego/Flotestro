//go:build integration

package integration

import (
	"encoding/csv"
	"net/http"
	"net/url"
	"strings"
	"testing"
)

// csvExport asks a list for its file and hands back the parsed rows, the
// header first.
func csvExport(t *testing.T, h *harness, path, list string) [][]string {
	t.Helper()
	response, raw := h.request(http.MethodGet, path, nil, nil)
	if response.StatusCode != http.StatusOK {
		t.Fatalf("GET %s answered %d: %s", path, response.StatusCode, truncate(raw, 300))
	}
	if contentType := response.Header.Get("Content-Type"); !strings.HasPrefix(contentType, "text/csv") {
		t.Fatalf("GET %s came as %q, want text/csv", path, contentType)
	}
	disposition := response.Header.Get("Content-Disposition")
	if !strings.HasPrefix(disposition, "attachment;") || !strings.Contains(disposition, `filename="flotestro-`+list+"-") ||
		!strings.HasSuffix(disposition, `.csv"`) {
		t.Fatalf("GET %s is not offered as a file of the list: %q", path, disposition)
	}
	rows, err := csv.NewReader(strings.NewReader(string(raw))).ReadAll()
	if err != nil {
		t.Fatalf("the export of %s does not parse: %v", path, err)
	}
	if len(rows) == 0 {
		t.Fatalf("the export of %s has no header", path)
	}
	for _, marker := range []string{"truncated", "error"} {
		if last := rows[len(rows)-1]; last[0] == marker {
			t.Fatalf("the export of %s ends with the %s marker: %v", path, marker, last)
		}
	}
	return rows
}

// requireHeader checks the first row of an export against the columns a
// sheet is built on: the names and their order are the contract.
func requireHeader(t *testing.T, rows [][]string, want []string) {
	t.Helper()
	if strings.Join(rows[0], ",") != strings.Join(want, ",") {
		t.Fatalf("the CSV header is %v, want %v", rows[0], want)
	}
	for _, row := range rows[1:] {
		if len(row) != len(want) {
			t.Errorf("row %v has %d columns, want %d", row, len(row), len(want))
		}
	}
}

// TestHostListExportsEveryHostOfTheFilter checks the fleet export against the
// JSON list: the same filter, the total of the list as the number of rows
// whatever the page size, and the columns in their fixed order.
func TestHostListExportsEveryHostOfTheFilter(t *testing.T) {
	h := newHarness(t)
	wantHeader := []string{
		"hostname", "id", "site", "environment", "owner", "failure_domain", "lifecycle_state",
		"connection_state", "last_seen_at", "os_family", "os_distribution", "os_version", "architecture",
		"agent_version", "release_channel", "management_address", "tags", "reboot_required",
		"failed_units", "pending_updates", "pending_security_updates", "package_database_broken",
		"maintenance_until", "identity_domain", "last_connection_refusal", "enrolled_at",
	}

	for _, filter := range []url.Values{{}, {"connection_state": {"online"}}, {"os_family": {"debian"}}} {
		query := filter.Encode()
		if query != "" {
			query += "&"
		}
		var page struct {
			Total int `json:"total"`
		}
		h.get("/api/v1/hosts?"+query+"limit=1", &page)

		rows := csvExport(t, h, "/api/v1/hosts?"+query+"format=csv", "hosts")
		requireHeader(t, rows, wantHeader)
		if len(rows)-1 != page.Total {
			t.Errorf("the export filtered on %q has %d rows for a list of %d", query, len(rows)-1, page.Total)
		}
		for _, row := range rows[1:] {
			if state := filter.Get("connection_state"); state != "" && row[7] != state {
				t.Errorf("host %s is %s in an export filtered on %s", row[0], row[7], state)
			}
			if family := filter.Get("os_family"); family != "" && row[9] != family {
				t.Errorf("host %s is %s in an export filtered on %s", row[0], row[9], family)
			}
		}
	}

	// A format that is not one is refused, not answered with JSON.
	response, _ := h.request(http.MethodGet, "/api/v1/hosts?format=xlsx", nil, nil)
	if response.StatusCode != http.StatusBadRequest {
		t.Errorf("an unknown format answered %d, want 400", response.StatusCode)
	}
}

// TestJobListExportGuardsFormulas checks the task export against the paged
// JSON list of one host, and that a cell an operator typed cannot become a
// formula: a cancel reason beginning with '=' is written with a leading
func TestJobListExportGuardsFormulas(t *testing.T) {
	h := newHarness(t)
	host := h.hostByFamily("debian")

	job := h.createOperation(host.ID, map[string]any{
		"action":  "unit.restart",
		"payload": unitPayload("cron.service"),
	})
	if job.State != "awaiting_approval" {
		t.Fatalf("the restart is in state %s, expected awaiting_approval", job.State)
	}
	const reason = `=HYPERLINK("http://example.invalid") pasted into the reason`
	h.do(http.MethodPost, "/api/v1/jobs/"+job.ID+"/cancel", map[string]any{"reason": reason}, nil, http.StatusOK)

	// The JSON list of the host, every page of it: the export is to have
	// exactly these tasks.
	listed := map[string]bool{}
	cursor := ""
	for {
		var page struct {
			Items      []jobView `json:"items"`
			NextCursor string    `json:"next_cursor"`
		}
		h.get("/api/v1/jobs?host_id="+host.ID+"&limit=500&cursor="+url.QueryEscape(cursor), &page)
		for _, item := range page.Items {
			listed[item.ID] = true
		}
		if page.NextCursor == "" {
			break
		}
		cursor = page.NextCursor
	}

	rows := csvExport(t, h, "/api/v1/jobs?host_id="+host.ID+"&format=csv", "jobs")
	requireHeader(t, rows, []string{
		"id", "hostname", "host_id", "action_type", "state", "created_at", "created_by", "requires_approval",
		"approved_by", "approved_at", "finished_at", "result_status", "result_error_code", "result_message",
		"wait_reason", "canceled_by", "cancel_reason", "campaign_id", "fanout_id", "expires_at",
	})
	if len(rows)-1 != len(listed) {
		t.Errorf("the export has %d rows for a list of %d tasks", len(rows)-1, len(listed))
	}
	found := false
	for _, row := range rows[1:] {
		if !listed[row[0]] {
			t.Errorf("task %s is in the export but not on the list of host %s", row[0], host.Hostname)
		}
		if row[2] != host.ID {
			t.Errorf("task %s of host %s is in the export of host %s", row[0], row[2], host.ID)
		}
		if row[0] != job.ID {
			continue
		}
		found = true
		if row[4] != "canceled" {
			t.Errorf("the canceled task is exported in state %q", row[4])
		}
		if row[16] != "'"+reason {
			t.Errorf("the cancel reason is exported as %q, want it guarded with a leading apostrophe", row[16])
		}
		if row[5] == "" || !strings.HasSuffix(row[5], "Z") {
			t.Errorf("created_at is exported as %q, want RFC 3339 in UTC", row[5])
		}
	}
	if !found {
		t.Errorf("the canceled task %s is not in the export", job.ID)
	}
}

// TestBackupListExportsWhatTheScreenLists checks a fleet export built from a
// computed view rather than a paged table: the file has one row per item of
// the JSON answer, in its columns.
func TestBackupListExportsWhatTheScreenLists(t *testing.T) {
	h := newHarness(t)
	var view struct {
		Items []struct {
			HostID     string `json:"host_id"`
			Definition string `json:"definition"`
		} `json:"items"`
	}
	h.get("/api/v1/backups", &view)

	rows := csvExport(t, h, "/api/v1/backups?format=csv", "backups")
	requireHeader(t, rows, []string{
		"hostname", "host_id", "definition", "tool", "repository", "status", "last_success_at", "age_hours",
		"unverified", "last_restore_at",
	})
	if len(rows)-1 != len(view.Items) {
		t.Fatalf("the export has %d rows for a view of %d definitions", len(rows)-1, len(view.Items))
	}
	for i, item := range view.Items {
		row := rows[i+1]
		if row[1] != item.HostID || row[2] != item.Definition {
			t.Errorf("row %d is %s/%s, the view lists %s/%s", i, row[1], row[2], item.HostID, item.Definition)
		}
	}
}
