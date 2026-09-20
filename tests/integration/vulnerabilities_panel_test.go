//go:build integration

package integration

import (
	"net/http"
	"net/url"
	"strings"
	"testing"
)

// cveRowView mirrors one row of the CVE list of the fleet screen.
type cveRowView struct {
	CVE                string   `json:"cve"`
	Severity           string   `json:"severity"`
	VendorSeverity     string   `json:"vendor_severity"`
	CVSSScore          *float64 `json:"cvss_score"`
	Hosts              int      `json:"hosts"`
	HostsWithVendorFix int      `json:"hosts_with_vendor_fix"`
	Packages           []string `json:"packages"`
	FirstSeen          string   `json:"first_seen"`
}

type cveListView struct {
	Items  []cveRowView `json:"items"`
	Count  int          `json:"count"`
	Total  int          `json:"total"`
	Limit  int          `json:"limit"`
	Offset int          `json:"offset"`
}

// cveReportView mirrors the page of one CVE.
type cveReportView struct {
	CVE      string `json:"cve"`
	Severity string `json:"severity"`
	Details  *struct {
		Source    string   `json:"source"`
		CVSSScore *float64 `json:"cvss_score"`
		Summary   string   `json:"summary"`
	} `json:"details"`
	References []struct {
		Provider   string `json:"provider"`
		AdvisoryID string `json:"advisory_id"`
	} `json:"references"`
	Hosts []struct {
		HostID           string `json:"host_id"`
		Hostname         string `json:"hostname"`
		Package          string `json:"package"`
		InstalledVersion string `json:"installed_version"`
		FixedVersion     string `json:"fixed_version"`
		State            string `json:"state"`
		VendorFix        string `json:"vendor_fix"`
		Severity         string `json:"severity"`
	} `json:"hosts"`
	HostsTotal         int      `json:"hosts_total"`
	AffectedHosts      int      `json:"affected_hosts"`
	UndecidedHosts     int      `json:"undecided_hosts"`
	HostsWithVendorFix int      `json:"hosts_with_vendor_fix"`
	Packages           []string `json:"packages"`
	Truncated          bool     `json:"truncated"`
}

// severityRank orders the canonical severities the way the list sorts.
var severityRank = map[string]int{
	"critical": 0, "high": 1, "medium": 2, "low": 3, "negligible": 4, "unrated": 5,
}

// TestCVEListAgreesWithTheCVEPage guards that the fleet's CVE list and the
// page of one CVE tell the same story about host count and severity.
func TestCVEListAgreesWithTheCVEPage(t *testing.T) {
	h := newHarness(t)
	var list cveListView
	h.get("/api/v1/vulnerabilities/cves?limit=20", &list)
	if list.Total == 0 || len(list.Items) == 0 {
		t.Skip("the test fleet has no affected finding with a CVE number")
	}
	if list.Count != len(list.Items) {
		t.Errorf("count %d with %d items", list.Count, len(list.Items))
	}

	// The gravest first, then the most widespread.
	for i := 1; i < len(list.Items); i++ {
		previous, current := list.Items[i-1], list.Items[i]
		if severityRank[previous.Severity] > severityRank[current.Severity] {
			t.Errorf("row %d (%s, %s) sorted above row %d (%s, %s)", i-1, previous.CVE,
				previous.Severity, i, current.CVE, current.Severity)
		}
		if previous.Severity == current.Severity && previous.Hosts < current.Hosts {
			t.Errorf("%s on %d hosts sorted above %s on %d hosts", previous.CVE,
				previous.Hosts, current.CVE, current.Hosts)
		}
	}

	for _, row := range list.Items {
		if !cvePattern.MatchString(row.CVE) {
			t.Errorf("a row that is not a CVE number: %q", row.CVE)
		}
		if row.Hosts == 0 {
			t.Errorf("%s listed with no host", row.CVE)
		}
		if row.HostsWithVendorFix > row.Hosts {
			t.Errorf("%s: %d hosts with a fix out of %d", row.CVE, row.HostsWithVendorFix, row.Hosts)
		}
		if len(row.Packages) == 0 {
			t.Errorf("%s listed without a package", row.CVE)
		}
	}

	// The row with the most hosts is the sharpest test of the count.
	chosen := list.Items[0]
	for _, row := range list.Items {
		if row.Hosts > chosen.Hosts {
			chosen = row
		}
	}

	// The search is a prefix: the number itself is found, and so may be a
	// longer number that begins with it - never a row that does not.
	var found cveListView
	h.get("/api/v1/vulnerabilities/cves?q="+url.QueryEscape(chosen.CVE), &found)
	matched := false
	for _, row := range found.Items {
		if !strings.HasPrefix(row.CVE, chosen.CVE) {
			t.Errorf("searching %s returned %s", chosen.CVE, row.CVE)
		}
		if row.CVE == chosen.CVE {
			matched = true
			if row.Hosts != chosen.Hosts {
				t.Errorf("%s: %d hosts on the search, %d on the list", chosen.CVE, row.Hosts, chosen.Hosts)
			}
		}
	}
	if !matched {
		t.Fatalf("searching %s found %d rows and not that one", chosen.CVE, len(found.Items))
	}

	var page cveReportView
	h.get("/api/v1/vulnerabilities/cves/"+chosen.CVE, &page)
	if page.CVE != chosen.CVE {
		t.Fatalf("the page answers about %q", page.CVE)
	}
	if page.Truncated {
		t.Fatalf("the test fleet cannot put %s on more than %d rows", chosen.CVE, page.HostsTotal)
	}
	affected := map[string]bool{}
	for _, host := range page.Hosts {
		if host.HostID == "" || host.Hostname == "" || host.Package == "" {
			t.Errorf("a row of %s without a host or a package: %+v", chosen.CVE, host)
		}
		if host.State == "affected" {
			affected[host.HostID] = true
		}
	}
	if len(affected) != chosen.Hosts {
		t.Errorf("%s: the list counts %d hosts, the page lists %d affected ones",
			chosen.CVE, chosen.Hosts, len(affected))
	}
	if page.AffectedHosts != len(affected) {
		t.Errorf("%s: the page counts %d affected hosts and lists %d", chosen.CVE, page.AffectedHosts, len(affected))
	}
	if page.HostsWithVendorFix != chosen.HostsWithVendorFix {
		t.Errorf("%s: %d hosts with a fix on the list, %d on the page", chosen.CVE,
			chosen.HostsWithVendorFix, page.HostsWithVendorFix)
	}
	if page.Severity != chosen.Severity {
		t.Errorf("%s: severity %q on the list, %q on the page", chosen.CVE, chosen.Severity, page.Severity)
	}
	if len(page.Packages) < len(chosen.Packages) {
		t.Errorf("%s: %d packages on the list, %d on the page", chosen.CVE, len(chosen.Packages), len(page.Packages))
	}

	// The severity filter keeps only rows of that word, and the fix filter
	// only rows with a fix somewhere.
	var filtered cveListView
	h.get("/api/v1/vulnerabilities/cves?severity="+chosen.Severity+"&fixable=true", &filtered)
	for _, row := range filtered.Items {
		if row.Severity != chosen.Severity {
			t.Errorf("filtering by %s returned %s (%s)", chosen.Severity, row.CVE, row.Severity)
		}
		if row.HostsWithVendorFix == 0 {
			t.Errorf("filtering by fixable returned %s with no fix", row.CVE)
		}
	}
}

// TestCVEPageRefusesWhatIsNotACVE guards that the page takes only a CVE number
// and says so when nothing is known about the one asked for: an empty page for
// a typo would read as "no host is affected".
func TestCVEPageRefusesWhatIsNotACVE(t *testing.T) {
	h := newHarness(t)
	h.do(http.MethodGet, "/api/v1/vulnerabilities/cves/openssl", nil, nil, http.StatusBadRequest)
	h.do(http.MethodGet, "/api/v1/vulnerabilities/cves/CVE-1999-0000001", nil, nil, http.StatusNotFound)
	h.do(http.MethodGet, "/api/v1/vulnerabilities/cves?severity=grave", nil, nil, http.StatusBadRequest)
}

// TestFleetHostTableFiltersWithoutMovingTheSummary guards that the host table
// of the fleet screen narrows by hostname, severity and page while the numbers
// above it keep describing the whole visible fleet.
func TestFleetHostTableFiltersWithoutMovingTheSummary(t *testing.T) {
	h := newHarness(t)
	// The summary next to the rows: the numbers a filter must not move.
	type fleetTableView struct {
		Affected   int `json:"affected"`
		HostsTotal int `json:"hosts_total"`
		Count      int `json:"count"`
		Total      int `json:"total"`
		Offset     int `json:"offset"`
		Rows       []struct {
			HostID     string         `json:"host_id"`
			Hostname   string         `json:"hostname"`
			Affected   int            `json:"affected"`
			BySeverity map[string]int `json:"by_severity"`
		} `json:"items"`
	}
	var whole fleetTableView
	h.get("/api/v1/vulnerabilities", &whole)
	if whole.Total == 0 || len(whole.Rows) == 0 {
		t.Fatal("the fleet screen without hosts")
	}
	if whole.Total != whole.HostsTotal {
		t.Errorf("the unfiltered table counts %d rows for %d hosts", whole.Total, whole.HostsTotal)
	}

	// One host by name: the table shrinks to it, the summary does not.
	chosen := whole.Rows[0]
	if chosen.Hostname == "" {
		t.Fatalf("the first row has no hostname: %+v", chosen)
	}
	var byName fleetTableView
	h.get("/api/v1/vulnerabilities?q="+url.QueryEscape(chosen.Hostname)+"&limit=1", &byName)
	if len(byName.Rows) != 1 || byName.Rows[0].HostID != chosen.HostID {
		t.Fatalf("searching %q returned %d rows", chosen.Hostname, len(byName.Rows))
	}
	if byName.Affected != whole.Affected || byName.HostsTotal != whole.HostsTotal {
		t.Errorf("the search moved the summary: %d/%d findings, %d/%d hosts",
			byName.Affected, whole.Affected, byName.HostsTotal, whole.HostsTotal)
	}

	// The page after the first is the rest of the same order.
	var second fleetTableView
	h.get("/api/v1/vulnerabilities?limit=1&offset=1", &second)
	if second.Offset != 1 {
		t.Errorf("offset %d", second.Offset)
	}
	if len(whole.Rows) > 1 && (len(second.Rows) != 1 || second.Rows[0].HostID != whole.Rows[1].HostID) {
		t.Errorf("the second page does not continue the first")
	}

	// A severity filter keeps the hosts with a finding of that word, and every
	// row of the unfiltered table carries the counts the filter reads.
	for _, row := range whole.Rows {
		sum := 0
		for _, count := range row.BySeverity {
			sum += count
		}
		if sum != row.Affected {
			t.Errorf("%s: %d findings by severity, %d affected", row.Hostname, sum, row.Affected)
		}
	}
	var high fleetTableView
	h.get("/api/v1/vulnerabilities?severity=high", &high)
	for _, row := range high.Rows {
		if row.BySeverity["high"] == 0 {
			t.Errorf("%s listed under high without a high finding", row.Hostname)
		}
	}
}
