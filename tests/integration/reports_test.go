//go:build integration

package integration

import (
	"net/http"
	"net/url"
	"testing"
	"time"
)

// The management reports against the lab: each one is a read over the
// records the other screens show, so each is checked against the screen
// it summarises - the host list, the campaign, the policy results.

type patchStatusReportView struct {
	Report string `json:"report"`
	Totals struct {
		Hosts           int `json:"hosts"`
		FullyPatched    int `json:"fully_patched"`
		SecurityUnknown int `json:"security_unknown"`
		RebootBacklog   int `json:"reboot_backlog"`
		RebootUnknown   int `json:"reboot_unknown"`
	} `json:"totals"`
	BySite []struct {
		Key   string `json:"key"`
		Hosts int    `json:"hosts"`
	} `json:"by_site"`
	Hosts []struct {
		HostID                 string `json:"host_id"`
		Hostname               string `json:"hostname"`
		PendingSecurityUpdates *int   `json:"pending_security_updates"`
		RebootRequired         *bool  `json:"reboot_required"`
		Campaigns              *int   `json:"campaigns"`
	} `json:"hosts"`
	HostsListed    int  `json:"hosts_listed"`
	HostsTruncated bool `json:"hosts_truncated"`
}

// reportPeriod is the query of a report over the last day, ending a
// minute from now so a record written while the test runs is inside it.
func reportPeriod(back time.Duration) string {
	now := time.Now().UTC()
	return url.Values{
		"from": {now.Add(-back).Format(time.RFC3339)},
		"to":   {now.Add(time.Minute).Format(time.RFC3339)},
	}.Encode()
}

// TestPatchStatusReportListsEveryVisibleHostOnce checks the patch report
// against the host list: every host of the list once, the total equal to
// the list's, the unknowns counted apart from the zeros, the breakdown
// by site summing to the total, and the file with the fixed header.
func TestPatchStatusReportListsEveryVisibleHostOnce(t *testing.T) {
	h := newHarness(t)
	var list struct {
		Total int `json:"total"`
	}
	h.get("/api/v1/hosts?limit=1", &list)

	var report patchStatusReportView
	h.get("/api/v1/reports/patch-status?"+reportPeriod(24*time.Hour), &report)
	if report.Report != "patch-status" {
		t.Fatalf("the document names itself %q", report.Report)
	}
	if report.Totals.Hosts != list.Total {
		t.Errorf("the report counts %d hosts, the list has %d", report.Totals.Hosts, list.Total)
	}
	if report.HostsTruncated || report.HostsListed != len(report.Hosts) || len(report.Hosts) != list.Total {
		t.Errorf("the report lists %d hosts (listed %d, truncated %v) for a fleet of %d",
			len(report.Hosts), report.HostsListed, report.HostsTruncated, list.Total)
	}
	seen := map[string]bool{}
	patched, securityUnknown, backlog, rebootUnknown := 0, 0, 0, 0
	for _, host := range report.Hosts {
		if seen[host.HostID] {
			t.Errorf("host %s is listed twice", host.Hostname)
		}
		seen[host.HostID] = true
		switch {
		case host.PendingSecurityUpdates == nil:
			securityUnknown++
		case *host.PendingSecurityUpdates == 0:
			patched++
		}
		switch {
		case host.RebootRequired == nil:
			rebootUnknown++
		case *host.RebootRequired:
			backlog++
		}
		// The admin token reads campaigns, so the column is there.
		if host.Campaigns == nil {
			t.Errorf("host %s has no campaign count for a reader who may read campaigns", host.Hostname)
		}
	}
	if report.Totals.FullyPatched != patched || report.Totals.SecurityUnknown != securityUnknown {
		t.Errorf("the totals say %d patched and %d unknown, the rows %d and %d",
			report.Totals.FullyPatched, report.Totals.SecurityUnknown, patched, securityUnknown)
	}
	if report.Totals.RebootBacklog != backlog || report.Totals.RebootUnknown != rebootUnknown {
		t.Errorf("the totals say a reboot backlog of %d and %d unknown, the rows %d and %d",
			report.Totals.RebootBacklog, report.Totals.RebootUnknown, backlog, rebootUnknown)
	}
	bySite := 0
	for _, site := range report.BySite {
		bySite += site.Hosts
	}
	if bySite != report.Totals.Hosts {
		t.Errorf("the sites sum to %d hosts, the total is %d", bySite, report.Totals.Hosts)
	}

	rows := csvExport(t, h, "/api/v1/reports/patch-status?"+reportPeriod(24*time.Hour)+"&format=csv", "report-patch-status")
	requireHeader(t, rows, []string{
		"hostname", "id", "site", "environment", "lifecycle_state", "connection_state", "agent_version",
		"last_seen_at", "pending_updates", "pending_security_updates", "reboot_required",
		"last_upgrade_at", "campaigns",
	})
	if len(rows)-1 != list.Total {
		t.Errorf("the file has %d rows for a fleet of %d", len(rows)-1, list.Total)
	}

	// A period given by one end alone is refused, and so is a report
	// nobody has.
	response, _ := h.request(http.MethodGet, "/api/v1/reports/patch-status?from=2026-01-01T00:00:00Z", nil, nil)
	if response.StatusCode != http.StatusBadRequest {
		t.Errorf("a half period answered %d, want 400", response.StatusCode)
	}
	response, _ = h.request(http.MethodGet, "/api/v1/reports/nothing", nil, nil)
	if response.StatusCode != http.StatusNotFound {
		t.Errorf("an unknown report answered %d, want 404", response.StatusCode)
	}
}

type campaignsReportView struct {
	Campaigns []struct {
		ID        string `json:"id"`
		State     string `json:"state"`
		Requester string `json:"requester"`
		Targets   int    `json:"targets"`
		Canceled  int    `json:"canceled"`
		BySite    []struct {
			Key     string `json:"key"`
			Targets int    `json:"targets"`
		} `json:"by_site"`
		SuccessRate *float64 `json:"success_rate"`
	} `json:"campaigns"`
	Totals struct {
		Campaigns int            `json:"campaigns"`
		ByState   map[string]int `json:"by_state"`
		Targets   int            `json:"targets"`
	} `json:"totals"`
}

// TestCampaignsReportCountsACanceledCampaign checks that a campaign that
// closed in the period is in the report whatever its end: a campaign
// ordered and canceled before any host started is a canceled campaign of
// the period, with its hosts counted as canceled and no success rate,
// because nothing was attempted.
func TestCampaignsReportCountsACanceledCampaign(t *testing.T) {
	h := newHarness(t)
	host := h.hostByFamily("debian")
	campaign := h.createCampaign(labCampaign("report of a canceled campaign", "cron.service", map[string]any{
		"selector":    map[string]any{"host_ids": []string{host.ID}},
		"canary_size": 0,
	}))
	var canceled campaignView
	h.do(http.MethodPost, "/api/v1/campaigns/"+campaign.ID+"/cancel",
		map[string]any{"reason": "the report needs a closed campaign"}, &canceled, http.StatusOK)
	if canceled.State != "canceled" {
		t.Fatalf("the cancel of a campaign nobody started answered %s, expected canceled", canceled.State)
	}

	var report campaignsReportView
	h.get("/api/v1/reports/campaigns?"+reportPeriod(time.Hour), &report)
	found := false
	for _, row := range report.Campaigns {
		if row.ID != campaign.ID {
			continue
		}
		found = true
		if row.State != "canceled" {
			t.Errorf("the campaign is %s in the report, expected canceled", row.State)
		}
		if row.Targets != 1 || row.Canceled != 1 {
			t.Errorf("the campaign has %d targets of which %d canceled, expected 1 and 1", row.Targets, row.Canceled)
		}
		if row.SuccessRate != nil {
			t.Errorf("a campaign nothing was attempted in has a success rate of %v", *row.SuccessRate)
		}
		if len(row.BySite) != 1 || row.BySite[0].Key != host.Site || row.BySite[0].Targets != 1 {
			t.Errorf("the split by site is %+v, expected one host in %s", row.BySite, host.Site)
		}
	}
	if !found {
		t.Fatalf("the report of the last hour does not list campaign %s", campaign.ID)
	}
	if report.Totals.Campaigns != len(report.Campaigns) {
		t.Errorf("the totals count %d campaigns, the report lists %d", report.Totals.Campaigns, len(report.Campaigns))
	}
	byState := 0
	for _, count := range report.Totals.ByState {
		byState += count
	}
	if byState != report.Totals.Campaigns || report.Totals.ByState["canceled"] < 1 {
		t.Errorf("the states %v do not add up to %d campaigns with the canceled one among them",
			report.Totals.ByState, report.Totals.Campaigns)
	}

	rows := csvExport(t, h, "/api/v1/reports/campaigns?"+reportPeriod(time.Hour)+"&format=csv", "report-campaigns")
	requireHeader(t, rows, []string{
		"id", "name", "operation", "state", "requester", "approver", "created_at", "started_at", "finished_at",
		"duration_seconds", "targets", "succeeded", "no_change", "failed", "unknown", "skipped", "canceled",
		"success_rate", "by_site",
	})
	if len(rows)-1 != len(report.Campaigns) {
		t.Errorf("the file has %d rows for a report of %d campaigns", len(rows)-1, len(report.Campaigns))
	}
}

type complianceReportView struct {
	Policies *struct {
		Policies []struct {
			ID            string         `json:"id"`
			Hosts         int            `json:"hosts"`
			Compliant     int            `json:"compliant"`
			Drift         int            `json:"drift"`
			Error         int            `json:"error"`
			NotApplicable int            `json:"not_applicable"`
			Unknown       int            `json:"unknown"`
			Rules         map[string]int `json:"rules"`
			DriftHosts    []struct {
				HostID string `json:"host_id"`
			} `json:"drift_hosts"`
		} `json:"policies"`
		Totals struct {
			Policies     int `json:"policies"`
			HostsInDrift int `json:"hosts_in_drift"`
		} `json:"totals"`
	} `json:"policies"`
	Security *struct {
		Hosts      int `json:"hosts"`
		BySeverity []struct {
			Severity string `json:"severity"`
			Failed   int    `json:"failed"`
		} `json:"by_severity"`
		Checks []struct {
			CheckID string `json:"check_id"`
		} `json:"checks"`
	} `json:"security"`
}

// TestComplianceReportAgreesWithThePolicyResults checks the compliance
// report against the results list of a policy the test publishes and
// evaluates: the rule tally by verdict equals the list's counts, the
// hosts add up across the verdicts, and the security section is there
// for a reader with the right to it.
func TestComplianceReportAgreesWithThePolicyResults(t *testing.T) {
	h := newHarness(t)
	policy := h.createPolicy(t, uniqueSubject("report-cron"), "report", []map[string]any{
		{"kind": "unit_state", "unit": "cron.service", "enabled": true, "active": true},
	})
	h.publishPolicy(t, policy.ID)
	outcome := h.evaluatePolicy(t, policy.ID)

	var report complianceReportView
	h.get("/api/v1/reports/compliance?"+reportPeriod(time.Hour), &report)
	if report.Policies == nil {
		t.Fatal("the report has no policy section for a reader who may read policies")
	}
	if report.Security == nil {
		t.Fatal("the report has no security section for a reader who may read security")
	}
	if report.Policies.Totals.Policies != len(report.Policies.Policies) {
		t.Errorf("the totals count %d policies, the report lists %d",
			report.Policies.Totals.Policies, len(report.Policies.Policies))
	}
	found := false
	for _, row := range report.Policies.Policies {
		if row.ID != policy.ID {
			continue
		}
		found = true
		if row.Hosts != outcome.Hosts {
			t.Errorf("the report counts %d hosts under the policy, the evaluation covered %d", row.Hosts, outcome.Hosts)
		}
		if sum := row.Compliant + row.Drift + row.Error + row.NotApplicable + row.Unknown; sum != row.Hosts {
			t.Errorf("the verdicts add up to %d hosts of %d", sum, row.Hosts)
		}
		if row.Unknown != 0 {
			t.Errorf("%d hosts are unknown in a period that ends after the evaluation", row.Unknown)
		}
		if len(row.DriftHosts) != row.Drift {
			t.Errorf("the row names %d drift hosts and counts %d", len(row.DriftHosts), row.Drift)
		}
		for _, verdict := range []string{"compliant", "drift", "error", "not_applicable"} {
			var page struct {
				Total int `json:"total"`
			}
			h.get("/api/v1/policies/"+policy.ID+"/results?verdict="+verdict+"&limit=1", &page)
			if row.Rules[verdict] != page.Total {
				t.Errorf("the report tallies %d %s rules, the results list %d", row.Rules[verdict], verdict, page.Total)
			}
		}
	}
	if !found {
		t.Fatalf("the report does not list policy %s", policy.ID)
	}
	if report.Security.Hosts == 0 || len(report.Security.Checks) == 0 {
		t.Errorf("the security section judged %d hosts with %d checks", report.Security.Hosts, len(report.Security.Checks))
	}

	rows := csvExport(t, h, "/api/v1/reports/compliance?"+reportPeriod(time.Hour)+"&format=csv", "report-compliance-policies")
	requireHeader(t, rows, []string{
		"policy_id", "name", "version", "enabled", "remediation_mode", "last_evaluated_at", "hosts",
		"compliant", "drift", "error", "not_applicable", "unknown", "drift_hosts",
	})
	if len(rows)-1 != len(report.Policies.Policies) {
		t.Errorf("the file has %d rows for a report of %d policies", len(rows)-1, len(report.Policies.Policies))
	}
	rows = csvExport(t, h, "/api/v1/reports/compliance?section=security&"+reportPeriod(time.Hour)+"&format=csv", "report-compliance-security")
	requireHeader(t, rows, []string{"check_id", "title", "severity", "failed", "passed", "unknown", "not_applicable"})
	if len(rows)-1 != len(report.Security.Checks) {
		t.Errorf("the security file has %d rows for %d checks", len(rows)-1, len(report.Security.Checks))
	}
}
