//go:build integration

package integration

import (
	"context"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"testing"
)

// attentionHostView is the part of a host the attention filters judge by:
// the facts the host reported and the placement an operator recorded.
type attentionHostView struct {
	ID                    string `json:"id"`
	Hostname              string `json:"hostname"`
	LifecycleState        string `json:"lifecycle_state"`
	AgentVersion          string `json:"agent_version"`
	FailureDomain         string `json:"failure_domain"`
	FailedUnits           *int   `json:"failed_units"`
	PackageDatabaseBroken bool   `json:"package_database_broken"`
	Identity              struct {
		Enrolled   bool  `json:"enrolled"`
		SSSDOnline *bool `json:"sssd_online"`
	} `json:"identity"`
}

// listHostsBy fetches the whole visible fleet narrowed by the query; the
// lab is far below one page, so a page is the fleet.
func listHostsBy(t *testing.T, h *harness, query url.Values) []attentionHostView {
	t.Helper()
	query.Set("limit", "500")
	var page struct {
		Items []attentionHostView `json:"items"`
	}
	h.get("/api/v1/hosts?"+query.Encode(), &page)
	return page.Items
}

// versionParts reads an agent version the way the database orders it:
// numerically, part by part.
func versionParts(version string) ([]int, bool) {
	version = strings.TrimPrefix(version, "v")
	if version == "" {
		return nil, false
	}
	var parts []int
	for _, part := range strings.Split(version, ".") {
		number, err := strconv.Atoi(part)
		if err != nil {
			// A suffix such as -rc1 stops the reading but does not void
			// the parts before it, as the database's pattern reads it.
			if len(parts) == 0 {
				return nil, false
			}
			break
		}
		parts = append(parts, number)
	}
	return parts, len(parts) > 0
}

func compareParts(a, b []int) int {
	for i := 0; i < len(a) && i < len(b); i++ {
		if a[i] != b[i] {
			if a[i] < b[i] {
				return -1
			}
			return 1
		}
	}
	return len(a) - len(b)
}

// TestHostListAttentionFiltersKeepOnlyTheHostsTheyName guards the filters the
// dashboard tiles link with: each keeps every host that satisfies it and no
// host that does not, a value that matches nothing gives an empty list rather
func TestHostListAttentionFiltersKeepOnlyTheHostsTheyName(t *testing.T) {
	h := newHarness(t)
	fleet := listHostsBy(t, h, url.Values{})
	if len(fleet) == 0 {
		t.Skip("the test fleet has no hosts")
	}
	byID := map[string]attentionHostView{}
	for _, host := range fleet {
		byID[host.ID] = host
	}

	// check asserts that the filtered list is exactly the hosts of the
	// fleet the predicate holds for.
	check := func(name string, query url.Values, holds func(attentionHostView) bool) {
		t.Helper()
		listed := listHostsBy(t, h, query)
		seen := map[string]bool{}
		for _, host := range listed {
			seen[host.ID] = true
			whole, known := byID[host.ID]
			if !known {
				t.Errorf("%s: host %s is on the filtered list but not in the fleet", name, host.Hostname)
				continue
			}
			if !holds(whole) {
				t.Errorf("%s: host %s is on the list without satisfying the filter: %+v", name, host.Hostname, whole)
			}
		}
		for _, host := range fleet {
			if holds(host) && !seen[host.ID] {
				t.Errorf("%s: host %s satisfies the filter and is missing from the list", name, host.Hostname)
			}
		}
	}

	check("failed_units=true", url.Values{"failed_units": {"true"}}, func(host attentionHostView) bool {
		return host.FailedUnits != nil && *host.FailedUnits > 0
	})
	check("failed_units=false", url.Values{"failed_units": {"false"}}, func(host attentionHostView) bool {
		return host.FailedUnits != nil && *host.FailedUnits == 0
	})
	check("package_db_broken=true", url.Values{"package_db_broken": {"true"}}, func(host attentionHostView) bool {
		return host.PackageDatabaseBroken && host.LifecycleState != "retired"
	})
	check("sssd_offline=true", url.Values{"sssd_offline": {"true"}}, func(host attentionHostView) bool {
		return host.Identity.Enrolled && host.Identity.SSSDOnline != nil && !*host.Identity.SSSDOnline &&
			host.LifecycleState != "retired"
	})
	check("sssd_offline=false", url.Values{"sssd_offline": {"false"}}, func(host attentionHostView) bool {
		return host.Identity.Enrolled && host.Identity.SSSDOnline != nil && *host.Identity.SSSDOnline
	})

	// The yardstick of "behind" is the newest version the fleet reports, as the
	// dashboard counts it; a host whose version does not parse is on neither
	// list.
	var newest []int
	for _, host := range fleet {
		if host.LifecycleState == "retired" {
			continue
		}
		if parts, ok := versionParts(host.AgentVersion); ok && (newest == nil || compareParts(parts, newest) > 0) {
			newest = parts
		}
	}
	if newest == nil {
		t.Fatalf("no host of the fleet reports a version that parses: %+v", fleet)
	}
	ordered := func(host attentionHostView) ([]int, bool) {
		if host.LifecycleState == "retired" {
			return nil, false
		}
		return versionParts(host.AgentVersion)
	}
	check("agent_behind=true", url.Values{"agent_behind": {"true"}}, func(host attentionHostView) bool {
		parts, ok := ordered(host)
		return ok && compareParts(parts, newest) < 0
	})
	check("agent_behind=false", url.Values{"agent_behind": {"false"}}, func(host attentionHostView) bool {
		parts, ok := ordered(host)
		return ok && compareParts(parts, newest) == 0
	})

	// The relay filter follows the open sessions, not the hosts: a host is behind
	// the relay only while its session says so.
	ctx := context.Background()
	var relayID string
	if err := h.database(ctx).QueryRow(ctx, `
		select id::text from relays where revoked_at is null
		order by enrolled_at desc limit 1`).Scan(&relayID); err == nil {
		rows, err := h.database(ctx).Query(ctx, `
			select host_id::text from agent_sessions
			where relay_id = $1::uuid and ended_at is null`, relayID)
		if err != nil {
			t.Fatal(err)
		}
		attested := map[string]bool{}
		for rows.Next() {
			var hostID string
			if err := rows.Scan(&hostID); err != nil {
				t.Fatal(err)
			}
			attested[hostID] = true
		}
		rows.Close()
		check("relay="+relayID, url.Values{"relay": {relayID}}, func(host attentionHostView) bool {
			return attested[host.ID]
		})
	}
	// A relay nobody enrolled is a valid question with an empty answer.
	if stray := listHostsBy(t, h, url.Values{"relay": {"00000000-0000-4000-8000-000000000000"}}); len(stray) != 0 {
		t.Errorf("a relay that does not exist attests %d hosts", len(stray))
	}

	// The failure domain is what an operator recorded; one host placed in a rack
	// of its own is the whole answer for that rack, and a rack nobody named is
	// empty.
	placed := h.placeInFailureDomain(fleet[0].ID, "integration-filter-rack")
	byDomain := listHostsBy(t, h, url.Values{"failure_domain": {"integration-filter-rack"}})
	if len(byDomain) != 1 || byDomain[0].ID != placed.ID {
		t.Errorf("the list of the rack is %+v, expected the one host %s", byDomain, fleet[0].Hostname)
	}
	if empty := listHostsBy(t, h, url.Values{"failure_domain": {"integration-rack-nobody-named"}}); len(empty) != 0 {
		t.Errorf("a rack nobody named holds %d hosts", len(empty))
	}

	// A value that is not a filter is the request's fault, named as such,
	// not a server fault and not a silent "no host".
	var problem struct {
		Code   string `json:"code"`
		Detail string `json:"detail"`
	}
	for _, query := range []string{"failed_units=maybe", "agent_behind=1.0", "relay=not-a-relay"} {
		h.do(http.MethodGet, "/api/v1/hosts?"+query, nil, &problem, http.StatusBadRequest)
		if problem.Code != "invalid_filter" {
			t.Errorf("%s was answered with %q (%s), expected invalid_filter", query, problem.Code, problem.Detail)
		}
	}
}

// TestFleetSummaryCountsTheDecisionsWaiting guards the counters behind the
// dashboard's "waiting for approval" tile and the sidebar's badges: the global
// test identity may read every list they count, so every counter is present,
func TestFleetSummaryCountsTheDecisionsWaiting(t *testing.T) {
	h := newHarness(t)
	var summary struct {
		JobsAwaitingApproval      *int `json:"jobs_awaiting_approval"`
		CampaignsAwaitingApproval *int `json:"campaigns_awaiting_approval"`
		CampaignsManualGate       *int `json:"campaigns_manual_gate"`
		HostsDrifted              *int `json:"hosts_drifted"`
		AlertsFiring              int  `json:"alerts_firing"`
	}
	h.get("/api/v1/fleet/summary", &summary)
	for name, value := range map[string]*int{
		"jobs_awaiting_approval":      summary.JobsAwaitingApproval,
		"campaigns_awaiting_approval": summary.CampaignsAwaitingApproval,
		"campaigns_manual_gate":       summary.CampaignsManualGate,
		"hosts_drifted":               summary.HostsDrifted,
	} {
		if value == nil {
			t.Errorf("the summary lacks %s for the global view", name)
		} else if *value < 0 {
			t.Errorf("%s = %d, a negative count", name, *value)
		}
	}
	if summary.AlertsFiring < 0 {
		t.Errorf("alerts_firing = %d, a negative count", summary.AlertsFiring)
	}

	// The campaign list filtered on the state is what the counter leads
	// to, and the two must agree while the list fits in one page.
	var campaigns struct {
		Items []struct {
			State string `json:"state"`
		} `json:"items"`
	}
	h.get("/api/v1/campaigns?state=awaiting_approval&limit=200", &campaigns)
	if summary.CampaignsAwaitingApproval != nil && len(campaigns.Items) < 200 &&
		*summary.CampaignsAwaitingApproval != len(campaigns.Items) {
		t.Errorf("campaigns_awaiting_approval = %d, the list has %d", *summary.CampaignsAwaitingApproval, len(campaigns.Items))
	}
	for _, campaign := range campaigns.Items {
		if campaign.State != "awaiting_approval" {
			t.Errorf("the list filtered on awaiting_approval carries a campaign in %s", campaign.State)
		}
	}
}
