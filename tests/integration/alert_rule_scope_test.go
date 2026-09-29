//go:build integration

package integration

import (
	"fmt"
	"net/http"
	"testing"
	"time"
)

// An alert rule carries a selector over hosts, so a rule tells whoever reads it
// what stands in the part of the fleet it watches. The panel therefore answers
// with the rules the caller may read the subject of, and refuses the rest by
// identifier the way it refuses a notification channel of another site.

// scopedRuleView is a rule with the part of its selector these tests read.
type scopedRuleView struct {
	ID       string `json:"id"`
	Name     string `json:"name"`
	Selector struct {
		Site        string `json:"site"`
		Environment string `json:"environment"`
	} `json:"selector"`
}

type scopedRuleList struct {
	Items []scopedRuleView `json:"items"`
	Count int              `json:"count"`
}

func (list scopedRuleList) holds(id string) bool {
	for _, rule := range list.Items {
		if rule.ID == id {
			return true
		}
	}
	return false
}

// createScopedRule writes a rule nobody would write for real - the busy time of
// a host never passes a hundred and one per cent - over the given placement,
// and takes it away when the test is done.
func createScopedRule(h *harness, name, site, environment string) scopedRuleView {
	h.t.Helper()
	selector := map[string]any{}
	if site != "" {
		selector["site"] = site
	}
	if environment != "" {
		selector["environment"] = environment
	}
	var rule scopedRuleView
	h.do(http.MethodPost, "/api/v1/monitoring/rules", map[string]any{
		"name":   fmt.Sprintf("integration: rule scope %s %d", name, time.Now().UnixNano()),
		"metric": "cpu_percent", "operator": "gt", "threshold": 101,
		"for_minutes": 0, "severity": "info", "enabled": false,
		"selector": selector,
	}, &rule, http.StatusCreated)
	if rule.ID == "" {
		h.t.Fatalf("the rule %s came back without an identifier", name)
	}
	h.t.Cleanup(func() {
		h.do(http.MethodDelete, "/api/v1/monitoring/rules/"+rule.ID, nil, nil, 0)
	})
	return rule
}

// TestAViewerOfOneSiteReadsOnlyTheAlertRulesOfThatSite pins the boundary on a
// running panel: by list and by identifier, and in both directions - what the
// viewer of the lab may read they do read.
func TestAViewerOfOneSiteReadsOnlyTheAlertRulesOfThatSite(t *testing.T) {
	h := newHarness(t)
	here := createScopedRule(h, "lab", "lab", "test")
	there := createScopedRule(h, "elsewhere", "elsewhere", "test")
	fleet := createScopedRule(h, "fleet", "", "")

	viewer := h.withToken(h.createPrincipal(uniqueSubject("viewer-lab-rules"), []map[string]string{
		{"role": "viewer", "site": "lab", "environment": "test"},
	}))

	var seen scopedRuleList
	viewer.get("/api/v1/monitoring/rules", &seen)
	if !seen.holds(here.ID) {
		t.Errorf("a viewer of the lab does not see the rule of the lab: %+v", seen.Items)
	}
	if seen.holds(there.ID) {
		t.Error("a viewer of the lab sees the rule of another site, and its selector with it")
	}
	if seen.holds(fleet.ID) {
		t.Error("a viewer of the lab sees a rule that watches the whole fleet")
	}
	if seen.Count != len(seen.Items) {
		t.Errorf("the count says %d for %d rows", seen.Count, len(seen.Items))
	}
	// Every rule that did come back is one of this site: nothing else slipped
	// through under a selector this test did not write.
	for _, rule := range seen.Items {
		if rule.Selector.Site != "lab" {
			t.Errorf("the rule %q of site %q reached a viewer of the lab", rule.Name, rule.Selector.Site)
		}
	}

	// By identifier the answer is a refusal with the scope on the trail, not an
	// empty rule and not a "no such rule" that would leave the caller guessing
	// whether it exists at all.
	var refusal struct {
		Code string `json:"code"`
	}
	for _, rule := range []scopedRuleView{there, fleet} {
		refusal.Code = ""
		viewer.do(http.MethodGet, "/api/v1/monitoring/rules/"+rule.ID, nil, &refusal, http.StatusForbidden)
		if refusal.Code != "permission_denied" {
			t.Errorf("reading the rule %s was refused as %q", rule.ID, refusal.Code)
		}
	}
	var own scopedRuleView
	viewer.get("/api/v1/monitoring/rules/"+here.ID, &own)
	if own.ID != here.ID {
		t.Errorf("a viewer of the lab read its own rule as %+v", own)
	}

	// The administrator of the installation still has all three: the boundary
	// narrows the answer, it does not take the rules away from their owner.
	var all scopedRuleList
	h.get("/api/v1/monitoring/rules", &all)
	for _, rule := range []scopedRuleView{here, there, fleet} {
		if !all.holds(rule.ID) {
			t.Errorf("the administrator does not see the rule %s", rule.ID)
		}
	}
}
