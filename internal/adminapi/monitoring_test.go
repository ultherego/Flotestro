package adminapi

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/ultherego/flotestro/internal/authz"
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

// An alert rule carries a selector over hosts, and a selector is the shape of
// somebody's fleet: a rule reaches a reader only when the reader's scope
// covers everything the selector can reach.

// ruleOver is a rule named after what it watches, with the selector under
// test; the rest of it is what every rule of these tests would carry.
func ruleOver(name string, selector monitoring.Selector) monitoring.Rule {
	return monitoring.Rule{
		ID: name, Name: name, Metric: monitoring.MetricCPUPercent, Operator: "gt",
		Threshold: 90, Severity: "warning", Selector: selector, Enabled: true,
	}
}

// ruleNames reads back what a list carries, so a failure names the rule that
// crossed the boundary rather than a count.
func ruleNames(rules []monitoring.Rule) []string {
	names := make([]string, 0, len(rules))
	for _, rule := range rules {
		names = append(names, rule.Name)
	}
	return names
}

func TestAViewerScopedToOneSiteSeesOnlyTheAlertRulesOfThatSite(t *testing.T) {
	here := ruleOver("here", monitoring.Selector{Site: "lab", Environment: "test"})
	there := ruleOver("there", monitoring.Selector{Site: "elsewhere", Environment: "test"})
	otherEnvironment := ruleOver("other environment", monitoring.Selector{Site: "lab", Environment: "prod"})
	fleet := ruleOver("fleet", monitoring.Selector{})
	all := []monitoring.Rule{here, there, otherEnvironment, fleet}

	viewer := principalWith(authz.RoleViewer, labScope)
	visible := visibleRules(viewer, all)
	if names := ruleNames(visible); len(names) != 1 || names[0] != "here" {
		t.Fatalf("a viewer of one site sees %v, expected only the rule of that site", names)
	}
	// The same verdict by identifier: what the list leaves out, a direct read
	// refuses, and what it keeps a direct read answers.
	for _, rule := range []monitoring.Rule{there, otherEnvironment, fleet} {
		if viewer.Can(authz.PermMonitoringRead, ruleScope(rule.Selector)) {
			t.Errorf("a viewer of the lab may read the rule %q by identifier", rule.Name)
		}
	}
	if !viewer.Can(authz.PermMonitoringRead, ruleScope(here.Selector)) {
		t.Error("a viewer of the lab may not read the rule of the lab by identifier")
	}

	// The administrator of the whole installation still sees every one of them:
	// narrowing the answer is not hiding the rules from whoever owns them.
	admin := principalWith(authz.RolePlatformAdmin, authz.GlobalScope)
	if names := ruleNames(visibleRules(admin, all)); len(names) != len(all) {
		t.Errorf("a reader of the whole fleet sees %v, expected every rule", names)
	}
}

// A selector that names nothing covers every host, so only a reader of the
// whole fleet may have it. The same holds for a selector that narrows in a way
// the scope model cannot express: what the query cannot check is not checked
// as satisfied.
func TestAnAlertRuleTheScopeModelCannotExpressReachesOnlyAReaderOfTheWholeFleet(t *testing.T) {
	rules := []monitoring.Rule{
		ruleOver("nothing named", monitoring.Selector{}),
		ruleOver("by operating system", monitoring.Selector{OSFamily: "debian"}),
		ruleOver("by expression", monitoring.Selector{Expression: "site = elsewhere"}),
		ruleOver("by group", monitoring.Selector{Groups: []string{"databases"}}),
		ruleOver("by host", monitoring.Selector{HostIDs: []string{"3f2504e0-4f89-11d3-9a0c-0305e82c3301"}}),
	}
	viewer := principalWith(authz.RoleViewer, labScope)
	if names := ruleNames(visibleRules(viewer, rules)); len(names) != 0 {
		t.Errorf("a viewer of one site sees %v, expected none of them", names)
	}
	admin := principalWith(authz.RolePlatformAdmin, authz.GlobalScope)
	if names := ruleNames(visibleRules(admin, rules)); len(names) != len(rules) {
		t.Errorf("a reader of the whole fleet sees %v, expected every rule", names)
	}
}

// The scope of a rule is what its selector names, category by category, and a
// category the selector leaves open is left open rather than filled with a
// wildcard: the five categories are site, environment, team, owner and tag.
func TestTheScopeOfAnAlertRuleIsWhatItsSelectorNames(t *testing.T) {
	scope := ruleScope(monitoring.Selector{
		Site: "lab", Environment: "test", Owner: "payments", Tags: []string{"role=db"},
	})
	if scope.Site != "lab" || scope.Environment != "test" {
		t.Errorf("the placement of the rule is %s", scope)
	}
	// A selector carries no team at all, so a binding narrowed to one team
	// reaches no rule: the rule watches the hosts of every team that matches.
	if scope.TeamAny || scope.Team != "" {
		t.Errorf("the rule claims a team: %s", scope)
	}
	team := principalWith(authz.RoleViewer, authz.OfTeam("11111111-1111-1111-1111-111111111111"))
	if team.Can(authz.PermMonitoringRead, scope) {
		t.Error("a viewer bound to one team reads a rule that names no team")
	}

	// Owner and tag are categories of their own, and each narrows on its own.
	ofAnotherOwner := authz.Scope{
		Site: authz.Wildcard, Environment: authz.Wildcard, TeamAny: true,
		Owners: []string{"billing"}, Tags: []string{authz.Wildcard},
	}
	if principalWith(authz.RoleViewer, ofAnotherOwner).Can(authz.PermMonitoringRead, scope) {
		t.Error("a viewer of another owner reads a rule about the hosts of payments")
	}
	ofTheOwner := ofAnotherOwner
	ofTheOwner.Owners = []string{"payments"}
	if !principalWith(authz.RoleViewer, ofTheOwner).Can(authz.PermMonitoringRead, scope) {
		t.Error("a viewer of the owner may not read a rule about that owner's hosts")
	}
	ofAnotherTag := ofAnotherOwner
	ofAnotherTag.Owners = []string{authz.Wildcard}
	ofAnotherTag.Tags = []string{"role=web"}
	if principalWith(authz.RoleViewer, ofAnotherTag).Can(authz.PermMonitoringRead, scope) {
		t.Error("a viewer of the web hosts reads a rule about the database hosts")
	}
}

// Nobody at all is not everybody: a principal whose binding has run out keeps
// none of the rules it used to read.
func TestAPrincipalWithoutMonitoringReadSeesNoAlertRuleAtAll(t *testing.T) {
	rules := []monitoring.Rule{
		ruleOver("here", monitoring.Selector{Site: "lab", Environment: "test"}),
		ruleOver("fleet", monitoring.Selector{}),
	}
	if names := ruleNames(visibleRules(authz.Principal{}, rules)); len(names) != 0 {
		t.Errorf("an identity with no binding sees %v", names)
	}
	// A right over something else is not a right over the rules.
	approver := principalWith(authz.RoleApprover, authz.GlobalScope)
	if names := ruleNames(visibleRules(approver, rules)); len(names) != 0 {
		t.Errorf("an approver, who has no monitoring.read, sees %v", names)
	}
}
