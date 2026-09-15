//go:build integration

package integration

import (
	"fmt"
	"net/http"
	"net/url"
	"regexp"
	"sort"
	"testing"
)

// factsHostView is the part of a host the live-selector tests read: the
// health facts and the agent version the selector keys compare.
type factsHostView struct {
	ID                     string `json:"id"`
	Hostname               string `json:"hostname"`
	ConnectionState        string `json:"connection_state"`
	AgentVersion           string `json:"agent_version"`
	PendingSecurityUpdates *int   `json:"pending_security_updates"`
	RebootRequired         *bool  `json:"reboot_required"`
}

// factsHosts reads the fleet with the facts the selector keys compare.
func (h *harness) factsHosts() []factsHostView {
	h.t.Helper()
	var result struct {
		Items []factsHostView `json:"items"`
	}
	h.get("/api/v1/hosts?limit=500", &result)
	return result.Items
}

// previewOf runs the campaign preview on a typed selector and returns the
// count and the sample of hostnames it answers.
func (h *harness) previewOf(expression string) (int, []string) {
	h.t.Helper()
	var preview struct {
		Count  int      `json:"count"`
		Sample []string `json:"sample"`
	}
	h.get("/api/v1/campaigns/preview?expression="+url.QueryEscape(expression), &preview)
	sort.Strings(preview.Sample)
	return preview.Count, preview.Sample
}

// TestSelectorNamesHostsByTheirHealthFacts: a selector on a health fact
// picks exactly the hosts whose record carries the fact. A host that has
// not reported the fact is in neither answer - unknown is not "none".
func TestSelectorNamesHostsByTheirHealthFacts(t *testing.T) {
	h := newHarness(t)
	fleet := h.factsHosts()
	if len(fleet) == 0 {
		t.Skip("no host in the lab")
	}
	var withUpdates, without, unknown []string
	for _, host := range fleet {
		switch {
		case host.PendingSecurityUpdates == nil:
			unknown = append(unknown, host.Hostname)
		case *host.PendingSecurityUpdates > 0:
			withUpdates = append(withUpdates, host.Hostname)
		default:
			without = append(without, host.Hostname)
		}
	}
	sort.Strings(withUpdates)
	sort.Strings(without)

	count, sample := h.previewOf(`{"security_updates":"true"}`)
	if count != len(withUpdates) || !sameIDs(sample, withUpdates) {
		t.Errorf("security_updates=true names %d hosts %v, expected %v", count, sample, withUpdates)
	}
	count, sample = h.previewOf(`{"security_updates":"false"}`)
	if count != len(without) || !sameIDs(sample, without) {
		t.Errorf("security_updates=false names %d hosts %v, expected %v", count, sample, without)
	}
	for _, name := range unknown {
		for _, listed := range sample {
			if listed == name {
				t.Errorf("%s has not reported its updates and is still listed as having none", name)
			}
		}
	}

	// The reboot fact answers the same way; the two lists together are
	// the hosts that reported, and nobody else.
	var reported int
	for _, host := range fleet {
		if host.RebootRequired != nil {
			reported++
		}
	}
	needing, _ := h.previewOf(`{"reboot_required":"true"}`)
	rested, _ := h.previewOf(`{"reboot_required":"false"}`)
	if needing+rested != reported {
		t.Errorf("reboot_required true (%d) and false (%d) do not add up to the %d hosts that reported",
			needing, rested, reported)
	}

	// A value no host can carry is refused before the query.
	h.do(http.MethodGet, "/api/v1/campaigns/preview?expression="+url.QueryEscape(`{"security_updates":"yes"}`),
		nil, nil, http.StatusBadRequest)
}

// TestSelectorComparesTheAgentVersion: a version comparison picks the
// hosts on one side of it, part by part; a host without a parseable
// version is on neither side.
func TestSelectorComparesTheAgentVersion(t *testing.T) {
	h := newHarness(t)
	fleet := h.factsHosts()
	// A version that does not parse - a lab build called "test" - is on
	// neither side of a comparison, so only the numbered ones count.
	numbered := regexp.MustCompile(`^v?\d+(\.\d+)*`)
	var versioned []string
	for _, host := range fleet {
		if numbered.MatchString(host.AgentVersion) {
			versioned = append(versioned, host.Hostname)
		}
	}
	if len(versioned) == 0 {
		t.Skip("no host in the lab reports an agent version")
	}
	sort.Strings(versioned)

	count, sample := h.previewOf(`{"agent_version":"< 99.0.0"}`)
	if count != len(versioned) || !sameIDs(sample, versioned) {
		t.Errorf("agent_version < 99.0.0 names %d hosts %v, expected every versioned host %v", count, sample, versioned)
	}
	if count, _ := h.previewOf(`{"agent_version":">= 99.0.0"}`); count != 0 {
		t.Errorf("agent_version >= 99.0.0 names %d hosts, expected none", count)
	}
	// The order is numeric, not textual: 0.10.0 is newer than 0.9.0, and
	// a bound with fewer parts is read the same way.
	if count, _ := h.previewOf(`{"agent_version":"> 0.0"}`); count != len(versioned) {
		t.Errorf("agent_version > 0.0 names %d hosts, expected %d", count, len(versioned))
	}
	// The combination reads like any other: a comparison and a state.
	online, _ := h.previewOf(`{"all":[{"agent_version":"< 99.0.0"},{"connection_state":"online"}]}`)
	var expected int
	for _, host := range fleet {
		if host.AgentVersion != "" && host.ConnectionState == "online" {
			expected++
		}
	}
	if online != expected {
		t.Errorf("the online versioned hosts count %d, expected %d", online, expected)
	}
	// A word is not a version.
	h.do(http.MethodGet, "/api/v1/campaigns/preview?expression="+url.QueryEscape(`{"agent_version":"latest"}`),
		nil, nil, http.StatusBadRequest)
}

// TestAlertRuleScopesByTagGroupAndExpression: a rule scoped by a tag
// covers the tagged host and nobody else, as the host page counts it; a
// rule scoped by an expression is read with the campaign grammar; a rule
// naming a group nobody created is refused with the name.
func TestAlertRuleScopesByTagGroupAndExpression(t *testing.T) {
	h := newHarness(t)
	lab := h.hosts()
	if len(lab) < 2 {
		t.Skip("the test needs two hosts in the lab")
	}
	tagged, other := lab[0], lab[1]
	marker := uniqueTag("alert")
	h.setTags(tagged.ID, []string{marker})

	rulesMatching := func(hostID string) int {
		var view hostMonitoringView
		h.get("/api/v1/hosts/"+hostID+"/monitoring", &view)
		return view.RulesMatching
	}
	taggedBefore, otherBefore := rulesMatching(tagged.ID), rulesMatching(other.ID)

	// A rule nobody would write for real: the scope is what is under test.
	var rule alertRuleView
	h.do(http.MethodPost, "/api/v1/monitoring/rules", map[string]any{
		"name": "integration: scoped by tag " + marker, "metric": "cpu_percent", "operator": "gt",
		"threshold": 1000, "for_minutes": 60, "severity": "info",
		"selector": map[string]any{"tags": []string{marker}},
	}, &rule, http.StatusCreated)
	t.Cleanup(func() {
		h.do(http.MethodDelete, "/api/v1/monitoring/rules/"+rule.ID, nil, nil, 0)
	})
	if got := rulesMatching(tagged.ID); got != taggedBefore+1 {
		t.Errorf("the tagged host is covered by %d rules, expected %d", got, taggedBefore+1)
	}
	if got := rulesMatching(other.ID); got != otherBefore {
		t.Errorf("an untagged host is covered by %d rules, expected %d", got, otherBefore)
	}

	// The tag removed, the rule covers the host no more: the scope is
	// resolved when asked, not when the rule was written.
	h.do(http.MethodPut, "/api/v1/hosts/"+tagged.ID+"/tags", map[string]any{"tags": []string{}}, nil, http.StatusOK)
	if got := rulesMatching(tagged.ID); got != taggedBefore {
		t.Errorf("after the tag was removed the host is still covered by %d rules, expected %d", got, taggedBefore)
	}

	// An expression in the campaign grammar scopes a rule the same way,
	// and one the grammar does not read is refused before it is recorded.
	var byExpression alertRuleView
	h.do(http.MethodPost, "/api/v1/monitoring/rules", map[string]any{
		"name": "integration: scoped by expression", "metric": "cpu_percent", "operator": "gt",
		"threshold": 1000, "for_minutes": 60, "severity": "info",
		"selector": map[string]any{"expression": fmt.Sprintf("tag = %s and agent_version < 99.0.0", marker)},
	}, &byExpression, http.StatusCreated)
	t.Cleanup(func() {
		h.do(http.MethodDelete, "/api/v1/monitoring/rules/"+byExpression.ID, nil, nil, 0)
	})
	if got := rulesMatching(tagged.ID); got != taggedBefore {
		t.Errorf("an expression on a tag the host lost still covers it: %d rules, expected %d", got, taggedBefore)
	}
	h.setTags(tagged.ID, []string{marker})
	if got := rulesMatching(tagged.ID); got != taggedBefore+2 {
		t.Errorf("the tagged host is covered by %d rules, expected %d", got, taggedBefore+2)
	}
	for name, selector := range map[string]map[string]any{
		"an unknown key":       {"expression": "colour = blue"},
		"an ordered site":      {"expression": "site < warsaw"},
		"a state nobody is in": {"expression": "connection = sleeping"},
		"an upper-case tag":    {"tags": []string{"Role=db"}},
		"a group nobody made":  {"groups": []string{uniqueName("nobody")}},
	} {
		h.do(http.MethodPost, "/api/v1/monitoring/rules", map[string]any{
			"name": "integration: " + name, "metric": "cpu_percent", "operator": "gt",
			"threshold": 1000, "for_minutes": 60, "severity": "info", "selector": selector,
		}, nil, http.StatusBadRequest)
	}

	// A saved group scopes a rule like a tag does.
	group := h.createGroup(map[string]any{
		"name": uniqueName("alert-scope"), "kind": "dynamic",
		"selector": map[string]any{"tag": marker},
	})
	var byGroup alertRuleView
	h.do(http.MethodPost, "/api/v1/monitoring/rules", map[string]any{
		"name": "integration: scoped by group", "metric": "cpu_percent", "operator": "gt",
		"threshold": 1000, "for_minutes": 60, "severity": "info",
		"selector": map[string]any{"groups": []string{group.Name}},
	}, &byGroup, http.StatusCreated)
	t.Cleanup(func() {
		h.do(http.MethodDelete, "/api/v1/monitoring/rules/"+byGroup.ID, nil, nil, 0)
	})
	if got := rulesMatching(tagged.ID); got != taggedBefore+3 {
		t.Errorf("the host in the group is covered by %d rules, expected %d", got, taggedBefore+3)
	}
	if got := rulesMatching(other.ID); got != otherBefore {
		t.Errorf("a host outside the group is covered by %d rules, expected %d", got, otherBefore)
	}
}
