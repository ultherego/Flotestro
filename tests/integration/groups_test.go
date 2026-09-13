//go:build integration

package integration

import (
	"fmt"
	"net/http"
	"net/url"
	"sort"
	"strings"
	"testing"
	"time"
)

// taggedHostView is the part of a host the tag tests read.
type taggedHostView struct {
	ID       string   `json:"id"`
	Hostname string   `json:"hostname"`
	OSFamily string   `json:"os_family"`
	Tags     []string `json:"tags"`
}

// groupView mirrors a saved group.
type groupView struct {
	ID           string         `json:"id"`
	Name         string         `json:"name"`
	Kind         string         `json:"kind"`
	Selector     map[string]any `json:"selector"`
	MemberCount  *int           `json:"member_count"`
	Unresolvable string         `json:"unresolvable"`
}

// setTags replaces the tags of a host and puts the previous ones back when
// the test ends: the lab fleet is shared, and a tag left behind would put
// the host into the next test's campaign.
func (h *harness) setTags(hostID string, tags []string) taggedHostView {
	h.t.Helper()
	var before taggedHostView
	h.get("/api/v1/hosts/"+hostID, &before)
	previous := append([]string{}, before.Tags...)
	h.t.Cleanup(func() {
		h.do(http.MethodPut, "/api/v1/hosts/"+hostID+"/tags", map[string]any{"tags": previous}, nil, 0)
	})
	var after taggedHostView
	h.do(http.MethodPut, "/api/v1/hosts/"+hostID+"/tags", map[string]any{"tags": tags}, &after, http.StatusOK)
	return after
}

// createGroup records a group and removes it when the test ends.
func (h *harness) createGroup(body map[string]any) groupView {
	h.t.Helper()
	var group groupView
	h.do(http.MethodPost, "/api/v1/host-groups", body, &group, http.StatusCreated)
	h.t.Cleanup(func() {
		h.do(http.MethodDelete, "/api/v1/host-groups/"+group.ID, nil, nil, 0)
	})
	return group
}

// groupHosts reads the hosts a group resolves to.
func (h *harness) groupHosts(groupID string) []taggedHostView {
	h.t.Helper()
	var result struct {
		Items []taggedHostView `json:"items"`
	}
	h.get("/api/v1/host-groups/"+groupID+"/hosts", &result)
	return result.Items
}

// hostsByQuery reads the host list with the given query.
func (h *harness) hostsByQuery(query url.Values) []taggedHostView {
	h.t.Helper()
	var result struct {
		Items []taggedHostView `json:"items"`
	}
	h.get("/api/v1/hosts?"+query.Encode(), &result)
	return result.Items
}

// uniqueTag makes a tag no other test run carries, so that a selector by
// it names exactly the hosts this test tagged.
func uniqueTag(prefix string) string {
	return fmt.Sprintf("%s=%d", prefix, time.Now().UnixNano())
}

// uniqueName makes a group name no other test run took.
func uniqueName(prefix string) string {
	return fmt.Sprintf("%s-%d", prefix, time.Now().UnixNano())
}

func idsOf(hosts []taggedHostView) []string {
	ids := make([]string, 0, len(hosts))
	for _, host := range hosts {
		ids = append(ids, host.ID)
	}
	sort.Strings(ids)
	return ids
}

func sameIDs(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

// TestHostTagsAreSetAndFoundByTag: a tag recorded on a host comes back in
// its record, sorted and without repeats, and the host list finds the host
// by the tag and by a search over the tag's text.
func TestHostTagsAreSetAndFoundByTag(t *testing.T) {
	h := newHarness(t)
	lab := h.hosts()
	if len(lab) == 0 {
		t.Skip("no host in the lab")
	}
	host := lab[0]
	marker := uniqueTag("test")

	tagged := h.setTags(host.ID, []string{"tier=gold", "role=db", marker, "role=db"})
	want := []string{"role=db", "tier=gold", marker}
	sort.Strings(want)
	if strings.Join(tagged.Tags, " ") != strings.Join(want, " ") {
		t.Fatalf("tags = %v, expected %v", tagged.Tags, want)
	}

	// Every given tag has to be on the host: the marker alone names this
	// host, and the marker with a tag the host lacks names nobody.
	found := h.hostsByQuery(url.Values{"tag": {marker, "role=db"}})
	if len(found) != 1 || found[0].ID != host.ID {
		t.Fatalf("the tag filter found %v, expected only %s", idsOf(found), host.Hostname)
	}
	if none := h.hostsByQuery(url.Values{"tag": {marker, "role=cache"}}); len(none) != 0 {
		t.Errorf("a tag the host lacks still matched %v", idsOf(none))
	}
	// The search reads the tags as well as the names.
	if found := h.hostsByQuery(url.Values{"q": {marker}}); len(found) != 1 || found[0].ID != host.ID {
		t.Errorf("the search by the tag text found %v, expected only %s", idsOf(found), host.Hostname)
	}

	// A tag that is not a tag is refused, not stored as something else.
	h.do(http.MethodPut, "/api/v1/hosts/"+host.ID+"/tags",
		map[string]any{"tags": []string{"Role=db"}}, nil, http.StatusBadRequest)
}

// TestAStaticGroupResolvesToItsMembers: a static group is the list it was
// given, no more and no less, and its size is counted in the database.
func TestAStaticGroupResolvesToItsMembers(t *testing.T) {
	h := newHarness(t)
	lab := h.hosts()
	if len(lab) < 2 {
		t.Skip("the test needs two hosts in the lab")
	}
	members := []string{lab[0].ID, lab[1].ID}
	sort.Strings(members)

	group := h.createGroup(map[string]any{
		"name": uniqueName("static"), "kind": "static",
		"description": "two lab hosts", "host_ids": members,
	})
	if group.Kind != "static" || group.MemberCount == nil || *group.MemberCount != 2 {
		t.Fatalf("group = %+v, expected a static group of 2", group)
	}
	if got := idsOf(h.groupHosts(group.ID)); !sameIDs(got, members) {
		t.Fatalf("the group resolves to %v, expected %v", got, members)
	}

	// The list is replaced whole: a host left out leaves the group.
	var updated groupView
	h.do(http.MethodPut, "/api/v1/host-groups/"+group.ID+"/members",
		map[string]any{"host_ids": []string{lab[0].ID}}, &updated, http.StatusOK)
	if got := idsOf(h.groupHosts(group.ID)); !sameIDs(got, []string{lab[0].ID}) {
		t.Errorf("after the replacement the group resolves to %v, expected only %s", got, lab[0].Hostname)
	}
	// A host the panel does not have is refused by name rather than dropped.
	h.do(http.MethodPut, "/api/v1/host-groups/"+group.ID+"/members",
		map[string]any{"host_ids": []string{"00000000-0000-4000-8000-000000000000"}}, nil, http.StatusBadRequest)
	// The group is found by name as well as by identifier.
	var byName groupView
	h.get("/api/v1/host-groups/"+group.Name, &byName)
	if byName.ID != group.ID {
		t.Errorf("the lookup by name gave %s, expected %s", byName.ID, group.ID)
	}
}

// TestADynamicGroupResolvesByTagAndByOSFamily: a dynamic group is its
// selector's answer at the moment of reading - by a tag and by a host fact.
func TestADynamicGroupResolvesByTagAndByOSFamily(t *testing.T) {
	h := newHarness(t)
	lab := h.hosts()
	if len(lab) == 0 {
		t.Skip("no host in the lab")
	}
	host := lab[0]
	marker := uniqueTag("dyn")
	h.setTags(host.ID, []string{marker})

	byTag := h.createGroup(map[string]any{
		"name": uniqueName("by-tag"), "kind": "dynamic",
		"selector": map[string]any{"tag": marker},
	})
	if byTag.MemberCount == nil || *byTag.MemberCount != 1 {
		t.Errorf("the group by tag counts %v hosts, expected 1", byTag.MemberCount)
	}
	if got := idsOf(h.groupHosts(byTag.ID)); !sameIDs(got, []string{host.ID}) {
		t.Fatalf("the group by tag resolves to %v, expected only %s", got, host.Hostname)
	}

	var withFamily taggedHostView
	h.get("/api/v1/hosts/"+host.ID, &withFamily)
	if withFamily.OSFamily == "" {
		t.Skip("the host has not reported its OS family")
	}
	byFamily := h.createGroup(map[string]any{
		"name": uniqueName("by-family"), "kind": "dynamic",
		"selector": map[string]any{"all": []map[string]any{
			{"os_family": withFamily.OSFamily},
			{"not": map[string]any{"lifecycle_state": "retired"}},
		}},
	})
	expected := idsOf(h.hostsByQuery(url.Values{"os_family": {withFamily.OSFamily}, "limit": {"500"}}))
	retired := idsOf(h.hostsByQuery(url.Values{"os_family": {withFamily.OSFamily}, "lifecycle_state": {"retired"}}))
	for _, id := range retired {
		for i, known := range expected {
			if known == id {
				expected = append(expected[:i], expected[i+1:]...)
				break
			}
		}
	}
	if got := idsOf(h.groupHosts(byFamily.ID)); !sameIDs(got, expected) {
		t.Errorf("the group by family resolves to %v, expected %v", got, expected)
	}

	// The tag is removed: the same group now names nobody, because it is
	// resolved when read rather than when created.
	h.do(http.MethodPut, "/api/v1/hosts/"+host.ID+"/tags", map[string]any{"tags": []string{}}, nil, http.StatusOK)
	if left := h.groupHosts(byTag.ID); len(left) != 0 {
		t.Errorf("after the tag was removed the group still resolves to %v", idsOf(left))
	}
}

// TestACampaignWithAnExpressionSelectorMaterialisesTheTaggedHosts: the
// typed selector is compiled into the host query, so the snapshot holds
// exactly the hosts the tag names.
func TestACampaignWithAnExpressionSelectorMaterialisesTheTaggedHosts(t *testing.T) {
	h := newHarness(t)
	lab := h.hosts()
	if len(lab) < 2 {
		t.Skip("the test needs two hosts in the lab")
	}
	marker := uniqueTag("campaign")
	tagged := []string{lab[0].ID, lab[1].ID}
	sort.Strings(tagged)
	for _, id := range tagged {
		h.setTags(id, []string{marker, "role=test"})
	}

	// The preview and the order answer the same question.
	var preview struct {
		Count    int    `json:"count"`
		Selector string `json:"selector"`
	}
	h.get("/api/v1/campaigns/preview?expression="+url.QueryEscape(fmt.Sprintf(`{"tag":%q}`, marker)), &preview)
	if preview.Count != 2 {
		t.Fatalf("the preview counts %d hosts, expected 2", preview.Count)
	}
	if preview.Selector != "tag="+marker {
		t.Errorf("the preview describes the selector as %q", preview.Selector)
	}

	campaign := h.createCampaign(labCampaign("tagged hosts", "cron.service", map[string]any{
		"selector": map[string]any{"expression": map[string]any{"tag": marker}},
	}))
	var targets []string
	for _, target := range h.campaignTargets(campaign.ID) {
		targets = append(targets, target.HostID)
	}
	sort.Strings(targets)
	if !sameIDs(targets, tagged) {
		t.Fatalf("the snapshot holds %v, expected %v", targets, tagged)
	}

	// A selector naming a group nobody created is refused with the name,
	// not materialised as an empty campaign.
	h.do(http.MethodPost, "/api/v1/campaigns", labCampaign("unknown group", "cron.service", map[string]any{
		"selector": map[string]any{"expression": map[string]any{"group": uniqueName("nobody")}},
	}), nil, http.StatusBadRequest)
}

// TestAnExcludedHostEndsExcludedWithTheReason: a host left out by name
// stays in the snapshot, closed as excluded, with the reason and the
// author in its message - and without a reason the order is refused.
func TestAnExcludedHostEndsExcludedWithTheReason(t *testing.T) {
	h := newHarness(t)
	lab := h.hosts()
	if len(lab) < 2 {
		t.Skip("the test needs two hosts in the lab")
	}
	left := lab[0]

	h.do(http.MethodPost, "/api/v1/campaigns", labCampaign("exclusion without a reason", "cron.service", map[string]any{
		"selector": map[string]any{"site": "lab", "exclude": []string{left.ID}},
	}), nil, http.StatusBadRequest)

	campaign := h.createCampaign(labCampaign("exclusion", "cron.service", map[string]any{
		"selector": map[string]any{
			"expression":     map[string]any{"site": "lab"},
			"exclude":        []string{left.ID},
			"exclude_reason": "the database primary; failing over first",
		},
	}))
	var excluded *campaignTargetView
	pending := 0
	for _, target := range h.campaignTargets(campaign.ID) {
		if target.HostID == left.ID {
			excluded = &target
		} else if target.State == "pending" {
			pending++
		}
	}
	if excluded == nil {
		t.Fatalf("the excluded host %s is not in the snapshot", left.Hostname)
	}
	if excluded.State != "excluded" || excluded.ErrorCode != "excluded" {
		t.Errorf("the excluded host is %s/%s, expected excluded/excluded", excluded.State, excluded.ErrorCode)
	}
	if !strings.Contains(excluded.Message, "failing over first") || !strings.Contains(excluded.Message, campaign.CreatedBy) {
		t.Errorf("the message %q does not carry the reason and the author %s", excluded.Message, campaign.CreatedBy)
	}
	if pending == 0 {
		t.Error("no other host is pending; the exclusion emptied the campaign")
	}
}

// TestTheSelectorRefusesACyclicGroup: a group that, through another
// group, refers to itself has no answer and is refused at the edit that
// would close the cycle - not at the first campaign that tries it.
func TestTheSelectorRefusesACyclicGroup(t *testing.T) {
	h := newHarness(t)
	first := h.createGroup(map[string]any{
		"name": uniqueName("cycle-a"), "kind": "dynamic",
		"selector": map[string]any{"tag": "role=db"},
	})
	second := h.createGroup(map[string]any{
		"name": uniqueName("cycle-b"), "kind": "dynamic",
		"selector": map[string]any{"group": first.Name},
	})
	// Closing the cycle: a -> b -> a.
	h.do(http.MethodPut, "/api/v1/host-groups/"+first.ID,
		map[string]any{"selector": map[string]any{"group": second.Name}}, nil, http.StatusBadRequest)
	// A group naming itself directly is the shortest cycle.
	h.do(http.MethodPut, "/api/v1/host-groups/"+first.ID,
		map[string]any{"selector": map[string]any{"group": first.Name}}, nil, http.StatusBadRequest)
	// The refused edit changed nothing: the chain still resolves, and the
	// first group still carries the selector it had.
	h.groupHosts(second.ID)
	var unchanged groupView
	h.get("/api/v1/host-groups/"+first.ID, &unchanged)
	if unchanged.Selector["tag"] != "role=db" {
		t.Errorf("the refused edit changed the selector to %v", unchanged.Selector)
	}
}
