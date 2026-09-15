//go:build integration

package integration

import (
	"encoding/json"
	"net/http"
	"slices"
	"testing"
	"time"
)

// hostPlacementView is the part of a host the placement and bulk tests
// read.
type hostPlacementView struct {
	ID                 string     `json:"id"`
	Hostname           string     `json:"hostname"`
	Site               string     `json:"site"`
	Environment        string     `json:"environment"`
	PlacementChangedAt *time.Time `json:"placement_changed_at"`
	Owner              string     `json:"owner"`
	Tags               []string   `json:"tags"`
}

// readPlacement reads a host with the entity tag of its hand-recorded
// facts.
func readPlacement(t *testing.T, h *harness, hostID string) (hostPlacementView, string) {
	t.Helper()
	response, body := h.request(http.MethodGet, "/api/v1/hosts/"+hostID, nil, nil)
	if response.StatusCode != http.StatusOK {
		t.Fatalf("GET the host: status %d; body: %s", response.StatusCode, body)
	}
	var host hostPlacementView
	if err := json.Unmarshal(body, &host); err != nil {
		t.Fatalf("the host does not decode: %v", err)
	}
	return host, response.Header.Get("ETag")
}

// TestHostPlacementRoundTrip guards moving a host between sites: the
// placement route moves a lab host to another site, the host reads back
// there with the moment of the move, the trail keeps both sides with the
// reason, a move without a reason or to nowhere is refused, and the host
// goes back where it stood.
func TestHostPlacementRoundTrip(t *testing.T) {
	h := newHarness(t)
	host := h.hostByFamily("debian")
	path := "/api/v1/hosts/" + host.ID + "/placement"

	before, fresh := readPlacement(t, h, host.ID)
	if fresh == "" {
		t.Fatal("the host read carries no ETag")
	}
	// The host goes back where it stood whatever the test finds; the
	// lab's role bindings are keyed on its site.
	t.Cleanup(func() {
		h.do(http.MethodPut, path, map[string]any{
			"site": before.Site, "environment": before.Environment,
			"reason": "placement test finished; the host goes back",
		}, nil, http.StatusOK)
	})

	// A move needs a reason and a place.
	h.do(http.MethodPut, path, map[string]any{
		"site": "moved-site", "environment": before.Environment, "reason": "short",
	}, nil, http.StatusBadRequest)
	h.do(http.MethodPut, path, map[string]any{
		"site": "", "environment": before.Environment, "reason": "a host cannot stand nowhere",
	}, nil, http.StatusBadRequest)

	// A stale tag is refused with the current version.
	response, body := h.request(http.MethodPut, path, map[string]any{
		"site": "moved-site", "environment": before.Environment, "reason": "stale write attempt",
	}, map[string]string{"If-Match": `W/"0000000000000000"`})
	if response.StatusCode != http.StatusPreconditionFailed {
		t.Fatalf("a stale If-Match answered %d; body: %s", response.StatusCode, body)
	}

	// The fresh tag lets the move through and the host reads back moved,
	// with the moment of the move on it.
	response, body = h.request(http.MethodPut, path, map[string]any{
		"site": " moved-site ", "environment": before.Environment, "reason": "carried to the new rack",
	}, map[string]string{"If-Match": fresh})
	if response.StatusCode != http.StatusOK {
		t.Fatalf("the move answered %d; body: %s", response.StatusCode, body)
	}
	var moved hostPlacementView
	if err := json.Unmarshal(body, &moved); err != nil {
		t.Fatal(err)
	}
	if moved.Site != "moved-site" || moved.Environment != before.Environment {
		t.Errorf("after the move the host stands in %s/%s", moved.Site, moved.Environment)
	}
	if moved.PlacementChangedAt == nil || time.Since(*moved.PlacementChangedAt) > time.Minute {
		t.Errorf("the move left placement_changed_at %v", moved.PlacementChangedAt)
	}
	read, _ := readPlacement(t, h, host.ID)
	if read.Site != "moved-site" || read.PlacementChangedAt == nil {
		t.Errorf("the read shows site %q, moved at %v", read.Site, read.PlacementChangedAt)
	}
	// The site filter of the fleet list follows the move at once.
	var page struct {
		Items []hostPlacementView `json:"items"`
	}
	h.get("/api/v1/hosts?site=moved-site&limit=500", &page)
	if !slices.ContainsFunc(page.Items, func(item hostPlacementView) bool { return item.ID == host.ID }) {
		t.Error("the moved host is not listed under its new site")
	}

	// The trail keeps both sides and the reason.
	var trail auditPage
	h.get("/api/v1/audit?target_id="+host.ID+"&action=host.placement&limit=10", &trail)
	found := false
	for _, event := range trail.Items {
		if event.Detail["reason"] == "carried to the new rack" {
			found = true
			if event.Detail["before"] != "site="+before.Site+" env="+before.Environment ||
				event.Detail["after"] != "site=moved-site env="+before.Environment {
				t.Errorf("the placement event has detail %v", event.Detail)
			}
		}
	}
	if !found {
		t.Error("the move is not on the trail")
	}

	// An operator of the old site alone cannot move a host into a site
	// they do not hold, nor out of one they hold into nowhere they hold.
	insider := h.withToken(h.createPrincipal(uniqueSubject("placement-insider"), []map[string]string{
		{"role": "operator", "site": "moved-site", "environment": before.Environment},
	}))
	insider.do(http.MethodPut, path, map[string]any{
		"site": "yet-another-site", "environment": before.Environment,
		"reason": "moving out of the scope I hold",
	}, nil, http.StatusForbidden)
}

// bulkOutcome mirrors the answer for one host of a bulk edit.
type bulkOutcome struct {
	HostID string `json:"host_id"`
	OK     bool   `json:"ok"`
	Code   string `json:"code"`
}

type bulkResponse struct {
	Results []bulkOutcome `json:"results"`
	Applied int           `json:"applied"`
	Failed  int           `json:"failed"`
}

// TestBulkMetadataAnswersEveryHost guards the bulk edit: one call adds a
// tag and sets the owner on two lab hosts and answers for each; the hosts
// read back changed; a host id the caller may not touch is answered with a
// code of its own, not with a refusal of the whole call; and a value the
// single route would refuse is refused before the first host.
func TestBulkMetadataAnswersEveryHost(t *testing.T) {
	h := newHarness(t)
	lab := h.hosts()
	if len(lab) < 2 {
		t.Skip("the bulk edit needs two lab hosts")
	}
	first, second := lab[0], lab[1]
	beforeFirst, _ := readPlacement(t, h, first.ID)
	beforeSecond, _ := readPlacement(t, h, second.ID)
	// The hosts keep what they carried: the tag goes off and the owner
	// goes back, whatever the test finds.
	t.Cleanup(func() {
		for _, before := range []hostPlacementView{beforeFirst, beforeSecond} {
			h.do(http.MethodPut, "/api/v1/hosts/"+before.ID+"/tags", map[string]any{"tags": before.Tags}, nil, http.StatusOK)
			h.do(http.MethodPut, "/api/v1/hosts/"+before.ID+"/owner",
				map[string]any{"owner": before.Owner, "reason": "bulk metadata test finished"}, nil, http.StatusOK)
		}
	})

	// The values are checked once, before any host: a bad tag, a missing
	// reason and an empty set are refused for the call.
	h.do(http.MethodPost, "/api/v1/hosts/bulk-metadata", map[string]any{
		"host_ids": []string{first.ID}, "reason": "bulk test with a bad tag",
		"set": map[string]any{"tags_add": []string{"Not A Tag"}},
	}, nil, http.StatusBadRequest)
	h.do(http.MethodPost, "/api/v1/hosts/bulk-metadata", map[string]any{
		"host_ids": []string{first.ID}, "reason": "short",
		"set": map[string]any{"tags_add": []string{"bulk-test"}},
	}, nil, http.StatusBadRequest)
	h.do(http.MethodPost, "/api/v1/hosts/bulk-metadata", map[string]any{
		"host_ids": []string{first.ID}, "reason": "bulk test with nothing to set", "set": map[string]any{},
	}, nil, http.StatusBadRequest)

	// The edit lands on both hosts and each is answered.
	var answer bulkResponse
	h.do(http.MethodPost, "/api/v1/hosts/bulk-metadata", map[string]any{
		"host_ids": []string{first.ID, second.ID, "00000000-0000-0000-0000-000000000000"},
		"reason":   "bulk metadata integration test",
		"set":      map[string]any{"tags_add": []string{"bulk-test=yes"}, "owner": "bulk team"},
	}, &answer, http.StatusOK)
	if answer.Applied != 2 || answer.Failed != 1 || len(answer.Results) != 3 {
		t.Fatalf("the bulk edit answered applied=%d failed=%d with %d results", answer.Applied, answer.Failed, len(answer.Results))
	}
	for _, outcome := range answer.Results {
		switch outcome.HostID {
		case first.ID, second.ID:
			if !outcome.OK || outcome.Code != "applied" {
				t.Errorf("host %s answered ok=%t code=%s", outcome.HostID, outcome.OK, outcome.Code)
			}
		default:
			if outcome.OK || outcome.Code != "host_not_found" {
				t.Errorf("the unknown host answered ok=%t code=%s", outcome.OK, outcome.Code)
			}
		}
	}
	for _, id := range []string{first.ID, second.ID} {
		view, _ := readPlacement(t, h, id)
		if view.Owner != "bulk team" || !slices.Contains(view.Tags, "bulk-test=yes") {
			t.Errorf("host %s reads back as owner %q with tags %v", id, view.Owner, view.Tags)
		}
	}

	// A host outside the caller's scope is answered with a code of its own:
	// the call goes through, the host stays as it was.
	outsider := h.withToken(h.createPrincipal(uniqueSubject("bulk-outsider"), []map[string]string{
		{"role": "operator", "site": "other-site", "environment": "other-environment"},
	}))
	var refused bulkResponse
	outsider.do(http.MethodPost, "/api/v1/hosts/bulk-metadata", map[string]any{
		"host_ids": []string{first.ID}, "reason": "bulk edit from outside the scope",
		"set": map[string]any{"tags_remove": []string{"bulk-test=yes"}},
	}, &refused, http.StatusOK)
	if len(refused.Results) != 1 || refused.Results[0].OK || refused.Results[0].Code != "permission_denied" {
		t.Errorf("the outsider's edit answered %+v", refused.Results)
	}
	view, _ := readPlacement(t, h, first.ID)
	if !slices.Contains(view.Tags, "bulk-test=yes") {
		t.Error("the outsider's refused edit took the tag off")
	}

	// The removal takes the tag off the hosts that carry it and leaves
	// the rest of their tags; the trail keeps an event per host.
	var removal bulkResponse
	h.do(http.MethodPost, "/api/v1/hosts/bulk-metadata", map[string]any{
		"host_ids": []string{first.ID, second.ID}, "reason": "bulk metadata test removes its tag",
		"set": map[string]any{"tags_remove": []string{"bulk-test=yes"}},
	}, &removal, http.StatusOK)
	if removal.Applied != 2 {
		t.Errorf("the removal applied to %d hosts", removal.Applied)
	}
	view, _ = readPlacement(t, h, first.ID)
	if slices.Contains(view.Tags, "bulk-test=yes") {
		t.Error("the tag is still on the host after the removal")
	}
	for _, tag := range beforeFirst.Tags {
		if !slices.Contains(view.Tags, tag) {
			t.Errorf("the bulk edit took the tag %q the host carried before", tag)
		}
	}
	var trail auditPage
	h.get("/api/v1/audit?target_id="+first.ID+"&action=host.metadata&limit=10", &trail)
	if len(trail.Items) < 2 {
		t.Errorf("the bulk edits left %d events on the trail of the first host", len(trail.Items))
	}
}
