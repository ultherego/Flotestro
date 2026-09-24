//go:build integration

package integration

import (
	"net/http"
	"net/url"
	"strings"
	"testing"
)

// searchHit is one answer of the global search: what it is and where its
// page is.
type searchHit struct {
	Kind     string `json:"kind"`
	ID       string `json:"id"`
	Title    string `json:"title"`
	Subtitle string `json:"subtitle"`
	Path     string `json:"path"`
}

func (h *harness) search(query string) []searchHit {
	h.t.Helper()
	var page struct {
		Items []searchHit `json:"items"`
	}
	h.get("/api/v1/search?"+url.Values{"q": {query}}.Encode(), &page)
	return page.Items
}

// hitOf returns the hit of the kind with the identifier, if the answer
// carries one.
func hitOf(hits []searchHit, kind, id string) *searchHit {
	for i := range hits {
		if hits[i].Kind == kind && hits[i].ID == id {
			return &hits[i]
		}
	}
	return nil
}

// TestSearchFindsAHostByThePrefixOfItsName types the beginning of a lab host's
// name into the global search and expects the host among the hits, with the
// address of its overview; the full name finds it too, one letter does not.
func TestSearchFindsAHostByThePrefixOfItsName(t *testing.T) {
	h := newHarness(t)
	hosts := h.hosts()
	if len(hosts) == 0 {
		t.Skip("no hosts are enrolled")
	}
	host := hosts[0]
	prefix := host.Hostname
	if len(prefix) > 3 {
		prefix = prefix[:3]
	}

	hit := hitOf(h.search(prefix), "host", host.ID)
	if hit == nil {
		t.Fatalf("the search for %q does not carry host %s", prefix, host.Hostname)
	}
	if hit.Title != host.Hostname || hit.Path != "/hosts/"+host.ID+"/overview" {
		t.Errorf("the hit of %s is %+v, expected its name and the overview address", host.Hostname, *hit)
	}
	if !strings.Contains(hit.Subtitle, host.Site+" / "+host.Environment) {
		t.Errorf("the subtitle %q of %s does not name the site and the environment", hit.Subtitle, host.Hostname)
	}
	if hitOf(h.search(host.Hostname), "host", host.ID) == nil {
		t.Errorf("the search for the full name %q does not carry the host", host.Hostname)
	}
	if hits := h.search(host.Hostname[:1]); len(hits) != 0 {
		t.Errorf("a one-character query was answered with %d hits, expected none", len(hits))
	}
}

// TestSearchFindsACampaignByAWordOfItsName orders a campaign and expects the
// search to find it by the beginning of its name and by one of its later
// words: an operator remembers a word of a name, not always the first one.
func TestSearchFindsACampaignByAWordOfItsName(t *testing.T) {
	h := newHarness(t)
	campaign := h.createCampaign(labCampaign("palette lookup rehearsal", "cron.service", nil))

	for _, query := range []string{"palette", "rehearsal", "Palette look"} {
		hit := hitOf(h.search(query), "campaign", campaign.ID)
		if hit == nil {
			t.Errorf("the search for %q does not carry campaign %s", query, campaign.ID)
			continue
		}
		if hit.Title != campaign.Name || hit.Path != "/campaigns/"+campaign.ID {
			t.Errorf("the hit of the campaign is %+v, expected its name and its address", *hit)
		}
	}
}

// TestSearchKeepsTheIdentitiesFromAViewer creates a viewer bound to one scope
// and expects their search to find that scope's hosts and no identity at all.
func TestSearchKeepsTheIdentitiesFromAViewer(t *testing.T) {
	h := newHarness(t)
	hosts := h.hosts()
	if len(hosts) == 0 {
		t.Skip("no hosts are enrolled")
	}
	host := hosts[0]
	subject := uniqueSubject("search-viewer")
	viewer := h.withToken(h.createPrincipal(subject, []map[string]string{
		{"role": "viewer", "site": host.Site, "environment": host.Environment},
	}))

	// The administrator finds the identity by the beginning of its subject.
	// The prefix carries the unique part: every run of this suite leaves an
	// identity behind, and the search is bounded per kind, so "search-viewer"
	// alone stops finding the newest one once a lab has a few runs on it.
	prefix := subject[:len(subject)-6]
	adminHits := h.search(prefix)
	found := false
	for _, hit := range adminHits {
		if hit.Kind == "principal" && hit.Title == subject {
			found = true
			if !strings.HasPrefix(hit.Path, "/access?tab=identities&q=") {
				t.Errorf("the identity hit leads to %q, expected the identity tab", hit.Path)
			}
		}
	}
	if !found {
		t.Errorf("the administrator's search for %q does not carry the identity", subject)
	}

	// The viewer gets no identity for the same query, and sees the host of
	// their scope by name.
	for _, hit := range viewer.search(prefix) {
		if hit.Kind == "principal" {
			t.Errorf("the viewer's search carries identity %q", hit.Title)
		}
	}
	if hitOf(viewer.search(host.Hostname), "host", host.ID) == nil {
		t.Errorf("the viewer's search for %q does not carry the host of their own scope", host.Hostname)
	}

	h.withToken("").do(http.MethodGet, "/api/v1/search?q=search", nil, nil, http.StatusUnauthorized)
}
