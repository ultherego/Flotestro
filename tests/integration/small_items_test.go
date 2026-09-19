//go:build integration

package integration

import (
	"context"
	"fmt"
	"net/http"
	"testing"
	"time"
)

// preferencesView mirrors the preferences of an identity as the API
// answers them.
type preferencesView struct {
	TimeZone    string     `json:"time_zone"`
	PageSize    int        `json:"page_size"`
	LandingPage string     `json:"landing_page"`
	Language    string     `json:"language"`
	Theme       string     `json:"theme"`
	UpdatedAt   *time.Time `json:"updated_at"`
}

// TestPreferencesRoundTrip guards that an identity's preferences are written
// whole under the identity, read back the same, and refused when they name a
// zone, a page or a language the panel cannot honour.
func TestPreferencesRoundTrip(t *testing.T) {
	h := newHarness(t)
	// A fresh identity, so the test does not overwrite the preferences of whoever
	// runs the suite; the operator role is enough, because the preferences need
	// no permission beyond being signed in.
	token := h.createPrincipal(uniqueSubject("preferences"), []map[string]string{
		{"role": "operator", "site": "*", "environment": "*"},
	})
	me := h.withToken(token)

	var initial preferencesView
	me.get("/api/v1/me/preferences", &initial)
	if initial.TimeZone != "" || initial.PageSize != 0 || initial.UpdatedAt != nil {
		t.Fatalf("a new identity is not on the defaults: %+v", initial)
	}

	var written preferencesView
	me.do(http.MethodPut, "/api/v1/me/preferences", map[string]any{
		"time_zone": "Europe/Warsaw", "page_size": 250, "landing_page": "/hosts", "language": "pl", "theme": "latte",
	}, &written, http.StatusOK)
	if written.UpdatedAt == nil {
		t.Fatal("the write does not say when it happened")
	}

	var read preferencesView
	me.get("/api/v1/me/preferences", &read)
	if read.TimeZone != "Europe/Warsaw" || read.PageSize != 250 || read.LandingPage != "/hosts" ||
		read.Language != "pl" || read.Theme != "latte" {
		t.Fatalf("the preferences did not come back as written: %+v", read)
	}

	// The whole row is written: a field left out goes back to the default.
	me.do(http.MethodPut, "/api/v1/me/preferences", map[string]any{"theme": "mocha-green"}, nil, http.StatusOK)
	me.get("/api/v1/me/preferences", &read)
	if read.TimeZone != "" || read.Theme != "mocha-green" {
		t.Fatalf("a field left out of the write did not go back to the default: %+v", read)
	}

	// What the panel cannot honour is refused by name.
	for _, body := range []map[string]any{
		{"time_zone": "Mars/Olympus"},
		{"page_size": 5000},
		{"landing_page": "https://elsewhere.example/hosts"},
		{"landing_page": "//elsewhere.example"},
		{"language": "de"},
		{"theme": "neon"},
	} {
		me.do(http.MethodPut, "/api/v1/me/preferences", body, nil, http.StatusBadRequest)
	}

	// The preferences belong to their identity: the suite's own token
	// reads its own row, not the one written above.
	var other preferencesView
	h.get("/api/v1/me/preferences", &other)
	if other.UpdatedAt != nil && read.UpdatedAt != nil && other.UpdatedAt.Equal(*read.UpdatedAt) {
		t.Fatal("the preferences of one identity are read under another")
	}

	// The identity sees its own sessions and tokens without the right to
	// manage identities: the token it acts with is on the list.
	var tokens struct {
		Items []struct {
			ID string `json:"id"`
		} `json:"items"`
	}
	me.get("/api/v1/me/tokens", &tokens)
	if len(tokens.Items) != 1 {
		t.Fatalf("the identity lists %d tokens; it holds one", len(tokens.Items))
	}
	var sessions struct {
		Items []map[string]any `json:"items"`
	}
	me.get("/api/v1/me/sessions", &sessions)
	if len(sessions.Items) != 0 {
		t.Fatalf("an identity that only used a token has %d browser sessions", len(sessions.Items))
	}
}

// notedHostView is the part of a host the notes test reads.
type notedHostView struct {
	ID    string `json:"id"`
	Notes string `json:"notes"`
}

// TestHostNotesRoundTripWithAudit guards that the notes of a host are written
// under the tag permission, come back with the host, clear with an empty text,
// and leave both texts on the trail.
func TestHostNotesRoundTripWithAudit(t *testing.T) {
	h := newHarness(t)
	host := h.hostByFamily("debian")

	var before notedHostView
	h.get("/api/v1/hosts/"+host.ID, &before)
	t.Cleanup(func() {
		h.do(http.MethodPut, "/api/v1/hosts/"+host.ID+"/notes",
			map[string]any{"notes": before.Notes, "reason": "after the test"}, nil, 0)
	})

	marker := fmt.Sprintf("integration note %d", time.Now().UnixNano())
	text := marker + "\nSecond paragraph: call the platform team before a reboot."
	var written notedHostView
	h.do(http.MethodPut, "/api/v1/hosts/"+host.ID+"/notes",
		map[string]any{"notes": text, "reason": "integration test of the host notes"}, &written, http.StatusOK)
	if written.Notes != text {
		t.Fatalf("the notes came back as %q", written.Notes)
	}
	var read notedHostView
	h.get("/api/v1/hosts/"+host.ID, &read)
	if read.Notes != text {
		t.Fatalf("the host read shows notes %q", read.Notes)
	}

	// A control character other than a line break is not a note.
	h.do(http.MethodPut, "/api/v1/hosts/"+host.ID+"/notes",
		map[string]any{"notes": "bell\x07here"}, nil, http.StatusBadRequest)

	// Clearing is an empty text, and the trail keeps what was cleared.
	var emptied struct {
		Notes string `json:"notes"`
	}
	h.do(http.MethodPut, "/api/v1/hosts/"+host.ID+"/notes",
		map[string]any{"notes": "", "reason": "clearing after the test"}, &emptied, http.StatusOK)
	if emptied.Notes != "" {
		t.Fatalf("the notes did not clear: %q", emptied.Notes)
	}

	var trail auditPage
	h.get("/api/v1/audit?action=host.notes&target_id="+host.ID+"&limit=20", &trail)
	var wrote, cleared bool
	for _, event := range trail.Items {
		if event.Detail["after"] == text && event.Detail["before"] == before.Notes {
			wrote = true
		}
		if event.Detail["before"] == text && event.Detail["after"] == "" {
			cleared = true
		}
	}
	if !wrote || !cleared {
		t.Fatalf("the trail does not carry both texts of the notes: wrote=%v cleared=%v among %d events",
			wrote, cleared, len(trail.Items))
	}
}

// tagCatalogueView mirrors the tag catalogue.
type tagCatalogueView struct {
	Items []struct {
		Tag   string `json:"tag"`
		Hosts int    `json:"hosts"`
	} `json:"items"`
}

// TestTagCatalogueListsAndRenames guards that a tag set on a host appears in
// the catalogue with its host count, that a rename moves it on every host
// carrying it in one step and says how many moved, that the old name leaves
func TestTagCatalogueListsAndRenames(t *testing.T) {
	h := newHarness(t)
	host := h.hostByFamily("debian")
	from := fmt.Sprintf("catalogue-%d", time.Now().UnixNano()%1_000_000)
	to := from + "-renamed"

	// setTags puts the previous tags back when the test ends, whichever
	// name the host carries by then.
	h.setTags(host.ID, []string{from, "catalogue-keep=yes"})

	var catalogue tagCatalogueView
	h.get("/api/v1/tags", &catalogue)
	countOf := func(tag string) int {
		for _, item := range catalogue.Items {
			if item.Tag == tag {
				return item.Hosts
			}
		}
		return 0
	}
	if countOf(from) != 1 {
		t.Fatalf("the catalogue counts %d hosts with %s; one carries it", countOf(from), from)
	}

	// A rename needs a reason and a tag of the right shape.
	h.do(http.MethodPost, "/api/v1/tags/rename", map[string]any{"from": from, "to": to, "reason": "short"}, nil, http.StatusBadRequest)
	h.do(http.MethodPost, "/api/v1/tags/rename", map[string]any{"from": from, "to": "Not A Tag", "reason": "integration test of the rename"}, nil, http.StatusBadRequest)
	h.do(http.MethodPost, "/api/v1/tags/rename", map[string]any{"from": from, "to": from, "reason": "integration test of the rename"}, nil, http.StatusBadRequest)

	var renamed struct {
		From    string   `json:"from"`
		To      string   `json:"to"`
		Hosts   int      `json:"hosts"`
		HostIDs []string `json:"host_ids"`
	}
	h.do(http.MethodPost, "/api/v1/tags/rename",
		map[string]any{"from": from, "to": to, "reason": "integration test of the rename"}, &renamed, http.StatusOK)
	if renamed.Hosts != 1 || len(renamed.HostIDs) != 1 || renamed.HostIDs[0] != host.ID {
		t.Fatalf("the rename answered %+v; one host carried the tag", renamed)
	}

	var after taggedHostView
	h.get("/api/v1/hosts/"+host.ID, &after)
	if !hasTag(after.Tags, to) || hasTag(after.Tags, from) || !hasTag(after.Tags, "catalogue-keep=yes") {
		t.Fatalf("after the rename the host carries %v", after.Tags)
	}
	h.get("/api/v1/tags", &catalogue)
	if countOf(from) != 0 || countOf(to) != 1 {
		t.Fatalf("after the rename the catalogue counts %s=%d and %s=%d", from, countOf(from), to, countOf(to))
	}

	// The tag is gone from every visible host: a second rename finds
	// nobody and says so rather than recording a rename that moved nothing.
	h.do(http.MethodPost, "/api/v1/tags/rename",
		map[string]any{"from": from, "to": to, "reason": "integration test of the rename"}, nil, http.StatusNotFound)

	// The trail names the rename once and the host once, with both lists.
	var trail auditPage
	h.get("/api/v1/audit?action=tag.rename&target_id="+from+"&limit=5", &trail)
	if len(trail.Items) == 0 || trail.Items[0].Detail["to"] != to {
		t.Fatalf("the trail does not name the rename of %s: %+v", from, trail.Items)
	}
	h.get("/api/v1/audit?action=host.tags&target_id="+host.ID+"&limit=5", &trail)
	found := false
	for _, event := range trail.Items {
		if rename, ok := event.Detail["rename"].(map[string]any); ok && rename["from"] == from && rename["to"] == to {
			found = true
		}
	}
	if !found {
		t.Fatal("the host's own trail does not carry the rename")
	}
}

func hasTag(tags []string, tag string) bool {
	for _, candidate := range tags {
		if candidate == tag {
			return true
		}
	}
	return false
}

// TestBudgetDeleteRefusedWhileHeld guards that a configured budget cannot be
// taken away while somebody holds its tokens - the ceiling is not pulled from
// under running work - and goes away, with a trail entry, once the tokens are
func TestBudgetDeleteRefusedWhileHeld(t *testing.T) {
	h := newHarness(t)
	ctx := context.Background()
	pool := h.database(ctx)

	key := fmt.Sprintf("domain:delete-test-%d:units", time.Now().UnixNano()%1_000_000)
	h.do(http.MethodPut, "/api/v1/budgets/"+key,
		map[string]any{"capacity": 2, "note": "integration test of the budget delete"}, nil, http.StatusOK)
	t.Cleanup(func() {
		_, _ = pool.Exec(ctx, `delete from budget_limits where key = $1`, key)
	})

	// The stand-in for work under way: one token, held by the test.
	const holder = "integration-test:budget-delete"
	if _, err := pool.Exec(ctx, `
		insert into budget_leases (key, owner, claimant, weight, lease_until)
		values ($1, $2, 'integration-test', 1, now() + interval '3 minutes')
		on conflict (key, owner) do update set lease_until = excluded.lease_until`,
		key, holder); err != nil {
		t.Fatalf("holding the token: %v", err)
	}
	t.Cleanup(func() {
		_, _ = pool.Exec(ctx, `delete from budget_leases where owner = $1`, holder)
	})

	h.do(http.MethodDelete, "/api/v1/budgets/"+key,
		map[string]any{"reason": "integration test of the budget delete"}, nil, http.StatusConflict)
	var still struct {
		Key string `json:"key"`
	}
	h.get("/api/v1/budgets/"+key, &still)
	if still.Key != key {
		t.Fatalf("the refused delete took the budget away: %+v", still)
	}

	// The token goes back; the delete goes through and leaves its entry.
	if _, err := pool.Exec(ctx, `delete from budget_leases where owner = $1`, holder); err != nil {
		t.Fatalf("giving the token back: %v", err)
	}
	h.do(http.MethodDelete, "/api/v1/budgets/"+key,
		map[string]any{"reason": "integration test of the budget delete"}, nil, http.StatusNoContent)
	h.do(http.MethodGet, "/api/v1/budgets/"+key, nil, nil, http.StatusNotFound)
	h.do(http.MethodDelete, "/api/v1/budgets/"+key,
		map[string]any{"reason": "integration test of the budget delete"}, nil, http.StatusNotFound)

	var trail auditPage
	h.get("/api/v1/audit?action=budget.delete&target_id="+key+"&limit=5", &trail)
	if len(trail.Items) != 1 || trail.Items[0].Detail["capacity"] != float64(2) {
		t.Fatalf("the trail does not carry the delete with the capacity it took away: %+v", trail.Items)
	}
}
