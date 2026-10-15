//go:build integration

package integration

import (
	"fmt"
	"net/http"
	"testing"

	"github.com/google/uuid"
)

// principalPage is the listing as the access screen reads it.
type principalPage struct {
	Items []struct {
		ID      string `json:"id"`
		Subject string `json:"subject"`
		Kind    string `json:"kind"`
	} `json:"items"`
	Count           int            `json:"count"`
	Total           int            `json:"total"`
	Limit           int            `json:"limit"`
	Offset          int            `json:"offset"`
	ByKind          map[string]int `json:"by_kind"`
	ByRole          map[string]int `json:"by_role"`
	WithoutBindings int            `json:"without_bindings"`
}

// The listing of identities is paged, searched by the server, and counts what
// the search matches rather than what the page holds.
//
// It answered with every identity there was, and asked the database twice
// more about each one. On the laboratory, whose suites had been running for a
// month, that was 1803 identities, 3607 round trips and a megabyte on the
// wire - and the owner, signed in as himself through the identity provider,
// could not find his own name on the screen. Whatever the panel does with
// that answer, the answer has to be a page.
func TestTheIdentitiesAreListedAPageAtATime(t *testing.T) {
	h := newHarness(t)
	stamp := uuid.NewString()[:8]
	// Three of our own, named so the search finds exactly these.
	for i := 0; i < 3; i++ {
		h.createPrincipal(fmt.Sprintf("paging-%s-%d", stamp, i), []map[string]string{{"role": "viewer"}})
	}

	var all principalPage
	h.get("/api/v1/principals?limit=2", &all)
	if all.Limit != 2 || len(all.Items) != 2 || all.Count != 2 {
		t.Fatalf("a page of two came back with limit=%d and %d items", all.Limit, len(all.Items))
	}
	if all.Total < 3 {
		t.Fatalf("the total says %d identities, and this test alone made three", all.Total)
	}
	// The counts are of the whole, not of the page: two rows cannot carry
	// more identities than the page holds unless they were counted apart.
	counted := 0
	for _, n := range all.ByKind {
		counted += n
	}
	if counted != all.Total {
		t.Errorf("the kinds add up to %d and the total says %d", counted, all.Total)
	}

	// The search is the server's, and it narrows the counts with the rows.
	var found principalPage
	h.get("/api/v1/principals?q=paging-"+stamp, &found)
	if found.Total != 3 {
		t.Fatalf("the search found %d of the three identities it was given", found.Total)
	}
	for _, item := range found.Items {
		if len(item.Subject) < 7 || item.Subject[:7] != "paging-" {
			t.Errorf("the search returned %s, which does not match it", item.Subject)
		}
	}
	if found.ByRole["viewer"] != 3 {
		t.Errorf("the roles of the matching identities say viewer=%d, want 3", found.ByRole["viewer"])
	}
	if found.WithoutBindings != 0 {
		t.Errorf("%d of the three matching identities hold no binding, and all three were granted one", found.WithoutBindings)
	}

	// The pages do not overlap and together they are the whole.
	var first, second principalPage
	h.get("/api/v1/principals?q=paging-"+stamp+"&limit=2&offset=0", &first)
	h.get("/api/v1/principals?q=paging-"+stamp+"&limit=2&offset=2", &second)
	if len(first.Items) != 2 || len(second.Items) != 1 {
		t.Fatalf("three identities came back as %d and %d", len(first.Items), len(second.Items))
	}
	seen := map[string]bool{}
	for _, item := range append(first.Items, second.Items...) {
		if seen[item.ID] {
			t.Errorf("%s is on both pages", item.Subject)
		}
		seen[item.ID] = true
	}
	if len(seen) != 3 {
		t.Errorf("the two pages carry %d identities between them, want 3", len(seen))
	}

	// A search nothing matches is an empty page, not an error and not the
	// first page of everything.
	var none principalPage
	h.get("/api/v1/principals?q=no-such-identity-"+stamp, &none)
	if none.Total != 0 || len(none.Items) != 0 {
		t.Errorf("a search for nothing answered with %d of %d", len(none.Items), none.Total)
	}
	if none.WithoutBindings != 0 {
		t.Errorf("a search matching nothing counts %d identities without a binding", none.WithoutBindings)
	}
}

// The identities a group mapping grants a role to hold no binding of their
// own, and the screen says so rather than leaving them looking unprivileged.
func TestAnIdentityWithNoBindingIsCountedApart(t *testing.T) {
	h := newHarness(t)
	subject := "no-binding-" + uuid.NewString()[:8]
	h.do(http.MethodPost, "/api/v1/principals", map[string]any{
		"subject": subject,
		"roles":   []map[string]any{},
		"reason":  "the integration suite checks the count of identities without a binding",
	}, nil, http.StatusCreated)

	var page principalPage
	h.get("/api/v1/principals?q="+subject, &page)
	if page.Total != 1 {
		t.Fatalf("the identity just created is not in the listing: total %d", page.Total)
	}
	if page.WithoutBindings != 1 {
		t.Errorf("an identity with no binding is counted %d times among those without one", page.WithoutBindings)
	}
	if len(page.ByRole) != 0 {
		t.Errorf("an identity with no binding contributes %v to the roles", page.ByRole)
	}
}
