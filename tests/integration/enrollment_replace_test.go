//go:build integration

package integration

import (
	"net/http"
	"testing"
)

// replacedOrderView mirrors an order with what a replacement copies.
type replacedOrderView struct {
	orderView
	Description string   `json:"description"`
	Owner       string   `json:"owner"`
	Tags        []string `json:"tags"`
	RelayID     string   `json:"relay_id"`
}

// TestAnEnrollmentOrderCanBeReplacedWithinItsScope checks that "revoke
// and replace" closes the order in hand and places one like it - the same
// placement, owner, tags and pool of uses - with a token of its own, shown
// once; that the old token comes back on no read afterwards; and that the
// right to do so is judged where the machine was to live, so an operator
// of another site neither replaces the order nor closes it by trying.
func TestAnEnrollmentOrderCanBeReplacedWithinItsScope(t *testing.T) {
	h := newHarness(t)
	reason := "integration test of the enrollment replacement"

	var first replacedOrderView
	h.do(http.MethodPost, "/api/v1/enrollment-requests", map[string]any{
		"description": "order to be replaced", "site": "lab", "environment": "test",
		"owner": "platform team", "tags": []string{"role=web", "rack=b7"}, "ttl_minutes": 20,
	}, &first, http.StatusCreated)
	t.Cleanup(func() {
		h.do(http.MethodPost, "/api/v1/enrollment-requests/"+first.ID+"/revoke", nil, nil, 0)
	})
	if first.Token == "" {
		t.Fatal("the first order came without a token")
	}

	// An operator of another site sees nothing of the order, so the
	// replacement is refused before anything is closed.
	elsewhere := h.withToken(h.createPrincipal(uniqueSubject("operator-elsewhere"), []map[string]string{
		{"role": "operator", "site": "elsewhere", "environment": "test"},
	}))
	var problem struct {
		Code string `json:"code"`
	}
	elsewhere.do(http.MethodPost, "/api/v1/enrollment-requests/"+first.ID+"/replace",
		map[string]any{"reason": reason}, &problem, http.StatusForbidden)
	if problem.Code != "permission_denied" {
		t.Fatalf("code = %q, expected permission_denied", problem.Code)
	}
	var untouched orderView
	h.get("/api/v1/enrollment-requests/"+first.ID, &untouched)
	if untouched.Status != "pending" {
		t.Fatalf("a refused replacement changed the order to %q", untouched.Status)
	}

	// The operator of the site replaces it: the old order is closed, the
	// new one is open, and only the new one carries a token.
	operator := h.withToken(h.createPrincipal(uniqueSubject("operator-replacing"), []map[string]string{
		{"role": "operator", "site": "lab", "environment": "test"},
	}))
	var second replacedOrderView
	operator.do(http.MethodPost, "/api/v1/enrollment-requests/"+first.ID+"/replace",
		map[string]any{"reason": reason}, &second, http.StatusCreated)
	t.Cleanup(func() {
		h.do(http.MethodPost, "/api/v1/enrollment-requests/"+second.ID+"/revoke", nil, nil, 0)
	})
	if second.ID == first.ID {
		t.Fatal("the replacement is the same order")
	}
	if second.Token == "" || second.Token == first.Token {
		t.Fatal("the replacement has no token of its own")
	}
	if second.Status != "pending" {
		t.Fatalf("the replacement is %q, expected pending", second.Status)
	}
	if second.Site != "lab" || second.Environment != "test" || second.Owner != "platform team" ||
		second.Description != "order to be replaced" || second.MaxUses != 1 {
		t.Fatalf("the replacement did not copy the order: %+v", second)
	}
	copied := map[string]bool{}
	for _, tag := range second.Tags {
		copied[tag] = true
	}
	if len(second.Tags) != 2 || !copied["role=web"] || !copied["rack=b7"] {
		t.Fatalf("the replacement did not copy the tags: %v", second.Tags)
	}

	var old orderView
	h.get("/api/v1/enrollment-requests/"+first.ID, &old)
	if old.Status != "revoked" {
		t.Fatalf("the replaced order is %q, expected revoked", old.Status)
	}
	if old.Token != "" {
		t.Fatal("reading the replaced order gives away its token")
	}
	var list struct {
		Items []orderView `json:"items"`
	}
	h.get("/api/v1/enrollment-requests?status=revoked&site=lab&environment=test", &list)
	for _, item := range list.Items {
		if item.Token != "" {
			t.Fatalf("the order list gives away the token of %s", item.ID)
		}
	}

	// A copy of a closed order does not close anything again and is a
	// new order all the same.
	var third orderView
	h.do(http.MethodPost, "/api/v1/enrollment-requests/"+first.ID+"/replace",
		map[string]any{"reason": reason}, &third, http.StatusCreated)
	t.Cleanup(func() {
		h.do(http.MethodPost, "/api/v1/enrollment-requests/"+third.ID+"/revoke", nil, nil, 0)
	})
	if third.Token == "" || third.Token == second.Token || third.Token == first.Token {
		t.Fatal("the copy of a closed order has no token of its own")
	}

	// The trail names both orders and neither token.
	var trail auditPage
	h.get("/api/v1/audit?action=host.enrollment.replace&target_id="+second.ID+"&limit=5", &trail)
	if len(trail.Items) == 0 {
		t.Fatal("the replacement left no event on the trail")
	}
	event := trail.Items[0]
	if event.Detail["old_request_id"] != first.ID || event.Detail["new_request_id"] != second.ID {
		t.Fatalf("the event does not name both orders: %v", event.Detail)
	}
	for key, value := range event.Detail {
		if text, ok := value.(string); ok && (text == first.Token || text == second.Token) {
			t.Fatalf("the trail carries a token under %q", key)
		}
	}
}
