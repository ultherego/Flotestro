//go:build integration

package integration

import (
	"fmt"
	"net/http"
	"testing"
	"time"
)

// The enrollment side of the same gap the tasks and the campaigns had: the key
// was re-read into an order and that order was handed back, whatever the second
// request asked for. A caller who reused a key was told a token for their
// machine was ordered when what stood was an order for another scope.
func TestAnIdempotencyKeyUsedForAnotherEnrollmentOrderIsRefused(t *testing.T) {
	h := newHarness(t)
	key := fmt.Sprintf("integration-enrollment-idempotency-%d", time.Now().UnixNano())
	order := func(change func(map[string]any)) map[string]any {
		body := map[string]any{
			"description": "enrollment idempotency key", "site": "lab", "environment": "test",
			"owner": "platform", "tags": []string{"web", "edge"}, "max_uses": 1, "ttl_minutes": 15,
		}
		if change != nil {
			change(body)
		}
		return body
	}

	created := h.postWithKey("/api/v1/enrollment-requests", order(nil), key, http.StatusCreated)

	// The same order again is the repeat the key exists for: the order that
	// stands comes back without its token, and no second one is made. Another
	// description and another order of the same tags are labels, not orders.
	repeated := h.postWithKey("/api/v1/enrollment-requests", order(func(b map[string]any) {
		b["description"] = "the same order, worded again"
		b["tags"] = []string{"edge", "web"}
	}), key, http.StatusOK)
	if repeated["id"] != created["id"] {
		t.Fatalf("the repeat of one order made a second one: %v and %v", created["id"], repeated["id"])
	}
	if token, _ := repeated["token"].(string); token != "" {
		t.Errorf("the repeat handed the token out a second time")
	}

	// Anything the caller asked for differently is not a repeat of anything.
	for name, change := range map[string]func(map[string]any){
		"scope":    func(b map[string]any) { b["site"] = "elsewhere" },
		"owner":    func(b map[string]any) { b["owner"] = "somebody-else" },
		"tags":     func(b map[string]any) { b["tags"] = []string{"web"} },
		"uses":     func(b map[string]any) { b["max_uses"] = 5 },
		"lifetime": func(b map[string]any) { b["ttl_minutes"] = 60 },
	} {
		refusal := h.postWithKey("/api/v1/enrollment-requests", order(change), key, http.StatusConflict)
		if refusal["code"] != "idempotency_key_reused" {
			t.Errorf("another %s under a used key was refused as %v: %v", name, refusal["code"], refusal["detail"])
		}
	}
}
