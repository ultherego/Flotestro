//go:build integration

package integration

import (
	"fmt"
	"net/http"
	"testing"
	"time"
)

// An idempotency key is the caller's own word that two requests are the same
// order. It was taken as that word without checking: a second, different order
// carrying a key already used on the host was answered with the first task, so
// the caller was told an order had gone through that never existed.
func TestAnIdempotencyKeyUsedForAnotherOrderIsRefused(t *testing.T) {
	h := newHarness(t)
	host := h.hostByFamily("debian")
	key := fmt.Sprintf("integration-idempotency-%d", time.Now().UnixNano())
	reason := "integration test of the idempotency key"

	first := map[string]any{
		"action": "journal.read", "reason": reason, "idempotency_key": key,
		"payload": map[string]any{"journal": map[string]any{"lines": 10}},
	}
	var created jobView
	h.do(http.MethodPost, "/api/v1/hosts/"+host.ID+"/operations", first, &created, http.StatusCreated)

	// The same order again is the repeat the key exists for.
	var repeated jobView
	h.do(http.MethodPost, "/api/v1/hosts/"+host.ID+"/operations", first, &repeated, http.StatusCreated)
	if repeated.ID != created.ID {
		t.Fatalf("the repeat of one order made a second task: %s and %s", created.ID, repeated.ID)
	}

	// A different order under the same key is not a repeat of anything.
	var refusal struct {
		Code string `json:"code"`
	}
	h.do(http.MethodPost, "/api/v1/hosts/"+host.ID+"/operations", map[string]any{
		"action": "journal.read", "reason": reason, "idempotency_key": key,
		"payload": map[string]any{"journal": map[string]any{"lines": 200}},
	}, &refusal, http.StatusConflict)
	if refusal.Code != "idempotency_key_reused" {
		t.Errorf("another order under a used key was refused as %q", refusal.Code)
	}

	// And an order of another kind likewise.
	h.do(http.MethodPost, "/api/v1/hosts/"+host.ID+"/operations", map[string]any{
		"action": "unit.restart", "reason": reason, "idempotency_key": key,
		"payload": map[string]any{"unit": map[string]any{"unit": "cron.service"}},
	}, &refusal, http.StatusConflict)
	if refusal.Code != "idempotency_key_reused" {
		t.Errorf("another action under a used key was refused as %q", refusal.Code)
	}
}
