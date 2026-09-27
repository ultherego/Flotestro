//go:build integration

package integration

import (
	"testing"

	"github.com/google/uuid"
)

// A change to what the fleet trusts is written down before it happens. The order
// is what this test guards: the beginning is on the trail, the outcome follows
// it, and a repeat of the same request is refused rather than making a second
// authority nobody asked for.
func TestATrustChangeIsWrittenDownBeforeItIsMade(t *testing.T) {
	h := newHarness(t)

	// No key, no change: a beginning nobody can recognise again would let a lost
	// answer be retried into a second authority.
	h.do("POST", "/api/v1/pki/prepare", map[string]any{
		"reason": "the trail of a trust change, integration test",
	}, nil, 400)

	key := uuid.NewString()
	var prepared struct {
		Fingerprint string `json:"fingerprint"`
		Serial      string `json:"serial"`
	}
	h.do("POST", "/api/v1/pki/prepare", map[string]any{
		"reason": "the trail of a trust change, integration test", "idempotency_key": key,
	}, &prepared, 201)
	if prepared.Fingerprint == "" {
		t.Fatal("the prepared authority carries no fingerprint")
	}

	// The same key again: the panel refuses instead of preparing a second CA.
	h.do("POST", "/api/v1/pki/prepare", map[string]any{
		"reason": "the same order, sent twice", "idempotency_key": key,
	}, nil, 409)

	// Both entries are on the trail, under the same key: the beginning first.
	var trail auditPage
	h.get("/api/v1/audit?action=pki.ca.prepare&limit=50", &trail)
	began, finished := false, false
	for _, event := range trail.Items {
		if event.Detail["intent_key"] != key {
			continue
		}
		switch event.Outcome {
		case "started":
			began = true
		case "success":
			finished = true
			if event.TargetID != prepared.Fingerprint {
				t.Errorf("the outcome names %q, the answer named %q", event.TargetID, prepared.Fingerprint)
			}
		}
	}
	if !began {
		t.Error("the beginning of the change is not on the trail")
	}
	if !finished {
		t.Error("the outcome of the change is not on the trail")
	}

	// The laboratory is left as it was: the prepared authority is taken out again.
	h.do("DELETE", "/api/v1/pki/"+prepared.Fingerprint+
		"?reason=the+laboratory+is+put+back+as+it+was&idempotency_key="+uuid.NewString(), nil, nil, 0)
}
