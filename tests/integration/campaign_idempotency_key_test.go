//go:build integration

package integration

import (
	"fmt"
	"net/http"
	"testing"
	"time"
)

// The campaign side of the same gap the single-host orders had: the key was
// re-read into a campaign and that campaign was handed back, whatever the
// second request actually asked for. A caller who reused a key by mistake was
// told a campaign of theirs was under way over hosts they never named.
func TestAnIdempotencyKeyUsedForAnotherCampaignIsRefused(t *testing.T) {
	h := newHarness(t)
	host := h.hostByFamily("debian")
	key := fmt.Sprintf("integration-campaign-idempotency-%d", time.Now().UnixNano())
	cron := map[string]any{"unit": map[string]any{"unit": "cron.service"}}
	order := func(payload map[string]any) map[string]any {
		return map[string]any{
			"action":          "unit.restart",
			"name":            "campaign idempotency key",
			"reason":          "integration test of the campaign idempotency key",
			"payload":         payload,
			"selector":        map[string]any{"host_ids": []string{host.ID}},
			"wave_size":       1,
			"idempotency_key": key,
		}
	}

	created := h.createCampaign(order(cron))

	// The same order again is the repeat the key exists for: the campaign that
	// was already created comes back, and no second one is made.
	var repeated campaignView
	h.do(http.MethodPost, "/api/v1/campaigns", order(cron), &repeated, http.StatusOK)
	if repeated.ID != created.ID {
		t.Fatalf("the repeat of one order made a second campaign: %s and %s", created.ID, repeated.ID)
	}

	var refusal campaignRefusal
	// Another payload under the same key is not a repeat of anything.
	h.do(http.MethodPost, "/api/v1/campaigns",
		order(map[string]any{"unit": map[string]any{"unit": "rsyslog.service"}}),
		&refusal, http.StatusConflict)
	if refusal.Code != "idempotency_key_reused" {
		t.Errorf("another payload under a used key was refused as %q: %s", refusal.Code, refusal.Detail)
	}

	// Another operation likewise.
	otherAction := order(cron)
	otherAction["action"] = "unit.stop"
	h.do(http.MethodPost, "/api/v1/campaigns", otherAction, &refusal, http.StatusConflict)
	if refusal.Code != "idempotency_key_reused" {
		t.Errorf("another action under a used key was refused as %q: %s", refusal.Code, refusal.Detail)
	}

	// And the same operation over other hosts: the selector is part of what
	// was ordered, and a campaign is the hosts it runs on. The other selector
	// names the host's site, because an order naming nobody is refused before
	// the key is ever read.
	otherHosts := order(cron)
	otherHosts["selector"] = map[string]any{"site": host.Site}
	h.do(http.MethodPost, "/api/v1/campaigns", otherHosts, &refusal, http.StatusConflict)
	if refusal.Code != "idempotency_key_reused" {
		t.Errorf("another selector under a used key was refused as %q: %s", refusal.Code, refusal.Detail)
	}
}
