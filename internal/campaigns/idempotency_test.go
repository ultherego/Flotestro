package campaigns

import (
	"encoding/json"
	"testing"
)

// The idempotency key is the caller's word that two requests are one order. It
// was taken as that word without looking: a second, different order under a key
// already used came back with the first campaign, so the caller was told an
// order had gone through that was never placed.
func TestAnOrderUnderAUsedKeyIsComparedWithTheCampaignTheKeyMade(t *testing.T) {
	existing := Campaign{
		ID:         "c-1",
		ActionType: "security.apply",
		// The row comes back from jsonb with its own key order and spacing.
		Payload:  json.RawMessage(`{"security": {"check_ids": ["a", "b"]}}`),
		Selector: json.RawMessage(`{"tags": ["web"], "exclude": ["db-1"]}`),
	}
	payload := json.RawMessage(`{"security":{"check_ids":["a","b"]}}`)
	selector := json.RawMessage(`{"exclude":["db-1"],"tags":["web"]}`)

	differs, err := orderDiffers(existing, "security.apply", payload, selector)
	if err != nil {
		t.Fatalf("comparing the repeat with the campaign: %v", err)
	}
	if differs != "" {
		t.Errorf("the same order written differently was read as a different %s", differs)
	}

	for _, probe := range []struct {
		name     string
		action   string
		payload  json.RawMessage
		selector json.RawMessage
		differs  string
	}{
		{"another operation", "package.upgrade", payload, selector, "action"},
		{"another payload", "security.apply",
			json.RawMessage(`{"security":{"check_ids":["a","c"]}}`), selector, "payload"},
		{"another selector", "security.apply", payload,
			json.RawMessage(`{"exclude":[],"tags":["web"]}`), "selector"},
	} {
		t.Run(probe.name, func(t *testing.T) {
			differs, err := orderDiffers(existing, probe.action, probe.payload, probe.selector)
			if err != nil {
				t.Fatalf("comparing the repeat with the campaign: %v", err)
			}
			if differs != probe.differs {
				t.Errorf("%s was named %q and not %q", probe.name, differs, probe.differs)
			}
		})
	}
}

// The selector resolves to a different set of hosts as the fleet changes, and
// the same order placed twice over a fleet that changed in between is still the
// same order. Only what the caller wrote is compared.
func TestARepeatIsJudgedByWhatWasOrderedAndNotByWhatItResolvedTo(t *testing.T) {
	existing := Campaign{
		ID:         "c-2",
		ActionType: "unit.restart",
		Payload:    json.RawMessage(`{"unit":{"unit":"cron.service"}}`),
		Selector:   json.RawMessage(`{"tags":["web"]}`),
	}
	differs, err := orderDiffers(existing, "unit.restart",
		json.RawMessage(`{"unit":{"unit":"cron.service"}}`), json.RawMessage(`{"tags":["web"]}`))
	if err != nil {
		t.Fatalf("comparing the repeat with the campaign: %v", err)
	}
	if differs != "" {
		t.Errorf("a repeat of one order was refused over its %s", differs)
	}
}
