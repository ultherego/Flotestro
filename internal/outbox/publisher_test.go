package outbox

import "testing"

// The notification is the wake-up call of every panel instance: it must
// carry the identifiers intact and nothing else, and a malformed one must
// be dropped rather than turned into an event with an empty identity.
func TestNotificationCarriesTheIdentifiers(t *testing.T) {
	payload := `{"id":42,"aggregate_type":"campaign_target","aggregate_id":"c1","event_type":"target.succeeded"}`
	id, aggregate, aggregateID, eventType, ok := Notification(payload)
	if !ok || id != 42 || aggregate != "campaign_target" || aggregateID != "c1" || eventType != "target.succeeded" {
		t.Fatalf("notification read as %d %s %s %s (%v)", id, aggregate, aggregateID, eventType, ok)
	}
	for _, bad := range []string{"", "{}", "not json", `{"id":0}`} {
		if _, _, _, _, ok := Notification(bad); ok {
			t.Errorf("%q was accepted as a notification", bad)
		}
	}
}
