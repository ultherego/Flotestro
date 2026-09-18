package adminapi

import (
	"net/url"
	"testing"
	"time"

	"github.com/ultherego/flotestro/internal/notify"
)

// The delivery list is narrowed by two vocabularies at once: the previous
// release's status and the queue's own state. Both have to be read, and a
// word neither knows has to be a refusal rather than a filter that
// quietly matches nothing - an operator who mistypes dead-letter is owed
// an answer, not an empty table that reads as "all clear".
func TestDeliveryFilterReadsBothVocabulariesAndRefusesTheRest(t *testing.T) {
	filter, code, _ := deliveryFilterOf(url.Values{
		"channel_id": {"c1"}, "state": {notify.StateDeadLetter},
		"since": {"2026-09-18T10:00:00Z"}, "limit": {"25"},
	})
	if code != "" {
		t.Fatalf("a query that reads was refused as %s", code)
	}
	if filter.ChannelID != "c1" || filter.State != notify.StateDeadLetter || filter.Limit != 25 {
		t.Errorf("the query was read as %+v", filter)
	}
	if !filter.Since.Equal(time.Date(2026, 9, 18, 10, 0, 0, 0, time.UTC)) {
		t.Errorf("the moment was read as %s", filter.Since)
	}

	// The old word still narrows, so the links and the exports written
	// under it keep working.
	if filter, code, _ := deliveryFilterOf(url.Values{"status": {notify.StatusFailed}}); code != "" ||
		filter.Status != notify.StatusFailed {
		t.Errorf("the previous release's status was refused as %s", code)
	}

	// Every state of the queue is a state the list takes.
	for _, state := range notify.States {
		if _, code, _ := deliveryFilterOf(url.Values{"state": {state}}); code != "" {
			t.Errorf("the state %s was refused as %s", state, code)
		}
	}

	for name, query := range map[string]url.Values{
		"a state nobody has":  {"state": {"dead-letter"}},
		"a status nobody has": {"status": {"queued"}},
		"a moment that is no": {"since": {"yesterday"}},
	} {
		if _, code, message := deliveryFilterOf(query); code == "" {
			t.Errorf("%s passed as a filter", name)
		} else if message == "" {
			t.Errorf("%s was refused as %s without a sentence", name, code)
		}
	}

	// An empty query is the whole queue, not a refusal.
	if filter, code, _ := deliveryFilterOf(url.Values{}); code != "" || filter.State != "" || filter.Status != "" {
		t.Errorf("an empty query was read as %+v (%s)", filter, code)
	}
}
