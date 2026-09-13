package outbox

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

// A delivery carries the selected events in order, signed over its exact
// bytes; a receiver that refuses makes the delivery fail so the cursor
// stays.
func TestWebhookSignsAndFiltersTheDelivery(t *testing.T) {
	var got Delivery
	var signature string
	status := http.StatusOK
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		signature = r.Header.Get(SignatureHeader)
		if !Verify("secret", body, signature) {
			t.Errorf("the signature does not verify")
		}
		_ = json.Unmarshal(body, &got)
		w.WriteHeader(status)
	}))
	defer server.Close()

	hook := Webhook{URL: server.URL, Secret: "secret", Prefixes: []string{"campaign."}}
	events := []Event{
		{ID: 1, Type: "target.running", Payload: json.RawMessage(`{}`), OccurredAt: time.Now()},
		{ID: 2, Type: "campaign.completed", Payload: json.RawMessage(`{"name":"x"}`), OccurredAt: time.Now()},
	}
	if err := hook.Deliver(context.Background(), events); err != nil {
		t.Fatalf("delivery: %v", err)
	}
	if len(got.Events) != 1 || got.Events[0].ID != 2 || got.FirstID != 2 || got.LastID != 2 {
		t.Fatalf("delivered %+v", got)
	}
	if signature == "" {
		t.Fatal("the delivery was not signed")
	}

	status = http.StatusBadGateway
	if err := hook.Deliver(context.Background(), events); err == nil {
		t.Fatal("a refused delivery counted as delivered")
	}

	// Nothing matching means nothing sent - and no error.
	if err := (Webhook{URL: "http://127.0.0.1:1", Prefixes: []string{"nothing."}}).Deliver(
		context.Background(), events); err != nil {
		t.Fatalf("an empty delivery reached the network: %v", err)
	}
}
