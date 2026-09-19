package outbox

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strconv"
	"testing"
	"time"
)

// A delivery carries the selected events in order, signed over its exact
// bytes; a receiver that refuses makes the delivery fail so the cursor stays.
func TestWebhookSignsAndFiltersTheDelivery(t *testing.T) {
	var got Delivery
	var signature string
	status := http.StatusOK
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		signature = r.Header.Get(SignatureHeader)
		timestamp := r.Header.Get(TimestampHeader)
		if !Verify("secret", body, timestamp, signature) {
			t.Errorf("the signature does not verify")
		}
		// The timestamp is under the signature: a delivery captured and
		// replayed with another moment does not verify.
		if Verify("secret", body, "1", signature) {
			t.Errorf("the signature verifies with another timestamp")
		}
		if sent, err := strconv.ParseInt(timestamp, 10, 64); err != nil ||
			time.Since(time.Unix(sent, 0)) > time.Minute {
			t.Errorf("the timestamp %q is not the moment of the delivery", timestamp)
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

// A receiver written against the previous form of the signature - over the
// body alone - keeps working for one release.
func TestWebhookVerifiesTheOlderSignature(t *testing.T) {
	body := []byte(`{"events":[]}`)
	if !Verify("secret", body, "1700000000", signBodyOnly("secret", body)) {
		t.Error("the signature over the body alone was refused")
	}
	if Verify("other", body, "1700000000", signBodyOnly("secret", body)) {
		t.Error("a signature with another secret verified")
	}
}
