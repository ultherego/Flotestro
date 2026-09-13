package outbox

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"
)

// Webhook delivers batches of events to one HTTP endpoint.
//
// The body is signed with HMAC-SHA256 over its exact bytes, so the receiver
// can tell the panel from anybody who learned the address. The receiver
// answers 2xx for a delivery it has taken; anything else, a timeout
// included, means the batch goes out again later - the receiver has to
// deduplicate by the event identifier.
type Webhook struct {
	URL    string
	Secret string
	// Prefixes narrows the events to those whose type starts with one of
	// them, e.g. "campaign." - empty means every event.
	Prefixes []string
	Client   *http.Client
}

// Delivery is the body of one webhook call.
type Delivery struct {
	// Events are in the order of the trail; FirstID and LastID repeat the
	// range so that a receiver can log the delivery without reading it.
	FirstID int64   `json:"first_id"`
	LastID  int64   `json:"last_id"`
	Events  []Event `json:"events"`
}

// The headers of a delivery.
const (
	SignatureHeader = "X-Flotestro-Signature"
	DeliveryHeader  = "X-Flotestro-Delivery"
)

// Deliver posts the batch. Events outside the prefixes are skipped, and a
// batch with nothing left to send is delivered without a call.
func (w Webhook) Deliver(ctx context.Context, events []Event) error {
	selected := make([]Event, 0, len(events))
	for _, event := range events {
		if w.matches(event.Type) {
			selected = append(selected, event)
		}
	}
	if len(selected) == 0 {
		return nil
	}
	body, err := json.Marshal(Delivery{
		FirstID: selected[0].ID, LastID: selected[len(selected)-1].ID, Events: selected,
	})
	if err != nil {
		return err
	}

	ctx, cancel := context.WithTimeout(ctx, 15*time.Second)
	defer cancel()
	request, err := http.NewRequestWithContext(ctx, http.MethodPost, w.URL, bytes.NewReader(body))
	if err != nil {
		return err
	}
	request.Header.Set("Content-Type", "application/json")
	request.Header.Set("User-Agent", "flotestro-webhook")
	request.Header.Set(DeliveryHeader, fmt.Sprintf("%d-%d", selected[0].ID, selected[len(selected)-1].ID))
	request.Header.Set(SignatureHeader, Sign(w.Secret, body))

	client := w.Client
	if client == nil {
		client = http.DefaultClient
	}
	response, err := client.Do(request)
	if err != nil {
		return err
	}
	defer response.Body.Close()
	// The answer is read and dropped so the connection can be reused; what
	// matters is the status alone.
	_, _ = io.Copy(io.Discard, io.LimitReader(response.Body, 64*1024))
	if response.StatusCode < 200 || response.StatusCode >= 300 {
		return fmt.Errorf("the receiver answered %d", response.StatusCode)
	}
	return nil
}

func (w Webhook) matches(eventType string) bool {
	if len(w.Prefixes) == 0 {
		return true
	}
	for _, prefix := range w.Prefixes {
		if strings.HasPrefix(eventType, prefix) {
			return true
		}
	}
	return false
}

// Sign computes the signature of a body: "sha256=" and the hex HMAC.
func Sign(secret string, body []byte) string {
	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write(body)
	return "sha256=" + hex.EncodeToString(mac.Sum(nil))
}

// Verify checks a signature against the body; a receiver uses it.
func Verify(secret string, body []byte, signature string) bool {
	return hmac.Equal([]byte(Sign(secret, body)), []byte(signature))
}
