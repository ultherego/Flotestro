//go:build integration

package integration

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

// The durable notification queue, against receivers that really answer. The
// tests run on the panel machine, so a server started here stands at 127.

// queueRowView is one row of the queue as the API serves it.
type queueRowView struct {
	ID            string     `json:"id"`
	ChannelID     string     `json:"channel_id"`
	ChannelName   string     `json:"channel_name"`
	EventID       int64      `json:"event_id"`
	EventType     string     `json:"event_type"`
	State         string     `json:"state"`
	Attempt       int        `json:"attempt"`
	NextAttemptAt time.Time  `json:"next_attempt_at"`
	LastErrorCode string     `json:"last_error_code"`
	LastError     string     `json:"last_error"`
	DeliveredAt   *time.Time `json:"delivered_at"`
	Status        string     `json:"status"`
}

type queueListView struct {
	Items       []queueRowView `json:"items"`
	DeadLetters int            `json:"dead_letters"`
}

// recipient is a receiver the panel really talks to.
type recipient struct {
	server   *httptest.Server
	status   atomic.Int64
	received atomic.Int64
	body     atomic.Value
}

func newRecipient(t *testing.T, status int) *recipient {
	t.Helper()
	r := &recipient{}
	r.status.Store(int64(status))
	r.server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, request *http.Request) {
		var payload map[string]any
		_ = json.NewDecoder(request.Body).Decode(&payload)
		r.body.Store(payload)
		r.received.Add(1)
		w.WriteHeader(int(r.status.Load()))
	}))
	t.Cleanup(r.server.Close)
	return r
}

// rowsOf reads the queue of one channel, newest first.
func rowsOf(h *harness, channelID string) queueListView {
	h.t.Helper()
	var list queueListView
	h.get("/api/v1/notifications/deliveries?channel_id="+channelID+"&limit=100", &list)
	return list
}

// awaitQueueRow waits until a row of the channel for the event satisfies the
// condition and returns it.
func awaitQueueRow(h *harness, channelID, eventType string, limit time.Duration,
	what string, ok func(queueRowView) bool) queueRowView {
	h.t.Helper()
	deadline := time.Now().Add(limit)
	var last queueRowView
	for time.Now().Before(deadline) {
		for _, row := range rowsOf(h, channelID).Items {
			if row.EventType != eventType {
				continue
			}
			last = row
			if ok(row) {
				return row
			}
		}
		time.Sleep(time.Second)
	}
	h.t.Fatalf("no row of %s on the channel %s %s within %s; the newest is %+v",
		eventType, channelID, what, limit, last)
	return queueRowView{}
}

// TestTheQueueHoldsAMessageUntilTheReceiverTakesIt guards chapter 10 of the
// security document end to end: the durable queue.
func TestTheQueueHoldsAMessageUntilTheReceiverTakesIt(t *testing.T) {
	h := newHarness(t)
	name := fmt.Sprintf("integration-queue-%d", time.Now().UnixNano())

	// The receiver that is down and comes back, and the one that refuses
	// the credentials whatever is sent to it.
	flaky := newRecipient(t, http.StatusInternalServerError)
	rejecting := newRecipient(t, http.StatusUnauthorized)

	// Both channels carry one subject, and the enrollment of a machine below is
	// what produces it.
	subject := "enrollment.completed"
	down := createChannel(h, map[string]any{
		"name": name + "-down", "kind": "webhook",
		"config": map[string]any{"url": flaky.server.URL, "secret": "integration-signing-secret"},
		"events": []string{subject}, "reason": notificationReason,
	})
	refusing := createChannel(h, map[string]any{
		"name": name + "-refusing", "kind": "webhook",
		"config": map[string]any{"url": rejecting.server.URL, "secret": "integration-signing-secret"},
		"events": []string{subject}, "reason": notificationReason,
	})

	// The event itself: a machine that does not exist joins the fleet.
	host := h.enrollSyntheticHost(t)
	if host.ID == "" {
		t.Fatal("the synthetic host was not enrolled")
	}

	// A 500 passes: the row waits for another attempt, with the attempt counted
	// on it and the transport code of the answer.
	waiting := awaitQueueRow(h, down.ID, subject, 60*time.Second, "waiting for another attempt",
		func(row queueRowView) bool { return row.State == "retry_wait" })
	if waiting.Attempt < 1 {
		t.Errorf("a row that failed an attempt counts %d attempts: %+v", waiting.Attempt, waiting)
	}
	if waiting.DeliveredAt != nil || waiting.Status == "sent" {
		t.Errorf("a row a receiver refused with a 500 is marked delivered: %+v", waiting)
	}
	if waiting.LastErrorCode == "" || waiting.LastError == "" {
		t.Errorf("the failed attempt left no typed reason: %+v", waiting)
	}
	if flaky.received.Load() == 0 {
		t.Error("the panel never reached the receiver that answered 500")
	}
	// The row names when it will be taken again: without it the screen
	// could not say "in a moment" rather than "never".
	if waiting.NextAttemptAt.IsZero() {
		t.Errorf("the row names no next attempt: %+v", waiting)
	}

	// A 401 is the credential's fault and cannot be mended by trying again, so
	// the row is a dead letter at once, with the code of the document rather than
	// the transport status.
	dead := awaitQueueRow(h, refusing.ID, subject, 60*time.Second, "refused as a dead letter",
		func(row queueRowView) bool { return row.State == "dead_letter" })
	if dead.LastErrorCode != "channel_credentials_rejected" {
		t.Errorf("a receiver that answered 401 left the code %q: %+v", dead.LastErrorCode, dead)
	}
	if dead.DeliveredAt != nil {
		t.Errorf("a dead letter is marked delivered: %+v", dead)
	}
	// The whole installation's dead letters are counted beside the page,
	// because that is what the screen has to show whatever the filter.
	if list := rowsOf(h, refusing.ID); list.DeadLetters < 1 {
		t.Errorf("the queue counts %d dead letters while one is listed", list.DeadLetters)
	}

	// The receiver comes back. Nothing is resent by hand: the row was
	// waiting all along, and the next attempt carries the same message.
	flaky.status.Store(int64(http.StatusOK))
	before := flaky.received.Load()
	// The first pause is the worker's base backoff with full jitter - up to half
	// a minute as the panel is configured - so the wait here is that pause and a
	// round of the queue, not a guess.
	delivered := awaitQueueRow(h, down.ID, subject, 60*time.Second, "delivered after the receiver came back",
		func(row queueRowView) bool { return row.State == "delivered" })
	if delivered.ID != waiting.ID {
		t.Errorf("the message was delivered as a new row %s rather than the waiting one %s", delivered.ID, waiting.ID)
	}
	if delivered.Attempt < 2 || delivered.DeliveredAt == nil {
		t.Errorf("the delivered row came back as %+v", delivered)
	}
	if flaky.received.Load() <= before {
		t.Error("the receiver that came back was never tried again")
	}
	if payload, ok := flaky.body.Load().(map[string]any); !ok || payload["event"] == nil {
		t.Errorf("the receiver was sent %v rather than the event", flaky.body.Load())
	}

	// A dead letter is an operator's to send again; the row goes back to the
	// queue with its attempts reset and the message it always carried.
	var retried queueRowView
	h.do(http.MethodPost, "/api/v1/notifications/deliveries/"+dead.ID+"/retry", nil, &retried, http.StatusOK)
	if retried.State != "pending" || retried.Attempt != 0 {
		t.Errorf("the retried dead letter came back as %+v", retried)
	}
	if retried.ID != dead.ID {
		t.Errorf("the retry made a new row %s rather than reviving %s", retried.ID, dead.ID)
	}
	// Only a dead letter can be put back: a row the worker still has in
	// hand is not an operator's to restart.
	h.do(http.MethodPost, "/api/v1/notifications/deliveries/"+delivered.ID+"/retry", nil, nil, http.StatusBadRequest)

	// And the credential never comes back out.
	var fetched struct {
		Config           json.RawMessage `json:"config"`
		PublicConfig     json.RawMessage `json:"public_config"`
		SecretConfigured bool            `json:"secret_configured"`
		SecretRotatedAt  *time.Time      `json:"secret_last_rotated_at"`
	}
	h.get("/api/v1/notifications/channels/"+down.ID, &fetched)
	if !fetched.SecretConfigured || fetched.SecretRotatedAt == nil {
		t.Errorf("the channel does not say its secret is configured: %+v", fetched)
	}
	var config map[string]any
	_ = json.Unmarshal(fetched.Config, &config)
	if _, present := config["secret"]; present {
		t.Errorf("the signing secret came back on the channel: %s", fetched.Config)
	}
}

// TestAnIncomingWebhookKeepsItsAddress guards the other half of the same rule.
func TestAnIncomingWebhookKeepsItsAddress(t *testing.T) {
	h := newHarness(t)
	name := fmt.Sprintf("integration-incoming-%d", time.Now().UnixNano())
	room := newRecipient(t, http.StatusOK)

	// Disabled: this test is about what the API shows, and a channel that
	// carried the events of the other tests would only add noise.
	channel := createChannel(h, map[string]any{
		"name": name, "kind": "slack_webhook",
		"config":  map[string]any{"url": room.server.URL + "/services/T0/B0/token"},
		"events":  []string{"host.offline"},
		"enabled": false, "reason": notificationReason,
	})

	var fetched struct {
		Config           json.RawMessage `json:"config"`
		PublicConfig     json.RawMessage `json:"public_config"`
		SecretConfigured bool            `json:"secret_configured"`
	}
	h.get("/api/v1/notifications/channels/"+channel.ID, &fetched)
	if !fetched.SecretConfigured {
		t.Errorf("the channel does not say its address is configured: %+v", fetched)
	}
	var config map[string]any
	_ = json.Unmarshal(fetched.Config, &config)
	if url, _ := config["url"].(string); url != "" {
		t.Errorf("the address of the incoming webhook came back: %s", fetched.Config)
	}
	if config["url_set"] != true {
		t.Errorf("the channel does not say an address is set: %s", fetched.Config)
	}
	// The summary beside it names the host and nothing of the path, so an
	// operator tells the right receiver from a mistyped one without ever being
	// shown the token.
	var public map[string]any
	_ = json.Unmarshal(fetched.PublicConfig, &public)
	host, _ := public["display_host"].(string)
	if host == "" {
		t.Errorf("the public summary names no host: %s", fetched.PublicConfig)
	}
	for _, secret := range []string{"/services/", "T0", "B0", "token"} {
		if strings.Contains(string(fetched.PublicConfig), secret) {
			t.Errorf("the public summary carries %q of the address: %s", secret, fetched.PublicConfig)
		}
	}

	// The test button still sends: the worker reads the address from the
	// secret store at the moment of sending, and the room answers.
	var outcome queueRowView
	h.do(http.MethodPost, "/api/v1/notifications/channels/"+channel.ID+"/test", nil, &outcome, http.StatusOK)
	if outcome.State != "delivered" || room.received.Load() == 0 {
		t.Errorf("the test of an incoming webhook came back as %+v after %d requests",
			outcome, room.received.Load())
	}

	// An edit that types no address keeps the stored one: the channel still sends
	// afterwards, which is the only way to tell "kept" from "quietly emptied".
	h.do(http.MethodPut, "/api/v1/notifications/channels/"+channel.ID, map[string]any{
		"name": name, "kind": "slack_webhook",
		"config":  map[string]any{"url_set": true},
		"events":  []string{"host.offline", "alert.fired"},
		"enabled": false, "reason": "the events of the channel changed",
	}, nil, http.StatusOK)
	before := room.received.Load()
	h.do(http.MethodPost, "/api/v1/notifications/channels/"+channel.ID+"/test", nil, &outcome, http.StatusOK)
	if outcome.State != "delivered" || room.received.Load() <= before {
		t.Errorf("the edit lost the stored address: %+v", outcome)
	}
}
