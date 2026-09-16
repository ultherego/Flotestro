package notify

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/ultherego/flotestro/internal/outbox"
)

// A channel carries the subjects it names and nothing else; the terminal
// campaign states fold into one subject, and the filter narrows by the
// severity of an alert and by the part of the fleet.
func TestSubjectsAndFilters(t *testing.T) {
	for eventType, want := range map[string]string{
		"campaign.completed": "campaign.finished", "campaign.canceled": "campaign.finished",
		"alert.fired": "alert.fired", "host.offline": "host.offline",
	} {
		if got, ok := SubjectOf(eventType); !ok || got != want {
			t.Errorf("SubjectOf(%q) = %q, %v; want %q", eventType, got, ok, want)
		}
	}
	for _, eventType := range []string{"campaign.running", "target.failed", "campaign.paused"} {
		if _, ok := SubjectOf(eventType); ok {
			t.Errorf("%q is carried although it is a phase, not news", eventType)
		}
	}

	filter := Filter{SeverityMin: "warning", Site: "krakow"}
	cases := []struct {
		scope Scope
		want  bool
	}{
		{Scope{Severity: "critical", Site: "krakow"}, true},
		{Scope{Severity: "info", Site: "krakow"}, false},
		{Scope{Severity: "warning", Site: "warsaw"}, false},
		// An event without a severity or a site is not an alert of another
		// site: unknown passes rather than fails.
		{Scope{}, true},
		{Scope{Site: "krakow"}, true},
	}
	for _, c := range cases {
		if got := filter.Matches(c.scope); got != c.want {
			t.Errorf("Matches(%+v) = %v, want %v", c.scope, got, c.want)
		}
	}
}

// The validation refuses what could never send and normalises the rest.
func TestChannelValidation(t *testing.T) {
	channel := Channel{Name: " ops ", Kind: KindEmail, Events: []string{"alert.fired", "alert.fired"},
		Config: json.RawMessage(`{"host":"mail.example.com","from":"panel@example.com","to":["a@example.com",""],"username":"u","password_secret":"smtp-pass","starttls":true}`)}
	config, err := channel.Validate()
	if err != nil {
		t.Fatalf("a sound mailbox was refused: %v", err)
	}
	email := config.(EmailConfig)
	if channel.Name != "ops" || len(channel.Events) != 1 || email.Port != 587 || len(email.To) != 1 {
		t.Errorf("the channel was not normalised: %+v %+v", channel, email)
	}

	refused := []Channel{
		{Name: "x", Kind: "pigeon", Config: json.RawMessage(`{}`)},
		{Name: "x", Kind: KindWebhook, Config: json.RawMessage(`{"url":"ftp://x"}`)},
		{Name: "x", Kind: KindWebhook, Events: []string{"weather"}, Config: json.RawMessage(`{"url":"https://x"}`)},
		{Name: "x", Kind: KindEmail, Config: json.RawMessage(`{"host":"h","from":"not an address","to":["a@b"]}`)},
		{Name: "x", Kind: KindEmail, Config: json.RawMessage(`{"host":"h","from":"a@b","to":["a@b"],"username":"u","password_secret":"p","starttls":false}`)},
		{Name: "x", Kind: KindEmail, Config: json.RawMessage(`{"host":"h","from":"a@b","to":["a@b"],"username":"u"}`)},
		{Name: "x", Kind: KindWebhook, Filter: Filter{SeverityMin: "loud"}, Config: json.RawMessage(`{"url":"https://x"}`)},
	}
	for i, channel := range refused {
		var refusal Error
		if _, err := channel.Validate(); err == nil || !asError(err, &refusal) || refusal.Code == "" {
			t.Errorf("case %d was accepted or refused without a code: %v", i, err)
		}
	}
}

func asError(err error, target *Error) bool {
	e, ok := err.(Error)
	if ok {
		*target = e
	}
	return ok
}

// A webhook delivery is signed the way the legacy webhook signs, so one
// receiver reads both; a refusal of the receiver is a typed failure.
func TestWebhookSenderSignsAndTypesTheRefusal(t *testing.T) {
	status := http.StatusOK
	var got Message
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		if !outbox.Verify("secret", body, r.Header.Get(outbox.TimestampHeader), r.Header.Get(outbox.SignatureHeader)) {
			t.Errorf("the signature does not verify")
		}
		_ = json.Unmarshal(body, &got)
		w.WriteHeader(status)
	}))
	defer server.Close()

	channel := Channel{ID: "c", Name: "hook", Kind: KindWebhook,
		Config: json.RawMessage(`{"url":"` + server.URL + `","secret":"secret"}`)}
	event := outbox.Event{ID: 7, Aggregate: "alert", AggregateID: "a", Type: "alert.fired",
		Payload:    json.RawMessage(`{"rule_name":"Filesystem full","metric":"filesystem_used_percent","severity":"critical","host_id":"h","hostname":"web-1","value":98.5,"detail":"/ at 98.5%"}`),
		OccurredAt: time.Now()}
	message, ok := Compose(event, "https://panel.example.com/")
	if !ok || message.Subject != "alert.fired" || message.Severity != "critical" ||
		message.Title != "[critical] Filesystem full on web-1" ||
		message.Link != "https://panel.example.com/hosts/h/monitoring" {
		t.Fatalf("the message reads %+v", message)
	}
	if err := (WebhookSender{Client: server.Client()}).Send(context.Background(), channel, message); err != nil {
		t.Fatalf("the delivery failed: %v", err)
	}
	if got.EventID != 7 || got.Title != message.Title {
		t.Errorf("the receiver got %+v", got)
	}

	status = http.StatusBadGateway
	err := (WebhookSender{Client: server.Client()}).Send(context.Background(), channel, message)
	var failure SendError
	if !asSendError(err, &failure) || failure.Code != CodeReceiverStatus {
		t.Errorf("a 502 was typed as %v", err)
	}

	refused := Channel{ID: "c", Name: "hook", Kind: KindWebhook, Config: json.RawMessage(`{"url":"http://127.0.0.1:1/"}`)}
	err = (WebhookSender{}).Send(context.Background(), refused, message)
	if !asSendError(err, &failure) || failure.Code != CodeConnectionRefused {
		t.Errorf("a closed port was typed as %v", err)
	}
}

func asSendError(err error, target *SendError) bool {
	e, ok := err.(SendError)
	if ok {
		*target = e
	}
	return ok
}

// The address of an incoming webhook is the credential that posts to the
// channel: the store shows only that it is set, and an edit that says so
// without typing one keeps the stored address. A new channel has nothing
// stored, so "set" without an address is refused at the store, not here.
func TestTheSlackAddressIsRedactedLikeASecret(t *testing.T) {
	shown := redact(KindSlackWebhook, json.RawMessage(`{"url":"https://hooks.example.com/T0/B0/secret"}`))
	var config map[string]any
	if err := json.Unmarshal(shown, &config); err != nil {
		t.Fatal(err)
	}
	if url, present := config["url"]; present && url != "" {
		t.Fatalf("the address left the store: %s", shown)
	}
	if config["url_set"] != true {
		t.Fatalf("the redacted configuration does not say the address is set: %s", shown)
	}
	if empty := redact(KindSlackWebhook, json.RawMessage(`{}`)); string(empty) != `{}` {
		t.Errorf("a channel without an address reads as having one: %s", empty)
	}

	kept := Channel{Name: "ops", Kind: KindSlackWebhook, Events: []string{"alert.fired"},
		Config: json.RawMessage(`{"url_set":true}`)}
	config2, err := kept.Validate()
	if err != nil {
		t.Fatalf("an edit that keeps the address was refused: %v", err)
	}
	if slack := config2.(SlackConfig); slack.URL != "" || !slack.URLSet {
		t.Errorf("the kept address is not marked as kept: %+v", slack)
	}
	fresh := Channel{Name: "ops", Kind: KindSlackWebhook, Events: []string{"alert.fired"},
		Config: json.RawMessage(`{"url":"https://hooks.example.com/T0/B0/new"}`)}
	config3, err := fresh.Validate()
	if err != nil {
		t.Fatalf("a fresh address was refused: %v", err)
	}
	if slack := config3.(SlackConfig); slack.URL == "" || slack.URLSet {
		t.Errorf("a typed address was not taken: %+v", slack)
	}
	none := Channel{Name: "ops", Kind: KindSlackWebhook, Events: []string{"alert.fired"},
		Config: json.RawMessage(`{}`)}
	if _, err := none.Validate(); err == nil {
		t.Error("a channel with neither an address nor a kept one was accepted")
	}
}
