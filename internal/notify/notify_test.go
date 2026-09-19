package notify

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
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
		// The place is fail-closed: an event that names no site is not known to be
		// this site's, and a channel of one site is told only what is known to be
		// its own.
		{Scope{}, false},
		{Scope{Site: "krakow"}, true},
		{Scope{Severity: "critical"}, false},
	}
	for _, c := range cases {
		if got := filter.Matches(c.scope); got != c.want {
			t.Errorf("Matches(%+v) = %v, want %v", c.scope, got, c.want)
		}
	}
	// The explicitly global channel - no site, no environment - is the one an
	// event of unknown place reaches; an environment filter is as closed as a
	// site filter.
	global := Filter{}
	if !global.Global() || !global.Matches(Scope{}) || !global.Matches(Scope{Site: "warsaw", Environment: "prod"}) {
		t.Error("the global channel does not carry an event of unknown place or of any place")
	}
	environment := Filter{Environment: "prod"}
	if environment.Global() || environment.Matches(Scope{Site: "krakow"}) || !environment.Matches(Scope{Environment: "prod"}) {
		t.Error("an environment filter passed an event of unknown environment")
	}
	// Security alerts of the installation are one subject whatever their
	// exact type, and the channel has to subscribe to it by name.
	if subject, ok := SubjectOf("security.duplicate_identity"); !ok || subject != SubjectSecurity {
		t.Errorf("a security event is carried as %q, %v", subject, ok)
	}
	if !KnownSubject(SubjectSecurity) {
		t.Error("the security subject is not in the catalogue")
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
	if !asSendError(err, &failure) || failure.Code != CodeReceiverStatus || failure.Status != http.StatusBadGateway {
		t.Errorf("a 502 was typed as %v", err)
	}

	refused := Channel{ID: "c", Name: "hook", Kind: KindWebhook, Config: json.RawMessage(`{"url":"http://127.0.0.1:1/"}`)}
	err = (WebhookSender{}).Send(context.Background(), refused, message)
	if !asSendError(err, &failure) || failure.Code != CodeConnectionRefused {
		t.Errorf("a closed port was typed as %v", err)
	}

	// The signing key comes from the secret store with the channel; a row that
	// carries it in the configuration is one from before the move, and both sign
	// the same way.
	status = http.StatusOK
	fromStore := Channel{ID: "c", Name: "hook", Kind: KindWebhook,
		Config: json.RawMessage(`{"url":"` + server.URL + `"}`)}.WithSecret("secret")
	if err := (WebhookSender{Client: server.Client()}).Send(context.Background(), fromStore, message); err != nil {
		t.Fatalf("the delivery signed with the stored secret failed: %v", err)
	}
}

// The sentence of a transport failure never carries the address: the address
// of an incoming webhook is the credential, and the log is read by people the
// credential is kept from.
func TestTheFailureSentenceKeepsTheAddressOut(t *testing.T) {
	channel := Channel{ID: "c", Name: "room", Kind: KindSlackWebhook, Config: json.RawMessage(`{}`)}.
		WithSecret("http://127.0.0.1:1/services/T0/B0/the-token")
	err := (SlackSender{}).Send(context.Background(), channel, Message{Title: "x"})
	var failure SendError
	if !asSendError(err, &failure) || failure.Code != CodeConnectionRefused {
		t.Fatalf("a closed port was typed as %v", err)
	}
	if strings.Contains(failure.Error(), "the-token") || strings.Contains(failure.Error(), "127.0.0.1:1/") {
		t.Errorf("the sentence carries the address: %s", failure.Error())
	}
	// A channel whose address is in neither the store nor the row cannot
	// send, and says so as a missing secret rather than a bad request.
	none := Channel{ID: "c", Name: "room", Kind: KindSlackWebhook, Config: json.RawMessage(`{}`)}
	if err := (SlackSender{}).Send(context.Background(), none, Message{}); !asSendError(err, &failure) || failure.Code != CodeSecretUnavailable {
		t.Errorf("a channel without an address was typed as %v", err)
	}
}

// The classification of an attempt is the document's table: 2xx is delivered,
// 408/429/5xx and a network error pass to the next attempt until the attempts
// run out, 401/403 are the credential's fault, and any other status is
func TestClassifyFollowsTheTable(t *testing.T) {
	status := func(code int) error {
		return SendError{Code: CodeReceiverStatus, Status: code, Err: errors.New("the receiver answered")}
	}
	cases := []struct {
		name    string
		err     error
		attempt int
		state   string
		code    string
	}{
		{"delivered", nil, 1, StateDelivered, ""},
		{"500 passes", status(500), 1, StateRetryWait, CodeReceiverStatus},
		{"503 passes", status(503), 5, StateRetryWait, CodeReceiverStatus},
		{"429 passes", status(429), 1, StateRetryWait, CodeReceiverStatus},
		{"408 passes", status(408), 1, StateRetryWait, CodeReceiverStatus},
		{"401 is the credential", status(401), 1, StateDeadLetter, CodeCredentialsRejected},
		{"403 is the credential", status(403), 1, StateDeadLetter, CodeCredentialsRejected},
		{"404 is permanent", status(404), 1, StateDeadLetter, CodePermanentHTTP},
		{"400 is permanent", status(400), 1, StateDeadLetter, CodePermanentHTTP},
		{"refused passes", SendError{Code: CodeConnectionRefused, Err: errors.New("refused")}, 1, StateRetryWait, CodeConnectionRefused},
		{"dns passes", SendError{Code: CodeDNSFailure, Err: errors.New("no such host")}, 3, StateRetryWait, CodeDNSFailure},
		{"timeout passes", context.DeadlineExceeded, 1, StateRetryWait, CodeTimeout},
		{"secret store passes", SendError{Code: CodeSecretUnavailable, Err: errors.New("no key")}, 1, StateRetryWait, CodeSecretUnavailable},
		{"the last attempt keeps the receiver's own answer", status(500), 20, StateDeadLetter, CodeReceiverStatus},
		{"a refusal on the last attempt keeps its reason", SendError{Code: CodeConnectionRefused, Err: errors.New("refused")}, 20, StateDeadLetter, CodeConnectionRefused},
		{"a bad login is the credential", SendError{Code: CodeSMTPAuthFailed, Err: errors.New("535")}, 1, StateDeadLetter, CodeCredentialsRejected},
		{"a 4xx reply passes", SendError{Code: CodeSMTPRejected, Status: 451, Err: errors.New("try later")}, 1, StateRetryWait, CodeSMTPRejected},
		{"a 5xx reply is permanent", SendError{Code: CodeSMTPRejected, Status: 550, Err: errors.New("no such user")}, 1, StateDeadLetter, CodePermanentSMTP},
		{"a configuration that does not read", SendError{Code: CodeInvalidConfig, Err: errors.New("bad json")}, 1, StateDeadLetter, CodeChannelMisconfigured},
	}
	for _, c := range cases {
		outcome := Classify(c.err, c.attempt, 20)
		if outcome.State != c.state || outcome.ErrorCode != c.code {
			t.Errorf("%s: classified as %s/%s, want %s/%s", c.name, outcome.State, outcome.ErrorCode, c.state, c.code)
		}
		if c.err != nil && outcome.Error == "" {
			t.Errorf("%s: the failure has no sentence", c.name)
		}
	}
}

// The pause before the next attempt doubles from the base up to the cap, and
// the jitter draws anywhere below it: attempt one waits at most the base,
// attempt seven at most the cap of an hour, and a draw of zero is an attempt
func TestBackoffIsExponentialWithFullJitter(t *testing.T) {
	base, ceiling := 30*time.Second, time.Hour
	for attempt, want := range map[int]time.Duration{
		1: 30 * time.Second, 2: time.Minute, 3: 2 * time.Minute, 6: 16 * time.Minute, 7: 32 * time.Minute,
		8: time.Hour, 20: time.Hour, 200: time.Hour,
	} {
		if got := Backoff(attempt, base, ceiling, 1); got != want {
			t.Errorf("attempt %d: the pause is %s, want %s", attempt, got, want)
		}
		if got := Backoff(attempt, base, ceiling, 0.5); got != want/2 {
			t.Errorf("attempt %d: half the draw is %s, want %s", attempt, got, want/2)
		}
	}
	if Backoff(1, base, ceiling, 0) != 0 || Backoff(0, base, ceiling, 1) != base {
		t.Error("a draw of zero, or an attempt below one, is not handled")
	}
}

// The suppression: a silence of the host, the rule or both keeps back the
// alerts of the host; a maintenance window keeps back everything of the host;
// a security alert of the installation is kept back by a global silence alone,
func TestDecideAppliesSilencesAndMaintenance(t *testing.T) {
	until := time.Date(2026, 9, 17, 12, 0, 0, 0, time.UTC)
	scoped := silence{ID: "s1", HostID: "h1", RuleID: "r1", Until: until, Reason: "disk swap"}
	global := silence{ID: "s2", Until: until, Reason: "planned audit", Global: true}
	window := &maintenance{Until: until, Reason: "kernel patching"}

	verdict := Decide("alert.fired", "h1", []silence{scoped}, nil)
	if !verdict.Suppressed || verdict.PolicyID != "s1" || verdict.Reason != SuppressedBySilence ||
		!strings.Contains(verdict.Sentence, "disk swap") {
		t.Errorf("a silenced alert reads %+v", verdict)
	}
	verdict = Decide("host.offline", "h1", nil, window)
	if !verdict.Suppressed || verdict.PolicyID != "" || verdict.Reason != SuppressedByMaintenance ||
		!strings.Contains(verdict.Sentence, "kernel patching") {
		t.Errorf("an event in a maintenance window reads %+v", verdict)
	}
	if verdict := Decide("alert.fired", "h1", nil, nil); verdict.Suppressed {
		t.Errorf("an alert without a silence was kept back: %+v", verdict)
	}
	// The security alert: the scoped silence and the window do not keep
	// it back; the global silence does.
	if verdict := Decide(SubjectSecurity, "h1", []silence{scoped}, window); verdict.Suppressed {
		t.Errorf("a scoped silence kept back a security alert: %+v", verdict)
	}
	if verdict := Decide(SubjectSecurity, "h1", []silence{scoped, global}, nil); !verdict.Suppressed || verdict.PolicyID != "s2" {
		t.Errorf("a global silence did not keep back a security alert: %+v", verdict)
	}
	// A global silence is written for the security alerts; it is not a
	// silence of every alert of every host.
	if verdict := Decide("alert.fired", "h1", []silence{global}, nil); verdict.Suppressed {
		t.Errorf("a global silence kept back an ordinary alert: %+v", verdict)
	}
	// An event that names no host is outside every window.
	if verdict := Decide("campaign.finished", "", nil, window); verdict.Suppressed {
		t.Errorf("a campaign end was kept back by a host's window: %+v", verdict)
	}
}

// The summary after a silence names what was kept back, bounded, and
// never the messages themselves.
func TestSummaryMessageIsBounded(t *testing.T) {
	kept := make([]string, MaxSummaryLines+3)
	for i := range kept {
		kept[i] = fmt.Sprintf("[warning] Filesystem full on web-%d", i)
	}
	until := time.Date(2026, 9, 17, 12, 0, 0, 0, time.UTC)
	message := SummaryMessage(kept, until, "disk swap", "https://panel.example.com/")
	if message.Subject != "alert.summary" || !strings.Contains(message.Title, fmt.Sprint(len(kept))) {
		t.Errorf("the summary reads %+v", message)
	}
	if !strings.Contains(message.Text, "... and 3 more") || !strings.Contains(message.Text, "web-0") ||
		strings.Contains(message.Text, "web-52") {
		t.Errorf("the summary is not bounded as it should be: %s", message.Text)
	}
	if message.Link != "https://panel.example.com/monitoring" {
		t.Errorf("the summary links to %q", message.Link)
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
// without typing one keeps the stored address.
func TestTheSlackAddressIsRedactedLikeASecret(t *testing.T) {
	shown := redact(KindSlackWebhook, json.RawMessage(`{"url":"https://hooks.example.com/T0/B0/secret"}`), false)
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
	if empty := redact(KindSlackWebhook, json.RawMessage(`{}`), false); string(empty) != `{}` {
		t.Errorf("a channel without an address reads as having one: %s", empty)
	}
	if moved := redact(KindSlackWebhook, json.RawMessage(`{}`), true); string(moved) != `{"url_set":true}` {
		t.Errorf("a channel with its address in the store does not say so: %s", moved)
	}
	if hook := redact(KindWebhook, json.RawMessage(`{"url":"https://x"}`), true); string(hook) != `{"url":"https://x","secret_set":true}` {
		t.Errorf("a webhook with its secret in the store does not say so: %s", hook)
	}

	// What goes to the store and what goes to the row: the credential leaves the
	// configuration, and the public summary names the host alone.
	credential, stored := credentialOf(SlackConfig{URL: "https://hooks.example.com/T0/B0/secret"})
	if credential != "https://hooks.example.com/T0/B0/secret" || stored.(SlackConfig).URL != "" {
		t.Errorf("the address was not moved out: %q %+v", credential, stored)
	}
	public := string(publicConfigOf(KindSlackWebhook, SlackConfig{URL: credential}, ""))
	if !strings.Contains(public, `"display_host":"hooks.example.com"`) || strings.Contains(public, "secret") {
		t.Errorf("the public summary reads %s", public)
	}
	if name := ChannelSecretName("0f1e2d3c-0000-4000-8000-000000000000"); !strings.HasPrefix(name, ChannelSecretPrefix) || !secretName.MatchString(name) {
		t.Errorf("the name of a channel's secret does not read as a secret name: %s", name)
	}
	// A mailbox cannot name a channel's own secret as its password.
	mail := Channel{Name: "ops", Kind: KindEmail, Events: []string{"alert.fired"},
		Config: json.RawMessage(`{"host":"h","from":"a@b","to":["a@b"],"username":"u","starttls":true,"password_secret":"` + ChannelSecretName("x") + `"}`)}
	if _, err := mail.Validate(); err == nil {
		t.Error("a mailbox naming a channel's secret as its password was accepted")
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
