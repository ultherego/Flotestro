package notify

import (
	"context"
	"encoding/json"
	"errors"
	"log/slog"
	"strings"
	"testing"
	"time"
)

// queueFake answers the calls the send path makes; the embedded store is nil,
// so a call the path did not make before is a panic and not a quiet pass.
type queueFake struct {
	*Store
	channel    Channel
	suppressed *Verdict
	settled    *Outcome
}

func (q *queueFake) Renew(context.Context, string, string, time.Duration) (bool, error) {
	return true, nil
}

func (q *queueFake) get(context.Context, string) (*Channel, error) {
	channel := q.channel
	return &channel, nil
}

func (q *queueFake) withSecret(_ context.Context, channel Channel) (Channel, error) {
	return channel, nil
}

func (q *queueFake) Settle(_ context.Context, _, _ string, outcome Outcome) error {
	q.settled = &outcome
	return nil
}

func (q *queueFake) settleSuppressed(_ context.Context, _, _ string, verdict Verdict) error {
	q.suppressed = &verdict
	return nil
}

// checkFake is the suppression of the moment: what the router would read from
// the silences at the instant the row is sent.
type checkFake struct {
	verdict  Verdict
	err      error
	channels []string
	subjects []string
}

func (c *checkFake) Recheck(_ context.Context, channelID string, message Message) (Verdict, error) {
	c.channels = append(c.channels, channelID)
	c.subjects = append(c.subjects, message.Subject)
	return c.verdict, c.err
}

type senderFake struct {
	sent []Message
}

func (s *senderFake) Send(_ context.Context, _ Channel, message Message) error {
	s.sent = append(s.sent, message)
	return nil
}

// waitingRow is a row that failed once and waited in retry_wait; the claim
// leased it and raised its attempt.
func waitingRow(t *testing.T, subject, eventType string) Delivery {
	t.Helper()
	message := Message{
		Subject: subject, EventType: eventType, Aggregate: "alert", AggregateID: "a1",
		Payload: json.RawMessage(`{"host_id":"h1","rule_id":"r1","severity":"critical"}`),
		Title:   "[critical] disk full on h1",
	}
	row := Delivery{
		ID: "d1", ChannelID: "c1", EventType: eventType, State: StateLeased,
		Attempt: 2, LastErrorCode: CodeTimeout, LastError: "timeout",
	}
	row, err := row.WithMessage(message)
	if err != nil {
		t.Fatalf("the row did not take its message: %v", err)
	}
	return row
}

func workerFake(store *queueFake, check suppressionCheck, sender Sender) *Worker {
	return &Worker{
		store: store, senders: map[string]Sender{KindWebhook: sender},
		log: slog.New(slog.DiscardHandler), options: Options{}.withDefaults(),
		suppression: check, owner: "owner", wake: make(chan struct{}, 1),
		summaryWake: make(chan struct{}, 1), random: func() float64 { return 0 },
	}
}

func newQueueFake() *queueFake {
	return &queueFake{channel: Channel{ID: "c1", Name: "ops", Kind: KindWebhook, Enabled: true}}
}

// The suppression is decided again at the instant the row would be sent: a
// silence an operator started while the row waited in backoff reaches it.
func TestASilenceStartedAfterTheRowWasEnqueuedKeepsItBack(t *testing.T) {
	store, sender := newQueueFake(), &senderFake{}
	check := &checkFake{verdict: Verdict{
		Suppressed: true, PolicyID: "s1", Reason: SuppressedBySilence,
		Sentence: "silence until 2026-09-20T12:00:00Z: network migration",
	}}
	worker := workerFake(store, check, sender)

	if err := worker.send(context.Background(), waitingRow(t, "alert.fired", "alert.fired")); err != nil {
		t.Fatalf("the row was not worked: %v", err)
	}
	if len(sender.sent) != 0 {
		t.Fatalf("a row covered by a silence was sent anyway: %+v", sender.sent)
	}
	if store.settled != nil {
		t.Errorf("the row was settled as an attempt: %+v", store.settled)
	}
	if store.suppressed == nil {
		t.Fatal("the row was not settled as suppressed")
	}
	if store.suppressed.PolicyID != "s1" || store.suppressed.Reason != SuppressedBySilence {
		t.Errorf("the suppressed row does not name what kept it: %+v", store.suppressed)
	}
	// The row's own channel and message are what the decision is made about:
	// a silence covers a rule and a host, not the queue as a whole.
	if len(check.channels) != 1 || check.channels[0] != "c1" || check.subjects[0] != "alert.fired" {
		t.Errorf("the suppression was asked about %v / %v", check.channels, check.subjects)
	}
}

// The decision is made against the instant of the send, not of the enqueue: a
// silence that began and ended while the row waited does not swallow it.
func TestASilenceThatEndedWhileTheRowWaitedDoesNotSwallowIt(t *testing.T) {
	store, sender := newQueueFake(), &senderFake{}
	worker := workerFake(store, &checkFake{}, sender)

	if err := worker.send(context.Background(), waitingRow(t, "alert.fired", "alert.fired")); err != nil {
		t.Fatalf("the row was not worked: %v", err)
	}
	if len(sender.sent) != 1 {
		t.Fatalf("the row was not sent once the silence had ended: %+v", sender.sent)
	}
	if store.suppressed != nil {
		t.Errorf("an expired silence kept the row back: %+v", store.suppressed)
	}
	if store.settled == nil || store.settled.State != StateDelivered {
		t.Errorf("the row was not settled as delivered: %+v", store.settled)
	}
}

// A resolve is never delivered for a fire that was kept back, whether the fire
// was kept back when it was written or on its way out.
func TestTheResolveKeepsItsPairingWithAFireKeptBackOnItsWayOut(t *testing.T) {
	fire := &Verdict{
		Suppressed: true, PolicyID: "s1", Reason: SuppressedBySilence,
		Sentence: "silence until 2026-09-20T12:00:00Z: network migration",
	}
	verdict := KeptFire(fire)
	if !verdict.Suppressed || verdict.Reason != SuppressedFireKept || verdict.PolicyID != "s1" {
		t.Fatalf("the resolve of a kept fire was not kept back: %+v", verdict)
	}
	if !strings.Contains(verdict.Sentence, fire.Sentence) {
		t.Errorf("the resolve does not say what kept its fire: %q", verdict.Sentence)
	}
	// A fire that went out holds nothing back; the resolve follows it.
	if held := KeptFire(nil); held.Suppressed {
		t.Errorf("a resolve was kept back although its fire went out: %+v", held)
	}

	store, sender := newQueueFake(), &senderFake{}
	worker := workerFake(store, &checkFake{verdict: verdict}, sender)
	if err := worker.send(context.Background(), waitingRow(t, "alert.resolved", "alert.resolved")); err != nil {
		t.Fatalf("the row was not worked: %v", err)
	}
	if len(sender.sent) != 0 {
		t.Fatalf("a receiver was told an alert cleared that it never saw start: %+v", sender.sent)
	}
	if store.suppressed == nil || store.suppressed.Reason != SuppressedFireKept {
		t.Errorf("the resolve was not kept back with its own reason: %+v", store.suppressed)
	}

	// The other direction: the fire went out, so the resolve has to go out too.
	store, sender = newQueueFake(), &senderFake{}
	worker = workerFake(store, &checkFake{}, sender)
	if err := worker.send(context.Background(), waitingRow(t, "alert.resolved", "alert.resolved")); err != nil {
		t.Fatalf("the row was not worked: %v", err)
	}
	if len(sender.sent) != 1 || store.suppressed != nil {
		t.Errorf("the resolve of a delivered fire was kept back: %+v %+v", sender.sent, store.suppressed)
	}
}

// Unknown is not "nothing covers it": a suppression that could not be read
// leaves the row for the next round rather than sending it under a silence.
func TestASuppressionThatCouldNotBeReadDoesNotSend(t *testing.T) {
	store, sender := newQueueFake(), &senderFake{}
	worker := workerFake(store, &checkFake{err: errors.New("the silences were not read")}, sender)

	if err := worker.send(context.Background(), waitingRow(t, "alert.fired", "alert.fired")); err == nil {
		t.Fatal("a suppression that could not be read passed as no suppression")
	}
	if len(sender.sent) != 0 || store.settled != nil || store.suppressed != nil {
		t.Errorf("the row was acted on: %+v %+v %+v", sender.sent, store.settled, store.suppressed)
	}
}

// The summary of an ended silence is the word about the suppression, so a
// silence still in force does not keep it back on its way out.
func TestTheSummaryOfAnEndedSilenceIsNotWeighedAgainstTheSilences(t *testing.T) {
	// The router carries no pool here: a summary is decided before the database.
	router := &Router{}
	until := time.Date(2026, 9, 20, 12, 0, 0, 0, time.UTC)
	message := SummaryMessage([]string{"[critical] disk full on h1"}, until, "network migration", "")

	verdict, err := router.Recheck(context.Background(), "c1", message)
	if err != nil || verdict.Suppressed {
		t.Errorf("the summary of an ended silence was kept back: %+v, %v", verdict, err)
	}
}
