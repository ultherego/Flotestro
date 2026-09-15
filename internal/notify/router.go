package notify

import (
	"context"
	"errors"
	"log/slog"
	"net/http"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/ultherego/flotestro/internal/outbox"
)

// Attempts is how many times a message is tried at one receiver before
// the log keeps it as failed and the router moves on.
const Attempts = 3

// attemptBackoff is the pause before the second and the third attempt: a
// receiver that dropped one connection is given a moment, a receiver
// that is down is not waited for.
var attemptBackoff = []time.Duration{0, 2 * time.Second, 5 * time.Second}

// Router is the consumer of the trail that feeds the channels. It takes
// a batch of events, finds the channels each one is for, sends and logs.
// A failed receiver is a row of the log, never an error of the batch: an
// error would hold the cursor, and one mailbox that is down would then
// hold every other channel with it.
type Router struct {
	pool    *pgxpool.Pool
	store   *Store
	log     *slog.Logger
	senders map[string]Sender
	// publicURL is the panel address the links point at; empty means
	// messages without links.
	publicURL string
	// now is replaced in tests.
	now func() time.Time
	// sleep is replaced in tests.
	sleep func(context.Context, time.Duration)
}

// NewRouter creates the router with the three senders. The secret reader
// is the store the mail passwords are read from; nil means a mail
// channel with a username cannot send.
func NewRouter(pool *pgxpool.Pool, store *Store, secrets SecretReader, publicURL string, log *slog.Logger) *Router {
	client := &http.Client{Timeout: sendTimeout}
	return &Router{
		pool: pool, store: store, log: log, publicURL: publicURL,
		senders: map[string]Sender{
			KindWebhook:      WebhookSender{Client: client},
			KindSlackWebhook: SlackSender{Client: client},
			KindEmail:        EmailSender{Secrets: secrets},
		},
		now: time.Now,
		sleep: func(ctx context.Context, d time.Duration) {
			timer := time.NewTimer(d)
			defer timer.Stop()
			select {
			case <-ctx.Done():
			case <-timer.C:
			}
		},
	}
}

// Deliver hands a batch of the trail to the channels. It is the
// outbox.Receiver the consumer calls; it errs only when the database
// does, so the cursor moves whatever the receivers did.
func (r *Router) Deliver(ctx context.Context, events []outbox.Event) error {
	channels, err := r.store.Enabled(ctx)
	if err != nil {
		return err
	}
	if len(channels) == 0 {
		return nil
	}
	for _, event := range events {
		message, ok := Compose(event, r.publicURL)
		if !ok {
			continue
		}
		scope, err := r.scopeOf(ctx, event)
		if err != nil {
			return err
		}
		for _, channel := range channels {
			if !channel.Subscribes(message.Subject) || !channel.Filter.Matches(scope) {
				continue
			}
			if err := r.send(ctx, channel, message); err != nil {
				return err
			}
		}
	}
	return nil
}

// scopeOf says where the event happened and how serious it is. The
// triggers of the host events write the site and the environment; the
// alert trigger names the host, and the host row says the rest. A host
// that is gone since leaves the scope unknown, and an unknown scope
// passes every filter rather than none.
func (r *Router) scopeOf(ctx context.Context, event outbox.Event) (Scope, error) {
	scope, hostID := ScopeHint(event)
	if hostID == "" || (scope.Site != "" && scope.Environment != "") {
		return scope, nil
	}
	err := r.pool.QueryRow(ctx, `select site, environment from hosts where id = $1`, hostID).
		Scan(&scope.Site, &scope.Environment)
	if errors.Is(err, pgx.ErrNoRows) {
		return scope, nil
	}
	if err != nil {
		return scope, err
	}
	return scope, nil
}

// send tries the message at the channel up to Attempts times and logs
// every attempt. The error it returns is the database's: a receiver
// that refused is in the log and not in the error.
func (r *Router) send(ctx context.Context, channel Channel, message Message) error {
	sender, ok := r.senders[channel.Kind]
	if !ok {
		return r.store.Record(ctx, Delivery{
			ChannelID: channel.ID, EventID: message.EventID, EventType: message.EventType,
			Attempt: 1, Status: StatusFailed, ErrorCode: CodeInvalidConfig,
			Error: "no sender for the kind " + channel.Kind,
		})
	}
	for attempt := 1; attempt <= Attempts; attempt++ {
		if attempt > 1 {
			r.sleep(ctx, attemptBackoff[min(attempt-1, len(attemptBackoff)-1)])
			if ctx.Err() != nil {
				return ctx.Err()
			}
		}
		err := sender.Send(ctx, channel, message)
		delivery := Delivery{
			ChannelID: channel.ID, EventID: message.EventID, EventType: message.EventType,
			Attempt: attempt, Status: StatusSent,
		}
		if err != nil {
			failure := classify(err)
			delivery.Status = StatusFailed
			delivery.ErrorCode = failure.Code
			delivery.Error = failure.Err.Error()
		}
		if recordErr := r.store.Record(ctx, delivery); recordErr != nil {
			return recordErr
		}
		if err == nil {
			return nil
		}
		r.log.Warn("a notification was not delivered",
			"channel", channel.Name, "kind", channel.Kind, "event", message.EventType,
			"attempt", attempt, "code", delivery.ErrorCode, "err", delivery.Error)
	}
	return nil
}

// Test sends the test message at a channel once and returns the row of
// the log it wrote. One attempt: the operator pressed a button and waits
// for the answer, and a receiver that is down is told at once.
func (r *Router) Test(ctx context.Context, id string) (*Delivery, error) {
	channel, err := r.store.get(ctx, id)
	if err != nil {
		return nil, err
	}
	sender, ok := r.senders[channel.Kind]
	if !ok {
		return nil, Error{Code: "unknown_kind", Message: "no sender for the kind " + channel.Kind}
	}
	now := r.now()
	delivery := Delivery{
		ChannelID: channel.ID, ChannelName: channel.Name, EventType: "test",
		Attempt: 1, Status: StatusSent, SentAt: now,
	}
	if err := sender.Send(ctx, *channel, TestMessage(*channel, now)); err != nil {
		failure := classify(err)
		delivery.Status = StatusFailed
		delivery.ErrorCode = failure.Code
		delivery.Error = failure.Err.Error()
	}
	if err := r.store.Record(ctx, delivery); err != nil {
		return nil, err
	}
	return &delivery, nil
}
