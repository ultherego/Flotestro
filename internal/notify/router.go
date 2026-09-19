package notify

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/ultherego/flotestro/internal/outbox"
)

// Router is the consumer of the trail that feeds the queue.
type Router struct {
	pool    *pgxpool.Pool
	store   *Store
	log     *slog.Logger
	senders map[string]Sender
	// publicURL is the panel address the links point at; empty means
	// messages without links.
	publicURL string
	// worker is woken when rows were written, so a message goes out within a
	// moment rather than at the next poll; nil means the worker of another
	// instance polls it up.
	worker *Worker
	// now is replaced in tests.
	now func() time.Time
}

// NewRouter creates the router with the three senders.
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
	}
}

// AttachWorker names the worker of this process, to be woken when rows
// are written or a dead letter is retried.
func (r *Router) AttachWorker(worker *Worker) {
	r.worker = worker
}

// Wake asks the worker of this process for a round now; nothing without
// one.
func (r *Router) Wake() {
	if r.worker != nil {
		r.worker.Wake()
	}
}

// Deliver hands a batch of the trail to the queue. It is the outbox.
func (r *Router) Deliver(ctx context.Context, events []outbox.Event) error {
	channels, err := r.store.Enabled(ctx)
	if err != nil {
		return err
	}
	if len(channels) == 0 {
		return nil
	}
	var rows []Delivery
	for _, event := range events {
		message, ok := Compose(event, r.publicURL)
		if !ok {
			continue
		}
		scope, err := r.scopeOf(ctx, event)
		if err != nil {
			return err
		}
		var matching []Channel
		for _, channel := range channels {
			if channel.Subscribes(message.Subject) && channel.Filter.Matches(scope) {
				matching = append(matching, channel)
			}
		}
		if len(matching) == 0 {
			continue
		}
		verdict, err := r.suppression(ctx, event, message)
		if err != nil {
			return err
		}
		for _, channel := range matching {
			row := Delivery{
				ChannelID: channel.ID, EventID: event.ID, EventType: event.Type,
				State: StatePending, channelRevision: channel.Revision,
			}
			if verdict.Suppressed {
				row.State = StateSuppressed
				row.PolicyID = verdict.PolicyID
				row.SuppressionReason = verdict.Reason
				row.LastError = verdict.Sentence
			}
			// A resolve is kept back for a channel whose fire was kept back: the two
			// are decided per channel, because the same silence may have started
			// between the fire and the resolve.
			if !verdict.Suppressed && message.Subject == "alert.resolved" {
				kept, err := r.fireWasKept(ctx, channel.ID, event.AggregateID)
				if err != nil {
					return err
				}
				if kept != nil {
					row.State = StateSuppressed
					row.PolicyID = kept.PolicyID
					row.SuppressionReason = SuppressedFireKept
					row.LastError = "the fire of this alert was kept back: " + kept.Sentence
				}
			}
			if row, err = row.WithMessage(message); err != nil {
				return err
			}
			rows = append(rows, row)
		}
	}
	if err := r.store.Enqueue(ctx, rows); err != nil {
		return err
	}
	if len(rows) > 0 {
		r.Wake()
	}
	return nil
}

// scopeOf says where the event happened and how serious it is.
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

// Verdict is what the suppression says about an event: kept back or
// not, by which policy, with the typed reason and the sentence.
type Verdict struct {
	Suppressed bool
	PolicyID   string
	Reason     string
	Sentence   string
}

// silence is what the suppression reads of a silence.
type silence struct {
	ID     string
	HostID string
	RuleID string
	Until  time.Time
	Reason string
	Global bool
}

// maintenance is what the suppression reads of a host's window.
type maintenance struct {
	Until  time.Time
	Reason string
}

// suppression decides, before the row is written, whether a silence or a
// maintenance window keeps the event back.
func (r *Router) suppression(ctx context.Context, event outbox.Event, message Message) (Verdict, error) {
	var fields payload
	_ = json.Unmarshal(event.Payload, &fields)
	hostID := fields.HostID
	if hostID == "" && event.Aggregate == "host" {
		hostID = event.AggregateID
	}
	ruleID := ""
	if message.Subject == "alert.fired" || message.Subject == "alert.resolved" {
		ruleID = ruleIDOf(event.Payload)
	}
	silences, err := r.activeSilences(ctx, hostID, ruleID)
	if err != nil {
		return Verdict{}, err
	}
	var window *maintenance
	if hostID != "" {
		if window, err = r.maintenanceOf(ctx, hostID); err != nil {
			return Verdict{}, err
		}
	}
	return Decide(message.Subject, hostID, silences, window), nil
}

// Decide is the suppression rule, without the database.
func Decide(subject, hostID string, silences []silence, window *maintenance) Verdict {
	security := subject == SubjectSecurity
	for _, s := range silences {
		if security && !s.Global {
			continue
		}
		if !security && s.Global && s.HostID == "" && s.RuleID == "" {
			// A global silence is written for the security alerts; it is
			// not a silence of every alert of every host.
			continue
		}
		return Verdict{
			Suppressed: true, PolicyID: s.ID, Reason: SuppressedBySilence,
			Sentence: fmt.Sprintf("silence until %s: %s", s.Until.UTC().Format(time.RFC3339), s.Reason),
		}
	}
	if window != nil && !security && hostID != "" {
		return Verdict{
			Suppressed: true, Reason: SuppressedByMaintenance,
			Sentence: fmt.Sprintf("maintenance window until %s: %s", window.Until.UTC().Format(time.RFC3339), window.Reason),
		}
	}
	return Verdict{}
}

// activeSilences reads the silences in force that cover the host and the rule,
// and the global ones.
func (r *Router) activeSilences(ctx context.Context, hostID, ruleID string) ([]silence, error) {
	rows, err := r.pool.Query(ctx, `
		select id, coalesce(host_id::text, ''), coalesce(rule_id::text, ''), until, reason, global
		  from silences
		 where expired_at is null and until > now()
		   and (host_id is null or host_id::text = $1)
		   and (rule_id is null or rule_id::text = $2)
		 order by global desc, created_at`, hostID, ruleID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var silences []silence
	for rows.Next() {
		var s silence
		if err := rows.Scan(&s.ID, &s.HostID, &s.RuleID, &s.Until, &s.Reason, &s.Global); err != nil {
			return nil, err
		}
		silences = append(silences, s)
	}
	return silences, rows.Err()
}

// maintenanceOf reads the maintenance window of the host, in force now;
// nil outside one.
func (r *Router) maintenanceOf(ctx context.Context, hostID string) (*maintenance, error) {
	var window maintenance
	err := r.pool.QueryRow(ctx, `
		select maintenance_until, coalesce(maintenance_reason, '')
		  from hosts where id = $1 and maintenance_until > now()`, hostID).
		Scan(&window.Until, &window.Reason)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	return &window, nil
}

// fireWasKept says whether the channel's row for the fire of the alert
// was suppressed, and by what.
func (r *Router) fireWasKept(ctx context.Context, channelID, alertID string) (*Verdict, error) {
	var kept Verdict
	err := r.pool.QueryRow(ctx, `
		select coalesce(policy_id::text, ''), suppression_reason, last_error
		  from notification_deliveries
		 where channel_id = $1 and aggregate_id = $2 and event_type = 'alert.fired' and state = 'suppressed'
		 order by created_at desc limit 1`, channelID, alertID).
		Scan(&kept.PolicyID, &kept.Reason, &kept.Sentence)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	kept.Suppressed = true
	return &kept, nil
}

// ruleIDOf reads the rule of an alert event; the trigger writes it as
// rule_id.
func ruleIDOf(raw json.RawMessage) string {
	var fields struct {
		RuleID *string `json:"rule_id"`
	}
	_ = json.Unmarshal(raw, &fields)
	if fields.RuleID == nil {
		return ""
	}
	return strings.TrimSpace(*fields.RuleID)
}

// Test sends the test message at a channel once and returns the row of the
// queue it wrote.
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
	message := TestMessage(*channel, now)
	delivery := Delivery{
		ChannelID: channel.ID, ChannelName: channel.Name, EventType: "test",
		Attempt: 1, State: StateDelivered, SentAt: now,
	}
	if delivery, err = delivery.WithMessage(message); err != nil {
		return nil, err
	}
	loaded, err := r.store.withSecret(ctx, *channel)
	if err == nil {
		err = sender.Send(ctx, loaded, message)
	}
	if err != nil {
		outcome := Classify(err, 1, 1)
		// A test is not retried: a failure that would pass is settled as a dead
		// letter of the test, with the transport code the operator reads.
		delivery.State = StateDeadLetter
		delivery.LastErrorCode = outcome.ErrorCode
		delivery.LastError = outcome.Error
	}
	if err := r.store.Record(ctx, delivery); err != nil {
		return nil, err
	}
	delivery.Status = legacyStatus(delivery.State)
	delivery.ErrorCode = delivery.LastErrorCode
	delivery.Error = delivery.LastError
	delivery.SentAt = delivery.UpdatedAt
	return &delivery, nil
}
