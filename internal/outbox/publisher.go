// Package outbox publishes the durable trail of events.
//
// The events are written by database triggers in the same transaction as
// the state change they describe, so a state cannot change without its
// event. The publisher is the other half of the contract: it leases the
// unpublished rows, hands them to a sink and marks them published, all in
// one transaction. A crash between the hand-over and the commit leaves the
// row unpublished and it goes out again - the delivery is at least once,
// and a consumer deduplicates by the event identifier.
//
// The first sink is a PostgreSQL notification: every instance of the panel
// listens to it and forwards the event to the open screens. A broker takes
// the same place later without a change to the shape of the events or to
// their identifiers.
package outbox

import (
	"context"
	"encoding/json"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

// NotifyChannel is the database channel the notification sink publishes on.
const NotifyChannel = "flotestro_outbox"

// Event is one row of the trail.
type Event struct {
	ID          int64           `json:"id"`
	Aggregate   string          `json:"aggregate_type"`
	AggregateID string          `json:"aggregate_id"`
	Type        string          `json:"event_type"`
	Payload     json.RawMessage `json:"payload"`
	OccurredAt  time.Time       `json:"occurred_at"`
}

// Sink receives the events. A sink that returns an error leaves the batch
// unpublished: the rows go out again on the next round.
type Sink interface {
	Publish(ctx context.Context, tx pgx.Tx, events []Event) error
}

// Publisher moves the events from the table to the sink.
type Publisher struct {
	pool     *pgxpool.Pool
	sink     Sink
	log      interface{ Error(string, ...any) }
	interval time.Duration
	batch    int
	wake     chan struct{}
}

// NewPublisher creates a publisher polling at the given interval. The
// interval is the ceiling of the latency; Wake shortens it to nothing when
// the process learns of a change another way.
func NewPublisher(pool *pgxpool.Pool, sink Sink, log interface{ Error(string, ...any) },
	interval time.Duration) *Publisher {
	if interval <= 0 {
		interval = 2 * time.Second
	}
	return &Publisher{pool: pool, sink: sink, log: log, interval: interval,
		batch: 200, wake: make(chan struct{}, 1)}
}

// Wake asks for a round now. Several wakes before the round starts merge
// into one.
func (p *Publisher) Wake() {
	select {
	case p.wake <- struct{}{}:
	default:
	}
}

// Run publishes until the context ends.
func (p *Publisher) Run(ctx context.Context) {
	ticker := time.NewTicker(p.interval)
	defer ticker.Stop()
	for {
		// A full batch means there may be more waiting: go again at once
		// instead of leaving the rest for the next tick.
		for {
			published, err := p.Publish(ctx)
			if err != nil {
				if ctx.Err() == nil {
					p.log.Error("the outbox was not published", "err", err)
				}
				break
			}
			if published < p.batch {
				break
			}
		}
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
		case <-p.wake:
		}
	}
}

// Publish runs one round: it leases up to a batch of unpublished rows,
// hands them to the sink and marks them published. It returns how many rows
// went out.
func (p *Publisher) Publish(ctx context.Context) (int, error) {
	tx, err := p.pool.Begin(ctx)
	if err != nil {
		return 0, err
	}
	defer tx.Rollback(ctx)

	// SKIP LOCKED lets several instances of the panel publish side by side
	// without waiting for one another; each row is leased by one of them.
	rows, err := tx.Query(ctx, `
		select id, aggregate_type, aggregate_id, event_type, payload, occurred_at
		  from outbox_events
		 where published_at is null
		 order by id
		 limit $1
		 for update skip locked`, p.batch)
	if err != nil {
		return 0, err
	}
	var events []Event
	var ids []int64
	for rows.Next() {
		var event Event
		if err := rows.Scan(&event.ID, &event.Aggregate, &event.AggregateID,
			&event.Type, &event.Payload, &event.OccurredAt); err != nil {
			rows.Close()
			return 0, err
		}
		events = append(events, event)
		ids = append(ids, event.ID)
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return 0, err
	}
	if len(events) == 0 {
		return 0, nil
	}

	if err := p.sink.Publish(ctx, tx, events); err != nil {
		return 0, err
	}
	if _, err := tx.Exec(ctx,
		`update outbox_events set published_at = now() where id = any($1)`, ids); err != nil {
		return 0, err
	}
	if err := tx.Commit(ctx); err != nil {
		return 0, err
	}
	return len(events), nil
}

// NotifySink publishes every event as a PostgreSQL notification. The
// notification is a wake-up call rather than the content: it carries the
// identifiers, and a receiver reads the rows from the table. That keeps it
// far below the size limit of a notification, and a receiver that missed
// one still finds the rows by their identifiers.
type NotifySink struct{}

// notification is what travels in the channel.
type notification struct {
	ID          int64  `json:"id"`
	Aggregate   string `json:"aggregate_type"`
	AggregateID string `json:"aggregate_id"`
	Type        string `json:"event_type"`
}

func (NotifySink) Publish(ctx context.Context, tx pgx.Tx, events []Event) error {
	for _, event := range events {
		body, err := json.Marshal(notification{
			ID: event.ID, Aggregate: event.Aggregate,
			AggregateID: event.AggregateID, Type: event.Type,
		})
		if err != nil {
			return err
		}
		// pg_notify inside the transaction: the notification leaves with the
		// commit, together with the published_at mark, or not at all.
		if _, err := tx.Exec(ctx, "select pg_notify($1, $2)", NotifyChannel, string(body)); err != nil {
			return err
		}
	}
	return nil
}

// Notification reads the content of a notification from NotifyChannel.
func Notification(payload string) (id int64, aggregate, aggregateID, eventType string, ok bool) {
	var n notification
	if err := json.Unmarshal([]byte(payload), &n); err != nil || n.ID == 0 {
		return 0, "", "", "", false
	}
	return n.ID, n.Aggregate, n.AggregateID, n.Type, true
}
