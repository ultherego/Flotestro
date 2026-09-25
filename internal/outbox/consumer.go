package outbox

import (
	"context"
	"errors"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/ultherego/flotestro/internal/metrics"
)

// Receiver takes a batch of events. An error leaves the cursor where it was
// and the batch goes out again after a pause.
type Receiver interface {
	Deliver(ctx context.Context, events []Event) error
}

// Consumer moves one external receiver along the trail.
type Consumer struct {
	pool     *pgxpool.Pool
	name     string
	receiver Receiver
	log      interface{ Error(string, ...any) }
	interval time.Duration
	batch    int
	wake     chan struct{}
}

// NewConsumer creates a consumer of the given name.
func NewConsumer(pool *pgxpool.Pool, name string, receiver Receiver,
	log interface{ Error(string, ...any) }, interval time.Duration) *Consumer {
	if interval <= 0 {
		interval = 2 * time.Second
	}
	return &Consumer{pool: pool, name: name, receiver: receiver, log: log,
		interval: interval, batch: 100, wake: make(chan struct{}, 1)}
}

// Wake asks for a round now.
func (c *Consumer) Wake() {
	select {
	case c.wake <- struct{}{}:
	default:
	}
}

// Run delivers until the context ends.
func (c *Consumer) Run(ctx context.Context) {
	// This process is the consumer, so its cursor holds the trail back. An
	// installation that stops running it says so through Retire.
	if err := c.claim(ctx); err != nil && ctx.Err() == nil {
		c.log.Error("the consumer was not claimed", "consumer", c.name, "err", err)
	}
	ticker := time.NewTicker(c.interval)
	defer ticker.Stop()
	for {
		for {
			delivered, err := c.Deliver(ctx)
			if err != nil {
				if ctx.Err() == nil {
					c.log.Error("the trail was not delivered", "consumer", c.name, "err", err)
				}
				break
			}
			if delivered < c.batch {
				break
			}
		}
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
		case <-c.wake:
		}
	}
}

// claim records that this installation runs the consumer, so the retention of
// the trail waits for its cursor.
func (c *Consumer) claim(ctx context.Context) error {
	_, err := c.pool.Exec(ctx, `
		insert into outbox_consumers (name) values ($1)
		on conflict (name) do update set active = true, updated_at = now()`, c.name)
	return err
}

// Retire says this installation no longer runs the named consumer. The cursor
// stays, so switching it on again resumes where it stopped, but it stops
// holding the whole trail back - which is what a webhook switched off used to
// do, for ever.
func Retire(ctx context.Context, pool *pgxpool.Pool, name string) error {
	_, err := pool.Exec(ctx, `
		update outbox_consumers set active = false, updated_at = now()
		 where name = $1 and active`, name)
	return err
}

// maxBackoff bounds how long a failing receiver is left alone.
const maxBackoff = 5 * time.Minute

// claimTerm is how long a round belongs to the instance that took it. It has
// to outlast the slowest receiver by a wide margin: a round still on its way
// when the term ends is delivered a second time by another instance.
const claimTerm = 5 * time.Minute

// narrowAfter is the number of failures after which the round is cut down to
// one event. A batch that fails says nothing about which of its events the
// receiver will not take; one at a time says exactly which.
const narrowAfter = 8

// deadLetterAfter is where a single event the receiver will not take is set
// aside and the trail moves past it. Without it one refused event holds every
// later event for ever - the webhook never recovers and the audit trail of the
// installation stops at that identifier.
const deadLetterAfter = 12

// processInstance names this process to the claim, so that the round of an
// instance that disappeared falls free when its term ends.
var processInstance = uuid.NewString()

// round is a claimed stretch of the trail: the events to deliver and the state
// that decides what happens when the delivery fails.
type round struct {
	events   []Event
	failures int
}

// Deliver runs one round: it claims a stretch of the trail, hands it to the
// receiver outside every transaction, and records the outcome in a second one.
// The delivery used to happen with the consumer row locked and a transaction
// open, so a receiver taking its whole timeout held one open for as long - and
// the oldest open transaction is what keeps the database from cleaning up
// after all the others.
func (c *Consumer) Deliver(ctx context.Context) (int, error) {
	taken, err := c.claimRound(ctx)
	if err != nil || taken == nil {
		return 0, err
	}
	if deliveryErr := c.receiver.Deliver(ctx, taken.events); deliveryErr != nil {
		if err := c.recordFailure(ctx, taken, deliveryErr); err != nil {
			return 0, err
		}
		return 0, deliveryErr
	}
	return len(taken.events), c.settle(ctx, taken)
}

// claimRound takes the round for this instance and reads the events it covers.
// It returns nil when there is nothing to do, and holds no transaction open
// past its own commit.
func (c *Consumer) claimRound(ctx context.Context) (*round, error) {
	tx, err := c.pool.Begin(ctx)
	if err != nil {
		return nil, err
	}
	defer tx.Rollback(ctx)

	var lastID int64
	var failures int
	err = tx.QueryRow(ctx, `
		update outbox_consumers
		   set claimed_by    = $2::uuid,
		       claimed_until = now() + make_interval(secs => $3::double precision),
		       updated_at    = now()
		 where name = $1
		   and next_attempt_at <= now()
		   and (claimed_until is null or claimed_until < now())
		returning last_id, failures`,
		c.name, processInstance, claimTerm.Seconds()).Scan(&lastID, &failures)
	if errors.Is(err, pgx.ErrNoRows) {
		// The row is missing (first run), another instance holds the round, or
		// the consumer is held back after a failure.
		_, err := c.pool.Exec(ctx,
			`insert into outbox_consumers (name) values ($1) on conflict (name) do nothing`, c.name)
		return nil, err
	}
	if err != nil {
		return nil, err
	}

	limit := c.batch
	if failures >= narrowAfter {
		limit = 1
	}
	rows, err := tx.Query(ctx, `
		select id, aggregate_type, aggregate_id, event_type, payload, occurred_at
		  from outbox_events
		 where id > $1
		 order by id
		 limit $2`, lastID, limit)
	if err != nil {
		return nil, err
	}
	var events []Event
	for rows.Next() {
		var event Event
		if err := rows.Scan(&event.ID, &event.Aggregate, &event.AggregateID,
			&event.Type, &event.Payload, &event.OccurredAt); err != nil {
			rows.Close()
			return nil, err
		}
		events = append(events, event)
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return nil, err
	}
	if len(events) == 0 {
		// Nothing to carry: the claim goes back at once rather than holding the
		// consumer for the whole term.
		if _, err := tx.Exec(ctx, releaseClaim+` where name = $1 and claimed_by = $2::uuid`,
			c.name, processInstance); err != nil {
			return nil, err
		}
	}
	if err := tx.Commit(ctx); err != nil {
		return nil, err
	}
	if len(events) == 0 {
		return nil, nil
	}
	return &round{events: events, failures: failures}, nil
}

// releaseClaim is the head of every settlement: the round goes back so another
// instance may take it without waiting out the term.
const releaseClaim = `update outbox_consumers set claimed_by = null, claimed_until = null, updated_at = now()`

// settle moves the cursor past a delivered round. The cursor never goes
// backwards: a claim whose term ran out while another instance moved on must
// not undo that instance's work.
func (c *Consumer) settle(ctx context.Context, taken *round) error {
	_, err := c.pool.Exec(ctx, `
		update outbox_consumers
		   set last_id = greatest(last_id, $2), failures = 0, last_error = '',
		       next_attempt_at = now(), claimed_by = null, claimed_until = null, updated_at = now()
		 where name = $1`, c.name, taken.events[len(taken.events)-1].ID)
	return err
}

// recordFailure records a refused round and the pause before the next attempt,
// and sets one event aside when the receiver has refused it on its own often
// enough.
func (c *Consumer) recordFailure(ctx context.Context, taken *round, cause error) error {
	failures := taken.failures + 1
	if failures >= deadLetterAfter && len(taken.events) == 1 {
		return c.setAside(ctx, taken.events[0], failures, cause)
	}
	backoff := time.Duration(1<<uint(min(failures, 8))) * time.Second
	if backoff > maxBackoff {
		backoff = maxBackoff
	}
	_, err := c.pool.Exec(ctx, `
		update outbox_consumers
		   set failures = $2, last_error = $3,
		       next_attempt_at = now() + make_interval(secs => $4::double precision),
		       claimed_by = null, claimed_until = null, updated_at = now()
		 where name = $1`, c.name, failures, cause.Error(), backoff.Seconds())
	return err
}

// setAside takes one event out of the way of the trail and keeps it whole. The
// event is kept rather than skipped, because what a receiver would not take is
// exactly what somebody will ask about.
func (c *Consumer) setAside(ctx context.Context, event Event, failures int, cause error) error {
	tx, err := c.pool.Begin(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx)
	if _, err := tx.Exec(ctx, `
		insert into outbox_dead_letters
			(consumer, event_id, aggregate, aggregate_id, event_type, payload, failures, last_error)
		values ($1, $2, $3, $4, $5, $6, $7, $8)
		on conflict (consumer, event_id) do nothing`,
		c.name, event.ID, event.Aggregate, event.AggregateID, event.Type,
		event.Payload, failures, cause.Error()); err != nil {
		return err
	}
	if _, err := tx.Exec(ctx, `
		update outbox_consumers
		   set last_id = greatest(last_id, $2), failures = 0, last_error = $3,
		       next_attempt_at = now(), claimed_by = null, claimed_until = null, updated_at = now()
		 where name = $1`, c.name, event.ID, cause.Error()); err != nil {
		return err
	}
	if err := tx.Commit(ctx); err != nil {
		return err
	}
	metrics.OutboxDeadLettered.Inc(c.name)
	c.log.Error("an event was set aside and the trail moved past it",
		"consumer", c.name, "event_id", event.ID, "event_type", event.Type,
		"failures", failures, "err", cause)
	return nil
}
