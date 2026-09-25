package outbox

import (
	"context"
	"errors"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
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

// Deliver runs one round: it locks the cursor, reads the events after it,
// hands them to the receiver and moves the cursor on success.
func (c *Consumer) Deliver(ctx context.Context) (int, error) {
	tx, err := c.pool.Begin(ctx)
	if err != nil {
		return 0, err
	}
	defer tx.Rollback(ctx)

	var lastID int64
	var failures int
	err = tx.QueryRow(ctx, `
		select last_id, failures from outbox_consumers
		 where name = $1 and next_attempt_at <= now()
		 for update skip locked`, c.name).Scan(&lastID, &failures)
	if errors.Is(err, pgx.ErrNoRows) {
		// Either the row is missing (first run), locked, or held back.
		_, err := c.pool.Exec(ctx,
			`insert into outbox_consumers (name) values ($1) on conflict (name) do nothing`, c.name)
		return 0, err
	}
	if err != nil {
		return 0, err
	}

	rows, err := tx.Query(ctx, `
		select id, aggregate_type, aggregate_id, event_type, payload, occurred_at
		  from outbox_events
		 where id > $1
		 order by id
		 limit $2`, lastID, c.batch)
	if err != nil {
		return 0, err
	}
	var events []Event
	for rows.Next() {
		var event Event
		if err := rows.Scan(&event.ID, &event.Aggregate, &event.AggregateID,
			&event.Type, &event.Payload, &event.OccurredAt); err != nil {
			rows.Close()
			return 0, err
		}
		events = append(events, event)
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return 0, err
	}
	if len(events) == 0 {
		return 0, tx.Commit(ctx)
	}

	if err := c.receiver.Deliver(ctx, events); err != nil {
		// The cursor stays; the failure and the pause before the next attempt are
		// recorded so that the receiver being down is visible and does not turn into
		// a tight loop.
		failures++
		backoff := time.Duration(1<<uint(min(failures, 8))) * time.Second
		if backoff > maxBackoff {
			backoff = maxBackoff
		}
		if _, updateErr := tx.Exec(ctx, `
			update outbox_consumers
			   set failures = $2, last_error = $3,
			       next_attempt_at = now() + make_interval(secs => $4), updated_at = now()
			 where name = $1`, c.name, failures, err.Error(), backoff.Seconds()); updateErr != nil {
			return 0, updateErr
		}
		if commitErr := tx.Commit(ctx); commitErr != nil {
			return 0, commitErr
		}
		return 0, err
	}
	if _, err := tx.Exec(ctx, `
		update outbox_consumers
		   set last_id = $2, failures = 0, last_error = '', next_attempt_at = now(), updated_at = now()
		 where name = $1`, c.name, events[len(events)-1].ID); err != nil {
		return 0, err
	}
	if err := tx.Commit(ctx); err != nil {
		return 0, err
	}
	return len(events), nil
}
