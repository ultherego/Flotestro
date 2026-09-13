// Package events broadcasts the changes of the state of operations to the open
// screens of the panel.
//
// The source is a notification from PostgreSQL rather than a channel in the
// memory of the process. The panel may run in several instances, and an agent
// connects to the one that happened to accept it - an operator looking through
// another instance has to see the same thing.
package events

import (
	"context"
	"encoding/json"
	"strings"
	"sync"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
)

// The notification channels in the database. Progress has one of its own,
// because it is transient: we do not record it and one must not infer the
// result from it.
//
// The job and campaign channels are published by the database triggers, so
// their names are bound to the migration that creates those triggers.
const (
	jobChannel      = "flotestro_jobs"
	progressChannel = "flotestro_progress"
	campaignChannel = "flotestro_campaigns"
	logChannel      = "flotestro_logs"
)

// Event describes the change of the state of one operation or its progress.
type Event struct {
	JobID      string `json:"job_id"`
	State      string `json:"state,omitempty"`
	CampaignID string `json:"campaign_id,omitempty"`
	// Progress is filled in for progress events. Progress does not change the
	// state of an operation and does not replace its result.
	Progress *Progress `json:"progress,omitempty"`
	// Log is filled in for the live view of a log. The lines are transient:
	// they are not recorded and cannot be read after the fact.
	Log *LogLines `json:"log,omitempty"`
}

// LogLines is a piece of the live view of a log.
type LogLines struct {
	Lines []string `json:"lines"`
	// Dropped says how many lines were skipped because of the rate limit. A
	// silent skip would have the operator believe they see everything.
	Dropped uint32 `json:"dropped,omitempty"`
}

// Progress describes the progress of a running operation.
type Progress struct {
	Step    uint32  `json:"step,omitempty"`
	Total   uint32  `json:"total,omitempty"`
	Percent *uint32 `json:"percent,omitempty"`
	Message string  `json:"message,omitempty"`
}

// Bus broadcasts the events to the subscribers in this process.
type Bus struct {
	pool *pgxpool.Pool

	mu            sync.Mutex
	subscriptions map[int]subscription
	next          int
}

type subscription struct {
	filter  func(Event) bool
	channel chan Event
}

func NewBus(pool *pgxpool.Pool) *Bus {
	return &Bus{pool: pool, subscriptions: map[int]subscription{}}
}

// Run listens for the notifications until the context ends. A broken
// connection is recreated: losing the listener must not silently stop the
// progress on the screens.
func (b *Bus) Run(ctx context.Context, log interface{ Error(string, ...any) }) {
	interval := time.Second
	for ctx.Err() == nil {
		if err := b.listen(ctx); err != nil && ctx.Err() == nil {
			log.Error("the listening for notifications was interrupted",
				"err", err, "retry_in", interval.String())
			select {
			case <-ctx.Done():
				return
			case <-time.After(interval):
			}
			if interval < 30*time.Second {
				interval *= 2
			}
			continue
		}
		interval = time.Second
	}
}

func (b *Bus) listen(ctx context.Context) error {
	// The listening occupies a connection exclusively, so we take one from the
	// pool and keep it instead of borrowing one for every notification.
	conn, err := b.pool.Acquire(ctx)
	if err != nil {
		return err
	}
	defer conn.Release()

	for _, name := range []string{jobChannel, progressChannel, campaignChannel, logChannel} {
		if _, err := conn.Exec(ctx, "listen "+name); err != nil {
			return err
		}
	}
	for {
		notification, err := conn.Conn().WaitForNotification(ctx)
		if err != nil {
			return err
		}
		switch notification.Channel {
		case progressChannel:
			b.broadcast(parseProgress(notification.Payload))
		case campaignChannel:
			b.broadcast(parseTarget(notification.Payload))
		case logChannel:
			b.broadcast(parseProgress(notification.Payload))
		default:
			b.broadcast(parse(notification.Payload))
		}
	}
}

// parse reads the content of a notification: the identifier, the state and an
// optional campaign.
func parse(payload string) Event {
	parts := strings.SplitN(payload, " ", 3)
	event := Event{}
	if len(parts) > 0 {
		event.JobID = parts[0]
	}
	if len(parts) > 1 {
		event.State = parts[1]
	}
	if len(parts) > 2 {
		event.CampaignID = strings.TrimSpace(parts[2])
	}
	return event
}

// parseTarget reads the notification about a change of the state of a target
// of a campaign. A target is not an operation: it goes through states of its
// own that no job reflects, so its event carries no identifier of an
// operation.
func parseTarget(payload string) Event {
	parts := strings.SplitN(payload, " ", 2)
	event := Event{}
	if len(parts) > 0 {
		event.CampaignID = parts[0]
	}
	if len(parts) > 1 {
		event.State = strings.TrimSpace(parts[1])
	}
	return event
}

// parseProgress reads a progress notification written as JSON.
func parseProgress(payload string) Event {
	var event Event
	if err := json.Unmarshal([]byte(payload), &event); err != nil {
		return Event{}
	}
	return event
}

// PublishLog broadcasts a piece of the live view of a log. The lines go over a
// channel separate from the progress: the progress describes the operation and
// the view is its content.
func (b *Bus) PublishLog(ctx context.Context, event Event) error {
	if event.JobID == "" {
		return nil
	}
	payload, err := json.Marshal(event)
	if err != nil {
		return err
	}
	_, err = b.pool.Exec(ctx, "select pg_notify($1, $2)", logChannel, string(payload))
	return err
}

// PublishProgress broadcasts the progress of an operation. The progress is not
// recorded: it goes through a notification and disappears. A screen that has
// just connected will see the next one - and that is enough, because the
// result is in the database anyway.
func (b *Bus) PublishProgress(ctx context.Context, event Event) error {
	if event.JobID == "" {
		return nil
	}
	payload, err := json.Marshal(event)
	if err != nil {
		return err
	}
	_, err = b.pool.Exec(ctx, "select pg_notify($1, $2)", progressChannel, string(payload))
	return err
}

func (b *Bus) broadcast(event Event) {
	b.mu.Lock()
	defer b.mu.Unlock()
	for _, sub := range b.subscriptions {
		if !sub.filter(event) {
			continue
		}
		select {
		case sub.channel <- event:
		default:
			// A slow receiver must not hold the broadcasting back. A lost
			// event does not lose the state: the screen reads it from the
			// database anyway, and the next event catches up with it.
		}
	}
}

// Subscribe returns the channel of the events matching the filter along with
// the function that ends the subscription.
func (b *Bus) Subscribe(filter func(Event) bool) (<-chan Event, func()) {
	eventChannel := make(chan Event, 16)
	b.mu.Lock()
	id := b.next
	b.next++
	b.subscriptions[id] = subscription{filter: filter, channel: eventChannel}
	b.mu.Unlock()

	return eventChannel, func() {
		b.mu.Lock()
		delete(b.subscriptions, id)
		b.mu.Unlock()
	}
}

// ForJob filters the events of one operation.
func ForJob(jobID string) func(Event) bool {
	return func(event Event) bool { return event.JobID == jobID }
}

// ForCampaign filters the events of the operations of one campaign.
func ForCampaign(campaignID string) func(Event) bool {
	return func(event Event) bool { return event.CampaignID == campaignID }
}
