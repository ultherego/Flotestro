// Package audit writes an append-only trail of events. Every path of success
// and of failure has to create an event, a refusal of access included.
package audit

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"strconv"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/ultherego/flotestro/internal/paging"
)

type ActorType string

const (
	ActorUser   ActorType = "user"
	ActorAgent  ActorType = "agent"
	ActorSystem ActorType = "system"
)

type Outcome string

const (
	OutcomeSuccess Outcome = "success"
	OutcomeFailure Outcome = "failure"
	OutcomeDenied  Outcome = "denied"
)

// Event describes a single audit event.
type Event struct {
	ActorType  ActorType
	ActorID    string
	Action     string
	TargetType string
	TargetID   string
	RequestID  string
	Outcome    Outcome
	Detail     map[string]any
}

// Recorder writes the events into the database.
type Recorder struct {
	pool *pgxpool.Pool
	log  *slog.Logger
}

func NewRecorder(pool *pgxpool.Pool, log *slog.Logger) *Recorder {
	return &Recorder{pool: pool, log: log}
}

// Record writes an event outside the transaction of the caller.
func (r *Recorder) Record(ctx context.Context, event Event) {
	if err := r.record(ctx, r.pool, event); err != nil {
		// A missing audit entry must not disappear silently, even when the
		// operation succeeded.
		r.log.Error("the audit event was not written",
			"action", event.Action, "target", event.TargetID, "err", err)
	}
}

// RecordTx writes an event inside the transaction of the caller, so that the
// change of state and its audit trail are committed together.
func (r *Recorder) RecordTx(ctx context.Context, tx pgx.Tx, event Event) error {
	return r.record(ctx, tx, event)
}

// queryExecutor allows writing an event both through the pool and inside the
// transaction of the caller. Both *pgxpool.Pool and pgx.Tx satisfy it.
type queryExecutor interface {
	Exec(ctx context.Context, sql string, args ...any) (pgconn.CommandTag, error)
}

func (r *Recorder) record(ctx context.Context, q queryExecutor, event Event) error {
	detail := event.Detail
	if detail == nil {
		detail = map[string]any{}
	}
	payload, err := json.Marshal(detail)
	if err != nil {
		return fmt.Errorf("serialising the detail: %w", err)
	}
	const query = `
		insert into audit_events
			(actor_type, actor_id, action, target_type, target_id, request_id, outcome, detail)
		values ($1, $2, $3, $4, $5, $6, $7, $8)`
	_, err = q.Exec(ctx, query,
		string(event.ActorType), event.ActorID, event.Action,
		nullable(event.TargetType), nullable(event.TargetID), nullable(event.RequestID),
		string(event.Outcome), payload)
	return err
}

func nullable(value string) any {
	if value == "" {
		return nil
	}
	return value
}

// Record describes a written event as the API returns it.
type Record struct {
	ID         int64           `json:"id"`
	OccurredAt time.Time       `json:"occurred_at"`
	ActorType  string          `json:"actor_type"`
	ActorID    string          `json:"actor_id"`
	Action     string          `json:"action"`
	TargetType string          `json:"target_type,omitempty"`
	TargetID   string          `json:"target_id,omitempty"`
	RequestID  string          `json:"request_id,omitempty"`
	Outcome    string          `json:"outcome"`
	Detail     json.RawMessage `json:"detail"`
}

// ListFilter narrows the trail. Empty fields do not narrow.
type ListFilter struct {
	TargetID   string
	TargetType string
	// Actor is the identity that acted: a principal subject or an agent's
	// host identifier.
	Actor   string
	Action  string
	Outcome string
	// Since and Until bound the time of the events; Until is exclusive.
	Since *time.Time
	Until *time.Time
}

// conditions renders the filter as SQL; the parameters continue from those
// already in args.
func (f ListFilter) conditions(args []any) ([]string, []any) {
	var conditions []string
	add := func(column, value string) {
		if value == "" {
			return
		}
		args = append(args, value)
		conditions = append(conditions, fmt.Sprintf("%s = $%d", column, len(args)))
	}
	add("target_id", f.TargetID)
	add("target_type", f.TargetType)
	add("actor_id", f.Actor)
	add("action", f.Action)
	add("outcome", f.Outcome)
	if f.Since != nil {
		args = append(args, *f.Since)
		conditions = append(conditions, fmt.Sprintf("occurred_at >= $%d", len(args)))
	}
	if f.Until != nil {
		args = append(args, *f.Until)
		conditions = append(conditions, fmt.Sprintf("occurred_at < $%d", len(args)))
	}
	return conditions, args
}

// Cursor is the key of the last event of the previous page. The trail is
// read newest first, so the next page holds the events before it.
type Cursor struct {
	OccurredAt time.Time
	ID         int64
	Set        bool
}

// ParseCursor reads a cursor issued by ListPaged. An empty value is the
// first page.
func ParseCursor(value string) (Cursor, error) {
	parts, err := paging.Decode(value, 2)
	if err != nil {
		return Cursor{}, err
	}
	if parts == nil {
		return Cursor{}, nil
	}
	at, err := paging.ParseTime(parts[0])
	if err != nil {
		return Cursor{}, err
	}
	id, err := strconv.ParseInt(parts[1], 10, 64)
	if err != nil {
		return Cursor{}, fmt.Errorf("%w: %v", paging.ErrInvalidCursor, err)
	}
	return Cursor{OccurredAt: at, ID: id, Set: true}, nil
}

// String renders the cursor for the next request.
func (c Cursor) String() string {
	return paging.Encode(paging.FormatTime(c.OccurredAt), strconv.FormatInt(c.ID, 10))
}

// ListPage is one page of the trail.
type ListPage struct {
	Items []Record `json:"items"`
	// NextCursor is empty on the last page.
	NextCursor string `json:"next_cursor,omitempty"`
}

// ListPaged reads the trail newest first, page by page. The key is
// (occurred_at, id): two events written in the same microsecond still have
// an order, so a page boundary between them loses neither.
func (r *Recorder) ListPaged(ctx context.Context, filter ListFilter, cursor Cursor, limit int) (ListPage, error) {
	if limit <= 0 || limit > 500 {
		limit = 100
	}
	conditions, args := filter.conditions(nil)
	if cursor.Set {
		args = append(args, cursor.OccurredAt, cursor.ID)
		conditions = append(conditions, fmt.Sprintf("(occurred_at, id) < ($%d, $%d)", len(args)-1, len(args)))
	}
	query := `
		select id, occurred_at, actor_type, actor_id, action,
		       coalesce(target_type, ''), coalesce(target_id, ''), coalesce(request_id, ''),
		       outcome, detail
		from audit_events`
	if len(conditions) > 0 {
		query += " where " + strings.Join(conditions, " and ")
	}
	// One row more than the page says whether there is a next page without
	// a count over the whole trail.
	args = append(args, limit+1)
	query += fmt.Sprintf(" order by occurred_at desc, id desc limit $%d", len(args))

	rows, err := r.pool.Query(ctx, query, args...)
	if err != nil {
		return ListPage{}, err
	}
	defer rows.Close()

	page := ListPage{Items: []Record{}}
	for rows.Next() {
		var rec Record
		if err := rows.Scan(&rec.ID, &rec.OccurredAt, &rec.ActorType, &rec.ActorID, &rec.Action,
			&rec.TargetType, &rec.TargetID, &rec.RequestID, &rec.Outcome, &rec.Detail); err != nil {
			return ListPage{}, err
		}
		page.Items = append(page.Items, rec)
	}
	if err := rows.Err(); err != nil {
		return ListPage{}, err
	}
	if len(page.Items) > limit {
		page.Items = page.Items[:limit]
		last := page.Items[limit-1]
		page.NextCursor = Cursor{OccurredAt: last.OccurredAt, ID: last.ID, Set: true}.String()
	}
	return page, nil
}

// List returns the latest events, optionally narrowed to one target.
func (r *Recorder) List(ctx context.Context, targetID string, limit int) ([]Record, error) {
	page, err := r.ListPaged(ctx, ListFilter{TargetID: targetID}, Cursor{}, limit)
	if err != nil {
		return nil, err
	}
	return page.Items, nil
}
