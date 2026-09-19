// Package audit writes an append-only trail of events. Every path of success
// and of failure has to create an event, a refusal of access included.
package audit

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"reflect"
	"strconv"
	"strings"
	"time"

	"github.com/google/uuid"
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
	// ApprovalChain names, for an approval, who ordered the change and who
	// approved it. Nil for everything else.
	ApprovalChain *ApprovalChain
	// Before and After describe, for a change, the state on both sides of it -
	// where the handler has both at hand without an extra read.
	Before any
	After  any
}

// ApprovalChain is the sequence of people behind an approved change.
type ApprovalChain struct {
	CreatedBy string   `json:"created_by"`
	Approvers []string `json:"approvers"`
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
// transaction of the caller.
type queryExecutor interface {
	Exec(ctx context.Context, sql string, args ...any) (pgconn.CommandTag, error)
	QueryRow(ctx context.Context, sql string, args ...any) pgx.Row
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
	chain, err := optionalJSON(event.ApprovalChain)
	if err != nil {
		return fmt.Errorf("serialising the approval chain: %w", err)
	}
	before, err := optionalJSON(event.Before)
	if err != nil {
		return fmt.Errorf("serialising the state before: %w", err)
	}
	after, err := optionalJSON(event.After)
	if err != nil {
		return fmt.Errorf("serialising the state after: %w", err)
	}

	request := requestFromContext(ctx)
	var actor Actor
	if request != nil {
		actor = request.actor
	}
	requestID := event.RequestID
	if requestID == "" {
		requestID = actor.RequestID
	}
	var amr []string
	if actor.SessionID != "" {
		amr = actor.AMR
		if amr == nil {
			amr = []string{}
		}
	}

	// The snapshot of the host is taken at the moment of writing: a host renamed
	// or retired later keeps the name and the address it had when the event
	// happened.
	var hostname, address any
	if event.TargetType == "host" && event.TargetID != "" {
		snapshot, ok := r.hostSnapshot(ctx, q, request, event.TargetID)
		if ok {
			hostname, address = nullable(snapshot.hostname), nullable(snapshot.address)
		}
	}

	// The actor is snapshotted the same way: the identity behind the event as it
	// was called and identified at this moment, never joined later.
	who := r.actorSnapshot(ctx, q, request, event)

	const query = `
		insert into audit_events
			(actor_type, actor_id, action, target_type, target_id, request_id, outcome, detail,
			 session_id, acr, amr, auth_time, target_hostname, target_address,
			 approval_chain, before, after,
			 actor_principal_id, actor_subject, actor_display_name, actor_kind,
			 actor_resource_type, actor_resource_id, actor_resource_name, credential_id)
		values ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16, $17,
			$18::uuid, $19, $20, $21, $22, $23::uuid, $24, $25::uuid)`
	_, err = q.Exec(ctx, query,
		string(event.ActorType), event.ActorID, event.Action,
		nullable(event.TargetType), nullable(event.TargetID), nullable(requestID),
		string(event.Outcome), payload,
		nullable(actor.SessionID), nullable(actor.ACR), amr, nullableTime(actor.AuthTime),
		hostname, address, chain, before, after,
		nullableUUID(who.PrincipalID), nullable(who.Subject), nullable(who.DisplayName), nullable(who.Kind),
		nullable(who.ResourceType), nullableUUID(who.ResourceID), nullable(who.ResourceName),
		nullableUUID(who.CredentialID))
	return err
}

// hostSnapshot reads the name and the management address of a host, once per
// request: the lookups made under one request are remembered in its context.
func (r *Recorder) hostSnapshot(ctx context.Context, q queryExecutor,
	request *requestContext, hostID string) (hostSnapshot, bool) {
	if snapshot, ok := request.cachedHost(hostID); ok {
		return snapshot, true
	}
	if _, err := uuid.Parse(hostID); err != nil {
		return hostSnapshot{}, false
	}
	var snapshot hostSnapshot
	err := q.QueryRow(ctx,
		`select hostname, coalesce(management_address, '') from hosts where id = $1`,
		hostID).Scan(&snapshot.hostname, &snapshot.address)
	if errors.Is(err, pgx.ErrNoRows) {
		return hostSnapshot{}, false
	}
	if err != nil {
		r.log.Warn("the target host of an audit event was not read", "host", hostID, "err", err)
		return hostSnapshot{}, false
	}
	request.rememberHost(hostID, snapshot)
	return snapshot, true
}

// optionalJSON renders a value for a nullable jsonb column: nil stays null.
func optionalJSON(value any) (any, error) {
	if value == nil {
		return nil, nil
	}
	switch rv := reflect.ValueOf(value); rv.Kind() {
	case reflect.Pointer, reflect.Map, reflect.Slice, reflect.Interface:
		if rv.IsNil() {
			return nil, nil
		}
	}
	encoded, err := json.Marshal(value)
	if err != nil {
		return nil, err
	}
	return encoded, nil
}

func nullableTime(value time.Time) any {
	if value.IsZero() {
		return nil
	}
	return value
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
	// The session behind the event and how it was authenticated; absent
	// for an API token, an agent or the system.
	SessionID string     `json:"session_id,omitempty"`
	ACR       string     `json:"acr,omitempty"`
	AMR       []string   `json:"amr,omitempty"`
	AuthTime  *time.Time `json:"auth_time,omitempty"`
	// The target host as it was when the event was written.
	TargetHostname string `json:"target_hostname,omitempty"`
	TargetAddress  string `json:"target_address,omitempty"`
	// The people behind an approval, and the two sides of a change.
	ApprovalChain json.RawMessage `json:"approval_chain,omitempty"`
	Before        json.RawMessage `json:"before,omitempty"`
	After         json.RawMessage `json:"after,omitempty"`
	// The actor as it was when the event was written; absent for an event
	// from before the snapshot was kept.
	Actor *ActorSnapshot `json:"actor,omitempty"`
}

// recordColumns is the projection every read of the trail uses, so the
// list and the export return the same shape of an event.
const recordColumns = `
		id, occurred_at, actor_type, actor_id, action,
		coalesce(target_type, ''), coalesce(target_id, ''), coalesce(request_id, ''),
		outcome, detail,
		coalesce(session_id, ''), coalesce(acr, ''), amr, auth_time,
		coalesce(target_hostname, ''), coalesce(target_address, ''),
		approval_chain, before, after,
		coalesce(actor_principal_id::text, ''), coalesce(actor_subject, ''),
		coalesce(actor_display_name, ''), coalesce(actor_kind, ''),
		coalesce(actor_resource_type, ''), coalesce(actor_resource_id::text, ''),
		coalesce(actor_resource_name, ''), coalesce(credential_id::text, '')`

// scanRecord reads one row of recordColumns.
func scanRecord(rows pgx.Rows) (Record, error) {
	var rec Record
	var who ActorSnapshot
	if err := rows.Scan(&rec.ID, &rec.OccurredAt, &rec.ActorType, &rec.ActorID, &rec.Action,
		&rec.TargetType, &rec.TargetID, &rec.RequestID, &rec.Outcome, &rec.Detail,
		&rec.SessionID, &rec.ACR, &rec.AMR, &rec.AuthTime,
		&rec.TargetHostname, &rec.TargetAddress,
		&rec.ApprovalChain, &rec.Before, &rec.After,
		&who.PrincipalID, &who.Subject, &who.DisplayName, &who.Kind,
		&who.ResourceType, &who.ResourceID, &who.ResourceName, &who.CredentialID); err != nil {
		return Record{}, err
	}
	if !who.empty() {
		rec.Actor = &who
	}
	// A null column reads as the JSON null; the answer leaves the field out
	// instead, as it does for every other value the event does not carry.
	rec.ApprovalChain = dropNull(rec.ApprovalChain)
	rec.Before = dropNull(rec.Before)
	rec.After = dropNull(rec.After)
	if rec.SessionID == "" {
		// The column is null for a token; an empty array read back would
		// say "a session without methods", which is another thing.
		rec.AMR = nil
	}
	return rec, nil
}

func dropNull(value json.RawMessage) json.RawMessage {
	if len(value) == 0 || string(value) == "null" {
		return nil
	}
	return value
}

// ListFilter narrows the trail. Empty fields do not narrow.
type ListFilter struct {
	TargetID   string
	TargetType string
	// HostID keeps the events of one host: those aimed at the host and those of
	// its jobs, which name the host in their detail.
	HostID string
	// Actor is the identity that acted as actor_id spells it: a principal subject
	// or an agent's host identifier.
	Actor string
	// ActorKind is one of the ActorKind constants.
	ActorKind string
	// ActorPrincipalID keeps the events of one identity by its immutable
	// identifier; ActorResourceID those of one host, relay or campaign.
	ActorPrincipalID string
	ActorResourceID  string
	Action           string
	// ActionPrefix keeps a family of actions by the beginning of the name (job.
	ActionPrefix string
	Outcome      string
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
	if f.HostID != "" {
		args = append(args, f.HostID)
		conditions = append(conditions, fmt.Sprintf(
			"((target_type = 'host' and target_id = $%d) or detail->>'host_id' = $%d)", len(args), len(args)))
	}
	add("actor_id", f.Actor)
	add("actor_kind", f.ActorKind)
	// The identifiers are compared as text: a value that is not an
	// identifier then matches nothing instead of failing the read.
	add("actor_principal_id::text", f.ActorPrincipalID)
	add("actor_resource_id::text", f.ActorResourceID)
	add("action", f.Action)
	// The prefix is compared as a string, not as a pattern: an action name
	// carries dots and underscores, which a LIKE would read as its own.
	if f.ActionPrefix != "" {
		args = append(args, f.ActionPrefix)
		conditions = append(conditions, fmt.Sprintf("left(action, length($%d)) = $%d", len(args), len(args)))
	}
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

// ListPaged reads the trail newest first, page by page.
func (r *Recorder) ListPaged(ctx context.Context, filter ListFilter, cursor Cursor, limit int) (ListPage, error) {
	if limit <= 0 || limit > 500 {
		limit = 100
	}
	conditions, args := filter.conditions(nil)
	if cursor.Set {
		args = append(args, cursor.OccurredAt, cursor.ID)
		conditions = append(conditions, fmt.Sprintf("(occurred_at, id) < ($%d, $%d)", len(args)-1, len(args)))
	}
	query := `select ` + recordColumns + ` from audit_events`
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
		rec, err := scanRecord(rows)
		if err != nil {
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

// Each reads the trail oldest first and hands every event to fn, without
// holding the whole range in memory: an export covers months, and a page at a
// time is the wrong shape for a file.
func (r *Recorder) Each(ctx context.Context, filter ListFilter, fn func(Record) error) error {
	conditions, args := filter.conditions(nil)
	query := `select ` + recordColumns + ` from audit_events`
	if len(conditions) > 0 {
		query += " where " + strings.Join(conditions, " and ")
	}
	query += " order by occurred_at asc, id asc"

	rows, err := r.pool.Query(ctx, query, args...)
	if err != nil {
		return err
	}
	defer rows.Close()
	for rows.Next() {
		rec, err := scanRecord(rows)
		if err != nil {
			return err
		}
		if err := fn(rec); err != nil {
			return err
		}
	}
	return rows.Err()
}
