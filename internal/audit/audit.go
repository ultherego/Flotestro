// Package audit zapisuje append-only slad zdarzen. Kazda sciezka sukcesu
// i bledu musi tworzyc zdarzenie, takze odmowa dostepu.
package audit

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"
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

// Event opisuje pojedyncze zdarzenie audytowe.
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

// Recorder zapisuje zdarzenia do bazy.
type Recorder struct {
	pool *pgxpool.Pool
	log  *slog.Logger
}

func NewRecorder(pool *pgxpool.Pool, log *slog.Logger) *Recorder {
	return &Recorder{pool: pool, log: log}
}

// Record zapisuje zdarzenie poza transakcja wywolujacego.
func (r *Recorder) Record(ctx context.Context, event Event) {
	if err := r.record(ctx, r.pool, event); err != nil {
		// Brak audytu nie moze cicho zniknac, nawet jesli operacja sie udala.
		r.log.Error("nie zapisano zdarzenia audytowego",
			"action", event.Action, "target", event.TargetID, "err", err)
	}
}

// RecordTx zapisuje zdarzenie w transakcji wywolujacego, dzieki czemu zmiana
// stanu i jej slad audytowy sa zatwierdzane razem.
func (r *Recorder) RecordTx(ctx context.Context, tx pgx.Tx, event Event) error {
	return r.record(ctx, tx, event)
}

// queryExecutor pozwala zapisac zdarzenie zarowno przez pule, jak i wewnatrz
// transakcji wywolujacego. Spelniaja go *pgxpool.Pool oraz pgx.Tx.
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
		return fmt.Errorf("serializacja detail: %w", err)
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

// Record opisuje zapisane zdarzenie zwracane przez API.
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

// List zwraca ostatnie zdarzenia, opcjonalnie zawezone do jednego celu.
func (r *Recorder) List(ctx context.Context, targetID string, limit int) ([]Record, error) {
	if limit <= 0 || limit > 500 {
		limit = 100
	}
	query := `
		select id, occurred_at, actor_type, actor_id, action,
		       coalesce(target_type, ''), coalesce(target_id, ''), coalesce(request_id, ''),
		       outcome, detail
		from audit_events`
	args := []any{}
	if targetID != "" {
		args = append(args, targetID)
		query += " where target_id = $1"
	}
	args = append(args, limit)
	query += fmt.Sprintf(" order by occurred_at desc, id desc limit $%d", len(args))

	rows, err := r.pool.Query(ctx, query, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var records []Record
	for rows.Next() {
		var rec Record
		if err := rows.Scan(&rec.ID, &rec.OccurredAt, &rec.ActorType, &rec.ActorID, &rec.Action,
			&rec.TargetType, &rec.TargetID, &rec.RequestID, &rec.Outcome, &rec.Detail); err != nil {
			return nil, err
		}
		records = append(records, rec)
	}
	return records, rows.Err()
}
