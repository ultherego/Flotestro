package identity

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

var (
	// ErrNotFound means there is no change with the given identifier.
	ErrNotFound = errors.New("the change does not exist")
	// ErrConflict means an operation not allowed in the current state.
	ErrConflict = errors.New("the operation is not allowed in the current state of the change")
	// ErrBlocked means a plan that rules out execution.
	ErrBlocked = errors.New("the plan holds conflicts and cannot be carried out")
)

// Store gives access to the directory change table.
type Store struct {
	pool *pgxpool.Pool
}

func NewStore(pool *pgxpool.Pool) *Store {
	return &Store{pool: pool}
}

func (s *Store) Pool() *pgxpool.Pool { return s.pool }

// Spec describes the change to create.
type Spec struct {
	Action           ActionType
	Payload          Payload
	Plan             Plan
	RequiresApproval bool
	CreatedBy        string
	RequestID        string
}

// Create records a planned change. A change that requires approval does not
// start until somebody approves it.
func (s *Store) Create(ctx context.Context, tx pgx.Tx, spec Spec) (*Change, error) {
	if err := Validate(spec.Action, spec.Payload); err != nil {
		return nil, err
	}
	hash, err := PayloadHash(spec.Action, spec.Payload)
	if err != nil {
		return nil, err
	}
	payloadJSON, err := json.Marshal(spec.Payload)
	if err != nil {
		return nil, err
	}
	planJSON, err := json.Marshal(spec.Plan)
	if err != nil {
		return nil, err
	}

	state := StatePlanned
	if spec.RequiresApproval {
		state = StateAwaitingApproval
	}
	id := uuid.NewString()

	const query = `
		insert into directory_changes
			(id, action_type, payload, payload_hash, plan, state, requires_approval,
			 created_by, request_id)
		values ($1, $2, $3, $4, $5, $6, $7, $8, $9)`
	if _, err := tx.Exec(ctx, query, id, string(spec.Action), payloadJSON, hash, planJSON,
		string(state), spec.RequiresApproval, spec.CreatedBy, nullable(spec.RequestID)); err != nil {
		return nil, fmt.Errorf("recording the directory change: %w", err)
	}
	return s.getTx(ctx, tx, id)
}

// Approve approves the change and admits it to execution.
func (s *Store) Approve(ctx context.Context, tx pgx.Tx, changeID, actor string) (*Change, error) {
	const query = `
		update directory_changes set state = $2, approved_by = $3, approved_at = now(),
		                             updated_at = now()
		where id = $1 and state = $4
		returning id`
	var updated string
	err := tx.QueryRow(ctx, query, changeID, string(StatePlanned), actor,
		string(StateAwaitingApproval)).Scan(&updated)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, ErrConflict
	}
	if err != nil {
		return nil, err
	}
	return s.getTx(ctx, tx, changeID)
}

// Cancel cancels a change that has not started yet.
func (s *Store) Cancel(ctx context.Context, changeID, actor, reason string) (*Change, error) {
	const query = `
		update directory_changes set state = $2, canceled_by = $3, canceled_at = now(),
		                             result_message = $4, finished_at = now(), updated_at = now()
		where id = $1 and state in ('planned', 'awaiting_approval')
		returning id`
	var updated string
	err := s.pool.QueryRow(ctx, query, changeID, string(StateCanceled), actor, nullable(reason)).Scan(&updated)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, ErrConflict
	}
	if err != nil {
		return nil, err
	}
	return s.Get(ctx, changeID)
}

// Claim takes a change for execution. The condition on the state means two
// replicas will not carry out the same change in parallel.
func (s *Store) Claim(ctx context.Context, changeID string) (bool, error) {
	const query = `
		update directory_changes set state = $2, started_at = now(), updated_at = now()
		where id = $1 and state = $3`
	tag, err := s.pool.Exec(ctx, query, changeID, string(StateRunning), string(StatePlanned))
	if err != nil {
		return false, err
	}
	return tag.RowsAffected() > 0, nil
}

// Finish records the execution result phase by phase.
func (s *Store) Finish(ctx context.Context, changeID string, state State,
	phases []Phase, message string) error {
	phasesJSON, err := json.Marshal(phases)
	if err != nil {
		return err
	}
	const query = `
		update directory_changes set state = $2, phases = $3, result_message = $4,
		                             finished_at = now(), updated_at = now()
		where id = $1`
	_, err = s.pool.Exec(ctx, query, changeID, string(state), phasesJSON, nullable(message))
	return err
}

// Pending returns the approved changes waiting for execution.
func (s *Store) Pending(ctx context.Context) ([]Change, error) {
	return s.query(ctx, "where state = 'planned' order by created_at limit 20")
}

// Get zwraca zmiane.
func (s *Store) Get(ctx context.Context, changeID string) (*Change, error) {
	found, err := s.query(ctx, "where id = $1", changeID)
	if err != nil {
		return nil, err
	}
	if len(found) == 0 {
		return nil, ErrNotFound
	}
	return &found[0], nil
}

func (s *Store) getTx(ctx context.Context, tx pgx.Tx, changeID string) (*Change, error) {
	rows, err := tx.Query(ctx, changeColumns+" where id = $1", changeID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	changes, err := scanChanges(rows)
	if err != nil {
		return nil, err
	}
	if len(changes) == 0 {
		return nil, ErrNotFound
	}
	return &changes[0], nil
}

// List returns the changes, optionally narrowed by state.
func (s *Store) List(ctx context.Context, state string, limit int) ([]Change, error) {
	if limit <= 0 || limit > 200 {
		limit = 50
	}
	if state != "" {
		return s.query(ctx, fmt.Sprintf("where state = $1 order by created_at desc limit %d", limit), state)
	}
	return s.query(ctx, fmt.Sprintf("order by created_at desc limit %d", limit))
}

const changeColumns = `
	select id, action_type, payload, encode(payload_hash, 'hex'), plan, state,
	       requires_approval, coalesce(approved_by, ''), approved_at,
	       coalesce(canceled_by, ''), phases, coalesce(result_message, ''),
	       created_by, coalesce(request_id, ''), started_at, finished_at, created_at
	from directory_changes `

func (s *Store) query(ctx context.Context, clause string, args ...any) ([]Change, error) {
	rows, err := s.pool.Query(ctx, changeColumns+clause, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	return scanChanges(rows)
}

func scanChanges(rows pgx.Rows) ([]Change, error) {
	var changes []Change
	for rows.Next() {
		var c Change
		if err := rows.Scan(&c.ID, &c.ActionType, &c.Payload, &c.PayloadHash, &c.Plan,
			&c.State, &c.RequiresApproval, &c.ApprovedBy, &c.ApprovedAt, &c.CanceledBy,
			&c.Phases, &c.ResultMessage, &c.CreatedBy, &c.RequestID,
			&c.StartedAt, &c.FinishedAt, &c.CreatedAt); err != nil {
			return nil, err
		}
		changes = append(changes, c)
	}
	return changes, rows.Err()
}

// SetLocalDeny sets the local denial marker for an external account.
// The marker takes effect at once, before the lock in the directory reaches
// the hosts and the identity provider.
func (s *Store) SetLocalDeny(ctx context.Context, subject, reason string, denied bool) (int64, error) {
	var query string
	var args []any
	if denied {
		query = `update principals set denied_at = now(), denied_reason = $2, updated_at = now()
		         where subject = $1`
		args = []any{subject, nullable(reason)}
	} else {
		query = `update principals set denied_at = null, denied_reason = null, updated_at = now()
		         where subject = $1`
		args = []any{subject}
	}
	tag, err := s.pool.Exec(ctx, query, args...)
	if err != nil {
		return 0, err
	}
	return tag.RowsAffected(), nil
}

func nullable(value string) any {
	if value == "" {
		return nil
	}
	return value
}
