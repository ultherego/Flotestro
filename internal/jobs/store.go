package jobs

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/ultherego/flotestro/internal/authz"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/ultherego/flotestro/internal/opspec"
)

var (
	// ErrNotFound means there is no job with the given identifier.
	ErrNotFound = errors.New("the task does not exist")
	// ErrConflict means an attempt at a transition forbidden in this state.
	ErrConflict = errors.New("the operation is not allowed in the current state of the task")
)

// Spec describes the task to create.
type Spec struct {
	HostID           string
	Action           opspec.ActionType
	Payload          opspec.Payload
	IdempotencyKey   string
	RequiresApproval bool
	// RequiredApprovals says how many people are needed. An operation that
	// destroys data requires two: a mistake by one person with the right to
	// approve costs data nobody will restore. Zero means the default value.
	RequiredApprovals int
	TimeoutSeconds    int
	MaxOutputBytes    int
	TTL               time.Duration
	CreatedBy         string
	RequestID         string
	// CampaignID binds the operation to the rollout that ordered it. Without
	// it the audit trail's correlation breaks off at the operation, and the
	// campaign screen does not know which operations are its own - the
	// progress of an upgrade under way had no way of reaching it.
	CampaignID    string
	Preconditions Preconditions
}

// Preconditions are checked by the agent right before execution.
type Preconditions struct {
	OSFamily             string   `json:"os_family,omitempty"`
	RequiredCapabilities []string `json:"required_capabilities,omitempty"`
	ExpectedBootID       string   `json:"expected_boot_id,omitempty"`
}

// Job is the view of a task returned by the API.
type Job struct {
	ID               string          `json:"id"`
	HostID           string          `json:"host_id"`
	CampaignID       *string         `json:"campaign_id,omitempty"`
	ActionType       string          `json:"action_type"`
	ActionVersion    int             `json:"action_version"`
	Payload          json.RawMessage `json:"payload"`
	PayloadHash      string          `json:"payload_hash"`
	IdempotencyKey   string          `json:"idempotency_key"`
	State            State           `json:"state"`
	RequiresApproval bool            `json:"requires_approval"`
	// RequiredApprovals and Approvals say how many approvals are needed and
	// how many there already are. Without them the operator clicks "approve"
	// and does not know why nothing happened.
	RequiredApprovals  int             `json:"required_approvals"`
	CollectedApprovals int             `json:"collected_approvals"`
	Approvals          []Approval      `json:"approvals,omitempty"`
	Preconditions      json.RawMessage `json:"preconditions"`
	TimeoutSeconds     int             `json:"timeout_seconds"`
	MaxOutputBytes     int             `json:"max_output_bytes"`
	ExpiresAt          time.Time       `json:"expires_at"`
	CreatedBy          string          `json:"created_by"`
	RequestID          string          `json:"request_id,omitempty"`
	ApprovedBy         string          `json:"approved_by,omitempty"`
	ApprovedAt         *time.Time      `json:"approved_at,omitempty"`
	CanceledBy         string          `json:"canceled_by,omitempty"`
	CancelReason       string          `json:"cancel_reason,omitempty"`
	ResultStatus       string          `json:"result_status,omitempty"`
	ResultErrorCode    string          `json:"result_error_code,omitempty"`
	ResultMessage      string          `json:"result_message,omitempty"`
	FinishedAt         *time.Time      `json:"finished_at,omitempty"`
	CreatedAt          time.Time       `json:"created_at"`
	UpdatedAt          time.Time       `json:"updated_at"`
}

// Attempt describes one attempt at carrying out a task.
type Attempt struct {
	ID              string          `json:"id"`
	JobID           string          `json:"job_id"`
	Number          int             `json:"attempt_number"`
	GatewayID       string          `json:"gateway_id,omitempty"`
	SessionID       *string         `json:"session_id,omitempty"`
	Status          string          `json:"status,omitempty"`
	ExitCode        *int            `json:"exit_code,omitempty"`
	ErrorCode       string          `json:"error_code,omitempty"`
	Message         string          `json:"message,omitempty"`
	Stdout          string          `json:"stdout,omitempty"`
	Stderr          string          `json:"stderr,omitempty"`
	OutputTruncated bool            `json:"output_truncated"`
	Replayed        bool            `json:"replayed"`
	UnitStateBefore json.RawMessage `json:"unit_state_before,omitempty"`
	UnitStateAfter  json.RawMessage `json:"unit_state_after,omitempty"`
	Detail          json.RawMessage `json:"detail,omitempty"`
	DispatchedAt    *time.Time      `json:"dispatched_at,omitempty"`
	FinishedAt      *time.Time      `json:"finished_at,omitempty"`
	CreatedAt       time.Time       `json:"created_at"`
}

// Store provides access to the task tables.
type Store struct {
	pool *pgxpool.Pool
}

func NewStore(pool *pgxpool.Pool) *Store {
	return &Store{pool: pool}
}

func (s *Store) Pool() *pgxpool.Pool { return s.pool }

// Create creates a task together with the plan hash. A task that requires
// approval starts in awaiting_approval and does not reach the queue until
// somebody approves it.
func (s *Store) Create(ctx context.Context, tx pgx.Tx, spec Spec) (*Job, error) {
	if err := opspec.Validate(spec.Action, spec.Payload); err != nil {
		return nil, err
	}
	payloadHash, err := opspec.PayloadHash(spec.Action, opspec.ActionVersion, spec.Payload)
	if err != nil {
		return nil, err
	}
	payloadJSON, err := json.Marshal(spec.Payload)
	if err != nil {
		return nil, err
	}
	preconditionsJSON, err := json.Marshal(spec.Preconditions)
	if err != nil {
		return nil, err
	}

	state := StateQueued
	if spec.RequiresApproval {
		state = StateAwaitingApproval
	}
	timeout := spec.TimeoutSeconds
	if timeout <= 0 {
		timeout = spec.Action.DefaultTimeout()
	}
	maxOutput := spec.MaxOutputBytes
	if maxOutput <= 0 {
		maxOutput = 64 << 10
	}
	ttl := spec.TTL
	if ttl <= 0 {
		ttl = 15 * time.Minute
	}
	idempotencyKey := spec.IdempotencyKey
	if idempotencyKey == "" {
		idempotencyKey = uuid.NewString()
	}

	const query = `
		insert into jobs (id, host_id, action_type, action_version, payload, payload_hash,
		                  idempotency_key, state, requires_approval, preconditions,
		                  timeout_seconds, max_output_bytes, expires_at, created_by, request_id,
		                  campaign_id, required_approvals)
		values ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15,
		        nullif($16, '')::uuid, $17)
		on conflict (host_id, idempotency_key) do nothing
		returning id`
	jobID := uuid.NewString()
	err = tx.QueryRow(ctx, query, jobID, spec.HostID, string(spec.Action), opspec.ActionVersion,
		payloadJSON, payloadHash, idempotencyKey, string(state), spec.RequiresApproval,
		preconditionsJSON, timeout, maxOutput, time.Now().Add(ttl),
		spec.CreatedBy, nullable(spec.RequestID), spec.CampaignID, requiredApprovals(spec)).Scan(&jobID)
	if errors.Is(err, pgx.ErrNoRows) {
		// The same idempotency key returns the existing task instead of
		// creating a second one. A repeated order is not an error.
		return s.getTx(ctx, tx, "where host_id = $1 and idempotency_key = $2", spec.HostID, idempotencyKey)
	}
	if err != nil {
		return nil, fmt.Errorf("creating the task: %w", err)
	}
	return s.getTx(ctx, tx, "where id = $1", jobID)
}

// Approve records an approval and lets the task through once it has
// collected enough of them.
//
// The approval is always recorded, also when one is not enough: a destructive
// operation requires two people, and the first of them is to see that their
// approval was accepted rather than bounced without a trace.
func (s *Store) Approve(ctx context.Context, tx pgx.Tx, jobID, actor, reason string) (*Job, error) {
	const recordApproval = `
		insert into job_approvals (job_id, approver, reason)
		values ($1, $2, $3)
		on conflict (job_id, approver) do nothing`
	if _, err := tx.Exec(ctx, recordApproval, jobID, actor, nullable(reason)); err != nil {
		return nil, err
	}

	// The same person does not count twice: the table's primary key guards
	// that in the database rather than in code, which can be bypassed by
	// another path.
	const query = `
		update jobs set state = $2, approved_by = $3, approved_at = now(), updated_at = now()
		where id = $1 and state = $4
		  and (select count(*) from job_approvals where job_id = $1) >= required_approvals
		returning id`
	var updated string
	err := tx.QueryRow(ctx, query, jobID, string(StateQueued), actor, string(StateAwaitingApproval)).Scan(&updated)
	if errors.Is(err, pgx.ErrNoRows) {
		// The task stays waiting: either approvals are missing, or somebody
		// changed its state in the meantime. The state we are about to read
		// settles it.
		task, err := s.getTx(ctx, tx, "where id = $1", jobID)
		if err != nil {
			return nil, err
		}
		if task.State != StateAwaitingApproval {
			return nil, ErrConflict
		}
		return task, nil
	}
	if err != nil {
		return nil, err
	}
	return s.getTx(ctx, tx, "where id = $1", jobID)
}

// Approvals returns the people who approved the task.
func (s *Store) Approvals(ctx context.Context, jobID string) ([]Approval, error) {
	const query = `
		select approver, coalesce(reason, ''), approved_at
		from job_approvals where job_id = $1 order by approved_at`
	rows, err := s.pool.Query(ctx, query, jobID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var approvals []Approval
	for rows.Next() {
		var approval Approval
		if err := rows.Scan(&approval.Approver, &approval.Reason, &approval.ApprovedAt); err != nil {
			return nil, err
		}
		approvals = append(approvals, approval)
	}
	return approvals, rows.Err()
}

// Approval is a single approval of a task.
type Approval struct {
	Approver   string    `json:"approver"`
	Reason     string    `json:"reason,omitempty"`
	ApprovedAt time.Time `json:"approved_at"`
}

// requiredApprovals decides how many people have to approve the task.
//
// The number is a property of the operation rather than of the environment: a
// disk formatted in a test environment is a formatted disk too.
func requiredApprovals(spec Spec) int {
	if spec.RequiredApprovals > 0 {
		return spec.RequiredApprovals
	}
	if spec.Action.Risk() == opspec.RiskDestructive {
		return 2
	}
	return 1
}

// Cancel cancels a task that has not reached a final state yet.
func (s *Store) Cancel(ctx context.Context, tx pgx.Tx, jobID, actor, reason string) (*Job, error) {
	const query = `
		update jobs set state = $2, canceled_by = $3, canceled_at = now(),
		                cancel_reason = $4, finished_at = now(), updated_at = now()
		where id = $1
		  and state in ('planned', 'awaiting_approval', 'queued', 'leased', 'dispatched', 'running')
		returning id`
	var updated string
	err := tx.QueryRow(ctx, query, jobID, string(StateCanceled), actor, nullable(reason)).Scan(&updated)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, ErrConflict
	}
	if err != nil {
		return nil, err
	}
	return s.getTx(ctx, tx, "where id = $1", jobID)
}

// CancelUndelivered ends the host's tasks that have not started yet.
//
// Tasks being delivered and running stay: the agent may be halfway through an
// uninterruptible operation, and the panel has no way of undoing it.
// Cancelling them in the database would only mean the result arriving for a
// task that no longer exists.
func (s *Store) CancelUndelivered(ctx context.Context, tx pgx.Tx, hostID, actor,
	reason string) (int, error) {
	const query = `
		update jobs set state = $2, canceled_by = $3, canceled_at = now(),
		                cancel_reason = $4, finished_at = now(), updated_at = now()
		where host_id = $1::uuid
		  and state in ('planned', 'awaiting_approval', 'queued', 'leased')`
	tag, err := tx.Exec(ctx, query, hostID, string(StateCanceled), actor, nullable(reason))
	if err != nil {
		return 0, err
	}
	return int(tag.RowsAffected()), nil
}

// OpenTasksOfAction returns the host's unfinished tasks of a given action
// together with their last attempt and payload.
//
// Used by operations that only the host's return settles: the agent replaces
// itself and has no way of sending the result back, because the process that
// computed it has just been replaced.
func (s *Store) OpenTasksOfAction(ctx context.Context, hostID,
	action string) ([]OpenTask, error) {
	const query = `
		select j.id::text, coalesce(a.id::text, ''), j.payload
		from jobs j
		left join lateral (
			select id from job_attempts where job_id = j.id
			order by attempt_number desc limit 1
		) a on true
		where j.host_id = $1::uuid and j.action_type = $2
		  and j.state in ('queued', 'leased', 'dispatched', 'running')
		order by j.created_at`
	rows, err := s.pool.Query(ctx, query, hostID, action)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var tasks []OpenTask
	for rows.Next() {
		var task OpenTask
		if err := rows.Scan(&task.JobID, &task.AttemptID, &task.Payload); err != nil {
			return nil, err
		}
		tasks = append(tasks, task)
	}
	return tasks, rows.Err()
}

// OpenTask is a task waiting to be settled.
type OpenTask struct {
	JobID     string
	AttemptID string
	Payload   json.RawMessage
}

// LeasedJob joins a task with the attempt carrying it out.
type LeasedJob struct {
	Job       Job
	AttemptID string
	Attempt   int
}

// Lease takes the tasks ready to run for the given hosts and gives them a
// lease. SKIP LOCKED means parallel workers neither block each other nor take
// the same task.
func (s *Store) Lease(ctx context.Context, gatewayID string, hostIDs []string,
	limit int, leaseDuration time.Duration) ([]LeasedJob, error) {
	if len(hostIDs) == 0 || limit <= 0 {
		return nil, nil
	}
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return nil, err
	}
	defer func() { _ = tx.Rollback(ctx) }()

	const selectQuery = `
		select id from jobs
		where state = 'queued'
		  and host_id = any($1)
		  and expires_at > now()
		order by created_at
		limit $2
		for update skip locked`
	rows, err := tx.Query(ctx, selectQuery, hostIDs, limit)
	if err != nil {
		return nil, fmt.Errorf("taking the tasks: %w", err)
	}
	var jobIDs []string
	for rows.Next() {
		var id string
		if err := rows.Scan(&id); err != nil {
			rows.Close()
			return nil, err
		}
		jobIDs = append(jobIDs, id)
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return nil, err
	}
	if len(jobIDs) == 0 {
		return nil, tx.Commit(ctx)
	}

	leased := make([]LeasedJob, 0, len(jobIDs))
	deadline := time.Now().Add(leaseDuration)
	for _, jobID := range jobIDs {
		if _, err := tx.Exec(ctx,
			`update jobs set state = $2, updated_at = now() where id = $1`,
			jobID, string(StateLeased)); err != nil {
			return nil, err
		}

		var attemptNumber int
		if err := tx.QueryRow(ctx,
			`select coalesce(max(attempt_number), 0) + 1 from job_attempts where job_id = $1`,
			jobID).Scan(&attemptNumber); err != nil {
			return nil, err
		}
		attemptID := uuid.NewString()
		if _, err := tx.Exec(ctx, `
			insert into job_attempts (id, job_id, attempt_number, lease_owner, lease_expires_at, gateway_id)
			values ($1, $2, $3, $4, $5, $6)`,
			attemptID, jobID, attemptNumber, gatewayID, deadline, gatewayID); err != nil {
			return nil, err
		}

		job, err := s.getTx(ctx, tx, "where id = $1", jobID)
		if err != nil {
			return nil, err
		}
		leased = append(leased, LeasedJob{Job: *job, AttemptID: attemptID, Attempt: attemptNumber})
	}
	if err := tx.Commit(ctx); err != nil {
		return nil, err
	}
	return leased, nil
}

// MarkDispatched records handing the task over to the agent.
func (s *Store) MarkDispatched(ctx context.Context, jobID, attemptID, sessionID string) error {
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback(ctx) }()

	if _, err := tx.Exec(ctx,
		`update jobs set state = $2, updated_at = now() where id = $1 and state = $3`,
		jobID, string(StateDispatched), string(StateLeased)); err != nil {
		return err
	}
	if _, err := tx.Exec(ctx,
		`update job_attempts set dispatched_at = now(), session_id = $2 where id = $1`,
		attemptID, nullableUUID(sessionID)); err != nil {
		return err
	}
	return tx.Commit(ctx)
}

// ReleaseLease returns the task to the queue when it could not be delivered.
func (s *Store) ReleaseLease(ctx context.Context, jobID, attemptID, reason string) error {
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback(ctx) }()

	if _, err := tx.Exec(ctx, `
		update jobs set state = $2, updated_at = now()
		where id = $1 and state in ('leased', 'dispatched')`,
		jobID, string(StateQueued)); err != nil {
		return err
	}
	if _, err := tx.Exec(ctx, `
		update job_attempts set finished_at = now(), status = 'released',
		                        message = $2, lease_expires_at = null
		where id = $1`, attemptID, reason); err != nil {
		return err
	}
	return tx.Commit(ctx)
}

// Result describes the result reported by the agent.
type Result struct {
	Status          string
	ExitCode        int32
	Stdout          []byte
	Stderr          []byte
	OutputTruncated bool
	ErrorCode       string
	Message         string
	Replayed        bool
	UnitStateBefore json.RawMessage
	UnitStateAfter  json.RawMessage
	// Detail is the result specific to the operation type, e.g. an upgrade plan.
	Detail json.RawMessage
}

// RecordResult records the result of an attempt and moves the task to a final
// state. It returns whether the result was accepted: a late result after a
// lost lease is kept for diagnostics but does not overwrite a newer
// decision.
func (s *Store) RecordResult(ctx context.Context, jobID, attemptID string,
	result Result, jobState State) (accepted bool, err error) {
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return false, err
	}
	defer func() { _ = tx.Rollback(ctx) }()

	var currentState State
	if err := tx.QueryRow(ctx, `select state from jobs where id = $1 for update`, jobID).
		Scan(&currentState); err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return false, ErrNotFound
		}
		return false, err
	}

	if _, err := tx.Exec(ctx, `
		update job_attempts set
			status = $2, exit_code = $3, error_code = $4, message = $5,
			stdout = $6, stderr = $7, output_truncated = $8, replayed = $9,
			unit_state_before = $10, unit_state_after = $11, result_detail = $12,
			finished_at = now(), lease_expires_at = null
		where id = $1`,
		attemptID, result.Status, result.ExitCode, nullable(result.ErrorCode), nullable(result.Message),
		string(result.Stdout), string(result.Stderr), result.OutputTruncated, result.Replayed,
		nullableJSON(result.UnitStateBefore), nullableJSON(result.UnitStateAfter),
		nullableJSON(result.Detail)); err != nil {
		return false, err
	}

	// A final state is final: a result that arrived after a cancellation or
	// after another settlement does not undo the decision.
	if currentState.Terminal() {
		return false, tx.Commit(ctx)
	}
	if err := currentState.Validate(jobState); err != nil {
		return false, tx.Commit(ctx)
	}

	if _, err := tx.Exec(ctx, `
		update jobs set state = $2, result_status = $3, result_error_code = $4,
		                result_message = $5, finished_at = now(), updated_at = now()
		where id = $1`,
		jobID, string(jobState), result.Status,
		nullable(result.ErrorCode), nullable(result.Message)); err != nil {
		return false, err
	}
	return true, tx.Commit(ctx)
}

// ReclaimExpiredLeases returns tasks whose lease expired to the queue. A
// gateway can disappear without closing its session, so time is the only
// certain signal that an attempt failed.
func (s *Store) ReclaimExpiredLeases(ctx context.Context) (int, error) {
	const query = `
		with expired as (
			select a.id as attempt_id, a.job_id
			from job_attempts a
			join jobs j on j.id = a.job_id
			where a.finished_at is null
			  and a.lease_expires_at is not null
			  and a.lease_expires_at < now()
			  and j.state in ('leased', 'dispatched', 'running')
			for update of a skip locked
		),
		closed as (
			update job_attempts set finished_at = now(), status = 'lease_expired',
			                        lease_expires_at = null
			where id in (select attempt_id from expired)
			returning job_id
		)
		update jobs set state = 'queued', updated_at = now()
		where id in (select job_id from closed)
		returning id`
	rows, err := s.pool.Query(ctx, query)
	if err != nil {
		return 0, err
	}
	defer rows.Close()
	count := 0
	for rows.Next() {
		count++
	}
	return count, rows.Err()
}

// ExpireOverdue marks the tasks that exceeded their TTL before starting.
func (s *Store) ExpireOverdue(ctx context.Context) (int, error) {
	const query = `
		update jobs set state = 'expired', result_status = 'expired',
		                finished_at = now(), updated_at = now()
		where state in ('planned', 'awaiting_approval', 'queued')
		  and expires_at <= now()
		returning id`
	rows, err := s.pool.Query(ctx, query)
	if err != nil {
		return 0, err
	}
	defer rows.Close()
	count := 0
	for rows.Next() {
		count++
	}
	return count, rows.Err()
}

// Get returns a task.
func (s *Store) Get(ctx context.Context, jobID string) (*Job, error) {
	return s.getPool(ctx, "where id = $1", jobID)
}

// ListFilter describes the filters of a task list.
type ListFilter struct {
	HostID string
	State  string
	Limit  int
	// Scopes narrow the result to the scopes in which the caller has the
	// right to read. An empty list narrows nothing; an empty scope inside the
	// list means a global permission.
	Scopes []Scope
}

// Scope is a site-environment pair. An empty field means "any".
type Scope struct {
	Site        string
	Environment string
}

// List returns the tasks matching the filter.
func (s *Store) List(ctx context.Context, filter ListFilter) ([]Job, error) {
	clause := "where 1 = 1"
	args := []any{}
	// A task belongs to a host, so it inherits visibility from it: the
	// operator of one environment must not see the tasks of the whole
	// fleet.
	if len(filter.Scopes) > 0 {
		translated := make([]authz.Scope, 0, len(filter.Scopes))
		for _, scope := range filter.Scopes {
			translated = append(translated, authz.Scope{Site: scope.Site, Environment: scope.Environment})
		}
		if condition, extra := authz.ScopeSQL(translated, "h.site", "h.environment", len(args)); condition != "" {
			clause += " and exists (select 1 from hosts h where h.id = jobs.host_id and " + condition + ")"
			args = append(args, extra...)
		}
	}
	if filter.HostID != "" {
		args = append(args, filter.HostID)
		clause += fmt.Sprintf(" and host_id = $%d", len(args))
	}
	if filter.State != "" {
		args = append(args, filter.State)
		clause += fmt.Sprintf(" and state = $%d", len(args))
	}
	limit := filter.Limit
	if limit <= 0 || limit > 500 {
		limit = 100
	}
	args = append(args, limit)
	clause += fmt.Sprintf(" order by created_at desc limit $%d", len(args))

	return s.queryJobs(ctx, s.pool, clause, args...)
}

// Attempts returns the attempts at carrying out a task.
func (s *Store) Attempts(ctx context.Context, jobID string) ([]Attempt, error) {
	const query = `
		select id, job_id, attempt_number, coalesce(gateway_id, ''), session_id,
		       coalesce(status, ''), exit_code, coalesce(error_code, ''), coalesce(message, ''),
		       coalesce(stdout, ''), coalesce(stderr, ''), output_truncated, replayed,
		       unit_state_before, unit_state_after, result_detail,
		       dispatched_at, finished_at, created_at
		from job_attempts
		where job_id = $1
		order by attempt_number`
	rows, err := s.pool.Query(ctx, query, jobID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var attempts []Attempt
	for rows.Next() {
		var a Attempt
		if err := rows.Scan(&a.ID, &a.JobID, &a.Number, &a.GatewayID, &a.SessionID,
			&a.Status, &a.ExitCode, &a.ErrorCode, &a.Message,
			&a.Stdout, &a.Stderr, &a.OutputTruncated, &a.Replayed,
			&a.UnitStateBefore, &a.UnitStateAfter, &a.Detail,
			&a.DispatchedAt, &a.FinishedAt, &a.CreatedAt); err != nil {
			return nil, err
		}
		attempts = append(attempts, a)
	}
	return attempts, rows.Err()
}

type queryable interface {
	Query(ctx context.Context, sql string, args ...any) (pgx.Rows, error)
}

func (s *Store) getPool(ctx context.Context, clause string, args ...any) (*Job, error) {
	return s.getFrom(ctx, s.pool, clause, args...)
}

func (s *Store) getTx(ctx context.Context, tx pgx.Tx, clause string, args ...any) (*Job, error) {
	return s.getFrom(ctx, tx, clause, args...)
}

func (s *Store) getFrom(ctx context.Context, q queryable, clause string, args ...any) (*Job, error) {
	found, err := s.queryJobs(ctx, q, clause+" limit 1", args...)
	if err != nil {
		return nil, err
	}
	if len(found) == 0 {
		return nil, ErrNotFound
	}
	return &found[0], nil
}

func (s *Store) queryJobs(ctx context.Context, q queryable, clause string, args ...any) ([]Job, error) {
	query := `
		select id, host_id, campaign_id, action_type, action_version, payload,
		       encode(payload_hash, 'hex'), idempotency_key, state, requires_approval,
		       preconditions, timeout_seconds, max_output_bytes, expires_at,
		       created_by, coalesce(request_id, ''), coalesce(approved_by, ''), approved_at,
		       coalesce(canceled_by, ''), coalesce(cancel_reason, ''),
		       coalesce(result_status, ''), coalesce(result_error_code, ''),
		       coalesce(result_message, ''), finished_at, created_at, updated_at,
		       required_approvals,
		       (select count(*) from job_approvals a where a.job_id = jobs.id)
		from jobs ` + clause

	rows, err := q.Query(ctx, query, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var jobs []Job
	for rows.Next() {
		var j Job
		var collected int
		if err := rows.Scan(&j.ID, &j.HostID, &j.CampaignID, &j.ActionType, &j.ActionVersion,
			&j.Payload, &j.PayloadHash, &j.IdempotencyKey, &j.State, &j.RequiresApproval,
			&j.Preconditions, &j.TimeoutSeconds, &j.MaxOutputBytes, &j.ExpiresAt,
			&j.CreatedBy, &j.RequestID, &j.ApprovedBy, &j.ApprovedAt,
			&j.CanceledBy, &j.CancelReason, &j.ResultStatus, &j.ResultErrorCode,
			&j.ResultMessage, &j.FinishedAt, &j.CreatedAt, &j.UpdatedAt,
			&j.RequiredApprovals, &collected); err != nil {
			return nil, err
		}
		// Every view of a task carries the number of collected approvals:
		// without it the operator clicks "approve" and does not know why
		// nothing happened.
		j.CollectedApprovals = collected
		jobs = append(jobs, j)
	}
	return jobs, rows.Err()
}

func nullable(value string) any {
	if value == "" {
		return nil
	}
	return value
}

func nullableUUID(value string) any {
	if value == "" {
		return nil
	}
	return value
}

func nullableJSON(value json.RawMessage) any {
	if len(value) == 0 {
		return nil
	}
	return []byte(value)
}

// AttemptOwner returns the task an attempt belongs to. The agent sends the
// result back with the attempt identifier, so the gateway has to find the
// job.
func (s *Store) AttemptOwner(ctx context.Context, attemptID string) (jobID, action string, err error) {
	err = s.pool.QueryRow(ctx, `
		select a.job_id, j.action_type
		  from job_attempts a join jobs j on j.id = a.job_id
		 where a.id = $1`, attemptID).Scan(&jobID, &action)
	if errors.Is(err, pgx.ErrNoRows) {
		return "", "", ErrNotFound
	}
	return jobID, action, err
}

// LastAttempt returns the identifier of the operation's last attempt. An
// empty one means an operation that has not been delivered yet - there is
// then nothing to interrupt on the host.
func (s *Store) LastAttempt(ctx context.Context, jobID string) (string, error) {
	var attemptID string
	err := s.pool.QueryRow(ctx, `
		select id from job_attempts
		 where job_id = $1
		 order by attempt_number desc
		 limit 1`, jobID).Scan(&attemptID)
	if errors.Is(err, pgx.ErrNoRows) {
		return "", nil
	}
	return attemptID, err
}

// AttemptContext returns the attempt's operation together with its campaign.
// Progress ordered in a campaign has to reach the campaign screen as well,
// and the agent knows only the attempt identifier.
func (s *Store) AttemptContext(ctx context.Context, attemptID string) (jobID, campaignID string, err error) {
	var campaign *string
	err = s.pool.QueryRow(ctx, `
		select a.job_id, j.campaign_id::text
		  from job_attempts a join jobs j on j.id = a.job_id
		 where a.id = $1`, attemptID).Scan(&jobID, &campaign)
	if errors.Is(err, pgx.ErrNoRows) {
		return "", "", ErrNotFound
	}
	if campaign != nil {
		campaignID = *campaign
	}
	return jobID, campaignID, err
}
