package jobs

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/ultherego/flotestro/internal/authz"
	"github.com/ultherego/flotestro/internal/budgets"
	"github.com/ultherego/flotestro/internal/metrics"
	"github.com/ultherego/flotestro/internal/opspec"
	"github.com/ultherego/flotestro/internal/paging"
)

var (
	// ErrNotFound means there is no job with the given identifier.
	ErrNotFound = errors.New("the task does not exist")
	// ErrConflict means an attempt at a transition forbidden in this state.
	ErrConflict = errors.New("the operation is not allowed in the current state of the task")
	// ErrSessionStale means a delivery over a session that is no longer the
	// host's open one: another gateway took the host over between the send and
	// the record.
	ErrSessionStale = errors.New("session_stale: the session is no longer the open session of the host")
)

// Spec describes the task to create.
type Spec struct {
	HostID           string
	Action           opspec.ActionType
	Payload          opspec.Payload
	IdempotencyKey   string
	RequiresApproval bool
	// RequiredApprovals says how many people are needed.
	RequiredApprovals int
	TimeoutSeconds    int
	MaxOutputBytes    int
	TTL               time.Duration
	CreatedBy         string
	RequestID         string
	// CampaignID binds the operation to the rollout that ordered it.
	CampaignID string
	// FanoutID binds the operation to the diagnostic read fan-out that ordered
	// it, for the same reason: the fan-out page lists its jobs by it, and the
	// result of every host is read from its own job.
	FanoutID      string
	Preconditions Preconditions
	// Class is the urgency the job asks for capacity with, when the order stated
	// one.
	Class budgets.Class
}

// Preconditions are checked by the agent right before execution.
type Preconditions struct {
	OSFamily             string   `json:"os_family,omitempty"`
	RequiredCapabilities []string `json:"required_capabilities,omitempty"`
	ExpectedBootID       string   `json:"expected_boot_id,omitempty"`
}

// Job is the view of a task returned by the API.
type Job struct {
	ID     string `json:"id"`
	HostID string `json:"host_id"`
	// Hostname is read with the task for the lists: a host is known by its
	// name, and a list of identifiers tells nobody anything.
	Hostname         string          `json:"hostname,omitempty"`
	CampaignID       *string         `json:"campaign_id,omitempty"`
	FanoutID         *string         `json:"fanout_id,omitempty"`
	ActionType       string          `json:"action_type"`
	ActionVersion    int             `json:"action_version"`
	Payload          json.RawMessage `json:"payload"`
	PayloadHash      string          `json:"payload_hash"`
	IdempotencyKey   string          `json:"idempotency_key"`
	State            State           `json:"state"`
	RequiresApproval bool            `json:"requires_approval"`
	// RequiredApprovals and Approvals say how many approvals are needed and how
	// many there already are.
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
	// CancelRequestedAt is when a cancel was asked of the host holding the task;
	// CancelAckAt, CancelOutcome and CancelPhase are the agent's answer - what
	// the request found on the host and what the host was doing.
	CancelRequestedAt *time.Time `json:"cancel_requested_at,omitempty"`
	CancelAckAt       *time.Time `json:"cancel_ack_at,omitempty"`
	CancelOutcome     string     `json:"cancel_outcome,omitempty"`
	CancelPhase       string     `json:"cancel_phase,omitempty"`
	// WaitReason says why a job has not started yet: the budget a queued job
	// waits for, as awaiting_budget:<key>, or the resource lock a delivered job
	// waits for on its host, as awaiting_lock:<blocker>.
	WaitReason string `json:"wait_reason,omitempty"`
	// BudgetClass is the class the order stated; empty means it was left
	// to the scheduler to derive.
	BudgetClass     string     `json:"budget_class,omitempty"`
	ResultStatus    string     `json:"result_status,omitempty"`
	ResultErrorCode string     `json:"result_error_code,omitempty"`
	ResultMessage   string     `json:"result_message,omitempty"`
	FinishedAt      *time.Time `json:"finished_at,omitempty"`
	CreatedAt       time.Time  `json:"created_at"`
	UpdatedAt       time.Time  `json:"updated_at"`
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
	// Verification is the read of the host after the change, as the host reported
	// it: {verifier, verified, expected, observed, reason}.
	Verification json.RawMessage `json:"verification,omitempty"`
	DispatchedAt *time.Time      `json:"dispatched_at,omitempty"`
	// AcceptedAt is when the agent said it holds the task, and StartedAt when it
	// said the operation is starting on the host.
	AcceptedAt *time.Time `json:"accepted_at,omitempty"`
	StartedAt  *time.Time `json:"started_at,omitempty"`
	FinishedAt *time.Time `json:"finished_at,omitempty"`
	CreatedAt  time.Time  `json:"created_at"`
}

// DispatchLease is how long the panel waits for the agent to say it holds a
// task after the envelope went out.
const DispatchLease = 60 * time.Second

// WaitReasonLockPrefix marks a wait reason that names a resource lock of the
// host, as awaiting_lock:<blocker>.
const WaitReasonLockPrefix = "awaiting_lock:"

// LockWaitReason renders the wait reason of a job whose task waits for a
// resource of its host.
func LockWaitReason(blocker string) string {
	return WaitReasonLockPrefix + blocker
}

// LockBlocker reads the blocker back out of a wait reason.
func LockBlocker(reason string) (string, bool) {
	if !strings.HasPrefix(reason, WaitReasonLockPrefix) {
		return "", false
	}
	return strings.TrimPrefix(reason, WaitReasonLockPrefix), true
}

// Store provides access to the task tables.
type Store struct {
	pool *pgxpool.Pool
}

func NewStore(pool *pgxpool.Pool) *Store {
	return &Store{pool: pool}
}

func (s *Store) Pool() *pgxpool.Pool { return s.pool }

// Create creates a task together with the plan hash.
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
		                  campaign_id, required_approvals, fanout_id, budget_class)
		values ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15,
		        nullif($16, '')::uuid, $17, nullif($18, '')::uuid, $19)
		on conflict (host_id, idempotency_key) do nothing
		returning id`
	jobID := uuid.NewString()
	err = tx.QueryRow(ctx, query, jobID, spec.HostID, string(spec.Action), opspec.ActionVersion,
		payloadJSON, payloadHash, idempotencyKey, string(state), spec.RequiresApproval,
		preconditionsJSON, timeout, maxOutput, time.Now().Add(ttl),
		spec.CreatedBy, nullable(spec.RequestID), spec.CampaignID, requiredApprovals(spec),
		spec.FanoutID, string(spec.Class)).Scan(&jobID)
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

// Approve records an approval and lets the task through once it has collected
// enough of them.
func (s *Store) Approve(ctx context.Context, tx pgx.Tx, jobID, actor, reason string) (*Job, error) {
	const recordApproval = `
		insert into job_approvals (job_id, approver, reason)
		values ($1, $2, $3)
		on conflict (job_id, approver) do nothing`
	if _, err := tx.Exec(ctx, recordApproval, jobID, actor, nullable(reason)); err != nil {
		return nil, err
	}

	// The same person does not count twice: the table's primary key guards that
	// in the database rather than in code, which can be bypassed by another path.
	const query = `
		update jobs set state = $2, approved_by = $3, approved_at = now(), updated_at = now()
		where id = $1 and state = $4
		  and (select count(*) from job_approvals where job_id = $1) >= required_approvals
		returning id`
	var updated string
	err := tx.QueryRow(ctx, query, jobID, string(StateQueued), actor, string(StateAwaitingApproval)).Scan(&updated)
	if errors.Is(err, pgx.ErrNoRows) {
		// The task stays waiting: either approvals are missing, or somebody changed
		// its state in the meantime.
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
	return s.approvalsFrom(ctx, s.pool, jobID)
}

// ApprovalsTx returns the approvals as the caller's transaction sees them: an
// approval written a moment ago in the same transaction is on the list, which
// a read through the pool would not show yet.
func (s *Store) ApprovalsTx(ctx context.Context, tx pgx.Tx, jobID string) ([]Approval, error) {
	return s.approvalsFrom(ctx, tx, jobID)
}

func (s *Store) approvalsFrom(ctx context.Context, q queryable, jobID string) ([]Approval, error) {
	const query = `
		select approver, coalesce(reason, ''), approved_at
		from job_approvals where job_id = $1 order by approved_at`
	rows, err := q.Query(ctx, query, jobID)
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
	var state string
	err := tx.QueryRow(ctx, `select state from jobs where id = $1 for update`, jobID).Scan(&state)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, err
	}
	switch State(state) {
	case StatePlanned, StateAwaitingApproval, StateQueued, StateLeased:
		if _, err := tx.Exec(ctx, `
			update jobs set state = $2, canceled_by = $3, canceled_at = now(),
			                cancel_reason = $4, wait_reason = '', finished_at = now(), updated_at = now()
			where id = $1`,
			jobID, string(StateCanceled), actor, nullable(reason)); err != nil {
			return nil, err
		}
		if err := releaseBudgets(ctx, tx, jobID); err != nil {
			return nil, err
		}
	case StateDispatched, StateRunning:
		if err := requestCancel(ctx, tx, jobID, actor, reason); err != nil {
			return nil, err
		}
	default:
		return nil, ErrConflict
	}
	return s.getTx(ctx, tx, "where id = $1", jobID)
}

// CancelUndelivered ends the host's tasks that have not started yet.
func (s *Store) CancelUndelivered(ctx context.Context, tx pgx.Tx, hostID, actor,
	reason string) (int, error) {
	const query = `
		update jobs set state = $2, canceled_by = $3, canceled_at = now(),
		                cancel_reason = $4, wait_reason = '', finished_at = now(), updated_at = now()
		where host_id = $1::uuid
		  and state in ('planned', 'awaiting_approval', 'queued', 'leased')
		returning id`
	canceled, err := collectIDs(tx.Query(ctx, query, hostID, string(StateCanceled), actor, nullable(reason)))
	if err != nil {
		return 0, err
	}
	// A leased job may already hold budget tokens; a canceled one holds
	// nothing.
	if err := releaseBudgets(ctx, tx, canceled...); err != nil {
		return 0, err
	}
	return len(canceled), nil
}

// OpenTasksOfAction returns the host's unfinished tasks of a given action
// together with their last attempt and payload.
func (s *Store) OpenTasksOfAction(ctx context.Context, hostID,
	action string) ([]OpenTask, error) {
	const query = `
		select j.id::text, coalesce(a.id::text, ''), j.payload, coalesce(s.boot_id, '')
		from jobs j
		left join lateral (
			select id, session_id from job_attempts where job_id = j.id
			order by attempt_number desc limit 1
		) a on true
		left join agent_sessions s on s.id = a.session_id
		where j.host_id = $1::uuid and j.action_type = $2
		  and j.state in ('queued', 'leased', 'dispatched', 'running', 'cancel_requested')
		order by j.created_at`
	rows, err := s.pool.Query(ctx, query, hostID, action)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var tasks []OpenTask
	for rows.Next() {
		var task OpenTask
		if err := rows.Scan(&task.JobID, &task.AttemptID, &task.Payload, &task.SessionBootID); err != nil {
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
	// SessionBootID is the boot identifier of the host in the session that
	// carried the last attempt out - the boot the operation was ordered under.
	SessionBootID string
}

// LeasedJob joins a task with the attempt carrying it out.
type LeasedJob struct {
	Job       Job
	AttemptID string
	Attempt   int
}

// Candidate is a queued task the scheduler weighs before taking it, together
// with the site of its host: the site is what the budgets are keyed by, and
// the task itself does not carry it.
type Candidate struct {
	Job  Job
	Site string
}

// Queued lists the tasks ready to run on the given hosts, oldest first,
// without taking them.
func (s *Store) Queued(ctx context.Context, hostIDs []string, limit int) ([]Candidate, error) {
	if len(hostIDs) == 0 || limit <= 0 {
		return nil, nil
	}
	queued, err := s.queryJobs(ctx, s.pool, `
		where state = 'queued'
		  and host_id = any($1)
		  and expires_at > now()
		order by created_at
		limit $2`, hostIDs, limit)
	if err != nil {
		return nil, fmt.Errorf("listing the queued tasks: %w", err)
	}
	if len(queued) == 0 {
		return nil, nil
	}
	rows, err := s.pool.Query(ctx, `select id::text, site from hosts where id = any($1)`, hostIDs)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	sites := map[string]string{}
	for rows.Next() {
		var id, site string
		if err := rows.Scan(&id, &site); err != nil {
			return nil, err
		}
		sites[id] = site
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	candidates := make([]Candidate, 0, len(queued))
	for _, job := range queued {
		candidates = append(candidates, Candidate{Job: job, Site: sites[job.HostID]})
	}
	return candidates, nil
}

// LeaseJobs takes the given tasks, provided they are still queued, and gives
// each a lease.
func (s *Store) LeaseJobs(ctx context.Context, gatewayID string, jobIDs []string,
	leaseDuration time.Duration) ([]LeasedJob, error) {
	if len(jobIDs) == 0 {
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
		  and id = any($1)
		  and expires_at > now()
		order by created_at
		for update skip locked`
	taken, err := collectIDs(tx.Query(ctx, selectQuery, jobIDs))
	if err != nil {
		return nil, fmt.Errorf("taking the tasks: %w", err)
	}
	if len(taken) == 0 {
		return nil, tx.Commit(ctx)
	}

	leased := make([]LeasedJob, 0, len(taken))
	deadline := time.Now().Add(leaseDuration)
	for _, jobID := range taken {
		// A task that is taken no longer waits: the reason it stood in the
		// queue goes away together with the queue state.
		if _, err := tx.Exec(ctx,
			`update jobs set state = $2, wait_reason = '', updated_at = now() where id = $1`,
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

// SetWaitReason records why a queued task was not taken.
func (s *Store) SetWaitReason(ctx context.Context, jobID, reason string) error {
	_, err := s.pool.Exec(ctx, `
		update jobs set wait_reason = $2, updated_at = now()
		where id = $1 and state = 'queued' and wait_reason <> $2`, jobID, reason)
	return err
}

// InFlight lists the tasks between the lease and the result that were admitted
// one by one - the ones whose budget tokens the scheduler has to keep alive.
func (s *Store) InFlight(ctx context.Context) ([]string, error) {
	return collectIDs(s.pool.Query(ctx, `
		select id from jobs
		where state in ('leased', 'dispatched', 'running', 'cancel_requested')
		  and campaign_id is null and fanout_id is null`))
}

// MarkDispatched records handing the task over to the agent.
func (s *Store) MarkDispatched(ctx context.Context, jobID, attemptID string, fence Fence) error {
	return s.MarkDispatchedWithLease(ctx, jobID, attemptID, fence, DispatchLease)
}

// MarkDispatchedWithLease is MarkDispatched with the lease the caller chose:
// the short dispatch lease for an agent that acknowledges a task, the
// execution lease for one that never will - an agent from before the
func (s *Store) MarkDispatchedWithLease(ctx context.Context, jobID, attemptID string,
	fence Fence, lease time.Duration) error {
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback(ctx) }()

	// The delivery counts only over the host's open session.
	var openSession string
	err = tx.QueryRow(ctx, `
		select s.id::text
		  from agent_sessions s join jobs j on j.host_id = s.host_id
		 where s.id = nullif($2, '')::uuid and j.id = $1 and s.ended_at is null
		   for update of s`,
		jobID, fence.SessionID).Scan(&openSession)
	if errors.Is(err, pgx.ErrNoRows) {
		return ErrSessionStale
	}
	if err != nil {
		return err
	}
	// An open row is the session's word that it is the newest; the fence is the
	// database's word that it owns the host right now.
	if err := fenceHolds(ctx, tx, jobID, fence); err != nil {
		return err
	}

	if _, err := tx.Exec(ctx,
		`update jobs set state = $2, updated_at = now() where id = $1 and state = $3`,
		jobID, string(StateDispatched), string(StateLeased)); err != nil {
		return err
	}
	// The envelope leaves before this row is written, and a quick agent
	// acknowledges it in between: an attempt that was accepted already keeps the
	// lease the acceptance gave it, and the job stays where the acknowledgement
	if _, err := tx.Exec(ctx, `
		update job_attempts
		   set dispatched_at = now(), session_id = $2,
		       lease_expires_at = case when accepted_at is null
		                               then least(lease_expires_at, now() + make_interval(secs => $3))
		                               else lease_expires_at end
		 where id = $1`,
		attemptID, nullableUUID(fence.SessionID), lease.Seconds()); err != nil {
		return err
	}
	return tx.Commit(ctx)
}

// AcceptAttempt records the agent's word that it holds the task: the
// acceptance time goes on the attempt, once, and the lease moves out from the
// dispatch lease to the execution lease given - never back.
func (s *Store) AcceptAttempt(ctx context.Context, attemptID, hostID string,
	executionLease time.Duration) (bool, error) {
	var actionType string
	var firstAck *float64
	err := s.pool.QueryRow(ctx, `
		update job_attempts a
		   set accepted_at = coalesce(a.accepted_at, now()),
		       lease_expires_at = greatest(a.lease_expires_at, now() + make_interval(secs => $3))
		  from jobs j
		 where a.id = $1
		   and j.id = a.job_id
		   and j.host_id = $2::uuid
		   and a.finished_at is null
		   and a.lease_expires_at is not null
		   and j.state in ('leased', 'dispatched', 'running')
		returning j.action_type,
		          case when a.accepted_at = now()
		               then extract(epoch from now() - a.dispatched_at)::float8 end`,
		attemptID, hostID, executionLease.Seconds()).Scan(&actionType, &firstAck)
	if errors.Is(err, pgx.ErrNoRows) {
		return false, nil
	}
	if err != nil {
		return false, fmt.Errorf("accepting the attempt: %w", err)
	}
	// A repeated acceptance - the agent sent it twice - measures nothing: the
	// first one set the time, and now() is the same inside one statement, so the
	// case above tells the two apart.
	if firstAck != nil {
		metrics.TaskAck.Observe(*firstAck, actionType)
	}
	return true, nil
}

// SetLockWait records why a delivered task has not started: it waits for a
// resource of its host that another task holds.
func (s *Store) SetLockWait(ctx context.Context, attemptID, hostID, blocker string) error {
	reason := LockWaitReason(blocker)
	_, err := s.pool.Exec(ctx, `
		update jobs j
		   set wait_reason = $3, updated_at = now()
		  from job_attempts a
		 where a.id = $1
		   and j.id = a.job_id
		   and j.host_id = $2::uuid
		   and a.finished_at is null
		   and j.state in ('leased', 'dispatched')
		   and j.wait_reason <> $3`,
		attemptID, hostID, reason)
	if err != nil {
		return fmt.Errorf("recording the wait for the lock: %w", err)
	}
	return nil
}

// MarkRunning moves the job of an attempt from dispatched to running on the
// agent's word that the operation started on the host, stamps the start on the
// attempt and clears whatever the job was waiting on.
func (s *Store) MarkRunning(ctx context.Context, attemptID, hostID string) (bool, error) {
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return false, err
	}
	defer func() { _ = tx.Rollback(ctx) }()

	var jobID, actionType, waitReason string
	var lockWait *float64
	err = tx.QueryRow(ctx, `
		select j.id, j.action_type, j.wait_reason,
		       extract(epoch from now() - a.accepted_at)::float8
		  from job_attempts a join jobs j on j.id = a.job_id
		 where a.id = $1
		   and j.host_id = $2::uuid
		   and a.finished_at is null
		   and j.state in ('leased', 'dispatched')
		 for update of j`, attemptID, hostID).Scan(&jobID, &actionType, &waitReason, &lockWait)
	if errors.Is(err, pgx.ErrNoRows) {
		return false, nil
	}
	if err != nil {
		return false, fmt.Errorf("finding the attempt to start: %w", err)
	}
	if err := StateDispatched.Validate(StateRunning); err != nil {
		return false, err
	}
	if _, err := tx.Exec(ctx,
		`update jobs set state = $2, wait_reason = '', updated_at = now() where id = $1`,
		jobID, string(StateRunning)); err != nil {
		return false, err
	}
	if _, err := tx.Exec(ctx,
		`update job_attempts set started_at = coalesce(started_at, now()) where id = $1`,
		attemptID); err != nil {
		return false, err
	}
	if err := tx.Commit(ctx); err != nil {
		return false, err
	}
	// Only a wait the agent reported counts: the gap between acceptance and start
	// of a task that found its resources free is the budget slot and the checks,
	// not a lock.
	if _, waited := LockBlocker(waitReason); waited && lockWait != nil {
		metrics.ResourceLockWait.Observe(*lockWait, actionType)
	}
	return true, nil
}

// FailUndelivered settles a task that could not be assembled for delivery and
// never will be by trying again: the attempt is closed with the reason, the
// job fails with a typed code, and the tokens go back.
func (s *Store) FailUndelivered(ctx context.Context, jobID, attemptID, code, message string) error {
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback(ctx) }()

	if _, err := tx.Exec(ctx, `
		update job_attempts set finished_at = now(), status = 'failed', error_code = $2,
		                        message = $3, lease_expires_at = null
		where id = $1`, attemptID, code, message); err != nil {
		return err
	}
	if _, err := tx.Exec(ctx, `
		update jobs set state = 'failed', result_status = 'failed', result_error_code = $2,
		                result_message = $3, wait_reason = '', finished_at = now(), updated_at = now()
		where id = $1 and state in ('leased', 'dispatched')`,
		jobID, code, message); err != nil {
		return err
	}
	if err := releaseBudgets(ctx, tx, jobID); err != nil {
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
	// The tokens go back with the task: a host that is not there to take
	// the work must not hold capacity for it until the next attempt.
	if err := releaseBudgets(ctx, tx, jobID); err != nil {
		return err
	}
	return tx.Commit(ctx)
}

// RenewAttemptLease moves the lease of an open attempt forward on a sign of
// life from the host: a progress report or a preview line.
func (s *Store) RenewAttemptLease(ctx context.Context, attemptID, hostID string,
	extension time.Duration) (bool, error) {
	tag, err := s.pool.Exec(ctx, `
		update job_attempts a
		   set lease_expires_at = greatest(a.lease_expires_at, now() + make_interval(secs => $3))
		  from jobs j
		 where a.id = $1
		   and j.id = a.job_id
		   and j.host_id = $2::uuid
		   and a.finished_at is null
		   and a.lease_expires_at is not null
		   and j.state in ('leased', 'dispatched', 'running', 'cancel_requested')`,
		attemptID, hostID, extension.Seconds())
	if err != nil {
		return false, fmt.Errorf("renewing the lease of the attempt: %w", err)
	}
	return tag.RowsAffected() > 0, nil
}

// AttemptStatusLeaseExpired is the status of an attempt the scheduler gave up
// on: its lease ran out with no result, and the job went back to the queue.
const AttemptStatusLeaseExpired = "lease_expired"

// AttemptStatusSuperseded is the status of an open attempt closed by the
// result of an earlier attempt of the same job: the panel had given the
// earlier one up, the host had not, and its result settled the job.
const AttemptStatusSuperseded = "superseded_by_result"

// lateResultDisposition says what a result does to an attempt that already has
// a status, by that status.
func lateResultDisposition(previousStatus string) (record, supersedes bool) {
	switch previousStatus {
	case AttemptStatusSuperseded:
		return false, false
	case AttemptStatusLeaseExpired:
		return true, true
	default:
		return true, false
	}
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
	// Verification is the host's reading of itself after the change, as the
	// contract's verifier made it.
	Verification json.RawMessage
}

// RecordResult records the result of an attempt and moves the task to a final
// state.
func (s *Store) RecordResult(ctx context.Context, jobID, attemptID string,
	result Result, jobState State, fence Fence) (accepted bool, err error) {
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return false, err
	}
	defer func() { _ = tx.Rollback(ctx) }()

	var currentState State
	var actionType string
	var maxOutput int
	if err := tx.QueryRow(ctx, `select state, action_type, max_output_bytes from jobs where id = $1 for update`, jobID).
		Scan(&currentState, &actionType, &maxOutput); err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return false, ErrNotFound
		}
		return false, err
	}
	var previousStatus string
	if err := tx.QueryRow(ctx, `select coalesce(status, '') from job_attempts where id = $1 for update`,
		attemptID).Scan(&previousStatus); err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return false, ErrNotFound
		}
		return false, err
	}
	record, supersedes := lateResultDisposition(previousStatus)
	if !record {
		return false, tx.Commit(ctx)
	}

	// A final state is final: a result that arrived after a cancellation or after
	// another settlement does not undo the decision - and does not rewrite what
	// the attempt says either.
	if currentState.Terminal() || currentState.Validate(jobState) != nil {
		if previousStatus == "" {
			if _, err := tx.Exec(ctx, `
				update job_attempts set
					status = $2, exit_code = $3, error_code = $4, replayed = $5,
					message = 'the result arrived after the job was settled',
					finished_at = now(), lease_expires_at = null
				where id = $1 and finished_at is null`,
				attemptID, result.Status, result.ExitCode, nullable(result.ErrorCode),
				result.Replayed); err != nil {
				return false, err
			}
		}
		return false, tx.Commit(ctx)
	}

	// The job is open and the result would settle it: only the session that owns
	// the host may do that.
	if err := fenceHolds(ctx, tx, jobID, fence); err != nil {
		return false, err
	}

	// The agent is asked to bound its output, but the bound is the task's and
	// holds here whatever the agent sent: an agent that ignores it must not fill
	// the database with one result.
	result.Stdout, result.Stderr, result.OutputTruncated = clampOutput(
		result.Stdout, result.Stderr, result.OutputTruncated, maxOutput)

	// The time from the hand-over to the result is the agent's task duration,
	// measured here because this is the one place every result passes through.
	var elapsed *float64
	if err := tx.QueryRow(ctx, `
		update job_attempts set
			status = $2, exit_code = $3, error_code = $4, message = $5,
			stdout = $6, stderr = $7, output_truncated = $8, replayed = $9,
			unit_state_before = $10, unit_state_after = $11, result_detail = $12,
			verification = $13,
			finished_at = now(), lease_expires_at = null
		where id = $1
		returning extract(epoch from now() - dispatched_at)::float8`,
		attemptID, result.Status, result.ExitCode, nullable(result.ErrorCode), nullable(result.Message),
		string(result.Stdout), string(result.Stderr), result.OutputTruncated, result.Replayed,
		nullableJSON(result.UnitStateBefore), nullableJSON(result.UnitStateAfter),
		nullableJSON(result.Detail), nullableJSON(result.Verification)).Scan(&elapsed); err != nil {
		return false, err
	}
	if elapsed != nil {
		metrics.AgentTaskDuration.Observe(*elapsed, actionType, result.Status)
	}
	if staleReason(result.ErrorCode) {
		metrics.PlanStale.Inc(actionType, result.ErrorCode)
	}

	// The attempt was given up on, the job was delivered again, and the result of
	// the first delivery is here: the redelivered attempt has nothing left to
	// wait for.
	if supersedes {
		if _, err := tx.Exec(ctx, `
			update job_attempts
			   set finished_at = now(), status = $3, lease_expires_at = null,
			       message = 'the result arrived on the earlier attempt after its lease had expired'
			 where job_id = $1 and id <> $2 and finished_at is null`,
			jobID, attemptID, AttemptStatusSuperseded); err != nil {
			return false, err
		}
	}

	// A settled job waits on nothing: a task refused for a busy lock
	// must not keep saying it waits for the lock.
	if _, err := tx.Exec(ctx, `
		update jobs set state = $2, result_status = $3, result_error_code = $4,
		                result_message = $5, wait_reason = '', finished_at = now(), updated_at = now()
		where id = $1`,
		jobID, string(jobState), result.Status,
		nullable(result.ErrorCode), nullable(result.Message)); err != nil {
		return false, err
	}
	// A result ends the work, whatever it says: the capacity the task held
	// is free the moment the settlement is.
	if jobState.Terminal() {
		if err := releaseBudgets(ctx, tx, jobID); err != nil {
			return false, err
		}
	}
	return true, tx.Commit(ctx)
}

// clampOutput cuts the output of an attempt to the bound of its task.
func clampOutput(stdout, stderr []byte, truncated bool, limit int) ([]byte, []byte, bool) {
	if limit <= 0 || len(stdout)+len(stderr) <= limit {
		return stdout, stderr, truncated
	}
	if len(stdout) > limit {
		stdout = stdout[:limit]
	}
	if room := limit - len(stdout); len(stderr) > room {
		stderr = stderr[:room]
	}
	return stdout, stderr, true
}

// staleReason says whether a refusal means the host state moved after the
// plan: the plan was right, the world changed, and the operator has to look
// again rather than retry.
func staleReason(code string) bool {
	switch code {
	case "precondition_failed", "precondition_changed", "payload_hash_mismatch", "plan_hash_mismatch", "plan_stale",
		"stale_plan", "replan_required", "plan_expired":
		return true
	}
	return false
}

// RebootReturnGrace is how much longer than its lease a restart of a host is
// waited for.
const RebootReturnGrace = 10 * time.Minute

// ReclaimExpiredLeases returns tasks whose lease expired to the queue.
func (s *Store) ReclaimExpiredLeases(ctx context.Context) (int, error) {
	const query = `
		with expired as (
			select a.id as attempt_id, a.job_id
			from job_attempts a
			join jobs j on j.id = a.job_id
			where a.finished_at is null
			  and a.lease_expires_at is not null
			  and a.lease_expires_at < case when j.action_type = $1
			                                then now() - make_interval(secs => $2)
			                                else now() end
			  and j.state in ('leased', 'dispatched', 'running')
			for update of a skip locked
		),
		closed as (
			update job_attempts set finished_at = now(), status = 'lease_expired',
			                        lease_expires_at = null
			where id in (select attempt_id from expired)
			returning job_id
		),
		settled as (
			update jobs set state = 'failed', result_status = 'failed',
			                result_error_code = $3, result_message = $4,
			                wait_reason = '', finished_at = now(), updated_at = now()
			where id in (select job_id from closed) and action_type = $1
			returning id
		),
		requeued as (
			update jobs set state = 'queued', wait_reason = '', updated_at = now()
			where id in (select job_id from closed) and action_type <> $1
			returning id
		)
		select id from settled
		union all
		select id from requeued`
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return 0, err
	}
	defer func() { _ = tx.Rollback(ctx) }()
	reclaimed, err := collectIDs(tx.Query(ctx, query,
		string(opspec.ActionSystemReboot), RebootReturnGrace.Seconds(),
		opspec.ErrorRebootNotObserved,
		"the host did not come back with a new boot identifier within the wait"))
	if err != nil {
		return 0, err
	}
	// The task asks for its tokens again when it is taken again; until then it
	// holds none, so that the capacity of a gateway that vanished comes back to
	// the fleet with the tasks.
	if err := releaseBudgets(ctx, tx, reclaimed...); err != nil {
		return 0, err
	}
	return len(reclaimed), tx.Commit(ctx)
}

// ExpireOverdue marks the tasks that exceeded their TTL before starting.
func (s *Store) ExpireOverdue(ctx context.Context) (int, error) {
	const query = `
		update jobs set state = 'expired', result_status = 'expired', wait_reason = '',
		                finished_at = now(), updated_at = now()
		where state in ('planned', 'awaiting_approval', 'queued')
		  and expires_at <= now()
		returning id`
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return 0, err
	}
	defer func() { _ = tx.Rollback(ctx) }()
	expired, err := collectIDs(tx.Query(ctx, query))
	if err != nil {
		return 0, err
	}
	// A queued task holds no tokens, but a lease that outlived a lost
	// gateway may still be on the books under its name.
	if err := releaseBudgets(ctx, tx, expired...); err != nil {
		return 0, err
	}
	return len(expired), tx.Commit(ctx)
}

// releaseBudgets gives back the budget tokens of the given tasks inside the
// caller's transaction. A task that held none is not an error.
func releaseBudgets(ctx context.Context, tx pgx.Tx, jobIDs ...string) error {
	for _, jobID := range jobIDs {
		if err := budgets.ReleaseIn(ctx, tx, budgets.JobOwner(jobID)); err != nil {
			return err
		}
	}
	return nil
}

// collectIDs reads a single-column result of identifiers.
func collectIDs(rows pgx.Rows, err error) ([]string, error) {
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var ids []string
	for rows.Next() {
		var id string
		if err := rows.Scan(&id); err != nil {
			return nil, err
		}
		ids = append(ids, id)
	}
	return ids, rows.Err()
}

// Get returns a task.
func (s *Store) Get(ctx context.Context, jobID string) (*Job, error) {
	return s.getPool(ctx, "where id = $1", jobID)
}

// ListFilter describes the filters of a task list.
type ListFilter struct {
	HostID string
	// HostnamePrefix keeps the tasks of the hosts whose name begins with it: the
	// operator knows a host by its name, and a name typed in full is a prefix of
	// itself.
	HostnamePrefix string
	State          string
	// Action keeps one operation type; ActionPrefix a family of them, by the
	// beginning of the name (packages.
	Action       string
	ActionPrefix string
	Actor        string
	CampaignID   string
	FanoutID     string
	ErrorCode    string
	// Since and Until bound the creation time; Until is exclusive.
	Since *time.Time
	Until *time.Time
	Limit int
	// Scopes narrow the result to the scopes in which the caller has the right to
	// read.
	Scopes []Scope
	// Sort is the order of the list; the zero value is the creation time,
	// newest first, the order the list always had.
	Sort Sort
}

// ErrInvalidSort means a sort a caller asked for that names no column of
// the list, or a direction that is neither asc nor desc.
var ErrInvalidSort = errors.New("invalid sort")

// Sort is the order of the task list: a column of the whitelist below and a
// direction.
type Sort struct {
	Column     string
	Descending bool
}

// ParseSort reads a sort as the API carries it: column, column:asc or
// column:desc.
func ParseSort(value string) (Sort, error) {
	value = strings.TrimSpace(value)
	if value == "" {
		return Sort{}, nil
	}
	column, direction, _ := strings.Cut(value, ":")
	if _, ok := sortColumns[column]; !ok {
		return Sort{}, fmt.Errorf("%w: %q is not a column of the task list", ErrInvalidSort, column)
	}
	switch direction {
	case "":
		return Sort{Column: column, Descending: column == "created_at"}, nil
	case "asc":
		return Sort{Column: column}, nil
	case "desc":
		return Sort{Column: column, Descending: true}, nil
	}
	return Sort{}, fmt.Errorf("%w: the direction must be asc or desc, not %q", ErrInvalidSort, direction)
}

// normalized is the sort with the default spelled out.
func (s Sort) normalized() Sort {
	if s.Column == "" {
		return Sort{Column: "created_at", Descending: true}
	}
	return s
}

// String renders the sort with its direction always named, so a cursor
// carries one spelling of an order however the caller spelled it.
func (s Sort) String() string {
	s = s.normalized()
	if s.Descending {
		return s.Column + ":desc"
	}
	return s.Column + ":asc"
}

// sortColumn is one column the list can be ordered by: the SQL expression that
// carries its order, the type the cursor's value is cast back to, the
// rendering of a row's value for the cursor and the check of a value that came
type sortColumn struct {
	expression string
	kind       string
	key        func(Job) string
	valid      func(string) bool
}

// sortColumns are the columns the task list can be ordered by.
var sortColumns = map[string]sortColumn{
	"created_at": {
		"created_at", "timestamptz", func(j Job) string { return paging.FormatTime(j.CreatedAt) }, validTimeKey,
	},
	"finished_at": {
		"coalesce(finished_at, '-infinity'::timestamptz)", "timestamptz",
		func(j Job) string { return timeKey(j.FinishedAt) }, validTimeKey,
	},
	"state":       {"state", "text", func(j Job) string { return string(j.State) }, anyText},
	"action_type": {"action_type", "text", func(j Job) string { return j.ActionType }, anyText},
	"hostname": {
		"coalesce((select h.hostname from hosts h where h.id = jobs.host_id), '')", "text",
		func(j Job) string { return j.Hostname }, anyText,
	},
}

// SortColumns lists the columns the list can be ordered by, for the API's
// description of itself.
func SortColumns() []string {
	names := make([]string, 0, len(sortColumns))
	for name := range sortColumns {
		names = append(names, name)
	}
	sort.Strings(names)
	return names
}

func anyText(string) bool { return true }

// timeKey renders a timestamp the way the expression coalesces it: the
// earliest possible moment for a task that has no such moment yet.
func timeKey(at *time.Time) string {
	if at == nil {
		return "-infinity"
	}
	return paging.FormatTime(*at)
}

func validTimeKey(value string) bool {
	if value == "-infinity" {
		return true
	}
	_, err := paging.ParseTime(value)
	return err == nil
}

// Scope is a site-environment pair. An empty field means "any".
type Scope struct {
	Site        string
	Environment string
	// Team is the group of hosts a binding names instead of a site.
	Team string
}

// conditions renders the filter as SQL over the jobs table.
func (f ListFilter) conditions() ([]string, []any) {
	var (
		conditions []string
		args       []any
	)
	// A task belongs to a host, so it inherits visibility from it: the operator
	// of one environment must not see the tasks of the whole fleet.
	if len(f.Scopes) > 0 {
		translated := make([]authz.Scope, 0, len(f.Scopes))
		for _, scope := range f.Scopes {
			translated = append(translated,
				authz.Scope{Site: scope.Site, Environment: scope.Environment, Team: scope.Team})
		}
		if condition, extra := authz.ScopeSQL(translated, "h.site", "h.environment", len(args)); condition != "" {
			conditions = append(conditions,
				"exists (select 1 from hosts h where h.id = jobs.host_id and "+condition+")")
			args = append(args, extra...)
		}
	}
	add := func(column, value string) {
		if value == "" {
			return
		}
		args = append(args, value)
		conditions = append(conditions, fmt.Sprintf("%s = $%d", column, len(args)))
	}
	add("host_id", f.HostID)
	// The name is compared as a string, like the operation prefix: a hostname
	// carries dots and dashes, and an underscore typed by mistake must not turn
	// into a wildcard.
	if f.HostnamePrefix != "" {
		args = append(args, f.HostnamePrefix)
		conditions = append(conditions, fmt.Sprintf(
			"exists (select 1 from hosts h where h.id = jobs.host_id and left(h.hostname, length($%d)) = $%d)",
			len(args), len(args)))
	}
	add("state", f.State)
	add("action_type", f.Action)
	// The prefix is compared as a string, not as a pattern: an operation
	// name carries dots and underscores, which a LIKE would read as its own.
	if f.ActionPrefix != "" {
		args = append(args, f.ActionPrefix)
		conditions = append(conditions, fmt.Sprintf("left(action_type, length($%d)) = $%d", len(args), len(args)))
	}
	add("created_by", f.Actor)
	add("campaign_id", f.CampaignID)
	add("fanout_id", f.FanoutID)
	add("result_error_code", f.ErrorCode)
	if f.Since != nil {
		args = append(args, *f.Since)
		conditions = append(conditions, fmt.Sprintf("created_at >= $%d", len(args)))
	}
	if f.Until != nil {
		args = append(args, *f.Until)
		conditions = append(conditions, fmt.Sprintf("created_at < $%d", len(args)))
	}
	return conditions, args
}

// List returns the tasks matching the filter, in the order of its Sort -
// newest first by default.
func (s *Store) List(ctx context.Context, filter ListFilter) ([]Job, error) {
	page, err := s.ListPaged(ctx, filter, Cursor{}, filter.Limit)
	if err != nil {
		return nil, err
	}
	return page.Items, nil
}

// Cursor is the key of the last task of the previous page: the order the page
// was read in, the value of the sorted column on that task and its identifier.
type Cursor struct {
	Sort  Sort
	Value string
	ID    string
	Set   bool
}

// ParseCursor reads a cursor issued by ListPaged. An empty value is the
// first page.
func ParseCursor(value string) (Cursor, error) {
	parts, err := paging.Decode(value, 3)
	if err != nil {
		return Cursor{}, err
	}
	if parts == nil {
		return Cursor{}, nil
	}
	order, err := ParseSort(parts[0])
	if err != nil {
		return Cursor{}, fmt.Errorf("%w: %v", paging.ErrInvalidCursor, err)
	}
	if !sortColumns[order.normalized().Column].valid(parts[1]) {
		return Cursor{}, fmt.Errorf("%w: the key %q is not a %s", paging.ErrInvalidCursor, parts[1], order.normalized().Column)
	}
	if _, err := uuid.Parse(parts[2]); err != nil {
		return Cursor{}, fmt.Errorf("%w: %v", paging.ErrInvalidCursor, err)
	}
	return Cursor{Sort: order, Value: parts[1], ID: parts[2], Set: true}, nil
}

// String renders the cursor for the next request.
func (c Cursor) String() string {
	return paging.Encode(c.Sort.String(), c.Value, c.ID)
}

// Matches says whether the cursor was issued for the given order.
func (c Cursor) Matches(order Sort) bool {
	return !c.Set || c.Sort.String() == order.String()
}

// ListPage is one page of the task list.
type ListPage struct {
	Items []Job `json:"items"`
	// NextCursor is empty on the last page.
	NextCursor string `json:"next_cursor,omitempty"`
}

// ListPaged reads the tasks matching the filter page by page, in the order the
// filter's Sort names - newest first by default.
func (s *Store) ListPaged(ctx context.Context, filter ListFilter, cursor Cursor, limit int) (ListPage, error) {
	if limit <= 0 || limit > 500 {
		limit = 100
	}
	order := filter.Sort.normalized()
	column, ok := sortColumns[order.Column]
	if !ok {
		return ListPage{}, fmt.Errorf("%w: %q", ErrInvalidSort, order.Column)
	}
	if !cursor.Matches(order) {
		return ListPage{}, fmt.Errorf("%w: issued for the order %s, not %s", paging.ErrInvalidCursor, cursor.Sort, order)
	}
	direction, comparison := "asc", ">"
	if order.Descending {
		direction, comparison = "desc", "<"
	}
	conditions, args := filter.conditions()
	if cursor.Set {
		// The key comes back as text and is cast to the column's type in the query,
		// so one cursor format serves a name, a state and a timestamp alike.
		args = append(args, cursor.Value, cursor.ID)
		conditions = append(conditions, fmt.Sprintf("(%s, id) %s ($%d::%s, $%d::uuid)",
			column.expression, comparison, len(args)-1, column.kind, len(args)))
	}
	clause := ""
	if len(conditions) > 0 {
		clause = "where " + strings.Join(conditions, " and ")
	}
	// One row more than the page says whether there is a next page without
	// a count over the whole table.
	args = append(args, limit+1)
	clause += fmt.Sprintf(" order by %s %s, id %s limit $%d", column.expression, direction, direction, len(args))

	items, err := s.queryJobs(ctx, s.pool, clause, args...)
	if err != nil {
		return ListPage{}, err
	}
	page := ListPage{Items: []Job{}}
	if items != nil {
		page.Items = items
	}
	if len(page.Items) > limit {
		page.Items = page.Items[:limit]
		last := page.Items[limit-1]
		page.NextCursor = Cursor{Sort: order, Value: column.key(last), ID: last.ID, Set: true}.String()
	}
	return page, nil
}

// Attempts returns the attempts at carrying out a task.
func (s *Store) Attempts(ctx context.Context, jobID string) ([]Attempt, error) {
	const query = `
		select id, job_id, attempt_number, coalesce(gateway_id, ''), session_id,
		       coalesce(status, ''), exit_code, coalesce(error_code, ''), coalesce(message, ''),
		       coalesce(stdout, ''), coalesce(stderr, ''), output_truncated, replayed,
		       unit_state_before, unit_state_after, result_detail, verification,
		       dispatched_at, accepted_at, started_at, finished_at, created_at
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
			&a.UnitStateBefore, &a.UnitStateAfter, &a.Detail, &a.Verification,
			&a.DispatchedAt, &a.AcceptedAt, &a.StartedAt, &a.FinishedAt, &a.CreatedAt); err != nil {
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
		       (select count(*) from job_approvals a where a.job_id = jobs.id),
		       coalesce((select h.hostname from hosts h where h.id = jobs.host_id), ''),
		       fanout_id, wait_reason, budget_class,
		       cancel_requested_at, cancel_ack_at, coalesce(cancel_outcome, ''), coalesce(cancel_phase, '')
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
			&j.RequiredApprovals, &collected, &j.Hostname, &j.FanoutID,
			&j.WaitReason, &j.BudgetClass,
			&j.CancelRequestedAt, &j.CancelAckAt, &j.CancelOutcome, &j.CancelPhase); err != nil {
			return nil, err
		}
		// Every view of a task carries the number of collected approvals: without it
		// the operator clicks "approve" and does not know why nothing happened.
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

// AttemptOwner returns the task an attempt belongs to, together with the
// status the attempt has right now.
func (s *Store) AttemptOwner(ctx context.Context, attemptID, hostID string) (jobID, action, status string, err error) {
	// The attempt must belong to the host that reports it: a host that learned
	// another host's attempt identifier must not settle that host's operation.
	err = s.pool.QueryRow(ctx, `
		select a.job_id, j.action_type, coalesce(a.status, '')
		  from job_attempts a join jobs j on j.id = a.job_id
		 where a.id = $1 and j.host_id = $2::uuid`, attemptID, hostID).Scan(&jobID, &action, &status)
	if errors.Is(err, pgx.ErrNoRows) {
		return "", "", "", ErrNotFound
	}
	return jobID, action, status, err
}

// LastAttempt returns the identifier of the operation's last attempt.
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
func (s *Store) AttemptContext(ctx context.Context, attemptID, hostID string) (jobID, campaignID string, err error) {
	var campaign *string
	// Bound to the reporting host for the same reason as AttemptOwner: a
	// progress line or a log line from a host is about that host's work.
	err = s.pool.QueryRow(ctx, `
		select a.job_id, j.campaign_id::text
		  from job_attempts a join jobs j on j.id = a.job_id
		 where a.id = $1 and j.host_id = $2::uuid`, attemptID, hostID).Scan(&jobID, &campaign)
	if errors.Is(err, pgx.ErrNoRows) {
		return "", "", ErrNotFound
	}
	if campaign != nil {
		campaignID = *campaign
	}
	return jobID, campaignID, err
}
