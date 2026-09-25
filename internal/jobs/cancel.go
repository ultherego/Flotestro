package jobs

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/ultherego/flotestro/internal/outbox"
)

// The cancel protocol of a task the host holds.

// The outcomes the agent answers a cancel with, as they are stored on the job.
// They are the names of CancelAck.
const (
	// CancelOutcomeNotStarted: the task had not begun on the host and
	// will not; the job is canceled.
	CancelOutcomeNotStarted = "not_started"
	// CancelOutcomeInterrupted: the task was under way in a phase the agent may
	// cut short, and was; the job is canceled, and the host's own account of the
	// interrupted work follows as an unapplied result.
	CancelOutcomeInterrupted = "interrupted"
	// CancelOutcomeNotInterruptible: the task is in a phase that must
	// run to its end; the job is running again and its result settles it.
	CancelOutcomeNotInterruptible = "not_interruptible"
	// CancelOutcomeAlreadyDone: the host's journal holds the result; the
	// job keeps waiting for it, or has it already.
	CancelOutcomeAlreadyDone = "already_done"
)

// KnownCancelOutcome says whether the word is one of the four outcomes.
func KnownCancelOutcome(outcome string) bool {
	switch outcome {
	case CancelOutcomeNotStarted, CancelOutcomeInterrupted, CancelOutcomeNotInterruptible, CancelOutcomeAlreadyDone:
		return true
	default:
		return false
	}
}

// CancelAckTimeoutCode is the error code of a job whose cancel request got no
// answer within the operation's timeout.
const CancelAckTimeoutCode = "cancel_ack_timeout"

// ResultStatusUnknown is the result status of a job settled without a result
// from the host - by the cancel sweep.
const ResultStatusUnknown = "unknown_needs_reconciliation"

// EventCancelRequested is the type of the trail event a cancel request leaves.
const EventCancelRequested = "job.cancel_requested"

// CancelRequest is a cancel the host has not answered yet: what the relay
// sends to the agent.
type CancelRequest struct {
	JobID      string
	HostID     string
	CampaignID string
	// AttemptID is the delivery the request is about - the attempt the agent
	// knows the task by - and Revision its number, which the request carries as
	// its revision.
	AttemptID string
	Revision  uint64
	Reason    string
	// RequestedAt and Deadline bound the wait: the deadline is the
	// request plus the operation's timeout.
	RequestedAt time.Time
	Deadline    time.Time
}

// requestCancel moves a dispatched or running job to cancel_requested and
// records the request on the trail, inside the caller's transaction.
func requestCancel(ctx context.Context, tx pgx.Tx, jobID, actor, reason string) error {
	var hostID, campaignID, attemptID string
	var revision int64
	var deadline time.Time
	err := tx.QueryRow(ctx, `
		update jobs j
		   set state = $2, canceled_by = $3, cancel_reason = $4,
		       cancel_requested_at = now(), updated_at = now(),
		       -- A new request is not the old one: the answer to the previous
		       -- one goes, or the relay would take this job for answered.
		       cancel_revision = j.cancel_revision + 1,
		       cancel_ack_at = null, cancel_outcome = null, cancel_phase = null
		  from (select a.id, a.attempt_number from job_attempts a
		         where a.job_id = $1 order by a.attempt_number desc limit 1) last
		 where j.id = $1
		returning j.host_id::text, coalesce(j.campaign_id::text, ''), last.id::text,
		          j.cancel_revision, now() + make_interval(secs => j.timeout_seconds)`,
		jobID, string(StateCancelRequested), actor, nullable(reason)).
		Scan(&hostID, &campaignID, &attemptID, &revision, &deadline)
	if errors.Is(err, pgx.ErrNoRows) {
		// A dispatched job without an attempt is a row somebody edited by
		// hand; there is no delivery to ask the host about.
		return ErrConflict
	}
	if err != nil {
		return fmt.Errorf("recording the cancel request: %w", err)
	}
	return outbox.Record(ctx, tx, "job", jobID, EventCancelRequested, map[string]any{
		"host_id":          hostID,
		"campaign_id":      campaignID,
		"attempt_id":       attemptID,
		"request_revision": revision,
		"requested_by":     actor,
		"reason":           reason,
		"deadline_unix":    deadline.Unix(),
	})
}

// RequestCancelOf asks the hosts carrying the tasks of a campaign to stop:
// every dispatched or running task of the campaign not named in keep moves to
// cancel_requested, with a request on the trail for each.
func RequestCancelOf(ctx context.Context, tx pgx.Tx, campaignID, actor, reason string,
	keep []string) ([]string, error) {
	if keep == nil {
		keep = []string{}
	}
	held, err := collectIDs(tx.Query(ctx, `
		select id::text from jobs
		 where campaign_id = $1::uuid
		   and state in ('dispatched', 'running')
		   and not (id::text = any($2::text[]))
		 order by created_at
		 for update`, campaignID, keep))
	if err != nil {
		return nil, err
	}
	for _, jobID := range held {
		if err := requestCancel(ctx, tx, jobID, actor, reason); err != nil {
			return nil, err
		}
	}
	return held, nil
}

// PendingCancels lists the cancel requests of the given hosts that no
// acknowledgement has answered yet.
func (s *Store) PendingCancels(ctx context.Context, hostIDs []string) ([]CancelRequest, error) {
	if len(hostIDs) == 0 {
		return nil, nil
	}
	rows, err := s.pool.Query(ctx, `
		select j.id::text, j.host_id::text, coalesce(j.campaign_id::text, ''),
		       coalesce(last.id::text, ''), j.cancel_revision,
		       coalesce(j.cancel_reason, ''), j.cancel_requested_at,
		       j.cancel_requested_at + make_interval(secs => j.timeout_seconds)
		  from jobs j
		  left join lateral (select a.id, a.attempt_number from job_attempts a
		                      where a.job_id = j.id order by a.attempt_number desc limit 1) last on true
		 where j.state = $1 and j.cancel_ack_at is null
		   and j.host_id = any($2::uuid[])
		 order by j.cancel_requested_at`,
		string(StateCancelRequested), hostIDs)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var pending []CancelRequest
	for rows.Next() {
		var request CancelRequest
		var revision int64
		if err := rows.Scan(&request.JobID, &request.HostID, &request.CampaignID,
			&request.AttemptID, &revision, &request.Reason,
			&request.RequestedAt, &request.Deadline); err != nil {
			return nil, err
		}
		if revision > 0 {
			request.Revision = uint64(revision)
		}
		pending = append(pending, request)
	}
	return pending, rows.Err()
}

// ErrCancelAckStale means an acknowledgement of a cancel request the panel has
// already replaced: the host answered the question it was asked, and the
// question moved. The answer goes on the trail and settles nothing.
var ErrCancelAckStale = errors.New("cancel_ack_stale: the answer names a cancel request that was replaced")

// CancelSettlement says what an acknowledgement did to the job.
type CancelSettlement struct {
	JobID      string
	CampaignID string
	// Previous is the state the job was in when the answer arrived, and State the
	// one it is in now.
	Previous State
	State    State
}

// RecordCancelAck records the agent's answer to a cancel request and settles
// the job by it.
func (s *Store) RecordCancelAck(ctx context.Context, jobID string, revision uint64,
	outcome, phase string, fence Fence) (CancelSettlement, error) {
	if !KnownCancelOutcome(outcome) {
		return CancelSettlement{}, fmt.Errorf("%w: unknown cancel outcome %q", ErrConflict, outcome)
	}
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return CancelSettlement{}, err
	}
	defer func() { _ = tx.Rollback(ctx) }()

	// Settling a job and freeing its budget is the owner's to do, exactly as
	// recording a result is: a session that no longer owns the host does not
	// get to say what became of its tasks.
	if err := fenceHolds(ctx, tx, jobID, fence); err != nil {
		return CancelSettlement{}, err
	}

	settlement := CancelSettlement{JobID: jobID}
	var previous string
	var current int64
	err = tx.QueryRow(ctx, `
		update jobs
		   set cancel_ack_at = coalesce(cancel_ack_at, now()),
		       cancel_outcome = coalesce(cancel_outcome, $2),
		       cancel_phase = coalesce(cancel_phase, $3),
		       updated_at = now()
		 where id = $1 and cancel_revision = $4
		returning state, coalesce(campaign_id::text, ''), cancel_revision`,
		jobID, outcome, nullable(phase), int64(revision)).
		Scan(&previous, &settlement.CampaignID, &current)
	if errors.Is(err, pgx.ErrNoRows) {
		// Either there is no such job, or the answer names a request the panel
		// has already replaced. The second is not an error of the host: it
		// answered the question it was asked, and the question moved.
		var known bool
		if scanErr := tx.QueryRow(ctx, `select true from jobs where id = $1`, jobID).Scan(&known); scanErr != nil {
			return CancelSettlement{}, ErrNotFound
		}
		return CancelSettlement{JobID: jobID}, ErrCancelAckStale
	}
	if err != nil {
		return CancelSettlement{}, err
	}
	settlement.Previous = State(previous)
	settlement.State = settlement.Previous
	if settlement.Previous != StateCancelRequested {
		return settlement, tx.Commit(ctx)
	}

	switch outcome {
	case CancelOutcomeNotStarted, CancelOutcomeInterrupted:
		if err := StateCancelRequested.Validate(StateCanceled); err != nil {
			return settlement, err
		}
		// The host holds nothing it will finish: the job is canceled and the
		// capacity is free.
		message := "the host acknowledged the cancel: " + outcome
		if phase != "" {
			message += " while " + phase
		}
		if _, err := tx.Exec(ctx, `
			update jobs set state = $2, result_status = 'canceled', result_message = $3,
			                canceled_at = coalesce(canceled_at, now()),
			                wait_reason = '', finished_at = now(), updated_at = now()
			 where id = $1`, jobID, string(StateCanceled), message); err != nil {
			return settlement, err
		}
		if err := releaseBudgets(ctx, tx, jobID); err != nil {
			return settlement, err
		}
		settlement.State = StateCanceled
	case CancelOutcomeNotInterruptible:
		if err := StateCancelRequested.Validate(StateRunning); err != nil {
			return settlement, err
		}
		if _, err := tx.Exec(ctx, `
			update jobs set state = $2, updated_at = now() where id = $1`,
			jobID, string(StateRunning)); err != nil {
			return settlement, err
		}
		settlement.State = StateRunning
	case CancelOutcomeAlreadyDone:
		// The result settles the job; nothing to move.
	}
	return settlement, tx.Commit(ctx)
}

// OutstandingCancelRevision is the revision of the cancel request the job is
// waiting for an answer to. Zero when there is none, which makes the answer of
// an agent that names no revision land on nothing.
func (s *Store) OutstandingCancelRevision(ctx context.Context, jobID string) uint64 {
	var revision int64
	if err := s.pool.QueryRow(ctx,
		`select cancel_revision from jobs where id = $1`, jobID).Scan(&revision); err != nil {
		return 0
	}
	if revision < 0 {
		return 0
	}
	return uint64(revision)
}

// SettleCancelTimeouts ends the cancel requests nobody answered in time: the
// job fails with an unknown outcome and its budget tokens go back.
func (s *Store) SettleCancelTimeouts(ctx context.Context) ([]string, error) {
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return nil, err
	}
	defer func() { _ = tx.Rollback(ctx) }()
	const message = "the host did not acknowledge the cancel within the operation's timeout; " +
		"the outcome on the host is unknown - read the host before ordering again"
	settled, err := collectIDs(tx.Query(ctx, `
		with overdue as (
			select id from jobs
			 where state = $1
			   and cancel_requested_at + make_interval(secs => timeout_seconds) < now()
			 for update skip locked),
		closed as (
			update job_attempts a
			   set finished_at = now(), status = 'failed', error_code = $2, message = $3,
			       lease_expires_at = null
			  from overdue o
			 where a.job_id = o.id and a.finished_at is null
			returning a.job_id)
		update jobs j
		   set state = 'failed', result_status = $4, result_error_code = $2, result_message = $3,
		       wait_reason = '', finished_at = now(), updated_at = now()
		  from overdue o
		 where j.id = o.id
		returning j.id::text`,
		string(StateCancelRequested), CancelAckTimeoutCode, message, ResultStatusUnknown))
	if err != nil {
		return nil, err
	}
	if err := releaseBudgets(ctx, tx, settled...); err != nil {
		return nil, err
	}
	return settled, tx.Commit(ctx)
}
