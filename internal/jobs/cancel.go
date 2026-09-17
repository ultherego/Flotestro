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
//
// A cancel of a delivered task is a question put to the host, not a state
// the panel writes on its own: the panel does not know whether the host
// has started, whether what it started can be stopped, or whether it has
// already finished and the result is on its way. The job stands
// cancel_requested with its budget tokens until the agent answers
// (CancelAck in agent.proto) or the operation's own timeout passes with
// no answer. Only then is the capacity the task held given back: a
// "canceled" written before the answer would hand the tokens of a host
// still running a transaction to the next task.

// The outcomes the agent answers a cancel with, as they are stored on the
// job. They are the names of CancelAck.Outcome in lower case, so a screen
// and the trail read the same word the protocol uses.
const (
	// CancelOutcomeNotStarted: the task had not begun on the host and
	// will not; the job is canceled.
	CancelOutcomeNotStarted = "not_started"
	// CancelOutcomeInterrupted: the task was under way in a phase the
	// agent may cut short, and was; the job is canceled, and the host's
	// own account of the interrupted work follows as an unapplied result.
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

// CancelAckTimeoutCode is the error code of a job whose cancel request got
// no answer within the operation's timeout. The outcome on the host is
// unknown: the host may have run the operation to its end, interrupted it
// or never started it, and only reading the host tells which.
const CancelAckTimeoutCode = "cancel_ack_timeout"

// ResultStatusUnknown is the result status of a job settled without a
// result from the host - by the cancel sweep. It is not a failure of the
// change and not a success: the panel does not know, and says so.
const ResultStatusUnknown = "unknown_needs_reconciliation"

// EventCancelRequested is the type of the trail event a cancel request
// leaves. The instance holding the host's session sends the request to
// the agent on it; the row on the job is what the instance reads, so a
// missed notification loses nothing.
const EventCancelRequested = "job.cancel_requested"

// CancelRequest is a cancel the host has not answered yet: what the relay
// sends to the agent.
type CancelRequest struct {
	JobID      string
	HostID     string
	CampaignID string
	// AttemptID is the delivery the request is about - the attempt the
	// agent knows the task by - and Revision its number, which the
	// request carries as its revision.
	AttemptID string
	Revision  uint64
	Reason    string
	// RequestedAt and Deadline bound the wait: the deadline is the
	// request plus the operation's timeout.
	RequestedAt time.Time
	Deadline    time.Time
}

// requestCancel moves a dispatched or running job to cancel_requested and
// records the request on the trail, inside the caller's transaction. The
// caller holds the row locked and has checked the state.
func requestCancel(ctx context.Context, tx pgx.Tx, jobID, actor, reason string) error {
	var hostID, campaignID, attemptID string
	var attemptNumber int64
	var deadline time.Time
	err := tx.QueryRow(ctx, `
		update jobs j
		   set state = $2, canceled_by = $3, cancel_reason = $4,
		       cancel_requested_at = now(), updated_at = now()
		  from (select a.id, a.attempt_number from job_attempts a
		         where a.job_id = $1 order by a.attempt_number desc limit 1) last
		 where j.id = $1
		returning j.host_id::text, coalesce(j.campaign_id::text, ''), last.id::text, last.attempt_number,
		          now() + make_interval(secs => j.timeout_seconds)`,
		jobID, string(StateCancelRequested), actor, nullable(reason)).
		Scan(&hostID, &campaignID, &attemptID, &attemptNumber, &deadline)
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
		"request_revision": attemptNumber,
		"requested_by":     actor,
		"reason":           reason,
		"deadline_unix":    deadline.Unix(),
	})
}

// RequestCancelOf asks the hosts carrying the tasks of a campaign to stop:
// every dispatched or running task of the campaign not named in keep
// moves to cancel_requested, with a request on the trail for each. The
// tasks in keep - the reboot and the verification owed to a host whose
// change landed - are left to finish, the way CancelQueuedOf leaves them.
// It returns the identifiers of the tasks asked.
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
// acknowledgement has answered yet. The relay of the instance holding a
// host's session reads its own hosts and sends the request to each; a
// request already acknowledged as already_done waits for the result and
// is not asked again.
func (s *Store) PendingCancels(ctx context.Context, hostIDs []string) ([]CancelRequest, error) {
	if len(hostIDs) == 0 {
		return nil, nil
	}
	rows, err := s.pool.Query(ctx, `
		select j.id::text, j.host_id::text, coalesce(j.campaign_id::text, ''),
		       coalesce(last.id::text, ''), coalesce(last.attempt_number, 0),
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

// CancelSettlement says what an acknowledgement did to the job.
type CancelSettlement struct {
	JobID      string
	CampaignID string
	// Previous is the state the job was in when the answer arrived, and
	// State the one it is in now. The two are equal for an answer to a
	// job that was settled already - by its result, or by the sweep.
	Previous State
	State    State
}

// RecordCancelAck records the agent's answer to a cancel request and
// settles the job by it.
//
// The first answer is the one that settled the job and the one the
// record keeps: the request may reach the host twice - from the instance
// that took the order and from the relay - and the second answer, given
// after the interruption, would read "already done" over an "interrupted"
// that was the truth of the moment. An answer that arrives for a job
// already settled is a note on the record, not a transition. The job
// moves only from cancel_requested: canceled on not_started and
// interrupted, with the tokens given back now that the host has said it
// holds nothing; back to running on not_interruptible, where the result
// settles it; nowhere on already_done, where the result is on its way or
// has arrived. An unknown outcome is refused: the panel does not guess
// what a word it does not know means for the host.
func (s *Store) RecordCancelAck(ctx context.Context, jobID, outcome, phase string) (CancelSettlement, error) {
	if !KnownCancelOutcome(outcome) {
		return CancelSettlement{}, fmt.Errorf("%w: unknown cancel outcome %q", ErrConflict, outcome)
	}
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return CancelSettlement{}, err
	}
	defer func() { _ = tx.Rollback(ctx) }()

	settlement := CancelSettlement{JobID: jobID}
	var previous string
	err = tx.QueryRow(ctx, `
		update jobs
		   set cancel_ack_at = coalesce(cancel_ack_at, now()),
		       cancel_outcome = coalesce(cancel_outcome, $2),
		       cancel_phase = coalesce(cancel_phase, $3),
		       updated_at = now()
		 where id = $1
		returning state, coalesce(campaign_id::text, '')`,
		jobID, outcome, nullable(phase)).Scan(&previous, &settlement.CampaignID)
	if errors.Is(err, pgx.ErrNoRows) {
		return CancelSettlement{}, ErrNotFound
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
		// The host holds nothing it will finish: the job is canceled and
		// the capacity is free. The attempt stays open for the host's own
		// account of the interruption, which the result path closes as a
		// late result; an attempt nobody ever reports on is closed by
		// the sweep of leases like any other.
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

// SettleCancelTimeouts ends the cancel requests nobody answered within
// the operation's timeout: the job fails with cancel_ack_timeout and an
// unknown outcome, its open attempt is closed with the same code, and its
// tokens go back. It returns the identifiers of the jobs it settled.
//
// The timeout is the operation's own: a request the host did not answer
// within the time the operation was allowed to take is a host that is not
// answering at all - offline, or an agent from before the protocol - and
// what it did with the task is a question to read off the host.
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
