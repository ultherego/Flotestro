package remediation

import (
	"context"
	"encoding/json"
	"errors"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

// ErrNotFound means a plan that does not exist.
var ErrNotFound = errors.New("there is no such remediation plan")

// ErrPlanRunning means a host on which a plan is already running.
var ErrPlanRunning = errors.New("a remediation plan is already running on this host")

// Store holds the remediation plans and their steps.
type Store struct {
	pool *pgxpool.Pool
}

func NewStore(pool *pgxpool.Pool) *Store { return &Store{pool: pool} }

// Pool exposes the pool for transactions combined with other writes.
func (s *Store) Pool() *pgxpool.Pool { return s.pool }

// Spec describes the plan to create.
type Spec struct {
	HostID          string
	PlanHash        string
	PlanHashVersion int
	Reason          string
	CreatedBy       string
	StopOnFailure   bool
	BootIDBefore    string
}

// Create records a plan together with its steps.
//
// Two plans must not run on one host at once: the steps of one assume the
// state the previous one left, and a parallel plan changes that state under
// them.
func (s *Store) Create(ctx context.Context, tx pgx.Tx, spec Spec, steps []Step) (*Plan, error) {
	var running int
	if err := tx.QueryRow(ctx,
		`select count(*) from remediation_plans where host_id = $1 and state = $2`,
		spec.HostID, StateRunning).Scan(&running); err != nil {
		return nil, err
	}
	if running > 0 {
		return nil, ErrPlanRunning
	}

	plan := &Plan{
		HostID: spec.HostID, PlanHash: spec.PlanHash, PlanHashVersion: spec.PlanHashVersion,
		Reason: spec.Reason, CreatedBy: spec.CreatedBy, StopOnFailure: spec.StopOnFailure,
		State: StateRunning, BootIDBefore: spec.BootIDBefore,
	}
	if err := tx.QueryRow(ctx, `
		insert into remediation_plans
		    (host_id, plan_hash, plan_hash_version, reason, created_by, stop_on_failure, state)
		values ($1, $2, $3, $4, $5, $6, $7)
		returning id, created_at`,
		spec.HostID, spec.PlanHash, spec.PlanHashVersion, spec.Reason,
		spec.CreatedBy, spec.StopOnFailure, StateRunning).Scan(&plan.ID, &plan.CreatedAt); err != nil {
		return nil, err
	}

	batch := &pgx.Batch{}
	for _, step := range steps {
		batch.Queue(`
			insert into remediation_steps
			    (plan_id, position, check_id, check_version, action_type, payload,
			     lock_class, requires_reboot, state)
			values ($1, $2, $3, $4, $5, $6, $7, $8, $9)`,
			plan.ID, step.Position, step.CheckID, step.CheckVersion, step.ActionType,
			[]byte(emptyWhenMissing(step.Payload)), step.LockClass, step.RequiresReboot, StepPending)
	}
	results := tx.SendBatch(ctx, batch)
	for range steps {
		if _, err := results.Exec(); err != nil {
			_ = results.Close()
			return nil, err
		}
	}
	if err := results.Close(); err != nil {
		return nil, err
	}

	plan.Steps = append([]Step(nil), steps...)
	return plan, nil
}

// Plan returns a plan together with its steps.
func (s *Store) Plan(ctx context.Context, planID string) (*Plan, error) {
	plans, err := s.query(ctx, "where id = $1", planID)
	if err != nil {
		return nil, err
	}
	if len(plans) == 0 {
		return nil, ErrNotFound
	}
	return &plans[0], nil
}

// ForHost returns the host's most recent plans.
func (s *Store) ForHost(ctx context.Context, hostID string, limit int) ([]Plan, error) {
	if limit <= 0 || limit > 50 {
		limit = 10
	}
	return s.query(ctx, "where host_id = $1 order by created_at desc limit $2", hostID, limit)
}

// Running returns the plans the runner has to carry further.
func (s *Store) Running(ctx context.Context) ([]Plan, error) {
	return s.query(ctx, "where state = $1 order by created_at", StateRunning)
}

func (s *Store) query(ctx context.Context, clause string, args ...any) ([]Plan, error) {
	rows, err := s.pool.Query(ctx, `
		select id, host_id, plan_hash, plan_hash_version, reason, created_by,
		       stop_on_failure, state, created_at, finished_at
		  from remediation_plans `+clause, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var plans []Plan
	for rows.Next() {
		var plan Plan
		if err := rows.Scan(&plan.ID, &plan.HostID, &plan.PlanHash, &plan.PlanHashVersion,
			&plan.Reason, &plan.CreatedBy, &plan.StopOnFailure, &plan.State,
			&plan.CreatedAt, &plan.FinishedAt); err != nil {
			return nil, err
		}
		plans = append(plans, plan)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	for i := range plans {
		steps, err := s.Steps(ctx, plans[i].ID)
		if err != nil {
			return nil, err
		}
		plans[i].Steps = steps
	}
	return plans, nil
}

// Steps returns a plan's steps in execution order.
func (s *Store) Steps(ctx context.Context, planID string) ([]Step, error) {
	rows, err := s.pool.Query(ctx, `
		select id, position, check_id, check_version, action_type, payload,
		       lock_class, requires_reboot, coalesce(job_id::text, ''), state,
		       coalesce(reason, ''), started_at, finished_at
		  from remediation_steps
		 where plan_id = $1
		 order by position`, planID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var steps []Step
	for rows.Next() {
		var step Step
		var payload []byte
		if err := rows.Scan(&step.ID, &step.Position, &step.CheckID, &step.CheckVersion,
			&step.ActionType, &payload, &step.LockClass, &step.RequiresReboot,
			&step.JobID, &step.State, &step.Reason, &step.StartedAt, &step.FinishedAt); err != nil {
			return nil, err
		}
		step.Payload = json.RawMessage(payload)
		steps = append(steps, step)
	}
	return steps, rows.Err()
}

// StartStep binds a step to a task and marks it as running.
func (s *Store) StartStep(ctx context.Context, stepID, jobID string) error {
	_, err := s.pool.Exec(ctx, `
		update remediation_steps
		   set state = $2, job_id = $3, started_at = now()
		 where id = $1`, stepID, StepRunning, jobID)
	return err
}

// FinishStep records the result of a step.
func (s *Store) FinishStep(ctx context.Context, stepID, state, reason string) error {
	_, err := s.pool.Exec(ctx, `
		update remediation_steps
		   set state = $2, reason = $3, finished_at = now()
		 where id = $1`, stepID, state, nullable(reason))
	return err
}

// SkipRemaining settles the steps that will no longer start.
func (s *Store) SkipRemaining(ctx context.Context, planID, reason string) error {
	_, err := s.pool.Exec(ctx, `
		update remediation_steps
		   set state = $2, reason = $3, finished_at = now()
		 where plan_id = $1 and state = $4`, planID, StepSkipped, nullable(reason), StepPending)
	return err
}

// FinishPlan records the final state of a plan.
func (s *Store) FinishPlan(ctx context.Context, planID, state string) error {
	_, err := s.pool.Exec(ctx, `
		update remediation_plans set state = $2, finished_at = now() where id = $1`, planID, state)
	return err
}

func emptyWhenMissing(payload json.RawMessage) json.RawMessage {
	if len(payload) == 0 {
		return json.RawMessage("{}")
	}
	return payload
}

func nullable(value string) any {
	if value == "" {
		return nil
	}
	return value
}

// ReturnDeadline gives the moment by which the host should already be back.
func ReturnDeadline(step Step) time.Time {
	if step.StartedAt == nil {
		return time.Now().UTC().Add(ReturnWindow)
	}
	return step.StartedAt.Add(ReturnWindow)
}
