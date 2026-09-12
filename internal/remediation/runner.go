package remediation

import (
	"context"
	"encoding/json"
	"log/slog"
	"time"

	"github.com/ultherego/flotestro/internal/audit"
	"github.com/ultherego/flotestro/internal/hosts"
	"github.com/ultherego/flotestro/internal/jobs"
	"github.com/ultherego/flotestro/internal/opspec"
)

// Runner drives remediation plans through their steps.
//
// It carries out nothing itself: it creates the tasks the scheduler delivers
// and waits for their result. A step starts only once the previous one
// succeeded - that is the whole dependency between the steps and the whole
// stop after a failure.
type Runner struct {
	store    *Store
	jobs     *jobs.Store
	hosts    *hosts.Store
	audit    *audit.Recorder
	log      *slog.Logger
	interval time.Duration
}

func NewRunner(store *Store, jobStore *jobs.Store, hostStore *hosts.Store,
	recorder *audit.Recorder, log *slog.Logger, interval time.Duration) *Runner {
	if interval <= 0 {
		interval = 5 * time.Second
	}
	return &Runner{store: store, jobs: jobStore, hosts: hostStore,
		audit: recorder, log: log, interval: interval}
}

// Run drives the plans until the context is closed.
func (r *Runner) Run(ctx context.Context) {
	ticker := time.NewTicker(r.interval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			r.tick(ctx)
		}
	}
}

func (r *Runner) tick(ctx context.Context) {
	plans, err := r.store.Running(ctx)
	if err != nil {
		r.log.Error("the remediation plans were not read", "err", err)
		return
	}
	for _, plan := range plans {
		if err := r.advance(ctx, plan); err != nil {
			r.log.Error("failure while running a remediation plan", "plan_id", plan.ID, "err", err)
		}
	}
}

// advance moves a plan forward by one step.
func (r *Runner) advance(ctx context.Context, plan Plan) error {
	step := plan.Current()
	if step == nil {
		return r.finish(ctx, plan, StateSucceeded, "")
	}

	if step.State == StepPending {
		return r.start(ctx, plan, step)
	}

	// The step is running: we wait for the task's result and, for a step with
	// a reboot, also for the host to come back. A reboot command that was
	// sent is not yet a host that came up - and that is the boundary where
	// the plan ends.
	task, err := r.jobs.Get(ctx, step.JobID)
	if err != nil {
		return err
	}
	if !task.State.Terminal() {
		return nil
	}
	if task.State != jobs.StateSucceeded {
		reason := "the task finished in the state " + string(task.State)
		if task.ResultMessage != "" {
			reason += ": " + task.ResultMessage
		}
		if err := r.store.FinishStep(ctx, step.ID, StepFailed, reason); err != nil {
			return err
		}
		if !plan.StopOnFailure {
			return nil
		}
		if err := r.store.SkipRemaining(ctx, plan.ID,
			"the previous step failed and the plan stops after a failure"); err != nil {
			return err
		}
		return r.finish(ctx, plan, StateFailed, reason)
	}

	if step.RequiresReboot {
		cameBack, reason := r.hostCameBack(ctx, plan)
		if !cameBack {
			if time.Now().UTC().Before(ReturnDeadline(*step)) {
				return nil
			}
			if err := r.store.FinishStep(ctx, step.ID, StepFailed, reason); err != nil {
				return err
			}
			return r.finish(ctx, plan, StateFailed, reason)
		}
	}

	if err := r.store.FinishStep(ctx, step.ID, StepSucceeded, ""); err != nil {
		return err
	}
	return nil
}

// start creates the task of a step.
func (r *Runner) start(ctx context.Context, plan Plan, step *Step) error {
	host, err := r.hosts.Get(ctx, plan.HostID)
	if err != nil {
		if err := r.store.FinishStep(ctx, step.ID, StepFailed, err.Error()); err != nil {
			return err
		}
		return r.finish(ctx, plan, StateFailed, err.Error())
	}

	action := opspec.ActionType(step.ActionType)
	var payload opspec.Payload
	if len(step.Payload) > 0 {
		if err := json.Unmarshal(step.Payload, &payload); err != nil {
			return r.abortStep(ctx, plan, step, "the step payload: "+err.Error())
		}
	}
	if err := opspec.Validate(action, payload); err != nil {
		return r.abortStep(ctx, plan, step, "the step payload was rejected: "+err.Error())
	}

	tx, err := r.jobs.Pool().Begin(ctx)
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback(ctx) }()

	task, err := r.jobs.Create(ctx, tx, jobs.Spec{
		HostID:  plan.HostID,
		Action:  action,
		Payload: payload,
		// The key binds the task to one specific step of one specific plan:
		// another pass of the runner does not create a second task.
		IdempotencyKey:  "remediation:" + plan.ID + ":" + step.CheckID,
		RequiresApprova: action.Mutating(),
		CreatedBy:       plan.CreatedBy,
		Preconditions: jobs.Preconditions{
			OSFamily:             host.OSFamily,
			RequiredCapabilities: []string{action.RequiredCapability()},
		},
	})
	if err != nil {
		_ = tx.Rollback(ctx)
		return r.abortStep(ctx, plan, step, "the task was not created: "+err.Error())
	}
	if err := r.audit.RecordTx(ctx, tx, audit.Event{
		ActorType: audit.ActorSystem, ActorID: "remediation:" + plan.ID,
		Action: "security.remediate.step", TargetType: "job", TargetID: task.ID,
		Outcome: audit.OutcomeSuccess,
		Detail: map[string]any{
			"host_id": plan.HostID, "plan_id": plan.ID, "check_id": step.CheckID,
			"position": step.Position, "action_type": step.ActionType,
			"plan_hash": plan.PlanHash, "created_by": plan.CreatedBy,
		},
	}); err != nil {
		return err
	}
	if err := tx.Commit(ctx); err != nil {
		return err
	}
	return r.store.StartStep(ctx, step.ID, task.ID)
}

// abortStep settles a step with a failure and ends the plan if that was decided.
func (r *Runner) abortStep(ctx context.Context, plan Plan, step *Step, reason string) error {
	if err := r.store.FinishStep(ctx, step.ID, StepFailed, reason); err != nil {
		return err
	}
	if !plan.StopOnFailure {
		return nil
	}
	if err := r.store.SkipRemaining(ctx, plan.ID, "the plan stopped after a failure"); err != nil {
		return err
	}
	return r.finish(ctx, plan, StateFailed, reason)
}

// hostCameBack checks whether the host came up after the reboot.
//
// The boot identifier settles it rather than the mere fact of a connection: a
// host that answers with the same boot_id has not restarted yet.
func (r *Runner) hostCameBack(ctx context.Context, plan Plan) (bool, string) {
	host, err := r.hosts.Get(ctx, plan.HostID)
	if err != nil {
		return false, "the host's state was not read: " + err.Error()
	}
	if host.ConnectionState != "online" {
		return false, "host nie cameBack po restarcie w " + ReturnWindow.String()
	}
	if plan.BootIDBefore != "" && host.BootID == plan.BootIDBefore {
		return false, "the host answers, but with the same boot identifier"
	}
	return true, ""
}

// finish closes a plan and records that in the audit trail.
func (r *Runner) finish(ctx context.Context, plan Plan, state, reason string) error {
	if err := r.store.FinishPlan(ctx, plan.ID, state); err != nil {
		return err
	}
	r.audit.Record(ctx, audit.Event{
		ActorType: audit.ActorSystem, ActorID: "remediation:" + plan.ID,
		Action: "security.remediate.finish", TargetType: "host", TargetID: plan.HostID,
		Outcome: auditOutcome(state),
		Detail: map[string]any{
			"plan_id": plan.ID, "state": state, "reason": reason,
			"plan_hash": plan.PlanHash, "created_by": plan.CreatedBy,
		},
	})
	r.log.Info("the remediation plan was settled", "plan_id", plan.ID, "host_id", plan.HostID, "state", state)
	return nil
}

func auditOutcome(state string) audit.Outcome {
	if state == StateSucceeded {
		return audit.OutcomeSuccess
	}
	return audit.OutcomeFailure
}
