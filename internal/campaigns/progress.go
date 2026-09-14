package campaigns

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/ultherego/flotestro/internal/audit"
	"github.com/ultherego/flotestro/internal/hosts"
	"github.com/ultherego/flotestro/internal/jobs"
	"github.com/ultherego/flotestro/internal/opspec"
	"github.com/ultherego/flotestro/internal/remediation"
)

// progressTarget settles one step of a host in a campaign: the change, the
// reboot or the verification after the reboot.
func (o *Orchestrator) progressTarget(ctx context.Context, campaign Campaign, target *Target) error {
	switch target.State {
	case TargetRunning:
		return o.afterMainJob(ctx, campaign, target)
	case TargetRebooting:
		return o.afterReboot(ctx, campaign, target)
	case TargetVerifying:
		return o.afterHealthCheck(ctx, campaign, target)
	case TargetPlanning:
		// Outside the planning phase a planning host is one that came back
		// from being offline and computes its plan again.
		return o.afterReplan(ctx, campaign, target)
	default:
		return nil
	}
}

// afterMainJob reacts to the result of the main task and decides about a reboot.
func (o *Orchestrator) afterMainJob(ctx context.Context, campaign Campaign, target *Target) error {
	// A fleet remediation runs a plan of steps rather than one task; the
	// host settles with the plan.
	if opspec.ActionType(campaign.ActionType) == opspec.ActionSecurityRemediate {
		return o.afterRemediation(ctx, campaign, target)
	}
	if target.JobID == nil {
		return nil
	}
	job, err := o.jobs.Get(ctx, *target.JobID)
	if err != nil {
		return err
	}
	// The host stays running for as long as its job is open - dispatched,
	// waiting on a lock, or running on the agent's word - and shows what
	// it waits on meanwhile.
	if err := o.followBlocker(ctx, target, job); err != nil {
		return err
	}
	if !jobs.State(job.State).Terminal() {
		return nil
	}
	if job.State != jobs.StateSucceeded {
		code, message := orDefault(job.ResultErrorCode, string(job.State)), job.ResultMessage
		// A broken session is told apart from a failed change: the outcome
		// on the host is unknown, and the campaign counts such hosts against
		// its own threshold.
		lost, detail, err := o.connectivityLost(ctx, job, target)
		if err != nil {
			return err
		}
		if lost {
			code, message = ConnectivityLostCode, detail
		}
		o.finishTarget(ctx, campaign, target, TargetFailed, code, message)
		return nil
	}

	// From here on the change itself is done; whatever follows is the
	// reboot's outcome, and the step records say so.
	changed := stepOutcome{Key: StepExecute, State: StepSucceeded}
	needsReboot, err := o.rebootNeeded(ctx, campaign, *target.JobID)
	if err != nil {
		return err
	}
	if !needsReboot {
		// A reboot that did not happen is a decision, and the strip is to
		// say whose: the policy's or the host's.
		why := "the host did not report that the change requires a reboot"
		if RebootPolicy(campaign.RebootPolicy) == RebootNever {
			why = "the reboot policy of the campaign is never"
		}
		notRebooted := stepOutcome{Key: StepReboot, State: StepSkipped, Reason: why}
		if len(campaign.HealthCheckUnits) == 0 {
			o.finishTargetSteps(ctx, campaign, target, TargetSucceeded, "", "", changed, notRebooted)
			return nil
		}
		// The units are verified whether or not a reboot came between:
		// the canary is there to say if the change left the service
		// standing, and a restart campaign with no reboot in it is the
		// one case where nothing else would ever look. The verification
		// follows the change directly, and the strip says the reboot was
		// skipped rather than never reached.
		host, err := o.hosts.Get(ctx, target.HostID)
		if err != nil {
			o.finishTargetSteps(ctx, campaign, target, TargetFailed, "host_unavailable", err.Error(),
				changed, notRebooted, stepOutcome{Key: StepVerify, State: StepFailed,
					Reason: stepReason("host_unavailable", err.Error())})
			return nil
		}
		return o.orderHealthCheck(ctx, campaign, target, host, StepExecute,
			"the change is done, verification is under way", changed, notRebooted)
	}

	host, err := o.hosts.Get(ctx, target.HostID)
	if err != nil {
		o.finishTargetSteps(ctx, campaign, target, TargetFailed, "host_unavailable", err.Error(),
			changed, stepOutcome{Key: StepReboot, State: StepFailed,
				Reason: stepReason("host_unavailable", err.Error())})
		return nil
	}

	rebootJobID, err := o.submitJob(ctx, campaign, host, opspec.ActionSystemReboot,
		opspec.Payload{Reboot: &opspec.RebootPayload{
			DelaySeconds: 15,
			Reason:       "Flotestro: campaign " + campaign.Name,
		}}, "campaign:"+campaign.ID+":reboot:"+target.HostID)
	if err != nil {
		o.finishTargetSteps(ctx, campaign, target, TargetFailed, "reboot_create_failed", err.Error(),
			changed, stepOutcome{Key: StepReboot, State: StepFailed,
				Reason: stepReason("reboot_create_failed", err.Error())})
		return nil
	}
	// The boot ID from before the reboot is the only certain proof that the
	// host really came back rather than merely failed to disconnect in
	// time. It is recorded with the transition, in the same transaction.
	planHash, _, _, err := o.store.HostPlan(ctx, campaign.ID, target.HostID)
	if err != nil {
		return err
	}
	if err := o.startStep(ctx, target, stepStart{
		Key: StepReboot, DependsOn: StepExecute, PlanHash: planHash,
		JobID: rebootJobID, Column: "reboot_job_id", State: TargetRebooting,
		Message: "a reboot was scheduled", BootID: &host.BootID, Closes: []stepOutcome{changed},
	}); err != nil {
		return err
	}

	o.log.Info("the campaign orders a reboot of a host",
		"campaign_id", campaign.ID, "host_id", target.HostID, "job_id", rebootJobID)
	return nil
}

// followBlocker copies onto the target what the host's job waits on: the
// lock the agent named, while the job waits for it, and nothing once the
// wait is over - the operation started, or the job settled. The write
// happens only when the text changes: the orchestrator passes every few
// seconds, and a host waiting a minute must not be rewritten every pass to
// say the same thing.
func (o *Orchestrator) followBlocker(ctx context.Context, target *Target, job *jobs.Job) error {
	blocker, _ := jobs.LockBlocker(job.WaitReason)
	if blocker == target.Blocker {
		return nil
	}
	if _, err := o.store.Pool().Exec(ctx,
		`update campaign_targets set blocker = $2 where id = $1 and blocker <> $2`,
		target.ID, blocker); err != nil {
		return fmt.Errorf("recording the blocker of the target: %w", err)
	}
	target.Blocker = blocker
	return nil
}

// afterRemediation settles a host of a fleet remediation from the state of
// its plan.
//
// The runner drives the steps and closes the plan: succeeded once every
// step went through, failed at the first step that did not, stopped when
// an operator stopped it. A step that requires a reboot already waits for
// the host to come back inside the plan, so the campaign has no reboot
// phase of its own here.
func (o *Orchestrator) afterRemediation(ctx context.Context, campaign Campaign, target *Target) error {
	plan, err := o.remediation.ForCampaignHost(ctx, campaign.ID, target.HostID)
	if errors.Is(err, remediation.ErrNotFound) {
		o.finishTarget(ctx, campaign, target, TargetFailed, "plan_missing",
			"the host's remediation plan is gone")
		return nil
	}
	if err != nil {
		return err
	}
	switch plan.State {
	case remediation.StateRunning:
		return nil
	case remediation.StateSucceeded:
		o.finishTarget(ctx, campaign, target, TargetSucceeded, "",
			fmt.Sprintf("remediation plan %s: %d steps succeeded", plan.ID, len(plan.Steps)))
	case remediation.StateStopped:
		o.finishTarget(ctx, campaign, target, TargetFailed, "remediation_stopped",
			"the remediation plan "+plan.ID+" was stopped before it finished")
	default:
		code, message := "remediation_failed", "the remediation plan "+plan.ID+" failed"
		for _, step := range plan.Steps {
			if step.State == remediation.StepFailed {
				message = "step " + step.CheckID + " (" + step.ActionType + "): " + step.Reason
				break
			}
		}
		o.finishTarget(ctx, campaign, target, TargetFailed, code, message)
	}
	return nil
}

// rebootNeeded answers whether the campaign's policy and the task's result
// require a reboot of the host.
func (o *Orchestrator) rebootNeeded(ctx context.Context, campaign Campaign, jobID string) (bool, error) {
	switch RebootPolicy(campaign.RebootPolicy) {
	case RebootNever:
		return false, nil
	case RebootAlways:
		return true, nil
	}

	attempts, err := o.jobs.Attempts(ctx, jobID)
	if err != nil {
		return false, err
	}
	if len(attempts) == 0 {
		return false, nil
	}
	detail := attempts[len(attempts)-1].Detail
	if len(detail) == 0 {
		return false, nil
	}
	var parsed struct {
		Kind           string `json:"kind"`
		RebootRequired bool   `json:"reboot_required"`
	}
	if err := json.Unmarshal(detail, &parsed); err != nil {
		return false, nil
	}
	return parsed.Kind == "package_apply" && parsed.RebootRequired, nil
}

// afterReboot waits for the host to come back with a new boot ID and orders
// the health check. The host counts as restored only after a new session and
// the verification, not after the reboot command has merely been sent.
func (o *Orchestrator) afterReboot(ctx context.Context, campaign Campaign, target *Target) error {
	if target.RebootJobID != nil {
		job, err := o.jobs.Get(ctx, *target.RebootJobID)
		if err != nil {
			return err
		}
		if jobs.State(job.State).Terminal() && job.State != jobs.StateSucceeded {
			o.finishTarget(ctx, campaign, target, TargetFailed,
				firstNonEmpty(job.ResultErrorCode, "reboot_failed"), job.ResultMessage)
			return nil
		}
	}

	host, err := o.hosts.Get(ctx, target.HostID)
	if err != nil {
		return err
	}
	// A new boot ID and an active session mean the host has come back.
	if host.ConnectionState != "online" || host.BootID == "" || host.BootID == target.BootIDBefore {
		since, known := rebootOrderedAt(target)
		if !known {
			return nil
		}
		verdict := judgeReboot(since, campaign.MaintenanceEnd, campaign.RebootTimeout(), time.Now())
		if !verdict.Waiting {
			o.finishTarget(ctx, campaign, target, TargetFailed, verdict.Code, verdict.Message)
		}
		return nil
	}

	// The host is back with a new boot ID: the reboot step is done, and
	// what follows is the verification's outcome.
	rebooted := stepOutcome{Key: StepReboot, State: StepSucceeded, Reason: "the host came back with boot ID " + host.BootID}
	if len(campaign.HealthCheckUnits) == 0 {
		o.finishTargetSteps(ctx, campaign, target, TargetSucceeded, "", "the host came back after the reboot",
			rebooted, stepOutcome{Key: StepVerify, State: StepSkipped,
				Reason: "the campaign names no units to check after the reboot"})
		return nil
	}
	return o.orderHealthCheck(ctx, campaign, target, host, StepReboot,
		"the host came back, verification is under way", rebooted)
}

// orderHealthCheck orders the verification of the campaign's units on a
// host whose change is done: right after the change when no reboot
// follows, or once the host came back from one. The steps that ended for
// the verification to start close in the same transaction, and the step
// row names the one it followed, so the strip reads the same whichever
// way the host got here.
func (o *Orchestrator) orderHealthCheck(ctx context.Context, campaign Campaign, target *Target,
	host *hosts.Host, after StepKey, message string, closes ...stepOutcome) error {
	healthJobID, err := o.submitJob(ctx, campaign, host, opspec.ActionUnitStatus,
		opspec.Payload{UnitStatus: &opspec.UnitStatusPayload{Units: campaign.HealthCheckUnits}},
		"campaign:"+campaign.ID+":health:"+target.HostID+":"+host.BootID)
	if err != nil {
		notVerified := stepOutcome{Key: StepVerify, State: StepFailed,
			Reason: stepReason("health_create_failed", err.Error())}
		o.finishTargetSteps(ctx, campaign, target, TargetFailed, "health_create_failed", err.Error(),
			append(append([]stepOutcome(nil), closes...), notVerified)...)
		return nil
	}
	planHash, _, _, err := o.store.HostPlan(ctx, campaign.ID, target.HostID)
	if err != nil {
		return err
	}
	if err := o.startStep(ctx, target, stepStart{
		Key: StepVerify, DependsOn: after, PlanHash: planHash,
		JobID: healthJobID, Column: "health_job_id", State: TargetVerifying,
		Message: message, Closes: closes, Planned: campaignPlans(campaign),
	}); err != nil {
		return err
	}

	o.log.Info("the campaign orders a health check of a host",
		"campaign_id", campaign.ID, "host_id", target.HostID, "after", after,
		"boot_id", host.BootID, "job_id", healthJobID)
	return nil
}

// rebootOrderedAt says since when the host has been away: the moment the
// target entered the rebooting state. The change before the reboot may
// have taken half an hour, and a wait counted from the start of the change
// would fail a host the moment its reboot was ordered. A target without
// either time cannot be judged and is waited for.
func rebootOrderedAt(target *Target) (time.Time, bool) {
	switch {
	case target.StateSince != nil:
		return *target.StateSince, true
	case target.StartedAt != nil:
		return *target.StartedAt, true
	default:
		return time.Time{}, false
	}
}

// rebootVerdict is the judgement on a host that has not come back from
// its reboot: Waiting while the campaign still waits for it, otherwise
// the code and the message the host is closed with.
type rebootVerdict struct {
	Waiting bool
	Code    string
	Message string
}

// judgeReboot decides whether a host away since the given moment is still
// waited for, from the campaign's maintenance window and its reboot
// timeout.
//
// The window is judged first and the timeout only then. The window is the
// operator's promise about when the fleet is touched: a host that is down
// after it ended is outside that promise however short its absence, and
// a timeout that merely has not run out yet does not put it back inside.
// The document lists "the host does not come back within the maintenance
// window" among the mandatory scenarios and keeps such a host failed; it
// says nothing about waiting past the end, so the campaign does not.
func judgeReboot(since time.Time, windowEnd *time.Time, timeout time.Duration, now time.Time) rebootVerdict {
	away := now.Sub(since).Round(time.Second)
	if windowEnd != nil && now.After(*windowEnd) {
		return rebootVerdict{Code: RebootWindowClosedCode,
			Message: fmt.Sprintf("the maintenance window ended at %s and the host has been away for %s since the reboot was ordered",
				windowEnd.UTC().Format(time.RFC3339), away)}
	}
	if now.Sub(since) > timeout {
		return rebootVerdict{Code: "reboot_timeout",
			Message: fmt.Sprintf("the host did not come back within %s of the reboot; it has been away for %s",
				timeout, away)}
	}
	return rebootVerdict{Waiting: true}
}

// afterHealthCheck settles a host after the units are verified.
func (o *Orchestrator) afterHealthCheck(ctx context.Context, campaign Campaign, target *Target) error {
	if target.HealthJobID == nil {
		return nil
	}
	job, err := o.jobs.Get(ctx, *target.HealthJobID)
	if err != nil {
		return err
	}
	if !jobs.State(job.State).Terminal() {
		return nil
	}
	if job.State != jobs.StateSucceeded {
		// A failed health check is a failure of the host in the campaign: the
		// change was carried out, but the host did not return to a working
		// state. The host carries the campaign's verdict - the check failed -
		// and the agent's finding travels in the message and on the task;
		// the policy and the threshold read one code for one stage. A
		// session lost during the check is the one exception: it is not a
		// verdict on the units, and the campaign counts it with the other
		// lost sessions.
		code := "health_check_failed"
		if job.ResultErrorCode == ConnectivityLostCode {
			code = ConnectivityLostCode
		}
		o.finishTarget(ctx, campaign, target, TargetFailed, code,
			stepReason(job.ResultErrorCode, job.ResultMessage))
		return nil
	}
	o.finishTarget(ctx, campaign, target, TargetSucceeded, "", "the health check passed")
	return nil
}

// finishTarget settles a host in a campaign and records that in the audit trail.
//
// The step the host was carrying ends with it: the outcome is derived
// from the target's state, so a host settled while running closes its
// change and a host settled while waiting records the step it never got
// to, with the reason. The places that know better - a change that
// succeeded and a reboot that could not be ordered - name the outcomes
// themselves through finishTargetSteps.
func (o *Orchestrator) finishTarget(ctx context.Context, campaign Campaign, target *Target,
	state TargetState, errorCode, message string) {
	o.finishTargetSteps(ctx, campaign, target, state, errorCode, message,
		settledOutcomes(campaign, target, state, errorCode, message)...)
}

// finishTargetSteps settles a host together with the named outcomes of
// its steps, in one transaction: a target cannot end with its step left
// open, and a step cannot close without the target that carried it.
func (o *Orchestrator) finishTargetSteps(ctx context.Context, campaign Campaign, target *Target,
	state TargetState, errorCode, message string, outcomes ...stepOutcome) {
	if err := o.settleTarget(ctx, campaign, target, state, errorCode, message, outcomes); err != nil {
		o.log.Error("the state of a campaign target was not recorded",
			"campaign_id", campaign.ID, "host_id", target.HostID, "err", err)
		return
	}
	target.State = state
	// The code stays on the target in memory as it is in the row: the pass
	// that settled the host reads it back to decide whether the campaign
	// goes on.
	target.ErrorCode = errorCode
	target.Message = message
	// The tokens go back to the pool together with the end of the host. The
	// release is separate from the expiry of the lease: the capacity is to
	// come back now rather than in two minutes.
	o.releaseCapacity(ctx, target)

	outcome := audit.OutcomeSuccess
	if state == TargetFailed {
		outcome = audit.OutcomeFailure
	}
	o.audit.Record(ctx, audit.Event{
		ActorType: audit.ActorSystem, ActorID: "campaign:" + campaign.ID,
		Action: "campaign.target." + string(state), TargetType: "host", TargetID: target.HostID,
		RequestID: campaign.RequestID, Outcome: outcome,
		Detail: withCompensation(map[string]any{
			"campaign_id": campaign.ID, "wave": target.Wave,
			"error_code": errorCode, "message": message,
		}, campaign),
	})
	o.log.Info("the campaign settled a host",
		"campaign_id", campaign.ID, "host_id", target.HostID,
		"state", state, "code", errorCode)
}

// pauseOnThreshold holds a campaign back once the failure threshold is
// crossed. The hosts already started finish their tasks; new ones do not
// start.
func (o *Orchestrator) pauseOnThreshold(ctx context.Context, campaign Campaign,
	reason string, failed, finished int) error {
	if err := o.store.SetState(ctx, campaign.ID, StatePaused, reason); err != nil {
		return err
	}
	o.audit.Record(ctx, audit.Event{
		ActorType: audit.ActorSystem, ActorID: "campaign:" + campaign.ID,
		Action: "campaign.pause", TargetType: "campaign", TargetID: campaign.ID,
		RequestID: campaign.RequestID, Outcome: audit.OutcomeFailure,
		Detail: map[string]any{
			"reason": reason, "failed": failed, "finished": finished,
			"threshold_percent":  campaign.FailureThresholdPercent,
			"threshold_absolute": campaign.FailureThresholdAbsolute,
		},
	})
	o.log.Warn("the campaign was held back after crossing the failure threshold",
		"campaign_id", campaign.ID, "reason", reason, "failed", failed, "finished", finished)
	return nil
}

// pauseOnWindowClosed holds a campaign back once a host was still
// rebooting when the maintenance window ended.
//
// The threshold has no say here. A host that is down after the window
// closed is exactly the case an operator must look at: the window is
// what the fleet was promised, the host is outside it, and whether the
// next wave may start after that is a decision, not a percentage. The
// document keeps such a host failed and says it blocks its failure
// domain; where it is silent about the campaign, the campaign stops and
// asks.
func (o *Orchestrator) pauseOnWindowClosed(ctx context.Context, campaign Campaign, hostIDs []string) error {
	// The judgement only closes a host this way under a window with an
	// end; the guard is for a row somebody settled by hand with the code.
	ended := "an unknown time"
	if campaign.MaintenanceEnd != nil {
		ended = campaign.MaintenanceEnd.UTC().Format(time.RFC3339)
	}
	reason := fmt.Sprintf("%s: %d hosts were still rebooting when the maintenance window ended at %s",
		PauseWindowClosedMidReboot, len(hostIDs), ended)
	if err := o.store.SetState(ctx, campaign.ID, StatePaused, reason); err != nil {
		return err
	}
	o.audit.Record(ctx, audit.Event{
		ActorType: audit.ActorSystem, ActorID: "campaign:" + campaign.ID,
		Action: "campaign.pause", TargetType: "campaign", TargetID: campaign.ID,
		RequestID: campaign.RequestID, Outcome: audit.OutcomeFailure,
		Detail: map[string]any{
			"reason": PauseWindowClosedMidReboot, "hosts": hostIDs,
			"maintenance_end": campaign.MaintenanceEnd,
		},
	})
	o.log.Warn("the campaign was held back after hosts did not come back inside the maintenance window",
		"campaign_id", campaign.ID, "hosts", hostIDs, "maintenance_end", campaign.MaintenanceEnd)
	return nil
}

// complete closes a campaign and records the report in the audit trail.
func (o *Orchestrator) complete(ctx context.Context, campaign Campaign,
	targets []Target, failed int) error {
	state := StateCompleted
	if failed > 0 && failed == len(targets) {
		// A campaign in which every host failed is not completed.
		state = StateFailed
	}
	if err := o.store.SetState(ctx, campaign.ID, state, ""); err != nil {
		return err
	}
	// The hosts gave their tokens back as they finished one by one. What
	// remains are the waiting records - and those have to disappear too,
	// because they count towards the share of the next campaigns.
	if o.budgets != nil {
		if err := o.budgets.ReleaseClaimant(ctx, "campaign:"+campaign.ID); err != nil {
			o.log.Error("the capacity of a finished campaign was not released",
				"campaign_id", campaign.ID, "err", err)
		}
	}

	counts, err := o.store.Counts(ctx, campaign.ID)
	if err != nil {
		return err
	}
	o.audit.Record(ctx, audit.Event{
		ActorType: audit.ActorSystem, ActorID: "campaign:" + campaign.ID,
		Action: "campaign.complete", TargetType: "campaign", TargetID: campaign.ID,
		RequestID: campaign.RequestID, Outcome: audit.OutcomeSuccess,
		Detail: map[string]any{"state": string(state), "totals": counts},
	})
	o.log.Info("the campaign finished",
		"campaign_id", campaign.ID, "state", state, "totals", fmt.Sprint(counts))
	return nil
}

// withCompensation adds the compensated campaign to an audit detail when
// there is one: the trail of the original is to lead to the campaign that
// undid it, and the trail of the compensation to what it undid.
func withCompensation(detail map[string]any, campaign Campaign) map[string]any {
	if campaign.CompensatesCampaignID != "" {
		detail["compensates_campaign_id"] = campaign.CompensatesCampaignID
	}
	return detail
}

func firstNonEmpty(values ...string) string {
	for _, value := range values {
		if value != "" {
			return value
		}
	}
	return ""
}

// settleTarget writes the target's terminal state and the outcomes of its
// steps in one transaction.
//
// An outcome closes the open step of its kind where there is one. Where
// there is none - the host was settled before the step was ordered - the
// step is recorded as it ended, so that the strip says "skipped: the host
// is in a maintenance window" instead of showing no step at all.
func (o *Orchestrator) settleTarget(ctx context.Context, campaign Campaign, target *Target,
	state TargetState, errorCode, message string, outcomes []stepOutcome) error {
	tx, err := o.store.Pool().Begin(ctx)
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback(ctx) }()

	if err := o.store.UpdateTargetTx(ctx, tx, target.ID, state, errorCode, message); err != nil {
		return err
	}
	for _, outcome := range outcomes {
		settled, err := o.store.FinishStep(ctx, tx, target.ID, outcome.Key, outcome.State, outcome.Reason)
		if err != nil {
			return err
		}
		if settled {
			continue
		}
		if err := o.store.RecordStep(ctx, tx, StepRecord{
			Target: *target, Key: outcome.Key,
			DependsOn: dependencyOf(outcome.Key, campaignPlans(campaign), target.RebootJobID != nil),
			State:     outcome.State, Reason: outcome.Reason,
		}); err != nil {
			return err
		}
	}
	if campaign.CompensatesCampaignID != "" && state.Finished() {
		if err := o.closeCompensation(ctx, tx, campaign, target, state, errorCode, message); err != nil {
			return err
		}
	}
	return tx.Commit(ctx)
}

// openCompensation records, on the original campaign's target for the same
// host, that its compensation started: a compensate step that follows the
// original's change, runs under the compensating campaign's plan for the
// host and is carried by that campaign's task.
//
// The original's target keeps its state. Its terminal state is the record
// of what that campaign did to the host, the report written from those
// states is immutable, and moving a failed target to "compensated" would
// take the failure out of every count and filter that reads the state -
// the history the document says a compensation must not erase. The step
// row is that history: it names the compensating campaign in its note,
// so the strip of the original reads "compensated by ..." without a word
// of the original's own record rewritten.
func (o *Orchestrator) openCompensation(ctx context.Context, tx pgx.Tx, originalID string,
	target *Target, start stepStart) error {
	original, found, err := o.store.compensatedTarget(ctx, tx, originalID, target.HostID)
	if err != nil {
		return err
	}
	if !found {
		// The order was checked against the original's snapshot; a host
		// missing from it now has left the fleet, and the compensating
		// campaign's own step says what happened on it.
		o.log.Warn("the compensated campaign has no target for the host",
			"campaign_id", originalID, "host_id", target.HostID)
		return nil
	}
	return o.store.StartStep(ctx, tx, StepRecord{
		Target: original, Key: StepCompensate, DependsOn: StepExecute,
		PlanHash: start.PlanHash, JobID: start.JobID,
		Reason: compensationNote(target.CampaignID),
	})
}

// compensationNote is what the compensate step of the original says about
// where it came from. The task and the plan digest point at the
// compensating campaign already; the note says it in words, on the strip.
func compensationNote(campaignID string) string {
	return "compensated by campaign " + campaignID
}

// closeCompensation settles the compensate step the compensating target
// opened on the original's target, with the outcome of the compensating
// change. A compensating host settled before its change started opened
// nothing, and nothing is closed: the original host was not touched, and
// the compensating campaign's own strip says why its host never ran.
func (o *Orchestrator) closeCompensation(ctx context.Context, tx pgx.Tx, campaign Campaign,
	target *Target, state TargetState, errorCode, message string) error {
	original, found, err := o.store.compensatedTarget(ctx, tx, campaign.CompensatesCampaignID, target.HostID)
	if err != nil || !found {
		return err
	}
	stepState, reason := compensationOutcome(state, errorCode, message)
	if reason == "" {
		// A change that succeeded has no error to quote; the note that
		// opened the step stays on it rather than giving way to nothing.
		reason = compensationNote(campaign.ID)
	}
	_, err = o.store.FinishStep(ctx, tx, original.ID, StepCompensate, stepState, reason)
	return err
}

// stepStart describes a step being ordered for a host: the task that
// carries it, the state the target runs it in and the steps it closes.
type stepStart struct {
	Key       StepKey
	DependsOn StepKey
	PlanHash  string
	// JobID and Column bind the task to the target row; both empty for a
	// step without a task of its own, such as a remediation plan.
	JobID  string
	Column string
	State  TargetState
	// Message is the target's message; Note travels on the step.
	Message string
	Note    string
	// BootID, when set, is recorded as the boot ID from before the change.
	BootID *string
	// Closes are the steps that ended for this one to start. A step among
	// them that was never ordered - a reboot the policy skipped on the way
	// to the verification - has no open row to close and is recorded as it
	// ended instead, the way settleTarget records a step a settled host
	// never got to.
	Closes []stepOutcome
	// Planned says whether the hosts of the campaign computed a plan step;
	// it places a step recorded from Closes on the strip. Read only when
	// such a record is written.
	Planned bool
	// Compensates names the campaign whose change on this host the step
	// undoes; set on the change step of a compensating campaign only. The
	// original's target for the same host gets its compensate step opened
	// in the same transaction: the reverse change runs on the host, and
	// the original is to say so on its own strip.
	Compensates string
}

// startStep orders a step: it binds the task, moves the target into the
// state the step runs in and opens the step row - in one transaction, so
// that the target and its step never disagree about what is under way.
func (o *Orchestrator) startStep(ctx context.Context, target *Target, start stepStart) error {
	tx, err := o.store.Pool().Begin(ctx)
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback(ctx) }()

	for _, done := range start.Closes {
		settled, err := o.store.FinishStep(ctx, tx, target.ID, done.Key, done.State, done.Reason)
		if err != nil {
			return err
		}
		if settled {
			continue
		}
		if err := o.store.RecordStep(ctx, tx, StepRecord{
			Target: *target, Key: done.Key,
			DependsOn: dependencyOf(done.Key, start.Planned, target.RebootJobID != nil),
			State:     done.State, Reason: done.Reason,
		}); err != nil {
			return err
		}
	}
	if start.Column != "" {
		if err := o.store.AttachJobTx(ctx, tx, target.ID, start.Column, start.JobID); err != nil {
			return err
		}
	}
	if start.BootID != nil {
		if err := o.store.SetBootIDBeforeTx(ctx, tx, target.ID, *start.BootID); err != nil {
			return err
		}
	}
	if err := o.store.UpdateTargetTx(ctx, tx, target.ID, start.State, "", start.Message); err != nil {
		return err
	}
	if err := o.store.StartStep(ctx, tx, StepRecord{
		Target: *target, Key: start.Key, DependsOn: start.DependsOn,
		PlanHash: start.PlanHash, JobID: start.JobID, Reason: start.Note,
	}); err != nil {
		return err
	}
	if start.Compensates != "" {
		if err := o.openCompensation(ctx, tx, start.Compensates, target, start); err != nil {
			return err
		}
	}
	if err := tx.Commit(ctx); err != nil {
		return err
	}
	target.State = start.State
	target.ErrorCode = ""
	if start.BootID != nil {
		target.BootIDBefore = *start.BootID
	}
	return nil
}

// campaignPlans says whether the hosts of this campaign computed a plan
// step of their own before the change. A plan handed in with the order -
// a fleet remediation - is no step of the host, so the change of such a
// campaign follows nothing on the host's strip.
func campaignPlans(campaign Campaign) bool {
	return opspec.PlanningAction(opspec.ActionType(campaign.ActionType)) != ""
}
