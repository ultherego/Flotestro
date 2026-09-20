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
	case TargetDispatched, TargetAwaitingLock, TargetRunning:
		// Three states of one task: handed over, waiting for a resource of the host,
		// running on the agent's word.
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
	// The host follows its task for as long as the task is open: handed over,
	// waiting on a lock with the blocker named, or running on the agent's word.
	if !jobs.State(job.State).Terminal() {
		return o.followJob(ctx, target, job)
	}
	// What the task ended with, read into one verdict: a broken session is told
	// apart from a failed change, and the host's own word that it changed nothing
	// from a change that landed.
	verdict := jobVerdict{State: job.State, ErrorCode: job.ResultErrorCode}
	if job.State != jobs.StateSucceeded {
		lost, detail, err := o.connectivityLost(ctx, job, target)
		if err != nil {
			return err
		}
		verdict.Lost = lost
		state, code := targetOutcome(verdict)
		message := job.ResultMessage
		if lost {
			message = detail
		}
		o.finishTarget(ctx, campaign, target, state, code, message)
		return nil
	}
	attempt, err := o.lastAttempt(ctx, *target.JobID)
	if err != nil {
		return err
	}
	var detail json.RawMessage
	if attempt != nil {
		detail = attempt.Detail
	}
	verdict.NoChange = resultNoChange(detail)
	if state, _ := targetOutcome(verdict); state == TargetNoChange {
		// Nothing changed on the host, so there is nothing to reboot for and nothing
		// to verify: the reboot and the verification are answers to a change, and
		// the strip says why neither ran.
		why := "the host reported that nothing changed"
		o.finishTargetSteps(ctx, campaign, target, TargetNoChange, "", why,
			stepOutcome{Key: StepExecute, State: StepSucceeded, Reason: why},
			stepOutcome{Key: StepReboot, State: StepSkipped, Reason: why},
			stepOutcome{Key: StepVerify, State: StepSkipped, Reason: why})
		return nil
	}

	// The task says it succeeded; the host's own reading of itself after the
	// change decides whether that is a success.
	if reason := unverifiedChange(opspec.ActionType(campaign.ActionType), attempt); reason != "" {
		o.log.Warn("the task of a campaign host succeeded and the host does not show the state asked for",
			"campaign_id", campaign.ID, "host_id", target.HostID, "job_id", *target.JobID, "reason", reason)
		o.finishTargetSteps(ctx, campaign, target, TargetFailed, opspec.ErrorAppliedUnverified, reason,
			stepOutcome{Key: StepExecute, State: StepFailed,
				Reason: stepReason(opspec.ErrorAppliedUnverified, reason)},
			stepOutcome{Key: StepReboot, State: StepSkipped,
				Reason: "the change was not confirmed on the host"},
			stepOutcome{Key: StepVerify, State: StepSkipped,
				Reason: "the change was not confirmed on the host"})
		return nil
	}

	// From here on the change itself is done; whatever follows is the
	// reboot's outcome, and the step records say so.
	changed := stepOutcome{Key: StepExecute, State: StepSucceeded}
	needsReboot := rebootNeeded(campaign, detail)
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
		// The units are verified whether or not a reboot came between: the canary is
		// there to say whether the change left the service standing.
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
	// The boot ID from before the reboot is the only certain proof that the host
	// really came back rather than merely failed to disconnect in time.
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

// followJob copies onto the target where its open task stands: dispatched
// until the agent says the operation started, waiting for a lock with the
// blocker the agent named while it waits, running once it started.
func (o *Orchestrator) followJob(ctx context.Context, target *Target, job *jobs.Job) error {
	// A task whose cancel was asked of the host stands where it stood: the host
	// has not said yet whether it started, and the answer or the result moves the
	// host - not a guess made from the request.
	if job.State == jobs.StateCancelRequested {
		return nil
	}
	state, blocker := taskStanding(job.State, job.WaitReason)
	if state == target.State && blocker == target.Blocker {
		return nil
	}
	if err := o.store.FollowTask(ctx, target, state, blocker); err != nil {
		return fmt.Errorf("recording where the task of the target stands: %w", err)
	}
	return nil
}

// taskStanding maps an open task onto the state of the host carrying it,
// together with the lock it waits on.
func taskStanding(state jobs.State, waitReason string) (TargetState, string) {
	if blocker, waiting := jobs.LockBlocker(waitReason); waiting {
		return TargetAwaitingLock, blocker
	}
	if state == jobs.StateRunning {
		return TargetRunning, ""
	}
	return TargetDispatched, ""
}

// jobVerdict is what the campaign reads off a task that ended: its state and
// error code, whether the session broke while it ran, and whether the host
// said it changed nothing.
type jobVerdict struct {
	State     jobs.State
	ErrorCode string
	Lost      bool
	NoChange  bool
}

// targetOutcome maps the end of a task onto the state of the host and the code
// it carries.
func targetOutcome(verdict jobVerdict) (TargetState, string) {
	switch {
	case verdict.State == jobs.StateSucceeded && verdict.NoChange:
		return TargetNoChange, ""
	case verdict.State == jobs.StateSucceeded:
		return TargetSucceeded, ""
	case verdict.Lost:
		return TargetUnknown, ConnectivityLostCode
	case verdict.ErrorCode == OutcomeUnknownCode:
		return TargetUnknown, OutcomeUnknownCode
	case verdict.ErrorCode == CancelAckTimeoutCode:
		return TargetUnknown, CancelAckTimeoutCode
	case verdict.State == jobs.StateCanceled:
		return TargetCanceled, string(jobs.StateCanceled)
	default:
		return TargetFailed, orDefault(verdict.ErrorCode, string(verdict.State))
	}
}

// resultNoChange reads off the result of a change whether the host said it
// changed nothing.
func resultNoChange(detail json.RawMessage) bool {
	if len(detail) == 0 {
		return false
	}
	var parsed struct {
		Kind    string          `json:"kind"`
		Changed *bool           `json:"changed"`
		Applied json.RawMessage `json:"applied"`
	}
	if err := json.Unmarshal(detail, &parsed); err != nil {
		return false
	}
	if parsed.Changed != nil {
		return !*parsed.Changed
	}
	if parsed.Kind == "package_apply" {
		return jsonListEmpty(parsed.Applied)
	}
	return false
}

// lastAttempt returns the task's latest attempt: its typed result and the
// host's reading of itself after the change. Empty when the task has none.
func (o *Orchestrator) lastAttempt(ctx context.Context, jobID string) (*jobs.Attempt, error) {
	attempts, err := o.jobs.Attempts(ctx, jobID)
	if err != nil {
		return nil, err
	}
	if len(attempts) == 0 {
		return nil, nil
	}
	return &attempts[len(attempts)-1], nil
}

// unverifiedChange says why a task that reports success is not one, from the
// verification the host sent with its result.
func unverifiedChange(action opspec.ActionType, attempt *jobs.Attempt) string {
	if attempt == nil || len(attempt.Verification) == 0 {
		return ""
	}
	verifier := action.Verifier()
	if verifier == opspec.VerifierNone || verifier.PanelSettled() {
		return ""
	}
	var observation struct {
		Verifier string `json:"verifier"`
		Verified bool   `json:"verified"`
		Expected string `json:"expected"`
		Observed string `json:"observed"`
		Reason   string `json:"reason"`
	}
	if err := json.Unmarshal(attempt.Verification, &observation); err != nil || observation.Verified {
		return ""
	}
	reason := observation.Reason
	if reason == "" {
		reason = fmt.Sprintf("the verifier %s expected %s and found %s",
			orDefault(observation.Verifier, string(verifier)),
			orDefault(observation.Expected, "the state of the order"),
			orDefault(observation.Observed, "something else"))
	}
	return "the change was made and the host does not show the state asked for: " + reason
}

// afterRemediation settles a host of a fleet remediation from the state of its
// plan.
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
func rebootNeeded(campaign Campaign, detail json.RawMessage) bool {
	switch RebootPolicy(campaign.RebootPolicy) {
	case RebootNever:
		return false
	case RebootAlways:
		return true
	}
	if len(detail) == 0 {
		return false
	}
	var parsed struct {
		Kind           string `json:"kind"`
		RebootRequired bool   `json:"reboot_required"`
	}
	if err := json.Unmarshal(detail, &parsed); err != nil {
		return false
	}
	return parsed.Kind == "package_apply" && parsed.RebootRequired
}

// afterReboot waits for the host to come back with a new boot ID and orders
// the health check.
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

// orderHealthCheck orders the verification of the campaign's units on a host
// whose change is done: right after the change when no reboot follows, or once
// the host came back from one.
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
// target entered the rebooting state.
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

// rebootVerdict is the judgement on a host that has not come back from its
// reboot: Waiting while the campaign still waits for it, otherwise the code
// and the message the host is closed with.
type rebootVerdict struct {
	Waiting bool
	Code    string
	Message string
}

// judgeReboot decides whether a host away since the given moment is still
// waited for, from the campaign's maintenance window and its reboot timeout.
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
		// A failed health check is a failure of the host in the campaign: the change
		// was carried out, but the host did not return to a working state.
		state, code := TargetFailed, "health_check_failed"
		if job.ResultErrorCode == ConnectivityLostCode {
			// The change landed and nobody saw the units after it: the host is unknown,
			// not failed, and the compensation count still reads its change step as
			// landed.
			state, code = TargetUnknown, ConnectivityLostCode
		}
		o.finishTarget(ctx, campaign, target, state, code,
			stepReason(job.ResultErrorCode, job.ResultMessage))
		return nil
	}
	o.finishTarget(ctx, campaign, target, TargetSucceeded, "", "the health check passed")
	return nil
}

// finishTarget settles a host in a campaign and records that in the audit
// trail.
func (o *Orchestrator) finishTarget(ctx context.Context, campaign Campaign, target *Target,
	state TargetState, errorCode, message string) {
	o.finishTargetSteps(ctx, campaign, target, state, errorCode, message,
		settledOutcomes(campaign, target, state, errorCode, message)...)
}

// finishTargetSteps settles a host together with the named outcomes of its
// steps, in one transaction: a target cannot end with its step left open, and
// a step cannot close without the target that carried it.
func (o *Orchestrator) finishTargetSteps(ctx context.Context, campaign Campaign, target *Target,
	state TargetState, errorCode, message string, outcomes ...stepOutcome) {
	revision, err := o.settleTarget(ctx, campaign, target, state, errorCode, message, outcomes)
	if err != nil {
		o.log.Error("the state of a campaign target was not recorded",
			"campaign_id", campaign.ID, "host_id", target.HostID, "err", err)
		return
	}
	target.Revision = revision
	target.State = state
	// The code stays on the target in memory as it is in the row: the pass that
	// settled the host reads it back to decide whether the campaign goes on.
	target.ErrorCode = errorCode
	target.Message = message
	// The tokens go back to the pool together with the end of the host.
	o.releaseCapacity(ctx, target)

	outcome := audit.OutcomeSuccess
	if state == TargetFailed || state == TargetUnknown {
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
// crossed.
func (o *Orchestrator) pauseOnThreshold(ctx context.Context, campaign Campaign, targets []Target,
	reason string, failed, finished int) error {
	if err := o.pause(ctx, &campaign, targets, reason); err != nil {
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

// pauseOnWindowClosed holds a campaign back once a host was still rebooting
// when the maintenance window ended.
func (o *Orchestrator) pauseOnWindowClosed(ctx context.Context, campaign Campaign, targets []Target,
	hostIDs []string) error {
	// The judgement only closes a host this way under a window with an
	// end; the guard is for a row somebody settled by hand with the code.
	ended := "an unknown time"
	if campaign.MaintenanceEnd != nil {
		ended = campaign.MaintenanceEnd.UTC().Format(time.RFC3339)
	}
	reason := fmt.Sprintf("%s: %d hosts were still rebooting when the maintenance window ended at %s",
		PauseWindowClosedMidReboot, len(hostIDs), ended)
	if err := o.pause(ctx, &campaign, targets, reason); err != nil {
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

// pause holds a campaign back by the machinery's own decision - a threshold
// crossed, a window closed, sessions lost.
func (o *Orchestrator) pause(ctx context.Context, campaign *Campaign, targets []Target, reason string) error {
	return o.store.SetState(ctx, campaign, pauseState(targets), reason)
}

// complete closes a campaign whose hosts have all settled and records the
// report in the audit trail.
func (o *Orchestrator) complete(ctx context.Context, campaign Campaign, targets []Target) error {
	state := settleCampaignState(tallyTargets(targets))
	if err := o.store.SetState(ctx, &campaign, state, ""); err != nil {
		return err
	}
	// The hosts gave their tokens back as they finished one by one.
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

// withCompensation adds the compensated campaign to an audit detail when there
// is one: the trail of the original is to lead to the campaign that undid it,
// and the trail of the compensation to what it undid.
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
func (o *Orchestrator) settleTarget(ctx context.Context, campaign Campaign, target *Target,
	state TargetState, errorCode, message string, outcomes []stepOutcome) (int64, error) {
	tx, err := o.store.Pool().Begin(ctx)
	if err != nil {
		return 0, err
	}
	defer func() { _ = tx.Rollback(ctx) }()

	revision, err := o.store.UpdateTargetTx(ctx, tx, target, state, errorCode, message)
	if err != nil {
		return 0, err
	}
	for _, outcome := range outcomes {
		settled, err := o.store.FinishStep(ctx, tx, target.ID, outcome.Key, outcome.State, outcome.Reason)
		if err != nil {
			return 0, err
		}
		if settled {
			continue
		}
		if err := o.store.RecordStep(ctx, tx, StepRecord{
			Target: *target, Key: outcome.Key,
			DependsOn: dependencyOf(outcome.Key, campaignPlans(campaign), target.RebootJobID != nil),
			State:     outcome.State, Reason: outcome.Reason,
		}); err != nil {
			return 0, err
		}
	}
	if campaign.CompensatesCampaignID != "" && state.Finished() {
		if err := o.closeCompensation(ctx, tx, campaign, target, state, errorCode, message); err != nil {
			return 0, err
		}
	}
	if err := tx.Commit(ctx); err != nil {
		return 0, err
	}
	return revision, nil
}

// openCompensation records, on the original campaign's target for the same
// host, that its compensation started.
func (o *Orchestrator) openCompensation(ctx context.Context, tx pgx.Tx, originalID string,
	target *Target, start stepStart) error {
	original, found, err := o.store.compensatedTarget(ctx, tx, originalID, target.HostID)
	if err != nil {
		return err
	}
	if !found {
		// The order was checked against the original's snapshot; a host missing from
		// it now has left the fleet, and the compensating campaign's own step says
		// what happened on it.
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
// where it came from.
func compensationNote(campaignID string) string {
	return "compensated by campaign " + campaignID
}

// closeCompensation settles the compensate step the compensating target opened
// on the original's target, with the outcome of the compensating change.
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
	// Closes are the steps that ended for this one to start.
	Closes []stepOutcome
	// Planned says whether the hosts of the campaign computed a plan step; it
	// places a step recorded from Closes on the strip.
	Planned bool
	// Compensates names the campaign whose change on this host the step undoes;
	// set on the change step of a compensating campaign only.
	Compensates string
}

// startStep orders a step: it binds the task, moves the target into the state
// the step runs in and opens the step row - in one transaction, so that the
// target and its step never disagree about what is under way.
func (o *Orchestrator) startStep(ctx context.Context, target *Target, start stepStart) error {
	tx, err := o.store.Pool().Begin(ctx)
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback(ctx) }()
	revision, err := o.startStepTx(ctx, tx, target, start)
	if err != nil {
		return err
	}
	if err := tx.Commit(ctx); err != nil {
		return err
	}
	o.applyStart(target, start, revision)
	return nil
}

// startStepTx writes the start of a step inside the caller's transaction and
// returns the revision the target will carry once it commits.
func (o *Orchestrator) startStepTx(ctx context.Context, tx pgx.Tx, target *Target, start stepStart) (int64, error) {
	for _, done := range start.Closes {
		settled, err := o.store.FinishStep(ctx, tx, target.ID, done.Key, done.State, done.Reason)
		if err != nil {
			return 0, err
		}
		if settled {
			continue
		}
		if err := o.store.RecordStep(ctx, tx, StepRecord{
			Target: *target, Key: done.Key,
			DependsOn: dependencyOf(done.Key, start.Planned, target.RebootJobID != nil),
			State:     done.State, Reason: done.Reason,
		}); err != nil {
			return 0, err
		}
	}
	if start.Column != "" {
		if err := o.store.AttachJobTx(ctx, tx, target, start.Column, start.JobID); err != nil {
			return 0, err
		}
	}
	if start.BootID != nil {
		if err := o.store.SetBootIDBeforeTx(ctx, tx, target, *start.BootID); err != nil {
			return 0, err
		}
	}
	revision, err := o.store.UpdateTargetTx(ctx, tx, target, start.State, "", start.Message)
	if err != nil {
		return 0, err
	}
	if err := o.store.StartStep(ctx, tx, StepRecord{
		Target: *target, Key: start.Key, DependsOn: start.DependsOn,
		PlanHash: start.PlanHash, JobID: start.JobID, Reason: start.Note,
	}); err != nil {
		return 0, err
	}
	if start.Compensates != "" {
		if err := o.openCompensation(ctx, tx, start.Compensates, target, start); err != nil {
			return 0, err
		}
	}
	return revision, nil
}

// applyStart copies a committed start onto the target in memory: the state the
// step runs in, the revision the row carries now, the task and the boot ID, so
// the rest of the pass reads the host as the database has it.
func (o *Orchestrator) applyStart(target *Target, start stepStart, revision int64) {
	target.Revision = revision
	target.State = start.State
	target.ErrorCode = ""
	target.Message = start.Message
	if start.BootID != nil {
		target.BootIDBefore = *start.BootID
	}
	if start.Column != "" && start.JobID != "" {
		jobID := start.JobID
		switch start.Column {
		case "job_id":
			target.JobID = &jobID
		case "reboot_job_id":
			target.RebootJobID = &jobID
		case "health_job_id":
			target.HealthJobID = &jobID
		case "plan_job_id":
			target.PlanJobID = &jobID
		}
	}
}

// campaignPlans says whether the targets of this campaign have a plan step of
// their own before the change: computed on the host, or split from the order
// in the panel, which opens and closes the step without a task.
func campaignPlans(campaign Campaign) bool {
	return opspec.CampaignPlans(opspec.ActionType(campaign.ActionType))
}
