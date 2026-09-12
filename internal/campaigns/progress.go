package campaigns

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	"github.com/ultherego/flotestro/internal/audit"
	"github.com/ultherego/flotestro/internal/jobs"
	"github.com/ultherego/flotestro/internal/opspec"
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
	default:
		return nil
	}
}

// afterMainJob reacts to the result of the main task and decides about a reboot.
func (o *Orchestrator) afterMainJob(ctx context.Context, campaign Campaign, target *Target) error {
	if target.JobID == nil {
		return nil
	}
	job, err := o.jobs.Get(ctx, *target.JobID)
	if err != nil {
		return err
	}
	if !jobs.State(job.State).Terminal() {
		return nil
	}
	if job.State != jobs.StateSucceeded {
		o.finishTarget(ctx, campaign, target, TargetFailed,
			job.ResultErrorCode, job.ResultMessage)
		return nil
	}

	needsReboot, err := o.rebootNeeded(ctx, campaign, *target.JobID)
	if err != nil {
		return err
	}
	if !needsReboot {
		o.finishTarget(ctx, campaign, target, TargetSucceeded, "", "")
		return nil
	}

	host, err := o.hosts.Get(ctx, target.HostID)
	if err != nil {
		o.finishTarget(ctx, campaign, target, TargetFailed, "host_unavailable", err.Error())
		return nil
	}
	// The boot ID from before the reboot is the only certain proof that the
	// host really came back rather than merely failed to disconnect in
	// time.
	if err := o.store.SetBootIDBefore(ctx, target.ID, host.BootID); err != nil {
		return err
	}
	target.BootIDBefore = host.BootID

	rebootJobID, err := o.submitJob(ctx, campaign, host, opspec.ActionSystemReboot,
		opspec.Payload{Reboot: &opspec.RebootPayload{
			DelaySeconds: 15,
			Reason:       "Flotestro: campaign " + campaign.Name,
		}}, "campaign:"+campaign.ID+":reboot:"+target.HostID)
	if err != nil {
		o.finishTarget(ctx, campaign, target, TargetFailed, "reboot_create_failed", err.Error())
		return nil
	}
	if err := o.store.AttachJob(ctx, target.ID, "reboot_job_id", rebootJobID); err != nil {
		return err
	}
	if err := o.store.UpdateTarget(ctx, target.ID, TargetRebooting, "", "a reboot was scheduled"); err != nil {
		return err
	}
	target.State = TargetRebooting

	o.log.Info("the campaign orders a reboot of a host",
		"campaign_id", campaign.ID, "host_id", target.HostID, "job_id", rebootJobID)
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
		if o.rebootTimedOut(target) {
			o.finishTarget(ctx, campaign, target, TargetFailed, "reboot_timeout",
				"the host did not come back after the reboot within the given time")
		}
		return nil
	}

	if len(campaign.HealthCheckUnits) == 0 {
		o.finishTarget(ctx, campaign, target, TargetSucceeded, "", "the host came back after the reboot")
		return nil
	}

	healthJobID, err := o.submitJob(ctx, campaign, host, opspec.ActionUnitStatus,
		opspec.Payload{UnitStatus: &opspec.UnitStatusPayload{Units: campaign.HealthCheckUnits}},
		"campaign:"+campaign.ID+":health:"+target.HostID+":"+host.BootID)
	if err != nil {
		o.finishTarget(ctx, campaign, target, TargetFailed, "health_create_failed", err.Error())
		return nil
	}
	if err := o.store.AttachJob(ctx, target.ID, "health_job_id", healthJobID); err != nil {
		return err
	}
	if err := o.store.UpdateTarget(ctx, target.ID, TargetVerifying, "", "the host came back, verification is under way"); err != nil {
		return err
	}
	target.State = TargetVerifying

	o.log.Info("the host came back after the reboot, verification is under way",
		"campaign_id", campaign.ID, "host_id", target.HostID, "boot_id", host.BootID)
	return nil
}

// rebootTimeout bounds the wait for the host to come back. Without it the
// campaign would wait forever for a machine that never came up.
const rebootTimeout = 15 * time.Minute

func (o *Orchestrator) rebootTimedOut(target *Target) bool {
	if target.StartedAt == nil {
		return false
	}
	return time.Since(*target.StartedAt) > rebootTimeout
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
		// state.
		o.finishTarget(ctx, campaign, target, TargetFailed,
			firstNonEmpty(job.ResultErrorCode, "health_check_failed"), job.ResultMessage)
		return nil
	}
	o.finishTarget(ctx, campaign, target, TargetSucceeded, "", "the health check passed")
	return nil
}

// finishTarget settles a host in a campaign and records that in the audit trail.
func (o *Orchestrator) finishTarget(ctx context.Context, campaign Campaign, target *Target,
	state TargetState, errorCode, message string) {
	if err := o.store.UpdateTarget(ctx, target.ID, state, errorCode, message); err != nil {
		o.log.Error("the state of a campaign target was not recorded",
			"campaign_id", campaign.ID, "host_id", target.HostID, "err", err)
		return
	}
	target.State = state
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
		Detail: map[string]any{
			"campaign_id": campaign.ID, "wave": target.Wave,
			"error_code": errorCode, "message": message,
		},
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

func firstNonEmpty(values ...string) string {
	for _, value := range values {
		if value != "" {
			return value
		}
	}
	return ""
}
