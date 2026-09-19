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
)

// holdOffline applies the campaign's offline policy to a host that was not
// connected when its turn came.
func (o *Orchestrator) holdOffline(ctx context.Context, campaign Campaign,
	target *Target, host *hosts.Host) error {
	detail := "the host is " + host.ConnectionState
	switch campaign.OfflinePolicy {
	case opspec.OfflineRequireOnline:
		o.finishTarget(ctx, campaign, target, TargetSkipped, "offline",
			detail+" and the policy require_online does not wait for it")
		return nil
	case opspec.OfflineSkip:
		o.finishTarget(ctx, campaign, target, TargetSkipped, "skipped_offline",
			detail+" and the policy skip_if_offline leaves it out")
		return nil
	}

	// A waiting policy. The deadline is checked here too: a host whose wave
	// came after the deadline has nothing to wait for.
	if pastDeadline(campaign, time.Now()) {
		o.finishTarget(ctx, campaign, target, TargetSkipped, "offline_deadline",
			detail+" and the campaign's deadline "+campaign.DeadlineAt.UTC().Format(time.RFC3339)+" has passed")
		return nil
	}
	if target.State == TargetQueuedOffline {
		return nil
	}
	until := "without a deadline"
	if campaign.DeadlineAt != nil {
		until = "until " + campaign.DeadlineAt.UTC().Format(time.RFC3339)
	}
	if err := o.store.UpdateTarget(ctx, target, TargetQueuedOffline, "offline",
		fmt.Sprintf("%s; the policy %s waits for it %s", detail, campaign.OfflinePolicy, until)); err != nil {
		return err
	}
	// A host that was waiting for a budget holds a place in the queue of
	// the budget; a host waiting for its connection holds none.
	o.releaseCapacity(ctx, target)
	o.log.Info("the campaign queued an offline host",
		"campaign_id", campaign.ID, "host_id", target.HostID,
		"policy", campaign.OfflinePolicy, "deadline", campaign.DeadlineAt)
	return nil
}

// pastDeadline says whether the campaign has stopped waiting for offline
// hosts.
func pastDeadline(campaign Campaign, now time.Time) bool {
	return campaign.DeadlineAt != nil && now.After(*campaign.DeadlineAt)
}

// serviceOfflineQueue looks after the hosts waiting for their connection.
func (o *Orchestrator) serviceOfflineQueue(ctx context.Context, campaign Campaign,
	targets []Target) error {
	now := time.Now()
	for i := range targets {
		target := &targets[i]
		if target.State != TargetQueuedOffline {
			continue
		}
		host, err := o.hosts.Get(ctx, target.HostID)
		if err != nil {
			o.finishTarget(ctx, campaign, target, TargetSkipped, "host_unavailable", err.Error())
			continue
		}
		if host.ConnectionState != "online" {
			if pastDeadline(campaign, now) {
				o.finishTarget(ctx, campaign, target, TargetSkipped, "offline_deadline",
					"the host is "+host.ConnectionState+" and the campaign's deadline "+
						campaign.DeadlineAt.UTC().Format(time.RFC3339)+" has passed")
			}
			continue
		}
		if campaign.OfflinePolicy == opspec.OfflineReplan {
			if err := o.replanTarget(ctx, campaign, target, host); err != nil {
				return err
			}
			continue
		}
		if err := o.store.UpdateTarget(ctx, target, TargetPending, "",
			"the host came back; waiting for its turn"); err != nil {
			return err
		}
		o.log.Info("an offline host came back to the campaign queue",
			"campaign_id", campaign.ID, "host_id", target.HostID)
	}
	return nil
}

// replanTarget orders the plan of a host again after it came back.
func (o *Orchestrator) replanTarget(ctx context.Context, campaign Campaign,
	target *Target, host *hosts.Host) error {
	change := opspec.ActionType(campaign.ActionType)
	action := opspec.PlanningAction(change)
	if action == "" {
		// The policy was validated against the registry, so this is a registry that
		// changed underneath a running campaign.
		o.finishTarget(ctx, campaign, target, TargetSkipped, "plan_changed_offline",
			"the operation has no planner any more, so the plan cannot be checked after the reconnect")
		return nil
	}
	var payload opspec.Payload
	if len(campaign.Payload) > 0 {
		if err := json.Unmarshal(campaign.Payload, &payload); err != nil {
			return err
		}
	}
	// The key names the plan this one follows: a host that goes offline
	// twice gets two re-plans, and two orchestrators get one.
	previous := "none"
	if target.PlanJobID != nil {
		previous = *target.PlanJobID
	}
	// The plan computed again is the next attempt of the same plan step: the
	// strip shows one plan with two attempts, not two plans.
	jobID, err := o.launch(ctx, &campaign, target,
		func(tx pgx.Tx) (string, error) {
			return o.submitJobTx(ctx, tx, campaign, host, action, planPayload(action, change, payload),
				"campaign:"+campaign.ID+":replan:"+target.HostID+":after:"+previous)
		},
		func(jobID string) stepStart {
			return stepStart{
				Key: StepPlan, JobID: jobID, Column: "plan_job_id", State: TargetPlanning,
				Message: "the host came back; its plan is computed again before the change",
			}
		})
	var refused *createRefusal
	if errors.As(err, &refused) {
		o.finishTarget(ctx, campaign, target, TargetFailed, "plan_create_failed", err.Error())
		return nil
	}
	if err != nil {
		return err
	}
	o.log.Info("the campaign is planning a returned host again",
		"campaign_id", campaign.ID, "host_id", target.HostID, "job_id", jobID)
	return nil
}

// afterReplan settles a host whose plan was computed again after a reconnect.
func (o *Orchestrator) afterReplan(ctx context.Context, campaign Campaign, target *Target) error {
	if target.PlanJobID == nil {
		return nil
	}
	job, err := o.jobs.Get(ctx, *target.PlanJobID)
	if err != nil {
		return err
	}
	if !jobs.State(job.State).Terminal() {
		return nil
	}
	if job.State != jobs.StateSucceeded {
		o.finishTarget(ctx, campaign, target, TargetFailed,
			orDefault(job.ResultErrorCode, "plan_failed"), job.ResultMessage)
		return nil
	}
	hash, plan, err := o.planFingerprint(ctx, *target.PlanJobID)
	if err != nil {
		return err
	}
	if hash == "" {
		o.finishTarget(ctx, campaign, target, TargetFailed, "plan_hash_missing",
			"the host gave no plan digest after the reconnect")
		return nil
	}
	if reason := planRefusal(plan); reason != "" {
		o.finishTarget(ctx, campaign, target, TargetIneligible, "plan_refused", reason)
		return nil
	}
	if planNoChange(plan) {
		// The host came back already in the desired state - somebody brought it
		// there while it was away.
		o.settleNoChange(ctx, campaign, target, hash)
		return nil
	}
	approved, _, _, err := o.store.HostPlan(ctx, campaign.ID, target.HostID)
	if err != nil {
		return err
	}
	if hash != approved {
		// The plan step did its work - the answer is a different plan.
		why := fmt.Sprintf("the plan computed after the reconnect (%s) differs from the approved one (%s); "+
			"the consent covered the old plan", shortHash(hash), shortHash(approved))
		o.finishTargetSteps(ctx, campaign, target, TargetSkipped, "plan_changed_offline", why,
			stepOutcome{Key: StepPlan, State: StepSucceeded, Reason: "plan " + shortHash(hash)},
			stepOutcome{Key: StepExecute, State: StepSkipped, Reason: stepReason("plan_changed_offline", why)})
		return nil
	}
	// The same plan, freshly verified: its age starts over, so the time
	// limit on plans does not stop a host that just proved its plan holds.
	if err := o.acceptPlan(ctx, campaign, target, hash, plan,
		"the plan still matches the approved one; waiting for its turn"); err != nil {
		return err
	}
	o.log.Info("a returned host confirmed its plan",
		"campaign_id", campaign.ID, "host_id", target.HostID, "plan_hash", hash)
	return nil
}

// shortHash trims a digest for a message. The full digests are in the plan
// records; a sentence needs only enough to tell them apart.
func shortHash(hash string) string {
	if len(hash) > 12 {
		return hash[:12]
	}
	if hash == "" {
		return "none"
	}
	return hash
}

// connectivityLost says whether a task ended because the session to the host
// broke while it ran, rather than because the change failed.
func (o *Orchestrator) connectivityLost(ctx context.Context, job *jobs.Job, target *Target) (bool, string, error) {
	switch job.State {
	case jobs.StateExpired:
		return true, "the task expired undelivered: the host lost its session after the dispatch", nil
	case jobs.StateTimedOut:
	default:
		return false, "", nil
	}
	attempts, err := o.jobs.Attempts(ctx, job.ID)
	if err != nil {
		return false, "", err
	}
	for _, attempt := range attempts {
		if attempt.Status == "lease_expired" {
			return true, "the session broke while the task ran: the lease expired without a result", nil
		}
	}
	host, err := o.hosts.Get(ctx, target.HostID)
	if err != nil {
		return false, "", err
	}
	if host.ConnectionState != "online" {
		return true, "the task timed out and the host is " + host.ConnectionState + " now", nil
	}
	return false, "", nil
}

// pauseOnConnectivityLoss holds a campaign back once too many hosts lost their
// session mid-task.
func (o *Orchestrator) pauseOnConnectivityLoss(ctx context.Context, campaign Campaign, targets []Target,
	lost int) error {
	reason := fmt.Sprintf("connectivity_lost: %d hosts lost their session while their task ran; the limit is %d",
		lost, campaign.ConnectivityLostAbsolute)
	if err := o.pause(ctx, &campaign, targets, reason); err != nil {
		return err
	}
	o.audit.Record(ctx, audit.Event{
		ActorType: audit.ActorSystem, ActorID: "campaign:" + campaign.ID,
		Action: "campaign.pause", TargetType: "campaign", TargetID: campaign.ID,
		RequestID: campaign.RequestID, Outcome: audit.OutcomeFailure,
		Detail: map[string]any{
			"reason": "connectivity_lost", "lost": lost,
			"threshold_connectivity_lost": campaign.ConnectivityLostAbsolute,
		},
	})
	o.log.Warn("the campaign was held back after hosts lost their session",
		"campaign_id", campaign.ID, "lost", lost, "threshold", campaign.ConnectivityLostAbsolute)
	return nil
}

// enterGate stops the campaign after the canary for a decision.
func (o *Orchestrator) enterGate(ctx context.Context, campaign Campaign) error {
	if campaign.State == StateManualGate {
		return nil
	}
	if err := o.store.SetState(ctx, &campaign, StateManualGate, ""); err != nil {
		return err
	}
	o.audit.Record(ctx, audit.Event{
		ActorType: audit.ActorSystem, ActorID: "campaign:" + campaign.ID,
		Action: "campaign.manual_gate", TargetType: "campaign", TargetID: campaign.ID,
		RequestID: campaign.RequestID, Outcome: audit.OutcomeSuccess,
		Detail: map[string]any{"canary_size": campaign.CanarySize},
	})
	o.log.Info("the campaign stops at the manual gate after the canary",
		"campaign_id", campaign.ID)
	return nil
}
