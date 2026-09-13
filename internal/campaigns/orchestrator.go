package campaigns

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"time"

	"github.com/ultherego/flotestro/internal/audit"
	"github.com/ultherego/flotestro/internal/authz"
	"github.com/ultherego/flotestro/internal/budgets"
	"github.com/ultherego/flotestro/internal/hosts"
	"github.com/ultherego/flotestro/internal/jobs"
	"github.com/ultherego/flotestro/internal/opspec"
)

// Orchestrator runs campaigns: the canary, the waves, the stop thresholds
// and the reboot phase with verification. It carries out nothing itself - it
// creates the tasks the scheduler delivers.
type Orchestrator struct {
	store *Store
	jobs  *jobs.Store
	hosts *hosts.Store
	audit *audit.Recorder
	// budgets guard the capacity of the fleet and of the sites. A campaign's
	// concurrency limit answers a different question: how many hosts are to
	// start at once within this change. Ten campaigns of five hosts each are
	// still fifty simultaneous mutations nobody decided on.
	budgets  *budgets.Store
	log      *slog.Logger
	interval time.Duration
	// Authorizer re-checks, immediately before a host is dispatched, that
	// the creator still holds the right to this operation on this host.
	// A permission withdrawn after the approval must stop the hosts that
	// have not started. Nil skips the check, for tests of the machinery.
	Authorizer Authorizer
}

// Authorizer answers whether a subject holds a permission in a scope now.
type Authorizer interface {
	PrincipalBySubject(ctx context.Context, subject string) (*authz.Principal, error)
}

func NewOrchestrator(store *Store, jobStore *jobs.Store, hostStore *hosts.Store,
	recorder *audit.Recorder, budgetStore *budgets.Store, log *slog.Logger,
	interval time.Duration) *Orchestrator {
	if interval <= 0 {
		interval = 5 * time.Second
	}
	return &Orchestrator{store: store, jobs: jobStore, hosts: hostStore,
		audit: recorder, budgets: budgetStore, log: log, interval: interval}
}

// Run drives the campaigns until the context is closed.
func (o *Orchestrator) Run(ctx context.Context) {
	ticker := time.NewTicker(o.interval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			o.tick(ctx)
		}
	}
}

func (o *Orchestrator) tick(ctx context.Context) {
	active, err := o.store.Active(ctx)
	if err != nil {
		o.log.Error("the active campaigns could not be read", "err", err)
		return
	}
	for _, campaign := range active {
		if err := o.advance(ctx, campaign); err != nil {
			o.log.Error("failure while running a campaign", "campaign_id", campaign.ID, "err", err)
		}
	}
}

// advance moves a campaign forward by one step.
func (o *Orchestrator) advance(ctx context.Context, campaign Campaign) error {
	targets, err := o.store.Targets(ctx, campaign.ID)
	if err != nil {
		return err
	}

	// The planning phase is a separate way: nothing changes yet, so there are
	// no waves, no thresholds and no campaign concurrency limit.
	if campaign.State == StatePlanning {
		return o.plan(ctx, campaign, targets)
	}

	// We renew the token leases before settling anything: a host that is just
	// finishing will give them back in a moment anyway, and a host halfway
	// through a transaction must not lose them to the passage of time.
	o.renewCapacity(ctx, targets)

	// First we settle what is already running: without that the thresholds
	// would be computed against a stale state.
	for i := range targets {
		if err := o.progressTarget(ctx, campaign, &targets[i]); err != nil {
			o.log.Error("failure while handling a campaign target",
				"campaign_id", campaign.ID, "host_id", targets[i].HostID, "err", err)
		}
	}

	failed, finished, lost := 0, 0, 0
	for _, target := range targets {
		if target.State.Finished() {
			finished++
		}
		if target.State == TargetFailed {
			failed++
		}
		if target.ConnectivityLost() {
			lost++
		}
	}

	// We check the stop threshold before starting anything new.
	if exceeded, reason := ThresholdExceeded(failed, finished, len(targets),
		campaign.FailureThresholdPercent, campaign.FailureThresholdAbsolute); exceeded {
		return o.pauseOnThreshold(ctx, campaign, reason, failed, finished)
	}
	// A lost session is a different signal from a failed change: a firewall
	// campaign that cuts hosts off looks like hosts that merely stopped
	// answering. It has its own threshold, and the first case can be enough.
	if campaign.ConnectivityLostAbsolute > 0 && lost >= campaign.ConnectivityLostAbsolute {
		return o.pauseOnConnectivityLoss(ctx, campaign, lost)
	}

	if allFinished(targets) {
		return o.complete(ctx, campaign, targets, failed)
	}

	// The hosts waiting for their connection are looked at on every pass,
	// whatever wave they belong to: one that came back goes to the queue,
	// one that did not by the deadline is closed.
	if err := o.serviceOfflineQueue(ctx, campaign, targets); err != nil {
		return err
	}

	// A maintenance window holds back the start of new hosts but does not
	// interrupt those already working.
	if !WithinMaintenanceWindow(time.Now(), campaign.MaintenanceStart, campaign.MaintenanceEnd) {
		return nil
	}

	wave := currentWave(targets)
	if wave < 0 {
		// Everything is settled or queued offline: nothing to start until a
		// host comes back or the deadline closes the queue.
		return nil
	}
	// A wave starts only once the previous one is settled in full. The canary
	// is wave zero, so the same rule gives the canary stage the document
	// requires.
	if !waveFinished(targets, wave-1) {
		return nil
	}

	// The manual gate: the canary is settled and the campaign asked for a
	// decision before the waves. Nothing starts until somebody advances it;
	// the gate opens once, and a canary host coming back from being offline
	// later does not close it again.
	if wave > 0 && campaign.ManualGate && campaign.GateAdvancedAt == nil {
		return o.enterGate(ctx, campaign)
	}

	desiredState := StateRunning
	// The canary phase is entered once. A canary host that comes back from
	// being offline while the waves run is started under the running state,
	// not by turning the campaign back into a canary.
	if wave == 0 && campaign.State != StateRunning {
		desiredState = StateCanary
	}
	if campaign.State != desiredState {
		if err := o.store.SetState(ctx, campaign.ID, desiredState, ""); err != nil {
			return err
		}
		o.log.Info("the campaign enters a phase",
			"campaign_id", campaign.ID, "phase", desiredState, "wave", wave)
	}

	return o.launchWave(ctx, campaign, targets, wave)
}

// launchWave starts the hosts of the current wave within the concurrency limit.
func (o *Orchestrator) launchWave(ctx context.Context, campaign Campaign,
	targets []Target, wave int) error {
	running := 0
	for _, target := range targets {
		// A host waiting for a budget takes no concurrency slot: it is doing
		// nothing yet, and counted as working it would block a wave that has
		// free capacity elsewhere.
		if target.Wave == wave && !target.State.Finished() && !target.State.Waiting() {
			running++
		}
	}

	for i := range targets {
		target := &targets[i]
		if target.Wave != wave || !target.State.Waiting() {
			continue
		}
		// A host waiting for its connection belongs to the offline queue,
		// which is walked before the wave: it comes back here as pending -
		// or, under replan_on_reconnect, only after its plan is checked.
		if target.State == TargetQueuedOffline {
			continue
		}
		if running >= campaign.MaxConcurrent {
			return nil
		}

		host, err := o.hosts.Get(ctx, target.HostID)
		if err != nil {
			o.finishTarget(ctx, campaign, target, TargetSkipped, "host_unavailable", err.Error())
			continue
		}
		// A disconnected host is handled by the campaign's offline policy:
		// skipped with a reason, or queued without a slot until it comes
		// back. Passing it over in silence would leave the wave standing
		// still with no reason given.
		if host.ConnectionState != "online" {
			if err := o.holdOffline(ctx, campaign, target, host); err != nil {
				return err
			}
			continue
		}
		// The creator's right is checked again, per host, right before the
		// dispatch: the approval was given hours ago, and a role withdrawn
		// since then must not carry a change onto the host through a
		// campaign that was ordered while it was still held.
		if refused, detail := o.creatorMayDispatch(ctx, campaign, host); refused {
			o.finishTarget(ctx, campaign, target, TargetSkipped, "out_of_scope", detail)
			continue
		}
		// A maintenance window means "somebody is working on this machine".
		// The campaign does not wait for it to end; it skips the host and
		// says so outright: otherwise a wave would stand still because of a
		// host that is under repair.
		if host.Maintenance.Active(time.Now().UTC()) {
			o.finishTarget(ctx, campaign, target, TargetSkipped, "maintenance",
				"the host is in a maintenance window until "+host.Maintenance.Until.Format(time.RFC3339))
			continue
		}

		// We ask for capacity only here: the host is connected, outside a
		// maintenance window and really ready to start. A token taken earlier
		// would reduce the fleet's capacity for somebody who could have used
		// it.
		free, err := o.takeCapacity(ctx, campaign, target, host)
		if err != nil {
			return err
		}
		if !free {
			continue
		}

		jobID, err := o.createJob(ctx, campaign, target, host)
		if err != nil {
			// The task was not created, so the tokens have nothing to guard.
			o.releaseCapacity(ctx, target)
			code := "job_create_failed"
			if errors.Is(err, ErrPlanExpired) {
				code = "plan_stale"
			}
			o.finishTarget(ctx, campaign, target, TargetFailed, code, err.Error())
			continue
		}
		if err := o.store.AttachJob(ctx, target.ID, "job_id", jobID); err != nil {
			return err
		}
		if err := o.store.SetBootIDBefore(ctx, target.ID, host.BootID); err != nil {
			return err
		}
		if err := o.store.UpdateTarget(ctx, target.ID, TargetRunning, "", ""); err != nil {
			return err
		}
		target.State = TargetRunning
		running++

		o.log.Info("the campaign started a host",
			"campaign_id", campaign.ID, "host_id", target.HostID,
			"wave", wave, "job_id", jobID)
	}
	return nil
}

// creatorMayDispatch says whether the campaign's creator still holds
// campaign.create and the operation's permission in the scope of the host.
// A campaign is created by an identity; the target rows carry no rights
// of their own.
func (o *Orchestrator) creatorMayDispatch(ctx context.Context, campaign Campaign, host *hosts.Host) (bool, string) {
	if o.Authorizer == nil {
		return false, ""
	}
	principal, err := o.Authorizer.PrincipalBySubject(ctx, campaign.CreatedBy)
	if errors.Is(err, authz.ErrUnauthenticated) {
		return true, "the identity that ordered the campaign (" + campaign.CreatedBy + ") is disabled or gone"
	}
	if err != nil {
		// Missing knowledge about the rights must not weaken the control;
		// the host waits for the next tick rather than starting unchecked.
		o.log.Error("the creator's rights could not be checked before the dispatch",
			"campaign_id", campaign.ID, "host_id", host.ID, "err", err)
		return true, "the rights of " + campaign.CreatedBy + " could not be checked: " + err.Error()
	}
	scope := authz.Scope{Site: host.Site, Environment: host.Environment}
	action := opspec.ActionType(campaign.ActionType)
	for _, permission := range []authz.Permission{authz.PermCampaignCreate, authz.Permission(action.Permission())} {
		if !principal.Can(permission, scope) {
			return true, campaign.CreatedBy + " no longer holds " + string(permission) +
				" on " + host.Site + "/" + host.Environment
		}
	}
	return false, ""
}

// createJob creates the campaign's main task for a host.
func (o *Orchestrator) createJob(ctx context.Context, campaign Campaign,
	target *Target, host *hosts.Host) (string, error) {
	var payload opspec.Payload
	if len(campaign.Payload) > 0 {
		if err := json.Unmarshal(campaign.Payload, &payload); err != nil {
			return "", err
		}
	}
	action := opspec.ActionType(campaign.ActionType)

	// A change computed per host travels with that host's plan digest. The
	// host compares it with the state it has now and refuses when the plan
	// has gone stale - the consent concerned that diff, not this one.
	if opspec.PlanningAction(action) != "" {
		hash, plan, computedAt, err := o.store.HostPlan(ctx, campaign.ID, target.HostID)
		if err != nil {
			return "", err
		}
		if hash == "" {
			return "", fmt.Errorf("the host %s has no computed plan", target.HostID)
		}
		// The digest still matches what was approved, but the world the
		// plan described is a day old: a plan computed before a weekend of
		// vendor updates would carry a different change than the approver
		// read. The host compares digests too; this is the bound in time.
		if age := time.Since(computedAt); age > PlanTTL {
			return "", fmt.Errorf("%w: computed %s ago, the limit is %s",
				ErrPlanExpired, age.Round(time.Minute), PlanTTL)
		}
		payload = withPlan(action, payload, hash, plan)
	}

	return o.submitJob(ctx, campaign, host, action, payload,
		"campaign:"+campaign.ID+":main:"+target.HostID)
}

// submitJob creates a task approved by the campaign. Approving a campaign is
// approving its tasks: the operator does not click every host separately.
func (o *Orchestrator) submitJob(ctx context.Context, campaign Campaign, host *hosts.Host,
	action opspec.ActionType, payload opspec.Payload, idempotencyKey string) (string, error) {
	tx, err := o.jobs.Pool().Begin(ctx)
	if err != nil {
		return "", err
	}
	defer func() { _ = tx.Rollback(ctx) }()

	job, err := o.jobs.Create(ctx, tx, jobs.Spec{
		HostID:           host.ID,
		Action:           action,
		Payload:          payload,
		IdempotencyKey:   idempotencyKey,
		RequiresApproval: false,
		TimeoutSeconds:   campaign.JobTimeoutSeconds,
		TTL:              time.Duration(campaign.JobTimeoutSeconds+600) * time.Second,
		CreatedBy:        "campaign:" + campaign.Name,
		RequestID:        campaign.RequestID,
		CampaignID:       campaign.ID,
		Preconditions: jobs.Preconditions{
			OSFamily:             host.OSFamily,
			RequiredCapabilities: []string{action.RequiredCapability()},
		},
	})
	if err != nil {
		return "", err
	}
	if err := o.audit.RecordTx(ctx, tx, audit.Event{
		ActorType: audit.ActorSystem, ActorID: "campaign:" + campaign.ID,
		Action: "job.create", TargetType: "job", TargetID: job.ID,
		RequestID: campaign.RequestID, Outcome: audit.OutcomeSuccess,
		Detail: map[string]any{
			"campaign_id": campaign.ID, "host_id": host.ID,
			"action_type": string(action), "approved_by": campaign.ApprovedBy,
		},
	}); err != nil {
		return "", err
	}
	if err := tx.Commit(ctx); err != nil {
		return "", err
	}
	return job.ID, nil
}

func allFinished(targets []Target) bool {
	for _, target := range targets {
		if !target.State.Finished() {
			return false
		}
	}
	return true
}

// currentWave returns the lowest wave that still has targets to start or
// to settle. A host queued offline does not hold its wave: it is looked
// after separately and joins the queue again when it comes back.
func currentWave(targets []Target) int {
	wave := -1
	for _, target := range targets {
		if !target.State.HoldsWave() {
			continue
		}
		if wave < 0 || target.Wave < wave {
			wave = target.Wave
		}
	}
	return wave
}

// waveFinished says whether every target of the given wave is settled or
// waiting for its connection.
func waveFinished(targets []Target, wave int) bool {
	if wave < 0 {
		return true
	}
	for _, target := range targets {
		if target.Wave == wave && target.State.HoldsWave() {
			return false
		}
	}
	return true
}
