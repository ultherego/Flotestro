package campaigns

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"sync"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"github.com/ultherego/flotestro/internal/audit"
	"github.com/ultherego/flotestro/internal/authz"
	"github.com/ultherego/flotestro/internal/budgets"
	"github.com/ultherego/flotestro/internal/hosts"
	"github.com/ultherego/flotestro/internal/jobs"
	"github.com/ultherego/flotestro/internal/opspec"
	"github.com/ultherego/flotestro/internal/remediation"
)

// Orchestrator runs campaigns: the canary, the waves, the stop thresholds and
// the reboot phase with verification.
type Orchestrator struct {
	store *Store
	jobs  *jobs.Store
	hosts *hosts.Store
	audit *audit.Recorder
	// budgets guard the capacity of the fleet and of the sites.
	budgets *budgets.Store
	// remediation holds the plans of a fleet remediation.
	remediation *remediation.Store
	log         *slog.Logger
	interval    time.Duration
	// Authorizer re-checks, immediately before a host is dispatched, that the
	// creator still holds the right to this operation on this host.
	Authorizer Authorizer
	// runner names this orchestrator among the instances of the control plane.
	runner string
	// held lists the campaigns this runner holds the lease of, with the token, so
	// the leases can be given back when the process stops rather than run out
	// under the next instance's feet.
	mu   sync.Mutex
	held map[string]int64
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
		audit: recorder, budgets: budgetStore, log: log, interval: interval,
		remediation: remediation.NewStore(store.Pool()),
		runner:      uuid.NewString(), held: map[string]int64{}}
}

// Runner names this orchestrator: the identifier its claims are recorded
// under.
func (o *Orchestrator) Runner() string { return o.runner }

// Run drives the campaigns until the context is closed.
func (o *Orchestrator) Run(ctx context.Context) {
	ticker := time.NewTicker(o.interval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			o.releaseLeases()
			return
		case <-ticker.C:
			o.tick(ctx)
		}
	}
}

// releaseLeases gives back every runner lease this orchestrator holds.
func (o *Orchestrator) releaseLeases() {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	o.mu.Lock()
	defer o.mu.Unlock()
	for campaignID, token := range o.held {
		campaign := Campaign{ID: campaignID, RunnerID: o.runner, RunnerToken: token}
		if err := o.store.ReleaseRunner(ctx, &campaign); err != nil {
			o.log.Warn("the runner lease of a campaign was not released at shutdown",
				"campaign_id", campaignID, "err", err)
		}
		delete(o.held, campaignID)
	}
}

func (o *Orchestrator) tick(ctx context.Context) {
	active, err := o.store.Active(ctx)
	if err != nil {
		o.log.Error("the active campaigns could not be read", "err", err)
		return
	}
	seen := map[string]bool{}
	for _, campaign := range active {
		seen[campaign.ID] = true
		// One runner per campaign: the lease is taken or renewed before anything is
		// read, and a campaign another instance drives is left to it.
		token, held, err := o.store.ClaimRunner(ctx, campaign.ID, o.runner)
		if err != nil {
			o.log.Error("the runner lease of a campaign could not be claimed",
				"campaign_id", campaign.ID, "err", err)
			continue
		}
		if !held {
			o.forget(campaign.ID)
			continue
		}
		o.remember(campaign.ID, token)
		campaign.RunnerID = o.runner
		campaign.RunnerToken = token
		// A campaign waiting for its approval has no host to drive; its
		// targets are adopted once it is let through.
		if campaign.State != StateAwaitingApproval {
			if err := o.store.AdoptTargets(ctx, campaign.ID, o.runner); err != nil {
				o.log.Error("the targets of a campaign could not be adopted",
					"campaign_id", campaign.ID, "err", err)
				continue
			}
		}
		err = o.advance(ctx, campaign)
		switch {
		case err == nil:
		case errors.Is(err, ErrLeaseLost):
			// Another instance holds the campaign now; whatever this pass still meant
			// to write is its business.
			o.forget(campaign.ID)
			o.log.Warn("the runner lease of a campaign was lost during a pass",
				"campaign_id", campaign.ID)
		case errors.Is(err, ErrConcurrentTransition):
			// The campaign or one of its hosts moved under this pass - an operator
			// paused or canceled it, a result landed.
			o.log.Info("a campaign moved under the pass; it is read again on the next",
				"campaign_id", campaign.ID, "detail", err.Error())
		default:
			o.log.Error("failure while running a campaign", "campaign_id", campaign.ID, "err", err)
		}
	}
	// A campaign that left the active list - it finished, or the operator
	// closed it - is no longer held; its lease row went with it.
	o.mu.Lock()
	for campaignID := range o.held {
		if !seen[campaignID] {
			delete(o.held, campaignID)
		}
	}
	o.mu.Unlock()
}

func (o *Orchestrator) remember(campaignID string, token int64) {
	o.mu.Lock()
	defer o.mu.Unlock()
	o.held[campaignID] = token
}

func (o *Orchestrator) forget(campaignID string) {
	o.mu.Lock()
	defer o.mu.Unlock()
	delete(o.held, campaignID)
}

// leaseKeeper renews the runner lease of a campaign while a pass takes its
// time - a wave of many hosts, a slow database.
type leaseKeeper struct {
	campaign *Campaign
	renewed  time.Time
}

// keep renews the lease once the renewal interval has passed. It returns
// ErrLeaseLost when the lease is gone: the caller stops writing.
func (o *Orchestrator) keep(ctx context.Context, keeper *leaseKeeper) error {
	if time.Since(keeper.renewed) < RunnerLeaseRenewal {
		return nil
	}
	if err := o.store.RenewRunner(ctx, keeper.campaign); err != nil {
		return err
	}
	keeper.renewed = time.Now()
	return nil
}

// advance moves a campaign forward by one step.
func (o *Orchestrator) advance(ctx context.Context, campaign Campaign) error {
	// A campaign that has not started is watched for the age of its plans before
	// its targets are read: a campaign waiting for an approval is looked at on
	// every pass, and a thousand target rows read every five seconds to learn
	if campaign.State == StateAwaitingApproval || (campaign.State == StatePlanned && campaign.StartedAt == nil) {
		oldest, err := o.store.OldestPlan(ctx, campaign.ID)
		if err != nil {
			return err
		}
		if plansExpired(oldest, campaign.StartedAt, time.Now()) {
			return o.expire(ctx, campaign, oldest)
		}
		if campaign.State == StateAwaitingApproval {
			return nil
		}
	}

	targets, err := o.store.Targets(ctx, campaign.ID)
	if err != nil {
		return err
	}

	// The planning phase is a separate way: nothing changes yet, so there are
	// no waves, no thresholds and no campaign concurrency limit.
	if campaign.State == StatePlanning {
		return o.plan(ctx, campaign, targets)
	}
	// A canceled campaign with hosts still at work drains: the hosts settle,
	// nothing starts, and the campaign ends with the last of them.
	if campaign.State == StateCanceling {
		return o.drain(ctx, campaign, targets)
	}
	// A pausing or paused campaign is looked after the same way, without the end:
	// the hosts under way settle, nothing starts, and a pausing campaign is
	// paused once none is in flight.
	if campaign.State == StatePausing || campaign.State == StatePaused {
		return o.settle(ctx, campaign, targets)
	}

	// We renew the token leases before settling anything: a host that is just
	// finishing will give them back in a moment anyway, and a host halfway
	// through a transaction must not lose them to the passage of time.
	o.renewCapacity(ctx, targets)

	// First we settle what is already running: without that the thresholds would
	// be computed against a stale state.
	var windowClosed []string
	for i := range targets {
		open := !targets[i].State.Finished()
		if err := o.progressTarget(ctx, campaign, &targets[i]); err != nil {
			o.log.Error("failure while handling a campaign target",
				"campaign_id", campaign.ID, "host_id", targets[i].HostID, "err", err)
		}
		if open && targets[i].RebootWindowClosed() {
			windowClosed = append(windowClosed, targets[i].HostID)
		}
	}

	// The tally reads unknown hosts as failures: the threshold bounds the hosts
	// that did not reach the desired state, and an unknown one did not, as far as
	// anyone can tell.
	counts := tallyTargets(targets)
	failed, finished, lost := counts.Failed, counts.Finished, counts.Lost

	// A host that did not come back inside the window stops the campaign before
	// the threshold has its say: the reason the operator reads is to name the
	// window, not a percentage the window pushed over.
	if len(windowClosed) > 0 {
		return o.pauseOnWindowClosed(ctx, campaign, targets, windowClosed)
	}
	// We check the stop threshold before starting anything new.
	if exceeded, reason := ThresholdExceeded(failed, finished, len(targets),
		campaign.FailureThresholdPercent, campaign.FailureThresholdAbsolute); exceeded {
		return o.pauseOnThreshold(ctx, campaign, targets, reason, failed, finished)
	}
	// A lost session is a different signal from a failed change: a firewall
	// campaign that cuts hosts off looks like hosts that merely stopped
	// answering.
	if campaign.ConnectivityLostAbsolute > 0 && lost >= campaign.ConnectivityLostAbsolute {
		return o.pauseOnConnectivityLoss(ctx, campaign, targets, lost)
	}

	if allFinished(targets) {
		return o.complete(ctx, campaign, targets)
	}

	// The hosts waiting for their connection are looked at on every pass,
	// whatever wave they belong to: one that came back goes to the queue, one
	// that did not by the deadline is closed.
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
	// A wave starts only once the previous one is settled in full. The canary is
	// wave zero, so the same rule gives the canary stage the document requires.
	if !waveFinished(targets, wave-1) {
		return nil
	}

	// The manual gate: the canary is settled and the campaign asked for a
	// decision before the waves.
	if wave > 0 && campaign.ManualGate && campaign.GateAdvancedAt == nil {
		return o.enterGate(ctx, campaign)
	}

	desiredState := StateRunning
	// The canary phase is entered once.
	if wave == 0 && campaign.State != StateRunning {
		desiredState = StateCanary
	}
	if campaign.State != desiredState {
		if err := o.store.SetState(ctx, &campaign, desiredState, ""); err != nil {
			return err
		}
		o.log.Info("the campaign enters a phase",
			"campaign_id", campaign.ID, "phase", desiredState, "wave", wave)
	}

	return o.launchWave(ctx, campaign, targets, wave)
}

// settle looks after a pausing or paused campaign: the hosts carrying a task
// keep their leases and are followed to their end, nothing new starts, and a
// pausing campaign becomes paused once no host is in flight.
func (o *Orchestrator) settle(ctx context.Context, campaign Campaign, targets []Target) error {
	o.renewCapacity(ctx, targets)
	for i := range targets {
		if err := o.progressTarget(ctx, campaign, &targets[i]); err != nil {
			o.log.Error("failure while settling a host of a paused campaign",
				"campaign_id", campaign.ID, "host_id", targets[i].HostID, "err", err)
		}
	}
	if campaign.State != StatePausing || !cancelSettled(targets) {
		return nil
	}
	if err := o.store.SetState(ctx, &campaign, StatePaused, campaign.PauseReason); err != nil {
		return err
	}
	o.log.Info("the campaign finished pausing: no host carries a task any more",
		"campaign_id", campaign.ID)
	return nil
}

// launchWave starts the hosts of the current wave within the concurrency
// limit.
func (o *Orchestrator) launchWave(ctx context.Context, campaign Campaign,
	targets []Target, wave int) error {
	running := activeTargets(targets)
	if running >= campaign.MaxConcurrent {
		return nil
	}
	claimed, err := o.store.ClaimWaveTargets(ctx, campaign.ID, wave, o.runner, campaign.MaxConcurrent-running)
	if err != nil {
		return err
	}
	byID := make(map[string]*Target, len(targets))
	for i := range targets {
		byID[targets[i].ID] = &targets[i]
	}
	keeper := &leaseKeeper{campaign: &campaign, renewed: time.Now()}

	for _, claim := range claimed {
		target, known := byID[claim.ID]
		if !known || !target.State.Waiting() || target.State == TargetQueuedOffline {
			// The claim reads the queue as it is now; the pass read it a moment ago.
			continue
		}
		target.Revision = claim.Revision
		target.ClaimToken = claim.ClaimToken
		if running >= campaign.MaxConcurrent {
			return nil
		}
		if err := o.keep(ctx, keeper); err != nil {
			return err
		}

		host, err := o.hosts.Get(ctx, target.HostID)
		if err != nil {
			o.finishTarget(ctx, campaign, target, TargetSkipped, "host_unavailable", err.Error())
			continue
		}
		// A disconnected host is handled by the campaign's offline policy: skipped
		// with a reason, or queued without a slot until it comes back.
		if host.ConnectionState != "online" {
			if err := o.holdOffline(ctx, campaign, target, host); err != nil {
				return err
			}
			continue
		}
		// The creator's right is checked again, per host, right before the dispatch:
		// the approval was given hours ago, and a role withdrawn since then must not
		// carry a change onto the host through a campaign that was ordered while it
		if refused, detail := o.creatorMayDispatch(ctx, campaign, host); refused {
			o.finishTarget(ctx, campaign, target, TargetSkipped, "out_of_scope", detail)
			continue
		}
		// A maintenance window means "somebody is working on this machine".
		if host.Maintenance.Active(time.Now().UTC()) {
			o.finishTarget(ctx, campaign, target, TargetSkipped, "maintenance",
				"the host is in a maintenance window until "+host.Maintenance.Until.Format(time.RFC3339))
			continue
		}

		// We ask for capacity only here: the host is connected, outside a
		// maintenance window and really ready to start.
		free, err := o.takeCapacity(ctx, campaign, target, host)
		if err != nil {
			return err
		}
		if !free {
			continue
		}

		// A fleet remediation has no single task: the host's plan of steps starts in
		// the remediation store, and the runner carries it.
		if opspec.ActionType(campaign.ActionType) == opspec.ActionSecurityRemediate {
			if err := o.startRemediation(ctx, campaign, target, host); err != nil {
				return err
			}
			if target.State == TargetRunning {
				running++
			}
			continue
		}

		// The task, the boot ID, the transition and the step go in one transaction,
		// under the campaign's lock: a pause or a cancel committed a moment earlier
		// is seen, and no task comes into being for a campaign that stopped.
		var planHash string
		jobID, err := o.launch(ctx, &campaign, target,
			func(tx pgx.Tx) (string, error) {
				id, hash, err := o.createJob(ctx, tx, campaign, target, host)
				planHash = hash
				return id, err
			},
			func(jobID string) stepStart {
				return stepStart{
					Key: StepExecute, DependsOn: dependencyOf(StepExecute, campaignPlans(campaign), false),
					PlanHash: planHash, JobID: jobID, Column: "job_id", State: TargetDispatched,
					BootID: &host.BootID, Compensates: campaign.CompensatesCampaignID,
				}
			})
		var refused *createRefusal
		if errors.As(err, &refused) {
			// The task was not created, so the tokens have nothing to guard.
			o.releaseCapacity(ctx, target)
			code := "job_create_failed"
			if errors.Is(err, ErrPlanExpired) {
				code = "plan_stale"
			}
			o.finishTarget(ctx, campaign, target, TargetFailed, code, err.Error())
			continue
		}
		if err != nil {
			// The campaign stopped, or the lease is gone: the tokens go
			// back and the wave ends here. Nothing was created.
			o.releaseCapacity(ctx, target)
			return err
		}
		running++

		o.log.Info("the campaign started a host",
			"campaign_id", campaign.ID, "host_id", target.HostID,
			"wave", wave, "job_id", jobID)
	}
	return nil
}

// createRefusal says the task of a launch could not be created: the plan is
// stale, the payload does not validate, the host has no plan.
type createRefusal struct {
	err error
}

func (r *createRefusal) Error() string { return r.err.Error() }
func (r *createRefusal) Unwrap() error { return r.err }

// launch creates the task of a step and starts the step on the host in one
// transaction under the campaign's lock.
func (o *Orchestrator) launch(ctx context.Context, campaign *Campaign, target *Target,
	create func(tx pgx.Tx) (string, error), step func(jobID string) stepStart) (string, error) {
	tx, err := o.store.Pool().Begin(ctx)
	if err != nil {
		return "", err
	}
	defer func() { _ = tx.Rollback(ctx) }()

	if err := o.store.LockForLaunch(ctx, tx, campaign); err != nil {
		return "", err
	}
	jobID, err := create(tx)
	if err != nil {
		return "", &createRefusal{err: err}
	}
	start := step(jobID)
	revision, err := o.startStepTx(ctx, tx, target, start)
	if err != nil {
		return "", err
	}
	if err := tx.Commit(ctx); err != nil {
		return "", err
	}
	o.applyStart(target, start, revision)
	return jobID, nil
}

// creatorMayDispatch says whether the campaign's creator still holds campaign.
// create and the operation's permission in the scope of the host.
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
	scope := hosts.ScopeOf(host)
	action := opspec.ActionType(campaign.ActionType)
	for _, permission := range []authz.Permission{authz.PermCampaignCreate, authz.Permission(action.Permission())} {
		if !principal.Can(permission, scope) {
			return true, campaign.CreatedBy + " no longer holds " + string(permission) +
				" on " + host.Site + "/" + host.Environment
		}
	}
	return false, ""
}

// createJob creates the campaign's main task for a host inside the launch
// transaction.
func (o *Orchestrator) createJob(ctx context.Context, tx pgx.Tx, campaign Campaign,
	target *Target, host *hosts.Host) (string, string, error) {
	var payload opspec.Payload
	if len(campaign.Payload) > 0 {
		if err := json.Unmarshal(campaign.Payload, &payload); err != nil {
			return "", "", err
		}
	}
	action := opspec.ActionType(campaign.ActionType)

	// A change computed per host travels with that host's plan digest.
	var planHash string
	if opspec.CampaignPlans(action) {
		hash, plan, computedAt, err := o.store.HostPlan(ctx, campaign.ID, target.HostID)
		if err != nil {
			return "", "", err
		}
		if hash == "" {
			return "", "", fmt.Errorf("the host %s has no computed plan", target.HostID)
		}
		// The digest still matches what was approved, but the world the plan
		// described is a day old: a plan computed before a weekend of vendor updates
		// would carry a different change than the approver read.
		if age := time.Since(computedAt); age > PlanTTL && !opspec.PanelPlanned(action) {
			return "", "", fmt.Errorf("%w: computed %s ago, the limit is %s",
				ErrPlanExpired, age.Round(time.Minute), PlanTTL)
		}
		payload = withPlan(action, payload, hash, plan)
		planHash = hash
	}

	jobID, err := o.submitJobTx(ctx, tx, campaign, host, action, payload,
		"campaign:"+campaign.ID+":main:"+target.HostID)
	return jobID, planHash, err
}

// startRemediation starts a host's remediation plan from the campaign's plan
// set.
func (o *Orchestrator) startRemediation(ctx context.Context, campaign Campaign,
	target *Target, host *hosts.Host) error {
	fail := func(code, message string) {
		o.releaseCapacity(ctx, target)
		o.finishTarget(ctx, campaign, target, TargetFailed, code, message)
	}

	hash, raw, computedAt, err := o.store.HostPlan(ctx, campaign.ID, target.HostID)
	if err != nil {
		return err
	}
	if hash == "" {
		fail("plan_missing", "the host has no remediation plan in this campaign")
		return nil
	}
	if age := time.Since(computedAt); age > PlanTTL {
		fail("plan_stale", fmt.Sprintf("%v: computed %s ago, the limit is %s",
			ErrPlanExpired, age.Round(time.Minute), PlanTTL))
		return nil
	}
	plan, err := remediation.DecodeHostPlan(raw)
	if err != nil {
		fail("plan_invalid", err.Error())
		return nil
	}
	if refused, detail := o.creatorMayRemediate(ctx, campaign, host, plan); refused {
		o.releaseCapacity(ctx, target)
		o.finishTarget(ctx, campaign, target, TargetSkipped, "out_of_scope", detail)
		return nil
	}

	// The plan, its audit record, the transition and the step go in one
	// transaction under the campaign's lock, like the task of an ordinary host: a
	// pause committed a moment earlier is seen, and no plan comes into being for
	tx, err := o.remediation.Pool().Begin(ctx)
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback(ctx) }()
	if err := o.store.LockForLaunch(ctx, tx, &campaign); err != nil {
		o.releaseCapacity(ctx, target)
		return err
	}

	created, err := o.remediation.Create(ctx, tx, remediation.Spec{
		HostID:          host.ID,
		PlanHash:        plan.FindingsHash,
		PlanHashVersion: plan.FindingsHashVersion,
		Reason:          "campaign " + campaign.Name,
		CreatedBy:       remediation.CampaignCreator(campaign.ID),
		StopOnFailure:   true,
		BootIDBefore:    host.BootID,
	}, plan.FreshSteps())
	if errors.Is(err, remediation.ErrPlanRunning) {
		// Another plan holds the host - one ordered by hand, or a previous campaign
		// still at work.
		fail("plan_in_progress", "a remediation plan is already running on this host")
		return nil
	}
	if err != nil {
		return err
	}
	if err := o.audit.RecordTx(ctx, tx, audit.Event{
		ActorType: audit.ActorSystem, ActorID: "campaign:" + campaign.ID,
		Action: "security.remediate", TargetType: "host", TargetID: host.ID,
		RequestID: campaign.RequestID, Outcome: audit.OutcomeSuccess,
		Detail: map[string]any{
			"campaign_id": campaign.ID, "plan_id": created.ID,
			"plan_hash": plan.FindingsHash, "step_set_hash": hash,
			"steps": plan.Plan.Changes, "approved_by": campaign.ApprovedBy,
		},
	}); err != nil {
		return err
	}
	// The change step of a remediation has no task of its own: the plan runs its
	// steps in the remediation store.
	start := stepStart{
		Key: StepExecute, PlanHash: hash, State: TargetRunning,
		Message: fmt.Sprintf("remediation plan %s: %d steps", created.ID, len(created.Steps)),
		Note:    "remediation plan " + created.ID, BootID: &host.BootID,
	}
	revision, err := o.startStepTx(ctx, tx, target, start)
	if err != nil {
		return err
	}
	if err := tx.Commit(ctx); err != nil {
		return err
	}
	o.applyStart(target, start, revision)
	o.log.Info("the campaign started a host's remediation plan",
		"campaign_id", campaign.ID, "host_id", host.ID, "plan_id", created.ID,
		"wave", target.Wave, "steps", len(created.Steps))
	return nil
}

// creatorMayRemediate says whether the campaign's creator still holds the
// permission of every step of the host's plan, in the scope of the host.
func (o *Orchestrator) creatorMayRemediate(ctx context.Context, campaign Campaign,
	host *hosts.Host, plan remediation.HostPlan) (bool, string) {
	if o.Authorizer == nil {
		return false, ""
	}
	principal, err := o.Authorizer.PrincipalBySubject(ctx, campaign.CreatedBy)
	if err != nil {
		return true, "the rights of " + campaign.CreatedBy + " could not be checked: " + err.Error()
	}
	scope := hosts.ScopeOf(host)
	for _, action := range plan.Actions() {
		permission := authz.Permission(opspec.ActionType(action).Permission())
		if !principal.Can(permission, scope) {
			return true, campaign.CreatedBy + " no longer holds " + string(permission) +
				" on " + host.Site + "/" + host.Environment + " (step " + action + ")"
		}
	}
	return false, ""
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
	jobID, err := o.submitJobTx(ctx, tx, campaign, host, action, payload, idempotencyKey)
	if err != nil {
		return "", err
	}
	if err := tx.Commit(ctx); err != nil {
		return "", err
	}
	return jobID, nil
}

// submitJobTx creates the task and its audit record inside the caller's
// transaction: the launch of a host commits the task together with the host's
// transition, so there is no task without a host that follows it.
func (o *Orchestrator) submitJobTx(ctx context.Context, tx pgx.Tx, campaign Campaign, host *hosts.Host,
	action opspec.ActionType, payload opspec.Payload, idempotencyKey string) (string, error) {
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
	return job.ID, nil
}

// activeTargets counts the hosts of the campaign that hold a concurrency slot
// right now, across every wave.
func activeTargets(targets []Target) int {
	active := 0
	for _, target := range targets {
		if !target.State.Finished() && !target.State.Waiting() {
			active++
		}
	}
	return active
}

func allFinished(targets []Target) bool {
	for _, target := range targets {
		if !target.State.Finished() {
			return false
		}
	}
	return true
}

// currentWave returns the lowest wave that still has targets to start or to
// settle.
func currentWave(targets []Target) int {
	wave := -1
	for _, target := range targets {
		if !target.HoldsWave() {
			continue
		}
		if wave < 0 || target.Wave < wave {
			wave = target.Wave
		}
	}
	return wave
}

// waveFinished says whether every target of the given wave is settled or -
// outside the canary - waiting for its connection.
func waveFinished(targets []Target, wave int) bool {
	if wave < 0 {
		return true
	}
	for _, target := range targets {
		if target.Wave == wave && target.HoldsWave() {
			return false
		}
	}
	return true
}

// expire ends a campaign whose plans passed their time limit before any host
// started.
func (o *Orchestrator) expire(ctx context.Context, campaign Campaign, oldest time.Time) error {
	targets, err := o.store.Targets(ctx, campaign.ID)
	if err != nil {
		return err
	}
	age := time.Since(oldest).Round(time.Minute)
	why := fmt.Sprintf("%v: the oldest plan was computed %s ago, the limit is %s, and no host had started",
		ErrPlanExpired, age, PlanTTL)
	for i := range targets {
		if targets[i].State.Finished() {
			continue
		}
		o.finishTarget(ctx, campaign, &targets[i], TargetSkipped, "plan_stale", why)
	}
	if err := o.store.SetState(ctx, &campaign, StateExpired, why); err != nil {
		return err
	}
	if o.budgets != nil {
		if err := o.budgets.ReleaseClaimant(ctx, "campaign:"+campaign.ID); err != nil {
			o.log.Error("the capacity of an expired campaign was not released",
				"campaign_id", campaign.ID, "err", err)
		}
	}
	o.audit.Record(ctx, audit.Event{
		ActorType: audit.ActorSystem, ActorID: "campaign:" + campaign.ID,
		Action: "campaign.expire", TargetType: "campaign", TargetID: campaign.ID,
		RequestID: campaign.RequestID, Outcome: audit.OutcomeFailure,
		Detail: map[string]any{
			"reason": why, "oldest_plan_at": oldest, "plan_ttl": PlanTTL.String(),
			"previous_state": string(campaign.State),
		},
	})
	o.log.Warn("the campaign expired before it started",
		"campaign_id", campaign.ID, "oldest_plan_at", oldest, "previous_state", campaign.State)
	return nil
}

// drain carries a canceled campaign to its end.
func (o *Orchestrator) drain(ctx context.Context, campaign Campaign, targets []Target) error {
	o.renewCapacity(ctx, targets)
	for i := range targets {
		if err := o.progressTarget(ctx, campaign, &targets[i]); err != nil {
			o.log.Error("failure while draining a campaign target",
				"campaign_id", campaign.ID, "host_id", targets[i].HostID, "err", err)
		}
	}
	if !cancelSettled(targets) {
		return nil
	}
	if err := o.store.SetState(ctx, &campaign, StateCanceled, ""); err != nil {
		return err
	}
	if o.budgets != nil {
		if err := o.budgets.ReleaseClaimant(ctx, "campaign:"+campaign.ID); err != nil {
			o.log.Error("the capacity of a canceled campaign was not released",
				"campaign_id", campaign.ID, "err", err)
		}
	}
	counts, err := o.store.Counts(ctx, campaign.ID)
	if err != nil {
		return err
	}
	o.audit.Record(ctx, audit.Event{
		ActorType: audit.ActorSystem, ActorID: "campaign:" + campaign.ID,
		Action: "campaign.canceled", TargetType: "campaign", TargetID: campaign.ID,
		RequestID: campaign.RequestID, Outcome: audit.OutcomeSuccess,
		Detail: map[string]any{"canceled_by": campaign.CanceledBy, "totals": counts},
	})
	o.log.Info("the canceled campaign drained its last host",
		"campaign_id", campaign.ID, "totals", fmt.Sprint(counts))
	return nil
}
