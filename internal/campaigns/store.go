package campaigns

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/ultherego/flotestro/internal/authz"
	"github.com/ultherego/flotestro/internal/jobs"
	"github.com/ultherego/flotestro/internal/metrics"
	"github.com/ultherego/flotestro/internal/opspec"
)

var (
	// ErrNotFound means there is no such campaign.
	ErrNotFound = errors.New("the campaign does not exist")
	// ErrConflict means an operation not allowed in the current state.
	ErrConflict = errors.New("the operation is not allowed in the current state of the campaign")
	// ErrNoTargets means a selector that named no host.
	ErrNoTargets = errors.New("the selector named no host")
	// ErrRepeated says the order carried an idempotency key already used:
	// the campaign returned with it is the existing one, not a new one.
	ErrRepeated = errors.New("the campaign was already created with this idempotency key")
	// ErrConcurrentTransition says the row moved under the writer: its revision,
	// its state or its claim token is not the one the writer read.
	ErrConcurrentTransition = errors.New("the row changed since it was read; the transition was not applied")
	// ErrIllegalTransition says the state machine has no such move: a
	// settled host asked to move again, a finished campaign asked to run.
	ErrIllegalTransition = errors.New("the transition is not one the state machine allows")
	// ErrLeaseLost says the orchestrator no longer holds the runner lease of the
	// campaign: another instance took it over, and this one stops writing to the
	// campaign until it claims the lease again.
	ErrLeaseLost = errors.New("the runner lease of the campaign is held by another instance")
)

// The runner lease of a campaign.
const (
	RunnerLeaseTerm    = 45 * time.Second
	RunnerLeaseRenewal = 15 * time.Second
)

// Store provides access to the campaign tables.
type Store struct {
	pool *pgxpool.Pool
}

func NewStore(pool *pgxpool.Pool) *Store {
	return &Store{pool: pool}
}

func (s *Store) Pool() *pgxpool.Pool { return s.pool }

// TargetHost is a host picked for a campaign.
type TargetHost struct {
	ID     string
	BootID string
	// State and Reason describe a host that is already settled at the moment the
	// campaign is created: ineligible for this operation or inside a maintenance
	// window.
	State   TargetState
	Reason  string
	Message string
}

// Create creates a campaign together with an immutable snapshot of its
// targets.
func (s *Store) Create(ctx context.Context, tx pgx.Tx, spec Spec, hosts []TargetHost) (*Campaign, error) {
	if err := spec.Validate(); err != nil {
		return nil, err
	}
	if len(hosts) == 0 {
		return nil, ErrNoTargets
	}

	selectorJSON, err := json.Marshal(spec.Selector)
	if err != nil {
		return nil, err
	}
	payload := spec.Payload
	if len(payload) == 0 {
		payload = json.RawMessage("{}")
	}
	// An empty Go slice would reach the database as NULL, and the column requires an array.
	healthChecks := spec.HealthCheckUnits
	if healthChecks == nil {
		healthChecks = []string{}
	}

	state := StateQueuedOrApproval(spec.RequiresApproval)
	// A change computed per host starts with planning: the consent is to concern
	// the diffs, and those are yet to come into being - read from the hosts, or
	// split from the order in the panel.
	if opspec.CampaignPlans(opspec.ActionType(spec.ActionType)) {
		state = StatePlanning
	}
	campaignID := uuid.NewString()

	// The policy is recorded as resolved: an empty value would leave the
	// orchestrator to guess, and a guess about an offline host is exactly what
	// the policy exists to replace.
	if spec.OfflinePolicy == "" {
		spec.OfflinePolicy = opspec.ActionType(spec.ActionType).OfflinePolicy()
	}

	// The fingerprint comes from the same description that reaches the database.
	fingerprint, err := Fingerprint(spec, hosts)
	if err != nil {
		return nil, err
	}

	// The selector is recorded as ordered, exclusions included: the approver
	// reads what was asked for, and the snapshot below says what it resolved to.
	const insert = `
		insert into campaigns (id, name, action_type, payload, selector, state,
		                       canary_size, wave_size, max_concurrent,
		                       failure_threshold_percent, failure_threshold_absolute,
		                       maintenance_start, maintenance_end, reboot_policy,
		                       health_check_units, job_timeout_seconds,
		                       requires_approval, created_by, request_id,
		                       approval_fingerprint, idempotency_key,
		                       offline_policy, deadline_at, manual_gate,
		                       connectivity_lost_absolute, compensates_campaign_id,
		                       reboot_timeout_seconds, policy_id, policy_version,
		                       retries_campaign_id)
		values ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16, $17, $18, $19, $20, $21,
		        $22, now() + make_interval(mins => $23), $24, $25, $26, $27, $28, $29, $30)
		on conflict (created_by, idempotency_key) where idempotency_key is not null do nothing`
	// The reboot timeout is recorded resolved, like the deadline: the row says
	// how long the campaign really waits, and the orchestrator does not have to
	// know what the default was on the day of the order.
	tag, err := tx.Exec(ctx, insert, campaignID, spec.Name, spec.ActionType, payload, selectorJSON,
		string(state), spec.CanarySize, spec.WaveSize, spec.MaxConcurrent,
		spec.FailureThresholdPercent, spec.FailureThresholdAbsolute,
		spec.MaintenanceStart, spec.MaintenanceEnd, string(spec.RebootPolicy),
		healthChecks, spec.JobTimeoutSeconds,
		spec.RequiresApproval, spec.CreatedBy, nullable(spec.RequestID),
		fingerprint, nullable(spec.IdempotencyKey),
		string(spec.OfflinePolicy), int(spec.Deadline()/time.Minute), spec.ManualGate,
		spec.ConnectivityLostAbsolute, nullable(spec.CompensatesCampaignID),
		int(spec.RebootTimeout()/time.Second), nullable(spec.PolicyID), nullableInt(spec.PolicyVersion),
		nullable(spec.RetriesCampaignID))
	if err != nil {
		return nil, fmt.Errorf("creating the campaign: %w", err)
	}
	if tag.RowsAffected() == 0 {
		// The same key from the same creator: the campaign already exists
		// and the repeat gets it back instead of a second one.
		rows, err := tx.Query(ctx, campaignColumns+" where created_by = $1 and idempotency_key = $2",
			spec.CreatedBy, spec.IdempotencyKey)
		if err != nil {
			return nil, err
		}
		existing, err := scanCampaigns(rows)
		if err != nil {
			return nil, err
		}
		if len(existing) == 0 {
			return nil, ErrConflict
		}
		return &existing[0], ErrRepeated
	}

	// We count the waves from the ready hosts only.
	ready := 0
	for _, host := range hosts {
		state := host.State
		if state == "" {
			state = TargetPending
		}
		wave, position := 0, 0
		if state == TargetPending {
			wave, position = AssignWave(ready, spec.CanarySize, spec.WaveSize)
			ready++
		}
		const insertTarget = `
			insert into campaign_targets (id, campaign_id, host_id, wave, position,
			                              boot_id_before, state, error_code, message,
			                              finished_at)
			values ($1, $2, $3, $4, $5, $6, $7, $8, $9,
			        case when $7 = 'pending' then null else now() end)`
		if _, err := tx.Exec(ctx, insertTarget, uuid.NewString(), campaignID,
			host.ID, wave, position, nullable(host.BootID), string(state),
			nullable(host.Reason), nullable(host.Message)); err != nil {
			return nil, fmt.Errorf("recording a campaign target: %w", err)
		}
	}
	if ready == 0 {
		return nil, ErrNoTargets
	}

	return s.getTx(ctx, tx, campaignID)
}

// HostPlanSpec is a per-host plan computed in the panel and handed in
// together with the order.
type HostPlanSpec struct {
	HostID   string
	PlanHash string
	Plan     json.RawMessage
}

// CreatePlanned creates a campaign whose per-host plans exist before the
// order: a fleet remediation, where the panel computes every host's steps from
// its findings.
func (s *Store) CreatePlanned(ctx context.Context, tx pgx.Tx, spec Spec, hosts []TargetHost,
	plans []HostPlanSpec) (*Campaign, error) {
	campaign, err := s.Create(ctx, tx, spec, hosts)
	if err != nil {
		return campaign, err
	}
	if len(plans) == 0 {
		return nil, fmt.Errorf("a planned campaign needs at least one host plan")
	}
	set := map[string]string{}
	for _, plan := range plans {
		content := plan.Plan
		if len(content) == 0 {
			content = json.RawMessage("{}")
		}
		if _, err := tx.Exec(ctx, `
			insert into campaign_plans (campaign_id, host_id, plan_hash, plan)
			values ($1, $2, $3, $4)`, campaign.ID, plan.HostID, plan.PlanHash, content); err != nil {
			return nil, fmt.Errorf("recording a host plan: %w", err)
		}
		set[plan.HostID] = plan.PlanHash
	}
	planSetHash := PlanSetFingerprint(set)
	fingerprint, err := FingerprintWithPlans(*campaign, planSetHash)
	if err != nil {
		return nil, err
	}
	if _, err := tx.Exec(ctx, `
		update campaigns
		   set plan_set_hash = $2, approval_fingerprint = $3, updated_at = now(),
		       revision = revision + 1
		 where id = $1`, campaign.ID, planSetHash, fingerprint); err != nil {
		return nil, fmt.Errorf("recording the plan set: %w", err)
	}
	return s.getTx(ctx, tx, campaign.ID)
}

// StateQueuedOrApproval returns the initial state of a campaign.
func StateQueuedOrApproval(requiresApproval bool) State {
	if requiresApproval {
		return StateAwaitingApproval
	}
	return StatePlanned
}

// AssignWave assigns a host to a wave. Wave 0 is the canary and has its own
// size; the following waves have a fixed size.
func AssignWave(index, canarySize, waveSize int) (wave, position int) {
	if index < canarySize {
		return 0, index
	}
	remaining := index - canarySize
	return remaining/waveSize + 1, remaining % waveSize
}

// Approve approves a campaign and lets it start.
func (s *Store) Approve(ctx context.Context, tx pgx.Tx, campaignID string, approval Approval) (*Campaign, error) {
	const query = `
		update campaigns set state = $2, approved_by = $3, approved_at = now(), updated_at = now(),
		                     revision = revision + 1
		where id = $1 and state = $4
		returning created_by, approval_fingerprint`
	var requestedBy, fingerprint string
	err := tx.QueryRow(ctx, query, campaignID, string(StatePlanned), approval.ApprovedBy,
		string(StateAwaitingApproval)).Scan(&requestedBy, &fingerprint)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, ErrConflict
	}
	if err != nil {
		return nil, err
	}
	// The record is the evidence; the columns above are the convenience.
	const record = `
		insert into campaign_approvals
		    (campaign_id, approval_fingerprint, requested_by, approved_by,
		     authentication, acr, amr, authenticated_at, reason, change_ticket)
		values ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)`
	amr := approval.AMR
	if amr == nil {
		amr = []string{}
	}
	if _, err := tx.Exec(ctx, record, campaignID, fingerprint, requestedBy, approval.ApprovedBy,
		approval.Authentication, approval.ACR, amr, approval.AuthenticatedAt,
		approval.Reason, approval.ChangeTicket); err != nil {
		return nil, fmt.Errorf("record the approval: %w", err)
	}
	return s.getTx(ctx, tx, campaignID)
}

// Approvals lists the approval records of a campaign, oldest first.
func (s *Store) Approvals(ctx context.Context, campaignID string) ([]Approval, error) {
	return s.approvalsFrom(ctx, s.pool, campaignID)
}

// ApprovalsTx lists the approvals as the caller's transaction sees them: the
// record Approve wrote a moment ago is on the list before the commit, which a
// read through the pool would not show yet.
func (s *Store) ApprovalsTx(ctx context.Context, tx pgx.Tx, campaignID string) ([]Approval, error) {
	return s.approvalsFrom(ctx, tx, campaignID)
}

// approvalQuerier is what a list of approvals needs; both the pool and a
// transaction provide it.
type approvalQuerier interface {
	Query(ctx context.Context, sql string, args ...any) (pgx.Rows, error)
}

func (s *Store) approvalsFrom(ctx context.Context, q approvalQuerier, campaignID string) ([]Approval, error) {
	const query = `
		select id, campaign_id, approval_fingerprint, requested_by, approved_by,
		       authentication, acr, amr, authenticated_at, reason, change_ticket, created_at
		from campaign_approvals where campaign_id = $1 order by created_at`
	rows, err := q.Query(ctx, query, campaignID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	approvals := []Approval{}
	for rows.Next() {
		var a Approval
		if err := rows.Scan(&a.ID, &a.CampaignID, &a.ApprovalFingerprint, &a.RequestedBy, &a.ApprovedBy,
			&a.Authentication, &a.ACR, &a.AMR, &a.AuthenticatedAt, &a.Reason, &a.ChangeTicket,
			&a.CreatedAt); err != nil {
			return nil, err
		}
		approvals = append(approvals, a)
	}
	return approvals, rows.Err()
}

// Pause holds a campaign back. The hosts already started finish their tasks.
func (s *Store) Pause(ctx context.Context, campaignID, actor, reason string) (*Campaign, error) {
	const query = `
		update campaigns set
			state = case when exists (select 1 from campaign_targets t
			                           where t.campaign_id = campaigns.id
			                             and t.state in ('dispatched', 'awaiting_lock', 'running', 'rebooting', 'verifying'))
			             then $2 else $3 end,
			paused_by = $4, paused_at = now(), pause_reason = $5, updated_at = now(),
			revision = revision + 1
		where id = $1 and state in ('planned', 'canary', 'manual_gate', 'running')
		returning id`
	var updated string
	err := s.pool.QueryRow(ctx, query, campaignID, string(StatePausing), string(StatePaused),
		actor, nullable(reason)).Scan(&updated)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, ErrConflict
	}
	if err != nil {
		return nil, err
	}
	return s.Get(ctx, campaignID)
}

// Resume restarts a campaign that was held back.
func (s *Store) Resume(ctx context.Context, campaignID, actor string) (*Campaign, error) {
	const query = `
		update campaigns set state = $2, paused_by = null, paused_at = null,
		                     pause_reason = null, updated_at = now(),
		                     revision = revision + 1
		where id = $1 and state in ($3, $4)
		returning id`
	var updated string
	err := s.pool.QueryRow(ctx, query, campaignID, string(StatePlanned),
		string(StatePaused), string(StatePausing)).Scan(&updated)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, ErrConflict
	}
	if err != nil {
		return nil, err
	}
	return s.Get(ctx, campaignID)
}

// Cancel stops a campaign.
func (s *Store) Cancel(ctx context.Context, campaignID, actor, reason string) (*Campaign, error) {
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return nil, err
	}
	defer func() { _ = tx.Rollback(ctx) }()

	// The state the campaign is leaving is read under a lock: the steps recorded
	// below depend on it, and a second cancel must find the row already moved.
	var previous string
	err = tx.QueryRow(ctx, `select state from campaigns where id = $1 for update`, campaignID).Scan(&previous)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, err
	}
	if State(previous).Terminal() || State(previous) == StateCanceling {
		return nil, ErrConflict
	}

	// The hosts that have not started will not be started - the ones waiting for
	// their connection included, and the ones computing a plan: a plan is a read,
	// and a cancel does not wait for a read.
	if _, err := tx.Exec(ctx, `
		update campaign_targets
		   set state = 'canceled', finished_at = now(), settled_at = now(), state_since = now(),
		       revision = revision + 1
		 where campaign_id = $1 and state in ('pending', 'awaiting_budget', 'queued_offline', 'planning')`,
		campaignID); err != nil {
		return nil, err
	}
	// The tasks the campaign created that are still in the panel's queue never
	// reached a host, and a cancel takes them back: a host that came online an
	// hour later would otherwise carry out a change of a campaign that no longer.
	why := "the campaign was canceled by " + actor
	if reason != "" {
		why += ": " + reason
	}
	owed, err := s.followUpJobs(ctx, tx, campaignID)
	if err != nil {
		return nil, err
	}
	takenBack, err := jobs.CancelQueuedOf(ctx, tx, campaignID, actor, why, owed)
	if err != nil {
		return nil, fmt.Errorf("taking back the queued tasks of the campaign: %w", err)
	}
	// The tasks the hosts hold are asked to stop, not written off: each moves to
	// cancel_requested with a request on the trail, and the agent answers what
	// the request found - a task not yet started ends canceled, one under way in.
	if _, err := jobs.RequestCancelOf(ctx, tx, campaignID, actor, why, owed); err != nil {
		return nil, fmt.Errorf("asking the hosts of the campaign to stop: %w", err)
	}
	if len(takenBack) > 0 {
		// A host whose task was taken back before it left the panel never
		// started: it ends canceled, like the hosts that were waiting.
		if _, err := tx.Exec(ctx, `
			update campaign_targets
			   set state = 'canceled', error_code = 'canceled',
			       message = 'the task was still queued in the panel when the campaign was canceled',
			       finished_at = now(), settled_at = now(), state_since = now(), blocker = '',
			       revision = revision + 1
			 where campaign_id = $1 and job_id = any($2::uuid[])
			   and state in ('dispatched', 'awaiting_lock', 'running')`,
			campaignID, takenBack); err != nil {
			return nil, err
		}
	}
	// The hosts still carrying a task keep it, and the row says the cancel
	// reached them while they worked: the campaign waits for them, and the
	// acknowledgement of the agent says whether the task was interrupted, never.
	if _, err := tx.Exec(ctx, `
		update campaign_targets
		   set cancel_requested_at = coalesce(cancel_requested_at, now()), revision = revision + 1
		 where campaign_id = $1
		   and state in ('dispatched', 'awaiting_lock', 'running', 'rebooting', 'verifying')`,
		campaignID); err != nil {
		return nil, err
	}
	// The tokens of the hosts that will not start go back now: a lease held by a
	// host that does nothing stops the next campaign until it expires.
	if _, err := tx.Exec(ctx, `
		delete from budget_leases
		 where owner in (select id::text from campaign_targets where campaign_id = $1 and state = 'canceled')`,
		campaignID); err != nil {
		return nil, err
	}
	// Every host that will not start gets the step it was waiting for recorded as
	// canceled, with the actor and the reason: the strip of a canceled host is to
	// say who stopped it, not stay blank.
	step := StepExecute
	if previous == string(StatePlanning) {
		step = StepPlan
	}
	if _, err := tx.Exec(ctx, `
		update campaign_steps s set state = 'canceled', reason = $2, finished_at = now(), updated_at = now()
		  from campaign_targets t
		 where s.target_id = t.id and t.campaign_id = $1 and t.state = 'canceled'
		   and s.state in ('pending', 'running')`,
		campaignID, why); err != nil {
		return nil, fmt.Errorf("closing the open steps of the canceled hosts: %w", err)
	}
	if _, err := tx.Exec(ctx, `
		insert into campaign_steps (campaign_id, target_id, host_id, step_key, state, reason, finished_at)
		select t.campaign_id, t.id, t.host_id, $2::text, 'canceled', $3::text, now()
		  from campaign_targets t
		 where t.campaign_id = $1 and t.state = 'canceled'
		on conflict (target_id, step_key, plan_hash) do nothing`,
		campaignID, string(step), why); err != nil {
		return nil, fmt.Errorf("recording the canceled steps: %w", err)
	}

	// Whether the campaign ends now or drains first is read off the hosts after
	// the waiting ones were closed: what is left under way is what the cancel
	// waits for.
	var underWay int
	if err := tx.QueryRow(ctx, `
		select count(*) from campaign_targets
		 where campaign_id = $1
		   and state in ('dispatched', 'awaiting_lock', 'running', 'rebooting', 'verifying')`,
		campaignID).Scan(&underWay); err != nil {
		return nil, err
	}
	next := StateCanceled
	if underWay > 0 {
		next = StateCanceling
	}
	if _, err := tx.Exec(ctx, `
		update campaigns set state = $2, canceled_by = $3, canceled_at = now(),
		                     pause_reason = $4, updated_at = now(), revision = revision + 1,
		                     finished_at = case when $2 = 'canceled' then now() else finished_at end
		where id = $1`, campaignID, string(next), actor, nullable(reason)); err != nil {
		return nil, err
	}
	// A cancellation that ends the campaign now writes its report here, so the
	// record shows the targets as the cancellation left them; one that drains
	// first gets its report from the orchestrator with the last host.
	if next == StateCanceled {
		if err := s.recordReport(ctx, tx, campaignID); err != nil {
			return nil, err
		}
	}
	if err := tx.Commit(ctx); err != nil {
		return nil, err
	}
	return s.Get(ctx, campaignID)
}

// followUpJobs lists the reboot and verification tasks of the hosts whose
// change is done: a cancel does not take those back, because a host left with
// its change applied and its reboot never ordered is a host the cancel would.
func (s *Store) followUpJobs(ctx context.Context, tx pgx.Tx, campaignID string) ([]string, error) {
	rows, err := tx.Query(ctx, `
		select j::text from campaign_targets t
		 cross join lateral (values (t.reboot_job_id), (t.health_job_id)) as owed (j)
		 where t.campaign_id = $1 and j is not null`, campaignID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	owed := []string{}
	for rows.Next() {
		var id string
		if err := rows.Scan(&id); err != nil {
			return nil, err
		}
		owed = append(owed, id)
	}
	return owed, rows.Err()
}

// Advance lets a campaign standing at the manual gate into the waves.
func (s *Store) Advance(ctx context.Context, campaignID, actor string) (*Campaign, error) {
	const query = `
		update campaigns set state = $2, gate_advanced_by = $3, gate_advanced_at = now(),
		                     updated_at = now(), revision = revision + 1
		where id = $1 and state = $4
		returning id`
	var updated string
	err := s.pool.QueryRow(ctx, query, campaignID, string(StateRunning), actor,
		string(StateManualGate)).Scan(&updated)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, ErrConflict
	}
	if err != nil {
		return nil, err
	}
	return s.Get(ctx, campaignID)
}

// SetState changes the state of a campaign on behalf of the orchestrator that
// drives it.
func (s *Store) SetState(ctx context.Context, campaign *Campaign, state State, reason string) error {
	const query = `
		update campaigns set state = $2, updated_at = now(), revision = revision + 1,
			pause_reason = case when ($2 in ('pausing', 'paused') and state <> 'pausing')
			                      or $2 in ('plan_failed', 'expired') then $3 else pause_reason end,
			paused_at    = case when $2 in ('pausing', 'paused') and state <> 'pausing' then now() else paused_at end,
			paused_by    = case when $2 in ('pausing', 'paused') and state <> 'pausing' then 'system' else paused_by end,
			started_at   = coalesce(started_at, case when $2 in ('canary', 'running') then now() end),
			finished_at  = case when $2 in ('completed', 'completed_with_issues', 'failed', 'plan_failed',
			                                'expired', 'canceled')
			                    then now() else finished_at end
		where id = $1 and revision = $4
		  and ($5::uuid is null or (runner_id = $5::uuid and runner_token = $6))
		returning revision`
	// Three tries are two re-reads: a campaign that moves twice under one
	// tick of the orchestrator is a campaign somebody else is driving.
	for attempt := 0; attempt < 3; attempt++ {
		if !campaign.State.mayBecome(state) {
			return fmt.Errorf("%w: %s cannot become %s", ErrIllegalTransition, campaign.State, state)
		}
		var runner any
		if campaign.RunnerID != "" {
			runner = campaign.RunnerID
		}
		args := []any{campaign.ID, string(state), nullable(reason), campaign.Revision, runner, campaign.RunnerToken}
		var revision int64
		var err error
		if !state.Terminal() {
			err = s.pool.QueryRow(ctx, query, args...).Scan(&revision)
		} else {
			err = s.withReport(ctx, campaign.ID, func(tx pgx.Tx) error {
				return tx.QueryRow(ctx, query, args...).Scan(&revision)
			})
		}
		if err == nil {
			campaign.State = state
			campaign.Revision = revision
			return nil
		}
		if !errors.Is(err, pgx.ErrNoRows) {
			return err
		}
		// The row moved, or the lease did. Read it again: what is there now
		// decides whether the transition still makes sense.
		fresh, err := s.Get(ctx, campaign.ID)
		if err != nil {
			return err
		}
		if campaign.RunnerID != "" && (fresh.RunnerID != campaign.RunnerID || fresh.RunnerToken != campaign.RunnerToken) {
			return ErrLeaseLost
		}
		if fresh.State != campaign.State {
			// Somebody moved the campaign: an operator paused or canceled it, or
			// another pass settled it.
			*campaign = *fresh
			return fmt.Errorf("%w: the campaign is %s now", ErrConcurrentTransition, fresh.State)
		}
		*campaign = *fresh
	}
	return ErrConcurrentTransition
}

// withReport runs a terminal transition together with the campaign's
// report in one transaction.
func (s *Store) withReport(ctx context.Context, campaignID string, write func(tx pgx.Tx) error) error {
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback(ctx) }()
	if err := write(tx); err != nil {
		return err
	}
	if err := s.recordReport(ctx, tx, campaignID); err != nil {
		return err
	}
	return tx.Commit(ctx)
}

// Active returns the campaigns the orchestrator has to handle.
func (s *Store) Active(ctx context.Context) ([]Campaign, error) {
	// Planning is an active state: the campaign changes nothing yet, but the
	// orchestrator has work to do - every host computes its own plan.
	return s.query(ctx, `
		where state in ('planning', 'planned', 'awaiting_approval', 'canary', 'running', 'pausing', 'canceling')
		   or (state = 'paused' and exists (select 1 from campaign_targets t
		                                     where t.campaign_id = campaigns.id
		                                       and t.state in ('dispatched', 'awaiting_lock', 'running',
		                                                       'rebooting', 'verifying')))
		order by created_at`)
}

// OldestPlan returns when the oldest plan of the campaign was computed;
// zero for a campaign without plans, which has no plan to grow old.
func (s *Store) OldestPlan(ctx context.Context, campaignID string) (time.Time, error) {
	var oldest *time.Time
	if err := s.pool.QueryRow(ctx,
		`select min(computed_at) from campaign_plans where campaign_id = $1`, campaignID).Scan(&oldest); err != nil {
		return time.Time{}, err
	}
	if oldest == nil {
		return time.Time{}, nil
	}
	return *oldest, nil
}

// SavePlan records the plan computed on one host.
func (s *Store) SavePlan(ctx context.Context, campaignID, hostID, hash string,
	plan json.RawMessage) error {
	return s.savePlan(ctx, s.pool, campaignID, hostID, hash, plan)
}

// SavePlanTx records the plan inside the caller's transaction, next to the
// target's return to the queue and the close of its plan step.
func (s *Store) SavePlanTx(ctx context.Context, tx pgx.Tx, campaignID, hostID, hash string,
	plan json.RawMessage) error {
	return s.savePlan(ctx, tx, campaignID, hostID, hash, plan)
}

func (s *Store) savePlan(ctx context.Context, q stepQuerier, campaignID, hostID, hash string,
	plan json.RawMessage) error {
	if len(plan) == 0 {
		plan = json.RawMessage("{}")
	}
	const query = `
		insert into campaign_plans (campaign_id, host_id, plan_hash, plan)
		values ($1, $2, $3, $4)
		on conflict (campaign_id, host_id) do update
		   set plan_hash = excluded.plan_hash, plan = excluded.plan,
		       computed_at = now()`
	_, err := q.Exec(ctx, query, campaignID, hostID, hash, plan)
	return err
}

// Plans returns the digests of a campaign's plans broken down by host.
func (s *Store) Plans(ctx context.Context, campaignID string) (map[string]string, error) {
	rows, err := s.pool.Query(ctx,
		`select host_id, plan_hash from campaign_plans where campaign_id = $1`, campaignID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	plans := map[string]string{}
	for rows.Next() {
		var host, hash string
		if err := rows.Scan(&host, &hash); err != nil {
			return nil, err
		}
		plans[host] = hash
	}
	return plans, rows.Err()
}

// HostPlan returns the plan computed on one host together with its content.
func (s *Store) HostPlan(ctx context.Context, campaignID, hostID string) (string, json.RawMessage, time.Time, error) {
	var hash string
	var plan json.RawMessage
	var computedAt time.Time
	const query = `
		select plan_hash, plan, computed_at from campaign_plans
		 where campaign_id = $1 and host_id = $2`
	err := s.pool.QueryRow(ctx, query, campaignID, hostID).Scan(&hash, &plan, &computedAt)
	if errors.Is(err, pgx.ErrNoRows) {
		return "", nil, time.Time{}, nil
	}
	return hash, plan, computedAt, err
}

// PlanEntry is one host's plan together with its content.
type PlanEntry struct {
	HostID   string          `json:"host_id"`
	Hostname string          `json:"hostname,omitempty"`
	PlanHash string          `json:"plan_hash"`
	Plan     json.RawMessage `json:"plan,omitempty"`
	// ComputedAt and ExpiresAt bound the plan in time: past the expiry the
	// host is not started on it, however good the digest still looks.
	ComputedAt time.Time `json:"computed_at"`
	ExpiresAt  time.Time `json:"expires_at"`
}

// PlansWithContent returns the plans of every host in a campaign.
func (s *Store) PlansWithContent(ctx context.Context, campaignID string) ([]PlanEntry, error) {
	const query = `
		select p.host_id, coalesce(h.hostname, ''), p.plan_hash, p.plan, p.computed_at
		  from campaign_plans p
		  left join hosts h on h.id = p.host_id
		 where p.campaign_id = $1
		 order by coalesce(h.hostname, p.host_id::text)`
	rows, err := s.pool.Query(ctx, query, campaignID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	entries := []PlanEntry{}
	for rows.Next() {
		var entry PlanEntry
		if err := rows.Scan(&entry.HostID, &entry.Hostname, &entry.PlanHash, &entry.Plan, &entry.ComputedAt); err != nil {
			return nil, err
		}
		entry.ExpiresAt = entry.ComputedAt.Add(PlanTTL)
		entries = append(entries, entry)
	}
	return entries, rows.Err()
}

// FinishPlanning records the digest of the set of plans together with the
// approval fingerprint and moves the campaign into the state where it waits
// for a decision.
func (s *Store) FinishPlanning(ctx context.Context, campaignID, planSetHash,
	fingerprint string, next State) error {
	const query = `
		update campaigns
		   set plan_set_hash = $2, approval_fingerprint = $3, state = $4, updated_at = now(),
		       revision = revision + 1
		 where id = $1 and state = $5`
	tag, err := s.pool.Exec(ctx, query, campaignID, planSetHash, fingerprint,
		string(next), string(StatePlanning))
	if err != nil {
		return err
	}
	if tag.RowsAffected() == 0 {
		return ErrConflict
	}
	return nil
}

// Event is one entry in the course of a campaign.
type Event struct {
	ID         int64           `json:"id"`
	Aggregate  string          `json:"aggregate_type"`
	Type       string          `json:"event_type"`
	Payload    json.RawMessage `json:"payload"`
	OccurredAt time.Time       `json:"occurred_at"`
}

// Course returns the durable trail of a campaign: what happened in it and
// when.
func (s *Store) Course(ctx context.Context, campaignID string, limit int) ([]Event, error) {
	return s.CourseAfter(ctx, campaignID, 0, limit)
}

// CourseAfter returns the trail of a campaign after the given event
// identifier.
func (s *Store) CourseAfter(ctx context.Context, campaignID string, after int64, limit int) ([]Event, error) {
	if limit <= 0 || limit > maxCourseEntries {
		limit = maxCourseEntries
	}
	const query = `
		select id, aggregate_type, event_type, payload, occurred_at
		  from outbox_events
		 where aggregate_id = $1 and aggregate_type in ('campaign', 'campaign_target')
		   and id > $2
		 order by id
		 limit $3`
	rows, err := s.pool.Query(ctx, query, campaignID, after, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	course := []Event{}
	for rows.Next() {
		var entry Event
		if err := rows.Scan(&entry.ID, &entry.Aggregate, &entry.Type,
			&entry.Payload, &entry.OccurredAt); err != nil {
			return nil, err
		}
		course = append(course, entry)
	}
	return course, rows.Err()
}

// maxCourseEntries bounds a single read of the course.
const maxCourseEntries = 2000

// ActiveTargets says which hosts are already targets of campaigns under way.
func (s *Store) ActiveTargets(ctx context.Context) (map[string]string, error) {
	const query = `
		select t.host_id, t.campaign_id
		  from campaign_targets t
		  join campaigns c on c.id = t.campaign_id
		 where c.state in ('planning', 'planned', 'awaiting_approval', 'canary',
		                   'manual_gate', 'running', 'pausing', 'canceling')
		   and t.state in ('pending', 'planning', 'awaiting_budget', 'queued_offline',
		                   'dispatched', 'awaiting_lock', 'running', 'rebooting', 'verifying')`
	rows, err := s.pool.Query(ctx, query)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	collisions := map[string]string{}
	for rows.Next() {
		var host, campaign string
		if err := rows.Scan(&host, &campaign); err != nil {
			return nil, err
		}
		collisions[host] = campaign
	}
	return collisions, rows.Err()
}

// Get returns a campaign.
func (s *Store) Get(ctx context.Context, campaignID string) (*Campaign, error) {
	found, err := s.query(ctx, "where id = $1", campaignID)
	if err != nil {
		return nil, err
	}
	if len(found) == 0 {
		return nil, ErrNotFound
	}
	return &found[0], nil
}

func (s *Store) getTx(ctx context.Context, tx pgx.Tx, campaignID string) (*Campaign, error) {
	rows, err := tx.Query(ctx, campaignColumns+" where id = $1", campaignID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	campaigns, err := scanCampaigns(rows)
	if err != nil {
		return nil, err
	}
	if len(campaigns) == 0 {
		return nil, ErrNotFound
	}
	return &campaigns[0], nil
}

// Scope is a site-environment pair. An empty field means "any".
type Scope struct {
	Site        string
	Environment string
	// Team, as in the job listing: a boundary this table cannot express, carried
	// so that it narrows to nothing instead of being dropped and leaving the
	// listing wide open.
	Team string
}

// ListFilter narrows the campaign list. Every field is optional; the
// page is bounded by Limit and starts at Offset, newest campaign first.
type ListFilter struct {
	State string
	// Action is the operation, as the record names it.
	Action string
	// CreatedBy is the subject that ordered the campaign.
	CreatedBy string
	// Since keeps the campaigns created at or after the moment.
	Since  *time.Time
	Limit  int
	Offset int
}

// ListPage is one page of the campaign list with the count of the whole
// list under the same filter, so a screen can say where the page stands.
type ListPage struct {
	Items []Campaign
	Total int
}

// List returns the campaigns narrowed to the scopes in which the caller has
// the right to read, and to the filter.
func (s *Store) List(ctx context.Context, filter ListFilter, scopes []Scope) (ListPage, error) {
	limit := filter.Limit
	if limit <= 0 || limit > 200 {
		limit = 50
	}
	offset := max(filter.Offset, 0)
	clause := "where 1 = 1"
	args := []any{}
	if filter.State != "" {
		args = append(args, filter.State)
		clause += fmt.Sprintf(" and state = $%d", len(args))
	}
	if filter.Action != "" {
		args = append(args, filter.Action)
		clause += fmt.Sprintf(" and action_type = $%d", len(args))
	}
	if filter.CreatedBy != "" {
		args = append(args, filter.CreatedBy)
		clause += fmt.Sprintf(" and created_by = $%d", len(args))
	}
	if filter.Since != nil {
		args = append(args, *filter.Since)
		clause += fmt.Sprintf(" and created_at >= $%d", len(args))
	}
	if warunek, dodatkowe := scopeCondition(scopes, len(args)); warunek != "" {
		clause += warunek
		args = append(args, dodatkowe...)
	}
	var total int
	if err := s.pool.QueryRow(ctx, "select count(*) from campaigns "+clause, args...).Scan(&total); err != nil {
		return ListPage{}, err
	}
	items, err := s.query(ctx, clause+" order by created_at desc limit "+itoa(limit)+" offset "+itoa(offset), args...)
	if err != nil {
		return ListPage{}, err
	}
	if err := s.attachProgress(ctx, items); err != nil {
		return ListPage{}, err
	}
	return ListPage{Items: items, Total: total}, nil
}

// attachProgress fills the progress of every campaign given from one grouped
// read of their targets.
func (s *Store) attachProgress(ctx context.Context, items []Campaign) error {
	if len(items) == 0 {
		return nil
	}
	ids := make([]string, 0, len(items))
	by := make(map[string]*Campaign, len(items))
	for i := range items {
		ids = append(ids, items[i].ID)
		items[i].Progress = &Progress{}
		by[items[i].ID] = &items[i]
	}
	rows, err := s.pool.Query(ctx, `
		select campaign_id::text, state, count(*)
		  from campaign_targets
		 where campaign_id = any($1::uuid[])
		 group by campaign_id, state`, ids)
	if err != nil {
		return err
	}
	defer rows.Close()
	for rows.Next() {
		var campaignID, state string
		var count int
		if err := rows.Scan(&campaignID, &state, &count); err != nil {
			return err
		}
		if campaign, present := by[campaignID]; present {
			campaign.Progress.Add(TargetState(state), count)
		}
	}
	return rows.Err()
}

// scopeCondition builds the visibility condition over a campaign's targets.
func scopeCondition(scopes []Scope, offset int) (string, []any) {
	przelozone := make([]authz.Scope, 0, len(scopes))
	for _, scope := range scopes {
		przelozone = append(przelozone,
			authz.Scope{Site: scope.Site, Environment: scope.Environment, Team: scope.Team})
	}
	warunek, args := authz.ScopeSQL(przelozone, "h.site", "h.environment", offset)
	if warunek == "" {
		return "", nil
	}
	return " and exists (select 1 from campaign_targets t join hosts h on h.id = t.host_id" +
		" where t.campaign_id = campaigns.id and " + warunek + ")", args
}

const campaignColumns = `
	select id, name, action_type, payload, selector, state,
	       canary_size, wave_size, max_concurrent,
	       failure_threshold_percent, failure_threshold_absolute,
	       maintenance_start, maintenance_end, reboot_policy, health_check_units,
	       job_timeout_seconds, requires_approval, approval_fingerprint, plan_set_hash,
	       coalesce(approved_by, ''), approved_at, coalesce(paused_by, ''),
	       coalesce(pause_reason, ''), coalesce(canceled_by, ''),
	       created_by, coalesce(request_id, ''), started_at, finished_at, created_at, updated_at,
	       offline_policy, deadline_at, manual_gate, coalesce(gate_advanced_by, ''),
	       gate_advanced_at, connectivity_lost_absolute, reboot_timeout_seconds,
	       coalesce(compensates_campaign_id::text, ''),
	       coalesce((select o.name from campaigns o where o.id = campaigns.compensates_campaign_id), ''),
	       coalesce((select jsonb_agg(jsonb_build_object('id', c.id, 'name', c.name, 'state', c.state)
	                                  order by c.created_at)
	                   from campaigns c where c.compensates_campaign_id = campaigns.id), '[]'::jsonb),
	       case when campaigns.state in ('completed', 'completed_with_issues', 'failed',
	                                     'plan_failed', 'expired', 'canceled')
	            then (select count(*) from campaign_targets t
	                   where t.campaign_id = campaigns.id and ` + changedTargetCondition + `)
	            else 0 end,
	       coalesce(policy_id::text, ''), coalesce(policy_version, 0),
	       coalesce(retries_campaign_id::text, ''),
	       coalesce((select o.name from campaigns o where o.id = campaigns.retries_campaign_id), ''),
	       coalesce((select jsonb_agg(jsonb_build_object('id', c.id, 'name', c.name, 'state', c.state)
	                                  order by c.created_at)
	                   from campaigns c where c.retries_campaign_id = campaigns.id), '[]'::jsonb),
	       revision, coalesce(runner_id::text, ''), runner_token, runner_until
	from campaigns `

// changedTargetCondition tells a target whose change landed on the host, on
// the alias t: the host succeeded, or failed only after the change - in the
// reboot or the verification - which the execute step records as succeeded.
const changedTargetCondition = `(t.state = 'succeeded'
	                          or (t.state <> 'no_change'
	                              and exists (select 1 from campaign_steps s
	                                           where s.target_id = t.id and s.step_key = 'execute' and s.state = 'succeeded')))`

func (s *Store) query(ctx context.Context, clause string, args ...any) ([]Campaign, error) {
	rows, err := s.pool.Query(ctx, campaignColumns+clause, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	return scanCampaigns(rows)
}

func scanCampaigns(rows pgx.Rows) ([]Campaign, error) {
	var campaigns []Campaign
	for rows.Next() {
		var c Campaign
		if err := rows.Scan(&c.ID, &c.Name, &c.ActionType, &c.Payload, &c.Selector, &c.State,
			&c.CanarySize, &c.WaveSize, &c.MaxConcurrent,
			&c.FailureThresholdPercent, &c.FailureThresholdAbsolute,
			&c.MaintenanceStart, &c.MaintenanceEnd, &c.RebootPolicy, &c.HealthCheckUnits,
			&c.JobTimeoutSeconds, &c.RequiresApproval, &c.ApprovalFingerprint, &c.PlanSetHash,
			&c.ApprovedBy, &c.ApprovedAt, &c.PausedBy, &c.PauseReason, &c.CanceledBy,
			&c.CreatedBy, &c.RequestID, &c.StartedAt, &c.FinishedAt,
			&c.CreatedAt, &c.UpdatedAt,
			&c.OfflinePolicy, &c.DeadlineAt, &c.ManualGate, &c.GateAdvancedBy,
			&c.GateAdvancedAt, &c.ConnectivityLostAbsolute, &c.RebootTimeoutSeconds,
			&c.CompensatesCampaignID, &c.CompensatesCampaignName, &c.CompensatedBy, &c.ChangedHosts,
			&c.PolicyID, &c.PolicyVersion,
			&c.RetriesCampaignID, &c.RetriesCampaignName, &c.RetriedBy,
			&c.Revision, &c.RunnerID, &c.RunnerToken, &c.RunnerUntil); err != nil {
			return nil, err
		}
		campaigns = append(campaigns, c)
	}
	return campaigns, rows.Err()
}

// Targets returns the campaign's targets in wave order.
func (s *Store) Targets(ctx context.Context, campaignID string) ([]Target, error) {
	page, err := s.TargetsPage(ctx, campaignID, TargetFilter{}, TargetCursor{}, 0)
	if err != nil {
		return nil, err
	}
	return page.Items, nil
}

// TargetFilter narrows a page of targets. Every field is optional.
type TargetFilter struct {
	// State keeps only the targets in this state.
	State string
	// Wave keeps only one wave when WaveSet is true.
	Wave    int
	WaveSet bool
	// Search keeps the hosts whose name contains the text.
	Search string
}

// TargetCursor is the position of the last row of the previous page.
type TargetCursor struct {
	Wave     int
	Position int
	Set      bool
}

// ParseTargetCursor reads a cursor of the form "wave:position".
func ParseTargetCursor(value string) (TargetCursor, error) {
	if value == "" {
		return TargetCursor{}, nil
	}
	var cursor TargetCursor
	if _, err := fmt.Sscanf(value, "%d:%d", &cursor.Wave, &cursor.Position); err != nil {
		return TargetCursor{}, fmt.Errorf("invalid cursor %q", value)
	}
	cursor.Set = true
	return cursor, nil
}

// String renders the cursor for the next request.
func (c TargetCursor) String() string {
	return fmt.Sprintf("%d:%d", c.Wave, c.Position)
}

// TargetPage is one page of a campaign's targets.
type TargetPage struct {
	Items []Target `json:"items"`
	// Total is the number of targets matching the filter, all pages included: the
	// operator is to know how many hosts a filter names, not how many fit on the
	// screen.
	Total int `json:"total"`
	// NextCursor is empty on the last page.
	NextCursor string `json:"next_cursor,omitempty"`
}

// maxTargetPage bounds a page. A screen showing more rows than that is not
// a screen anybody reads; larger reads go page by page.
const maxTargetPage = 1000

// TargetsPage reads the targets of a campaign page by page, in the order of
// the rollout.
func (s *Store) TargetsPage(ctx context.Context, campaignID string, filter TargetFilter,
	cursor TargetCursor, limit int) (TargetPage, error) {
	if limit > maxTargetPage {
		limit = maxTargetPage
	}
	where := "where t.campaign_id = $1"
	args := []any{campaignID}
	if filter.State != "" {
		args = append(args, filter.State)
		where += fmt.Sprintf(" and t.state = $%d", len(args))
	}
	if filter.WaveSet {
		args = append(args, filter.Wave)
		where += fmt.Sprintf(" and t.wave = $%d", len(args))
	}
	if filter.Search != "" {
		args = append(args, "%"+filter.Search+"%")
		where += fmt.Sprintf(" and h.hostname ilike $%d", len(args))
	}

	page := TargetPage{Items: []Target{}}
	if err := s.pool.QueryRow(ctx, `select count(*) from campaign_targets t
		left join hosts h on h.id = t.host_id `+where, args...).Scan(&page.Total); err != nil {
		return page, err
	}

	if cursor.Set {
		args = append(args, cursor.Wave, cursor.Position)
		where += fmt.Sprintf(" and (t.wave, t.position) > ($%d, $%d)", len(args)-1, len(args))
	}
	query := `
		select t.id, t.campaign_id, t.host_id, coalesce(h.hostname, ''), t.wave, t.position,
		       t.state, t.job_id, t.plan_job_id, t.reboot_job_id, t.health_job_id,
		       coalesce(t.boot_id_before, ''),
		       coalesce(t.error_code, ''), coalesce(t.message, ''), t.started_at, t.finished_at,
		       t.state_since, t.blocker,
		       t.revision, coalesce(t.claimed_by::text, ''), t.claim_token, t.cancel_requested_at,
		       coalesce(j.cancel_outcome, ''), coalesce(j.cancel_phase, '')
		from campaign_targets t
		left join hosts h on h.id = t.host_id
		left join jobs j on j.id = t.job_id ` + where + `
		order by t.wave, t.position`
	if limit > 0 {
		// One row more than the page says whether there is a next page
		// without a second count.
		args = append(args, limit+1)
		query += fmt.Sprintf(" limit $%d", len(args))
	}
	rows, err := s.pool.Query(ctx, query, args...)
	if err != nil {
		return page, err
	}
	defer rows.Close()

	for rows.Next() {
		var t Target
		if err := rows.Scan(&t.ID, &t.CampaignID, &t.HostID, &t.Hostname, &t.Wave, &t.Position,
			&t.State, &t.JobID, &t.PlanJobID, &t.RebootJobID, &t.HealthJobID, &t.BootIDBefore,
			&t.ErrorCode, &t.Message, &t.StartedAt, &t.FinishedAt, &t.StateSince, &t.Blocker,
			&t.Revision, &t.ClaimedBy, &t.ClaimToken, &t.CancelRequestedAt,
			&t.CancelOutcome, &t.CancelPhase); err != nil {
			return page, err
		}
		page.Items = append(page.Items, t)
	}
	if err := rows.Err(); err != nil {
		return page, err
	}
	if limit > 0 && len(page.Items) > limit {
		page.Items = page.Items[:limit]
		last := page.Items[limit-1]
		page.NextCursor = TargetCursor{Wave: last.Wave, Position: last.Position}.String()
	}
	return page, nil
}

// UpdateTarget records the state of a campaign target.
func (s *Store) UpdateTarget(ctx context.Context, target *Target, state TargetState,
	errorCode, message string) error {
	revision, err := s.updateTarget(ctx, s.pool, target, state, errorCode, message)
	if err != nil {
		return err
	}
	target.Revision = revision
	target.State = state
	target.ErrorCode = errorCode
	target.Message = message
	return nil
}

// UpdateTargetTx records the state inside the caller's transaction.
func (s *Store) UpdateTargetTx(ctx context.Context, tx pgx.Tx, target *Target, state TargetState,
	errorCode, message string) (int64, error) {
	return s.updateTarget(ctx, tx, target, state, errorCode, message)
}

func (s *Store) updateTarget(ctx context.Context, q stepQuerier, target *Target, state TargetState,
	errorCode, message string) (int64, error) {
	if !target.State.mayBecome(state) {
		return 0, fmt.Errorf("%w: a %s host cannot become %s", ErrIllegalTransition, target.State, state)
	}
	// The previous state and the moment it was entered come back with the update:
	// the time spent in a state is measured when it is left, and only this
	// statement knows both ends.
	const query = `
		update campaign_targets t set
			state       = $5,
			revision    = t.revision + 1,
			error_code  = $6,
			message     = $7,
			started_at  = coalesce(t.started_at,
			                       case when $5 not in ('pending', 'awaiting_budget', 'queued_offline')
			                            then now() end),
			finished_at = case when $5 in ('succeeded', 'no_change', 'failed', 'unknown', 'skipped', 'canceled')
			                   then now() else t.finished_at end,
			settled_at  = case when $5 in ('succeeded', 'no_change', 'failed', 'unknown', 'skipped', 'canceled')
			                   then now() else t.settled_at end,
			state_since = case when t.state <> $5 then now() else t.state_since end,
			blocker     = case when $5 in ('succeeded', 'no_change', 'failed', 'unknown', 'skipped', 'canceled')
			                   then '' else t.blocker end
		from (select t.id, t.state, t.state_since, c.action_type
		        from campaign_targets t join campaigns c on c.id = t.campaign_id
		       where t.id = $1 for update of t) old
		where t.id = old.id and t.revision = $2 and t.state = $3 and t.claim_token = $4
		returning t.revision, old.state, extract(epoch from now() - old.state_since)::float8, old.action_type`
	var previous, actionType string
	var seconds float64
	var revision int64
	err := q.QueryRow(ctx, query, target.ID, target.Revision, string(target.State), target.ClaimToken,
		string(state), nullable(errorCode), nullable(message)).
		Scan(&revision, &previous, &seconds, &actionType)
	if errors.Is(err, pgx.ErrNoRows) {
		return 0, ErrConcurrentTransition
	}
	if err != nil {
		return 0, err
	}
	if previous != string(state) {
		metrics.TargetStateDuration.Observe(seconds, previous, actionType)
	}
	return revision, nil
}

// TransitionTarget moves a target from one state to another against the
// revision and the claim token the caller read.
func (s *Store) TransitionTarget(ctx context.Context, id string, expectedRevision int64,
	from, to TargetState, token int64) (int64, error) {
	target := Target{ID: id, Revision: expectedRevision, State: from, ClaimToken: token}
	return s.updateTarget(ctx, s.pool, &target, to, "", "")
}

// FollowTask records where the open task of a target stands: dispatched,
// waiting for a lock with the blocker the agent named, or running.
func (s *Store) FollowTask(ctx context.Context, target *Target, state TargetState, blocker string) error {
	if !target.State.mayBecome(state) {
		return fmt.Errorf("%w: a %s host cannot become %s", ErrIllegalTransition, target.State, state)
	}
	const query = `
		update campaign_targets t set
			state       = $5,
			revision    = t.revision + 1,
			blocker     = $6,
			state_since = case when t.state <> $5 then now() else t.state_since end
		from (select t.id, t.state, t.state_since, c.action_type
		        from campaign_targets t join campaigns c on c.id = t.campaign_id
		       where t.id = $1 for update of t) old
		where t.id = old.id and t.revision = $2 and t.state = $3 and t.claim_token = $4
		returning t.revision, old.state, extract(epoch from now() - old.state_since)::float8, old.action_type`
	var previous, actionType string
	var seconds float64
	var revision int64
	err := s.pool.QueryRow(ctx, query, target.ID, target.Revision, string(target.State), target.ClaimToken,
		string(state), blocker).Scan(&revision, &previous, &seconds, &actionType)
	if errors.Is(err, pgx.ErrNoRows) {
		return ErrConcurrentTransition
	}
	if err != nil {
		return err
	}
	if previous != string(state) {
		metrics.TargetStateDuration.Observe(seconds, previous, actionType)
	}
	target.Revision = revision
	target.State = state
	target.Blocker = blocker
	return nil
}

// AttachJobTx binds a target to the task that was created, inside the caller's
// transaction - the one that creates the task and moves the target, so a
// target never names a task that does not exist and a task is never created.
func (s *Store) AttachJobTx(ctx context.Context, tx pgx.Tx, target *Target, column, jobID string) error {
	return s.attachJob(ctx, tx, target, column, jobID)
}

// attachJob writes the task identifier under the claim the caller holds.
func (s *Store) attachJob(ctx context.Context, q stepQuerier, target *Target, column, jobID string) error {
	var query string
	switch column {
	case "job_id":
		query = `update campaign_targets set job_id = $2 where id = $1 and revision = $3 and claim_token = $4`
	case "reboot_job_id":
		query = `update campaign_targets set reboot_job_id = $2 where id = $1 and revision = $3 and claim_token = $4`
	case "health_job_id":
		query = `update campaign_targets set health_job_id = $2 where id = $1 and revision = $3 and claim_token = $4`
	case "plan_job_id":
		query = `update campaign_targets set plan_job_id = $2 where id = $1 and revision = $3 and claim_token = $4`
	default:
		return fmt.Errorf("unknown task column %q", column)
	}
	tag, err := q.Exec(ctx, query, target.ID, jobID, target.Revision, target.ClaimToken)
	if err != nil {
		return err
	}
	if tag.RowsAffected() == 0 {
		return ErrConcurrentTransition
	}
	return nil
}

// SetBootIDBeforeTx records the boot ID from before the reboot, inside the
// transaction that orders the reboot: the proof the host came back is written
// with the order, never beside it.
func (s *Store) SetBootIDBeforeTx(ctx context.Context, tx pgx.Tx, target *Target, bootID string) error {
	return s.setBootIDBefore(ctx, tx, target, bootID)
}

func (s *Store) setBootIDBefore(ctx context.Context, q stepQuerier, target *Target, bootID string) error {
	tag, err := q.Exec(ctx,
		`update campaign_targets set boot_id_before = $2 where id = $1 and revision = $3 and claim_token = $4`,
		target.ID, nullable(bootID), target.Revision, target.ClaimToken)
	if err != nil {
		return err
	}
	if tag.RowsAffected() == 0 {
		return ErrConcurrentTransition
	}
	return nil
}

// ErrSkipNotAllowed says the host is not one an operator may skip: only a host
// waiting for its connection is, because only such a host is holding the
// campaign for nothing - a host under way settles on its own, and a host in.
var ErrSkipNotAllowed = errors.New("skip_not_allowed: only a host waiting for its connection can be skipped")

// SkipTarget lets an operator leave a host waiting for its connection out of
// the campaign, with a reason: the offline canary the document lets the
// operator skip by name so that the wave barrier opens.
func (s *Store) SkipTarget(ctx context.Context, campaignID, hostID, actor, reason string) (*Target, error) {
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return nil, err
	}
	defer func() { _ = tx.Rollback(ctx) }()

	campaign, err := s.getTx(ctx, tx, campaignID)
	if err != nil {
		return nil, err
	}
	if campaign.State.Terminal() {
		return nil, ErrConflict
	}
	var target Target
	err = tx.QueryRow(ctx, `
		select id, campaign_id, host_id, wave, position, state, revision, claim_token, job_id, reboot_job_id
		  from campaign_targets where campaign_id = $1 and host_id = $2::uuid for update`,
		campaignID, hostID).Scan(&target.ID, &target.CampaignID, &target.HostID, &target.Wave, &target.Position,
		&target.State, &target.Revision, &target.ClaimToken, &target.JobID, &target.RebootJobID)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, err
	}
	if target.State != TargetQueuedOffline {
		return nil, ErrSkipNotAllowed
	}
	message := "skipped by " + actor + ": " + reason
	revision, err := s.updateTarget(ctx, tx, &target, TargetSkipped, SkippedByOperatorCode, message)
	if err != nil {
		return nil, err
	}
	// The strip of the host says who left it out and why, on the step it
	// was waiting to run.
	for _, outcome := range settledOutcomes(*campaign, &target, TargetSkipped, SkippedByOperatorCode, message) {
		if err := s.RecordStep(ctx, tx, StepRecord{
			Target: target, Key: outcome.Key,
			DependsOn: dependencyOf(outcome.Key, campaignPlans(*campaign), target.RebootJobID != nil),
			State:     outcome.State, Reason: outcome.Reason,
		}); err != nil {
			return nil, err
		}
	}
	if err := tx.Commit(ctx); err != nil {
		return nil, err
	}
	target.Revision = revision
	target.State = TargetSkipped
	target.ErrorCode = SkippedByOperatorCode
	target.Message = message
	return &target, nil
}

// Counts returns the number of targets in each state.
func (s *Store) Counts(ctx context.Context, campaignID string) (map[string]int, error) {
	const query = `select state, count(*) from campaign_targets where campaign_id = $1 group by state`
	rows, err := s.pool.Query(ctx, query, campaignID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	counts := map[string]int{}
	for rows.Next() {
		var state string
		var count int
		if err := rows.Scan(&state, &count); err != nil {
			return nil, err
		}
		counts[state] = count
	}
	return counts, rows.Err()
}

// nullableInt writes zero as NULL: a campaign without a policy has no
// version of it.
func nullableInt(value int) any {
	if value == 0 {
		return nil
	}
	return value
}

func nullable(value string) any {
	if value == "" {
		return nil
	}
	return value
}

func itoa(value int) string {
	return fmt.Sprintf("%d", value)
}
