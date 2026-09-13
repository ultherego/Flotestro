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
	"github.com/ultherego/flotestro/internal/opspec"
)

var (
	// ErrNotFound means there is no such campaign.
	ErrNotFound = errors.New("the campaign does not exist")
	// ErrConflict means an operation not allowed in the current state.
	ErrConflict = errors.New("the operation is not allowed in the current state of the campaign")
	// ErrNoTargets means a selector that named no host.
	ErrNoTargets = errors.New("the selector named no host")
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
	// State and Reason describe a host that is already settled at the moment
	// the campaign is created: ineligible for this operation or inside a
	// maintenance window. An empty state means a host ready to work.
	State   TargetState
	Reason  string
	Message string
}

// Create creates a campaign together with an immutable snapshot of its
// targets. The division into waves happens at planning time: a host added to
// the fleet later will not enter a campaign under way without the operator
// knowing.
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
	// A change computed per host starts with planning: the consent is to
	// concern the diffs, and those are yet to come into being.
	if opspec.PlanningAction(opspec.ActionType(spec.ActionType)) != "" {
		state = StatePlanning
	}
	campaignID := uuid.NewString()

	// The fingerprint comes from the same description that reaches the
	// database. The approval will have to quote it, so the consent concerns
	// this list of hosts and this policy rather than the campaign identifier
	// alone.
	fingerprint, err := Fingerprint(spec, hosts)
	if err != nil {
		return nil, err
	}

	const insert = `
		insert into campaigns (id, name, action_type, payload, selector, state,
		                       canary_size, wave_size, max_concurrent,
		                       failure_threshold_percent, failure_threshold_absolute,
		                       maintenance_start, maintenance_end, reboot_policy,
		                       health_check_units, job_timeout_seconds,
		                       requires_approval, created_by, request_id,
		                       approval_fingerprint)
		values ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16, $17, $18, $19, $20)`
	if _, err := tx.Exec(ctx, insert, campaignID, spec.Name, spec.ActionType, payload, selectorJSON,
		string(state), spec.CanarySize, spec.WaveSize, spec.MaxConcurrent,
		spec.FailureThresholdPercent, spec.FailureThresholdAbsolute,
		spec.MaintenanceStart, spec.MaintenanceEnd, string(spec.RebootPolicy),
		healthChecks, spec.JobTimeoutSeconds,
		spec.RequiresApproval, spec.CreatedBy, nullable(spec.RequestID),
		fingerprint); err != nil {
		return nil, fmt.Errorf("creating the campaign: %w", err)
	}

	// We count the waves from the ready hosts only. A host settled right away
	// must not take a place in the canary: a canary made of hosts that will
	// do nothing is not a trial on a small group.
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
func (s *Store) Approve(ctx context.Context, tx pgx.Tx, campaignID, actor string) (*Campaign, error) {
	const query = `
		update campaigns set state = $2, approved_by = $3, approved_at = now(), updated_at = now()
		where id = $1 and state = $4
		returning id`
	var updated string
	err := tx.QueryRow(ctx, query, campaignID, string(StatePlanned), actor,
		string(StateAwaitingApproval)).Scan(&updated)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, ErrConflict
	}
	if err != nil {
		return nil, err
	}
	return s.getTx(ctx, tx, campaignID)
}

// Pause holds a campaign back. The hosts already started finish their tasks.
func (s *Store) Pause(ctx context.Context, campaignID, actor, reason string) (*Campaign, error) {
	const query = `
		update campaigns set state = $2, paused_by = $3, paused_at = now(),
		                     pause_reason = $4, updated_at = now()
		where id = $1 and state in ('planned', 'canary', 'running')
		returning id`
	var updated string
	err := s.pool.QueryRow(ctx, query, campaignID, string(StatePaused), actor, nullable(reason)).Scan(&updated)
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
		                     pause_reason = null, updated_at = now()
		where id = $1 and state = $3
		returning id`
	var updated string
	err := s.pool.QueryRow(ctx, query, campaignID, string(StatePlanned), string(StatePaused)).Scan(&updated)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, ErrConflict
	}
	if err != nil {
		return nil, err
	}
	return s.Get(ctx, campaignID)
}

// Cancel ends a campaign. The targets that have not started are skipped.
func (s *Store) Cancel(ctx context.Context, campaignID, actor, reason string) (*Campaign, error) {
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return nil, err
	}
	defer func() { _ = tx.Rollback(ctx) }()

	const query = `
		update campaigns set state = $2, canceled_by = $3, canceled_at = now(),
		                     pause_reason = $4, finished_at = now(), updated_at = now()
		where id = $1 and state not in ('completed', 'failed', 'canceled')
		returning id`
	var updated string
	err = tx.QueryRow(ctx, query, campaignID, string(StateCanceled), actor, nullable(reason)).Scan(&updated)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, ErrConflict
	}
	if err != nil {
		return nil, err
	}

	// The hosts that have not started will not be started.
	if _, err := tx.Exec(ctx, `
		update campaign_targets set state = 'canceled', finished_at = now()
		where campaign_id = $1 and state in ('pending', 'awaiting_budget')`,
		campaignID); err != nil {
		return nil, err
	}
	if err := tx.Commit(ctx); err != nil {
		return nil, err
	}
	return s.Get(ctx, campaignID)
}

// SetState changes the state of a campaign.
func (s *Store) SetState(ctx context.Context, campaignID string, state State, reason string) error {
	const query = `
		update campaigns set state = $2, updated_at = now(),
			pause_reason = case when $2 = 'paused' then $3 else pause_reason end,
			paused_at    = case when $2 = 'paused' then now() else paused_at end,
			paused_by    = case when $2 = 'paused' then 'system' else paused_by end,
			started_at   = coalesce(started_at, case when $2 in ('canary', 'running') then now() end),
			finished_at  = case when $2 in ('completed', 'failed', 'canceled') then now() else finished_at end
		where id = $1`
	_, err := s.pool.Exec(ctx, query, campaignID, string(state), nullable(reason))
	return err
}

// Active returns the campaigns the orchestrator has to handle.
func (s *Store) Active(ctx context.Context) ([]Campaign, error) {
	// Planning is an active state: the campaign changes nothing yet, but
	// the orchestrator has work to do - every host computes its own plan.
	return s.query(ctx,
		"where state in ('planning', 'planned', 'canary', 'running') order by created_at")
}

// SavePlan records the plan computed on one host.
//
// A plan comes into being once and is not recomputed after the approval: the
// consent concerns that diff, not what the host computes now.
func (s *Store) SavePlan(ctx context.Context, campaignID, hostID, hash string,
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
	_, err := s.pool.Exec(ctx, query, campaignID, hostID, hash, plan)
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
//
// The digest alone is enough to bind the consent but not to execute: a file
// write has to come back to the host with the digest of the content the
// operator reviewed, and that lies in the plan's content rather than in its
// digest.
func (s *Store) HostPlan(ctx context.Context, campaignID, hostID string) (string, json.RawMessage, error) {
	var hash string
	var plan json.RawMessage
	const query = `
		select plan_hash, plan from campaign_plans
		 where campaign_id = $1 and host_id = $2`
	err := s.pool.QueryRow(ctx, query, campaignID, hostID).Scan(&hash, &plan)
	if errors.Is(err, pgx.ErrNoRows) {
		return "", nil, nil
	}
	return hash, plan, err
}

// PlanEntry is one host's plan together with its content.
type PlanEntry struct {
	HostID   string          `json:"host_id"`
	Hostname string          `json:"hostname,omitempty"`
	PlanHash string          `json:"plan_hash"`
	Plan     json.RawMessage `json:"plan,omitempty"`
}

// PlansWithContent returns the plans of every host in a campaign.
//
// The consent concerns the set of plans, so the operator has to see it in
// full rather than infer it from a single digest. The host name travels
// together with the plan, because a list of identifiers tells nobody
// anything.
func (s *Store) PlansWithContent(ctx context.Context, campaignID string) ([]PlanEntry, error) {
	const query = `
		select p.host_id, coalesce(h.hostname, ''), p.plan_hash, p.plan
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
		if err := rows.Scan(&entry.HostID, &entry.Hostname, &entry.PlanHash, &entry.Plan); err != nil {
			return nil, err
		}
		entries = append(entries, entry)
	}
	return entries, rows.Err()
}

// FinishPlanning records the digest of the set of plans together with the
// approval fingerprint and moves the campaign into the state where it waits
// for a decision.
//
// The approval fingerprint changes here for the last time: from this moment
// the consent concerns one specific set of plans rather than the request
// alone.
func (s *Store) FinishPlanning(ctx context.Context, campaignID, planSetHash,
	fingerprint string, next State) error {
	const query = `
		update campaigns
		   set plan_set_hash = $2, approval_fingerprint = $3, state = $4, updated_at = now()
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
//
// The final state is visible in the tables, but the course is what the
// operator needs while it runs: when the canary started, which host failed
// first and at what time the campaign stopped. Notifications will not keep
// that - an event sent at the moment the panel restarts exists nowhere any
// more.
func (s *Store) Course(ctx context.Context, campaignID string, limit int) ([]Event, error) {
	return s.CourseAfter(ctx, campaignID, 0, limit)
}

// CourseAfter returns the trail of a campaign after the given event
// identifier. It is how a stream resumes after a broken connection and how
// a long trail is read page by page: the identifiers grow with time, so
// "after" is a cursor that no later insert can move.
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

// maxCourseEntries bounds a single read of the course. A campaign on a
// thousand hosts has a few thousand events and there is no reason to send
// them all at once.
const maxCourseEntries = 2000

// ActiveTargets says which hosts are already targets of campaigns under way.
//
// A collision does not stop a new request: the resource locks on the host
// will queue the operations anyway. But the operator is to know before the
// start - a campaign waiting for somebody else's package transaction looks
// like a campaign standing still for no reason.
func (s *Store) ActiveTargets(ctx context.Context) (map[string]string, error) {
	const query = `
		select t.host_id, t.campaign_id
		  from campaign_targets t
		  join campaigns c on c.id = t.campaign_id
		 where c.state in ('planning', 'planned', 'awaiting_approval', 'canary', 'running')
		   and t.state in ('pending', 'planning', 'awaiting_budget', 'running',
		                   'rebooting', 'verifying')`
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

// List returns the campaigns, optionally narrowed by state.
// Scope is a site-environment pair. An empty field means "any".
type Scope struct {
	Site        string
	Environment string
}

// List returns the campaigns narrowed to the scopes in which the caller has
// the right to read.
//
// A campaign has no scope of its own - it has targets. Visible is therefore
// the one that touches at least one host from the caller's scope; the
// operator of one environment sees the campaigns that concern them and does
// not see anybody else's.
func (s *Store) List(ctx context.Context, state string, limit int, scopes []Scope) ([]Campaign, error) {
	if limit <= 0 || limit > 200 {
		limit = 50
	}
	clause := "where 1 = 1"
	args := []any{}
	if state != "" {
		args = append(args, state)
		clause += fmt.Sprintf(" and state = $%d", len(args))
	}
	if warunek, dodatkowe := scopeCondition(scopes, len(args)); warunek != "" {
		clause += warunek
		args = append(args, dodatkowe...)
	}
	return s.query(ctx, clause+" order by created_at desc limit "+itoa(limit), args...)
}

// scopeCondition builds the visibility condition over a campaign's targets.
func scopeCondition(scopes []Scope, offset int) (string, []any) {
	przelozone := make([]authz.Scope, 0, len(scopes))
	for _, scope := range scopes {
		przelozone = append(przelozone, authz.Scope{Site: scope.Site, Environment: scope.Environment})
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
	       created_by, coalesce(request_id, ''), started_at, finished_at, created_at, updated_at
	from campaigns `

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
			&c.CreatedAt, &c.UpdatedAt); err != nil {
			return nil, err
		}
		campaigns = append(campaigns, c)
	}
	return campaigns, rows.Err()
}

// Targets returns the campaign's targets in wave order.
func (s *Store) Targets(ctx context.Context, campaignID string) ([]Target, error) {
	const query = `
		select t.id, t.campaign_id, t.host_id, coalesce(h.hostname, ''), t.wave, t.position,
		       t.state, t.job_id, t.plan_job_id, t.reboot_job_id, t.health_job_id,
		       coalesce(t.boot_id_before, ''),
		       coalesce(t.error_code, ''), coalesce(t.message, ''), t.started_at, t.finished_at
		from campaign_targets t
		left join hosts h on h.id = t.host_id
		where t.campaign_id = $1
		order by t.wave, t.position`
	rows, err := s.pool.Query(ctx, query, campaignID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var targets []Target
	for rows.Next() {
		var t Target
		if err := rows.Scan(&t.ID, &t.CampaignID, &t.HostID, &t.Hostname, &t.Wave, &t.Position,
			&t.State, &t.JobID, &t.PlanJobID, &t.RebootJobID, &t.HealthJobID, &t.BootIDBefore,
			&t.ErrorCode, &t.Message, &t.StartedAt, &t.FinishedAt); err != nil {
			return nil, err
		}
		targets = append(targets, t)
	}
	return targets, rows.Err()
}

// UpdateTarget records the state of a campaign target.
func (s *Store) UpdateTarget(ctx context.Context, targetID string, state TargetState,
	errorCode, message string) error {
	const query = `
		update campaign_targets set
			state       = $2,
			error_code  = $3,
			message     = $4,
			started_at  = coalesce(started_at,
			                       case when $2 not in ('pending', 'awaiting_budget')
			                            then now() end),
			finished_at = case when $2 in ('succeeded', 'failed', 'skipped', 'canceled')
			                   then now() else finished_at end
		where id = $1`
	_, err := s.pool.Exec(ctx, query, targetID, string(state), nullable(errorCode), nullable(message))
	return err
}

// AttachJob binds a target to the task that was created.
func (s *Store) AttachJob(ctx context.Context, targetID, column, jobID string) error {
	var query string
	switch column {
	case "job_id":
		query = `update campaign_targets set job_id = $2 where id = $1`
	case "reboot_job_id":
		query = `update campaign_targets set reboot_job_id = $2 where id = $1`
	case "health_job_id":
		query = `update campaign_targets set health_job_id = $2 where id = $1`
	case "plan_job_id":
		query = `update campaign_targets set plan_job_id = $2 where id = $1`
	default:
		return fmt.Errorf("unknown task column %q", column)
	}
	_, err := s.pool.Exec(ctx, query, targetID, jobID)
	return err
}

// SetBootIDBefore records the boot ID from before the reboot.
func (s *Store) SetBootIDBefore(ctx context.Context, targetID, bootID string) error {
	_, err := s.pool.Exec(ctx,
		`update campaign_targets set boot_id_before = $2 where id = $1`, targetID, nullable(bootID))
	return err
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

func nullable(value string) any {
	if value == "" {
		return nil
	}
	return value
}

func itoa(value int) string {
	return fmt.Sprintf("%d", value)
}
