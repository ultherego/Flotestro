package campaigns

import (
	"context"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
)

// StepKey names one executable step of a target.
//
// A host in a campaign does not run "the campaign": it computes a plan,
// carries the change, reboots when the policy asks, verifies its units and
// - after a failure - runs the approved way back. Every one of those is a
// step of its own with its own task, its own attempts and its own reason
// for not running. The target's state says where the host stands; the
// steps say how it got there.
type StepKey string

const (
	StepPlan       StepKey = "plan"
	StepExecute    StepKey = "execute"
	StepReboot     StepKey = "reboot"
	StepVerify     StepKey = "verify"
	StepCompensate StepKey = "compensate"
)

// StepOrder is the order the steps of a host run in, which is also their
// dependency order: the chain is linear.
var StepOrder = []StepKey{StepPlan, StepExecute, StepReboot, StepVerify, StepCompensate}

// StepState is the state of one step.
type StepState string

const (
	StepPending   StepState = "pending"
	StepRunning   StepState = "running"
	StepSucceeded StepState = "succeeded"
	StepFailed    StepState = "failed"
	StepSkipped   StepState = "skipped"
	StepCanceled  StepState = "canceled"
)

// Open says whether the step still awaits its outcome.
func (s StepState) Open() bool {
	return s == StepPending || s == StepRunning
}

// Step is one executable step of a campaign target as the API returns it.
type Step struct {
	ID         string  `json:"id"`
	CampaignID string  `json:"campaign_id"`
	TargetID   string  `json:"target_id"`
	HostID     string  `json:"host_id"`
	Hostname   string  `json:"hostname,omitempty"`
	StepKey    StepKey `json:"step_key"`
	// DependsOn is the step this one waited for; empty for the first step
	// of the host.
	DependsOn StepKey `json:"depends_on,omitempty"`
	// PlanHash is the digest of the plan the step ran under. The plan step
	// has none - it is what computes the digest - and neither has a
	// campaign without a planner.
	PlanHash string    `json:"plan_hash,omitempty"`
	State    StepState `json:"state"`
	// JobID is the task of the latest attempt; absent for a step settled
	// without a task and for a remediation, which runs its own plan.
	JobID    *string `json:"job_id,omitempty"`
	Attempts int     `json:"attempts"`
	// Reason says why the step ended the way it did. It is never empty for
	// a step that failed, was skipped or was canceled.
	Reason     string     `json:"reason,omitempty"`
	CreatedAt  time.Time  `json:"created_at"`
	StartedAt  *time.Time `json:"started_at,omitempty"`
	FinishedAt *time.Time `json:"finished_at,omitempty"`
	UpdatedAt  time.Time  `json:"updated_at"`
	// Wave and Position place the step's target in the rollout; they order
	// the list and carry the cursor.
	Wave     int `json:"wave"`
	Position int `json:"position"`
}

// stepQuerier is what the step statements need; both the pool and a
// transaction provide it. A step is written next to the target's
// transition, so the statement must run on the caller's connection.
type stepQuerier interface {
	Exec(ctx context.Context, sql string, args ...any) (pgconn.CommandTag, error)
	Query(ctx context.Context, sql string, args ...any) (pgx.Rows, error)
	QueryRow(ctx context.Context, sql string, args ...any) pgx.Row
}

// StepRecord describes a step to write.
type StepRecord struct {
	Target    Target
	Key       StepKey
	DependsOn StepKey
	PlanHash  string
	State     StepState
	// JobID is the task carrying the step; empty for a step that has none.
	JobID  string
	Reason string
}

// RecordStep writes a step that comes into being already settled or waiting:
// a step the engine decided not to run, with the reason, or one it queued.
//
// A step recorded again for the same target and plan is the same step; the
// record then replaces its state and reason, and the attempt count stays,
// because nothing was ordered.
func (s *Store) RecordStep(ctx context.Context, q stepQuerier, record StepRecord) error {
	if err := record.validate(); err != nil {
		return err
	}
	const query = `
		insert into campaign_steps (campaign_id, target_id, host_id, step_key, depends_on,
		                            plan_hash, state, job_id, reason, finished_at)
		values ($1, $2, $3, $4, $5, $6, $7, $8, $9,
		        case when $7 in ('succeeded', 'failed', 'skipped', 'canceled') then now() end)
		on conflict (target_id, step_key, plan_hash) do update
		   set state       = excluded.state,
		       depends_on  = coalesce(excluded.depends_on, campaign_steps.depends_on),
		       job_id      = coalesce(excluded.job_id, campaign_steps.job_id),
		       reason      = excluded.reason,
		       finished_at = excluded.finished_at,
		       updated_at  = now()`
	_, err := q.Exec(ctx, query, record.Target.CampaignID, record.Target.ID, record.Target.HostID,
		string(record.Key), nullable(string(record.DependsOn)), nullable(record.PlanHash),
		string(record.State), nullable(record.JobID), nullable(record.Reason))
	if err != nil {
		return fmt.Errorf("recording the %s step: %w", record.Key, err)
	}
	return nil
}

// StartStep records that a step was ordered: the task exists and the host
// is about to carry it.
//
// The same step ordered again - a plan computed once more after a
// reconnect - is the next attempt of the same row: the task changes, the
// count grows, the outcome opens again. Two rows for one step would make
// the unique index a lie and the strip on the screen a puzzle.
func (s *Store) StartStep(ctx context.Context, q stepQuerier, record StepRecord) error {
	record.State = StepRunning
	if err := record.validate(); err != nil {
		return err
	}
	const query = `
		insert into campaign_steps (campaign_id, target_id, host_id, step_key, depends_on,
		                            plan_hash, state, job_id, reason, attempts, started_at)
		values ($1, $2, $3, $4, $5, $6, 'running', $7, $8, 1, now())
		on conflict (target_id, step_key, plan_hash) do update
		   set state       = 'running',
		       depends_on  = coalesce(excluded.depends_on, campaign_steps.depends_on),
		       job_id      = excluded.job_id,
		       reason      = excluded.reason,
		       attempts    = campaign_steps.attempts + 1,
		       started_at  = now(),
		       finished_at = null,
		       updated_at  = now()`
	_, err := q.Exec(ctx, query, record.Target.CampaignID, record.Target.ID, record.Target.HostID,
		string(record.Key), nullable(string(record.DependsOn)), nullable(record.PlanHash),
		nullable(record.JobID), nullable(record.Reason))
	if err != nil {
		return fmt.Errorf("starting the %s step: %w", record.Key, err)
	}
	return nil
}

// FinishStep settles the open step of the given kind on a target. It says
// whether there was one.
//
// Only an open step is settled: a step already closed keeps its outcome,
// so a pass of the orchestrator repeated after a crash changes nothing. A
// target with no open step of that kind is not an error either - the
// step was never ordered, and the caller records that fact separately.
func (s *Store) FinishStep(ctx context.Context, q stepQuerier, targetID string, key StepKey,
	state StepState, reason string) (bool, error) {
	if state.Open() {
		return false, fmt.Errorf("the %s step cannot be finished into %s", key, state)
	}
	if reason == "" && (state == StepFailed || state == StepSkipped || state == StepCanceled) {
		return false, fmt.Errorf("the %s step ends %s without a reason", key, state)
	}
	const query = `
		update campaign_steps
		   set state = $3, reason = $4, finished_at = now(), updated_at = now()
		 where target_id = $1 and step_key = $2 and state in ('pending', 'running')`
	tag, err := q.Exec(ctx, query, targetID, string(key), string(state), nullable(reason))
	if err != nil {
		return false, fmt.Errorf("finishing the %s step: %w", key, err)
	}
	return tag.RowsAffected() > 0, nil
}

func (r StepRecord) validate() error {
	if r.Target.ID == "" || r.Target.CampaignID == "" || r.Target.HostID == "" {
		return fmt.Errorf("a step needs its target, campaign and host")
	}
	if !knownStep(r.Key) {
		return fmt.Errorf("unknown step %q", r.Key)
	}
	if r.DependsOn != "" && !knownStep(r.DependsOn) {
		return fmt.Errorf("unknown step dependency %q", r.DependsOn)
	}
	if r.Reason == "" && (r.State == StepFailed || r.State == StepSkipped || r.State == StepCanceled) {
		return fmt.Errorf("the %s step is %s without a reason", r.Key, r.State)
	}
	return nil
}

func knownStep(key StepKey) bool {
	for _, known := range StepOrder {
		if known == key {
			return true
		}
	}
	return false
}

// StepsOfTarget returns the steps of one target in dependency order.
func (s *Store) StepsOfTarget(ctx context.Context, targetID string) ([]Step, error) {
	rows, err := s.pool.Query(ctx, stepColumns+` where s.target_id = $1 order by `+stepRank, targetID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	return scanSteps(rows)
}

// StepPage is one page of a campaign's steps. The page is cut by target,
// never in the middle of a host: a strip of steps torn between two pages
// would show a host with half its course.
type StepPage struct {
	Items []Step `json:"items"`
	// NextCursor is empty on the last page.
	NextCursor string `json:"next_cursor,omitempty"`
}

// maxStepTargets bounds the targets one page of steps covers.
const maxStepTargets = 1000

// StepsOfCampaign reads the steps of a campaign page by page in the order
// of the rollout - wave, position, then the dependency order of the steps
// within a host. The limit counts targets, not steps: a page holds whole
// hosts. An empty host identifier means every host.
func (s *Store) StepsOfCampaign(ctx context.Context, campaignID, hostID string,
	cursor TargetCursor, limit int) (StepPage, error) {
	if limit <= 0 || limit > maxStepTargets {
		limit = maxStepTargets
	}
	page := StepPage{Items: []Step{}}

	// The page of targets first: which hosts fit, and where the next page
	// starts. One row more than the page says whether there is a next page.
	where := "where t.campaign_id = $1"
	args := []any{campaignID}
	if hostID != "" {
		args = append(args, hostID)
		where += fmt.Sprintf(" and t.host_id = $%d", len(args))
	}
	if cursor.Set {
		args = append(args, cursor.Wave, cursor.Position)
		where += fmt.Sprintf(" and (t.wave, t.position) > ($%d, $%d)", len(args)-1, len(args))
	}
	args = append(args, limit+1)
	rows, err := s.pool.Query(ctx, `select t.id, t.wave, t.position from campaign_targets t `+where+
		fmt.Sprintf(" order by t.wave, t.position limit $%d", len(args)), args...)
	if err != nil {
		return page, err
	}
	targetIDs := []string{}
	var last TargetCursor
	for rows.Next() {
		var id string
		var wave, position int
		if err := rows.Scan(&id, &wave, &position); err != nil {
			rows.Close()
			return page, err
		}
		if len(targetIDs) == limit {
			page.NextCursor = last.String()
			break
		}
		targetIDs = append(targetIDs, id)
		last = TargetCursor{Wave: wave, Position: position}
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return page, err
	}
	if len(targetIDs) == 0 {
		return page, nil
	}

	rows, err = s.pool.Query(ctx, stepColumns+` where s.target_id = any($1)
		order by t.wave, t.position, `+stepRank, targetIDs)
	if err != nil {
		return page, err
	}
	defer rows.Close()
	page.Items, err = scanSteps(rows)
	return page, err
}

// stepRank orders the steps of one host the way they run.
const stepRank = `array_position(array['plan', 'execute', 'reboot', 'verify', 'compensate'], s.step_key)`

const stepColumns = `
	select s.id, s.campaign_id, s.target_id, s.host_id, coalesce(h.hostname, ''),
	       s.step_key, coalesce(s.depends_on, ''), coalesce(s.plan_hash, ''), s.state,
	       s.job_id, s.attempts, coalesce(s.reason, ''),
	       s.created_at, s.started_at, s.finished_at, s.updated_at, t.wave, t.position
	  from campaign_steps s
	  join campaign_targets t on t.id = s.target_id
	  left join hosts h on h.id = s.host_id`

func scanSteps(rows pgx.Rows) ([]Step, error) {
	steps := []Step{}
	for rows.Next() {
		var step Step
		if err := rows.Scan(&step.ID, &step.CampaignID, &step.TargetID, &step.HostID, &step.Hostname,
			&step.StepKey, &step.DependsOn, &step.PlanHash, &step.State,
			&step.JobID, &step.Attempts, &step.Reason,
			&step.CreatedAt, &step.StartedAt, &step.FinishedAt, &step.UpdatedAt,
			&step.Wave, &step.Position); err != nil {
			return nil, err
		}
		steps = append(steps, step)
	}
	return steps, rows.Err()
}

// stepOutcome is how one step of a target ended, as the engine settles it
// together with the target.
type stepOutcome struct {
	Key    StepKey
	State  StepState
	Reason string
}

// stepReason joins an error code and a message into the reason of a step.
// The code alone is a reason: it names what happened even when the
// message is empty.
func stepReason(code, message string) string {
	switch {
	case code == "":
		return message
	case message == "":
		return code
	default:
		return code + ": " + message
	}
}

// runningStep says which step a target in the given state is carrying.
// A waiting state carries none.
func runningStep(state TargetState) StepKey {
	switch state {
	case TargetPlanning:
		return StepPlan
	case TargetRunning:
		return StepExecute
	case TargetRebooting:
		return StepReboot
	case TargetVerifying:
		return StepVerify
	default:
		return ""
	}
}

// nextStep says which step a waiting target would have run next: the plan
// while the campaign plans, the change otherwise. A target settled while
// waiting gets that step recorded with the reason, so the strip on the
// screen says "skipped because ..." rather than showing nothing at all.
func nextStep(campaign Campaign) StepKey {
	if campaign.State == StatePlanning {
		return StepPlan
	}
	return StepExecute
}

// stepStateOf maps the state a target is settled into onto the state of
// the step that carried it. A host ruled ineligible by its own plan ran
// the plan step to the end: the answer was "no", which is an outcome of the
// plan rather than a failure of the read.
func stepStateOf(state TargetState) StepState {
	switch state {
	case TargetSucceeded, TargetIneligible:
		return StepSucceeded
	case TargetFailed:
		return StepFailed
	case TargetSkipped:
		return StepSkipped
	case TargetCanceled:
		return StepCanceled
	default:
		return StepPending
	}
}

// settledOutcomes derives the outcome of the target's step from the state
// it is settled into. A target with a running step settles that step; a
// waiting target settles the step it would have run next, which never
// ran and says why.
func settledOutcomes(campaign Campaign, target *Target, state TargetState,
	code, message string) []stepOutcome {
	reason := stepReason(code, message)
	if key := runningStep(target.State); key != "" {
		return []stepOutcome{{Key: key, State: stepStateOf(state), Reason: reason}}
	}
	if !target.State.Waiting() {
		return nil
	}
	stepState := stepStateOf(state)
	if stepState == StepSucceeded {
		// A waiting host settled as succeeded ran nothing; there is no step
		// to credit and nothing to explain.
		return nil
	}
	return []stepOutcome{{Key: nextStep(campaign), State: stepState, Reason: reason}}
}

// dependencyOf says which step a step of the given kind followed on this
// target. The plan is first; the change follows the plan where the
// campaign has one; the reboot follows the change; the verification
// follows the reboot where there was one and the change otherwise.
func dependencyOf(key StepKey, planned, rebooted bool) StepKey {
	switch key {
	case StepExecute:
		if planned {
			return StepPlan
		}
	case StepReboot:
		return StepExecute
	case StepVerify:
		if rebooted {
			return StepReboot
		}
		return StepExecute
	case StepCompensate:
		return StepExecute
	}
	return ""
}
