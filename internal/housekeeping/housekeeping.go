// Package housekeeping deletes what the panel no longer needs to keep.
//
// Most tables of the panel grow with the fleet and stop; a few grow with
// time: every session an agent opens leaves a row, and every request leaves
// an event on the trail. Without a sweep a fleet that changes nothing still
// fills the database, and a host that reconnects in a loop fills it fast.
// The sweep runs in the panel rather than in a cron job next to it, because
// the retention is a policy of the installation and belongs where the
// other policies are set.
package housekeeping

import (
	"context"
	"fmt"
	"log/slog"
	"sync"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/ultherego/flotestro/internal/audit"
)

// SessionRetention is how long an ended agent session stays on record. The
// timeline of a host shows its sessions; a month of them is what an
// operator looks back at.
const SessionRetention = 30 * 24 * time.Hour

// The retentions of the records that grow with the work of the fleet: a
// job per host per change, a campaign per change, an event of the trail
// per state a target passes through. A quarter of finished jobs covers
// every investigation of a host's recent past; a year of campaigns keeps
// the history of the fleet's changes for a review; a month of delivered
// events is the replay window a consumer that lost its cursor could ask
// for.
const (
	JobRetention      = 90 * 24 * time.Hour
	CampaignRetention = 365 * 24 * time.Hour
	OutboxRetention   = 30 * 24 * time.Hour
)

// SweepBatch bounds what one sweep deletes of one kind. A sweep that
// deletes a year of jobs in one statement holds the locks and bloats the
// log for minutes; five thousand rows an hour drains a backlog of a
// hundred thousand in a day without anybody noticing the sweep.
const SweepBatch = 5000

// Options describes what the sweep deletes.
type Options struct {
	// Sessions is the retention of ended agent sessions. Zero means the
	// default of SessionRetention; the sessions are always swept, because
	// nothing in the panel reads a session older than that.
	Sessions time.Duration
	// Audit is the retention of the audit trail. Zero keeps the trail
	// forever: the trail is evidence, and throwing it away is a decision the
	// installation has to take explicitly.
	Audit time.Duration
	// Jobs is the retention of finished jobs, Campaigns of finished
	// campaigns and Outbox of the delivered events of the durable trail.
	// Zero means the default of each; unlike the trail they are always
	// swept, because they are the working record of the fleet and not its
	// evidence - the trail keeps who ordered what.
	Jobs      time.Duration
	Campaigns time.Duration
	Outbox    time.Duration
	// Interval is how often the sweep runs.
	Interval time.Duration
}

// Report is what the last sweep did, for the status screen: when it ran,
// what it removed by kind and whether it failed. A panel whose sweep has
// not run since it started says so rather than showing zeros.
type Report struct {
	LastSweepAt *time.Time        `json:"last_sweep_at,omitempty"`
	LastError   string            `json:"last_error,omitempty"`
	Removed     map[string]int64  `json:"removed"`
	Retention   map[string]string `json:"retention"`
}

// Sweeper runs the retention sweeps.
type Sweeper struct {
	pool    *pgxpool.Pool
	log     *slog.Logger
	options Options
	// extra are the sweeps of other stores that keep their own rules, run
	// on the same clock.
	extra []namedSweep
	// recorder writes what the sweep notices onto the trail. Nil means the
	// expiries are still enforced, but not noted.
	recorder *audit.Recorder

	// The record of the last sweep, read by the status screen from another
	// goroutine than the one that sweeps.
	mu      sync.Mutex
	lastAt  time.Time
	lastErr string
	removed map[string]int64
}

type namedSweep struct {
	name string
	run  func(ctx context.Context) error
}

// Also adds a sweep of another store to the same schedule: a store that
// knows what of its own is stale says so here rather than run a ticker of
// its own.
func (s *Sweeper) Also(name string, run func(ctx context.Context) error) *Sweeper {
	s.extra = append(s.extra, namedSweep{name: name, run: run})
	return s
}

// WithAudit attaches the recorder the sweep notes its findings with.
func (s *Sweeper) WithAudit(recorder *audit.Recorder) *Sweeper {
	s.recorder = recorder
	return s
}

// New prepares a sweeper.
func New(pool *pgxpool.Pool, log *slog.Logger, options Options) *Sweeper {
	if options.Sessions <= 0 {
		options.Sessions = SessionRetention
	}
	if options.Jobs <= 0 {
		options.Jobs = JobRetention
	}
	if options.Campaigns <= 0 {
		options.Campaigns = CampaignRetention
	}
	if options.Outbox <= 0 {
		options.Outbox = OutboxRetention
	}
	if options.Interval <= 0 {
		options.Interval = time.Hour
	}
	return &Sweeper{pool: pool, log: log, options: options, removed: map[string]int64{}}
}

// Options returns the retentions the sweeper runs with, after the defaults
// filled the gaps: what the settings screen shows as effective.
func (s *Sweeper) Options() Options {
	return s.options
}

// Report returns what the last sweep did.
func (s *Sweeper) Report() Report {
	s.mu.Lock()
	defer s.mu.Unlock()
	report := Report{
		Removed:   make(map[string]int64, len(s.removed)),
		LastError: s.lastErr,
		Retention: map[string]string{
			"agent_sessions": s.options.Sessions.String(),
			"jobs":           s.options.Jobs.String(),
			"campaigns":      s.options.Campaigns.String(),
			"outbox_events":  s.options.Outbox.String(),
		},
	}
	if s.options.Audit > 0 {
		report.Retention["audit_events"] = s.options.Audit.String()
	}
	for kind, count := range s.removed {
		report.Removed[kind] = count
	}
	if !s.lastAt.IsZero() {
		at := s.lastAt
		report.LastSweepAt = &at
	}
	return report
}

// note records the outcome of one kind of sweep for the report.
func (s *Sweeper) note(kind string, removed int64) {
	s.mu.Lock()
	s.removed[kind] = removed
	s.mu.Unlock()
}

// finish stamps the sweep as done, with its error if it had one.
func (s *Sweeper) finish(err error) {
	s.mu.Lock()
	s.lastAt = time.Now()
	s.lastErr = ""
	if err != nil {
		s.lastErr = err.Error()
	}
	s.mu.Unlock()
}

// Run sweeps at the interval until the context ends. The first sweep runs
// at once: an installation that has just set a retention is not to wait an
// hour to see it take effect.
func (s *Sweeper) Run(ctx context.Context) {
	ticker := time.NewTicker(s.options.Interval)
	defer ticker.Stop()
	for {
		s.sweep(ctx)
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
		}
	}
}

// Sweep runs every retention once.
func (s *Sweeper) Sweep(ctx context.Context) (err error) {
	defer func() { s.finish(err) }()
	sessions, err := s.SweepSessions(ctx)
	if err != nil {
		return err
	}
	s.note("agent_sessions", sessions)
	events, err := s.SweepAudit(ctx)
	if err != nil {
		return err
	}
	s.note("audit_events", events)
	if sessions > 0 || events > 0 {
		s.log.Info("the retention sweep deleted old records",
			"agent_sessions", sessions, "audit_events", events)
	}
	// The working record of the fleet, oldest first and a batch at a time.
	// The order matters: a campaign gone takes its plans with it, and the
	// jobs those plans pointed at become free for the job sweep.
	for _, kind := range []struct {
		name string
		run  func(context.Context) (int64, error)
	}{
		{"campaigns", s.SweepCampaigns},
		{"jobs", s.SweepJobs},
		{"outbox_events", s.SweepOutbox},
	} {
		removed, err := kind.run(ctx)
		if err != nil {
			return err
		}
		s.note(kind.name, removed)
		if removed > 0 {
			s.log.Info("the retention sweep deleted old records", "kind", kind.name, "rows", removed,
				"batch_full", removed == SweepBatch)
		}
	}
	expired, err := s.NoteExpiredBindings(ctx)
	if err != nil {
		return err
	}
	if expired > 0 {
		s.log.Info("role bindings expired", "bindings", expired)
	}
	for _, sweep := range s.extra {
		if err := sweep.run(ctx); err != nil {
			return fmt.Errorf("%s: %w", sweep.name, err)
		}
	}
	return nil
}

func (s *Sweeper) sweep(ctx context.Context) {
	if err := s.Sweep(ctx); err != nil && ctx.Err() == nil {
		s.log.Error("the retention sweep failed", "err", err)
	}
}

// SweepSessions deletes the agent sessions that ended before the retention.
// An open session is never deleted, however old: it is the record of a
// connection that still exists.
func (s *Sweeper) SweepSessions(ctx context.Context) (int64, error) {
	tag, err := s.pool.Exec(ctx, `
		delete from agent_sessions
		where ended_at is not null and ended_at < now() - $1::interval`,
		interval(s.options.Sessions))
	if err != nil {
		return 0, fmt.Errorf("sweeping the agent sessions: %w", err)
	}
	return tag.RowsAffected(), nil
}

// SweepAudit deletes the audit events older than the retention. With no
// retention set nothing is deleted.
//
// The trail is append-only by a trigger that refuses updates and deletes
// through the ordinary path, so the sweep goes through the function the
// schema provides for exactly this purpose.
func (s *Sweeper) SweepAudit(ctx context.Context) (int64, error) {
	if s.options.Audit <= 0 {
		return 0, nil
	}
	var deleted int64
	if err := s.pool.QueryRow(ctx, `select audit_events_expire($1::interval)`,
		interval(s.options.Audit)).Scan(&deleted); err != nil {
		return 0, fmt.Errorf("sweeping the audit trail: %w", err)
	}
	return deleted, nil
}

// SweepJobs deletes the finished jobs older than the retention, a batch at
// a time. A job in flight is never deleted, however old: its state is the
// only record of a task a host may still be carrying. A job of a campaign
// stays as long as the campaign does - the campaign's report is read
// through its jobs - and a job a campaign plan points at stays until the
// plan goes with its campaign, because the reference has no cascade. The
// attempts, the approvals and the secret leases go with the job by their
// own cascades.
func (s *Sweeper) SweepJobs(ctx context.Context) (int64, error) {
	tag, err := s.pool.Exec(ctx, `
		delete from jobs where id in (
			select j.id from jobs j
			where j.state in ('succeeded', 'failed', 'timed_out', 'canceled', 'expired')
			  and coalesce(j.finished_at, j.updated_at) < now() - $1::interval
			  and (j.campaign_id is null
			       or not exists (select 1 from campaigns c where c.id = j.campaign_id))
			  and not exists (select 1 from campaign_targets t where t.plan_job_id = j.id)
			order by coalesce(j.finished_at, j.updated_at)
			limit $2)`,
		interval(s.options.Jobs), SweepBatch)
	if err != nil {
		return 0, fmt.Errorf("sweeping the jobs: %w", err)
	}
	return tag.RowsAffected(), nil
}

// SweepCampaigns deletes the finished campaigns older than the retention,
// a batch at a time, with their targets, steps, plans, approvals and
// report by the cascades of the schema. A campaign under way is never
// deleted. A campaign another campaign retries or compensates stays until
// that one goes: the reference has no cascade, and the newer campaign's
// page names the older one.
//
// The approvals and the report are append-only by triggers that refuse a
// delete through the ordinary path, so the sweep goes through the
// function the schema provides for exactly this purpose, like the trail.
func (s *Sweeper) SweepCampaigns(ctx context.Context) (int64, error) {
	var deleted int64
	if err := s.pool.QueryRow(ctx, `select campaigns_expire($1::interval, $2)`,
		interval(s.options.Campaigns), SweepBatch).Scan(&deleted); err != nil {
		return 0, fmt.Errorf("sweeping the campaigns: %w", err)
	}
	return deleted, nil
}

// SweepOutbox deletes the delivered events of the durable trail older than
// the retention, a batch at a time. Delivered means published by the panel
// and taken by every external consumer: an event a consumer has not
// reached yet stays whatever its age, because the consumer's cursor is a
// promise that it will get every event in order. An unpublished event is
// never deleted.
func (s *Sweeper) SweepOutbox(ctx context.Context) (int64, error) {
	tag, err := s.pool.Exec(ctx, `
		delete from outbox_events where id in (
			select e.id from outbox_events e
			where e.published_at is not null
			  and e.occurred_at < now() - $1::interval
			  and e.id <= coalesce((select min(last_id) from outbox_consumers), e.id)
			order by e.id
			limit $2)`,
		interval(s.options.Outbox), SweepBatch)
	if err != nil {
		return 0, fmt.Errorf("sweeping the durable trail: %w", err)
	}
	return tag.RowsAffected(), nil
}

// interval renders a duration for a PostgreSQL interval parameter.
func interval(d time.Duration) string {
	return fmt.Sprintf("%d seconds", int64(d.Seconds()))
}

// NoteExpiredBindings writes one audit event for every role binding whose
// validity has passed since the last sweep. The binding stops granting
// anything the moment it expires, whether or not the sweep has run; the
// sweep only makes the expiry visible on the trail, once, which the flag
// on the row guarantees. The flag and the event are committed together.
func (s *Sweeper) NoteExpiredBindings(ctx context.Context) (int, error) {
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return 0, fmt.Errorf("noting the expired bindings: %w", err)
	}
	defer func() { _ = tx.Rollback(ctx) }()

	rows, err := tx.Query(ctx, `
		update role_bindings b set expiry_noted = true
		from principals p
		where p.id = b.principal_id
		  and b.valid_until is not null and b.valid_until <= now() and not b.expiry_noted
		returning b.id, b.principal_id, p.subject, b.role, b.site, b.environment, b.valid_until`)
	if err != nil {
		return 0, fmt.Errorf("noting the expired bindings: %w", err)
	}
	type expiredBinding struct {
		id, principalID, subject, role, site, environment string
		validUntil                                        time.Time
	}
	var expired []expiredBinding
	for rows.Next() {
		var binding expiredBinding
		if err := rows.Scan(&binding.id, &binding.principalID, &binding.subject, &binding.role,
			&binding.site, &binding.environment, &binding.validUntil); err != nil {
			rows.Close()
			return 0, err
		}
		expired = append(expired, binding)
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return 0, err
	}
	if len(expired) == 0 {
		return 0, nil
	}

	if s.recorder != nil {
		for _, binding := range expired {
			if err := s.recorder.RecordTx(ctx, tx, audit.Event{
				ActorType: audit.ActorSystem, ActorID: "housekeeping",
				Action: "binding.expired", TargetType: "principal", TargetID: binding.principalID,
				Outcome: audit.OutcomeSuccess,
				Detail: map[string]any{
					"subject": binding.subject, "binding_id": binding.id,
					"role": binding.role, "site": binding.site, "environment": binding.environment,
					"valid_until": binding.validUntil.UTC().Format(time.RFC3339),
				},
			}); err != nil {
				return 0, fmt.Errorf("noting the expired binding %s: %w", binding.id, err)
			}
		}
	}
	if err := tx.Commit(ctx); err != nil {
		return 0, fmt.Errorf("noting the expired bindings: %w", err)
	}
	return len(expired), nil
}
