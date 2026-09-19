// Package housekeeping deletes what the panel no longer needs to keep.
package housekeeping

import (
	"context"
	"fmt"
	"log/slog"
	"sync"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/ultherego/flotestro/internal/audit"
	"github.com/ultherego/flotestro/internal/support"
)

// SessionRetention is how long an ended agent session stays on record.
const SessionRetention = 30 * 24 * time.Hour

// The retentions of the records that grow with the work of the fleet: a job
// per host per change, a campaign per change, an event of the trail per state
// a target passes through.
const (
	JobRetention      = 90 * 24 * time.Hour
	CampaignRetention = 365 * 24 * time.Hour
	OutboxRetention   = 30 * 24 * time.Hour
)

// The retentions of the support bundles: how long one is kept at all, and how
// long one nobody fetched is kept (security remediation, chapter 14.6).
const (
	SupportBundleRetention          = support.DefaultRetention
	SupportBundleUnfetchedRetention = support.DefaultUnfetchedRetention
)

// SweepBatch bounds what one sweep deletes of one kind.
const SweepBatch = 5000

// Options describes what the sweep deletes.
type Options struct {
	// Sessions is the retention of ended agent sessions.
	Sessions time.Duration
	// Audit is the retention of the audit trail.
	Audit time.Duration
	// Jobs is the retention of finished jobs, Campaigns of finished campaigns and
	// Outbox of the delivered events of the durable trail.
	Jobs      time.Duration
	Campaigns time.Duration
	Outbox    time.Duration
	// SupportBundles is the retention of a support bundle, and
	// SupportBundlesUnfetched of one nobody downloaded. An archive of the
	// panel's own state is not kept for the sake of keeping it.
	SupportBundles          time.Duration
	SupportBundlesUnfetched time.Duration
	// Interval is how often the sweep runs.
	Interval time.Duration
}

// Report is what the last sweep did, for the status screen: when it ran, what
// it removed by kind and whether it failed.
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

// Also adds a sweep of another store to the same schedule: a store that knows
// what of its own is stale says so here rather than run a ticker of its own.
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
	bundles := support.Retention{Age: options.SupportBundles, Unfetched: options.SupportBundlesUnfetched}.WithDefaults()
	options.SupportBundles, options.SupportBundlesUnfetched = bundles.Age, bundles.Unfetched
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
			"agent_sessions":            s.options.Sessions.String(),
			"jobs":                      s.options.Jobs.String(),
			"campaigns":                 s.options.Campaigns.String(),
			"outbox_events":             s.options.Outbox.String(),
			"support_bundles":           s.options.SupportBundles.String(),
			"support_bundles_unfetched": s.options.SupportBundlesUnfetched.String(),
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

// Run sweeps at the interval until the context ends.
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
	for _, kind := range []struct {
		name string
		run  func(context.Context) (int64, error)
	}{
		{"campaigns", s.SweepCampaigns},
		{"jobs", s.SweepJobs},
		{"outbox_events", s.SweepOutbox},
		{"support_bundles", s.SweepSupportBundles},
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

// SweepJobs deletes the finished jobs older than the retention, a batch at a
// time.
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

// SweepCampaigns deletes the finished campaigns older than the retention, a
// batch at a time, with their targets, steps, plans, approvals and report by
// the cascades of the schema.
func (s *Sweeper) SweepCampaigns(ctx context.Context) (int64, error) {
	var deleted int64
	if err := s.pool.QueryRow(ctx, `select campaigns_expire($1::interval, $2)`,
		interval(s.options.Campaigns), SweepBatch).Scan(&deleted); err != nil {
		return 0, fmt.Errorf("sweeping the campaigns: %w", err)
	}
	return deleted, nil
}

// SweepOutbox deletes the delivered events of the durable trail older than the
// retention, a batch at a time.
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

// SweepSupportBundles removes the support bundles past their retention, and
// the download tokens that can no longer open anything. A bundle nobody came
// for goes sooner than one somebody did.
func (s *Sweeper) SweepSupportBundles(ctx context.Context) (int64, error) {
	store := support.NewStore(s.pool, nil)
	return store.Sweep(ctx, support.Retention{
		Age: s.options.SupportBundles, Unfetched: s.options.SupportBundlesUnfetched,
	}, time.Now())
}

// interval renders a duration for a PostgreSQL interval parameter.
func interval(d time.Duration) string {
	return fmt.Sprintf("%d seconds", int64(d.Seconds()))
}

// NoteExpiredBindings writes one audit event for every role binding whose
// validity has passed since the last sweep.
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
