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
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/ultherego/flotestro/internal/audit"
)

// SessionRetention is how long an ended agent session stays on record. The
// timeline of a host shows its sessions; a month of them is what an
// operator looks back at.
const SessionRetention = 30 * 24 * time.Hour

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
	// Interval is how often the sweep runs.
	Interval time.Duration
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
	if options.Interval <= 0 {
		options.Interval = time.Hour
	}
	return &Sweeper{pool: pool, log: log, options: options}
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
func (s *Sweeper) Sweep(ctx context.Context) error {
	sessions, err := s.SweepSessions(ctx)
	if err != nil {
		return err
	}
	events, err := s.SweepAudit(ctx)
	if err != nil {
		return err
	}
	if sessions > 0 || events > 0 {
		s.log.Info("the retention sweep deleted old records",
			"agent_sessions", sessions, "audit_events", events)
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
