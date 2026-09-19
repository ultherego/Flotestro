package monitoring

// The lease of the alert evaluator: which control-plane instance is allowed to
// judge the rules right now.

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"
)

// ErrLeaseLost means the instance no longer holds the lease it was working
// under: another instance took it, or this one stopped renewing long enough
// for it to run out.
var ErrLeaseLost = errors.New(ErrorEvaluatorLeaseLost +
	": the instance no longer holds the lease of the alert evaluator")

// ErrorEvaluatorLeaseLost is the code of ErrLeaseLost, as the error guide
// lists it and as the log line names it.
const ErrorEvaluatorLeaseLost = "alert_evaluator_lease_lost"

// ErrFenceStale means the database refused a write of the alert state made
// under this pass's token: the lease is gone, and the episode belongs to a
// newer leader. It is a lease loss found at the write rather than at the
// renewal, so it answers to both codes.
var ErrFenceStale = fmt.Errorf("%s: %w", ErrorAlertFenceStale, ErrLeaseLost)

// ErrorAlertFenceStale is the code of ErrFenceStale, as the error guide lists
// it and as the log line and the counter name it.
const ErrorAlertFenceStale = "alert_fence_stale"

// evaluatorLeaseName is the row of monitoring_leases the evaluator holds.
const evaluatorLeaseName = "alert_evaluator"

// Lease is one lease as the database holds it.
type Lease struct {
	Name string
	// Holder is the instance that has it; empty for a lease nobody holds.
	Holder string
	// Token grows each time the lease changes hands, so a holder can tell
	// "I still have it" from "I had it, lost it and took it again".
	Token int64
	// Until is zero for a lease nobody holds.
	Until time.Time
}

// Held says whether the lease may be worked under at the given moment.
func (l Lease) Held(now time.Time) bool {
	return l.Holder != "" && l.Until.After(now)
}

// fence is the lease carried into every write of the alert state: who writes
// and under which token the row is stamped.
type fence struct {
	Holder string
	Token  int64
}

// fenceOf is the fence a pass under this lease writes under.
func fenceOf(lease Lease) fence {
	return fence{Holder: lease.Holder, Token: lease.Token}
}

// held says whether there is anything to write under. The token is minted from
// zero the first time the lease changes hands, so zero is "no lease": a pass
// without one writes nothing rather than writing unfenced.
func (f fence) held() bool { return f.Holder != "" && f.Token > 0 }

// accepts is the fence itself, the same rule the statements apply in SQL. A row
// carrying no token may be moved - a panel of the previous release, or an
// operator acknowledging, left it that way - and a row carrying one may be
// moved by a lease whose token is not older than it. Not older, rather than
// newer: a leader has to be able to write the same row twice under its own
// lease, and a pass that refused its own writes would never make progress.
func (f fence) accepts(rowToken *int64) bool {
	if !f.held() {
		return false
	}
	return rowToken == nil || *rowToken <= f.Token
}

// EvaluatorLease reads the lease without touching it, for the status
// screen: who is evaluating and until when.
func (s *Store) EvaluatorLease(ctx context.Context) (Lease, error) {
	lease := Lease{Name: evaluatorLeaseName}
	var until *time.Time
	err := s.pool.QueryRow(ctx, `
		select coalesce(holder::text, ''), token, lease_until
		  from monitoring_leases where name = $1`, evaluatorLeaseName).
		Scan(&lease.Holder, &lease.Token, &until)
	if errors.Is(err, pgx.ErrNoRows) {
		return lease, nil
	}
	if until != nil {
		lease.Until = *until
	}
	return lease, err
}

// TakeEvaluatorLease takes the lease for this instance, or renews it when this
// instance holds it already, and says whether it holds it afterwards.
func (s *Store) TakeEvaluatorLease(ctx context.Context) (Lease, bool, error) {
	return s.acquireEvaluatorLease(ctx)
}

// ReleaseEvaluatorLease gives back a lease this instance took, so the next
// instance may start its pass at once instead of waiting out the term.
func (s *Store) ReleaseEvaluatorLease(ctx context.Context, lease Lease) error {
	return s.releaseEvaluatorLease(ctx, lease)
}

// acquireEvaluatorLease takes the lease for this instance, or renews it when
// this instance holds it already, and says whether it holds it afterwards.
func (s *Store) acquireEvaluatorLease(ctx context.Context) (Lease, bool, error) {
	lease := Lease{Name: evaluatorLeaseName, Holder: s.instanceID}
	var until *time.Time
	err := s.pool.QueryRow(ctx, `
		with candidate as (
		    select name from monitoring_leases
		     where name = $1
		       and (holder is null or holder = $2::uuid
		            or lease_until is null or lease_until < now())
		     for update skip locked
		)
		update monitoring_leases l
		   set holder      = $2::uuid,
		       lease_until = now() + make_interval(secs => $3::double precision),
		       token       = case when l.holder is distinct from $2::uuid
		                          then l.token + 1 else l.token end,
		       updated_at  = now()
		  from candidate
		 where l.name = candidate.name
		returning l.token, l.lease_until`,
		evaluatorLeaseName, s.instanceID, s.options.EvaluatorLease.Seconds()).
		Scan(&lease.Token, &until)
	if errors.Is(err, pgx.ErrNoRows) {
		return Lease{Name: evaluatorLeaseName}, false, nil
	}
	if err != nil {
		return Lease{Name: evaluatorLeaseName}, false, err
	}
	if until != nil {
		lease.Until = *until
	}
	return lease, true, nil
}

// renewEvaluatorLease moves the lease forward.
func (s *Store) renewEvaluatorLease(ctx context.Context, lease Lease) error {
	tag, err := s.pool.Exec(ctx, `
		update monitoring_leases
		   set lease_until = now() + make_interval(secs => $4::double precision),
		       updated_at = now()
		 where name = $1 and holder = $2::uuid and token = $3 and lease_until > now()`,
		lease.Name, lease.Holder, lease.Token, s.options.EvaluatorLease.Seconds())
	if err != nil {
		return err
	}
	if tag.RowsAffected() == 0 {
		return ErrLeaseLost
	}
	return nil
}

// releaseEvaluatorLease gives the lease up at the end of a pass, so the next
// instance may take it at once rather than waiting out the term.
func (s *Store) releaseEvaluatorLease(ctx context.Context, lease Lease) error {
	_, err := s.pool.Exec(ctx, `
		update monitoring_leases
		   set holder = null, lease_until = null, updated_at = now()
		 where name = $1 and holder = $2::uuid and token = $3`,
		lease.Name, lease.Holder, lease.Token)
	return err
}
