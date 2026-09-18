package monitoring

// The lease of the alert evaluator: which control-plane instance is
// allowed to judge the rules right now.
//
// Every instance runs the evaluator, and until now every one of them
// evaluated every rule over every host on every tick. The unique index
// over the open episodes made that look harmless: the second instance's
// insert lost the race and was swallowed by "on conflict do nothing", so
// the duplicate fire never became a duplicate row. An index is a poor
// leader election. It guards the one statement that starts an episode and
// nothing after it - firing, refreshing and resolving are plain updates -
// so two instances a second apart can resolve an episode the other has
// just refreshed, and each of them does the whole fleet's work to get
// there. One holder at a time is the honest answer, and an instance that
// finds the lease taken does nothing at all rather than a little.

import (
	"context"
	"errors"
	"time"

	"github.com/jackc/pgx/v5"
)

// ErrLeaseLost means the instance no longer holds the lease it was working
// under: another instance took it, or this one stopped renewing long
// enough for it to run out. The pass stops where it is. Nothing is written
// after this, because the fleet is somebody else's to judge now, and a
// half-finished pass by a former leader is how two panels end up
// contradicting each other about one alert.
var ErrLeaseLost = errors.New(ErrorEvaluatorLeaseLost +
	": the instance no longer holds the lease of the alert evaluator")

// ErrorEvaluatorLeaseLost is the code of ErrLeaseLost, as the error guide
// lists it and as the log line names it.
const ErrorEvaluatorLeaseLost = "alert_evaluator_lease_lost"

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

// acquireEvaluatorLease takes the lease for this instance, or renews it
// when this instance holds it already, and says whether it holds it
// afterwards.
//
// A lease is free when nobody holds it or when its holder stopped renewing
// it for the term. The row is taken with skip locked: an instance that
// finds it locked does not wait - the other one is either renewing or
// taking it, and either way this instance has no business with the fleet
// on this tick.
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

// renewEvaluatorLease moves the lease forward. It is conditional on the
// holder and the token together, and on the lease not having run out: a
// row that names anything else is somebody else's now, and the caller
// learns it as ErrLeaseLost. A lease that ran out is not quietly taken
// back here - it is taken by an acquire, which gives it a new token, so a
// pass that was interrupted never carries on under the old one.
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

// releaseEvaluatorLease gives the lease up at the end of a pass, so the
// next instance may take it at once rather than waiting out the term. A
// release by an instance that has since lost the lease changes nothing.
func (s *Store) releaseEvaluatorLease(ctx context.Context, lease Lease) error {
	_, err := s.pool.Exec(ctx, `
		update monitoring_leases
		   set holder = null, lease_until = null, updated_at = now()
		 where name = $1 and holder = $2::uuid and token = $3`,
		lease.Name, lease.Holder, lease.Token)
	return err
}
