package monitoring

// The lease of the alert evaluator: which control-plane instance is allowed to
// judge the rules right now.

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/ultherego/flotestro/internal/leases"
)

// ErrLeaseLost means the instance no longer holds the lease it was working
// under: another took it, or this one stopped renewing long enough to lose it.
var ErrLeaseLost = fmt.Errorf("%s: %w", ErrorEvaluatorLeaseLost, leases.ErrLost)

// ErrorEvaluatorLeaseLost is the code of ErrLeaseLost, as the error guide
// lists it and as the log line names it.
const ErrorEvaluatorLeaseLost = "alert_evaluator_lease_lost"

// ErrFenceStale means the database refused a write of the alert state made
// under this pass's token: the lease is gone, so the episode is not ours.
var ErrFenceStale = fmt.Errorf("%s: %w", ErrorAlertFenceStale, ErrLeaseLost)

// ErrorAlertFenceStale is the code of ErrFenceStale, as the error guide lists
// it and as the log line and the counter name it.
const ErrorAlertFenceStale = "alert_fence_stale"

// evaluatorLeaseName is the row of monitoring_leases the evaluator holds.
const evaluatorLeaseName = "alert_evaluator"

// maintenanceLeaseName is the row the maintenance pass holds: preparing the
// partitions, rolling the samples up and applying their retention is the work
// of the installation, not of every replica of the panel.
const maintenanceLeaseName = "monitoring_maintenance"

// maintenanceLease is the term of that lease. It covers a whole pass over a
// large fleet and runs out on its own when the instance holding it goes.
const maintenanceLease = 10 * time.Minute

// Lease is one lease as the database holds it. Every background pass of the
// panel takes a row of the same table, so the type is the shared one.
type Lease = leases.Lease

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
// zero the first time the lease changes hands, so zero is "no lease".
func (f fence) held() bool { return f.Holder != "" && f.Token > 0 }

// accepts is the fence itself, the same rule the statements apply in SQL. A row
// carrying no token may be moved: a panel of the previous release wrote it.
func (f fence) accepts(rowToken *int64) bool {
	if !f.held() {
		return false
	}
	return rowToken == nil || *rowToken <= f.Token
}

// EvaluatorLease reads the lease without touching it, for the status
// screen: who is evaluating and until when.
func (s *Store) EvaluatorLease(ctx context.Context) (Lease, error) {
	return leases.Read(ctx, s.pool, evaluatorLeaseName)
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

// acquireEvaluatorLease takes the lease of the alert evaluator.
func (s *Store) acquireEvaluatorLease(ctx context.Context) (Lease, bool, error) {
	return s.acquireLease(ctx, evaluatorLeaseName, s.options.EvaluatorLease)
}

// acquireLease takes the named lease for this instance.
func (s *Store) acquireLease(ctx context.Context, name string, term time.Duration) (Lease, bool, error) {
	return leases.Take(ctx, s.pool, name, s.instanceID, term)
}

// renewEvaluatorLease moves the lease forward. The loss is reported under this
// package's code, which the evaluator and the error guide both name.
func (s *Store) renewEvaluatorLease(ctx context.Context, lease Lease) error {
	if err := leases.Renew(ctx, s.pool, lease, s.options.EvaluatorLease); err != nil {
		if errors.Is(err, leases.ErrLost) {
			return ErrLeaseLost
		}
		return err
	}
	return nil
}

// releaseEvaluatorLease gives the named lease up at the end of a pass, so the
// next instance may take it at once rather than waiting out the term.
func (s *Store) releaseEvaluatorLease(ctx context.Context, lease Lease) error {
	return leases.Release(ctx, s.pool, lease)
}
