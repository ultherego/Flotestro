package vuln

import (
	"context"
	"time"

	"github.com/ultherego/flotestro/internal/leases"
)

// correlatorLease is the name of the lease this pass runs under. The table is
// the panel's background-pass leases, one row per kind of pass.
const correlatorLease = "vuln_correlator"

// leaseTerm is how long a pass holds the lease. It covers a whole cycle -
// every feed and every host - with room for a slow registry, and expires on its
// own when the instance holding it disappears.
const leaseTerm = 30 * time.Minute

// TakeCorrelatorLease takes the lease for this instance, or renews it when this
// instance holds it already, and says whether it holds it afterwards. A replica
// that does not hold it does no pass: every replica downloading every feed and
// rewriting every host's findings is duplicated work whose last commit wins.
func (s *Store) TakeCorrelatorLease(ctx context.Context, instanceID string) (leases.Lease, bool, error) {
	return leases.Take(ctx, s.pool, correlatorLease, instanceID, leaseTerm)
}

// ReleaseCorrelatorLease gives the lease back, so another instance may start
// its pass at once instead of waiting out the term.
func (s *Store) ReleaseCorrelatorLease(ctx context.Context, lease leases.Lease) error {
	return leases.Release(ctx, s.pool, lease)
}
