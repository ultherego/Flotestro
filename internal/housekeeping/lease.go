package housekeeping

import (
	"context"
	"time"

	"github.com/google/uuid"

	"github.com/ultherego/flotestro/internal/leases"
)

// sweepLease is the row of monitoring_leases this pass holds. That table is
// the panel's background-pass leases, one row per kind of pass.
const sweepLease = "housekeeping_sweep"

// leaseTerm is how long a sweep holds the lease: long enough for a pass over a
// year of records, and it runs out on its own when the instance holding it
// disappears.
const leaseTerm = 30 * time.Minute

// sweepInstance names this process to the lease.
var sweepInstance = uuid.NewString()

// takeLease takes the lease for this instance and says whether it holds it. A
// replica that does not hold it sweeps nothing: every replica deleting the same
// rows at the same moment is duplicated work, and the batches of the others cut
// across the pass that is reading.
func (s *Sweeper) takeLease(ctx context.Context) (leases.Lease, bool, error) {
	return leases.Take(ctx, s.pool, sweepLease, sweepInstance, leaseTerm)
}

// releaseLease gives the lease back, so another instance may sweep at once
// instead of waiting out the term.
func (s *Sweeper) releaseLease(ctx context.Context, lease leases.Lease) error {
	return leases.Release(ctx, s.pool, lease)
}
