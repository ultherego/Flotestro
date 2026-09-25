package housekeeping

import (
	"context"
	"errors"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
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
func (s *Sweeper) takeLease(ctx context.Context) (bool, error) {
	var token int64
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
		returning l.token`,
		sweepLease, sweepInstance, leaseTerm.Seconds()).Scan(&token)
	if errors.Is(err, pgx.ErrNoRows) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	return true, nil
}

// releaseLease gives the lease back, so another instance may sweep at once
// instead of waiting out the term.
func (s *Sweeper) releaseLease(ctx context.Context) error {
	_, err := s.pool.Exec(ctx, `
		update monitoring_leases set holder = null, lease_until = null, updated_at = now()
		 where name = $1 and holder = $2::uuid`, sweepLease, sweepInstance)
	return err
}
