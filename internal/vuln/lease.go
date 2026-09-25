package vuln

import (
	"context"
	"errors"
	"time"

	"github.com/jackc/pgx/v5"
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
func (s *Store) TakeCorrelatorLease(ctx context.Context, instanceID string) (bool, error) {
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
		correlatorLease, instanceID, leaseTerm.Seconds()).Scan(&token)
	if errors.Is(err, pgx.ErrNoRows) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	return true, nil
}

// ReleaseCorrelatorLease gives the lease back, so another instance may start
// its pass at once instead of waiting out the term.
func (s *Store) ReleaseCorrelatorLease(ctx context.Context, instanceID string) error {
	_, err := s.pool.Exec(ctx, `
		update monitoring_leases set holder = null, lease_until = null, updated_at = now()
		 where name = $1 and holder = $2::uuid`, correlatorLease, instanceID)
	return err
}
