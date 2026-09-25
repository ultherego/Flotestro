// Package leases holds the panel's background-pass leases: one row of
// monitoring_leases per kind of pass, so that work belonging to the
// installation runs on one instance at a time instead of on every replica.
package leases

import (
	"context"
	"errors"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

// ErrLost means the lease is no longer this instance's: it expired, or another
// instance took it. A pass that finds this stops rather than write over the one
// that holds it now.
var ErrLost = errors.New("the lease of this pass is no longer held")

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

// Take takes the named lease for this instance, or renews it when this instance
// holds it already, and says whether it holds it afterwards. A row nobody
// created is a lease nobody can take: the migration that adds a pass adds its
// row, so a pass whose row is missing does nothing rather than run everywhere.
func Take(ctx context.Context, pool *pgxpool.Pool, name, holder string,
	term time.Duration) (Lease, bool, error) {
	lease := Lease{Name: name, Holder: holder}
	var until *time.Time
	err := pool.QueryRow(ctx, `
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
		name, holder, term.Seconds()).Scan(&lease.Token, &until)
	if errors.Is(err, pgx.ErrNoRows) {
		return Lease{Name: name}, false, nil
	}
	if err != nil {
		return Lease{Name: name}, false, err
	}
	if until != nil {
		lease.Until = *until
	}
	return lease, true, nil
}

// Renew moves the lease forward and answers ErrLost when it has moved on.
func Renew(ctx context.Context, pool *pgxpool.Pool, lease Lease, term time.Duration) error {
	tag, err := pool.Exec(ctx, `
		update monitoring_leases
		   set lease_until = now() + make_interval(secs => $4::double precision),
		       updated_at = now()
		 where name = $1 and holder = $2::uuid and token = $3 and lease_until > now()`,
		lease.Name, lease.Holder, lease.Token, term.Seconds())
	if err != nil {
		return err
	}
	if tag.RowsAffected() == 0 {
		return ErrLost
	}
	return nil
}

// Release gives the lease up at the end of a pass, so the next instance may
// take it at once rather than waiting out the term. The token is part of the
// condition: an instance that lost the lease does not release somebody else's.
func Release(ctx context.Context, pool *pgxpool.Pool, lease Lease) error {
	_, err := pool.Exec(ctx, `
		update monitoring_leases
		   set holder = null, lease_until = null, updated_at = now()
		 where name = $1 and holder = $2::uuid and token = $3`,
		lease.Name, lease.Holder, lease.Token)
	return err
}

// Read reads a lease without touching it, for the status screen.
func Read(ctx context.Context, pool *pgxpool.Pool, name string) (Lease, error) {
	lease := Lease{Name: name}
	var until *time.Time
	err := pool.QueryRow(ctx, `
		select coalesce(holder::text, ''), token, lease_until
		  from monitoring_leases where name = $1`, name).
		Scan(&lease.Holder, &lease.Token, &until)
	if errors.Is(err, pgx.ErrNoRows) {
		return lease, nil
	}
	if until != nil {
		lease.Until = *until
	}
	return lease, err
}
