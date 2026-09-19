package jobs

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

// ErrStaleFence means a write on a session that no longer owns its host: the
// host's ownership row names a newer session, a newer token, or a lease that
// ran out.
var ErrStaleFence = errors.New("session_fence_stale: the session no longer owns the host")

// ErrorSessionFenceStale is the code of ErrStaleFence, as the error guide
// lists it and as the trail and the metrics name it.
const ErrorSessionFenceStale = "session_fence_stale"

// The lease of a session's ownership and how often the gateway renews it.
const (
	OwnerLeaseTTL   = 45 * time.Second
	OwnerRenewEvery = 15 * time.Second
)

// Fence names the session a write is made on and the token that session got
// when it claimed the host.
type Fence struct {
	SessionID string
	Token     uint64
}

// Owner is the ownership row of a host as the scheduler reads it.
type Owner struct {
	SessionID  string
	InstanceID string
	Token      uint64
	// LeaseUntil is zero for a host nobody owns.
	LeaseUntil  time.Time
	ConnectedAt time.Time
}

// Live says whether the owner may be delivered to at the given moment: it
// names a session and its lease has not run out.
func (o Owner) Live(now time.Time) bool {
	return o.SessionID != "" && o.LeaseUntil.After(now)
}

// processInstanceID names this control-plane process among the instances that
// share the database.
var processInstanceID = uuid.NewString()

// InstanceID returns the identifier of this control-plane process.
func InstanceID() string { return processInstanceID }

// ClaimSession makes the given session the owner of the host and returns the
// fencing token it got.
func (s *Store) ClaimSession(ctx context.Context, hostID, sessionID, instanceID string,
	ttl time.Duration) (uint64, error) {
	if hostID == "" || sessionID == "" || instanceID == "" {
		return 0, errors.New("a claim of a session names the host, the session and the instance")
	}
	var token int64
	err := s.pool.QueryRow(ctx, `
		insert into host_session_owners
			(host_id, fencing_token, session_id, owner_instance_id, lease_until, connected_at, revision)
		values ($1::uuid, 1, $2::uuid, $3::uuid, now() + make_interval(secs => $4), now(), 1)
		on conflict (host_id) do update set
			fencing_token     = host_session_owners.fencing_token + 1,
			session_id        = excluded.session_id,
			owner_instance_id = excluded.owner_instance_id,
			lease_until       = excluded.lease_until,
			connected_at      = now(),
			revision          = host_session_owners.revision + 1,
			updated_at        = now()
		returning fencing_token`,
		hostID, sessionID, instanceID, ttl.Seconds()).Scan(&token)
	if err != nil {
		return 0, fmt.Errorf("claiming the session of the host: %w", err)
	}
	return uint64(token), nil
}

// RenewOwnership moves the lease of the owner forward.
func (s *Store) RenewOwnership(ctx context.Context, hostID, sessionID, instanceID string,
	token uint64, ttl time.Duration) error {
	tag, err := s.pool.Exec(ctx, `
		update host_session_owners
		   set lease_until = now() + make_interval(secs => $5), updated_at = now()
		 where host_id = $1::uuid
		   and session_id = $2::uuid
		   and owner_instance_id = $3::uuid
		   and fencing_token = $4`,
		hostID, sessionID, instanceID, int64(token), ttl.Seconds())
	if err != nil {
		return fmt.Errorf("renewing the ownership of the host: %w", err)
	}
	if tag.RowsAffected() == 0 {
		return ErrStaleFence
	}
	return nil
}

// ReleaseOwnership gives the host up when its session closes: the row keeps
// its token and forgets the session, so the scheduler holds the host's tasks
// until a session claims it again.
func (s *Store) ReleaseOwnership(ctx context.Context, hostID, sessionID string, token uint64) error {
	tag, err := s.pool.Exec(ctx, `
		update host_session_owners
		   set session_id = null, owner_instance_id = null, lease_until = null,
		       updated_at = now()
		 where host_id = $1::uuid
		   and session_id = $2::uuid
		   and fencing_token = $3`,
		hostID, sessionID, int64(token))
	if err != nil {
		return fmt.Errorf("releasing the ownership of the host: %w", err)
	}
	if tag.RowsAffected() == 0 {
		return ErrStaleFence
	}
	return nil
}

// OwnerOf reads the ownership row of a host.
func (s *Store) OwnerOf(ctx context.Context, hostID string) (Owner, error) {
	owners, err := s.OwnersOf(ctx, []string{hostID})
	if err != nil {
		return Owner{}, err
	}
	return owners[hostID], nil
}

// OwnersOf reads the ownership rows of the given hosts in one query, for the
// scheduler's pass over a batch.
func (s *Store) OwnersOf(ctx context.Context, hostIDs []string) (map[string]Owner, error) {
	owners := make(map[string]Owner, len(hostIDs))
	if len(hostIDs) == 0 {
		return owners, nil
	}
	rows, err := s.pool.Query(ctx, `
		select host_id::text, coalesce(session_id::text, ''), coalesce(owner_instance_id::text, ''),
		       fencing_token, lease_until, connected_at
		  from host_session_owners
		 where host_id = any($1::uuid[])`, hostIDs)
	if err != nil {
		return nil, fmt.Errorf("reading the owners of the hosts: %w", err)
	}
	defer rows.Close()
	for rows.Next() {
		var hostID string
		var owner Owner
		var token int64
		var leaseUntil, connectedAt *time.Time
		if err := rows.Scan(&hostID, &owner.SessionID, &owner.InstanceID, &token,
			&leaseUntil, &connectedAt); err != nil {
			return nil, err
		}
		owner.Token = uint64(token)
		if leaseUntil != nil {
			owner.LeaseUntil = *leaseUntil
		}
		if connectedAt != nil {
			owner.ConnectedAt = *connectedAt
		}
		owners[hostID] = owner
	}
	return owners, rows.Err()
}

// SweepExpiredOwners forgets the sessions of the owner rows whose lease ran
// out: an instance that died without releasing its hosts leaves them named as
// owners, and while the expired lease already refuses every write, the rows
func (s *Store) SweepExpiredOwners(ctx context.Context) (int64, error) {
	tag, err := s.pool.Exec(ctx, `
		update host_session_owners
		   set session_id = null, owner_instance_id = null, lease_until = null,
		       updated_at = now()
		 where session_id is not null and lease_until < now()`)
	if err != nil {
		return 0, fmt.Errorf("sweeping the expired session owners: %w", err)
	}
	return tag.RowsAffected(), nil
}

// fenceHolds checks, inside a transaction that already holds the job's row,
// that the fence names the live owner of the job's host.
func fenceHolds(ctx context.Context, tx pgx.Tx, jobID string, fence Fence) error {
	if fence.SessionID == "" {
		return ErrStaleFence
	}
	var one int
	err := tx.QueryRow(ctx, `
		select 1
		  from host_session_owners o
		  join jobs j on j.host_id = o.host_id
		 where j.id = $1
		   and o.session_id = $2::uuid
		   and o.fencing_token = $3
		   and o.lease_until > now()
		   for share of o`,
		jobID, fence.SessionID, int64(fence.Token)).Scan(&one)
	if errors.Is(err, pgx.ErrNoRows) {
		return ErrStaleFence
	}
	return err
}
