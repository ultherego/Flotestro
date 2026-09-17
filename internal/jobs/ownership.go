package jobs

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

// ErrStaleFence means a write on a session that no longer owns its host:
// the host's ownership row names a newer session, a newer token, or a
// lease that ran out. The database refused the write, nothing was
// changed, and the write is never repeated as a plain update - the
// instance that owns the host now carries on with the host's answers.
var ErrStaleFence = errors.New("session_fence_stale: the session no longer owns the host")

// ErrorSessionFenceStale is the code of ErrStaleFence, as the error guide
// lists it and as the trail and the metrics name it.
const ErrorSessionFenceStale = "session_fence_stale"

// The lease of a session's ownership and how often the gateway renews it.
// Three renewals fit in one lease: a renewal that fails once - a slow
// query, a pool with no free connection for a moment - does not lose the
// host, and an instance that stops renewing loses it within a minute,
// which is how long the scheduler of the other instances holds its tasks
// at most.
const (
	OwnerLeaseTTL   = 45 * time.Second
	OwnerRenewEvery = 15 * time.Second
)

// Fence names the session a write is made on and the token that session
// got when it claimed the host. Every write of a delivery or a result
// carries one; the database compares it with the host's ownership row and
// refuses a write from a session that has been superseded. An empty fence
// is refused as well: a write that names no session is a write nobody
// owns, and the machinery fails closed.
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
// names a session and its lease has not run out. The scheduler delivers
// nothing to a host without a live owner.
func (o Owner) Live(now time.Time) bool {
	return o.SessionID != "" && o.LeaseUntil.After(now)
}

// processInstanceID names this control-plane process among the instances
// that share the database. It is drawn once at start and is the only thing
// about ownership the process keeps in memory: it says who wrote a row,
// never who owns a host - that is read from the row every time.
var processInstanceID = uuid.NewString()

// InstanceID returns the identifier of this control-plane process.
func InstanceID() string { return processInstanceID }

// ClaimSession makes the given session the owner of the host and returns
// the fencing token it got. The claim is one upsert: the token of the host
// grows by one whatever the row said before, so a new connection never
// has to guess whether the previous instance really died - it takes the
// host, and the previous instance's writes fail against the new token.
// Two claims for one host at the same moment are serialised by the row,
// and each gets its own number.
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

// RenewOwnership moves the lease of the owner forward. The renewal is
// conditional on the instance, the session and the token together: a row
// that names any other owner is somebody else's, and the caller learns it
// as ErrStaleFence - its session has been superseded and is to close.
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

// ReleaseOwnership gives the host up when its session closes: the row
// keeps its token and forgets the session, so the scheduler holds the
// host's tasks until a session claims it again. The release is
// conditional on the session and the token: a session that was superseded
// releases nothing, because the row is the newer session's now, and the
// caller learns it as ErrStaleFence.
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

// OwnerOf reads the ownership row of a host. A host without a row has no
// owner and is returned as a zero Owner; the caller asks Live before it
// delivers anything.
func (s *Store) OwnerOf(ctx context.Context, hostID string) (Owner, error) {
	owners, err := s.OwnersOf(ctx, []string{hostID})
	if err != nil {
		return Owner{}, err
	}
	return owners[hostID], nil
}

// OwnersOf reads the ownership rows of the given hosts in one query, for
// the scheduler's pass over a batch. A host without a row is missing from
// the answer, which reads as no owner.
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
// out: an instance that died without releasing its hosts leaves them
// named as owners, and while the expired lease already refuses every
// write, the rows would say the host is held by a process that is gone.
// The tokens stay - a token never goes back - so a write from the dead
// instance stays refused after the sweep as before it.
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

// fenceHolds checks, inside a transaction that already holds the job's
// row, that the fence names the live owner of the job's host. The owner
// row is locked for share: a claim in flight waits for this write to
// commit rather than racing it, and the token it then takes is the one
// that refuses the next write of this session. A fence that names no
// session is refused without asking the database.
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
