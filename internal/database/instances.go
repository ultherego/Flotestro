package database

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"sort"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"
)

// The replicas of the control plane and the budget they share.
//
// Chapter 21 of the containerisation document names three ways a scaled
// deployment goes wrong, and two of them live here. The first is the gateway
// identifier: every replica must have its own, because the scheduler's
// leases, the session fencing and the audit trail all read that identifier
// as "the instance". Two replicas sharing one are invisible to every
// mechanism that would otherwise notice, since each of them reads the
// other's rows as its own. The second is the connection budget: N replicas
// times the maximum of the pool against what the server answers, a sum no
// single replica can see and every one of them takes from.
//
// Both are answered by one row per identifier: who holds it, when they last
// said they were alive, and how large a pool they were allowed. The
// identifier is then claimed rather than declared, and the budget is a
// question the panel can answer before somebody scales instead of after.

// CodeGatewayIDInUse is the refusal of a start that finds its gateway
// identifier held by another, living process. It is a code of the error
// guide: the log names it and the runbook is indexed by it.
const CodeGatewayIDInUse = "gateway_id_in_use"

// The pace of the heartbeat and the age at which a record stops counting as
// a live replica.
//
// Four heartbeats fit in the stale window, so a replica that misses one on a
// slow query does not look dead to anybody, and a replica that is actually
// gone frees its identifier inside a minute. An orderly stop gives the row
// back at once, so only a crash ever has to be waited out.
const (
	InstanceHeartbeatEvery = 15 * time.Second
	InstanceStaleAfter     = 60 * time.Second
)

// instanceClaimPoll is how often a start that is waiting for a record to age
// out looks again. It is a variable so the waiting can be exercised without
// a test that takes as long as the wait.
var instanceClaimPoll = 2 * time.Second

// ErrInstanceSuperseded is what a heartbeat returns when the row of the
// gateway identifier no longer names this process: another process has taken
// the identifier over. It is not a transient error - two processes are now
// answering under one identifier, and the one that lost the row is the one
// that has to stop.
var ErrInstanceSuperseded = errors.New("the gateway identifier of this process was taken over by another instance")

// Instance is one row of control_plane_instances as it is read back.
type Instance struct {
	GatewayID  string
	InstanceID string
	Hostname   string
	Version    string
	// PoolMaxConns is what this replica may open against the database;
	// zero means a replica that did not say, which the budget counts as
	// unknown rather than as nothing.
	PoolMaxConns    int32
	StartedAt       time.Time
	LastHeartbeatAt time.Time
	// SinceHeartbeat is measured by the clock of the database rather than
	// by the clock of the process that reads it: the replicas are separate
	// machines and their clocks differ, and a judgement about who is alive
	// must not depend on whose clock was asked.
	SinceHeartbeat time.Duration
}

// Live says whether the record still counts as a replica that is running.
func (i Instance) Live() bool { return i.SinceHeartbeat < InstanceStaleAfter }

// Claim is what a starting control plane says about itself.
type Claim struct {
	// GatewayID is FLOTESTRO_GATEWAY_ID: the identifier the rest of the
	// product reads as "this instance".
	GatewayID string
	// InstanceID is this process, drawn anew at every start.
	InstanceID string
	Hostname   string
	Version    string
	// PoolMaxConns is the maximum of this replica's connection pool, which
	// makes the row its share of the installation's budget.
	PoolMaxConns int32
	// Log receives the one line about waiting for a record to age out and
	// the one about a takeover. Nil uses the default logger.
	Log *slog.Logger
}

// Validate refuses a claim that cannot identify a replica. An empty gateway
// identifier is not a replica nobody can tell apart - it is every replica at
// once, because every one of them would write the same empty string into the
// sessions and the leases.
func (c Claim) Validate() error {
	if strings.TrimSpace(c.GatewayID) == "" {
		return errors.New("FLOTESTRO_GATEWAY_ID is empty; every replica answers under an identifier of " +
			"its own, and the leases and the sessions are written under it")
	}
	if c.GatewayID != strings.TrimSpace(c.GatewayID) {
		return fmt.Errorf("FLOTESTRO_GATEWAY_ID is %q; it begins or ends with whitespace, and two "+
			"replicas that differ only in that are one identifier to everything that reads it", c.GatewayID)
	}
	if len(c.GatewayID) > 128 {
		return fmt.Errorf("FLOTESTRO_GATEWAY_ID is %d characters long; it travels in every session and "+
			"every lease, and 128 is the most it may take", len(c.GatewayID))
	}
	if c.InstanceID == "" {
		return errors.New("a claim of a gateway identifier names the process that makes it")
	}
	return nil
}

// InstanceInUseError is the refusal: the gateway identifier is held by a
// process that is still renewing its heartbeat.
type InstanceInUseError struct {
	GatewayID string
	// Holder is the row as it was last read: the process that has the
	// identifier, where it runs and when it last said so.
	Holder Instance
	// Waited is how long this start watched the record before deciding
	// that the process behind it is alive.
	Waited time.Duration
}

// Code names the refusal as the error guide lists it.
func (e *InstanceInUseError) Code() string { return CodeGatewayIDInUse }

func (e *InstanceInUseError) Error() string {
	where := e.Holder.Hostname
	if where == "" {
		where = "an unnamed host"
	}
	return fmt.Sprintf("%s: FLOTESTRO_GATEWAY_ID=%q is held by the instance %s on %s, which renewed its "+
		"heartbeat %s ago and is still renewing it; two replicas under one identifier are read as one "+
		"instance by the job leases, the session fencing and the audit trail",
		CodeGatewayIDInUse, e.GatewayID, e.Holder.InstanceID, where, e.Holder.SinceHeartbeat.Round(time.Second))
}

// Registration is the claimed identifier: what this process holds and what
// it found in its place.
type Registration struct {
	GatewayID  string
	InstanceID string
	// First says the identifier had no row at all: this is the first
	// replica ever to answer under it.
	First bool
	// TookOverFrom names the instance whose record this start took over -
	// the ordinary restart, where the previous process of this very
	// replica left a row nobody renews any more. Empty on a first claim
	// and on a re-claim by the same process.
	TookOverFrom string
	// Waited is how long the start watched a record that was not being
	// renewed before taking it over.
	Waited time.Duration
}

// instanceDecision is what a claim does with the row it finds.
type instanceDecision int

const (
	// takeInstance: the identifier is free, is this process's own, or is
	// held by a record nobody renews any more.
	takeInstance instanceDecision = iota
	// refuseInstance: the heartbeat of the record has moved since this
	// start first looked, so another process is alive under the identifier.
	refuseInstance
	// waitInstance: the record still looks fresh, but nothing has been seen
	// to move yet. A process killed a second ago leaves exactly this, and
	// so does a replica that is running; the two are told apart by looking
	// again.
	waitInstance
)

// judgeInstanceClaim decides what a start does with the row under its
// gateway identifier. firstSeen is the heartbeat of the first look, zero on
// the first look itself; a heartbeat that has moved since is a process that
// is alive, whatever its age says.
func judgeInstanceClaim(instanceID string, holder *Instance, firstSeen time.Time) instanceDecision {
	switch {
	case holder == nil:
		return takeInstance
	case holder.InstanceID == instanceID:
		// This very process claiming again: a retry after an interrupted
		// start, not a second replica.
		return takeInstance
	case !holder.Live():
		return takeInstance
	case !firstSeen.IsZero() && !holder.LastHeartbeatAt.Equal(firstSeen):
		return refuseInstance
	default:
		return waitInstance
	}
}

// ClaimInstance takes the gateway identifier for this process.
//
// The three outcomes are the three deployments. A free identifier, or one
// whose record nobody renews any more, is taken: the first start of a
// replica and every ordinary restart. An identifier whose record is still
// being renewed is refused: a second replica was started under the
// identifier of the first, which is the mistake nothing downstream can see.
// In between there is a record that looks fresh and is not being renewed -
// what a killed process leaves behind - and that one is waited out rather
// than refused, because refusing it would turn every crash into an outage
// that lasts until somebody notices.
func ClaimInstance(ctx context.Context, pool *pgxpool.Pool, claim Claim) (Registration, error) {
	if err := claim.Validate(); err != nil {
		return Registration{}, err
	}
	log := claim.Log
	if log == nil {
		log = slog.Default()
	}
	started := time.Now()
	// The bound is the stale window with one heartbeat of slack: past it a
	// record that is not being renewed has aged out by definition, so a
	// start that is still waiting is waiting on something else.
	deadline := started.Add(InstanceStaleAfter + InstanceHeartbeatEvery)
	var firstSeen time.Time
	var announced bool
	for {
		registration, holder, err := tryClaimInstance(ctx, pool, claim, firstSeen)
		if err != nil {
			return Registration{}, err
		}
		if holder == nil {
			registration.Waited = time.Since(started)
			switch {
			case registration.First:
				log.Info("the gateway identifier was claimed", "gateway_id", claim.GatewayID,
					"instance_id", claim.InstanceID)
			case registration.TookOverFrom != "":
				log.Info("the record of a gateway identifier nobody renews any more was taken over; "+
					"this is what an ordinary restart looks like",
					"gateway_id", claim.GatewayID, "instance_id", claim.InstanceID,
					"previous_instance_id", registration.TookOverFrom,
					"waited", registration.Waited.Round(time.Second).String())
			}
			return registration, nil
		}
		if firstSeen.IsZero() {
			firstSeen = holder.LastHeartbeatAt
		}
		if holder.InstanceID == "" {
			// The row appeared between the lock and the insert and has not
			// been read yet; the next attempt reads it.
			select {
			case <-ctx.Done():
				return Registration{}, ctx.Err()
			case <-time.After(instanceClaimPoll):
			}
			continue
		}
		if judgeInstanceClaim(claim.InstanceID, holder, firstSeen) == refuseInstance {
			return Registration{}, &InstanceInUseError{
				GatewayID: claim.GatewayID, Holder: *holder, Waited: time.Since(started)}
		}
		if !announced {
			// Said once, not once per attempt: a restart after a crash is
			// the ordinary case here, and it is not an incident.
			log.Warn("the gateway identifier is held by a record that has not aged out yet; waiting to "+
				"see whether another instance is still renewing it",
				"gateway_id", claim.GatewayID, "holder_instance_id", holder.InstanceID,
				"holder_hostname", holder.Hostname,
				"last_heartbeat_seconds_ago", holder.SinceHeartbeat.Round(time.Second).Seconds(),
				"stale_after", InstanceStaleAfter.String())
			announced = true
		}
		if time.Now().After(deadline) {
			return Registration{}, &InstanceInUseError{
				GatewayID: claim.GatewayID, Holder: *holder, Waited: time.Since(started)}
		}
		select {
		case <-ctx.Done():
			return Registration{}, ctx.Err()
		case <-time.After(instanceClaimPoll):
		}
	}
}

// tryClaimInstance is one attempt. It returns either the registration and no
// holder, or no registration and the row that stands in the way.
func tryClaimInstance(ctx context.Context, pool *pgxpool.Pool, claim Claim,
	firstSeen time.Time) (Registration, *Instance, error) {
	tx, err := pool.Begin(ctx)
	if err != nil {
		return Registration{}, nil, fmt.Errorf("claiming the gateway identifier: %w", err)
	}
	defer func() { _ = tx.Rollback(context.WithoutCancel(ctx)) }()

	// The row is locked while it is judged, so two replicas starting at the
	// same moment are serialised by the row rather than by luck. A row that
	// does not exist yet locks nothing, and the insert below settles that
	// race instead: the second one gets the unique violation and looks
	// again, by which time there is a row to judge.
	holder, err := readInstanceForUpdate(ctx, tx, claim.GatewayID)
	if err != nil {
		return Registration{}, nil, err
	}
	if judgeInstanceClaim(claim.InstanceID, holder, firstSeen) != takeInstance {
		return Registration{}, holder, nil
	}

	registration := Registration{GatewayID: claim.GatewayID, InstanceID: claim.InstanceID}
	if holder == nil {
		_, err := tx.Exec(ctx, `
			insert into control_plane_instances
				(gateway_id, instance_id, hostname, version, pool_max_conns,
				 started_at, last_heartbeat_at, revision)
			values ($1, $2::uuid, $3, $4, $5, now(), now(), 1)`,
			claim.GatewayID, claim.InstanceID, claim.Hostname, claim.Version, claim.PoolMaxConns)
		if err != nil {
			var pgErr *pgconn.PgError
			if errors.As(err, &pgErr) && pgErr.Code == uniqueViolation {
				// Another replica inserted the row between the lock that
				// found nothing and this insert. Nothing was written; the
				// next attempt reads the row it lost to.
				return Registration{}, &Instance{GatewayID: claim.GatewayID}, nil
			}
			return Registration{}, nil, fmt.Errorf("claiming the gateway identifier: %w", err)
		}
		registration.First = true
	} else {
		if holder.InstanceID != claim.InstanceID {
			registration.TookOverFrom = holder.InstanceID
		}
		_, err := tx.Exec(ctx, `
			update control_plane_instances
			   set instance_id = $2::uuid, hostname = $3, version = $4, pool_max_conns = $5,
			       started_at = now(), last_heartbeat_at = now(), revision = revision + 1
			 where gateway_id = $1`,
			claim.GatewayID, claim.InstanceID, claim.Hostname, claim.Version, claim.PoolMaxConns)
		if err != nil {
			return Registration{}, nil, fmt.Errorf("taking over the gateway identifier: %w", err)
		}
	}
	if err := tx.Commit(ctx); err != nil {
		return Registration{}, nil, fmt.Errorf("committing the claim of the gateway identifier: %w", err)
	}
	return registration, nil, nil
}

// uniqueViolation is the SQLSTATE of a primary key that is already taken.
const uniqueViolation = "23505"

// readInstanceForUpdate reads and locks the row of a gateway identifier.
func readInstanceForUpdate(ctx context.Context, tx pgx.Tx, gatewayID string) (*Instance, error) {
	instance := Instance{GatewayID: gatewayID}
	var since float64
	err := tx.QueryRow(ctx, `
		select instance_id::text, hostname, version, pool_max_conns, started_at, last_heartbeat_at,
		       extract(epoch from now() - last_heartbeat_at)
		  from control_plane_instances where gateway_id = $1 for update`, gatewayID).
		Scan(&instance.InstanceID, &instance.Hostname, &instance.Version, &instance.PoolMaxConns,
			&instance.StartedAt, &instance.LastHeartbeatAt, &since)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("reading the holder of the gateway identifier: %w", err)
	}
	instance.SinceHeartbeat = time.Duration(since * float64(time.Second))
	return &instance, nil
}

// HeartbeatInstance says this process is still the one holding the
// identifier. A heartbeat that changes nothing means the row names somebody
// else, which is ErrInstanceSuperseded and is not survivable: the leases and
// the sessions this process writes are being read as another instance's.
func HeartbeatInstance(ctx context.Context, pool *pgxpool.Pool, registration Registration) error {
	tag, err := pool.Exec(ctx, `
		update control_plane_instances set last_heartbeat_at = now()
		 where gateway_id = $1 and instance_id = $2::uuid`,
		registration.GatewayID, registration.InstanceID)
	if err != nil {
		return fmt.Errorf("the heartbeat of the control-plane instance: %w", err)
	}
	if tag.RowsAffected() == 0 {
		return ErrInstanceSuperseded
	}
	return nil
}

// ReleaseInstance gives the identifier back on an orderly stop, so the
// replica that takes its place starts at once instead of waiting for the
// record to age out. A row that names another process is left alone.
func ReleaseInstance(ctx context.Context, pool *pgxpool.Pool, registration Registration) error {
	_, err := pool.Exec(ctx, `
		delete from control_plane_instances where gateway_id = $1 and instance_id = $2::uuid`,
		registration.GatewayID, registration.InstanceID)
	if err != nil {
		return fmt.Errorf("releasing the gateway identifier: %w", err)
	}
	return nil
}

// KeepInstanceAlive renews the heartbeat until the context ends, and returns
// when the identifier is taken from under this process. A failure that is
// not a takeover - the database is away for a moment - is logged and tried
// again: the stale window holds four heartbeats for exactly that.
func KeepInstanceAlive(ctx context.Context, pool *pgxpool.Pool, registration Registration, log *slog.Logger) error {
	if log == nil {
		log = slog.Default()
	}
	ticker := time.NewTicker(InstanceHeartbeatEvery)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return nil
		case <-ticker.C:
		}
		err := HeartbeatInstance(ctx, pool, registration)
		switch {
		case err == nil:
		case errors.Is(err, ErrInstanceSuperseded):
			log.Error("another process holds this gateway identifier now: two instances are answering "+
				"under one identifier, and the leases and sessions of this one are being read as the "+
				"other's", "code", CodeGatewayIDInUse, "gateway_id", registration.GatewayID,
				"instance_id", registration.InstanceID)
			return err
		case ctx.Err() != nil:
			return nil
		default:
			log.Warn("the heartbeat of this control-plane instance could not be written; it is tried again",
				"err", err, "gateway_id", registration.GatewayID, "stale_after", InstanceStaleAfter.String())
		}
	}
}

// LiveInstances lists the replicas whose heartbeat still counts, newest
// heartbeat first. A record that has aged out is left out: it is not a
// replica, and counting it would inflate the budget with a process that is
// gone.
func LiveInstances(ctx context.Context, pool *pgxpool.Pool) ([]Instance, error) {
	rows, err := pool.Query(ctx, `
		select gateway_id, instance_id::text, hostname, version, pool_max_conns,
		       started_at, last_heartbeat_at, extract(epoch from now() - last_heartbeat_at)
		  from control_plane_instances
		 where last_heartbeat_at > now() - make_interval(secs => $1)
		 order by gateway_id`, InstanceStaleAfter.Seconds())
	if err != nil {
		return nil, fmt.Errorf("reading the control-plane instances: %w", err)
	}
	defer rows.Close()
	instances := []Instance{}
	for rows.Next() {
		var instance Instance
		var since float64
		if err := rows.Scan(&instance.GatewayID, &instance.InstanceID, &instance.Hostname,
			&instance.Version, &instance.PoolMaxConns, &instance.StartedAt,
			&instance.LastHeartbeatAt, &since); err != nil {
			return nil, err
		}
		instance.SinceHeartbeat = time.Duration(since * float64(time.Second))
		instances = append(instances, instance)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	return instances, nil
}

// Budget is the connection arithmetic of chapter 21, done before somebody
// scales rather than after: the replicas that are alive, what each of them
// may open, and what the server answers in total.
type Budget struct {
	// Replicas are the live rows, and Instances are those rows.
	Replicas  int
	Instances []Instance
	// PoolMaxConns is this replica's own pool - the size a further replica
	// would most likely be given, and what the answer about the next one
	// is computed with.
	PoolMaxConns int32
	// Claimed is the sum of the pools of the live replicas: the
	// connections the installation may open at any moment, whether or not
	// it is opening them now.
	Claimed int
	// Unreported counts live replicas whose row names no pool. Their share
	// is not zero, it is unknown, and an unknown share is said out loud
	// rather than left out of the sum.
	Unreported int
	// ServerMaxConns is max_connections and Reserved is what the server
	// keeps for superusers; the difference is what ordinary clients share.
	ServerMaxConns int
	Reserved       int
	Available      int
	// InUse is what is connected to this database right now, replicas and
	// everything else - a psql session, a backup, the monitoring.
	InUse int
	// Headroom is what is left of Available once every live replica has
	// opened its whole pool. It goes negative when the replicas are
	// allowed more than the server answers.
	Headroom int
	// NextReplicaFits says whether one more replica of this size would
	// still fit; Shortfall is how many connections it would be over.
	NextReplicaFits bool
	Shortfall       int
}

// Overcommitted says the replicas may already open more than the server
// answers. Nothing is wrong until they all try at once, and then it is the
// whole fleet rather than the replica that was misconfigured.
func (b Budget) Overcommitted() bool { return b.Headroom < 0 }

// Summary is the one sentence the status screen and the log carry.
func (b Budget) Summary() string {
	switch {
	case b.ServerMaxConns == 0:
		return "the connection budget is unknown: the server did not answer what max_connections is"
	case b.Overcommitted():
		return fmt.Sprintf("%d replica(s) may open %d connections in total and the server answers %d: "+
			"%d over, which the next restart turns into a fleet-wide outage",
			b.Replicas, b.Claimed, b.Available, -b.Headroom)
	case !b.NextReplicaFits:
		return fmt.Sprintf("%d replica(s) may open %d of the %d connections the server answers; another "+
			"replica of %d connections would be %d over",
			b.Replicas, b.Claimed, b.Available, b.PoolMaxConns, b.Shortfall)
	default:
		return fmt.Sprintf("%d replica(s) may open %d of the %d connections the server answers; another "+
			"replica of %d connections fits", b.Replicas, b.Claimed, b.Available, b.PoolMaxConns)
	}
}

// ReadBudget gathers what the installation may open and what the server
// allows. The pool of this replica is read from the pool itself rather than
// from the row, because it is the one number here that is a fact of this
// process and not a report of another's.
func ReadBudget(ctx context.Context, pool *pgxpool.Pool) (Budget, error) {
	instances, err := LiveInstances(ctx, pool)
	if err != nil {
		return Budget{}, err
	}
	var serverMax, reserved, inUse int
	if err := pool.QueryRow(ctx, `
		select current_setting('max_connections')::int,
		       current_setting('superuser_reserved_connections')::int,
		       (select count(*) from pg_stat_activity where datname = current_database())`).
		Scan(&serverMax, &reserved, &inUse); err != nil {
		return Budget{}, fmt.Errorf("reading the connection limit of the server: %w", err)
	}
	return budgetOf(instances, pool.Config().MaxConns, serverMax, reserved, inUse), nil
}

// budgetOf is the arithmetic itself, separate from the reading so that it
// can be exercised without a database.
func budgetOf(instances []Instance, poolMaxConns int32, serverMax, reserved, inUse int) Budget {
	budget := Budget{
		Replicas: len(instances), Instances: instances, PoolMaxConns: poolMaxConns,
		ServerMaxConns: serverMax, Reserved: reserved, InUse: inUse,
	}
	budget.Available = serverMax - reserved
	if budget.Available < 0 {
		budget.Available = 0
	}
	for _, instance := range instances {
		if instance.PoolMaxConns <= 0 {
			budget.Unreported++
			continue
		}
		budget.Claimed += int(instance.PoolMaxConns)
	}
	budget.Headroom = budget.Available - budget.Claimed
	next := budget.Claimed + int(poolMaxConns)
	budget.NextReplicaFits = next <= budget.Available
	if !budget.NextReplicaFits {
		budget.Shortfall = next - budget.Available
	}
	return budget
}

// GatewayIDs lists the identifiers of the live replicas, for a log line and
// for the screen.
func (b Budget) GatewayIDs() []string {
	ids := make([]string, 0, len(b.Instances))
	for _, instance := range b.Instances {
		ids = append(ids, instance.GatewayID)
	}
	sort.Strings(ids)
	return ids
}
