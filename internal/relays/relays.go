// Package relays keeps the identities of the relays of the sites.
package relays

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

// ErrNotFound means a relay that is unknown or revoked.
var ErrNotFound = errors.New("the relay does not exist")

// Relay describes a registered relay of a site.
type Relay struct {
	ID               string     `json:"id"`
	Name             string     `json:"name"`
	Site             string     `json:"site"`
	Environment      string     `json:"environment,omitempty"`
	Serial           string     `json:"serial,omitempty"`
	NotAfter         *time.Time `json:"not_after,omitempty"`
	EnrolledAt       time.Time  `json:"enrolled_at"`
	LastSeenAt       *time.Time `json:"last_seen_at,omitempty"`
	RevokedAt        *time.Time `json:"revoked_at,omitempty"`
	RevocationReason string     `json:"revocation_reason,omitempty"`
}

// The states of a relay as the panel sees them. They are the same four the
// metrics count, so a number on the dashboard and a row in the list agree.
const (
	StateActive    = "active"
	StateSilent    = "silent"
	StateNeverSeen = "never_seen"
	StateRevoked   = "revoked"
)

// SilentAfter is how long without a contact makes a relay silent.
const SilentAfter = 10 * time.Minute

// StateAt classifies a relay at a given moment.
func (r Relay) StateAt(now time.Time) string {
	switch {
	case r.RevokedAt != nil:
		return StateRevoked
	case r.LastSeenAt == nil:
		return StateNeverSeen
	case now.Sub(*r.LastSeenAt) > SilentAfter:
		return StateSilent
	}
	return StateActive
}

// Heartbeat is what a relay reports about itself when it calls the centre.
type Heartbeat struct {
	BufferBytes    int64 `json:"buffer_bytes"`
	BufferMaxBytes int64 `json:"buffer_max_bytes"`
	BufferedItems  int   `json:"buffered_items"`
	BufferDropped  int64 `json:"buffer_dropped"`
	Sessions       int   `json:"sessions"`
	// SpoolBytesLimit is the room the durable spool of the relay may take on
	// disk.
	SpoolBytesLimit int64 `json:"spool_bytes_limit,omitempty"`
	// InstanceID names the process of the relay: a fresh identifier at every
	// start.
	InstanceID string `json:"instance_id,omitempty"`
	// UpstreamState is connected, buffering or reconnecting, as the relay saw its
	// link at the moment of the report.
	UpstreamState string    `json:"upstream_state,omitempty"`
	RelayVersion  string    `json:"relay_version,omitempty"`
	ReportedAt    time.Time `json:"reported_at"`
}

type Store struct {
	pool *pgxpool.Pool
	// retention is how long the buffer history is kept; set once at
	// startup by the process that also runs the sweep.
	retention Options

	mu         sync.RWMutex
	heartbeats map[string]Heartbeat
}

func NewStore(pool *pgxpool.Pool) *Store {
	return &Store{pool: pool, heartbeats: map[string]Heartbeat{}}
}

// RecordHeartbeat keeps the latest report of a relay.
func (s *Store) RecordHeartbeat(id string, heartbeat Heartbeat) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.heartbeats[id] = heartbeat
}

// LastHeartbeat returns the latest report of a relay, if it made one since
// the panel started.
func (s *Store) LastHeartbeat(id string) (Heartbeat, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	heartbeat, ok := s.heartbeats[id]
	return heartbeat, ok
}

func (s *Store) Pool() *pgxpool.Pool { return s.pool }

// Upsert registers a relay or refreshes its identity at a repeated enrollment.
func (s *Store) Upsert(ctx context.Context, tx pgx.Tx, name, site, environment string) (string, error) {
	const query = `
		insert into relays (id, name, site, environment)
		values ($1, $2, $3, nullif($4, ''))
		on conflict (name) do update set site = excluded.site, environment = excluded.environment
		returning id`
	var id string
	if err := tx.QueryRow(ctx, query, uuid.NewString(), name, site, environment).Scan(&id); err != nil {
		return "", fmt.Errorf("registering the relay: %w", err)
	}
	return id, nil
}

// SaveCertificate writes the current certificate of a relay. The previous
// fingerprint is replaced: a relay has exactly one identity at a time.
func (s *Store) SaveCertificate(ctx context.Context, tx pgx.Tx, id, serial string,
	fingerprint []byte, notAfter time.Time) error {
	const query = `
		update relays set fingerprint_sha256 = $2, serial = $3, not_after = $4, revoked_at = null
		where id = $1`
	_, err := tx.Exec(ctx, query, id, fingerprint, serial, notAfter)
	return err
}

// SaveNames writes the network names the relay is visible under.
func (s *Store) SaveNames(ctx context.Context, tx pgx.Tx, id string, names []string) error {
	if names == nil {
		names = []string{}
	}
	_, err := tx.Exec(ctx, "update relays set advertised_names = $2 where id = $1", id, names)
	return err
}

// Names returns the recorded network names of a relay.
func (s *Store) Names(ctx context.Context, id string) ([]string, error) {
	var names []string
	err := s.pool.QueryRow(ctx, "select advertised_names from relays where id = $1", id).Scan(&names)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, ErrNotFound
	}
	return names, err
}

// RecordRenewal writes the moment the certificate of a relay was replaced.
func (s *Store) RecordRenewal(ctx context.Context, tx pgx.Tx, id string) error {
	_, err := tx.Exec(ctx, "update relays set renewed_at = now() where id = $1", id)
	return err
}

// Status describes a relay presenting a certificate.
type Status struct {
	ID          string
	Name        string
	Site        string
	Environment string
	Revoked     bool
	Known       bool
}

// LookupCertificate recognises a relay by the fingerprint of its certificate.
func (s *Store) LookupCertificate(ctx context.Context, fingerprint []byte) (Status, error) {
	const query = `
		select id, name, site, coalesce(environment, ''), revoked_at is not null
		from relays where fingerprint_sha256 = $1`
	var status Status
	err := s.pool.QueryRow(ctx, query, fingerprint).
		Scan(&status.ID, &status.Name, &status.Site, &status.Environment, &status.Revoked)
	if errors.Is(err, pgx.ErrNoRows) {
		return Status{}, nil
	}
	if err != nil {
		return Status{}, err
	}
	status.Known = true
	return status, nil
}

// MarkSeen records the contact of a relay.
func (s *Store) MarkSeen(ctx context.Context, id string) {
	_, _ = s.pool.Exec(ctx, "update relays set last_seen_at = now() where id = $1", id)
}

// List returns the relays together with their state.
func (s *Store) List(ctx context.Context) ([]Relay, error) {
	const query = `
		select id, name, site, coalesce(environment, ''), coalesce(serial, ''),
		       not_after, enrolled_at, last_seen_at, revoked_at, coalesce(revocation_reason, '')
		from relays order by site, name`
	rows, err := s.pool.Query(ctx, query)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	list := []Relay{}
	for rows.Next() {
		var relay Relay
		if err := rows.Scan(&relay.ID, &relay.Name, &relay.Site, &relay.Environment,
			&relay.Serial, &relay.NotAfter, &relay.EnrolledAt, &relay.LastSeenAt,
			&relay.RevokedAt, &relay.RevocationReason); err != nil {
			return nil, err
		}
		list = append(list, relay)
	}
	return list, rows.Err()
}

// Get returns one relay, revoked or not.
func (s *Store) Get(ctx context.Context, id string) (*Relay, error) {
	const query = `
		select id, name, site, coalesce(environment, ''), coalesce(serial, ''),
		       not_after, enrolled_at, last_seen_at, revoked_at, coalesce(revocation_reason, '')
		from relays where id = $1`
	var relay Relay
	err := s.pool.QueryRow(ctx, query, id).Scan(&relay.ID, &relay.Name, &relay.Site,
		&relay.Environment, &relay.Serial, &relay.NotAfter, &relay.EnrolledAt,
		&relay.LastSeenAt, &relay.RevokedAt, &relay.RevocationReason)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, err
	}
	return &relay, nil
}

// Revoke takes the right to mediate away from a relay.
func (s *Store) Revoke(ctx context.Context, id, reason string) error {
	tag, err := s.pool.Exec(ctx,
		"update relays set revoked_at = now(), revocation_reason = $2 where id = $1 and revoked_at is null",
		id, reason)
	if err != nil {
		return err
	}
	if tag.RowsAffected() == 0 {
		return ErrNotFound
	}
	return nil
}

// AttestedHost is a host whose current session came through a relay.
type AttestedHost struct {
	HostID          string     `json:"host_id"`
	Hostname        string     `json:"hostname"`
	Site            string     `json:"site"`
	Environment     string     `json:"environment,omitempty"`
	LifecycleState  string     `json:"lifecycle_state"`
	AgentVersion    string     `json:"agent_version,omitempty"`
	ConnectedAt     time.Time  `json:"connected_at"`
	LastHeartbeatAt *time.Time `json:"last_heartbeat_at,omitempty"`
}

// AttestedHosts lists the hosts with an open session attested by the relay.
func (s *Store) AttestedHosts(ctx context.Context, id string) ([]AttestedHost, error) {
	const query = `
		select h.id, h.hostname, h.site, coalesce(h.environment, ''), h.lifecycle_state,
		       coalesce(s.agent_version, ''), s.started_at, s.last_heartbeat_at
		from agent_sessions s join hosts h on h.id = s.host_id
		where s.relay_id = $1 and s.ended_at is null
		order by h.hostname`
	rows, err := s.pool.Query(ctx, query, id)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	list := []AttestedHost{}
	for rows.Next() {
		var host AttestedHost
		if err := rows.Scan(&host.HostID, &host.Hostname, &host.Site, &host.Environment,
			&host.LifecycleState, &host.AgentVersion, &host.ConnectedAt,
			&host.LastHeartbeatAt); err != nil {
			return nil, err
		}
		list = append(list, host)
	}
	return list, rows.Err()
}

// AttestedCounts counts the open sessions attested by each relay.
func (s *Store) AttestedCounts(ctx context.Context) (map[string]int, error) {
	rows, err := s.pool.Query(ctx, `
		select relay_id, count(*) from agent_sessions
		where relay_id is not null and ended_at is null group by relay_id`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	counts := map[string]int{}
	for rows.Next() {
		var id string
		var count int
		if err := rows.Scan(&id, &count); err != nil {
			return nil, err
		}
		counts[id] = count
	}
	return counts, rows.Err()
}
