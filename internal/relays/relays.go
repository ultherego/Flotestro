// Package relays keeps the identities of the relays of the sites.
//
// A relay terminates the connection of an agent and attests to the panel whose
// traffic it is, so it is a separate trust boundary. The panel has to know
// which relay attested the identity of a host and whether it was allowed to do
// so.
package relays

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

// ErrNotFound means a relay that is unknown or revoked.
var ErrNotFound = errors.New("the relay does not exist")

// Relay describes a registered relay of a site.
type Relay struct {
	ID          string     `json:"id"`
	Name        string     `json:"name"`
	Site        string     `json:"site"`
	Environment string     `json:"environment,omitempty"`
	Serial      string     `json:"serial,omitempty"`
	NotAfter    *time.Time `json:"not_after,omitempty"`
	EnrolledAt  time.Time  `json:"enrolled_at"`
	LastSeenAt  *time.Time `json:"last_seen_at,omitempty"`
	RevokedAt   *time.Time `json:"revoked_at,omitempty"`
}

type Store struct {
	pool *pgxpool.Pool
}

func NewStore(pool *pgxpool.Pool) *Store { return &Store{pool: pool} }

func (s *Store) Pool() *pgxpool.Pool { return s.pool }

// Upsert registers a relay or refreshes its identity at a repeated
// enrollment. The name is the natural key: reinstalling the same relay is not
// to create a second entry.
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
//
// The names stay in the registry, because they are what goes into the server
// certificate at every renewal. Were they to come from the request, a relay
// could take the name of somebody else's service at a renewal and become
// something else to the agents.
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

// MarkSeen records the contact of a relay. A write error must not tear the
// session down: the mark is operational information rather than a condition of
// working.
func (s *Store) MarkSeen(ctx context.Context, id string) {
	_, _ = s.pool.Exec(ctx, "update relays set last_seen_at = now() where id = $1", id)
}

// List returns the relays together with their state.
func (s *Store) List(ctx context.Context) ([]Relay, error) {
	const query = `
		select id, name, site, coalesce(environment, ''), coalesce(serial, ''),
		       not_after, enrolled_at, last_seen_at, revoked_at
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
			&relay.RevokedAt); err != nil {
			return nil, err
		}
		list = append(list, relay)
	}
	return list, rows.Err()
}

// Revoke takes the right to mediate away from a relay. The sessions of the
// agents then go directly or do not go at all - that is a deliberate decision
// of the operator.
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
