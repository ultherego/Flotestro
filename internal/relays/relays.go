// Package relays przechowuje tozsamosc relayow lokalizacji.
//
// Relay konczy polaczenie agenta i sam swiadczy panelowi, czyj to ruch, wiec
// jest osobna granica zaufania. Panel musi wiedziec, ktory relay poswiadczyl
// tozsamosc hosta i czy wolno mu bylo to zrobic.
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

// ErrNotFound oznacza relay nieznany albo odwolany.
var ErrNotFound = errors.New("relay nie istnieje")

// Relay opisuje zarejestrowany relay lokalizacji.
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

// Upsert rejestruje relay albo odswieza jego tozsamosc przy ponownym
// enrollmencie. Nazwa jest kluczem naturalnym: ponowna instalacja tego samego
// relaya nie ma tworzyc drugiego wpisu.
func (s *Store) Upsert(ctx context.Context, tx pgx.Tx, name, site, environment string) (string, error) {
	const query = `
		insert into relays (id, name, site, environment)
		values ($1, $2, $3, nullif($4, ''))
		on conflict (name) do update set site = excluded.site, environment = excluded.environment
		returning id`
	var id string
	if err := tx.QueryRow(ctx, query, uuid.NewString(), name, site, environment).Scan(&id); err != nil {
		return "", fmt.Errorf("rejestracja relaya: %w", err)
	}
	return id, nil
}

// SaveCertificate zapisuje obecny certyfikat relaya. Poprzedni odcisk jest
// zastepowany: relay ma dokladnie jedna tozsamosc naraz.
func (s *Store) SaveCertificate(ctx context.Context, tx pgx.Tx, id, serial string,
	fingerprint []byte, notAfter time.Time) error {
	const query = `
		update relays set fingerprint_sha256 = $2, serial = $3, not_after = $4, revoked_at = null
		where id = $1`
	_, err := tx.Exec(ctx, query, id, fingerprint, serial, notAfter)
	return err
}

// Status opisuje relay przedstawiajacy certyfikat.
type Status struct {
	ID          string
	Name        string
	Site        string
	Environment string
	Revoked     bool
	Known       bool
}

// LookupCertificate rozpoznaje relay po odcisku certyfikatu.
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

// MarkSeen odnotowuje kontakt relaya. Blad zapisu nie moze zerwac sesji:
// znacznik jest informacja operacyjna, a nie warunkiem dzialania.
func (s *Store) MarkSeen(ctx context.Context, id string) {
	_, _ = s.pool.Exec(ctx, "update relays set last_seen_at = now() where id = $1", id)
}

// List zwraca relaye wraz ze stanem.
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

	lista := []Relay{}
	for rows.Next() {
		var relay Relay
		if err := rows.Scan(&relay.ID, &relay.Name, &relay.Site, &relay.Environment,
			&relay.Serial, &relay.NotAfter, &relay.EnrolledAt, &relay.LastSeenAt,
			&relay.RevokedAt); err != nil {
			return nil, err
		}
		lista = append(lista, relay)
	}
	return lista, rows.Err()
}

// Revoke odbiera relayowi prawo posredniczenia. Sesje agentow ida wtedy
// bezposrednio albo nie ida wcale - to swiadoma decyzja operatora.
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
