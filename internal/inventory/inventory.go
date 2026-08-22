// Package inventory przechowuje niemutowalne rewizje inventory hostow.
package inventory

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

// Report to znormalizowany raport przyjety od agenta.
type Report struct {
	Revision       string
	Full           bool
	SchemaVersion  string
	OSFamily       string
	OSDistribution string
	OSVersion      string
	Architecture   string
	RawJSON        []byte

	// Identity opisuje integracje hosta z domena. Puste wskazniki oznaczaja
	// stan nieustalony i nie nadpisuja poprzedniej wiedzy.
	IdentityEnrolled   bool
	IdentityDomain     string
	IdentityRealm      string
	IdentitySSSDOnline *bool
}

// Revision opisuje zapisana rewizje.
type Revision struct {
	ID            string          `json:"id"`
	HostID        string          `json:"host_id"`
	Revision      string          `json:"revision"`
	Full          bool            `json:"full"`
	SchemaVersion string          `json:"schema_version"`
	Payload       json.RawMessage `json:"payload"`
	ObservedAt    time.Time       `json:"observed_at"`
}

type Store struct {
	pool *pgxpool.Pool
}

func NewStore(pool *pgxpool.Pool) *Store {
	return &Store{pool: pool}
}

// Save zapisuje rewizje i normalizuje pola uzywane w selektorach.
// Powtorzony raport o tej samej rewizji nie tworzy nowego wiersza, ale nadal
// odswieza znacznik obserwacji hosta.
func (s *Store) Save(ctx context.Context, hostID string, report Report) (stored bool, err error) {
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return false, err
	}
	defer func() { _ = tx.Rollback(ctx) }()

	const insert = `
		insert into inventory_revisions
			(id, host_id, revision, is_full, schema_version, payload, observed_at)
		values ($1, $2, $3, $4, $5, $6, now())
		on conflict (host_id, revision) do nothing
		returning id`
	var revisionID string
	err = tx.QueryRow(ctx, insert, uuid.NewString(), hostID, report.Revision,
		report.Full, report.SchemaVersion, report.RawJSON).Scan(&revisionID)
	switch {
	case errors.Is(err, pgx.ErrNoRows):
		stored = false
	case err != nil:
		return false, fmt.Errorf("zapis rewizji inventory: %w", err)
	default:
		stored = true
	}

	const updateHost = `
		update hosts set
			current_inventory_revision = $2,
			os_family                  = coalesce(nullif($3, ''), os_family),
			os_distribution            = coalesce(nullif($4, ''), os_distribution),
			os_version                 = coalesce(nullif($5, ''), os_version),
			architecture               = coalesce(nullif($6, ''), architecture),
			identity_enrolled          = $7,
			identity_domain            = nullif($8, ''),
			identity_realm             = nullif($9, ''),
			identity_sssd_online       = $10,
			identity_checked_at        = now(),
			updated_at                 = now()
		where id = $1`
	if _, err := tx.Exec(ctx, updateHost, hostID, report.Revision,
		report.OSFamily, report.OSDistribution, report.OSVersion, report.Architecture,
		report.IdentityEnrolled, report.IdentityDomain, report.IdentityRealm,
		report.IdentitySSSDOnline); err != nil {
		return false, fmt.Errorf("normalizacja inventory hosta: %w", err)
	}

	if err := tx.Commit(ctx); err != nil {
		return false, err
	}
	return stored, nil
}

// Latest zwraca ostatnia rewizje hosta.
func (s *Store) Latest(ctx context.Context, hostID string) (*Revision, error) {
	const query = `
		select id, host_id, revision, is_full, schema_version, payload, observed_at
		from inventory_revisions
		where host_id = $1
		order by observed_at desc
		limit 1`
	var rev Revision
	err := s.pool.QueryRow(ctx, query, hostID).Scan(&rev.ID, &rev.HostID, &rev.Revision,
		&rev.Full, &rev.SchemaVersion, &rev.Payload, &rev.ObservedAt)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	return &rev, nil
}
