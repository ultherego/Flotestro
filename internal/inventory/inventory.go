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

	// LocalAccounts jest pelna lista kont widzianych na hoscie. Nil oznacza
	// brak danych w tym raporcie i nie kasuje poprzedniej obserwacji.
	LocalAccounts []LocalAccount
}

// LocalAccount jest obserwacja konta na hoscie.
type LocalAccount struct {
	Name              string          `json:"name"`
	UID               int64           `json:"uid"`
	GID               int64           `json:"gid"`
	Home              string          `json:"home,omitempty"`
	Shell             string          `json:"shell,omitempty"`
	Gecos             string          `json:"gecos,omitempty"`
	Source            string          `json:"source"`
	Groups            []string        `json:"groups"`
	Locked            *bool           `json:"locked"`
	PasswordSet       *bool           `json:"password_set"`
	SSHKeys           json.RawMessage `json:"ssh_keys"`
	UnavailableReason string          `json:"unavailable_reason,omitempty"`
	ObservedAt        time.Time       `json:"observed_at"`
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

	if report.LocalAccounts != nil {
		if err := replaceLocalAccounts(ctx, tx, hostID, report.LocalAccounts); err != nil {
			return false, err
		}
	}

	if err := tx.Commit(ctx); err != nil {
		return false, err
	}
	return stored, nil
}

// replaceLocalAccounts podmienia obserwacje kont hosta. Konta usuniete na
// hoscie znikaja z panelu, bo lista w raporcie jest pelna, a nie przyrostowa.
func replaceLocalAccounts(ctx context.Context, tx pgx.Tx, hostID string, accounts []LocalAccount) error {
	names := make([]string, 0, len(accounts))
	for _, account := range accounts {
		names = append(names, account.Name)
	}
	const deleteStale = `delete from host_local_accounts where host_id = $1 and name <> all($2)`
	if _, err := tx.Exec(ctx, deleteStale, hostID, names); err != nil {
		return fmt.Errorf("czyszczenie kont lokalnych: %w", err)
	}

	batch := &pgx.Batch{}
	for _, account := range accounts {
		queueLocalAccount(batch, hostID, account)
	}
	results := tx.SendBatch(ctx, batch)
	defer results.Close()
	for range accounts {
		if _, err := results.Exec(); err != nil {
			return fmt.Errorf("zapis kont lokalnych: %w", err)
		}
	}
	return nil
}

// queueLocalAccount dokleja zapis obserwacji konta do partii. Zapytanie jest
// jedno dla raportu pelnego i dla wyniku pojedynczej operacji, wiec obie
// sciezki zapisuja dokladnie ten sam zestaw pol.
func queueLocalAccount(batch *pgx.Batch, hostID string, account LocalAccount) {
	const upsert = `
		insert into host_local_accounts
			(host_id, name, uid, gid, home, shell, gecos, source, groups,
			 locked, password_set, ssh_keys, unavailable_reason, observed_at)
		values ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, nullif($13, ''), now())
		on conflict (host_id, name) do update set
			uid = excluded.uid, gid = excluded.gid, home = excluded.home,
			shell = excluded.shell, gecos = excluded.gecos, source = excluded.source,
			groups = excluded.groups, locked = excluded.locked,
			password_set = excluded.password_set,
			ssh_keys = excluded.ssh_keys,
			unavailable_reason = excluded.unavailable_reason,
			observed_at = now()`
	keys := account.SSHKeys
	if len(keys) == 0 {
		keys = json.RawMessage("[]")
	}
	groups := account.Groups
	if groups == nil {
		groups = []string{}
	}
	batch.Queue(upsert, hostID, account.Name, account.UID, account.GID,
		account.Home, account.Shell, account.Gecos, account.Source, groups,
		account.Locked, account.PasswordSet, keys, account.UnavailableReason)
}

// UpsertLocalAccount zapisuje obserwacje pojedynczego konta. Sluzy do
// domkniecia petli po operacji: wynik zadania niesie stan konta odczytany
// z hosta po zmianie, a pelny raport inventory przyjdzie dopiero pozniej.
func (s *Store) UpsertLocalAccount(ctx context.Context, hostID string, account LocalAccount) error {
	batch := &pgx.Batch{}
	queueLocalAccount(batch, hostID, account)
	results := s.pool.SendBatch(ctx, batch)
	defer results.Close()
	_, err := results.Exec()
	return err
}

// LocalAccounts zwraca ostatnia obserwacje kont hosta.
func (s *Store) LocalAccounts(ctx context.Context, hostID string) ([]LocalAccount, error) {
	const query = `
		select name, uid, gid, coalesce(home, ''), coalesce(shell, ''),
		       coalesce(gecos, ''), source, groups, locked, password_set, ssh_keys,
		       coalesce(unavailable_reason, ''), observed_at
		from host_local_accounts
		where host_id = $1
		order by source, name`
	rows, err := s.pool.Query(ctx, query, hostID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	accounts := []LocalAccount{}
	for rows.Next() {
		var account LocalAccount
		if err := rows.Scan(&account.Name, &account.UID, &account.GID, &account.Home,
			&account.Shell, &account.Gecos, &account.Source, &account.Groups,
			&account.Locked, &account.PasswordSet, &account.SSHKeys,
			&account.UnavailableReason,
			&account.ObservedAt); err != nil {
			return nil, err
		}
		accounts = append(accounts, account)
	}
	return accounts, rows.Err()
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
