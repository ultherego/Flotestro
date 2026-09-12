// Package inventory keeps the immutable inventory revisions of the hosts.
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

// Report is a normalised report accepted from an agent.
type Report struct {
	Revision       string
	Full           bool
	SchemaVersion  string
	OSFamily       string
	OSDistribution string
	OSVersion      string
	Architecture   string
	RawJSON        []byte

	// The identity describes the integration of the host with a domain. Empty
	// pointers mean an undetermined state and do not overwrite the previous
	// knowledge.
	IdentityEnrolled   bool
	IdentityDomain     string
	IdentityRealm      string
	IdentitySSSDOnline *bool

	// LocalAccounts is the full list of the accounts seen on the host. Nil
	// means no data in this report and does not erase the previous
	// observation.
	LocalAccounts []LocalAccount

	// Fragments is the report split into modules. An empty list means an agent
	// from before the split and does not erase what is already known about the
	// modules.
	Fragments []Fragment
}

// Fragment is the state of one module of a host together with a revision and
// a freshness of its own.
type Fragment struct {
	HostID            string          `json:"host_id"`
	Module            string          `json:"module"`
	Revision          string          `json:"revision"`
	Source            string          `json:"source"`
	Payload           json.RawMessage `json:"payload"`
	UnavailableReason string          `json:"unavailable_reason,omitempty"`
	ObservedAt        time.Time       `json:"observed_at"`
}

// LocalAccount is an observation of an account on a host.
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

// Revision describes a stored revision.
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

// Save writes a revision and normalises the fields used in the selectors. A
// repeated report about the same revision does not create a new row but still
// refreshes the observation mark of the host.
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
		return false, fmt.Errorf("writing the inventory revision: %w", err)
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
		return false, fmt.Errorf("normalising the inventory of the host: %w", err)
	}

	if report.LocalAccounts != nil {
		if err := replaceLocalAccounts(ctx, tx, hostID, report.LocalAccounts); err != nil {
			return false, err
		}
	}

	if err := saveFragments(ctx, tx, hostID, report.Fragments); err != nil {
		return false, err
	}

	if err := tx.Commit(ctx); err != nil {
		return false, err
	}
	return stored, nil
}

// replaceLocalAccounts swaps the observation of the accounts of a host. The
// accounts removed on the host disappear from the panel, because the list in
// the report is full rather than incremental.
func replaceLocalAccounts(ctx context.Context, tx pgx.Tx, hostID string, accounts []LocalAccount) error {
	names := make([]string, 0, len(accounts))
	for _, account := range accounts {
		names = append(names, account.Name)
	}
	const deleteStale = `delete from host_local_accounts where host_id = $1 and name <> all($2)`
	if _, err := tx.Exec(ctx, deleteStale, hostID, names); err != nil {
		return fmt.Errorf("clearing the local accounts: %w", err)
	}

	batch := &pgx.Batch{}
	for _, account := range accounts {
		queueLocalAccount(batch, hostID, account)
	}
	results := tx.SendBatch(ctx, batch)
	defer results.Close()
	for range accounts {
		if _, err := results.Exec(); err != nil {
			return fmt.Errorf("writing the local accounts: %w", err)
		}
	}
	return nil
}

// queueLocalAccount adds the write of an account observation to the batch.
// The query is one for a full report and for the result of a single operation,
// so both paths write exactly the same set of fields.
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

// UpsertLocalAccount writes the observation of a single account. It serves to
// close the loop after an operation: the result of a job carries the state of
// the account read from the host after the change, and the full inventory
// report comes only later.
func (s *Store) UpsertLocalAccount(ctx context.Context, hostID string, account LocalAccount) error {
	batch := &pgx.Batch{}
	queueLocalAccount(batch, hostID, account)
	results := s.pool.SendBatch(ctx, batch)
	defer results.Close()
	_, err := results.Exec()
	return err
}

// LocalAccounts returns the latest observation of the accounts of a host.
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

// Latest returns the latest revision of a host.
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

// saveFragments writes the modules that have changed. A module with the same
// revision is not rewritten: the data are the same, so moving updated_at would
// pretend a change that did not happen. The observation mark is always
// refreshed - the fact that the state has not changed was observed now as
// well.
func saveFragments(ctx context.Context, tx pgx.Tx, hostID string, fragments []Fragment) error {
	const query = `
		insert into host_module_inventory
			(host_id, module, revision, source, payload, unavailable_reason, observed_at, updated_at)
		values ($1, $2, $3, $4, $5, nullif($6, ''), $7, now())
		on conflict (host_id, module) do update set
			observed_at        = excluded.observed_at,
			revision           = excluded.revision,
			source             = excluded.source,
			payload            = excluded.payload,
			unavailable_reason = excluded.unavailable_reason,
			updated_at         = case
				when host_module_inventory.revision = excluded.revision
				then host_module_inventory.updated_at
				else now()
			end`
	for _, fragment := range fragments {
		if fragment.Module == "" || fragment.Revision == "" {
			continue
		}
		observed := fragment.ObservedAt
		if observed.IsZero() {
			observed = time.Now().UTC()
		}
		if _, err := tx.Exec(ctx, query, hostID, fragment.Module, fragment.Revision,
			fragment.Source, fragment.Payload, fragment.UnavailableReason, observed); err != nil {
			return fmt.Errorf("writing the module %s: %w", fragment.Module, err)
		}
	}
	return nil
}

// SaveFragment writes one module outside the inventory cycle. The on-demand
// reads use it: the operator opens a tab, the host sends the state back, and
// the state belongs to the host - not to the history of the jobs, where one
// would have to look for it.
func (s *Store) SaveFragment(ctx context.Context, hostID string, fragment Fragment) error {
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback(ctx) }()
	if err := saveFragments(ctx, tx, hostID, []Fragment{fragment}); err != nil {
		return err
	}
	return tx.Commit(ctx)
}

// Fragment returns the state of one module of a host. A missing row means a
// module the host has not reported yet.
func (s *Store) Fragment(ctx context.Context, hostID, module string) (*Fragment, error) {
	const query = `
		select host_id, module, revision, source, payload,
		       coalesce(unavailable_reason, ''), observed_at
		  from host_module_inventory
		 where host_id = $1 and module = $2`
	var fragment Fragment
	err := s.pool.QueryRow(ctx, query, hostID, module).Scan(&fragment.HostID,
		&fragment.Module, &fragment.Revision, &fragment.Source, &fragment.Payload,
		&fragment.UnavailableReason, &fragment.ObservedAt)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	return &fragment, nil
}

// Fragments returns every module of a host, by name.
func (s *Store) Fragments(ctx context.Context, hostID string) ([]Fragment, error) {
	const query = `
		select host_id, module, revision, source, payload,
		       coalesce(unavailable_reason, ''), observed_at
		  from host_module_inventory
		 where host_id = $1
		 order by module`
	rows, err := s.pool.Query(ctx, query, hostID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var wynik []Fragment
	for rows.Next() {
		var fragment Fragment
		if err := rows.Scan(&fragment.HostID, &fragment.Module, &fragment.Revision,
			&fragment.Source, &fragment.Payload, &fragment.UnavailableReason,
			&fragment.ObservedAt); err != nil {
			return nil, err
		}
		wynik = append(wynik, fragment)
	}
	return wynik, rows.Err()
}

// HostFragments returns the modules of many hosts in one query.
//
// The fleet view computes the compliance for every host separately, but asking
// the database once per host would turn one screen into hundreds of
// queries.
func (s *Store) HostFragments(ctx context.Context, hostIDs []string) (map[string][]Fragment, error) {
	wynik := map[string][]Fragment{}
	if len(hostIDs) == 0 {
		return wynik, nil
	}
	const query = `
		select host_id, module, revision, source, payload,
		       coalesce(unavailable_reason, ''), observed_at
		  from host_module_inventory
		 where host_id = any($1)
		 order by host_id, module`
	rows, err := s.pool.Query(ctx, query, hostIDs)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	for rows.Next() {
		var fragment Fragment
		if err := rows.Scan(&fragment.HostID, &fragment.Module, &fragment.Revision,
			&fragment.Source, &fragment.Payload, &fragment.UnavailableReason,
			&fragment.ObservedAt); err != nil {
			return nil, err
		}
		wynik[fragment.HostID] = append(wynik[fragment.HostID], fragment)
	}
	return wynik, rows.Err()
}
