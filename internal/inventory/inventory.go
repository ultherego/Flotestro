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

	// The identity describes the integration of the host with a domain.
	IdentityEnrolled   bool
	IdentityDomain     string
	IdentityRealm      string
	IdentitySSSDOnline *bool

	// LocalAccounts is the full list of the accounts seen on the host. Nil means
	// no data in this report and does not erase the previous observation.
	LocalAccounts []LocalAccount

	// Fragments is the report split into modules.
	Fragments []Fragment
}

// covers says whether the report observed the module: a full report covers
// everything, a partial one only the modules it carries.
func (r Report) covers(module string) bool {
	if r.Full {
		return true
	}
	for _, fragment := range r.Fragments {
		if fragment.Module == module {
			return true
		}
	}
	return false
}

// ModuleAccounts is the module of the local accounts, as the agent names it.
// The panel reads its unavailable reason: a report whose accounts could not be
// read must not erase the ones the panel holds.
const ModuleAccounts = "accounts"

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
	Name        string          `json:"name"`
	UID         int64           `json:"uid"`
	GID         int64           `json:"gid"`
	Home        string          `json:"home,omitempty"`
	Shell       string          `json:"shell,omitempty"`
	Gecos       string          `json:"gecos,omitempty"`
	Source      string          `json:"source"`
	Groups      []string        `json:"groups"`
	Locked      *bool           `json:"locked"`
	PasswordSet *bool           `json:"password_set"`
	SSHKeys     json.RawMessage `json:"ssh_keys"`
	// ExpiresAt is the expiry date as YYYY-MM-DD from the shadow record.
	ExpiresAt         string    `json:"expires_at,omitempty"`
	UnavailableReason string    `json:"unavailable_reason,omitempty"`
	ObservedAt        time.Time `json:"observed_at"`
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

// The bounds an agent cannot move. A report of an ordinary host is a few
// hundred kilobytes and a lab Debian with every module on reports 2.
const (
	MaxPayloadBytes     = 6 << 20
	MaxRevisionsPerHost = 20
)

// ErrOversized means a report larger than MaxPayloadBytes. The caller
// refuses it without writing anything.
var ErrOversized = errors.New("the inventory report exceeds the size limit")

type Store struct {
	pool *pgxpool.Pool
	// refreshAfter says how long a module that has not changed may keep the mark
	// of its last observation before a report of it moves the mark.
	refreshAfter func(module string) time.Duration
}

func NewStore(pool *pgxpool.Pool) *Store {
	return &Store{pool: pool}
}

// ObservationRefresh is how stale the mark of the last observation of an
// unchanged module may become before a report of it rewrites the row. A host
// that reconnects reports everything again, and rewriting thousands of rows
// that say what they said a minute ago is most of what a return of the fleet
// costs the database. The mark is evidence of freshness, so the window is the
// width of the lag it adds: a quarter of what the policy tolerates for the
// module, at most this long (SetRefreshWindow).
const ObservationRefresh = 15 * time.Minute

// SetRefreshWindow replaces the window per module. The panel gives it the
// freshness the policy requires of each module, so that skipping a write can
// never be what makes a fact too old to rest a verdict on.
func (s *Store) SetRefreshWindow(window func(module string) time.Duration) {
	s.refreshAfter = window
}

// window is the lag the mark of an unchanged module may carry.
func (s *Store) window(module string) time.Duration {
	if s != nil && s.refreshAfter != nil {
		if window := s.refreshAfter(module); window > 0 && window < ObservationRefresh {
			return window
		}
	}
	return ObservationRefresh
}

// Save writes a revision and normalises the fields used in the selectors.
func (s *Store) Save(ctx context.Context, hostID string, report Report) (stored bool, err error) {
	if len(report.RawJSON) > MaxPayloadBytes {
		return false, fmt.Errorf("%w: %d bytes, the limit is %d", ErrOversized,
			len(report.RawJSON), MaxPayloadBytes)
	}
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return false, err
	}
	defer func() { _ = tx.Rollback(ctx) }()

	// A revision seen before is not written again, but its observation mark
	// moves, so a host back at an earlier revision has it as its latest.
	const insert = `
		insert into inventory_revisions
			(id, host_id, revision, is_full, schema_version, payload, observed_at)
		values ($1, $2, $3, $4, $5, $6, now())
		on conflict (host_id, revision) do update set observed_at = now()
		returning (xmax = 0)`
	if err := tx.QueryRow(ctx, insert, uuid.NewString(), hostID, report.Revision,
		report.Full, report.SchemaVersion, report.RawJSON).Scan(&stored); err != nil {
		return false, fmt.Errorf("writing the inventory revision: %w", err)
	}

	// The older revisions go in the same transaction as the new one arrives: the
	// cap holds at every commit rather than until the next sweep.
	if stored {
		if err := pruneRevisions(ctx, tx, hostID); err != nil {
			return false, err
		}
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
			identity_checked_at        = case when $11 then now() else identity_checked_at end,
			updated_at                 = now()
		where id = $1`
	// A partial report carries the identity over from the last read, so the
	// values are the same - but the date of the check moves only when the module
	// was really read.
	if _, err := tx.Exec(ctx, updateHost, hostID, report.Revision,
		report.OSFamily, report.OSDistribution, report.OSVersion, report.Architecture,
		report.IdentityEnrolled, report.IdentityDomain, report.IdentityRealm,
		report.IdentitySSSDOnline, report.covers("identity")); err != nil {
		return false, fmt.Errorf("normalising the inventory of the host: %w", err)
	}

	if report.LocalAccounts != nil {
		if err := replaceLocalAccounts(ctx, tx, hostID, report.LocalAccounts, s.window("accounts")); err != nil {
			return false, err
		}
	}

	if err := s.saveFragments(ctx, tx, hostID, report.Fragments, false); err != nil {
		return false, err
	}

	if err := tx.Commit(ctx); err != nil {
		return false, err
	}
	return stored, nil
}

// pruneRevisions deletes the revisions of a host beyond the newest
// MaxRevisionsPerHost.
func pruneRevisions(ctx context.Context, tx pgx.Tx, hostID string) error {
	const query = `
		delete from inventory_revisions
		where host_id = $1
		  and id not in (
			select id from inventory_revisions
			where host_id = $1
			order by observed_at desc, created_at desc
			limit $2)`
	if _, err := tx.Exec(ctx, query, hostID, MaxRevisionsPerHost); err != nil {
		return fmt.Errorf("pruning the inventory revisions: %w", err)
	}
	return nil
}

// replaceLocalAccounts swaps the observation of the accounts of a host.
func replaceLocalAccounts(ctx context.Context, tx pgx.Tx, hostID string, accounts []LocalAccount,
	window time.Duration) error {
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
		queueLocalAccount(batch, hostID, account, window)
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
func queueLocalAccount(batch *pgx.Batch, hostID string, account LocalAccount, window time.Duration) {
	const upsert = `
		insert into host_local_accounts
			(host_id, name, uid, gid, home, shell, gecos, source, groups,
			 locked, password_set, ssh_keys, unavailable_reason, expires_at, observed_at)
		values ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, nullif($13, ''), nullif($14, ''), now())
		on conflict (host_id, name) do update set
			uid = excluded.uid, gid = excluded.gid, home = excluded.home,
			shell = excluded.shell, gecos = excluded.gecos, source = excluded.source,
			groups = excluded.groups, locked = excluded.locked,
			password_set = excluded.password_set,
			ssh_keys = excluded.ssh_keys,
			unavailable_reason = excluded.unavailable_reason,
			expires_at = excluded.expires_at,
			observed_at = now()
		-- An account that says what it said, recently, is not written again: the
		-- row would only get a new mark, and a return of the fleet is thousands.
		where (host_local_accounts.uid, host_local_accounts.gid, host_local_accounts.home,
		       host_local_accounts.shell, host_local_accounts.gecos, host_local_accounts.source,
		       host_local_accounts.groups, host_local_accounts.locked,
		       host_local_accounts.password_set, host_local_accounts.ssh_keys,
		       host_local_accounts.unavailable_reason, host_local_accounts.expires_at)
		      is distinct from
		      (excluded.uid, excluded.gid, excluded.home, excluded.shell, excluded.gecos,
		       excluded.source, excluded.groups, excluded.locked, excluded.password_set,
		       excluded.ssh_keys, excluded.unavailable_reason, excluded.expires_at)
		   or host_local_accounts.observed_at <= now() - make_interval(secs => $15)`
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
		account.Locked, account.PasswordSet, keys, account.UnavailableReason, account.ExpiresAt,
		window.Seconds())
}

// DeleteLocalAccount removes the observation of an account the host no longer
// has.
func (s *Store) DeleteLocalAccount(ctx context.Context, hostID, name string) error {
	const query = `delete from host_local_accounts where host_id = $1 and name = $2`
	_, err := s.pool.Exec(ctx, query, hostID, name)
	return err
}

// UpsertLocalAccount writes the observation of a single account.
func (s *Store) UpsertLocalAccount(ctx context.Context, hostID string, account LocalAccount) error {
	batch := &pgx.Batch{}
	queueLocalAccount(batch, hostID, account, 0)
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
		       coalesce(unavailable_reason, ''), coalesce(expires_at, ''), observed_at
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
			&account.UnavailableReason, &account.ExpiresAt,
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

// saveFragments writes the modules that have changed.
func (s *Store) saveFragments(ctx context.Context, tx pgx.Tx, hostID string, fragments []Fragment,
	force bool) error {
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
			end
		-- A module that says what it said, observed not long before, is not written
		-- again; the mark moves once it is older than the window of the module.
		where (host_module_inventory.revision, host_module_inventory.source,
		       host_module_inventory.payload, host_module_inventory.unavailable_reason)
		      is distinct from
		      (excluded.revision, excluded.source, excluded.payload, excluded.unavailable_reason)
		   or host_module_inventory.observed_at <= excluded.observed_at - make_interval(secs => $8)`
	for _, fragment := range fragments {
		if fragment.Module == "" || fragment.Revision == "" {
			continue
		}
		observed := fragment.ObservedAt
		if observed.IsZero() {
			observed = time.Now().UTC()
		}
		window := s.window(fragment.Module)
		if force {
			window = 0
		}
		if _, err := tx.Exec(ctx, query, hostID, fragment.Module, fragment.Revision,
			fragment.Source, fragment.Payload, fragment.UnavailableReason, observed,
			window.Seconds()); err != nil {
			return fmt.Errorf("writing the module %s: %w", fragment.Module, err)
		}
	}
	return nil
}

// SaveFragment writes one module outside the inventory cycle.
func (s *Store) SaveFragment(ctx context.Context, hostID string, fragment Fragment) error {
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback(ctx) }()
	// The answer to an order is always written: it is what the view of that order
	// compares with the moment the order was made (adminapi/reads.go), and a mark
	// left from an earlier read would pass for a snapshot older than the order.
	if err := s.saveFragments(ctx, tx, hostID, []Fragment{fragment}, true); err != nil {
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

	var result []Fragment
	for rows.Next() {
		var fragment Fragment
		if err := rows.Scan(&fragment.HostID, &fragment.Module, &fragment.Revision,
			&fragment.Source, &fragment.Payload, &fragment.UnavailableReason,
			&fragment.ObservedAt); err != nil {
			return nil, err
		}
		result = append(result, fragment)
	}
	return result, rows.Err()
}

// HostFragments returns the modules of many hosts in one query.
func (s *Store) HostFragments(ctx context.Context, hostIDs []string) (map[string][]Fragment, error) {
	result := map[string][]Fragment{}
	if len(hostIDs) == 0 {
		return result, nil
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
		result[fragment.HostID] = append(result[fragment.HostID], fragment)
	}
	return result, rows.Err()
}
