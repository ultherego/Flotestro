package cryptostate

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"slices"
	"sort"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/ultherego/flotestro/internal/secrets"
)

// Record is the installation's row: which key seals the secrets, which CA
// issues the certificates, and the sentinel that proves the key on disk is the
// one the row was written with.
type Record struct {
	InstallationID string
	Provider       string
	ActiveKeyID    string
	// IssuerID and IssuerFingerprint describe the CA that signs; the
	// files on disk have to match them.
	IssuerID          string
	IssuerFingerprint string
	Sentinel          secrets.Envelope
	InitializedAt     time.Time
	UpdatedAt         time.Time
	Revision          int64
}

// Facts is what the database holds that binds it to key material.
type Facts struct {
	// SecretVersions counts the live versions of the secret store: each
	// is unreadable without the key it was sealed under.
	SecretVersions int
	// Hosts and Certificates are the fleet: each host trusts the CA that
	// issued its certificate.
	Hosts        int
	Certificates int
}

// Empty says whether nothing in the database depends on key material.
func (f Facts) Empty() bool {
	return f.SecretVersions == 0 && f.Hosts == 0 && f.Certificates == 0
}

// ErrNoRecord means the installation has no row yet: either it is new or
// it was made before the row existed.
var ErrNoRecord = errors.New("no installation record")

// Storage is the seam between the guard and the database, so the startup
// table can be exercised without one.
type Storage interface {
	// Lock takes the installation lock and holds it until the returned function
	// runs.
	Lock(ctx context.Context) (func(), error)
	Load(ctx context.Context) (*Record, error)
	Insert(ctx context.Context, record Record) error
	// Update replaces the record, raising its revision.
	Update(ctx context.Context, record Record) error
	// UpdateIfRevision replaces the record only while it still stands at the
	// revision the caller read. Two replicas rotating at once would otherwise
	// each write over the other's work with no sign of it.
	UpdateIfRevision(ctx context.Context, record Record, expected int64) error
	Facts(ctx context.Context) (Facts, error)
	// AssignIssuer fills in the issuer identifier of the certificates
	// issued by the named CA that carry none yet.
	AssignIssuer(ctx context.Context, subject, serial, issuerID string) (int64, error)
	// LiveKeyIDs names every key that a secret version still in use was
	// sealed with. A key named here and absent from the provider is a secret
	// nobody can read, and the panel is to find that at the start rather than
	// at the moment an operation needs the value.
	LiveKeyIDs(ctx context.Context) ([]string, error)
}

// installationLockID is the advisory lock of the initialisation: "FCRY".
const installationLockID = 0x46435259

// Postgres is the Storage over the fleet database.
type Postgres struct {
	pool *pgxpool.Pool
}

// NewPostgres builds the storage over the pool.
func NewPostgres(pool *pgxpool.Pool) *Postgres { return &Postgres{pool: pool} }

// LiveKeyIDs names the keys the live secret versions were sealed with. Rows of
// the form that predates the key identifiers carry none and are left out: the
// rewrap reaches them, and the legacy key is adopted separately.
func (p *Postgres) LiveKeyIDs(ctx context.Context) ([]string, error) {
	rows, err := p.pool.Query(ctx, `
		select distinct key_id from secret_versions
		 where destroyed_at is null and coalesce(key_id, '') <> ''`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var keys []string
	for rows.Next() {
		var key string
		if err := rows.Scan(&key); err != nil {
			return nil, err
		}
		keys = append(keys, key)
	}
	return keys, rows.Err()
}

// Lock implements Storage with a session-level advisory lock on a
// connection taken from the pool for the purpose.
func (p *Postgres) Lock(ctx context.Context) (func(), error) {
	conn, err := p.pool.Acquire(ctx)
	if err != nil {
		return nil, fmt.Errorf("the connection for the installation lock: %w", err)
	}
	if _, err := conn.Exec(ctx, "select pg_advisory_lock($1)", installationLockID); err != nil {
		conn.Release()
		return nil, fmt.Errorf("the installation lock: %w", err)
	}
	return func() {
		_, _ = conn.Exec(context.WithoutCancel(ctx), "select pg_advisory_unlock($1)", installationLockID)
		conn.Release()
	}, nil
}

// Load implements Storage.
func (p *Postgres) Load(ctx context.Context) (*Record, error) {
	var record Record
	err := p.pool.QueryRow(ctx, `
		select installation_id, secrets_key_provider, active_secrets_key_id,
		       active_agent_ca_id, active_agent_ca_fingerprint,
		       sentinel_key_id, sentinel_wrapped_dek, sentinel_nonce, sentinel_ciphertext,
		       initialized_at, updated_at, revision
		  from crypto_installation_state where singleton`).Scan(
		&record.InstallationID, &record.Provider, &record.ActiveKeyID,
		&record.IssuerID, &record.IssuerFingerprint,
		&record.Sentinel.KeyID, &record.Sentinel.WrappedDEK, &record.Sentinel.Nonce, &record.Sentinel.Ciphertext,
		&record.InitializedAt, &record.UpdatedAt, &record.Revision)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, ErrNoRecord
	}
	if err != nil {
		return nil, err
	}
	record.Sentinel.Version = secrets.EnvelopeVersion
	return &record, nil
}

// Insert implements Storage. The primary key refuses a second row, so
// two panels racing past the lock could still not make two installations.
func (p *Postgres) Insert(ctx context.Context, record Record) error {
	_, err := p.pool.Exec(ctx, `
		insert into crypto_installation_state
			(installation_id, secrets_key_provider, active_secrets_key_id,
			 active_agent_ca_id, active_agent_ca_fingerprint,
			 sentinel_key_id, sentinel_wrapped_dek, sentinel_nonce, sentinel_ciphertext)
		values ($1, $2, $3, $4, $5, $6, $7, $8, $9)`,
		record.InstallationID, record.Provider, record.ActiveKeyID,
		record.IssuerID, record.IssuerFingerprint,
		record.Sentinel.KeyID, record.Sentinel.WrappedDEK, record.Sentinel.Nonce, record.Sentinel.Ciphertext)
	return err
}

// Update implements Storage.
func (p *Postgres) Update(ctx context.Context, record Record) error {
	tag, err := p.pool.Exec(ctx, `
		update crypto_installation_state
		   set active_secrets_key_id = $1, active_agent_ca_id = $2, active_agent_ca_fingerprint = $3,
		       sentinel_key_id = $4, sentinel_wrapped_dek = $5, sentinel_nonce = $6, sentinel_ciphertext = $7,
		       updated_at = now(), revision = revision + 1
		 where singleton and installation_id = $8`,
		record.ActiveKeyID, record.IssuerID, record.IssuerFingerprint,
		record.Sentinel.KeyID, record.Sentinel.WrappedDEK, record.Sentinel.Nonce, record.Sentinel.Ciphertext,
		record.InstallationID)
	if err != nil {
		return err
	}
	if tag.RowsAffected() == 0 {
		return fmt.Errorf("the installation record of %s is gone", record.InstallationID)
	}
	return nil
}

// ErrRevisionMoved means the record changed under the caller: another instance
// rotated the key or the authority since this one read it.
var ErrRevisionMoved = errors.New("the installation record moved to another revision")

// UpdateIfRevision implements Storage.
func (p *Postgres) UpdateIfRevision(ctx context.Context, record Record, expected int64) error {
	tag, err := p.pool.Exec(ctx, `
		update crypto_installation_state
		   set active_secrets_key_id = $1, active_agent_ca_id = $2, active_agent_ca_fingerprint = $3,
		       sentinel_key_id = $4, sentinel_wrapped_dek = $5, sentinel_nonce = $6, sentinel_ciphertext = $7,
		       updated_at = now(), revision = revision + 1
		 where singleton and installation_id = $8 and revision = $9`,
		record.ActiveKeyID, record.IssuerID, record.IssuerFingerprint,
		record.Sentinel.KeyID, record.Sentinel.WrappedDEK, record.Sentinel.Nonce, record.Sentinel.Ciphertext,
		record.InstallationID, expected)
	if err != nil {
		return err
	}
	if tag.RowsAffected() == 0 {
		return fmt.Errorf("%w: this instance read revision %d", ErrRevisionMoved, expected)
	}
	return nil
}

// Facts implements Storage.
func (p *Postgres) Facts(ctx context.Context) (Facts, error) {
	var facts Facts
	err := p.pool.QueryRow(ctx, `
		select (select count(*) from secret_versions where destroyed_at is null),
		       (select count(*) from hosts),
		       (select count(*) from agent_certificates)`).
		Scan(&facts.SecretVersions, &facts.Hosts, &facts.Certificates)
	return facts, err
}

// AssignIssuer implements Storage.
func (p *Postgres) AssignIssuer(ctx context.Context, subject, serial, issuerID string) (int64, error) {
	tag, err := p.pool.Exec(ctx, `
		update agent_certificates set issuer_id = $3
		 where issuer_id is null and issuer_subject = $1 and issuer_serial = $2`,
		subject, serial, issuerID)
	if err != nil {
		return 0, err
	}
	return tag.RowsAffected(), nil
}

// The keys of the installation as rows of the database. The methods sit on the
// same Postgres as the record because they share a pool and a transaction
// boundary, but they answer a separate interface: a panel that keeps its keys
// in files has a record all the same.

// WrappedKeys implements KeyStore.
func (p *Postgres) WrappedKeys(ctx context.Context, purpose string) ([]WrappedKey, error) {
	rows, err := p.pool.Query(ctx, `
		select key_id, purpose, kek_id, installation_id, envelope_version, nonce, ciphertext, created_at, retired_at
		  from crypto_wrapped_keys where purpose = $1 order by key_id`, purpose)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var keys []WrappedKey
	for rows.Next() {
		var key WrappedKey
		var installation *string
		if err := rows.Scan(&key.KeyID, &key.Purpose, &key.KEKID, &installation, &key.EnvelopeVersion,
			&key.Nonce, &key.Ciphertext, &key.CreatedAt, &key.RetiredAt); err != nil {
			return nil, err
		}
		key.InstallationID = installationOf(installation)
		keys = append(keys, key)
	}
	return keys, rows.Err()
}

// WrappedKey implements KeyStore.
func (p *Postgres) WrappedKey(ctx context.Context, keyID string) (WrappedKey, error) {
	var key WrappedKey
	var installation *string
	err := p.pool.QueryRow(ctx, `
		select key_id, purpose, kek_id, installation_id, envelope_version, nonce, ciphertext, created_at, retired_at
		  from crypto_wrapped_keys where key_id = $1`, keyID).
		Scan(&key.KeyID, &key.Purpose, &key.KEKID, &installation, &key.EnvelopeVersion,
			&key.Nonce, &key.Ciphertext, &key.CreatedAt, &key.RetiredAt)
	if errors.Is(err, pgx.ErrNoRows) {
		return WrappedKey{}, fmt.Errorf("%w: %s", ErrWrappedKeyMissing, keyID)
	}
	key.InstallationID = installationOf(installation)
	return key, err
}

// installationOf reads the column of a row that may not have one. A row of the
// first form names no installation, and that absence is not the empty string
// somebody wrote into it.
func installationOf(value *string) string {
	if value == nil {
		return ""
	}
	return *value
}

// installationColumn writes the other way: a row that names no installation
// leaves the column null rather than storing an empty name.
func installationColumn(value string) *string {
	if value == "" {
		return nil
	}
	return &value
}

// PutWrappedKey is the plain insert. The primary key does the refusing: two
// replicas of one installation initialising at once both insert, and exactly
// one of them wins.
//
// It checks nothing about the record, so it is not what a replica writes with:
// a replica seals with the key it loaded at start and goes through
// PutWrappedKeyUnderRecordedKEK.
func (p *Postgres) PutWrappedKey(ctx context.Context, key WrappedKey) error {
	_, err := p.pool.Exec(ctx, `
		insert into crypto_wrapped_keys
			(key_id, purpose, kek_id, installation_id, envelope_version, nonce, ciphertext)
		values ($1, $2, $3, $4, $5, $6, $7)`,
		key.KeyID, key.Purpose, key.KEKID, installationColumn(key.InstallationID),
		key.EnvelopeVersion, key.Nonce, key.Ciphertext)
	var unique *pgconn.PgError
	if errors.As(err, &unique) && unique.Code == "23505" {
		return fmt.Errorf("%w: %s", ErrKeyExists, key.KeyID)
	}
	return err
}

// PutWrappedKeyUnderRecordedKEK implements KeyStore: the write a replica makes
// with the key encryption key it loaded at start.
//
// The record is read for share and the row inserted in the same transaction,
// so a rewrap running at the same time is serialised against this write rather
// than racing it. Either the rewrap waits, and the row it then finds still
// wrapped with the old key stops it; or it goes first, and the record it
// leaves behind names another key, which is what this refuses on.
func (p *Postgres) PutWrappedKeyUnderRecordedKEK(ctx context.Context, key WrappedKey) error {
	return p.inTransaction(ctx, func(tx pgx.Tx) error {
		if err := recordStillNames(ctx, tx, key); err != nil {
			return err
		}
		_, err := tx.Exec(ctx, `
			insert into crypto_wrapped_keys
				(key_id, purpose, kek_id, installation_id, envelope_version, nonce, ciphertext)
			values ($1, $2, $3, $4, $5, $6, $7)`,
			key.KeyID, key.Purpose, key.KEKID, installationColumn(key.InstallationID),
			key.EnvelopeVersion, key.Nonce, key.Ciphertext)
		var unique *pgconn.PgError
		if errors.As(err, &unique) && unique.Code == "23505" {
			return fmt.Errorf("%w: %s", ErrKeyExists, key.KeyID)
		}
		return err
	})
}

// recordStillNames holds the installation record still for the rest of the
// transaction and says whether it is the one this row was sealed for.
//
// The share lock is the whole of it: a rewrap changes the record before it
// touches a single row, so a writer holding this lock cannot be overtaken by
// one. Both take the record first, so neither waits on the other's rows.
func recordStillNames(ctx context.Context, tx pgx.Tx, key WrappedKey) error {
	var recorded *string
	var installation string
	err := tx.QueryRow(ctx, `
		select kek_id, installation_id::text from crypto_installation_state
		 where singleton for share`).Scan(&recorded, &installation)
	if errors.Is(err, pgx.ErrNoRows) {
		return fatal(CodeKEKRotated, fmt.Sprintf(
			"the key %s was sealed with %s and this database has no installation record",
			key.KeyID, key.KEKID), nil)
	}
	if err != nil {
		return fmt.Errorf("the installation record: %w", err)
	}
	if installation != key.InstallationID {
		return fatal(CodeWrappedKeyInstallationMismatch, fmt.Sprintf(
			"the key %s was sealed for the installation %s and this database describes %s",
			key.KeyID, wrappedKeyOwner(key.InstallationID), installation), nil)
	}
	if installationOf(recorded) != key.KEKID {
		return fatal(CodeKEKRotated, fmt.Sprintf(
			"the key %s was sealed with %s and the installation is now wrapped with %s; "+
				"the row would open for nobody",
			key.KeyID, key.KEKID, recordedKEK(recorded)), nil)
	}
	return nil
}

// recordedKEK names what the record says, for an operator reading the refusal.
// A record that names none is an installation whose keys went back to files.
func recordedKEK(recorded *string) string {
	if name := installationOf(recorded); name != "" {
		return name
	}
	return "no key encryption key at all"
}

// RetireWrappedKey implements KeyStore. A key already retired keeps the moment
// it was retired at: the second call is the same statement of fact as the
// first.
func (p *Postgres) RetireWrappedKey(ctx context.Context, keyID string) error {
	tag, err := p.pool.Exec(ctx, `
		update crypto_wrapped_keys set retired_at = coalesce(retired_at, now())
		 where key_id = $1`, keyID)
	if err != nil {
		return err
	}
	if tag.RowsAffected() == 0 {
		return fmt.Errorf("%w: %s", ErrWrappedKeyMissing, keyID)
	}
	return nil
}

// DeleteWrappedKey implements KeyStore.
func (p *Postgres) DeleteWrappedKey(ctx context.Context, keyID string) error {
	tag, err := p.pool.Exec(ctx, `delete from crypto_wrapped_keys where key_id = $1`, keyID)
	if err != nil {
		return err
	}
	if tag.RowsAffected() == 0 {
		return fmt.Errorf("%w: %s", ErrWrappedKeyMissing, keyID)
	}
	return nil
}

// KEKID says which key encryption key this installation's rows are wrapped
// with. An empty answer is an installation that still keeps its keys in the
// state directory.
func (p *Postgres) KEKID(ctx context.Context) (string, error) {
	var id *string
	err := p.pool.QueryRow(ctx, `select kek_id from crypto_installation_state where singleton`).Scan(&id)
	if errors.Is(err, pgx.ErrNoRows) {
		return "", ErrNoRecord
	}
	if err != nil || id == nil {
		return "", err
	}
	return *id, nil
}

// SetKEKID records the key encryption key the rows were wrapped with. It is
// written once, by the migration of the keys into the database; a second,
// different key arrives through a rewrap, which changes every row and this
// column in one transaction.
func (p *Postgres) SetKEKID(ctx context.Context, id string) error {
	tag, err := p.pool.Exec(ctx, `
		update crypto_installation_state set kek_id = $1, updated_at = now()
		 where singleton`, id)
	if err != nil {
		return err
	}
	if tag.RowsAffected() == 0 {
		return ErrNoRecord
	}
	return nil
}

// ImportKeys implements ImportStore: every key and the name of the key
// encryption key in one transaction. Half a migration is worse than none - an
// installation whose secret store reads from the database while its authority
// still reads from one replica's disk is shared in a way that hides what it
// still depends on.
func (p *Postgres) ImportKeys(ctx context.Context, kekID string, keys []WrappedKey, retired []RetiredAuthority) error {
	return p.inTransaction(ctx, func(tx pgx.Tx) error {
		var recorded *string
		// The row is taken for update first, so that a second panel doing the same
		// thing waits here rather than half way through.
		if err := tx.QueryRow(ctx,
			`select kek_id from crypto_installation_state where singleton for update`).Scan(&recorded); err != nil {
			if errors.Is(err, pgx.ErrNoRows) {
				return ErrNoRecord
			}
			return err
		}
		if recorded != nil && *recorded != "" {
			return fmt.Errorf("the installation is already wrapped with %s", *recorded)
		}
		var existing int
		if err := tx.QueryRow(ctx, `select count(*) from crypto_wrapped_keys`).Scan(&existing); err != nil {
			return err
		}
		if existing > 0 {
			return fmt.Errorf("the database already holds %d wrapped keys while the record names none", existing)
		}
		if err := insertKeys(ctx, tx, keys); err != nil {
			return err
		}
		// The withdrawn certificates travel in the same transaction. They carry no
		// key, but an installation that loses them stops recognising every host
		// that has not renewed since the rotation.
		for _, authority := range retired {
			if _, err := tx.Exec(ctx, `
				insert into crypto_retired_authorities (serial, certificate) values ($1, $2)
				on conflict (serial) do nothing`, authority.Serial, string(authority.Certificate)); err != nil {
				return fmt.Errorf("the withdrawn authority %s: %w", authority.Serial, err)
			}
		}
		// Moving the keys is switching the provider: the record has to say so in
		// the same transaction, or the next start would find an installation
		// sealed by one provider and a panel running another.
		_, err := tx.Exec(ctx, `
			update crypto_installation_state
			   set kek_id = $1, secrets_key_provider = $2, updated_at = now(), revision = revision + 1
			 where singleton`, kekID, DBProviderName)
		return err
	})
}

// ReplaceKeys implements ImportStore: the rewrap. Every row and the record
// move together, so that no moment exists in which the database names one key
// encryption key and holds rows wrapped with another.
func (p *Postgres) ReplaceKeys(ctx context.Context, fromKEKID, toKEKID string, read, keys []WrappedKey) error {
	return p.inTransaction(ctx, func(tx pgx.Tx) error {
		tag, err := tx.Exec(ctx, `
			update crypto_installation_state set kek_id = $2, updated_at = now()
			 where singleton and kek_id = $1`, fromKEKID, toKEKID)
		if err != nil {
			return err
		}
		if tag.RowsAffected() == 0 {
			return fmt.Errorf("the installation is no longer wrapped with %s", fromKEKID)
		}
		// The rows are taken for update and held against what the rewrap
		// opened. A row it never read, and a row whose bytes changed under it -
		// an authority another replica activated carries the same name and
		// other content - must not be written over with what this rewrap
		// re-sealed, because that would put the state the installation had
		// before back as the state it has now.
		current, err := wrappedKeysOf(ctx, tx, fromKEKID)
		if err != nil {
			return err
		}
		if err := rowsStillThese(current, read); err != nil {
			return err
		}
		// Only the rows this rewrap read, by name. A key made by another replica
		// between the read and here is wrapped with the old key encryption key
		// too, and deleting it by that alone would take away a key the record
		// may already name as the active one - and one this rewrap never
		// re-wrapped, so it would be in no backup either.
		names := make([]string, 0, len(read))
		for _, key := range read {
			names = append(names, key.KeyID)
		}
		if _, err := tx.Exec(ctx,
			`delete from crypto_wrapped_keys where kek_id = $1 and key_id = any($2)`,
			fromKEKID, names); err != nil {
			return err
		}
		var strangers int
		if err := tx.QueryRow(ctx,
			`select count(*) from crypto_wrapped_keys where kek_id <> $1`, toKEKID).Scan(&strangers); err != nil {
			return err
		}
		if strangers > 0 {
			return fmt.Errorf("%d keys are wrapped with neither %s nor %s; the rewrap would leave them unreadable",
				strangers, fromKEKID, toKEKID)
		}
		return insertKeys(ctx, tx, keys)
	})
}

// ForgetKeys implements ImportStore: the last step of a revert, once the files
// are back where the panel reads them from.
func (p *Postgres) ForgetKeys(ctx context.Context, kekID string, keyIDs []string) error {
	return p.inTransaction(ctx, func(tx pgx.Tx) error {
		tag, err := tx.Exec(ctx, `
			update crypto_installation_state
			   set kek_id = null, secrets_key_provider = $2, updated_at = now(), revision = revision + 1
			 where singleton and kek_id = $1`, kekID, LocalProviderName)
		if err != nil {
			return err
		}
		if tag.RowsAffected() == 0 {
			return fmt.Errorf("the installation is not wrapped with %s", kekID)
		}
		// The keys the revert wrote to the files, by name, and nothing else: a key
		// made while the revert ran is in no file, so dropping it here would lose
		// it entirely.
		if _, err := tx.Exec(ctx,
			`delete from crypto_wrapped_keys where kek_id = $1 and key_id = any($2)`,
			kekID, keyIDs); err != nil {
			return err
		}
		var left int
		if err := tx.QueryRow(ctx,
			`select count(*) from crypto_wrapped_keys where kek_id = $1`, kekID).Scan(&left); err != nil {
			return err
		}
		if left > 0 {
			return fmt.Errorf("%w: %d keys appeared while the revert ran and are in no file",
				ErrRevisionMoved, left)
		}
		// The withdrawn certificates go with them: the files are back by now, and
		// leaving the rows would make a later import refuse a set it already has.
		_, err = tx.Exec(ctx, `delete from crypto_retired_authorities`)
		return err
	})
}

// wrappedKeysOf reads every row wrapped with one key encryption key and holds
// them for the rest of the transaction, so a second writer waits here.
func wrappedKeysOf(ctx context.Context, tx pgx.Tx, kekID string) ([]WrappedKey, error) {
	rows, err := tx.Query(ctx, `
		select key_id, purpose, kek_id, installation_id, envelope_version, nonce, ciphertext, created_at, retired_at
		  from crypto_wrapped_keys where kek_id = $1 order by key_id for update`, kekID)
	if err != nil {
		return nil, fmt.Errorf("the keys wrapped with %s: %w", kekID, err)
	}
	defer rows.Close()
	var keys []WrappedKey
	for rows.Next() {
		var key WrappedKey
		var installation *string
		if err := rows.Scan(&key.KeyID, &key.Purpose, &key.KEKID, &installation, &key.EnvelopeVersion,
			&key.Nonce, &key.Ciphertext, &key.CreatedAt, &key.RetiredAt); err != nil {
			return nil, err
		}
		key.InstallationID = installationOf(installation)
		keys = append(keys, key)
	}
	return keys, rows.Err()
}

// rowsStillThese refuses when the rows the database holds are not the rows the
// caller read: another name, or the same name holding other bytes. A rewrap
// re-seals what it opened and writes it back under the same names, so anything
// that moved in between would be written over with the state as it was before
// it moved - an authority another replica activated would go back to being the
// prepared one, with both operations reported as having succeeded.
func rowsStillThese(now, read []WrappedKey) error {
	seen := make(map[string]WrappedKey, len(read))
	for _, key := range read {
		seen[key.KeyID] = key
	}
	for _, key := range now {
		was, ok := seen[key.KeyID]
		if !ok {
			return fmt.Errorf("%w: the key %s appeared while this ran", ErrRevisionMoved, key.KeyID)
		}
		if !sameWrappedKey(was, key) {
			return fmt.Errorf("%w: the key %s changed while this ran", ErrRevisionMoved, key.KeyID)
		}
		delete(seen, key.KeyID)
	}
	for keyID := range seen {
		return fmt.Errorf("%w: the key %s went away while this ran", ErrRevisionMoved, keyID)
	}
	return nil
}

// sameWrappedKey says whether two rows hold the same wrapped key: everything
// the row is sealed from or about, which is every column but the moment it was
// created.
func sameWrappedKey(a, b WrappedKey) bool {
	return a.KeyID == b.KeyID && a.Purpose == b.Purpose && a.KEKID == b.KEKID &&
		a.InstallationID == b.InstallationID && a.EnvelopeVersion == b.EnvelopeVersion &&
		bytes.Equal(a.Nonce, b.Nonce) && bytes.Equal(a.Ciphertext, b.Ciphertext) &&
		sameMoment(a.RetiredAt, b.RetiredAt)
}

// sameMoment compares two moments that may be absent; an absent one is not a
// moment equal to any other.
func sameMoment(a, b *time.Time) bool {
	if a == nil || b == nil {
		return a == nil && b == nil
	}
	return a.Equal(*b)
}

// insertKeys writes the rows of a migration. The retirement of a key is kept:
// a rewrap must not bring a retired key back into use.
func insertKeys(ctx context.Context, tx pgx.Tx, keys []WrappedKey) error {
	for _, key := range keys {
		if _, err := tx.Exec(ctx, `
			insert into crypto_wrapped_keys
				(key_id, purpose, kek_id, installation_id, envelope_version, nonce, ciphertext, retired_at)
			values ($1, $2, $3, $4, $5, $6, $7, $8)`,
			key.KeyID, key.Purpose, key.KEKID, installationColumn(key.InstallationID), key.EnvelopeVersion,
			key.Nonce, key.Ciphertext, key.RetiredAt); err != nil {
			return fmt.Errorf("the key %s: %w", key.KeyID, err)
		}
	}
	return nil
}

func (p *Postgres) inTransaction(ctx context.Context, do func(pgx.Tx) error) error {
	tx, err := p.pool.Begin(ctx)
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback(context.WithoutCancel(ctx)) }()
	if err := do(tx); err != nil {
		return err
	}
	return tx.Commit(ctx)
}

// The authorities of the installation as rows: the wrapped ones the fleet
// signs with, and the certificates of those it has withdrawn from signing.

// ReplaceAuthority implements AuthorityKeyStore. The removal and the insert
// share a transaction, so that no replica ever reads a moment in which the
// installation has two authorities that sign, or none.
func (p *Postgres) ReplaceAuthority(ctx context.Context, row WrappedKey, remove, seen []string) error {
	return p.inTransaction(ctx, func(tx pgx.Tx) error {
		// An authority is sealed with the key this replica loaded at start,
		// like every other row, so it is written under the same guard.
		if err := recordStillNames(ctx, tx, row); err != nil {
			return err
		}
		// And the write carries the condition the decision used: which
		// authorities were there when the caller read them. Without it another
		// replica could activate an authority between that read and this
		// write, and this write would delete it and put its own in - the
		// installation signing with an authority nobody activated, and the
		// trail saying both succeeded.
		if err := authoritiesStillThese(ctx, tx, seen); err != nil {
			return err
		}
		if err := deleteAuthorities(ctx, tx, remove); err != nil {
			return err
		}
		_, err := tx.Exec(ctx, `
			insert into crypto_wrapped_keys
				(key_id, purpose, kek_id, installation_id, envelope_version, nonce, ciphertext, retired_at)
			values ($1, $2, $3, $4, $5, $6, $7, $8)`,
			row.KeyID, row.Purpose, row.KEKID, installationColumn(row.InstallationID), row.EnvelopeVersion,
			row.Nonce, row.Ciphertext, row.RetiredAt)
		if err != nil {
			return fmt.Errorf("the authority %s: %w", row.KeyID, err)
		}
		return nil
	})
}

// DeleteAuthorities implements AuthorityKeyStore. seen carries the condition
// the decision rested on, like the write does: dropping a prepared authority
// another replica has meanwhile activated would leave the installation with
// nothing that signs.
func (p *Postgres) DeleteAuthorities(ctx context.Context, keyIDs, seen []string) error {
	return p.inTransaction(ctx, func(tx pgx.Tx) error {
		if err := authoritiesStillThese(ctx, tx, seen); err != nil {
			return err
		}
		return deleteAuthorities(ctx, tx, keyIDs)
	})
}

// authoritiesStillThese refuses when the authorities of the installation are
// not the ones the caller read. The rows are locked, so a second writer waits
// here rather than racing past.
func authoritiesStillThese(ctx context.Context, tx pgx.Tx, seen []string) error {
	rows, err := tx.Query(ctx,
		`select key_id from crypto_wrapped_keys where purpose = $1 order by key_id for update`,
		PurposeAgentCA)
	if err != nil {
		return fmt.Errorf("the authorities of the installation: %w", err)
	}
	var now []string
	for rows.Next() {
		var keyID string
		if err := rows.Scan(&keyID); err != nil {
			rows.Close()
			return err
		}
		now = append(now, keyID)
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return err
	}
	want := append([]string(nil), seen...)
	sort.Strings(want)
	if !slices.Equal(now, want) {
		return fmt.Errorf("%w: this instance read the authorities %s and the installation now holds %s",
			ErrRevisionMoved, orNone(want), orNone(now))
	}
	return nil
}

// orNone names a set for a refusal somebody has to read.
func orNone(ids []string) string {
	if len(ids) == 0 {
		return "none"
	}
	return strings.Join(ids, ", ")
}

// deleteAuthorities removes rows by name, and only rows that are authorities:
// a name that turned out to belong to a key of the secret store would take the
// secrets of the installation with it.
func deleteAuthorities(ctx context.Context, tx pgx.Tx, keyIDs []string) error {
	if len(keyIDs) == 0 {
		return nil
	}
	_, err := tx.Exec(ctx,
		`delete from crypto_wrapped_keys where key_id = any($1) and purpose = $2`,
		keyIDs, PurposeAgentCA)
	return err
}

// RetiredAuthorities implements AuthorityKeyStore.
func (p *Postgres) RetiredAuthorities(ctx context.Context) ([][]byte, error) {
	rows, err := p.pool.Query(ctx,
		`select certificate from crypto_retired_authorities order by serial`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var certificates [][]byte
	for rows.Next() {
		var certPEM string
		if err := rows.Scan(&certPEM); err != nil {
			return nil, err
		}
		certificates = append(certificates, []byte(certPEM))
	}
	return certificates, rows.Err()
}

// PutRetiredAuthority implements AuthorityKeyStore. A serial already there
// keeps the moment it was withdrawn at: writing the same certificate twice is
// the same statement of fact.
func (p *Postgres) PutRetiredAuthority(ctx context.Context, serial string, certPEM []byte) error {
	_, err := p.pool.Exec(ctx, `
		insert into crypto_retired_authorities (serial, certificate) values ($1, $2)
		on conflict (serial) do update set certificate = excluded.certificate`,
		serial, string(certPEM))
	return err
}

// DeleteRetiredAuthority implements AuthorityKeyStore.
func (p *Postgres) DeleteRetiredAuthority(ctx context.Context, serial string) error {
	_, err := p.pool.Exec(ctx, `delete from crypto_retired_authorities where serial = $1`, serial)
	return err
}
