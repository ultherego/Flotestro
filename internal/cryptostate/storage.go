package cryptostate

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"
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
