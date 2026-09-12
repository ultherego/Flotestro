package secrets

import (
	"context"
	"errors"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

// Store holds the secrets and the leases.
type Store struct {
	pool   *pgxpool.Pool
	cipher *Cipher
}

func NewStore(pool *pgxpool.Pool, cipher *Cipher) *Store {
	return &Store{pool: pool, cipher: cipher}
}

// Pool exposes the pool for transactions combined with other writes.
func (s *Store) Pool() *pgxpool.Pool { return s.pool }

// Create creates a secret together with its first version.
func (s *Store) Create(ctx context.Context, name, description string, value []byte, author string) (*Secret, error) {
	if err := ValidateName(name); err != nil {
		return nil, err
	}
	if err := ValidateValue(value); err != nil {
		return nil, err
	}

	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return nil, err
	}
	defer func() { _ = tx.Rollback(ctx) }()

	var id string
	if err := tx.QueryRow(ctx, `
		insert into secrets (name, description, created_by) values ($1, $2, $3)
		returning id`, name, nullable(description), author).Scan(&id); err != nil {
		return nil, err
	}
	if err := s.saveVersion(ctx, tx, id, 1, value, author); err != nil {
		return nil, err
	}
	if err := tx.Commit(ctx); err != nil {
		return nil, err
	}
	return s.Secret(ctx, name)
}

// Rotate adds a new version and makes it the current one.
//
// The previous versions stay: a host that got a lease on version 3 is to get
// it also when version 4 has come into being in the meantime.
func (s *Store) Rotate(ctx context.Context, name string, value []byte, author string) (*Secret, error) {
	if err := ValidateValue(value); err != nil {
		return nil, err
	}
	secret, err := s.Secret(ctx, name)
	if err != nil {
		return nil, err
	}
	if secret.RetiredAt != nil {
		return nil, ErrRetired
	}

	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return nil, err
	}
	defer func() { _ = tx.Rollback(ctx) }()

	if err := s.saveVersion(ctx, tx, secret.ID, secret.CurrentVersion+1, value, author); err != nil {
		return nil, err
	}
	if err := tx.Commit(ctx); err != nil {
		return nil, err
	}
	return s.Secret(ctx, name)
}

// saveVersion records the encrypted value and moves the current version.
func (s *Store) saveVersion(ctx context.Context, tx pgx.Tx, secretID string,
	version int, value []byte, author string) error {
	nonce, ciphertext, err := s.cipher.Encrypt(value)
	if err != nil {
		return err
	}
	if _, err := tx.Exec(ctx, `
		insert into secret_versions (secret_id, version, nonce, ciphertext, size_bytes, created_by)
		values ($1, $2, $3, $4, $5, $6)`,
		secretID, version, nonce, ciphertext, len(value), author); err != nil {
		return err
	}
	_, err = tx.Exec(ctx, `
		update secrets set current_version = $2, updated_at = now() where id = $1`, secretID, version)
	return err
}

// Secret returns the metadata of a secret together with its version history -
// without the content.
func (s *Store) Secret(ctx context.Context, name string) (*Secret, error) {
	secrets, err := s.query(ctx, "where name = $1", name)
	if err != nil {
		return nil, err
	}
	if len(secrets) == 0 {
		return nil, ErrNotFound
	}
	versions, err := s.versions(ctx, secrets[0].ID)
	if err != nil {
		return nil, err
	}
	secrets[0].Versions = versions
	return &secrets[0], nil
}

// List returns every secret.
func (s *Store) List(ctx context.Context) ([]Secret, error) {
	return s.query(ctx, "order by name")
}

func (s *Store) query(ctx context.Context, clause string, args ...any) ([]Secret, error) {
	rows, err := s.pool.Query(ctx, `
		select id, name, coalesce(description, ''), current_version,
		       created_by, created_at, updated_at, retired_at
		  from secrets `+clause, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var secrets []Secret
	for rows.Next() {
		var secret Secret
		if err := rows.Scan(&secret.ID, &secret.Name, &secret.Description, &secret.CurrentVersion,
			&secret.CreatedBy, &secret.CreatedAt, &secret.UpdatedAt, &secret.RetiredAt); err != nil {
			return nil, err
		}
		secrets = append(secrets, secret)
	}
	return secrets, rows.Err()
}

func (s *Store) versions(ctx context.Context, secretID string) ([]Version, error) {
	rows, err := s.pool.Query(ctx, `
		select version, size_bytes, created_by, created_at, destroyed_at
		  from secret_versions where secret_id = $1 order by version desc`, secretID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var versions []Version
	for rows.Next() {
		var version Version
		if err := rows.Scan(&version.Version, &version.SizeBytes, &version.CreatedBy,
			&version.CreatedAt, &version.Destroyed); err != nil {
			return nil, err
		}
		versions = append(versions, version)
	}
	return versions, rows.Err()
}

// Retire closes a secret: the metadata stays, the issuing ends.
func (s *Store) Retire(ctx context.Context, name string) error {
	tag, err := s.pool.Exec(ctx, `
		update secrets set retired_at = now(), updated_at = now()
		 where name = $1 and retired_at is null`, name)
	if err != nil {
		return err
	}
	if tag.RowsAffected() == 0 {
		return ErrNotFound
	}
	// The leases issued earlier lose their validity together with the secret.
	_, err = s.pool.Exec(ctx, `
		update secret_leases set revoked_at = now()
		 where secret_id = (select id from secrets where name = $1)
		   and redeemed_at is null and revoked_at is null`, name)
	return err
}

// Destroy deletes the content of one version, leaving a trace that it
// existed.
func (s *Store) Destroy(ctx context.Context, name string, version int) error {
	tag, err := s.pool.Exec(ctx, `
		update secret_versions
		   set ciphertext = '\x'::bytea, nonce = '\x'::bytea, destroyed_at = now()
		 where secret_id = (select id from secrets where name = $1)
		   and version = $2 and destroyed_at is null`, name, version)
	if err != nil {
		return err
	}
	if tag.RowsAffected() == 0 {
		return ErrNotFound
	}
	return nil
}

// Issue creates a lease for the duration of one task.
//
// We fix the version at the moment of issuing: a task ordered against the
// current version is to get the version that was current when it was
// delivered - not the one that comes into being while it runs.
func (s *Store) Issue(ctx context.Context, name string, version int,
	jobID, hostID string, window time.Duration) (*Lease, error) {
	if err := ValidateName(name); err != nil {
		return nil, err
	}
	secret, err := s.Secret(ctx, name)
	if err != nil {
		return nil, err
	}
	if secret.RetiredAt != nil {
		return nil, ErrRetired
	}
	if version == 0 {
		version = secret.CurrentVersion
	}
	if version <= 0 {
		return nil, ErrNotFound
	}
	if window <= 0 {
		window = LeaseWindow
	}

	lease := &Lease{
		SecretID: secret.ID, SecretName: secret.Name, Version: version,
		JobID: jobID, HostID: hostID,
	}
	err = s.pool.QueryRow(ctx, `
		insert into secret_leases (secret_id, version, job_id, host_id, expires_at)
		values ($1, $2, $3, $4, now() + $5::interval)
		returning id, issued_at, expires_at`,
		secret.ID, version, jobID, hostID, window.String()).
		Scan(&lease.ID, &lease.IssuedAt, &lease.ExpiresAt)
	if err != nil {
		return nil, err
	}
	return lease, nil
}

// Redeem returns the value of the secret and uses up the lease.
//
// A lease is single-use: the same task may fetch the secret once. A second
// attempt is a refusal rather than a second copy - a repeated fetch means
// either a retry of the operation, which gets its own lease, or somebody
// using a lease that is not theirs.
func (s *Store) Redeem(ctx context.Context, jobID, hostID, name string, version int) ([]byte, int, error) {
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return nil, 0, err
	}
	defer func() { _ = tx.Rollback(ctx) }()

	var leaseID, secretID string
	var issuedVersion int
	versionCondition := ""
	args := []any{jobID, hostID, name}
	if version > 0 {
		versionCondition = " and l.version = $4"
		args = append(args, version)
	}
	err = tx.QueryRow(ctx, `
		select l.id, l.secret_id, l.version
		  from secret_leases l
		  join secrets s on s.id = l.secret_id
		 where l.job_id = $1 and l.host_id = $2 and s.name = $3
		   and l.redeemed_at is null and l.revoked_at is null
		   and l.expires_at > now() and s.retired_at is null`+versionCondition+`
		 order by l.issued_at desc
		 limit 1
		   for update`, args...).Scan(&leaseID, &secretID, &issuedVersion)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, 0, ErrNoLease
	}
	if err != nil {
		return nil, 0, err
	}

	var nonce, ciphertext []byte
	var destroyed *time.Time
	if err := tx.QueryRow(ctx, `
		select nonce, ciphertext, destroyed_at from secret_versions
		 where secret_id = $1 and version = $2`, secretID, issuedVersion).
		Scan(&nonce, &ciphertext, &destroyed); err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, 0, ErrNotFound
		}
		return nil, 0, err
	}
	if destroyed != nil || len(ciphertext) == 0 {
		return nil, 0, ErrDestroyed
	}

	value, err := s.cipher.Decrypt(nonce, ciphertext)
	if err != nil {
		return nil, 0, err
	}
	if _, err := tx.Exec(ctx, `
		update secret_leases set redeemed_at = now() where id = $1`, leaseID); err != nil {
		return nil, 0, err
	}
	if err := tx.Commit(ctx); err != nil {
		return nil, 0, err
	}
	return value, issuedVersion, nil
}

// Revoke closes the unused leases of a task.
//
// A task that has finished or was cancelled has no reason to keep an open
// right to a secret.
func (s *Store) Revoke(ctx context.Context, jobID string) error {
	_, err := s.pool.Exec(ctx, `
		update secret_leases set revoked_at = now()
		 where job_id = $1 and redeemed_at is null and revoked_at is null`, jobID)
	return err
}

// Leases returns the leases of a task - to be shown in the operation's audit
// trail.
func (s *Store) Leases(ctx context.Context, jobID string) ([]Lease, error) {
	rows, err := s.pool.Query(ctx, `
		select l.id, l.secret_id, s.name, l.version, l.job_id, l.host_id,
		       l.issued_at, l.expires_at, l.redeemed_at, l.revoked_at
		  from secret_leases l join secrets s on s.id = l.secret_id
		 where l.job_id = $1 order by l.issued_at`, jobID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var leases []Lease
	for rows.Next() {
		var lease Lease
		if err := rows.Scan(&lease.ID, &lease.SecretID, &lease.SecretName,
			&lease.Version, &lease.JobID, &lease.HostID,
			&lease.IssuedAt, &lease.ExpiresAt,
			&lease.RedeemedAt, &lease.RevokedAt); err != nil {
			return nil, err
		}
		leases = append(leases, lease)
	}
	return leases, rows.Err()
}

func nullable(value string) any {
	if value == "" {
		return nil
	}
	return value
}
