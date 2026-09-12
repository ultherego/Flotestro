// Package certificates keeps the scope of the observation of certificates and
// the history of their deployments.
//
// The panel keeps what the host will not say by itself: which file is the
// certificate of a service, which service reads it and at which address the
// effect of a deployment can be seen. Without that the module would have to
// guess - or search the whole disk, which ends with a list of authorities from
// the trust store instead of an answer.
//
// The private key is not here in any form: only the name of the secret
// remains.
package certificates

import (
	"context"
	"errors"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"
)

// ErrNotFound means a missing target or deployment.
var ErrNotFound = errors.New("the panel does not observe this certificate")

// Target describes a file the panel watches over on a host.
type Target struct {
	ID     string `json:"id"`
	HostID string `json:"host_id"`
	Path   string `json:"path"`
	// KeyPath and KeySecret describe the private key: where it is to lie and
	// where it comes from. The panel does not know the value of the key and
	// must not know it.
	KeyPath   string `json:"key_path,omitempty"`
	KeySecret string `json:"key_secret,omitempty"`
	// ReloadUnit is the service that reads this file; ProbeTarget the address
	// at which it can be seen that it has read it.
	ReloadUnit  string    `json:"reload_unit,omitempty"`
	ProbeTarget string    `json:"probe_target,omitempty"`
	Service     string    `json:"service,omitempty"`
	Note        string    `json:"note,omitempty"`
	CreatedBy   string    `json:"created_by"`
	CreatedAt   time.Time `json:"created_at"`
	UpdatedBy   string    `json:"updated_by"`
	UpdatedAt   time.Time `json:"updated_at"`
}

// Deployment describes one deployment of a certificate by the panel.
type Deployment struct {
	HostID            string     `json:"host_id"`
	Path              string     `json:"path"`
	FingerprintSHA256 string     `json:"fingerprint_sha256"`
	Subject           string     `json:"subject,omitempty"`
	Issuer            string     `json:"issuer,omitempty"`
	NotAfter          *time.Time `json:"not_after,omitempty"`
	// Certificate is public content: the certificate together with its chain.
	// The panel keeps it so that it can show exactly what was sent - and so
	// that one can come back to it.
	Certificate string    `json:"certificate,omitempty"`
	KeySecret   string    `json:"key_secret,omitempty"`
	KeyVersion  int       `json:"key_secret_version,omitempty"`
	JobID       string    `json:"job_id,omitempty"`
	DeployedBy  string    `json:"deployed_by"`
	DeployedAt  time.Time `json:"deployed_at"`
}

// executor allows calling the same queries inside a transaction and outside
// one.
type executor interface {
	Exec(ctx context.Context, sql string, args ...any) (pgconn.CommandTag, error)
}

// Store provides access to the certificate tables.
type Store struct {
	pool *pgxpool.Pool
}

func NewStore(pool *pgxpool.Pool) *Store { return &Store{pool: pool} }

// Targets returns the files the panel watches over on a host.
func (s *Store) Targets(ctx context.Context, hostID string) ([]Target, error) {
	const query = `
		select id::text, host_id::text, path, key_path, key_secret, reload_unit,
		       probe_target, service, note, created_by, created_at, updated_by, updated_at
		from certificate_targets where host_id = $1 order by path`
	rows, err := s.pool.Query(ctx, query, hostID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var result []Target
	for rows.Next() {
		var target Target
		if err := rows.Scan(&target.ID, &target.HostID, &target.Path, &target.KeyPath, &target.KeySecret,
			&target.ReloadUnit, &target.ProbeTarget, &target.Service, &target.Note,
			&target.CreatedBy, &target.CreatedAt, &target.UpdatedBy, &target.UpdatedAt); err != nil {
			return nil, err
		}
		result = append(result, target)
	}
	return result, rows.Err()
}

// Target returns one observed file.
func (s *Store) Target(ctx context.Context, hostID, path string) (Target, error) {
	const query = `
		select id::text, host_id::text, path, key_path, key_secret, reload_unit,
		       probe_target, service, note, created_by, created_at, updated_by, updated_at
		from certificate_targets where host_id = $1 and path = $2`
	var target Target
	err := s.pool.QueryRow(ctx, query, hostID, path).Scan(&target.ID, &target.HostID, &target.Path,
		&target.KeyPath, &target.KeySecret, &target.ReloadUnit, &target.ProbeTarget, &target.Service,
		&target.Note, &target.CreatedBy, &target.CreatedAt, &target.UpdatedBy, &target.UpdatedAt)
	if errors.Is(err, pgx.ErrNoRows) {
		return Target{}, ErrNotFound
	}
	return target, err
}

// Set creates or updates an observed file.
func (s *Store) Set(ctx context.Context, target Target) (Target, error) {
	const query = `
		insert into certificate_targets (host_id, path, key_path, key_secret, reload_unit,
		                                 probe_target, service, note, created_by, updated_by)
		values ($1, $2, $3, $4, $5, $6, $7, $8, $9, $9)
		on conflict (host_id, path) do update set
			key_path = excluded.key_path, key_secret = excluded.key_secret,
			reload_unit = excluded.reload_unit, probe_target = excluded.probe_target,
			service = excluded.service, note = excluded.note,
			updated_by = excluded.updated_by, updated_at = now()
		returning id::text, created_at, updated_at`
	err := s.pool.QueryRow(ctx, query, target.HostID, target.Path, target.KeyPath, target.KeySecret,
		target.ReloadUnit, target.ProbeTarget, target.Service, target.Note, target.UpdatedBy).
		Scan(&target.ID, &target.CreatedAt, &target.UpdatedAt)
	target.CreatedBy = target.UpdatedBy
	return target, err
}

// Delete ends the observation of a file. The history of the deployments
// stays: the fact that the panel once put something there is not undone by
// removing the target.
func (s *Store) Delete(ctx context.Context, hostID, path string) error {
	const query = `delete from certificate_targets where host_id = $1 and path = $2`
	tag, err := s.pool.Exec(ctx, query, hostID, path)
	if err != nil {
		return err
	}
	if tag.RowsAffected() == 0 {
		return ErrNotFound
	}
	return nil
}

// SaveDeployment adds an entry to the history of the deployments.
func (s *Store) SaveDeployment(ctx context.Context, q executor, deployment Deployment) error {
	const query = `
		insert into certificate_deployments (host_id, path, fingerprint_sha256, subject,
		                                     issuer, not_after, certificate, key_secret,
		                                     key_secret_version, job_id, deployed_by)
		values ($1, $2, $3, $4, $5, $6, $7, $8, $9, nullif($10, '')::uuid, $11)`
	_, err := q.Exec(ctx, query, deployment.HostID, deployment.Path, deployment.FingerprintSHA256,
		deployment.Subject, deployment.Issuer, deployment.NotAfter, deployment.Certificate,
		deployment.KeySecret, deployment.KeyVersion, deployment.JobID, deployment.DeployedBy)
	return err
}

// Deployments returns the history of the deployments of a file, newest
// first.
func (s *Store) Deployments(ctx context.Context, hostID, path string, limit int) ([]Deployment, error) {
	if limit <= 0 || limit > 100 {
		limit = 20
	}
	const query = `
		select host_id::text, path, fingerprint_sha256, subject, issuer, not_after,
		       certificate, key_secret, key_secret_version,
		       coalesce(job_id::text, ''), deployed_by, deployed_at
		from certificate_deployments
		where host_id = $1 and ($2 = '' or path = $2)
		order by deployed_at desc
		limit $3`
	rows, err := s.pool.Query(ctx, query, hostID, path, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var result []Deployment
	for rows.Next() {
		var deployment Deployment
		if err := rows.Scan(&deployment.HostID, &deployment.Path, &deployment.FingerprintSHA256,
			&deployment.Subject, &deployment.Issuer, &deployment.NotAfter, &deployment.Certificate,
			&deployment.KeySecret, &deployment.KeyVersion, &deployment.JobID,
			&deployment.DeployedBy, &deployment.DeployedAt); err != nil {
			return nil, err
		}
		result = append(result, deployment)
	}
	return result, rows.Err()
}

// Latest returns the newest deployment of every file on a host.
//
// It answers the question "did the panel put there what lies on the host": the
// fingerprint from the deployment compared with the one from the inventory
// tells a deployed certificate from one replaced outside the panel.
func (s *Store) Latest(ctx context.Context, hostID string) (map[string]Deployment, error) {
	const query = `
		select distinct on (path) path, fingerprint_sha256, subject, issuer, not_after,
		       key_secret, key_secret_version, coalesce(job_id::text, ''),
		       deployed_by, deployed_at
		from certificate_deployments
		where host_id = $1
		order by path, deployed_at desc`
	rows, err := s.pool.Query(ctx, query, hostID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	result := map[string]Deployment{}
	for rows.Next() {
		deployment := Deployment{HostID: hostID}
		if err := rows.Scan(&deployment.Path, &deployment.FingerprintSHA256, &deployment.Subject,
			&deployment.Issuer, &deployment.NotAfter, &deployment.KeySecret,
			&deployment.KeyVersion, &deployment.JobID,
			&deployment.DeployedBy, &deployment.DeployedAt); err != nil {
			return nil, err
		}
		result[deployment.Path] = deployment
	}
	return result, rows.Err()
}
