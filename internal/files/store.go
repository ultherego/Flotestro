// Package files keeps the desired state of configuration files and the history
// of their changes.
package files

import (
	"context"
	"errors"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/ultherego/flotestro/internal/authz"
	filesmodule "github.com/ultherego/flotestro/internal/modules/files"
)

// ErrNotFound means a missing file or version.
var ErrNotFound = errors.New("the file is not managed by the panel")

// DesiredState describes a file the panel manages.
type DesiredState struct {
	HostID string `json:"host_id"`
	Path   string `json:"path"`
	// SHA256 is empty for a file whose content comes from the secret store:
	// the panel then keeps neither the content nor its digest.
	SHA256 string `json:"desired_sha256,omitempty"`
	// SecretName and SecretVersion describe the desired state of a file with a
	// secret.
	SecretName    string    `json:"desired_secret,omitempty"`
	SecretVersion int       `json:"desired_secret_version,omitempty"`
	Mode          string    `json:"mode,omitempty"`
	Owner         string    `json:"owner,omitempty"`
	Group         string    `json:"group,omitempty"`
	Validator     string    `json:"validator,omitempty"`
	UpdatedBy     string    `json:"updated_by"`
	UpdatedAt     time.Time `json:"updated_at"`
}

// Version is one content of a file in the history.
type Version struct {
	// SHA256 is empty for an entry whose content came from the secret store:
	// the panel then keeps neither the content nor its digest.
	SHA256 string `json:"sha256,omitempty"`
	// SecretName and SecretVersion describe an entry with a secret.
	SecretName    string    `json:"secret_name,omitempty"`
	SecretVersion int       `json:"secret_version,omitempty"`
	SizeBytes     int64     `json:"size_bytes"`
	JobID         *string   `json:"job_id,omitempty"`
	AppliedBy     string    `json:"applied_by"`
	AppliedAt     time.Time `json:"applied_at"`
}

// executor allows calling the same queries inside a transaction and outside
// one.
type executor interface {
	Exec(ctx context.Context, sql string, args ...any) (pgconn.CommandTag, error)
}

// Store provides access to the file tables.
type Store struct {
	pool *pgxpool.Pool
}

func NewStore(pool *pgxpool.Pool) *Store { return &Store{pool: pool} }

// SaveVersion writes content addressed by its digest.
func (s *Store) SaveVersion(ctx context.Context, q executor, content []byte) (string, error) {
	digest := filesmodule.Fingerprint(content)
	const query = `
		insert into file_versions (sha256, content, size_bytes)
		values ($1, $2, $3)
		on conflict (sha256) do nothing`
	if _, err := q.Exec(ctx, query, digest, content, len(content)); err != nil {
		return "", err
	}
	return digest, nil
}

// Content returns the content of the version with the given digest, without
// asking whose it is. Only a caller that has already bounded the question by
// host may use it; everything that answers a request uses ContentInScope.
func (s *Store) Content(ctx context.Context, digest string) ([]byte, error) {
	const query = `select content from file_versions where sha256 = $1`
	var content []byte
	err := s.pool.QueryRow(ctx, query, digest).Scan(&content)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, ErrNotFound
	}
	return content, err
}

// ContentInScope returns the content of a version carried by a host the caller
// may see, and ErrNotFound when no such host carries it.
//
// A digest is not a secret: it travels in the results of tasks, in the plan an
// operator looks at, in the operation journal and in the answers of the API,
// which reach a wider circle than the content of the file. Reading the content
// by the digest alone therefore handed the configuration of one site to
// whoever held the permission in another.
func (s *Store) ContentInScope(ctx context.Context, digest string, scopes []authz.Scope) ([]byte, error) {
	condition, args := authz.ScopeSQL(scopes, authz.Columns{
		Site: "h.site", Environment: "h.environment", Team: "h.team_id",
		Owner: "h.owner", Tags: "h.tags",
	}, 1)
	where := ""
	if condition != "" {
		where = " and " + condition
	}
	query := `
		select v.content from file_versions v
		 where v.sha256 = $1
		   and exists (
		       select 1 from hosts h
		        where (h.id in (select host_id from managed_files where desired_sha256 = v.sha256)
		            or h.id in (select host_id from managed_file_history where sha256 = v.sha256))` +
		where + `)`
	var content []byte
	err := s.pool.QueryRow(ctx, query, append([]any{digest}, args...)...).Scan(&content)
	if errors.Is(err, pgx.ErrNoRows) {
		// A version nobody the caller may see carries is, to the caller, a
		// version that is not there. Saying "you may not read this one" would
		// confirm that the digest names something.
		return nil, ErrNotFound
	}
	return content, err
}

// Set writes the desired state of a file and adds an entry to the history.
func (s *Store) Set(ctx context.Context, q executor, state DesiredState, jobID string) error {
	const saveState = `
		insert into managed_files (host_id, path, desired_sha256, desired_secret,
		                           desired_secret_version, mode, owner_name,
		                           group_name, validator, updated_by, updated_at)
		values ($1, $2, nullif($3, ''), nullif($4, ''), nullif($5, 0),
		        nullif($6, ''), nullif($7, ''), nullif($8, ''), nullif($9, ''), $10, now())
		on conflict (host_id, path) do update set
			desired_sha256 = excluded.desired_sha256,
			desired_secret = excluded.desired_secret,
			desired_secret_version = excluded.desired_secret_version,
			mode = excluded.mode, owner_name = excluded.owner_name,
			group_name = excluded.group_name, validator = excluded.validator,
			updated_by = excluded.updated_by, updated_at = now()`
	if _, err := q.Exec(ctx, saveState, state.HostID, state.Path, state.SHA256,
		state.SecretName, state.SecretVersion, state.Mode, state.Owner, state.Group,
		state.Validator, state.UpdatedBy); err != nil {
		return err
	}

	const saveHistory = `
		insert into managed_file_history (host_id, path, sha256, secret_name,
		                                  secret_version, job_id, applied_by)
		values ($1, $2, nullif($3, ''), nullif($4, ''), nullif($5, 0), nullif($6, '')::uuid, $7)`
	if _, err := q.Exec(ctx, saveHistory, state.HostID, state.Path, state.SHA256,
		state.SecretName, state.SecretVersion, jobID, state.UpdatedBy); err != nil {
		return err
	}
	return nil
}

// Delete removes the desired state. The history stays: the fact that a file
// was managed and stopped being managed has to be reconstructible.
func (s *Store) Delete(ctx context.Context, q executor, hostID, path string) error {
	const query = `delete from managed_files where host_id = $1 and path = $2`
	_, err := q.Exec(ctx, query, hostID, path)
	return err
}

// List returns the files managed on a host.
func (s *Store) List(ctx context.Context, hostID string) ([]DesiredState, error) {
	const query = `
		select host_id, path, coalesce(desired_sha256, ''), coalesce(desired_secret, ''),
		       coalesce(desired_secret_version, 0), coalesce(mode, ''), coalesce(owner_name, ''),
		       coalesce(group_name, ''), coalesce(validator, ''), updated_by, updated_at
		from managed_files where host_id = $1 order by path`
	rows, err := s.pool.Query(ctx, query, hostID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var result []DesiredState
	for rows.Next() {
		var state DesiredState
		if err := rows.Scan(&state.HostID, &state.Path, &state.SHA256, &state.SecretName,
			&state.SecretVersion, &state.Mode, &state.Owner, &state.Group,
			&state.Validator, &state.UpdatedBy, &state.UpdatedAt); err != nil {
			return nil, err
		}
		result = append(result, state)
	}
	return result, rows.Err()
}

// History returns the successive versions of a file, newest first.
func (s *Store) History(ctx context.Context, hostID, path string, limit int) ([]Version, error) {
	if limit <= 0 || limit > 100 {
		limit = 20
	}
	// An entry with a secret has no content in the store of versions, so the join
	// has to be an outer one: otherwise the history of a file with a secret would
	// be empty.
	const query = `
		select coalesce(h.sha256, ''), coalesce(v.size_bytes, 0),
		       coalesce(h.secret_name, ''), coalesce(h.secret_version, 0),
		       h.job_id::text, h.applied_by, h.applied_at
		from managed_file_history h
		left join file_versions v on v.sha256 = h.sha256
		where h.host_id = $1 and h.path = $2
		order by h.applied_at desc
		limit $3`
	rows, err := s.pool.Query(ctx, query, hostID, path, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var result []Version
	for rows.Next() {
		var version Version
		if err := rows.Scan(&version.SHA256, &version.SizeBytes, &version.SecretName,
			&version.SecretVersion, &version.JobID,
			&version.AppliedBy, &version.AppliedAt); err != nil {
			return nil, err
		}
		result = append(result, version)
	}
	return result, rows.Err()
}
