// Package backup stores the definitions of copies and the history of their
// runs.
//
// There is no backup data here and there never will be: the host talks to the
// repository directly. The panel keeps what the host will not say by itself -
// what is to be backed up, where to and for how long it stays - and what the
// host does not remember between operations: when the last copy succeeded.
package backup

import (
	"context"
	"encoding/json"
	"errors"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"
)

// ErrNotFound means there is no such definition.
var ErrNotFound = errors.New("the panel does not know such a backup definition")

// Definition describes what to back up and where to.
type Definition struct {
	ID     string `json:"id"`
	HostID string `json:"host_id"`
	Name   string `json:"name"`
	Tool   string `json:"tool"`
	// Repository is a reference to the backup target. The panel shows it but
	// does not mediate through it.
	Repository  string   `json:"repository,omitempty"`
	Paths       []string `json:"paths,omitempty"`
	Excludes    []string `json:"excludes,omitempty"`
	Tags        []string `json:"tags,omitempty"`
	KeepLast    int      `json:"keep_last,omitempty"`
	KeepDaily   int      `json:"keep_daily,omitempty"`
	KeepWeekly  int      `json:"keep_weekly,omitempty"`
	KeepMonthly int      `json:"keep_monthly,omitempty"`
	Prune       bool     `json:"prune,omitempty"`
	Runbook     string   `json:"runbook,omitempty"`
	// Initialize is the consent to create the repository on the first copy.
	Initialize bool `json:"initialize,omitempty"`
	// PasswordSecret and EnvSecrets are the names of secrets. Neither this
	// table nor anyone outside the store knows the values.
	PasswordSecret string            `json:"password_secret,omitempty"`
	EnvSecrets     map[string]string `json:"env_secrets,omitempty"`
	Note           string            `json:"note,omitempty"`
	CreatedBy      string            `json:"created_by"`
	CreatedAt      time.Time         `json:"created_at"`
	UpdatedBy      string            `json:"updated_by"`
	UpdatedAt      time.Time         `json:"updated_at"`
}

// Run is one execution of a backup operation.
type Run struct {
	HostID     string `json:"host_id"`
	Definition string `json:"definition"`
	Kind       string `json:"kind"`
	JobID      string `json:"job_id,omitempty"`
	Outcome    string `json:"outcome"`
	SnapshotID string `json:"snapshot_id,omitempty"`
	// The counters are pointers: a tool that does not give them leaves
	// missing knowledge rather than zero.
	BytesAdded      *int64     `json:"bytes_added,omitempty"`
	TotalBytes      *int64     `json:"total_bytes,omitempty"`
	FilesNew        *int64     `json:"files_new,omitempty"`
	DurationSeconds *float64   `json:"duration_seconds,omitempty"`
	Snapshots       *int       `json:"snapshots,omitempty"`
	RepositorySize  *int64     `json:"repository_size,omitempty"`
	LastSuccessAt   *time.Time `json:"last_success_at,omitempty"`
	Message         string     `json:"message,omitempty"`
	StartedBy       string     `json:"started_by,omitempty"`
	RecordedAt      time.Time  `json:"recorded_at"`
}

// executor allows calling the same queries inside and outside a transaction.
type executor interface {
	Exec(ctx context.Context, sql string, args ...any) (pgconn.CommandTag, error)
}

// Store provides access to the backup tables.
type Store struct {
	pool *pgxpool.Pool
}

func NewStore(pool *pgxpool.Pool) *Store { return &Store{pool: pool} }

const definitionColumns = `id::text, host_id::text, name, tool, repository, paths, excludes,
	tags, keep_last, keep_daily, keep_weekly, keep_monthly, prune, runbook, initialize,
	password_secret, env_secrets, note, created_by, created_at, updated_by, updated_at`

// Definitions returns the host's backup definitions.
func (s *Store) Definitions(ctx context.Context, hostID string) ([]Definition, error) {
	rows, err := s.pool.Query(ctx,
		`select `+definitionColumns+` from backup_definitions where host_id = $1 order by name`, hostID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var result []Definition
	for rows.Next() {
		definition, err := readDefinition(rows)
		if err != nil {
			return nil, err
		}
		result = append(result, definition)
	}
	return result, rows.Err()
}

// Definition returns a single definition.
func (s *Store) Definition(ctx context.Context, hostID, name string) (Definition, error) {
	rows, err := s.pool.Query(ctx,
		`select `+definitionColumns+` from backup_definitions where host_id = $1 and name = $2`,
		hostID, name)
	if err != nil {
		return Definition{}, err
	}
	defer rows.Close()
	if !rows.Next() {
		return Definition{}, ErrNotFound
	}
	return readDefinition(rows)
}

func readDefinition(rows pgx.Rows) (Definition, error) {
	var definition Definition
	var zmienne []byte
	if err := rows.Scan(&definition.ID, &definition.HostID, &definition.Name, &definition.Tool,
		&definition.Repository, &definition.Paths, &definition.Excludes, &definition.Tags,
		&definition.KeepLast, &definition.KeepDaily, &definition.KeepWeekly, &definition.KeepMonthly,
		&definition.Prune, &definition.Runbook, &definition.Initialize,
		&definition.PasswordSecret, &zmienne,
		&definition.Note, &definition.CreatedBy, &definition.CreatedAt,
		&definition.UpdatedBy, &definition.UpdatedAt); err != nil {
		return Definition{}, err
	}
	if len(zmienne) > 0 {
		_ = json.Unmarshal(zmienne, &definition.EnvSecrets)
	}
	return definition, nil
}

// Set creates or updates a definition.
func (s *Store) Set(ctx context.Context, definition Definition) (Definition, error) {
	// An empty list and a missing list mean the same thing in the database -
	// the column does not accept an empty value, and a definition without
	// exclusions is an ordinary definition.
	definition.Paths = nonNilList(definition.Paths)
	definition.Excludes = nonNilList(definition.Excludes)
	definition.Tags = nonNilList(definition.Tags)
	zmienne, err := json.Marshal(definition.EnvSecrets)
	if err != nil {
		return Definition{}, err
	}
	if definition.EnvSecrets == nil {
		zmienne = []byte("{}")
	}
	const query = `
		insert into backup_definitions (host_id, name, tool, repository, paths, excludes, tags,
		                                keep_last, keep_daily, keep_weekly, keep_monthly, prune,
		                                runbook, initialize, password_secret, env_secrets, note,
		                                created_by, updated_by)
		values ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16, $17, $18, $18)
		on conflict (host_id, name) do update set
			tool = excluded.tool, repository = excluded.repository, paths = excluded.paths,
			excludes = excluded.excludes, tags = excluded.tags, keep_last = excluded.keep_last,
			keep_daily = excluded.keep_daily, keep_weekly = excluded.keep_weekly,
			keep_monthly = excluded.keep_monthly, prune = excluded.prune,
			runbook = excluded.runbook, initialize = excluded.initialize,
			password_secret = excluded.password_secret,
			env_secrets = excluded.env_secrets, note = excluded.note,
			updated_by = excluded.updated_by, updated_at = now()
		returning id::text, created_at, updated_at`
	err = s.pool.QueryRow(ctx, query, definition.HostID, definition.Name, definition.Tool,
		definition.Repository, definition.Paths, definition.Excludes, definition.Tags,
		definition.KeepLast, definition.KeepDaily, definition.KeepWeekly, definition.KeepMonthly,
		definition.Prune, definition.Runbook, definition.Initialize,
		definition.PasswordSecret, zmienne, definition.Note, definition.UpdatedBy).
		Scan(&definition.ID, &definition.CreatedAt, &definition.UpdatedAt)
	definition.CreatedBy = definition.UpdatedBy
	return definition, err
}

// Delete removes a definition. The history of runs stays.
func (s *Store) Delete(ctx context.Context, hostID, name string) error {
	tag, err := s.pool.Exec(ctx,
		`delete from backup_definitions where host_id = $1 and name = $2`, hostID, name)
	if err != nil {
		return err
	}
	if tag.RowsAffected() == 0 {
		return ErrNotFound
	}
	return nil
}

// RecordRun appends the result of an operation to the history.
func (s *Store) RecordRun(ctx context.Context, q executor, run Run) error {
	const query = `
		insert into backup_runs (host_id, definition, kind, job_id, outcome, snapshot_id,
		                         bytes_added, total_bytes, files_new, duration_seconds,
		                         snapshots, repository_size, last_success_at, message, started_by)
		values ($1, $2, $3, nullif($4, '')::uuid, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15)`
	_, err := q.Exec(ctx, query, run.HostID, run.Definition, run.Kind,
		run.JobID, run.Outcome, run.SnapshotID, run.BytesAdded,
		run.TotalBytes, run.FilesNew, run.DurationSeconds, run.Snapshots,
		run.RepositorySize, run.LastSuccessAt, run.Message, run.StartedBy)
	return err
}

const kolumnyPrzebiegu = `host_id::text, definition, kind, coalesce(job_id::text, ''), outcome,
	snapshot_id, bytes_added, total_bytes, files_new, duration_seconds, snapshots,
	repository_size, last_success_at, message, started_by, recorded_at`

// Runs returns the history of the host's operations, newest first.
func (s *Store) Runs(ctx context.Context, hostID, definition string, limit int) ([]Run, error) {
	if limit <= 0 || limit > 200 {
		limit = 50
	}
	rows, err := s.pool.Query(ctx, `select `+kolumnyPrzebiegu+`
		from backup_runs where host_id = $1 and ($2 = '' or definition = $2)
		order by recorded_at desc limit $3`, hostID, definition, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var result []Run
	for rows.Next() {
		run, err := readRun(rows)
		if err != nil {
			return nil, err
		}
		result = append(result, run)
	}
	return result, rows.Err()
}

// Latest returns the newest run of every kind for every definition.
//
// It is where the answer to the two questions the operator asks most often
// comes from: when the last copy succeeded and whether anybody has ever
// verified it.
func (s *Store) Latest(ctx context.Context, hostID string) (map[string]map[string]Run, error) {
	rows, err := s.pool.Query(ctx, `select distinct on (definition, kind) `+kolumnyPrzebiegu+`
		from backup_runs where host_id = $1 and outcome = 'succeeded'
		order by definition, kind, recorded_at desc`, hostID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	result := map[string]map[string]Run{}
	for rows.Next() {
		run, err := readRun(rows)
		if err != nil {
			return nil, err
		}
		if result[run.Definition] == nil {
			result[run.Definition] = map[string]Run{}
		}
		result[run.Definition][run.Kind] = run
	}
	return result, rows.Err()
}

// LatestInFleet returns the newest successful run of a given kind for every
// host and every definition.
func (s *Store) LatestInFleet(ctx context.Context, hostIDs []string, kind string) ([]Run, error) {
	if len(hostIDs) == 0 {
		return nil, nil
	}
	rows, err := s.pool.Query(ctx, `select distinct on (host_id, definition) `+kolumnyPrzebiegu+`
		from backup_runs where host_id = any($1) and kind = $2 and outcome = 'succeeded'
		order by host_id, definition, recorded_at desc`, hostIDs, kind)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var result []Run
	for rows.Next() {
		run, err := readRun(rows)
		if err != nil {
			return nil, err
		}
		result = append(result, run)
	}
	return result, rows.Err()
}

// FleetDefinitions returns the definitions of many hosts at once.
func (s *Store) FleetDefinitions(ctx context.Context, hostIDs []string) ([]Definition, error) {
	if len(hostIDs) == 0 {
		return nil, nil
	}
	rows, err := s.pool.Query(ctx, `select `+definitionColumns+`
		from backup_definitions where host_id = any($1) order by host_id, name`, hostIDs)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var result []Definition
	for rows.Next() {
		definition, err := readDefinition(rows)
		if err != nil {
			return nil, err
		}
		result = append(result, definition)
	}
	return result, rows.Err()
}

func readRun(rows pgx.Rows) (Run, error) {
	var run Run
	if err := rows.Scan(&run.HostID, &run.Definition, &run.Kind,
		&run.JobID, &run.Outcome, &run.SnapshotID, &run.BytesAdded,
		&run.TotalBytes, &run.FilesNew, &run.DurationSeconds,
		&run.Snapshots, &run.RepositorySize, &run.LastSuccessAt,
		&run.Message, &run.StartedBy, &run.RecordedAt); err != nil {
		return Run{}, err
	}
	return run, nil
}

// nonNilList turns a missing list into an empty list.
func nonNilList(values []string) []string {
	if values == nil {
		return []string{}
	}
	return values
}
