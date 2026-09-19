// Package database opens the connection pool and applies the migrations
// embedded in the binary.
package database

import (
	"context"
	"fmt"
	"io/fs"
	"log/slog"
	"sort"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/ultherego/flotestro/db"
	"github.com/ultherego/flotestro/internal/config"
)

// Open creates the connection pool and waits for the database to answer.
func Open(ctx context.Context, dsn string, settings config.DatabasePool) (*pgxpool.Pool, error) {
	if err := settings.Validate(); err != nil {
		return nil, err
	}
	cfg, err := pgxpool.ParseConfig(dsn)
	if err != nil {
		return nil, fmt.Errorf("an invalid DSN: %w", err)
	}
	cfg.MaxConns = settings.MaxConns
	cfg.MinConns = settings.MinConns
	cfg.MaxConnLifetime = settings.MaxConnLifetime
	cfg.MaxConnIdleTime = settings.MaxConnIdleTime
	cfg.HealthCheckPeriod = settings.HealthCheckPeriod
	// The DSN may carry connect_timeout of its own.
	switch {
	case settings.ConnectTimeoutSet || cfg.ConnConfig.ConnectTimeout <= 0:
		cfg.ConnConfig.ConnectTimeout = settings.ConnectTimeout
	case cfg.ConnConfig.ConnectTimeout >= config.DatabaseStartupTimeout:
		return nil, fmt.Errorf("the DSN asks for connect_timeout=%s, which is not under the %s the "+
			"control plane waits for the database at start; lower it, or set %s",
			cfg.ConnConfig.ConnectTimeout, config.DatabaseStartupTimeout, config.EnvDBConnectTimeout)
	}

	pool, err := pgxpool.NewWithConfig(ctx, cfg)
	if err != nil {
		return nil, fmt.Errorf("the connection pool: %w", err)
	}

	pingCtx, cancel := context.WithTimeout(ctx, config.DatabaseStartupTimeout)
	defer cancel()
	if err := waitForDatabase(pingCtx, pool); err != nil {
		pool.Close()
		return nil, err
	}
	return pool, nil
}

func waitForDatabase(ctx context.Context, pool *pgxpool.Pool) error {
	var lastErr error
	for {
		if err := pool.Ping(ctx); err == nil {
			return nil
		} else {
			lastErr = err
		}
		select {
		case <-ctx.Done():
			return fmt.Errorf("the database did not answer: %w", lastErr)
		case <-time.After(500 * time.Millisecond):
		}
	}
}

// renamedMigrations maps the former file names of migrations to the current
// ones.
var renamedMigrations = map[string]string{
	"0044_budzety":      "0044_budgets",
	"0045_kwalifikacja": "0045_qualification",
}

// EmbeddedVersions lists the migrations this binary carries, in the order they
// are applied.
func EmbeddedVersions() ([]string, error) {
	entries, err := fs.Glob(db.Migrations, "migrations/*.sql")
	if err != nil {
		return nil, err
	}
	sort.Strings(entries)
	versions := make([]string, 0, len(entries))
	for _, entry := range entries {
		versions = append(versions, versionOf(entry))
	}
	return versions, nil
}

// versionOf turns the path of an embedded migration into its version.
func versionOf(entry string) string {
	return strings.TrimSuffix(strings.TrimPrefix(entry, "migrations/"), ".sql")
}

// MigrateOptions is the contract the migrator runs under.
type MigrateOptions struct {
	// Role is the role the migrator takes on after connecting, so that every
	// object it creates belongs to the owner of the schema rather than to the
	// login it happened to use.
	Role string
	// LockWait bounds the wait for another migrator. Zero means the
	// default of the configuration.
	LockWait time.Duration
	// Log receives the line about waiting for another migrator and the
	// line about every migration applied. Nil uses the default logger.
	Log *slog.Logger
}

// migrationLockID is the advisory lock every migrator of this product takes:
// "FLOT".
const migrationLockID = 0x464c4f54

// migrationLockPoll is how often a waiting migrator asks again.
var migrationLockPoll = 2 * time.Second

// Migrate applies the missing migrations in one transaction per file.
func Migrate(ctx context.Context, pool *pgxpool.Pool, opts MigrateOptions) error {
	log := opts.Log
	if log == nil {
		log = slog.Default()
	}
	lockWait := opts.LockWait
	if lockWait <= 0 {
		lockWait = config.DefaultMigrationLockWait
	}

	conn, err := pool.Acquire(ctx)
	if err != nil {
		return fmt.Errorf("the connection for the migration: %w", err)
	}
	defer conn.Release()

	// The role is taken on before the lock and before any DDL, so that the lock,
	// the bookkeeping table and every object the migrations create belong to the
	// same owner.
	if err := assumeRole(ctx, conn, opts.Role, log); err != nil {
		return err
	}
	if err := takeMigrationLock(ctx, conn, lockWait, log); err != nil {
		return err
	}
	defer func() {
		_, _ = conn.Exec(context.WithoutCancel(ctx), "select pg_advisory_unlock($1)", migrationLockID)
	}()

	if _, err := conn.Exec(ctx, `
		create table if not exists schema_migrations (
			version    text        primary key,
			applied_at timestamptz not null default now()
		)`); err != nil {
		return fmt.Errorf("the schema_migrations table: %w", err)
	}

	applied := map[string]bool{}
	rows, err := conn.Query(ctx, "select version from schema_migrations")
	if err != nil {
		return fmt.Errorf("reading the applied migrations: %w", err)
	}
	for rows.Next() {
		var version string
		if err := rows.Scan(&version); err != nil {
			rows.Close()
			return err
		}
		applied[version] = true
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return err
	}

	// Migrations recorded under their former file names are re-labelled, so
	// that a database migrated before the rename does not run them again.
	for former, current := range renamedMigrations {
		if !applied[former] {
			continue
		}
		if _, err := conn.Exec(ctx,
			"update schema_migrations set version = $2 where version = $1", former, current); err != nil {
			return fmt.Errorf("re-labelling the migration %s: %w", former, err)
		}
		delete(applied, former)
		applied[current] = true
	}

	entries, err := fs.Glob(db.Migrations, "migrations/*.sql")
	if err != nil {
		return err
	}
	sort.Strings(entries)

	for _, entry := range entries {
		version := versionOf(entry)
		if applied[version] {
			continue
		}
		body, err := db.Migrations.ReadFile(entry)
		if err != nil {
			return err
		}

		tx, err := conn.Begin(ctx)
		if err != nil {
			return err
		}
		if _, err := tx.Exec(ctx, string(body)); err != nil {
			_ = tx.Rollback(ctx)
			return fmt.Errorf("the migration %s: %w", version, err)
		}
		if _, err := tx.Exec(ctx, "insert into schema_migrations (version) values ($1)", version); err != nil {
			_ = tx.Rollback(ctx)
			return err
		}
		if err := tx.Commit(ctx); err != nil {
			return fmt.Errorf("committing the migration %s: %w", version, err)
		}
		log.Info("a migration was applied", "version", version)
	}
	return nil
}

// migrationConn is what the role and the lock need: one connection, not a
// pool.
type migrationConn interface {
	Exec(ctx context.Context, sql string, args ...any) (pgconn.CommandTag, error)
	QueryRow(ctx context.Context, sql string, args ...any) pgx.Row
}

// takeMigrationLock waits for the migrator that is already running.
func takeMigrationLock(ctx context.Context, conn migrationConn, wait time.Duration, log *slog.Logger) error {
	deadline := time.Now().Add(wait)
	announced := false
	for {
		var acquired bool
		if err := conn.QueryRow(ctx, "select pg_try_advisory_lock($1)", migrationLockID).Scan(&acquired); err != nil {
			return fmt.Errorf("the lock of the migration: %w", err)
		}
		if acquired {
			if announced {
				log.Info("the schema lock was granted; this migrator continues")
			}
			return nil
		}
		if !announced {
			// Named once and not once per attempt: this is the normal
			// course of a rolling upgrade, not an incident.
			log.Info("another migrator holds the schema lock; waiting rather than migrating alongside it",
				"wait", wait.String())
			announced = true
		}
		if time.Now().After(deadline) {
			return fmt.Errorf("another migrator has held the schema lock for %s (%s): it is still "+
				"running, or a session was left open on the database; nothing was migrated",
				wait, config.EnvMigrationLockWait)
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(migrationLockPoll):
		}
	}
}

// assumeRole takes on the configured role for the rest of the session.
func assumeRole(ctx context.Context, conn migrationConn, role string, log *slog.Logger) error {
	if role == "" {
		return nil
	}
	if err := validRoleName(role); err != nil {
		return err
	}
	var sessionUser string
	var superuser bool
	if err := conn.QueryRow(ctx,
		`select session_user, coalesce((select rolsuper from pg_roles where rolname = session_user), false)`).
		Scan(&sessionUser, &superuser); err != nil {
		return fmt.Errorf("reading the login role of the migrator: %w", err)
	}
	if superuser {
		return fmt.Errorf("%s names %q, and the migrator logs in as the superuser %q, which may set any "+
			"role at all; the separation the setting asks for would not exist, so nothing was migrated",
			config.EnvMigrationRole, role, sessionUser)
	}
	if _, err := conn.Exec(ctx, "set role "+quoteIdentifier(role)); err != nil {
		return fmt.Errorf("%s names %q and the migrator logs in as %q, which is not a member of it: %w",
			config.EnvMigrationRole, role, sessionUser, err)
	}
	var current string
	var canLogin bool
	if err := conn.QueryRow(ctx,
		`select current_user, coalesce((select rolcanlogin from pg_roles where rolname = current_user), false)`).
		Scan(&current, &canLogin); err != nil {
		return fmt.Errorf("confirming the role of the migrator: %w", err)
	}
	if current != role {
		return fmt.Errorf("%s names %q and the migration runs as %q; nothing was migrated",
			config.EnvMigrationRole, role, current)
	}
	if canLogin {
		// Not a refusal: the owner of the schema is meant to be NOLOGIN, but an
		// installation migrating towards that layout still has the right owner even
		// while the role can still log in.
		log.Warn("the migration role can log in; the owner of the schema is meant to be a NOLOGIN role "+
			"that only the migrator's login may take on", "role", role)
	}
	log.Info("the migration runs under an assumed role", "login", sessionUser, "role", role)
	return nil
}

// validRoleName refuses anything that is not a plain role name.
func validRoleName(role string) error {
	if len(role) > 63 {
		return fmt.Errorf("%s is longer than the 63 characters a PostgreSQL role name may take",
			config.EnvMigrationRole)
	}
	for i, r := range role {
		switch {
		case r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z', r == '_':
		case i > 0 && (r >= '0' && r <= '9' || r == '-' || r == '$'):
		default:
			return fmt.Errorf("%s is %q; a role name here is letters, digits, underscores and dashes, "+
				"and it does not begin with a digit", config.EnvMigrationRole, role)
		}
	}
	return nil
}

// quoteIdentifier renders a checked name as a quoted identifier, so that a
// role whose name happens to be a keyword or holds capitals is read as it was
// written.
func quoteIdentifier(name string) string {
	return `"` + strings.ReplaceAll(name, `"`, `""`) + `"`
}

// SchemaReport says how the schema of a database compares with the one this
// binary carries.
type SchemaReport struct {
	// Level is the newest migration the database records; empty when it
	// records none, which is an empty database.
	Level string
	// Expected is the newest migration this binary carries.
	Expected string
	// Applied is how many migrations the database records.
	Applied int
	// Pending are the migrations this binary carries that the database
	// does not have: the database is behind the binary.
	Pending []string
	// Ahead are the migrations the database records that this binary does
	// not carry: another, newer version migrated it.
	Ahead []string
}

// The codes a schema that does not match is reported under. They are the
// codes of the error guide, so the log line and the runbook use one word.
const (
	// CodeSchemaBehind: the database misses migrations this binary carries.
	CodeSchemaBehind = "schema_behind"
	// CodeSchemaAhead: the database carries migrations this binary does
	// not know, so a newer control plane has already migrated it.
	CodeSchemaAhead = "schema_ahead"
)

// Current says whether the database is exactly the schema this binary
// expects.
func (r SchemaReport) Current() bool { return len(r.Pending) == 0 && len(r.Ahead) == 0 }

// Code names what is wrong, or is empty when nothing is.
func (r SchemaReport) Code() string {
	switch {
	case len(r.Ahead) > 0:
		return CodeSchemaAhead
	case len(r.Pending) > 0:
		return CodeSchemaBehind
	default:
		return ""
	}
}

// Summary is the one sentence the log and the exit carry.
func (r SchemaReport) Summary() string {
	switch r.Code() {
	case CodeSchemaAhead:
		return fmt.Sprintf("the database is at %s and this binary carries up to %s: it was migrated by a "+
			"newer control plane (%d migration(s) it does not know)", r.Level, r.Expected, len(r.Ahead))
	case CodeSchemaBehind:
		return fmt.Sprintf("the database is at %s and this binary expects %s: %d migration(s) have not "+
			"been applied", displayLevel(r.Level), r.Expected, len(r.Pending))
	default:
		return fmt.Sprintf("the database is at %s, which is the schema this binary expects", r.Expected)
	}
}

func displayLevel(level string) string {
	if level == "" {
		return "no migration at all"
	}
	return level
}

// CheckSchema reads the schema of the database and changes nothing - not even
// the bookkeeping table, which a check that created it would report as a
// database it had just improved.
func CheckSchema(ctx context.Context, pool *pgxpool.Pool) (SchemaReport, error) {
	embedded, err := EmbeddedVersions()
	if err != nil {
		return SchemaReport{}, err
	}
	var present bool
	// Unqualified on purpose: the table lives wherever the search path of the
	// connection puts it, which is the same place the migrator wrote it, and
	// naming a schema here would report an installation that uses another one as
	if err := pool.QueryRow(ctx, "select to_regclass('schema_migrations') is not null").
		Scan(&present); err != nil {
		return SchemaReport{}, fmt.Errorf("reading the schema of the database: %w", err)
	}
	var applied []string
	if present {
		rows, err := pool.Query(ctx, "select version from schema_migrations")
		if err != nil {
			return SchemaReport{}, fmt.Errorf("reading the applied migrations: %w", err)
		}
		for rows.Next() {
			var version string
			if err := rows.Scan(&version); err != nil {
				rows.Close()
				return SchemaReport{}, err
			}
			applied = append(applied, version)
		}
		rows.Close()
		if err := rows.Err(); err != nil {
			return SchemaReport{}, err
		}
	}
	return compareSchema(embedded, applied), nil
}

// compareSchema is the judgement itself, over two lists of versions. It is
// separate from the reading so that it can be exercised without a database.
func compareSchema(embedded, applied []string) SchemaReport {
	// The rename of a migration file is a rename, not a new migration: a database
	// recorded under the former name is translated here, the same way the
	// migrator translates it, so a check never calls it ahead of a binary that
	recorded := map[string]bool{}
	for _, version := range applied {
		if current, renamed := renamedMigrations[version]; renamed {
			version = current
		}
		recorded[version] = true
	}
	carries := map[string]bool{}
	report := SchemaReport{Applied: len(recorded)}
	for _, version := range embedded {
		carries[version] = true
		if !recorded[version] {
			report.Pending = append(report.Pending, version)
		}
	}
	if len(embedded) > 0 {
		report.Expected = embedded[len(embedded)-1]
	}
	levels := make([]string, 0, len(recorded))
	for version := range recorded {
		levels = append(levels, version)
		if !carries[version] {
			report.Ahead = append(report.Ahead, version)
		}
	}
	sort.Strings(levels)
	sort.Strings(report.Ahead)
	if len(levels) > 0 {
		report.Level = levels[len(levels)-1]
	}
	return report
}
