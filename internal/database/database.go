// Package database opens the connection pool and applies the migrations
// embedded in the binary.
package database

import (
	"context"
	"fmt"
	"io/fs"
	"sort"
	"strings"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/ultherego/flotestro/db"
)

// Open creates the connection pool and waits for the database to answer.
func Open(ctx context.Context, dsn string) (*pgxpool.Pool, error) {
	cfg, err := pgxpool.ParseConfig(dsn)
	if err != nil {
		return nil, fmt.Errorf("an invalid DSN: %w", err)
	}
	cfg.MaxConns = 16
	cfg.MaxConnLifetime = time.Hour

	pool, err := pgxpool.NewWithConfig(ctx, cfg)
	if err != nil {
		return nil, fmt.Errorf("the connection pool: %w", err)
	}

	pingCtx, cancel := context.WithTimeout(ctx, 30*time.Second)
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
// ones. The version is the file name, so a rename would otherwise make an
// already migrated database run the migration a second time.
var renamedMigrations = map[string]string{
	"0044_budzety":      "0044_budgets",
	"0045_kwalifikacja": "0045_qualification",
}

// Migrate applies the missing migrations in one transaction per file. An
// advisory lock prevents several replicas from migrating at the same time.
func Migrate(ctx context.Context, pool *pgxpool.Pool) error {
	conn, err := pool.Acquire(ctx)
	if err != nil {
		return fmt.Errorf("the connection for the migration: %w", err)
	}
	defer conn.Release()

	const migrationLockID = 0x464c4f54 // "FLOT"
	if _, err := conn.Exec(ctx, "select pg_advisory_lock($1)", migrationLockID); err != nil {
		return fmt.Errorf("the lock of the migration: %w", err)
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
		version := strings.TrimSuffix(strings.TrimPrefix(entry, "migrations/"), ".sql")
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
	}
	return nil
}
