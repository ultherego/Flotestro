// Package database otwiera pule polaczen i stosuje migracje osadzone w binarce.
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

// Open tworzy pule polaczen i czeka, az baza odpowie.
func Open(ctx context.Context, dsn string) (*pgxpool.Pool, error) {
	cfg, err := pgxpool.ParseConfig(dsn)
	if err != nil {
		return nil, fmt.Errorf("nieprawidlowy DSN: %w", err)
	}
	cfg.MaxConns = 16
	cfg.MaxConnLifetime = time.Hour

	pool, err := pgxpool.NewWithConfig(ctx, cfg)
	if err != nil {
		return nil, fmt.Errorf("pula polaczen: %w", err)
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
			return fmt.Errorf("baza nie odpowiedziala: %w", lastErr)
		case <-time.After(500 * time.Millisecond):
		}
	}
}

// Migrate stosuje brakujace migracje w jednej transakcji na plik.
// Blokada doradcza zapobiega rownoczesnej migracji przez wiele replik.
func Migrate(ctx context.Context, pool *pgxpool.Pool) error {
	conn, err := pool.Acquire(ctx)
	if err != nil {
		return fmt.Errorf("polaczenie do migracji: %w", err)
	}
	defer conn.Release()

	const migrationLockID = 0x464c4f54 // "FLOT"
	if _, err := conn.Exec(ctx, "select pg_advisory_lock($1)", migrationLockID); err != nil {
		return fmt.Errorf("blokada migracji: %w", err)
	}
	defer func() {
		_, _ = conn.Exec(context.WithoutCancel(ctx), "select pg_advisory_unlock($1)", migrationLockID)
	}()

	if _, err := conn.Exec(ctx, `
		create table if not exists schema_migrations (
			version    text        primary key,
			applied_at timestamptz not null default now()
		)`); err != nil {
		return fmt.Errorf("tabela schema_migrations: %w", err)
	}

	applied := map[string]bool{}
	rows, err := conn.Query(ctx, "select version from schema_migrations")
	if err != nil {
		return fmt.Errorf("odczyt zastosowanych migracji: %w", err)
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
			return fmt.Errorf("migracja %s: %w", version, err)
		}
		if _, err := tx.Exec(ctx, "insert into schema_migrations (version) values ($1)", version); err != nil {
			_ = tx.Rollback(ctx)
			return err
		}
		if err := tx.Commit(ctx); err != nil {
			return fmt.Errorf("commit migracji %s: %w", version, err)
		}
	}
	return nil
}
