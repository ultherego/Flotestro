package database

import (
	"context"
	"fmt"
	"log/slog"

	"github.com/jackc/pgx/v5/pgxpool"
)

// Preflight asks the database what it is before the panel settles on it. A
// connection that opens says nothing about whether this is the writer, whether
// the role may do what the panel needs, or whether the extension the search
// indexes rest on is there - and each of those fails later, in a place that
// does not name the cause.
//
// Nothing here is logged with the DSN in it: the DSN carries the password.
func Preflight(ctx context.Context, pool *pgxpool.Pool, log *slog.Logger) error {
	var version, user, database string
	var standby bool
	if err := pool.QueryRow(ctx, `
		select version(), current_user, current_database(), pg_is_in_recovery()`).
		Scan(&version, &user, &database, &standby); err != nil {
		return fmt.Errorf("asking the database what it is: %w", err)
	}
	if standby {
		return fmt.Errorf("this database is a standby: it accepts the connection and refuses every write. " +
			"Point the panel at the writer, or add target_session_attrs=read-write to the DSN so the " +
			"connection is refused here instead of at the first change")
	}
	// The search indexes rest on pg_trgm. The migration creates it when the role
	// may; when it may not, the creation fails in the middle of a migration
	// rather than here, with a message about an index.
	var trigrams bool
	if err := pool.QueryRow(ctx,
		`select exists (select 1 from pg_extension where extname = 'pg_trgm')`).Scan(&trigrams); err != nil {
		return fmt.Errorf("asking about the extensions: %w", err)
	}
	if log != nil {
		log.Info("the database this panel runs against",
			"server", version, "role", user, "database", database, "pg_trgm", trigrams)
	}
	return nil
}
