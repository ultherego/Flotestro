package database

import (
	"context"
	"io"
	"log/slog"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
)

// quietLog is a logger the tests can hand to code that reports what it is
// doing without the output of a passing test carrying it.
func quietLog() *slog.Logger {
	return slog.New(slog.NewTextHandler(io.Discard, nil))
}

// fakeRow answers one query with values prepared by the test.
type fakeRow struct {
	values []any
	err    error
}

func (r fakeRow) Scan(dest ...any) error {
	if r.err != nil {
		return r.err
	}
	for i := range dest {
		if i >= len(r.values) {
			break
		}
		switch target := dest[i].(type) {
		case *bool:
			*target = r.values[i].(bool)
		case *string:
			*target = r.values[i].(string)
		}
	}
	return nil
}

// fakeConn stands in for the one connection the migrator holds.
type fakeConn struct {
	rows     func(sql string) fakeRow
	executed []string
	execErr  error
}

func (c *fakeConn) Exec(ctx context.Context, sql string, args ...any) (pgconn.CommandTag, error) {
	c.executed = append(c.executed, sql)
	return pgconn.CommandTag{}, c.execErr
}

func (c *fakeConn) QueryRow(ctx context.Context, sql string, args ...any) pgx.Row {
	return c.rows(sql)
}

// roleConn answers the two questions assumeRole asks.
func roleConn(sessionUser string, superuser bool, currentUser string, canLogin bool) *fakeConn {
	return &fakeConn{rows: func(sql string) fakeRow {
		if strings.HasPrefix(sql, "select session_user") {
			return fakeRow{values: []any{sessionUser, superuser}}
		}
		return fakeRow{values: []any{currentUser, canLogin}}
	}}
}

func TestAssumeRoleTakesTheConfiguredRole(t *testing.T) {
	conn := roleConn("flotestro_migrator", false, "flotestro_owner", false)
	if err := assumeRole(context.Background(), conn, "flotestro_owner", quietLog()); err != nil {
		t.Fatalf("the role was refused: %v", err)
	}
	if len(conn.executed) != 1 || conn.executed[0] != `set role "flotestro_owner"` {
		t.Fatalf("the role was not taken on as a quoted identifier: %v", conn.executed)
	}
}

func TestAssumeRoleWithoutARoleChangesNothing(t *testing.T) {
	conn := roleConn("flotestro", false, "flotestro", true)
	if err := assumeRole(context.Background(), conn, "", quietLog()); err != nil {
		t.Fatalf("the quick start, which names no role, was refused: %v", err)
	}
	if len(conn.executed) != 0 {
		t.Fatalf("a run that names no role must not change the session: %v", conn.executed)
	}
}

// A login that may set any role at all makes the separation the setting
// asks for a decoration, so the migration stops before it starts.
func TestAssumeRoleRefusesASuperuserLogin(t *testing.T) {
	conn := roleConn("postgres", true, "flotestro_owner", false)
	err := assumeRole(context.Background(), conn, "flotestro_owner", quietLog())
	if err == nil {
		t.Fatal("a superuser migrator was accepted")
	}
	if !strings.Contains(err.Error(), "superuser") {
		t.Fatalf("the refusal does not say what is wrong: %v", err)
	}
	if len(conn.executed) != 0 {
		t.Fatalf("the refusal must happen before anything is executed: %v", conn.executed)
	}
}

// The role that is in force after SET ROLE is read back rather than assumed: a
// session that ended up as somebody else would own every object the migration
// creates.
func TestAssumeRoleRefusesADifferentRoleInForce(t *testing.T) {
	conn := roleConn("flotestro_migrator", false, "flotestro_migrator", true)
	err := assumeRole(context.Background(), conn, "flotestro_owner", quietLog())
	if err == nil {
		t.Fatal("a session that stayed on the login role was accepted")
	}
}

func TestValidRoleNameRefusesWhatIsNotAName(t *testing.T) {
	for _, role := range []string{"flotestro owner", `owner"; drop schema public`, "0owner", strings.Repeat("a", 64)} {
		if err := validRoleName(role); err == nil {
			t.Fatalf("the role name %q was accepted", role)
		}
	}
	for _, role := range []string{"flotestro_owner", "Owner", "_owner", "flotestro-owner"} {
		if err := validRoleName(role); err != nil {
			t.Fatalf("the role name %q was refused: %v", role, err)
		}
	}
}

// The second migrator waits for the first instead of migrating alongside
// it: the lock is taken without blocking and asked for again.
func TestTakeMigrationLockWaitsForTheOtherMigrator(t *testing.T) {
	previous := migrationLockPoll
	migrationLockPoll = time.Millisecond
	defer func() { migrationLockPoll = previous }()

	attempts := 0
	conn := &fakeConn{rows: func(string) fakeRow {
		attempts++
		return fakeRow{values: []any{attempts >= 3}}
	}}
	if err := takeMigrationLock(context.Background(), conn, time.Minute, quietLog()); err != nil {
		t.Fatalf("the lock was not granted: %v", err)
	}
	if attempts != 3 {
		t.Fatalf("the migrator asked %d times instead of waiting until it was granted", attempts)
	}
}

// A wait that runs out is a refusal that migrates nothing, not a migration
// that starts anyway.
func TestTakeMigrationLockGivesUpAfterTheWait(t *testing.T) {
	conn := &fakeConn{rows: func(string) fakeRow { return fakeRow{values: []any{false}} }}
	err := takeMigrationLock(context.Background(), conn, time.Nanosecond, quietLog())
	if err == nil {
		t.Fatal("a migrator that never got the lock reported success")
	}
	if !strings.Contains(err.Error(), "nothing was migrated") {
		t.Fatalf("the refusal does not say that nothing was migrated: %v", err)
	}
}

func TestCompareSchemaCallsAMatchingSchemaCurrent(t *testing.T) {
	report := compareSchema([]string{"0001_a", "0002_b"}, []string{"0002_b", "0001_a"})
	if !report.Current() {
		t.Fatalf("a matching schema was reported as %s: %s", report.Code(), report.Summary())
	}
	if report.Level != "0002_b" || report.Expected != "0002_b" || report.Applied != 2 {
		t.Fatalf("the report does not describe the schema: %+v", report)
	}
}

func TestCompareSchemaCallsAMissingMigrationBehind(t *testing.T) {
	report := compareSchema([]string{"0001_a", "0002_b", "0003_c"}, []string{"0001_a", "0002_b"})
	if report.Code() != CodeSchemaBehind {
		t.Fatalf("a database missing a migration was reported as %q", report.Code())
	}
	if len(report.Pending) != 1 || report.Pending[0] != "0003_c" {
		t.Fatalf("the missing migration is not named: %+v", report.Pending)
	}
}

// An empty database is behind, not current: a readiness gate that let it
// through would admit a panel with no tables at all.
func TestCompareSchemaCallsAnEmptyDatabaseBehind(t *testing.T) {
	report := compareSchema([]string{"0001_a"}, nil)
	if report.Code() != CodeSchemaBehind {
		t.Fatalf("an empty database was reported as %q", report.Code())
	}
	if !strings.Contains(report.Summary(), "no migration at all") {
		t.Fatalf("the summary does not say the database has no migration: %s", report.Summary())
	}
}

// A database a newer control plane has already migrated is ahead.
func TestCompareSchemaCallsANewerDatabaseAhead(t *testing.T) {
	report := compareSchema([]string{"0001_a"}, []string{"0001_a", "0002_b"})
	if report.Code() != CodeSchemaAhead {
		t.Fatalf("a database migrated by a newer binary was reported as %q", report.Code())
	}
	if len(report.Ahead) != 1 || report.Ahead[0] != "0002_b" {
		t.Fatalf("the unknown migration is not named: %+v", report.Ahead)
	}
	// Both at once is reported as ahead: the newer version is the fact
	// that decides what may be done next.
	diverged := compareSchema([]string{"0001_a", "0003_c"}, []string{"0001_a", "0002_b"})
	if diverged.Code() != CodeSchemaAhead {
		t.Fatalf("a diverged schema was reported as %q", diverged.Code())
	}
}

// A renamed migration file is a rename, not a new migration: a database
// migrated before the rename matches a binary that carries exactly that
// migration under its current name.
func TestCompareSchemaTranslatesARenamedMigration(t *testing.T) {
	report := compareSchema([]string{"0044_budgets"}, []string{"0044_budzety"})
	if !report.Current() {
		t.Fatalf("a database migrated before the rename was reported as %s", report.Code())
	}
}

// The binary has to carry migrations at all; a comparison against nothing
// would call every database ahead of it.
func TestEmbeddedVersionsAreOrdered(t *testing.T) {
	versions, err := EmbeddedVersions()
	if err != nil {
		t.Fatalf("the embedded migrations could not be read: %v", err)
	}
	if len(versions) == 0 {
		t.Fatal("the binary carries no migration")
	}
	for i := 1; i < len(versions); i++ {
		if versions[i-1] >= versions[i] {
			t.Fatalf("the migrations are not in order: %s before %s", versions[i-1], versions[i])
		}
	}
}
