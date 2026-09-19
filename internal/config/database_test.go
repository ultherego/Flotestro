package config

import (
	"strings"
	"testing"
	"time"
)

func TestDatabasePoolDefaults(t *testing.T) {
	pool, err := DatabasePoolFromEnv()
	if err != nil {
		t.Fatalf("the defaults were refused: %v", err)
	}
	if err := pool.Validate(); err != nil {
		t.Fatalf("the defaults do not validate: %v", err)
	}
	if pool.MaxConns != DefaultDBMaxConns || pool.MinConns != DefaultDBMinConns {
		t.Fatalf("the default pool is not the documented one: %+v", pool)
	}
	if pool.ConnectTimeoutSet {
		t.Fatal("a pool nobody configured must not claim the connect timeout was named")
	}
}

func TestDatabasePoolReadsTheEnvironment(t *testing.T) {
	t.Setenv(EnvDBMaxConns, "40")
	t.Setenv(EnvDBMinConns, "8")
	t.Setenv(EnvDBMaxConnLifetime, "30m")
	t.Setenv(EnvDBMaxConnIdleTime, "5m")
	t.Setenv(EnvDBHealthCheckPeriod, "10s")
	t.Setenv(EnvDBConnectTimeout, "5s")

	pool, err := DatabasePoolFromEnv()
	if err != nil {
		t.Fatalf("a valid pool was refused: %v", err)
	}
	if err := pool.Validate(); err != nil {
		t.Fatalf("a valid pool does not validate: %v", err)
	}
	if pool.MaxConns != 40 || pool.MinConns != 8 || pool.MaxConnLifetime != 30*time.Minute ||
		pool.MaxConnIdleTime != 5*time.Minute || pool.HealthCheckPeriod != 10*time.Second ||
		pool.ConnectTimeout != 5*time.Second {
		t.Fatalf("the pool does not carry what was configured: %+v", pool)
	}
	if !pool.ConnectTimeoutSet {
		t.Fatal("a connect timeout named by the installation has to win against the one in the DSN")
	}
}

// A value nobody can read is a refusal rather than a silent default: the
// numbers are a budget shared with every other replica.
func TestDatabasePoolRefusesWhatItCannotRead(t *testing.T) {
	t.Setenv(EnvDBMaxConns, "plenty")
	if _, err := DatabasePoolFromEnv(); err == nil || !strings.Contains(err.Error(), EnvDBMaxConns) {
		t.Fatalf("an unreadable connection count was accepted: %v", err)
	}
	t.Setenv(EnvDBMaxConns, "16")
	t.Setenv(EnvDBMaxConnLifetime, "one hour")
	if _, err := DatabasePoolFromEnv(); err == nil || !strings.Contains(err.Error(), EnvDBMaxConnLifetime) {
		t.Fatalf("an unreadable duration was accepted: %v", err)
	}
}

func TestDatabasePoolRefusesValuesThatContradictEachOther(t *testing.T) {
	cases := []struct {
		name    string
		change  func(*DatabasePool)
		mention string
	}{
		{"a pool smaller than the long-lived connections", func(p *DatabasePool) { p.MaxConns = 3 }, EnvDBMaxConns},
		{"more kept open than may be held", func(p *DatabasePool) { p.MinConns = 20 }, EnvDBMinConns},
		{"a negative minimum", func(p *DatabasePool) { p.MinConns = -1 }, EnvDBMinConns},
		{"a connection that is never retired", func(p *DatabasePool) { p.MaxConnLifetime = 0 }, EnvDBMaxConnLifetime},
		{"an idle time past the lifetime", func(p *DatabasePool) { p.MaxConnIdleTime = 2 * time.Hour }, EnvDBMaxConnIdleTime},
		{"a pool that never checks itself", func(p *DatabasePool) { p.HealthCheckPeriod = 0 }, EnvDBHealthCheckPeriod},
		{"an unbounded attempt", func(p *DatabasePool) { p.ConnectTimeout = 0 }, EnvDBConnectTimeout},
		{"an attempt longer than the start-up wait",
			func(p *DatabasePool) { p.ConnectTimeout = DatabaseStartupTimeout }, EnvDBConnectTimeout},
	}
	for _, testCase := range cases {
		t.Run(testCase.name, func(t *testing.T) {
			pool := DefaultDatabasePool()
			testCase.change(&pool)
			err := pool.Validate()
			if err == nil {
				t.Fatalf("%s was accepted", testCase.name)
			}
			if !strings.Contains(err.Error(), testCase.mention) {
				t.Fatalf("the refusal does not name the variable to edit: %v", err)
			}
		})
	}
}

func TestMigrationDefaultsToTheQuickStart(t *testing.T) {
	migration, err := MigrationFromEnv()
	if err != nil {
		t.Fatalf("the defaults were refused: %v", err)
	}
	if !migration.AutoMigrate {
		t.Fatal("the quick start brings the schema forward at the start")
	}
	if migration.Role != "" {
		t.Fatalf("a quick start assumes no role: %q", migration.Role)
	}
	if migration.LockWait != DefaultMigrationLockWait {
		t.Fatalf("the wait for another migrator is %s", migration.LockWait)
	}
}

func TestMigrationReadsTheEnvironment(t *testing.T) {
	t.Setenv(EnvAutoMigrate, "false")
	t.Setenv(EnvMigrationRole, " flotestro_owner ")
	t.Setenv(EnvMigrationLockWait, "2m")
	migration, err := MigrationFromEnv()
	if err != nil {
		t.Fatalf("a valid migration contract was refused: %v", err)
	}
	if migration.AutoMigrate {
		t.Fatal("a deployment that turned auto-migration off still migrates at the start")
	}
	if migration.Role != "flotestro_owner" {
		t.Fatalf("the role is not the configured one: %q", migration.Role)
	}
	if migration.LockWait != 2*time.Minute {
		t.Fatalf("the wait is not the configured one: %s", migration.LockWait)
	}
}

// Whether a serving replica holds the rights to change the schema is not a
// question to answer by falling back to a default.
func TestMigrationRefusesAWordThatIsNeitherTrueNorFalse(t *testing.T) {
	t.Setenv(EnvAutoMigrate, "yes")
	if _, err := MigrationFromEnv(); err == nil || !strings.Contains(err.Error(), EnvAutoMigrate) {
		t.Fatalf("a word that is neither true nor false was accepted: %v", err)
	}
}

func TestMigrationRefusesAMigratorThatDoesNotWait(t *testing.T) {
	t.Setenv(EnvMigrationLockWait, "0s")
	if _, err := MigrationFromEnv(); err == nil {
		t.Fatal("a migrator that does not wait for the one already running was accepted")
	}
}
