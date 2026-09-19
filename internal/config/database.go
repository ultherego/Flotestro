package config

import (
	"fmt"
	"os"
	"strconv"
	"strings"
	"time"
)

// The shape of the connection pool and the migration contract. A pool is not a
// performance setting: it is a budget.

// The defaults of the pool.
const (
	// DefaultDBMaxConns is the pool of one replica.
	DefaultDBMaxConns int32 = 16
	// DefaultDBMinConns is what the pool keeps open while idle, so that the
	// first task after a quiet night does not pay for a handshake.
	DefaultDBMinConns int32 = 2
	// DefaultDBMaxConnLifetime retires a connection while it is healthy;
	// it is also what lets a failover reach the pool at all.
	DefaultDBMaxConnLifetime = time.Hour
	// DefaultDBMaxConnIdleTime gives back what the fleet stopped needing.
	DefaultDBMaxConnIdleTime = 15 * time.Minute
	// DefaultDBHealthCheckPeriod is how often the pool looks at what it
	// holds.
	DefaultDBHealthCheckPeriod = 30 * time.Second
	// DefaultDBConnectTimeout bounds one attempt to open a connection.
	DefaultDBConnectTimeout = 10 * time.Second
)

// MinimumDBMaxConns is the smallest pool a control plane can work with.
const MinimumDBMaxConns int32 = 4

// DatabaseStartupTimeout is how long the control plane waits at start for the
// database to answer.
const DatabaseStartupTimeout = 30 * time.Second

// DatabasePool is the shape of the connection pool of one replica, as the
// installation asked for it.
type DatabasePool struct {
	MaxConns          int32
	MinConns          int32
	MaxConnLifetime   time.Duration
	MaxConnIdleTime   time.Duration
	HealthCheckPeriod time.Duration
	// ConnectTimeout bounds one attempt to open a connection.
	ConnectTimeout time.Duration
	// ConnectTimeoutSet says whether the installation named the connect timeout
	// itself.
	ConnectTimeoutSet bool
}

// The names of the settings, in one place, so that a refusal names the
// variable an operator has to edit rather than a field of a struct.
const (
	EnvDBMaxConns          = "FLOTESTRO_DB_MAX_CONNS"
	EnvDBMinConns          = "FLOTESTRO_DB_MIN_CONNS"
	EnvDBMaxConnLifetime   = "FLOTESTRO_DB_MAX_CONN_LIFETIME"
	EnvDBMaxConnIdleTime   = "FLOTESTRO_DB_MAX_CONN_IDLE_TIME"
	EnvDBHealthCheckPeriod = "FLOTESTRO_DB_HEALTH_CHECK_PERIOD"
	EnvDBConnectTimeout    = "FLOTESTRO_DB_CONNECT_TIMEOUT"
)

// DefaultDatabasePool is the pool an installation gets without saying
// anything.
func DefaultDatabasePool() DatabasePool {
	return DatabasePool{
		MaxConns:          DefaultDBMaxConns,
		MinConns:          DefaultDBMinConns,
		MaxConnLifetime:   DefaultDBMaxConnLifetime,
		MaxConnIdleTime:   DefaultDBMaxConnIdleTime,
		HealthCheckPeriod: DefaultDBHealthCheckPeriod,
		ConnectTimeout:    DefaultDBConnectTimeout,
	}
}

// DatabasePoolFromEnv reads the pool out of the environment and refuses what
// it cannot make sense of.
func DatabasePoolFromEnv() (DatabasePool, error) {
	pool := DefaultDatabasePool()
	var err error
	if pool.MaxConns, err = envInt32(EnvDBMaxConns, pool.MaxConns); err != nil {
		return pool, err
	}
	if pool.MinConns, err = envInt32(EnvDBMinConns, pool.MinConns); err != nil {
		return pool, err
	}
	if pool.MaxConnLifetime, err = envExactDuration(EnvDBMaxConnLifetime, pool.MaxConnLifetime); err != nil {
		return pool, err
	}
	if pool.MaxConnIdleTime, err = envExactDuration(EnvDBMaxConnIdleTime, pool.MaxConnIdleTime); err != nil {
		return pool, err
	}
	if pool.HealthCheckPeriod, err = envExactDuration(EnvDBHealthCheckPeriod, pool.HealthCheckPeriod); err != nil {
		return pool, err
	}
	// Whether the variable was named at all is read before it is parsed:
	// it decides who wins against a connect_timeout carried by the DSN.
	if value, ok := os.LookupEnv(EnvDBConnectTimeout); ok && strings.TrimSpace(value) != "" {
		pool.ConnectTimeoutSet = true
	}
	if pool.ConnectTimeout, err = envExactDuration(EnvDBConnectTimeout, pool.ConnectTimeout); err != nil {
		return pool, err
	}
	return pool, nil
}

// Validate refuses a pool that contradicts itself or the database it will be
// pointed at.
func (p DatabasePool) Validate() error {
	if p.MaxConns < MinimumDBMaxConns {
		return fmt.Errorf("%s is %d; a replica needs at least %d connections, because the event bus "+
			"and the epoch watcher each hold one for as long as the process lives",
			EnvDBMaxConns, p.MaxConns, MinimumDBMaxConns)
	}
	if p.MinConns < 0 {
		return fmt.Errorf("%s is %d; a pool cannot keep fewer than no connections open", EnvDBMinConns, p.MinConns)
	}
	if p.MinConns > p.MaxConns {
		return fmt.Errorf("%s is %d and %s is %d; the pool cannot keep more connections open than it may hold",
			EnvDBMinConns, p.MinConns, EnvDBMaxConns, p.MaxConns)
	}
	if p.MaxConnLifetime <= 0 {
		return fmt.Errorf("%s is %s; a connection that is never retired outlives the failover "+
			"that was supposed to move it", EnvDBMaxConnLifetime, p.MaxConnLifetime)
	}
	if p.MaxConnIdleTime <= 0 {
		return fmt.Errorf("%s is %s; it has to be a positive duration", EnvDBMaxConnIdleTime, p.MaxConnIdleTime)
	}
	if p.MaxConnIdleTime > p.MaxConnLifetime {
		return fmt.Errorf("%s is %s and %s is %s; a connection retired by age before it can ever go "+
			"idle long enough makes the idle setting a value nobody can reach",
			EnvDBMaxConnIdleTime, p.MaxConnIdleTime, EnvDBMaxConnLifetime, p.MaxConnLifetime)
	}
	if p.HealthCheckPeriod <= 0 {
		return fmt.Errorf("%s is %s; the pool would never look at what it holds",
			EnvDBHealthCheckPeriod, p.HealthCheckPeriod)
	}
	if p.ConnectTimeout <= 0 {
		return fmt.Errorf("%s is %s; an attempt to connect has to be bounded", EnvDBConnectTimeout, p.ConnectTimeout)
	}
	if p.ConnectTimeout >= DatabaseStartupTimeout {
		return fmt.Errorf("%s is %s, which is not under the %s the control plane waits for the database "+
			"at start; the start would give up before the first attempt has finished",
			EnvDBConnectTimeout, p.ConnectTimeout, DatabaseStartupTimeout)
	}
	return nil
}

// Migration is the contract of the schema: who brings it forward, under
// which role, and whether a serving process may do it at all.
type Migration struct {
	// AutoMigrate lets a serving process bring the schema forward itself.
	AutoMigrate bool
	// Role is the role the migrator takes on after connecting, usually the
	// NOLOGIN owner of the schema.
	Role string
	// LockWait bounds how long a migrator waits for another one that holds the
	// schema lock.
	LockWait time.Duration
}

// DefaultMigrationLockWait is how long a second migrator waits.
const DefaultMigrationLockWait = 15 * time.Minute

// The names of the migration settings.
const (
	EnvAutoMigrate          = "FLOTESTRO_AUTO_MIGRATE"
	EnvMigrationRole        = "FLOTESTRO_MIGRATION_ROLE"
	EnvMigrationLockWait    = "FLOTESTRO_MIGRATION_LOCK_WAIT"
	EnvMigrationDatabaseURL = "FLOTESTRO_MIGRATION_DATABASE_URL"
)

// MigrationFromEnv reads the migration contract.
func MigrationFromEnv() (Migration, error) {
	migration := Migration{AutoMigrate: true, LockWait: DefaultMigrationLockWait}
	if value, ok := os.LookupEnv(EnvAutoMigrate); ok && value != "" {
		switch strings.ToLower(strings.TrimSpace(value)) {
		case "true":
			migration.AutoMigrate = true
		case "false":
			migration.AutoMigrate = false
		default:
			return migration, fmt.Errorf("%s is %q; it is true or false, and a word that is neither "+
				"must not decide whether a serving replica brings the schema forward", EnvAutoMigrate, value)
		}
	}
	migration.Role = strings.TrimSpace(Env(EnvMigrationRole, ""))
	var err error
	if migration.LockWait, err = envExactDuration(EnvMigrationLockWait, migration.LockWait); err != nil {
		return migration, err
	}
	if migration.LockWait <= 0 {
		return migration, fmt.Errorf("%s is %s; a migrator that does not wait for the one already "+
			"running is a migrator that races it", EnvMigrationLockWait, migration.LockWait)
	}
	return migration, nil
}

// envInt32 reads a whole-number setting.
func envInt32(key string, fallback int32) (int32, error) {
	value, ok := os.LookupEnv(key)
	if !ok || strings.TrimSpace(value) == "" {
		return fallback, nil
	}
	parsed, err := strconv.ParseInt(strings.TrimSpace(value), 10, 32)
	if err != nil {
		return fallback, fmt.Errorf("%s is %q, which is not a whole number", key, value)
	}
	return int32(parsed), nil
}

// envExactDuration reads a duration setting and refuses what it cannot
// read, for the same reason as envInt32.
func envExactDuration(key string, fallback time.Duration) (time.Duration, error) {
	value, ok := os.LookupEnv(key)
	if !ok || strings.TrimSpace(value) == "" {
		return fallback, nil
	}
	parsed, err := time.ParseDuration(strings.TrimSpace(value))
	if err != nil {
		return fallback, fmt.Errorf("%s is %q, which is not a duration such as 30s, 15m or 1h", key, value)
	}
	return parsed, nil
}
