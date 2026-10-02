package storage

// pgx pool construction, connection settings and migration execution.
//
// Three decisions here are load-bearing and each one is a security property, not
// a preference:
//
//  1. statement_timeout is set on EVERY connection. Without it a single slow
//     query holds a pool slot indefinitely, and 25 stuck queries exhaust the pool
//     and take down /token for every user. The timeout is a circuit breaker, not
//     a performance tuning knob.
//
//  2. Prepared statement caching is DISABLED. PgBouncer and other poolers in
//     transaction mode multiplex connections, so a prepared statement created on
//     one server connection is missing on the next. With caching on, the second
//     request through the pooler fails with "prepared statement does not exist".
//     Disabling it is what makes this safe to put behind a pooler; the cost is
//     one extra parse per query, which is irrelevant next to a network round trip.
//
//  3. Every query must be given a context with a deadline by its caller. This
//     package cannot enforce that, so the pool is configured to make a missing
//     deadline fail fast (see connect_timeout and statement_timeout) rather than
//     hang. Repositories wrap errors with domain.Wrapf so ErrNotFound and
//     ErrConflict survive for errors.Is.

import (
	"context"
	"errors"
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/golang-migrate/migrate/v4"
	// The pgx/v5 database driver, registered for its side effect. migrate looks
	// this up by the string "pgx5" passed to migrate.NewWithDatabaseInstance
	// or via a source URL scheme.
	_ "github.com/golang-migrate/migrate/v4/database/pgx/v5"
	"github.com/golang-migrate/migrate/v4/source/iofs"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/spf13/viper"

	// Embedded migrations. Using embed rather than reading the directory at
	// runtime means the binary is self-contained: a container that cannot see
	// the migrations directory still starts, and there is no way to run a binary
	// against a schema it does not contain. The embed lives in the migrations
	// package because //go:embed cannot reach a parent directory.
	"oauth-server/migrations"
)

// Config is the subset of configuration this package needs, read from
// config.yaml under the `database` key.
type Config struct {
	// URL is a libpq/pgx connection string. It carries the password, so it must
	// come from the environment in any deployment that is not local development.
	URL string

	MaxConnections int32
	MinConnections int32

	// StatementTimeout is applied to every connection in the pool.
	StatementTimeout time.Duration

	// ConnectTimeout bounds the initial handshake.
	ConnectTimeout time.Duration
}

// LoadConfig reads the database configuration from viper.
//
// Durations are read as integers of MILLISECONDS and converted explicitly.
// Viper parses a bare integer into a time.Duration as nanoseconds, so assigning
// GetInt into a time.Duration field turns a 5000ms timeout into 5 microseconds.
// The same trap is why every *_ttl in config.yaml is a plain integer of seconds
// rather than a duration string.
func LoadConfig(v *viper.Viper) Config {
	return Config{
		URL:              v.GetString("database.url"),
		MaxConnections:   int32(v.GetInt("database.max_connections")),
		MinConnections:   int32(v.GetInt("database.min_connections")),
		StatementTimeout: time.Duration(v.GetInt("database.statement_timeout_ms")) * time.Millisecond,
		ConnectTimeout:   time.Duration(v.GetInt("database.connect_timeout_seconds")) * time.Second,
	}
}

// Pool wraps pgxpool.Pool with the settings this server depends on.
type Pool struct {
	pool *pgxpool.Pool
}

// NewPool builds a pool from cfg and verifies connectivity with a ping.
//
// The ping is not optional. pgx.NewWithConfig succeeds against a database that
// is down, because the pool is lazy; without a ping the first real request
// fails instead, which in a rolling deploy means every instance reports healthy
// and then 500s under load.
func NewPool(ctx context.Context, cfg Config) (*Pool, error) {
	if cfg.URL == "" {
		return nil, errors.New("storage: database.url is empty")
	}

	poolCfg, err := pgxpool.ParseConfig(cfg.URL)
	if err != nil {
		return nil, fmt.Errorf("storage: parse database url: %w", err)
	}

	if cfg.MaxConnections > 0 {
		poolCfg.MaxConns = cfg.MaxConnections
	}
	if cfg.MinConnections > 0 {
		poolCfg.MinConns = cfg.MinConnections
	}

	if cfg.ConnectTimeout > 0 {
		poolCfg.ConnConfig.ConnectTimeout = cfg.ConnectTimeout
	}

	if cfg.StatementTimeout > 0 {
		// Applied in the connection config so it covers every connection the
		// pool opens, including ones opened later to satisfy MinConns. Setting
		// it per session via AfterConnect would work too, but this way it is
		// part of the parsed config and is visible in logs and to the pooler.
		poolCfg.ConnConfig.RuntimeParams["statement_timeout"] =
			strconv.FormatInt(cfg.StatementTimeout.Milliseconds(), 10)
	}

	// See the package comment: this is what makes a pooler safe in front.
	poolCfg.ConnConfig.DefaultQueryExecMode = pgx.QueryExecModeExec

	// Health checks must not queue behind the traffic they are meant to detect
	// trouble in. A longer check interval than the default 30s means a dead
	// connection is noticed sooner.
	poolCfg.HealthCheckPeriod = 30 * time.Second

	pool, err := pgxpool.NewWithConfig(ctx, poolCfg)
	if err != nil {
		return nil, fmt.Errorf("storage: create pool: %w", err)
	}

	pingCtx, cancel := context.WithTimeout(ctx, cfg.ConnectTimeout)
	defer cancel()
	if err := pool.Ping(pingCtx); err != nil {
		pool.Close()
		return nil, fmt.Errorf("storage: ping: %w", err)
	}

	return &Pool{pool: pool}, nil
}

// RunMigrations applies all embedded migrations up to the latest version.
//
// Migrations run at boot rather than as a separate deploy step. The reason is
// ordering: code that expects a column cannot be started before the migration
// that adds it, and a separate step means someone has to remember the order. At
// boot the order is impossible to get wrong, and an instance that cannot migrate
// exits instead of serving traffic against the wrong schema.
//
// ErrNoChange is not an error: it means the database is already current, which
// is the normal case for every instance after the first.
func RunMigrations(ctx context.Context, dbURL string) error {
	if dbURL == "" {
		return errors.New("storage: database.url is empty")
	}
	// golang-migrate has no context-aware entry point, so a cancelled or expired
	// context is checked here rather than discovered after a DDL lock is held.
	// A migration that has already taken an ACCESS EXCLUSIVE lock cannot be
	// abandoned safely, and that is the one failure worth catching early.
	if err := ctx.Err(); err != nil {
		return fmt.Errorf("storage: migrate up: %w", err)
	}

	source, err := iofs.New(migrations.FS, ".")
	if err != nil {
		return fmt.Errorf("storage: open embedded migrations: %w", err)
	}
	// Close errors on the embedded migration source are not actionable: the
	// migration outcome is decided by m.Up below.
	defer func() { _ = source.Close() }()

	// golang-migrate selects a database driver by the SCHEME of the URL it is
	// given, but the pgx/v5 driver is registered under the name "pgx5" and
	// rewrites the scheme to "postgres" itself once it has parsed the URL. The
	// connection string in config.yaml is a libpq URL with a "postgres" scheme,
	// so handing it over unchanged asks golang-migrate for a driver named
	// "postgres", which is not registered by this import. Substituting the
	// scheme is therefore required, and it is a rewrite of the scheme only; the
	// host, credentials, port, database and query parameters are untouched.
	migrationURL, err := migrationDriverURL(dbURL)
	if err != nil {
		return err
	}

	m, err := migrate.NewWithSourceInstance("iofs", source, migrationURL)
	if err != nil {
		return fmt.Errorf("storage: migration driver: %w", err)
	}
	defer func() { _, _ = m.Close() }()

	if err := m.Up(); err != nil && !errors.Is(err, migrate.ErrNoChange) {
		return fmt.Errorf("storage: migrate up: %w", err)
	}
	return nil
}

// migrationDriverURL rewrites a libpq connection URL so golang-migrate selects
// the pgx5 driver.
//
// golang-migrate resolves the database driver from the URL scheme. The driver in
// github.com/golang-migrate/migrate/v4/database/pgx/v5 registers itself as
// "pgx5" and, in its own Open method, sets the scheme back to "postgres" before
// handing the string to database/sql. So the scheme this function writes is the
// driver's registration name and nothing else, and the rest of the URL is passed
// through byte for byte.
//
// Only the two spellings that appear in configuration are handled. Anything else
// is refused rather than guessed at, because a silently mis-parsed URL connects
// to the wrong database and the failure then shows up as missing tables in an
// unrelated part of the system.
func migrationDriverURL(dbURL string) (string, error) {
	switch {
	case strings.HasPrefix(dbURL, "postgres://"):
		return "pgx5://" + strings.TrimPrefix(dbURL, "postgres://"), nil
	case strings.HasPrefix(dbURL, "postgresql://"):
		return "pgx5://" + strings.TrimPrefix(dbURL, "postgresql://"), nil
	default:
		return "", fmt.Errorf("storage: database url scheme is not postgres:// or postgresql://")
	}
}

// GetPool returns the underlying pool for repositories to query.
//
// Repositories take the pgxpool.Pool rather than a custom interface so that the
// transaction and copy APIs are available without a wrapper reimplementing
// them. Test doubles use a real PostgreSQL rather than a mock: the behaviour
// being tested here, conditional updates and unique violations, IS the
// database's behaviour, and a mock would only test the mock.
func (p *Pool) GetPool() *pgxpool.Pool {
	return p.pool
}

// Close releases every pooled connection. Safe to call more than once.
func (p *Pool) Close() {
	if p.pool != nil {
		p.pool.Close()
	}
}
