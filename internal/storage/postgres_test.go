package storage

// Tests for configuration parsing and pool construction.
//
// The pool tests need a live PostgreSQL, so they are skipped unless
// TEST_DATABASE_URL is set. That is deliberate rather than lazy: the behaviour
// worth testing here is the interaction with a real server (does
// statement_timeout actually apply, does a connection to a dead database
// actually fail), and a mock would assert only that the mock was called.

import (
	"context"
	"database/sql"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/spf13/viper"
)

func testDBURL(t *testing.T) string {
	t.Helper()
	url := os.Getenv("TEST_DATABASE_URL")
	if url == "" {
		t.Skip("TEST_DATABASE_URL is not set; skipping PostgreSQL-backed test")
	}
	return url
}

func TestLoadConfigConvertsMilliseconds(t *testing.T) {
	t.Parallel()

	v := viper.New()
	v.Set("database.url", "postgres://u:p@localhost:5432/db")
	v.Set("database.max_connections", 25)
	v.Set("database.min_connections", 5)
	v.Set("database.statement_timeout_ms", 5000)
	v.Set("database.connect_timeout_seconds", 10)

	cfg := LoadConfig(v)

	tests := []struct {
		name string
		got  any
		want any
	}{
		{name: "url", got: cfg.URL, want: "postgres://u:p@localhost:5432/db"},
		{name: "max connections", got: cfg.MaxConnections, want: int32(25)},
		{name: "min connections", got: cfg.MinConnections, want: int32(5)},
		// The point of this test: 5000 must become 5s, not 5us. Viper hands
		// back a bare int, and assigning it straight to a time.Duration
		// multiplies by one nanosecond.
		{name: "statement timeout", got: cfg.StatementTimeout, want: 5 * time.Second},
		{name: "connect timeout", got: cfg.ConnectTimeout, want: 10 * time.Second},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			if tc.got != tc.want {
				t.Errorf("%s = %v, want %v", tc.name, tc.got, tc.want)
			}
		})
	}
}

func TestNewPoolRejectsEmptyURL(t *testing.T) {
	t.Parallel()

	_, err := NewPool(context.Background(), Config{})
	if err == nil {
		t.Fatal("NewPool with an empty URL = nil error, want an error")
	}
	if !strings.Contains(err.Error(), "database.url") {
		t.Errorf("error %q does not mention database.url", err)
	}
}

func TestRunMigrationsRejectsEmptyURL(t *testing.T) {
	t.Parallel()

	if err := RunMigrations(context.Background(), ""); err == nil {
		t.Fatal("RunMigrations with an empty URL = nil, want an error")
	}
}

func TestRunMigrationsHonoursCancelledContext(t *testing.T) {
	t.Parallel()

	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	err := RunMigrations(ctx, testDBURL(t))
	if err == nil {
		t.Fatal("RunMigrations with a cancelled context = nil, want an error")
	}
	if !strings.Contains(err.Error(), "context canceled") {
		t.Errorf("error %q does not mention the cancelled context", err)
	}
}

// No t.Parallel: TestMigrationsApplyAndAreIdempotent drops and recreates the
// public schema, so it must not overlap with any other test touching the same
// database. Running these in parallel meant the schema could disappear between
// this test's pool creation and its query, producing an intermittent failure
// that looks like a pool bug but is a test-ordering bug.
func TestNewPoolAppliesStatementTimeout(t *testing.T) {
	url := testDBURL(t)
	ctx := context.Background()

	pool, err := NewPool(ctx, Config{
		URL:              url,
		MaxConnections:   5,
		MinConnections:   1,
		StatementTimeout: 2 * time.Second,
		ConnectTimeout:   10 * time.Second,
	})
	if err != nil {
		t.Fatalf("NewPool: %v", err)
	}
	defer pool.Close()

	conn, err := pool.GetPool().Acquire(ctx)
	if err != nil {
		t.Fatalf("acquire: %v", err)
	}
	defer conn.Release()

	// Read the setting back from the server rather than from the config we set,
	// so this asserts the value the server actually accepted.
	var timeout string
	if err := conn.QueryRow(ctx, "SHOW statement_timeout").Scan(&timeout); err != nil {
		t.Fatalf("SHOW statement_timeout: %v", err)
	}
	if timeout != "2s" {
		t.Errorf("statement_timeout = %q, want %q", timeout, "2s")
	}
}

func TestNewPoolFailsOnUnreachableDatabase(t *testing.T) {
	t.Parallel()

	// Port 1 is reserved and never listening. The ping must surface this rather
	// than returning a pool that only fails on first use.
	_, err := NewPool(context.Background(), Config{
		URL:            "postgres://oauth:oauth@127.0.0.1:1/oauth?sslmode=disable",
		MaxConnections: 1,
		ConnectTimeout: 2 * time.Second,
	})
	if err == nil {
		t.Fatal("NewPool against a dead database = nil error, want a failure at construction time")
	}
	if !strings.Contains(err.Error(), "ping") {
		t.Errorf("error %q does not mention the ping, so the failure came from somewhere unexpected", err)
	}
}

// resetDatabase drops and recreates the public schema.
//
// This test needs an empty database, and it also needs to leave one behind that
// is exactly what the migrations produce. Running it against a database that
// already has the schema applied by other means fails with "relation already
// exists", because golang-migrate has no way to know the schema is already
// correct when its own bookkeeping table is absent. Truncating public schema is
// destructive, so it is confined to a test that skips without TEST_DATABASE_URL.
func resetDatabase(t *testing.T, db *sql.DB) {
	t.Helper()
	ctx := context.Background()
	if _, err := db.ExecContext(ctx, `DROP SCHEMA public CASCADE; CREATE SCHEMA public;`); err != nil {
		t.Fatalf("reset schema: %v", err)
	}
}

// Destructive: this drops the public schema. It must run serially, after any
// other test that has an open pool against this database.
func TestMigrationsApplyAndAreIdempotent(t *testing.T) {
	url := testDBURL(t)
	ctx := context.Background()

	admin, err := sql.Open("pgx/v5", url)
	if err != nil {
		t.Fatalf("sql.Open: %v", err)
	}
	defer admin.Close()
	resetDatabase(t, admin)

	// Applying twice must be a no-op the second time. If it is not, every
	// additional server instance fails to start.
	if err := RunMigrations(ctx, url); err != nil {
		t.Fatalf("first RunMigrations: %v", err)
	}
	if err := RunMigrations(ctx, url); err != nil {
		t.Fatalf("second RunMigrations: %v, want ErrNoChange to be swallowed: %v", err, err)
	}

	// The schema_migrations bookkeeping table is what makes the second run a
	// no-op, so assert on it rather than on a table count.
	var version int
	var dirty bool
	if err := admin.QueryRow(`SELECT version, dirty FROM schema_migrations LIMIT 1`).Scan(&version, &dirty); err != nil {
		t.Fatalf("read schema_migrations: %v", err)
	}
	if dirty {
		t.Error("schema_migrations.dirty is true, want false; a failed migration was left behind")
	}
	if version < 1 {
		t.Errorf("schema version = %d, want at least 1", version)
	}
}
