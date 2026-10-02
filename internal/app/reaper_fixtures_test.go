package app

// Reaper test fixtures.
//
// Deliberately thin: the only tables the reaper tests insert into are ones with a
// foreign key, so these helpers create the minimum parent rows needed and nothing
// more. All fixtures are unique per call and removed by the caller's t.Cleanup, so
// tests in this package can run in sequence against a shared database without
// colliding.

import (
	"context"
	"fmt"
	"log/slog"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"oauth-server/internal/storage"
)

// reaperTestSchema is the isolated schema the reaper tests operate in.
//
// Isolated for the same reason the integration package isolates: a sweep is a bulk
// DELETE over nine tables, and the storage package's own tests assert on rows in those
// tables. Sharing the schema makes the two packages interfere, and the resulting
// failures look like reaper bugs.
const reaperTestSchema = "oauth_app_test"

// newPoolForReaper builds a migrated pool scoped to the reaper test schema.
func newPoolForReaper(t *testing.T) *pgxpool.Pool {
	t.Helper()

	base := os.Getenv("TEST_DATABASE_URL")
	if base == "" {
		t.Skip("TEST_DATABASE_URL is not set; skipping PostgreSQL-backed test")
	}

	ctx := context.Background()

	// The schema has to exist and the migrations have to run inside it, so this
	// connects to the base URL first, creates the schema, and only then migrates
	// through a search_path-qualified URL. Identifier.Sanitize quotes the name,
	// which matters because the schema is interpolated into DDL where a bare string
	// would be a syntax error at best.
	admin, err := pgx.Connect(ctx, base)
	if err != nil {
		t.Fatalf("connect for schema setup: %v", err)
	}
	ident := pgx.Identifier{reaperTestSchema}.Sanitize()
	if _, err := admin.Exec(ctx, "CREATE SCHEMA IF NOT EXISTS "+ident); err != nil {
		admin.Close(ctx)
		t.Fatalf("create schema: %v", err)
	}
	if _, err := admin.Exec(ctx, "SET search_path TO "+ident); err != nil {
		admin.Close(ctx)
		t.Fatalf("set search_path: %v", err)
	}
	admin.Close(ctx)

	schemaURL := withSearchPath(t, base)
	if err := storage.RunMigrations(ctx, schemaURL); err != nil {
		t.Fatalf("RunMigrations: %v", err)
	}

	pool, err := storage.NewPool(ctx, storage.Config{
		URL:              schemaURL,
		MaxConnections:   5,
		MinConnections:   1,
		StatementTimeout: 10 * time.Second,
		ConnectTimeout:   10 * time.Second,
	})
	if err != nil {
		t.Fatalf("NewPool: %v", err)
	}
	t.Cleanup(pool.Close)
	return pool.GetPool()
}

// withSearchPath appends a search_path setting to the database URL.
//
// Done through the URL rather than a SET on the pool because pgxpool hands every
// connection to a different backend: a search_path set on one acquired connection does
// not apply to the next checkout, so the migrations would land in the public schema
// while these queries ran against the isolated one.
func withSearchPath(t *testing.T, url string) string {
	t.Helper()

	sep := "?"
	if strings.ContainsAny(url, "?") {
		sep = "&"
	}
	return url + sep + "search_path=" + reaperTestSchema
}

// reaperSeq makes fixture identifiers unique within a test run.
func reaperSeq(t *testing.T, label string) string {
	t.Helper()
	return fmt.Sprintf("%s-%d", label, time.Now().UnixNano())
}

// insertUserForReaper inserts the parent row sessions need.
//
// The password_hash column is NOT NULL but is never read by anything in the reaper
// path, so a fixed placeholder keeps the fixture small. It must still look like a
// hash to any future constraint that starts validating its format.
func insertUserForReaper(t *testing.T, raw *pgxpool.Pool, userID string) {
	t.Helper()
	ctx := context.Background()
	_, err := raw.Exec(ctx, `
		INSERT INTO users (user_id, email, password_hash, email_verified)
		VALUES ($1, $2, $3, TRUE)`,
		userID, userID+"@reaper.invalid",
		"$argon2id$v=19$m=65536,t=3,p=1$reaperfixture$reaperfixture")
	if err != nil {
		t.Fatalf("insert user: %v", err)
	}
	t.Cleanup(func() {
		_, _ = raw.Exec(context.Background(), `DELETE FROM users WHERE user_id = $1`, userID)
	})
}

// insertSessionForUserForReaper inserts a session under an existing user and returns its ID.
//
// expires_at and absolute_expires_at are both set from at: the idle deadline first,
// the hard ceiling an hour later. sessions_expiry_order_chk enforces
// absolute_expires_at > expires_at, so passing one timestamp twice would be rejected.
func insertSessionForUserForReaper(t *testing.T, raw *pgxpool.Pool, userID string, expiresAt time.Time) string {
	t.Helper()
	ctx := context.Background()

	sessionID := reaperSeq(t, "session")
	_, err := raw.Exec(ctx, `
		INSERT INTO sessions (
			session_id, user_id, auth_time,
			expires_at, absolute_expires_at,
			acr, amr
		) VALUES ($1, $2, now(), $3, $4, 'aal1', ARRAY['pwd'])`,
		sessionID, userID, expiresAt, expiresAt.Add(time.Hour))
	if err != nil {
		t.Fatalf("insert session: %v", err)
	}
	return sessionID
}

// sessionExists reports whether a session row is still present.
func sessionExists(t *testing.T, raw *pgxpool.Pool, sessionID string) bool {
	t.Helper()
	var one int
	err := raw.QueryRow(context.Background(),
		`SELECT 1 FROM sessions WHERE session_id = $1`, sessionID).Scan(&one)
	if err == nil {
		return true
	}
	if err == pgx.ErrNoRows {
		return false
	}
	t.Fatalf("check session: %v", err)
	return false
}

// countSessionsForUser counts a single user's sessions.
//
// Scoped by user rather than counting the table, so a row left behind by another test
// in this schema cannot make an unrelated assertion fail.
func countSessionsForUser(t *testing.T, raw *pgxpool.Pool, userID string) int {
	t.Helper()
	var n int
	err := raw.QueryRow(context.Background(),
		`SELECT count(*) FROM sessions WHERE user_id = $1`, userID).Scan(&n)
	if err != nil {
		t.Fatalf("count sessions: %v", err)
	}
	return n
}

// newTestLogger returns a logger that discards output.
//
// The reaper logs at Info and Error. Discarding keeps test output clean without
// suppressing the failure itself, which the test asserts on directly.
func newTestLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(discardWriter{}, nil))
}

type discardWriter struct{}

func (discardWriter) Write(p []byte) (int, error) { return len(p), nil }
