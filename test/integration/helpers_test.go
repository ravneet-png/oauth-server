// Container lifecycle, application construction against the real router, HTTP helpers and database assertions for the integration suite.

package integration

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"net/url"
	"os"
	"regexp"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"oauth-server/internal/app"
	"oauth-server/internal/config"
	"oauth-server/internal/storage"
)

// The services are the ones docker-compose.yml starts; the defaults match it so a
// developer with the stack up runs the suite with no environment at all.
func envOr(name, fallback string) string {
	if v := os.Getenv(name); v != "" {
		return v
	}
	return fallback
}

var (
	testDBURL    = envOr("TEST_DATABASE_URL", "postgres://oauth:oauth@localhost:5432/oauth?sslmode=disable")
	testRedisURL = envOr("TEST_REDIS_URL", "redis://localhost:6379/0")

	// The suite gets its own schema inside the same database.
	//
	// `go test ./...` runs package binaries in parallel, and internal/storage's tests
	// write to the same tables this suite truncates between every test. Sharing the
	// public schema means whichever package truncates last decides whether the other's
	// rows still exist, which shows up as a different flaky failure per run. A separate
	// schema keeps one server and one set of migrations, and makes the interference
	// impossible rather than unlikely.
	testSchema = envOr("TEST_DB_SCHEMA", "oauth_integration_test")

	// Migrations run once per test binary. They are idempotent, but running them per
	// test would serialise every test behind a schema lock and turn a fast suite into a
	// slow one for no coverage gain.
	migrateOnce sync.Once
	migrateErr  error
)

// testDBURLInSchema returns testDBURL with search_path pointed at the suite's schema.
func testDBURLInSchema() (string, error) {
	parsed, err := url.Parse(testDBURL)
	if err != nil {
		return "", fmt.Errorf("parse %s: %w", testDBURL, err)
	}
	q := parsed.Query()
	q.Set("search_path", testSchema)
	parsed.RawQuery = q.Encode()
	return parsed.String(), nil
}

// ensureTestSchema creates the suite's schema.
//
// Done on the default search_path: pointing search_path at a schema that does not exist
// yet would leave every unqualified CREATE in the migrations looking for a table in a
// missing schema, and creating it is one statement.
func ensureTestSchema(ctx context.Context) error {
	conn, err := pgx.Connect(ctx, testDBURL)
	if err != nil {
		return fmt.Errorf("connect for schema creation: %w", err)
	}
	defer func() { _ = conn.Close(ctx) }()

	_, err = conn.Exec(ctx, "CREATE SCHEMA IF NOT EXISTS "+pgx.Identifier{testSchema}.Sanitize())
	return err
}

// truncateOrder lists every table that carries test state.
//
// signing_keys is deliberately absent: regenerating an RSA key per test costs more than
// the whole suite and proves nothing, and no test asserts on an empty key table.
const truncateSQL = `TRUNCATE clients, users, sessions, client_sessions, token_families,
	auth_codes, refresh_tokens, issued_access_tokens, revoked_tokens, par_requests,
	auth_requests, consents, mfa_backup_codes, email_verifications, audit_log CASCADE`

// env is one constructed server plus the handles a test needs to arrange data and assert
// on it.
type env struct {
	t      *testing.T
	App    *app.App
	Server *httptest.Server
	Client *http.Client
	DB     *pgxpool.Pool
}

// newEnv builds the application against the real router and an httptest server.
//
// The server is the production router with the production middleware chain, not a
// reduced one. A test that mounts handlers directly skips CSRF, session resolution and
// header policy, which are exactly the layers the integration suite exists to cover.
func newEnv(t *testing.T) *env {
	t.Helper()

	migrateOnce.Do(func() {
		if err := ensureTestSchema(context.Background()); err != nil {
			migrateErr = err
			return
		}
		schemaURL, err := testDBURLInSchema()
		if err != nil {
			migrateErr = err
			return
		}
		migrateErr = runMigrations(context.Background(), schemaURL)
		if migrateErr != nil {
			return
		}
		// Clear the signing keys once, at migration time, rather than per test.
		//
		// This table is special: a row is encrypted under the key material in
		// testSecrets, so a row left by an earlier run with different material cannot
		// be decrypted and would fail every test at boot. Truncating once here lets
		// the first test generate a key that all tests in this binary share, so an
		// RSA key is generated once instead of once per test.
		pool, err := pgxpool.New(context.Background(), schemaURL)
		if err != nil {
			migrateErr = err
			return
		}
		defer pool.Close()
		if _, err := pool.Exec(context.Background(), "TRUNCATE signing_keys CASCADE"); err != nil {
			migrateErr = err
			return
		}
	})
	if migrateErr != nil {
		t.Fatalf("migrate: %v", migrateErr)
	}

	application, err := app.New(context.Background(), app.Options{
		Config:  testConfig(),
		Secrets: testSecrets(),
		Logger:  testLogger(t),
	})
	if err != nil {
		t.Fatalf("app.New: %v", err)
	}

	jar, err := cookiejar.New(nil)
	if err != nil {
		t.Fatalf("cookie jar: %v", err)
	}

	srv := httptest.NewServer(application.Router)
	e := &env{
		t:      t,
		App:    application,
		Server: srv,
		DB:     application.Pool.GetPool(),
		Client: &http.Client{
			Jar: jar,
			// Redirects are asserted on rather than followed. Following them
			// automatically hides the status code and Location the flow is
			// defined by, so a broken redirect chain still looks green.
			CheckRedirect: func(*http.Request, []*http.Request) error {
				return http.ErrUseLastResponse
			},
			Timeout: 20 * time.Second,
		},
	}

	t.Cleanup(func() {
		srv.Close()
		application.Close()
	})

	e.reset()
	return e
}

// reset empties the database and Redis so each test starts from a known state.
func (e *env) reset() {
	e.t.Helper()
	if _, err := e.DB.Exec(context.Background(), truncateSQL); err != nil {
		e.t.Fatalf("truncate: %v", err)
	}
	if err := e.App.Cache.Raw().FlushDB(context.Background()).Err(); err != nil {
		e.t.Fatalf("flush redis: %v", err)
	}
}

// url builds an absolute URL for a path on the test server.
func (e *env) url(path string) string { return e.Server.URL + path }

// response pairs an http.Response with the body bytes.
//
// The body is read once, at send time, and kept. Reading it lazily means whichever
// assertion ran first consumed it and every later one saw an empty string, which reads
// as an empty response from the server rather than as a test bug.
type response struct {
	*http.Response
	raw []byte
}

// do sends a request and returns the response with its body already read.
func (e *env) do(req *http.Request) *response {
	e.t.Helper()
	resp, err := e.Client.Do(req)
	if err != nil {
		e.t.Fatalf("%s %s: %v", req.Method, req.URL.Path, err)
	}
	b, err := io.ReadAll(resp.Body)
	if err != nil {
		e.t.Fatalf("read body: %v", err)
	}
	_ = resp.Body.Close()
	resp.Body = io.NopCloser(bytes.NewReader(b))
	return &response{Response: resp, raw: b}
}

func (e *env) get(path string) *response {
	e.t.Helper()
	req, _ := http.NewRequest(http.MethodGet, e.url(path), nil)
	return e.do(req)
}

func (e *env) postForm(path string, form url.Values) *response {
	e.t.Helper()
	req, _ := http.NewRequest(http.MethodPost, e.url(path), strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	return e.do(req)
}

// getBearer sends a GET carrying an Authorization: Bearer header.
func (e *env) getBearer(path, token string) *response {
	e.t.Helper()
	req, _ := http.NewRequest(http.MethodGet, e.url(path), nil)
	req.Header.Set("Authorization", "Bearer "+token)
	return e.do(req)
}

// postFormBasic posts a form with HTTP Basic client authentication.
func (e *env) postFormBasic(path string, form url.Values, clientID, secret string) *response {
	e.t.Helper()
	req, _ := http.NewRequest(http.MethodPost, e.url(path), strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.SetBasicAuth(clientID, secret)
	return e.do(req)
}

// body returns the response body as a string.
func body(t *testing.T, resp *response) string {
	t.Helper()
	return string(resp.raw)
}

// decodeJSON decodes the response body into dst.
func decodeJSON(t *testing.T, resp *response, dst any) {
	t.Helper()
	if err := json.Unmarshal(resp.raw, dst); err != nil {
		t.Fatalf("decode JSON (status %d): %v; body=%s", resp.StatusCode, err, body(t, resp))
	}
}

// hiddenInput extracts the value of a hidden form field from a rendered page.
//
// Read out of the HTML rather than out of the CSRF cookie: the cookie is the state, the
// token is what the form must echo back, and using the cookie would make the test pass
// without ever exercising the field the server actually checks.
func hiddenInput(t *testing.T, resp *response, name string) string {
	t.Helper()
	re := regexp.MustCompile(`name="` + regexp.QuoteMeta(name) + `"\s+value="([^"]*)"`)
	m := re.FindStringSubmatch(body(t, resp))
	if m == nil {
		t.Fatalf("no hidden input %q in page (status %d)", name, resp.StatusCode)
	}
	return m[1]
}

// location returns the Location header.
func location(t *testing.T, resp *response) string {
	t.Helper()
	loc := resp.Header.Get("Location")
	if loc == "" {
		t.Fatalf("no Location header on %d response", resp.StatusCode)
	}
	return loc
}

// testConfig is a complete, valid configuration for the local stack.
//
// Built as a literal rather than loaded from config.yaml so a test does not depend on
// the checked-in example staying parseable, and so a change to the example cannot
// silently change what the suite exercises.
func testConfig() *config.Config {
	schemaURL, err := testDBURLInSchema()
	if err != nil {
		panic("integration database URL: " + err.Error())
	}
	return &config.Config{
		Env: "test",
		Server: config.ServerConfig{
			Host:   "127.0.0.1",
			Port:   0,
			Issuer: "http://localhost:8080",
		},
		Database: config.DatabaseConfig{
			URL:                   schemaURL,
			MaxConnections:        10,
			MinConnections:        1,
			StatementTimeoutMS:    5000,
			ConnectTimeoutSeconds: 10,
		},
		Redis: config.RedisConfig{
			URL:                         testRedisURL,
			RevocationTTLPaddingSeconds: 60,
			FailClosedOnIntrospection:   true,
		},
		Tokens: config.TokensConfig{
			AccessTTLSeconds:            900,
			RefreshIdleTTLSeconds:       2592000,
			RefreshAbsoluteTTLSeconds:   7776000,
			ClientCredentialsTTLSeconds: 900,
			IDTokenTTLSeconds:           900,
			AuthorizationCodeTTLSeconds: 600,
			PARTTLSeconds:               60,
			AuthRequestTTLSeconds:       900,
			EmailVerificationTTLSeconds: 86400,
			MFAPendingTTLSeconds:        300,
		},
		Keys: config.KeysConfig{
			Algorithm:        "RS256",
			KeySize:          2048,
			RotationDays:     30,
			RetentionHours:   48,
			ClockSkewSeconds: 60,
		},
		// Rate limiting is off for the suite. Leaving it on would make tests that
		// deliberately repeat a request flaky, and the limiter has its own tests.
		RateLimit: config.RateLimitConfig{Enabled: false},
		Security: config.SecurityConfig{
			PasswordMinLength: 12,
			Argon2: config.Argon2Config{
				MemoryKiB:   65536,
				Iterations:  3,
				Parallelism: 4,
				SaltLength:  16,
				KeyLength:   32,
			},
			HighEntropyHash:               "sha256",
			MFAIssuer:                     "OAuth Server Test",
			MFASkewStep:                   0,
			SessionIdleTimeoutSeconds:     3600,
			SessionAbsoluteTimeoutSeconds: 86400,
			SessionCookieName:             "oauth_session",
			SessionCookieSecure:           false,
			SessionCookieSameSite:         "Lax",
			AllowedInternalPaths:          []string{"/authorize", "/consent", "/mfa", "/login", "/verify-email"},
		},
		Registration: config.RegistrationConfig{ClientRegistrationEnabled: false},
		Email: config.EmailConfig{
			SMTPHost:                 "localhost",
			SMTPPort:                 1025,
			FromAddress:              "noreply@localhost",
			FromName:                 "OAuth Server",
			EnumerationSafeResponses: true,
		},
		Backchannel: config.BackchannelConfig{
			MaxAttempts:    3,
			TimeoutSeconds: 5,
		},
		Audit:   config.AuditConfig{RetainDays: 400},
		Logging: config.LoggingConfig{Level: "error", Format: "text"},
	}
}

// testSecrets supplies 32-byte key material. Fixed rather than random so a failure that
// depends on a key is reproducible.
func testSecrets() config.Secrets {
	key := make([]byte, 32)
	for i := range key {
		key[i] = byte(i + 1)
	}
	pepper := make([]byte, 32)
	for i := range pepper {
		pepper[i] = byte(0xff - i)
	}
	return config.Secrets{
		KeyEncryptionKey: key,
		AuditPepper:      pepper,
	}
}

// runMigrations applies the embedded schema.
func runMigrations(ctx context.Context, databaseURL string) error {
	return storage.RunMigrations(ctx, databaseURL)
}

// testLogger writes error-level records to stderr so a handler that fails with a 500
// leaves a reason behind. Discarding everything, as is tempting, turns every server-side
// failure into a bare "status = 500" that has to be reproduced with a debugger.
func testLogger(t *testing.T) *slog.Logger {
	t.Helper()
	return slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelError}))
}
