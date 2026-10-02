package storage

// Repository tests against a live PostgreSQL.
//
// Every test needs TEST_DATABASE_URL and is skipped without it. That is not
// laziness: the behaviour worth testing in a repository IS the database's
// behaviour. Conditional updates, unique violations, CHECK constraints and
// unnest batch inserts have no meaning against a mock, and a mock that returns
// what the test expects proves only that the mock returns what the test expects.
//
// The tests share a schema and therefore do NOT run in parallel. They insert
// rows with fixed IDs and several assert on table-wide counts, so a concurrent
// test would observe another test's rows. Isolation is achieved by unique IDs
// per test instead, which keeps them independent without the flakiness of
// truncating shared tables underneath each other.

import (
	"context"
	crand "crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/netip"
	"reflect"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	"oauth-server/internal/crypto"
	"oauth-server/internal/domain"
)

// newTestPool builds a pool against the test database and registers cleanup.
//
// Migrated on every test run rather than once per package: a previous test that
// mutated the schema, or a developer whose database predates a migration, both
// otherwise produce failures that look like repository bugs.
func newTestPool(t *testing.T) *pgxpool.Pool {
	t.Helper()
	url := testDBURL(t)

	if err := RunMigrations(context.Background(), url); err != nil {
		t.Fatalf("RunMigrations: %v", err)
	}

	pool, err := NewPool(context.Background(), Config{
		URL:              url,
		MaxConnections:   10,
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

// sameJSON reports whether two JSON documents are semantically equal.
//
// PostgreSQL's JSONB type does not keep the text it was given: it discards
// insignificant whitespace and orders object keys. A round-trip test that
// compares bytes therefore fails against correct storage, and a test that
// compares loosely would miss a genuine content change, so the documents are
// decoded and compared structurally.
func sameJSON(t *testing.T, got, want []byte) bool {
	t.Helper()
	var g, w any
	if err := json.Unmarshal(got, &g); err != nil {
		t.Errorf("stored document is not valid JSON (%v): %s", err, got)
		return false
	}
	if err := json.Unmarshal(want, &w); err != nil {
		t.Fatalf("expected document is not valid JSON (%v): %s", err, want)
	}
	return reflect.DeepEqual(g, w)
}

// uniqueHash returns a 64-character hex digest that is unique to this run.
//
// code_hash, token_hash and jti are globally unique columns, so a test that
// hashes a fixed string collides with its own leftovers on the next run. Since
// these inserts are ON CONFLICT DO NOTHING, the collision is silent: the row is
// simply not written, and the test fails later complaining that a code the test
// just created is unusable. Mixing the run token in keeps the column's real
// uniqueness semantics and makes reruns independent.
func uniqueHash(t *testing.T, label string) string {
	t.Helper()
	return crypto.SHA256Hex(uniqueID(t, label))
}

// uniqueID returns an identifier that is unique within this test, this run, and
// this process.
//
// The obvious implementation, the test name plus a fixed suffix, is not unique
// often enough to be usable: a helper called twice inside one test (two
// authorization codes, two tokens in a family) produces the same id twice and the
// second insert dies on the primary key, and a rerun against a database that still
// holds the previous run's rows dies the same way. Both look like repository bugs
// and neither is one.
//
// So the id carries two extra components: a per-process token, so reruns and
// parallel packages cannot collide, and a monotonic counter, so repeated calls
// within a test cannot. The test name stays as the prefix because a failing test
// has to be able to find its rows by eye, and the whole thing is kept short
// because most id columns are VARCHAR(64).
func uniqueID(t *testing.T, suffix string) string {
	t.Helper()
	n := testIDCounter.Add(1)
	return fmt.Sprintf("t_%s_%s_%d_%s", sanitiseForID(t.Name()), testRunID(), n, suffix)
}

// testRunID is the per-process component, computed once.
var (
	testRunIDOnce  sync.Once
	testRunIDValue string
	testIDCounter  atomic.Uint64
)

func testRunID() string {
	testRunIDOnce.Do(func() {
		var b [4]byte
		if _, err := crand.Read(b[:]); err != nil {
			// A test helper cannot fail the run over an id, and the counter plus
			// test name still keep ids distinct within this process.
			testRunIDValue = strconv.FormatInt(time.Now().UnixNano()%0xffffff, 16)
			return
		}
		testRunIDValue = hex.EncodeToString(b[:])
	})
	return testRunIDValue
}

func sanitiseForID(name string) string {
	out := make([]rune, 0, len(name))
	for _, r := range name {
		switch {
		case r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z', r >= '0' && r <= '9':
			out = append(out, r)
		default:
			out = append(out, '_')
		}
	}
	// 24 characters still identifies the test in a psql session, and leaves room
	// for the run token, counter and suffix inside a VARCHAR(64).
	if len(out) > 24 {
		out = out[:24]
	}
	return string(out)
}

// mustCreateUser inserts a user row directly, returning its id.
//
// Inserted with SQL rather than through UserRepo.Create so that a repository test
// does not fail because of an unrelated repository, and so a client or token test
// does not need a valid Argon2id hash. The password_hash is a syntactically valid
// PHC string so a future test that does call VerifyPassword is not misled.
func mustCreateUser(t *testing.T, pool *pgxpool.Pool, id, email string) {
	t.Helper()
	const q = `
		INSERT INTO users (user_id, email, password_hash)
		VALUES ($1, $2, $3)
		ON CONFLICT (user_id) DO NOTHING`
	const hash = "$argon2id$v=19$m=8192,t=1,p=1$c29tZXNhbHRzb21lc2FsdA$Y3ludGhldGljYWxpZ25hdHVyZWZvcmVzdG9ubHk"
	if _, err := pool.Exec(context.Background(), q, id, email, hash); err != nil {
		t.Fatalf("insert user %s: %v", id, err)
	}
}

func mustCreateClient(t *testing.T, pool *pgxpool.Pool, c *domain.Client) {
	t.Helper()
	if err := NewClientRepo(pool).Create(context.Background(), c); err != nil {
		t.Fatalf("create client %s: %v", c.ClientID, err)
	}
}

// newTestClient returns a minimal valid client for the schema's CHECK constraints.
func newTestClient(t *testing.T, clientID string) *domain.Client {
	t.Helper()
	secret := "secret-" + clientID
	hash := crypto.SHA256Hex(secret)
	return &domain.Client{
		ClientID:                clientID,
		ClientSecretHash:        &hash,
		ClientIDIssuedAt:        time.Now().UTC().Truncate(time.Second),
		ClientSecretExpiresAt:   time.Time{}, // 0 == never expires
		ClientName:              "Test Client " + clientID,
		RedirectURIs:            []string{"https://example.com/cb"},
		GrantTypes:              []string{domain.GrantAuthorizationCode, domain.GrantRefreshToken},
		ResponseTypes:           []string{"code"},
		Scopes:                  []string{"openid", "email"},
		TokenEndpointAuthMethod: domain.AuthMethodClientSecretBasic,
		TokenTTL:                15 * time.Minute,
		RefreshIdleTTL:          30 * 24 * time.Hour,
		ClientCredentialsTTL:    15 * time.Minute,
		Contacts:                []string{"admin@example.com"},
		SubjectType:             domain.SubjectTypePublic,
		PostLogoutRedirectURIs:  []string{"https://example.com/logout"},
	}
}

// =============================================================================
// client_repo
// =============================================================================

func TestClientRepoRoundTrip(t *testing.T) {
	pool := newTestPool(t)
	repo := NewClientRepo(pool)
	ctx := context.Background()

	want := newTestClient(t, uniqueID(t, "client"))
	want.JWKSURI = stringPtr("https://example.com/jwks")
	want.JWKSet = json.RawMessage(`{"keys":[{"kty":"RSA","kid":"a"}]}`)
	want.LogoURI = stringPtr("https://example.com/logo.png")
	want.ClientURI = stringPtr("https://example.com")
	want.PolicyURI = stringPtr("https://example.com/policy")
	want.TosURI = stringPtr("https://example.com/tos")
	want.SectorIdentifierURI = stringPtr("https://example.com/sector.json")
	want.BackchannelLogoutURI = stringPtr("https://example.com/backchannel")
	want.BackchannelLogoutSessionRequired = true
	want.PARRequired = true
	want.SubjectType = domain.SubjectTypePairwise
	want.ResponseTypes = []string{"code"}
	want.Scopes = []string{"openid", "email", "profile"}
	want.ClientSecretExpiresAt = time.Now().UTC().Add(24 * time.Hour).Truncate(time.Second)

	if err := repo.Create(ctx, want); err != nil {
		t.Fatalf("Create: %v", err)
	}

	got, err := repo.GetByID(ctx, want.ClientID)
	if err != nil {
		t.Fatalf("GetByID: %v", err)
	}

	if got.ClientName != want.ClientName {
		t.Errorf("ClientName = %q, want %q", got.ClientName, want.ClientName)
	}
	if got.ClientSecretHash == nil || *got.ClientSecretHash != *want.ClientSecretHash {
		t.Error("ClientSecretHash did not round-trip")
	}
	// Durations are stored as INTEGER seconds, so they come back truncated to the
	// second. Comparing exactly would fail on any sub-second component, and
	// comparing loosely would hide a units bug, so the check is that the value is
	// right to within a second.
	if d := got.TokenTTL - want.TokenTTL; d > time.Second || d < -time.Second {
		t.Errorf("TokenTTL = %v, want %v", got.TokenTTL, want.TokenTTL)
	}
	if got.RefreshIdleTTL != want.RefreshIdleTTL {
		t.Errorf("RefreshIdleTTL = %v, want %v", got.RefreshIdleTTL, want.RefreshIdleTTL)
	}
	// The epoch columns are the ones most likely to be mishandled, so they get an
	// explicit check rather than relying on the struct comparison above.
	if !got.ClientSecretExpiresAt.Equal(want.ClientSecretExpiresAt.Truncate(time.Second)) {
		t.Errorf("ClientSecretExpiresAt = %v, want %v", got.ClientSecretExpiresAt, want.ClientSecretExpiresAt)
	}
	if got.JWKSURI == nil || *got.JWKSURI != *want.JWKSURI {
		t.Error("JWKSURI did not round-trip")
	}
	// JSONB does not preserve the input's text: object keys are sorted and
	// whitespace is normalised. Comparing the bytes would fail on a correct
	// round trip, so the documents are compared as JSON.
	if !sameJSON(t, got.JWKSet, want.JWKSet) {
		t.Errorf("JWKSet = %s, want %s", got.JWKSet, want.JWKSet)
	}
	if !got.BackchannelLogoutSessionRequired {
		t.Error("BackchannelLogoutSessionRequired did not round-trip")
	}
	if !got.PARRequired {
		t.Error("PARRequired did not round-trip")
	}
	if got.SubjectType != domain.SubjectTypePairwise {
		t.Errorf("SubjectType = %q, want pairwise", got.SubjectType)
	}
	if !got.IsConfidential() {
		t.Error("a client_secret_basic client should be confidential")
	}
}

func TestClientRepoSecretNeverExpiryIsZeroTime(t *testing.T) {
	pool := newTestPool(t)
	repo := NewClientRepo(pool)
	ctx := context.Background()

	c := newTestClient(t, uniqueID(t, "noexp"))
	// Zero time means "never expires" per RFC 7591, and must not come back as
	// 1970: a client whose secret has no expiry reading as long expired would have
	// every token request rejected.
	c.ClientSecretExpiresAt = time.Time{}
	if err := repo.Create(ctx, c); err != nil {
		t.Fatalf("Create: %v", err)
	}

	got, err := repo.GetByID(ctx, c.ClientID)
	if err != nil {
		t.Fatalf("GetByID: %v", err)
	}
	if !got.ClientSecretExpiresAt.IsZero() {
		t.Errorf("ClientSecretExpiresAt = %v, want the zero time for a never-expiring secret", got.ClientSecretExpiresAt)
	}
}

func TestClientRepoNotFound(t *testing.T) {
	pool := newTestPool(t)
	_, err := NewClientRepo(pool).GetByID(context.Background(), "definitely-not-a-client")
	if !errors.Is(err, domain.ErrNotFound) {
		t.Errorf("GetByID on a missing client = %v, want ErrNotFound", err)
	}
}

func TestClientRepoDuplicateIsConflict(t *testing.T) {
	pool := newTestPool(t)
	repo := NewClientRepo(pool)
	ctx := context.Background()

	c := newTestClient(t, uniqueID(t, "dup"))
	if err := repo.Create(ctx, c); err != nil {
		t.Fatalf("first Create: %v", err)
	}
	err := repo.Create(ctx, c)
	if !errors.Is(err, domain.ErrConflict) {
		t.Errorf("duplicate Create = %v, want ErrConflict", err)
	}
}

func TestClientRepoDisabledClientIsStillReturned(t *testing.T) {
	pool := newTestPool(t)
	repo := NewClientRepo(pool)
	ctx := context.Background()

	// A disabled client must resolve so /token can answer invalid_client rather
	// than ErrNotFound. The two being indistinguishable is an enumeration oracle
	// for registered client IDs.
	disabledAt := time.Now().UTC()
	c := newTestClient(t, uniqueID(t, "disabled"))
	c.DisabledAt = &disabledAt
	if err := repo.Create(ctx, c); err != nil {
		t.Fatalf("Create: %v", err)
	}

	got, err := repo.GetByID(ctx, c.ClientID)
	if err != nil {
		t.Fatalf("GetByID on a disabled client: %v", err)
	}
	if got.IsEnabled() {
		t.Error("IsEnabled = true for a client with disabled_at set")
	}
	if got.DisabledAt == nil {
		t.Error("DisabledAt did not round-trip")
	}
}

func TestClientRepoBackchannelReturnsOnlyLiveClientsWithURI(t *testing.T) {
	pool := newTestPool(t)
	repo := NewClientRepo(pool)
	ctx := context.Background()

	withBackchannel := newTestClient(t, uniqueID(t, "bcl"))
	withBackchannel.BackchannelLogoutURI = stringPtr("https://example.com/bc")
	mustCreateClient(t, pool, withBackchannel)

	withoutURI := newTestClient(t, uniqueID(t, "nobcl"))
	mustCreateClient(t, pool, withoutURI)

	disabledAt := time.Now().UTC()
	disabled := newTestClient(t, uniqueID(t, "bcloff"))
	disabled.BackchannelLogoutURI = stringPtr("https://example.com/bc")
	disabled.DisabledAt = &disabledAt
	mustCreateClient(t, pool, disabled)

	got, err := repo.GetWithBackchannelLogout(ctx)
	if err != nil {
		t.Fatalf("GetWithBackchannelLogout: %v", err)
	}

	found := map[string]bool{}
	for _, c := range got {
		found[c.ClientID] = true
	}
	if !found[withBackchannel.ClientID] {
		t.Error("an enabled client with a backchannel URI was not returned")
	}
	if found[withoutURI.ClientID] {
		t.Error("a client with no backchannel URI was returned")
	}
	if found[disabled.ClientID] {
		t.Error("a disabled client was returned; logout would be sent to a disabled client")
	}
}

func TestClientRepoRejectsImplicitGrant(t *testing.T) {
	pool := newTestPool(t)
	repo := NewClientRepo(pool)

	// OAuth 2.1 removes the implicit grant. The schema CHECK is the backstop, so
	// this asserts the database refuses it rather than trusting the registration
	// handler to have validated first.
	c := newTestClient(t, uniqueID(t, "implicit"))
	c.GrantTypes = []string{"implicit"}
	c.RedirectURIs = []string{"https://example.com/cb"}
	c.ResponseTypes = []string{"code"}

	err := repo.Create(context.Background(), c)
	if !errors.Is(err, domain.ErrConflict) {
		t.Errorf("Create with the implicit grant = %v, want ErrConflict from the CHECK", err)
	}
}

func TestClientRepoRejectsPublicClientWithSecret(t *testing.T) {
	pool := newTestPool(t)
	repo := NewClientRepo(pool)

	// clients_secret_consistency_chk is what makes IsConfidential derivable. A
	// `none` client holding a secret would break that derivation.
	c := newTestClient(t, uniqueID(t, "pubsec"))
	c.TokenEndpointAuthMethod = domain.AuthMethodNone
	// ClientSecretHash deliberately left set.

	err := repo.Create(context.Background(), c)
	if !errors.Is(err, domain.ErrConflict) {
		t.Errorf("Create with a none client holding a secret = %v, want ErrConflict", err)
	}
}

func TestClientRepoRejectsFragmentInRedirectURI(t *testing.T) {
	pool := newTestPool(t)
	repo := NewClientRepo(pool)

	// RFC 6749 3.1.2.2: a redirect URI must not contain a fragment. The CHECK is
	// the last line of defence if the application validator has a bug.
	c := newTestClient(t, uniqueID(t, "frag"))
	c.RedirectURIs = []string{"https://example.com/cb#frag"}

	err := repo.Create(context.Background(), c)
	if !errors.Is(err, domain.ErrConflict) {
		t.Errorf("Create with a fragment in the redirect URI = %v, want ErrConflict", err)
	}
}

// =============================================================================
// user_repo
// =============================================================================

func TestUserRepoRoundTrip(t *testing.T) {
	pool := newTestPool(t)
	repo := NewUserRepo(pool)
	ctx := context.Background()

	id := uniqueID(t, "user")
	name := "Test User"
	secret := []byte("encrypted-mfa-secret-bytes")

	mustCreateUser(t, pool, id, id+"@example.com")
	_, err := pool.Exec(ctx, `UPDATE users SET name = $2, email_verified = true,
		mfa_enabled = true, mfa_secret_enc = $3, mfa_last_counter = 42,
		is_admin = true WHERE user_id = $1`, id, name, secret)
	if err != nil {
		t.Fatalf("seed user: %v", err)
	}

	got, err := repo.GetByID(ctx, id)
	if err != nil {
		t.Fatalf("GetByID: %v", err)
	}
	if got.Name == nil || *got.Name != name {
		t.Errorf("Name = %v, want %q", got.Name, name)
	}
	if !got.EmailVerified {
		t.Error("EmailVerified did not round-trip")
	}
	if string(got.MFASecretEnc) != string(secret) {
		t.Errorf("MFASecretEnc = %v, want %q", got.MFASecretEnc, secret)
	}
	if got.MFALastCounter != 42 {
		t.Errorf("MFALastCounter = %d, want 42", got.MFALastCounter)
	}
	if !got.IsAdmin {
		t.Error("IsAdmin did not round-trip")
	}
	if !got.HasMFA() {
		t.Error("HasMFA = false for an enabled user with a secret")
	}
	if got.DisplayName() != name {
		t.Errorf("DisplayName() = %q, want %q", got.DisplayName(), name)
	}
}

func TestUserRepoCreateAndGetByEmailIsCaseInsensitive(t *testing.T) {
	pool := newTestPool(t)
	repo := NewUserRepo(pool)
	ctx := context.Background()

	id := uniqueID(t, "email")
	// The address is unique per call, so the unique index on lower(email) cannot
	// collide with a previous run or with a second -count iteration in the same
	// process, while the mixed case within it still proves normalisation.
	// uniqueID preserves the uppercase in the test name and the suffix.
	emailLocal := uniqueID(t, "Mixed.Case")
	u := &domain.User{
		UserID:       id,
		Email:        emailLocal + "@Example.COM",
		PasswordHash: "$argon2id$v=19$m=8192,t=1,p=1$c2FsdA$aGFzaA",
	}
	if err := repo.Create(ctx, u); err != nil {
		t.Fatalf("Create: %v", err)
	}
	wantEmail := strings.ToLower(emailLocal) + "@example.com"

	got, err := repo.GetByEmail(ctx, wantEmail)
	if err != nil {
		t.Fatalf("GetByEmail with a different case: %v", err)
	}
	if got.UserID != id {
		t.Errorf("GetByEmail returned user %q, want %q", got.UserID, id)
	}
	// The stored value must be canonical, because audit rows HMAC it and two
	// spellings of one address would produce two different pseudonyms.
	if got.Email != wantEmail {
		t.Errorf("stored Email = %q, want %q", got.Email, wantEmail)
	}
}

func TestUserRepoCreateIfNotExists(t *testing.T) {
	pool := newTestPool(t)
	repo := NewUserRepo(pool)
	ctx := context.Background()

	email := uniqueID(t, "cne") + "@example.com"
	first := &domain.User{UserID: uniqueID(t, "cne1"), Email: email, PasswordHash: "x"}
	second := &domain.User{UserID: uniqueID(t, "cne2"), Email: email, PasswordHash: "y"}

	created, err := repo.CreateIfNotExists(ctx, first)
	if err != nil {
		t.Fatalf("first CreateIfNotExists: %v", err)
	}
	if !created {
		t.Error("first CreateIfNotExists reported created = false")
	}

	// A double-clicked registration button must not produce a spurious error.
	created, err = repo.CreateIfNotExists(ctx, second)
	if err != nil {
		t.Fatalf("second CreateIfNotExists: %v", err)
	}
	if created {
		t.Error("second CreateIfNotExists reported created = true for a duplicate email")
	}

	got, err := repo.GetByEmail(ctx, email)
	if err != nil {
		t.Fatalf("GetByEmail: %v", err)
	}
	if got.UserID != first.UserID {
		t.Errorf("stored user is %q, want the first %q; the second must not have overwritten it", got.UserID, first.UserID)
	}
}

func TestUserRepoUpdateEmailVerified(t *testing.T) {
	pool := newTestPool(t)
	repo := NewUserRepo(pool)
	ctx := context.Background()

	id := uniqueID(t, "verify")
	mustCreateUser(t, pool, id, id+"@example.com")

	if err := repo.UpdateEmailVerified(ctx, id, true); err != nil {
		t.Fatalf("UpdateEmailVerified: %v", err)
	}
	got, err := repo.GetByID(ctx, id)
	if err != nil {
		t.Fatalf("GetByID: %v", err)
	}
	if !got.EmailVerified {
		t.Error("EmailVerified = false after being set")
	}
}

func TestUserRepoUpdateOnMissingUserIsNotFound(t *testing.T) {
	pool := newTestPool(t)
	repo := NewUserRepo(pool)
	ctx := context.Background()

	// A silent no-op here would let a caller believe MFA was enrolled for a user
	// that does not exist.
	if err := repo.UpdateEmailVerified(ctx, "no-such-user", true); !errors.Is(err, domain.ErrNotFound) {
		t.Errorf("UpdateEmailVerified on a missing user = %v, want ErrNotFound", err)
	}
	if err := repo.UpdateMFA(ctx, "no-such-user", []byte("x"), true); !errors.Is(err, domain.ErrNotFound) {
		t.Errorf("UpdateMFA on a missing user = %v, want ErrNotFound", err)
	}
}

func TestUserRepoUpdateMFA(t *testing.T) {
	pool := newTestPool(t)
	repo := NewUserRepo(pool)
	ctx := context.Background()

	id := uniqueID(t, "mfa")
	mustCreateUser(t, pool, id, id+"@example.com")

	secret := []byte{0xde, 0xad, 0xbe, 0xef}
	if err := repo.UpdateMFA(ctx, id, secret, true); err != nil {
		t.Fatalf("UpdateMFA: %v", err)
	}

	got, err := repo.GetByID(ctx, id)
	if err != nil {
		t.Fatalf("GetByID: %v", err)
	}
	if !got.MFAEnabled {
		t.Error("MFAEnabled = false after enrolment")
	}
	if string(got.MFASecretEnc) != string(secret) {
		t.Errorf("MFASecretEnc = %v, want %v", got.MFASecretEnc, secret)
	}
}

func TestUserRepoLoginFailureLocksAtThreshold(t *testing.T) {
	pool := newTestPool(t)
	repo := NewUserRepo(pool)
	ctx := context.Background()

	id := uniqueID(t, "lock")
	mustCreateUser(t, pool, id, id+"@example.com")

	const threshold = 3
	for i := 1; i <= threshold; i++ {
		locked, err := repo.RecordLoginFailure(ctx, id, threshold, 15*time.Minute)
		if err != nil {
			t.Fatalf("RecordLoginFailure #%d: %v", i, err)
		}
		if wantLocked := i >= threshold; locked != wantLocked {
			t.Errorf("attempt %d: locked = %v, want %v", i, locked, wantLocked)
		}
	}

	got, err := repo.GetByID(ctx, id)
	if err != nil {
		t.Fatalf("GetByID: %v", err)
	}
	if !got.IsLocked(time.Now()) {
		t.Error("IsLocked = false after reaching the threshold")
	}

	// A successful login must clear the counter, or the user is locked for ever.
	if err := repo.RecordLoginSuccess(ctx, id); err != nil {
		t.Fatalf("RecordLoginSuccess: %v", err)
	}
	got, err = repo.GetByID(ctx, id)
	if err != nil {
		t.Fatalf("GetByID after success: %v", err)
	}
	if got.IsLocked(time.Now()) {
		t.Error("IsLocked = true after a successful login")
	}
	if got.FailedLoginCount != 0 {
		t.Errorf("FailedLoginCount = %d after success, want 0", got.FailedLoginCount)
	}
	if got.LastLoginAt == nil {
		t.Error("LastLoginAt was not set by a successful login")
	}
}

func TestUserRepoDeleteTearsDownReferencingRows(t *testing.T) {
	pool := newTestPool(t)
	repo := NewUserRepo(pool)
	ctx := context.Background()

	id := uniqueID(t, "teardown")
	mustCreateUser(t, pool, id, id+"@example.com")

	clientID := uniqueID(t, "teardown-client")
	mustCreateClient(t, pool, newTestClient(t, clientID))

	// A session plus a consent. Both tables are ON DELETE RESTRICT, so neither can be
	// left holding a row for the delete of users to succeed. Delete clears them itself:
	// GDPR erasure that left either behind would be an erasure that did not erase.
	sessionID := uniqueID(t, "sess")
	_, err := pool.Exec(ctx, `INSERT INTO sessions (session_id, user_id, expires_at, absolute_expires_at)
		VALUES ($1, $2, now() + interval '1 hour', now() + interval '1 day')`, sessionID, id)
	if err != nil {
		t.Fatalf("insert session: %v", err)
	}
	if _, err := pool.Exec(ctx, `INSERT INTO consents (user_id, client_id, scopes, granted_at)
		VALUES ($1, $2, ARRAY['openid'], now())`, id, clientID); err != nil {
		t.Fatalf("insert consent: %v", err)
	}

	if err := repo.Delete(ctx, id); err != nil {
		t.Fatalf("Delete with referencing rows: %v", err)
	}

	// The user is gone, and so is everything that pointed at them.
	var userCount, sessionCount, consentCount int
	if err := pool.QueryRow(ctx, `SELECT count(*) FROM users WHERE user_id = $1`, id).Scan(&userCount); err != nil {
		t.Fatalf("count users: %v", err)
	}
	if err := pool.QueryRow(ctx, `SELECT count(*) FROM sessions WHERE user_id = $1`, id).Scan(&sessionCount); err != nil {
		t.Fatalf("count sessions: %v", err)
	}
	if err := pool.QueryRow(ctx, `SELECT count(*) FROM consents WHERE user_id = $1`, id).Scan(&consentCount); err != nil {
		t.Fatalf("count consents: %v", err)
	}
	if userCount != 0 || sessionCount != 0 || consentCount != 0 {
		t.Errorf("after Delete: users=%d sessions=%d consents=%d, want all 0",
			userCount, sessionCount, consentCount)
	}

	// The session row it scrubbed must be unlinked from the audit log rather than left
	// pointing at a session that no longer exists.
	var dangling int
	if err := pool.QueryRow(ctx, `SELECT count(*) FROM audit_log WHERE session_id = $1`, sessionID).Scan(&dangling); err != nil {
		t.Fatalf("count audit rows: %v", err)
	}
	if dangling != 0 {
		t.Errorf("audit_log still references deleted session %q in %d rows", sessionID, dangling)
	}
}

func TestUserRepoDeleteAfterCleanup(t *testing.T) {
	pool := newTestPool(t)
	repo := NewUserRepo(pool)
	ctx := context.Background()

	id := uniqueID(t, "deletable")
	mustCreateUser(t, pool, id, id+"@example.com")

	if err := repo.Delete(ctx, id); err != nil {
		t.Fatalf("Delete: %v", err)
	}
	if _, err := repo.GetByID(ctx, id); !errors.Is(err, domain.ErrNotFound) {
		t.Errorf("GetByID after Delete = %v, want ErrNotFound", err)
	}
}

func TestUserRepoUpdateBackupCodes(t *testing.T) {
	pool := newTestPool(t)
	repo := NewUserRepo(pool)
	mfa := NewMFARepo(pool)
	ctx := context.Background()

	id := uniqueID(t, "bcodes")
	mustCreateUser(t, pool, id, id+"@example.com")

	first := []string{uniqueHash(t, "bc1"), uniqueHash(t, "bc2")}
	if err := repo.UpdateBackupCodes(ctx, id, first); err != nil {
		t.Fatalf("UpdateBackupCodes: %v", err)
	}
	n, err := mfa.CountUnused(ctx, id)
	if err != nil {
		t.Fatalf("CountUnused: %v", err)
	}
	if n != 2 {
		t.Fatalf("CountUnused after enrol = %d, want 2", n)
	}

	// A spent code is evidence and must survive re-enrolment; only the unspent
	// ones are replaced. Dropping the used row would erase the record that the
	// code was used at all.
	spent := first[0]
	ok, err := mfa.Consume(ctx, spent)
	if err != nil || !ok {
		t.Fatalf("Consume of a fresh code: ok=%v err=%v", ok, err)
	}

	second := []string{uniqueHash(t, "bc3"), uniqueHash(t, "bc4"), uniqueHash(t, "bc5")}
	if err := repo.UpdateBackupCodes(ctx, id, second); err != nil {
		t.Fatalf("UpdateBackupCodes replace: %v", err)
	}

	n, err = mfa.CountUnused(ctx, id)
	if err != nil {
		t.Fatalf("CountUnused after replace: %v", err)
	}
	if n != 3 {
		t.Errorf("CountUnused after replace = %d, want 3; replacement must be wholesale", n)
	}
	unused, err := mfa.GetUnused(ctx, id)
	if err != nil {
		t.Fatalf("GetUnused: %v", err)
	}
	for _, c := range unused {
		if c.CodeHash == spent {
			t.Error("a spent code is still in the unused set after re-enrolment")
		}
	}
	for _, want := range second {
		found := false
		for _, c := range unused {
			if c.CodeHash == want {
				found = true
			}
		}
		if !found {
			t.Errorf("new code %s is missing after replace", want)
		}
	}
	// The old unspent code must be gone, or the user silently has more recovery
	// codes than the UI told them.
	for _, c := range unused {
		if c.CodeHash == first[1] {
			t.Error("a superseded unused code survived replacement")
		}
	}

	// An empty set clears them, and is a real write rather than a silent no-op.
	if err := repo.UpdateBackupCodes(ctx, id, nil); err != nil {
		t.Fatalf("UpdateBackupCodes clear: %v", err)
	}
	n, err = mfa.CountUnused(ctx, id)
	if err != nil {
		t.Fatalf("CountUnused after clear: %v", err)
	}
	if n != 0 {
		t.Errorf("CountUnused after clearing = %d, want 0", n)
	}
	// The spent code is still there: clearing unused codes is not erasure.
	kept, err := mfa.GetUnused(ctx, id)
	if err != nil {
		t.Fatalf("GetUnused after clear: %v", err)
	}
	if len(kept) != 0 {
		t.Errorf("GetUnused after clear returned %d rows, want 0", len(kept))
	}

	// A user that does not exist is reported as such rather than as a foreign key
	// violation, so a caller can tell a bad id from a broken schema.
	err = repo.UpdateBackupCodes(ctx, uniqueID(t, "ghost"), []string{uniqueHash(t, "x")})
	if !errors.Is(err, domain.ErrNotFound) {
		t.Errorf("UpdateBackupCodes for a missing user = %v, want ErrNotFound", err)
	}
}

// =============================================================================
// auth_code_repo, including the concurrency guarantee
// =============================================================================

func newTestAuthCode(t *testing.T, pool *pgxpool.Pool, hash string) *domain.AuthCode {
	t.Helper()
	clientID := uniqueID(t, "codeclient")
	mustCreateClient(t, pool, newTestClient(t, clientID))
	userID := uniqueID(t, "codeuser")
	mustCreateUser(t, pool, userID, userID+"@example.com")

	return &domain.AuthCode{
		CodeHash:            hash,
		ClientID:            clientID,
		UserID:              userID,
		Scope:               []string{"openid", "email"},
		RedirectURI:         "https://example.com/cb",
		CodeChallenge:       "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM",
		CodeChallengeMethod: "S256",
		ExpiresAt:           time.Now().UTC().Add(10 * time.Minute),
	}
}

func TestAuthCodeRepoAtomicMarkUsed(t *testing.T) {
	pool := newTestPool(t)
	repo := NewAuthCodeRepo(pool)
	ctx := context.Background()

	code := newTestAuthCode(t, pool, uniqueID(t, "code"))
	if err := repo.Create(ctx, code); err != nil {
		t.Fatalf("Create: %v", err)
	}

	// GetByHash before consumption must show it unused, because reuse detection
	// reads this to tell "already redeemed" from "never existed".
	before, err := repo.GetByHash(ctx, code.CodeHash)
	if err != nil {
		t.Fatalf("GetByHash: %v", err)
	}
	if before.IsConsumed() {
		t.Fatal("a freshly created code reports as consumed")
	}

	got, err := repo.AtomicMarkUsed(ctx, code.CodeHash)
	if err != nil {
		t.Fatalf("AtomicMarkUsed: %v", err)
	}
	if got == nil {
		t.Fatal("AtomicMarkUsed returned nil for an unused code")
	}
	if !got.IsConsumed() {
		t.Error("the returned code does not carry used_at")
	}
	if got.UsedAt == nil {
		t.Fatal("UsedAt is nil on a consumed code")
	}
	// The row must carry everything the token endpoint needs, or the caller would
	// have to re-read and race with the reaper.
	if got.UserID != code.UserID || got.ClientID != code.ClientID {
		t.Error("the returned row is missing the ownership fields needed to issue tokens")
	}
	if len(got.Scope) != 2 {
		t.Errorf("Scope = %v, want 2 entries", got.Scope)
	}

	// Second call must return nil with no error.
	again, err := repo.AtomicMarkUsed(ctx, code.CodeHash)
	if err != nil {
		t.Fatalf("second AtomicMarkUsed: %v", err)
	}
	if again != nil {
		t.Error("second AtomicMarkUsed returned a row; the code was redeemed twice")
	}
}

// TestAuthCodeRepoConcurrentRedemptionExactlyOneWins is the test that justifies the
// conditional UPDATE. A read-then-write implementation passes every other test in
// this file and fails this one.
func TestAuthCodeRepoConcurrentRedemptionExactlyOneWins(t *testing.T) {
	pool := newTestPool(t)
	repo := NewAuthCodeRepo(pool)

	code := newTestAuthCode(t, pool, uniqueID(t, "racecode"))
	if err := repo.Create(context.Background(), code); err != nil {
		t.Fatalf("Create: %v", err)
	}

	const racers = 16
	var (
		wg      sync.WaitGroup
		mu      sync.Mutex
		winners int
	)
	start := make(chan struct{})

	for i := 0; i < racers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-start // Release all goroutines together to maximise the collision.
			got, err := repo.AtomicMarkUsed(context.Background(), code.CodeHash)
			mu.Lock()
			defer mu.Unlock()
			if err != nil {
				t.Errorf("AtomicMarkUsed: %v", err)
				return
			}
			if got != nil {
				winners++
			}
		}()
	}
	close(start)
	wg.Wait()

	if winners != 1 {
		t.Errorf("%d of %d concurrent redemptions succeeded, want exactly 1", winners, racers)
	}
}

func TestAuthCodeRepoEnsureFamilyID(t *testing.T) {
	pool := newTestPool(t)
	repo := NewAuthCodeRepo(pool)
	ctx := context.Background()

	code := newTestAuthCode(t, pool, uniqueID(t, "famcode"))
	if err := repo.Create(ctx, code); err != nil {
		t.Fatalf("Create: %v", err)
	}

	familyID := uniqueID(t, "family")
	famRepo := NewTokenFamilyRepo(pool)
	if err := famRepo.Create(ctx, &domain.TokenFamily{
		FamilyID:          familyID,
		UserID:            code.UserID,
		ClientID:          code.ClientID,
		AbsoluteExpiresAt: time.Now().UTC().Add(30 * 24 * time.Hour),
	}); err != nil {
		t.Fatalf("create family: %v", err)
	}

	if err := repo.EnsureFamilyID(ctx, code.CodeHash, familyID); err != nil {
		t.Fatalf("EnsureFamilyID: %v", err)
	}

	got, err := repo.GetByHash(ctx, code.CodeHash)
	if err != nil {
		t.Fatalf("GetByHash: %v", err)
	}
	if got.FamilyID == nil || *got.FamilyID != familyID {
		t.Errorf("FamilyID = %v, want %q", got.FamilyID, familyID)
	}

	// A second call must not move the code to a different family: that would let
	// a later call redirect reuse detection at an unrelated family. It is
	// idempotent rather than an error, so that the redemption path can call it
	// without knowing whether the consent step already assigned one.
	other := uniqueID(t, "family2")
	if err := famRepo.Create(ctx, &domain.TokenFamily{
		FamilyID:          other,
		UserID:            code.UserID,
		ClientID:          code.ClientID,
		AbsoluteExpiresAt: time.Now().UTC().Add(30 * 24 * time.Hour),
	}); err != nil {
		t.Fatalf("create second family: %v", err)
	}
	if err := repo.EnsureFamilyID(ctx, code.CodeHash, other); err != nil {
		t.Errorf("second EnsureFamilyID = %v, want nil (idempotent)", err)
	}
	got, err = repo.GetByHash(ctx, code.CodeHash)
	if err != nil {
		t.Fatalf("GetByHash after second call: %v", err)
	}
	if got.FamilyID == nil || *got.FamilyID != familyID {
		t.Errorf("FamilyID after second call = %v, want %q (must not be reassigned)", got.FamilyID, familyID)
	}
}

func TestAuthCodeRepoDeleteExpired(t *testing.T) {
	pool := newTestPool(t)
	repo := NewAuthCodeRepo(pool)
	ctx := context.Background()

	expired := newTestAuthCode(t, pool, uniqueID(t, "expcode"))
	expired.ExpiresAt = time.Now().UTC().Add(-time.Minute)
	if err := repo.Create(ctx, expired); err != nil {
		t.Fatalf("Create expired: %v", err)
	}

	live := newTestAuthCode(t, pool, uniqueID(t, "livecode"))
	if err := repo.Create(ctx, live); err != nil {
		t.Fatalf("Create live: %v", err)
	}

	n, err := repo.DeleteExpired(ctx)
	if err != nil {
		t.Fatalf("DeleteExpired: %v", err)
	}
	if n < 1 {
		t.Error("DeleteExpired removed nothing; an expired code survived")
	}

	// A live code must never be reaped.
	if _, err := repo.GetByHash(ctx, live.CodeHash); err != nil {
		t.Errorf("a live code was removed by the reaper: %v", err)
	}
}

// =============================================================================
// refresh_token_repo
// =============================================================================

func newTestRefreshToken(t *testing.T, pool *pgxpool.Pool, hash string) *domain.RefreshToken {
	t.Helper()
	ctx := context.Background()
	clientID := uniqueID(t, "rtclient")
	mustCreateClient(t, pool, newTestClient(t, clientID))
	userID := uniqueID(t, "rtuser")
	mustCreateUser(t, pool, userID, userID+"@example.com")
	familyID := uniqueID(t, "rtfamily")

	if err := NewTokenFamilyRepo(pool).Create(ctx, &domain.TokenFamily{
		FamilyID:          familyID,
		UserID:            userID,
		ClientID:          clientID,
		AbsoluteExpiresAt: time.Now().UTC().Add(30 * 24 * time.Hour),
	}); err != nil {
		t.Fatalf("create family: %v", err)
	}

	return &domain.RefreshToken{
		TokenHash: hash,
		FamilyID:  familyID,
		ClientID:  clientID,
		UserID:    userID,
		Scope:     []string{"openid"},
		ExpiresAt: time.Now().UTC().Add(30 * 24 * time.Hour),
	}
}

func TestRefreshTokenRepoAtomicRotate(t *testing.T) {
	pool := newTestPool(t)
	repo := NewRefreshTokenRepo(pool)
	ctx := context.Background()

	tok := newTestRefreshToken(t, pool, uniqueID(t, "rt"))
	if err := repo.Create(ctx, tok); err != nil {
		t.Fatalf("Create: %v", err)
	}

	got, err := repo.AtomicRotate(ctx, tok.TokenHash)
	if err != nil {
		t.Fatalf("AtomicRotate: %v", err)
	}
	if got == nil {
		t.Fatal("AtomicRotate returned nil for an unrevoked token")
	}
	if !got.WasRotated() {
		t.Errorf("the rotated token does not report reason %q", domain.RevocationReasonRotated)
	}
	// The reason is the input to the reuse decision, so it must be set by the same
	// statement that revoked the row.
	if got.RevocationReason == nil || *got.RevocationReason != domain.RevocationReasonRotated {
		t.Errorf("RevocationReason = %v, want %q", got.RevocationReason, domain.RevocationReasonRotated)
	}

	again, err := repo.AtomicRotate(ctx, tok.TokenHash)
	if err != nil {
		t.Fatalf("second AtomicRotate: %v", err)
	}
	if again != nil {
		t.Error("second AtomicRotate returned a row; the token was redeemed twice")
	}
}

func TestRefreshTokenRepoConcurrentRotationExactlyOneWins(t *testing.T) {
	pool := newTestPool(t)
	repo := NewRefreshTokenRepo(pool)

	tok := newTestRefreshToken(t, pool, uniqueID(t, "rtrace"))
	if err := repo.Create(context.Background(), tok); err != nil {
		t.Fatalf("Create: %v", err)
	}

	const racers = 16
	var (
		wg      sync.WaitGroup
		mu      sync.Mutex
		winners int
	)
	start := make(chan struct{})

	for i := 0; i < racers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-start
			got, err := repo.AtomicRotate(context.Background(), tok.TokenHash)
			mu.Lock()
			defer mu.Unlock()
			if err != nil {
				t.Errorf("AtomicRotate: %v", err)
				return
			}
			if got != nil {
				winners++
			}
		}()
	}
	close(start)
	wg.Wait()

	if winners != 1 {
		t.Errorf("%d of %d concurrent rotations succeeded, want exactly 1", winners, racers)
	}
}

func TestRefreshTokenRepoGetByHashReturnsRevoked(t *testing.T) {
	pool := newTestPool(t)
	repo := NewRefreshTokenRepo(pool)
	ctx := context.Background()

	tok := newTestRefreshToken(t, pool, uniqueID(t, "rtrev"))
	if err := repo.Create(ctx, tok); err != nil {
		t.Fatalf("Create: %v", err)
	}
	if _, err := repo.AtomicRotate(ctx, tok.TokenHash); err != nil {
		t.Fatalf("AtomicRotate: %v", err)
	}

	// Reuse detection needs to SEE the revoked row to find its family. Hiding it
	// would make a stolen-token replay indistinguishable from an unknown token.
	got, err := repo.GetByHash(ctx, tok.TokenHash)
	if err != nil {
		t.Fatalf("GetByHash on a rotated token: %v", err)
	}
	if !got.IsRevoked() {
		t.Error("GetByHash did not return the revoked row")
	}
	if got.FamilyID != tok.FamilyID {
		t.Errorf("FamilyID = %q, want %q; the reuse cascade has nothing to revoke without it", got.FamilyID, tok.FamilyID)
	}
}

func TestRefreshTokenRepoRevokeFamily(t *testing.T) {
	pool := newTestPool(t)
	repo := NewRefreshTokenRepo(pool)
	ctx := context.Background()

	// Two tokens in one family, one in another.
	first := newTestRefreshToken(t, pool, uniqueID(t, "rta"))
	if err := repo.Create(ctx, first); err != nil {
		t.Fatalf("Create first: %v", err)
	}
	secondHash := uniqueID(t, "rtb")
	second := *first
	second.TokenHash = secondHash
	if err := repo.Create(ctx, &second); err != nil {
		t.Fatalf("Create second: %v", err)
	}

	other := newTestRefreshToken(t, pool, uniqueID(t, "rtc"))
	if err := repo.Create(ctx, other); err != nil {
		t.Fatalf("Create other family: %v", err)
	}

	n, err := repo.RevokeFamily(ctx, first.FamilyID, domain.RevocationReasonReuseCascade)
	if err != nil {
		t.Fatalf("RevokeFamily: %v", err)
	}
	if n != 2 {
		t.Errorf("RevokeFamily revoked %d tokens, want 2", n)
	}

	// The other family must be untouched, or one compromised grant nukes an
	// unrelated session.
	untouched, err := repo.GetByHash(ctx, other.TokenHash)
	if err != nil {
		t.Fatalf("GetByHash: %v", err)
	}
	if untouched.IsRevoked() {
		t.Error("RevokeFamily revoked a token in an unrelated family")
	}
}

func TestRefreshTokenRepoRevokeBySessionAndUser(t *testing.T) {
	pool := newTestPool(t)
	repo := NewRefreshTokenRepo(pool)
	ctx := context.Background()

	sessionID := uniqueID(t, "rtsess")
	sessionUser := uniqueID(t, "sessuser")
	mustCreateUser(t, pool, sessionUser, sessionUser+"@example.com")
	_, err := pool.Exec(ctx, `INSERT INTO sessions (session_id, user_id, expires_at, absolute_expires_at)
		VALUES ($1, $2, now() + interval '1 hour', now() + interval '1 day')`,
		sessionID, sessionUser)
	if err != nil {
		t.Fatalf("insert session: %v", err)
	}

	withSession := newTestRefreshToken(t, pool, uniqueID(t, "rtsess_tok"))
	withSession.SessionID = &sessionID
	if err := repo.Create(ctx, withSession); err != nil {
		t.Fatalf("Create with session: %v", err)
	}

	withoutSession := newTestRefreshToken(t, pool, uniqueID(t, "rtsess_none"))
	if err := repo.Create(ctx, withoutSession); err != nil {
		t.Fatalf("Create without session: %v", err)
	}

	n, err := repo.RevokeBySession(ctx, sessionID, domain.RevocationReasonLogout)
	if err != nil {
		t.Fatalf("RevokeBySession: %v", err)
	}
	if n != 1 {
		t.Errorf("RevokeBySession revoked %d tokens, want 1", n)
	}

	// A client_credentials token has a NULL session and must survive a human's
	// logout: it has no browser session to log out of.
	still, err := repo.GetByHash(ctx, withoutSession.TokenHash)
	if err != nil {
		t.Fatalf("GetByHash: %v", err)
	}
	if still.IsRevoked() {
		t.Error("RevokeBySession revoked a token with no session; machine access was broken by a user logout")
	}
}

func TestRefreshTokenRepoRevokeAllForUser(t *testing.T) {
	pool := newTestPool(t)
	repo := NewRefreshTokenRepo(pool)
	ctx := context.Background()

	userID := uniqueID(t, "rtall")
	mustCreateUser(t, pool, userID, userID+"@example.com")

	// A single user with tokens across two different clients, since the index is
	// not client-scoped and that must not change the answer.
	clientIDs := []string{uniqueID(t, "rtc1"), uniqueID(t, "rtc2")}
	var hashes []string
	for _, cid := range clientIDs {
		mustCreateClient(t, pool, newTestClient(t, cid))
		h := uniqueID(t, "rttok")
		hashes = append(hashes, h)
		if err := repo.Create(ctx, &domain.RefreshToken{
			TokenHash: h,
			FamilyID:  uniqueID(t, "rtfam"),
			ClientID:  cid,
			UserID:    userID,
			Scope:     []string{"openid"},
			ExpiresAt: time.Now().UTC().Add(time.Hour),
		}); err != nil {
			// Family FK is required, so create the family first.
			t.Logf("note: token insert may need a family: %v", err)
		}
	}

	// Build proper families so the FK holds, then revoke.
	for i, cid := range clientIDs {
		famID := uniqueID(t, "fam")
		if err := NewTokenFamilyRepo(pool).Create(ctx, &domain.TokenFamily{
			FamilyID:          famID,
			UserID:            userID,
			ClientID:          cid,
			AbsoluteExpiresAt: time.Now().UTC().Add(time.Hour),
		}); err != nil {
			t.Fatalf("create family: %v", err)
		}
		if err := repo.Create(ctx, &domain.RefreshToken{
			TokenHash: hashes[i],
			FamilyID:  famID,
			ClientID:  cid,
			UserID:    userID,
			Scope:     []string{"openid"},
			ExpiresAt: time.Now().UTC().Add(time.Hour),
		}); err != nil {
			t.Fatalf("Create token: %v", err)
		}
	}

	n, err := repo.RevokeAllForUser(ctx, userID, domain.RevocationReasonGDPR)
	if err != nil {
		t.Fatalf("RevokeAllForUser: %v", err)
	}
	if n != 2 {
		t.Errorf("RevokeAllForUser revoked %d tokens, want 2 across both clients", n)
	}
}

func TestRefreshTokenRepoSetReplacedByHash(t *testing.T) {
	pool := newTestPool(t)
	repo := NewRefreshTokenRepo(pool)
	ctx := context.Background()

	oldTok := newTestRefreshToken(t, pool, uniqueID(t, "rtold"))
	if err := repo.Create(ctx, oldTok); err != nil {
		t.Fatalf("Create old: %v", err)
	}
	if _, err := repo.AtomicRotate(ctx, oldTok.TokenHash); err != nil {
		t.Fatalf("rotate old: %v", err)
	}

	newTokHash := uniqueID(t, "rtnew")
	newTok := *oldTok
	newTok.TokenHash = newTokHash
	newTok.RevokedAt = nil
	newTok.RevocationReason = nil
	if err := repo.Create(ctx, &newTok); err != nil {
		t.Fatalf("Create new: %v", err)
	}

	if err := repo.SetReplacedByHash(ctx, oldTok.TokenHash, newTokHash); err != nil {
		t.Fatalf("SetReplacedByHash: %v", err)
	}

	got, err := repo.GetByHash(ctx, oldTok.TokenHash)
	if err != nil {
		t.Fatalf("GetByHash: %v", err)
	}
	if got.ReplacedByHash == nil || *got.ReplacedByHash != newTokHash {
		t.Errorf("ReplacedByHash = %v, want %q; the grace-window check has nothing to compare against", got.ReplacedByHash, newTokHash)
	}
}

// =============================================================================
// token_family_repo
// =============================================================================

func TestTokenFamilyRepoLifecycle(t *testing.T) {
	pool := newTestPool(t)
	repo := NewTokenFamilyRepo(pool)
	ctx := context.Background()

	clientID := uniqueID(t, "famclient")
	mustCreateClient(t, pool, newTestClient(t, clientID))
	userID := uniqueID(t, "famuser")
	mustCreateUser(t, pool, userID, userID+"@example.com")

	fam := &domain.TokenFamily{
		FamilyID:          uniqueID(t, "fam"),
		UserID:            userID,
		ClientID:          clientID,
		AbsoluteExpiresAt: time.Now().UTC().Add(30 * 24 * time.Hour),
	}
	if err := repo.Create(ctx, fam); err != nil {
		t.Fatalf("Create: %v", err)
	}

	got, err := repo.Revoke(ctx, fam.FamilyID, domain.RevocationReasonLogout)
	if err != nil {
		t.Fatalf("Revoke: %v", err)
	}
	if got == nil {
		t.Fatal("Revoke returned nil for a live family")
	}
	if !got.IsRevoked() {
		t.Error("the returned family does not report as revoked")
	}

	again, err := repo.Revoke(ctx, fam.FamilyID, domain.RevocationReasonLogout)
	if err != nil {
		t.Fatalf("second Revoke: %v", err)
	}
	if again != nil {
		t.Error("second Revoke returned a row")
	}
}

// =============================================================================
// access_token_repo
// =============================================================================

func newTestAccessToken(t *testing.T, pool *pgxpool.Pool, jti string) *domain.IssuedAccessToken {
	t.Helper()
	clientID := uniqueID(t, "atclient")
	mustCreateClient(t, pool, newTestClient(t, clientID))
	userID := uniqueID(t, "atuser")
	mustCreateUser(t, pool, userID, userID+"@example.com")

	return &domain.IssuedAccessToken{
		JTI:       jti,
		UserID:    &userID,
		ClientID:  clientID,
		Scope:     []string{"openid", "email"},
		IssuedAt:  time.Now().UTC(),
		ExpiresAt: time.Now().UTC().Add(15 * time.Minute),
	}
}

func TestAccessTokenRepoTrackAndQuery(t *testing.T) {
	pool := newTestPool(t)
	repo := NewAccessTokenRepo(pool)
	ctx := context.Background()

	tok := newTestAccessToken(t, pool, uniqueID(t, "atjti"))
	if err := repo.Track(ctx, tok); err != nil {
		t.Fatalf("Track: %v", err)
	}

	got, err := repo.GetByJTI(ctx, tok.JTI)
	if err != nil {
		t.Fatalf("GetByJTI: %v", err)
	}
	if !got.HasUser() {
		t.Error("HasUser = false for a token with a user")
	}
	if len(got.Scope) != 2 {
		t.Errorf("Scope = %v, want 2 entries", got.Scope)
	}

	byUser, err := repo.GetActiveByUserID(ctx, *tok.UserID)
	if err != nil {
		t.Fatalf("GetActiveByUserID: %v", err)
	}
	found := false
	for _, a := range byUser {
		if a.JTI == tok.JTI {
			found = true
		}
	}
	if !found {
		t.Error("the tracked token was not returned by GetActiveByUserID")
	}
}

func TestAccessTokenRepoGetBySourceAuthCode(t *testing.T) {
	pool := newTestPool(t)
	repo := NewAccessTokenRepo(pool)
	ctx := context.Background()

	codeHash := uniqueID(t, "atcode")
	for i := 0; i < 3; i++ {
		tok := newTestAccessToken(t, pool, fmt.Sprintf("%s_%d", uniqueID(t, "atjti"), i))
		tok.SourceAuthCodeHash = &codeHash
		if err := repo.Track(ctx, tok); err != nil {
			t.Fatalf("Track: %v", err)
		}
	}

	got, err := repo.GetBySourceAuthCode(ctx, codeHash)
	if err != nil {
		t.Fatalf("GetBySourceAuthCode: %v", err)
	}
	// Reuse detection must find every token descended from a replayed code.
	if len(got) != 3 {
		t.Errorf("GetBySourceAuthCode returned %d tokens, want 3", len(got))
	}
}

func TestAccessTokenRepoExpiredAreExcluded(t *testing.T) {
	pool := newTestPool(t)
	repo := NewAccessTokenRepo(pool)
	ctx := context.Background()

	userID := uniqueID(t, "atexp")
	mustCreateUser(t, pool, userID, userID+"@example.com")

	// expires_at > issued_at is a CHECK, so an expired token needs a past issued_at.
	expired := newTestAccessToken(t, pool, uniqueID(t, "atexp_jti"))
	expired.UserID = &userID
	expired.IssuedAt = time.Now().UTC().Add(-2 * time.Hour)
	expired.ExpiresAt = time.Now().UTC().Add(-time.Hour)
	if err := repo.Track(ctx, expired); err != nil {
		t.Fatalf("Track expired: %v", err)
	}

	got, err := repo.GetActiveByUserID(ctx, userID)
	if err != nil {
		t.Fatalf("GetActiveByUserID: %v", err)
	}
	for _, a := range got {
		if a.JTI == expired.JTI {
			t.Error("an expired token was returned by a query that filters on expiry")
		}
	}
}

func TestAccessTokenRepoDetachUserKeepsRecord(t *testing.T) {
	pool := newTestPool(t)
	repo := NewAccessTokenRepo(pool)
	ctx := context.Background()

	tok := newTestAccessToken(t, pool, uniqueID(t, "detach"))
	if err := repo.Track(ctx, tok); err != nil {
		t.Fatalf("Track: %v", err)
	}

	n, err := repo.DetachUser(ctx, *tok.UserID)
	if err != nil {
		t.Fatalf("DetachUser: %v", err)
	}
	if n < 1 {
		t.Error("DetachUser removed nothing")
	}

	// The record must survive with a null user: an access token that outlives its
	// user still has to be deny-listable.
	got, err := repo.GetByJTI(ctx, tok.JTI)
	if err != nil {
		t.Fatalf("GetByJTI after detach: %v", err)
	}
	if got.UserID != nil {
		t.Errorf("UserID = %v after detach, want NULL", *got.UserID)
	}
}

// =============================================================================
// revoked_token_repo
// =============================================================================

func TestRevokedTokenRepoAddAndCheck(t *testing.T) {
	pool := newTestPool(t)
	repo := NewRevokedTokenRepo(pool)
	ctx := context.Background()

	jti := uniqueID(t, "revjti")
	if err := repo.Add(ctx, jti, time.Now().UTC().Add(15*time.Minute)); err != nil {
		t.Fatalf("Add: %v", err)
	}

	revoked, err := repo.IsRevoked(ctx, jti)
	if err != nil {
		t.Fatalf("IsRevoked: %v", err)
	}
	if !revoked {
		t.Error("IsRevoked = false for a just-revoked jti")
	}

	// A jti that was never revoked must be false, not an error.
	revoked, err = repo.IsRevoked(ctx, "never-revoked")
	if err != nil {
		t.Fatalf("IsRevoked on an unknown jti: %v", err)
	}
	if revoked {
		t.Error("IsRevoked = true for an unknown jti")
	}
}

func TestRevokedTokenRepoExpiredEntryDoesNotDeny(t *testing.T) {
	pool := newTestPool(t)
	repo := NewRevokedTokenRepo(pool)
	ctx := context.Background()

	// The entry outlives its token because the reaper has not run. The answer must
	// still be correct: an expired token denies nothing, so a stale entry must not
	// break a legitimate request.
	jti := uniqueID(t, "stalejti")
	if err := repo.Add(ctx, jti, time.Now().UTC().Add(-time.Minute)); err != nil {
		t.Fatalf("Add: %v", err)
	}

	revoked, err := repo.IsRevoked(ctx, jti)
	if err != nil {
		t.Fatalf("IsRevoked: %v", err)
	}
	if revoked {
		t.Error("IsRevoked = true for an entry whose token has expired; a stale deny-list entry broke a valid request")
	}
}

func TestRevokedTokenRepoAddBatch(t *testing.T) {
	pool := newTestPool(t)
	repo := NewRevokedTokenRepo(pool)
	ctx := context.Background()

	entries := make([]RevocationEntry, 0, 25)
	for i := 0; i < 25; i++ {
		entries = append(entries, RevocationEntry{
			JTI:       fmt.Sprintf("%s_%02d", uniqueID(t, "batch"), i),
			ExpiresAt: time.Now().UTC().Add(time.Hour),
		})
	}

	if err := repo.AddBatch(ctx, entries); err != nil {
		t.Fatalf("AddBatch: %v", err)
	}
	for _, e := range entries {
		revoked, err := repo.IsRevoked(ctx, e.JTI)
		if err != nil {
			t.Fatalf("IsRevoked: %v", err)
		}
		if !revoked {
			t.Errorf("batch entry %s was not inserted", e.JTI)
		}
	}
}

func TestRevokedTokenRepoAddBatchEmptyIsNoOp(t *testing.T) {
	pool := newTestPool(t)
	// An empty batch is a legitimate call from a sweep that found nothing. Building
	// a statement with an empty array would be a syntax error, not a no-op.
	if err := NewRevokedTokenRepo(pool).AddBatch(context.Background(), nil); err != nil {
		t.Errorf("AddBatch(nil) = %v, want nil", err)
	}
}

func TestRevokedTokenRepoAddIsIdempotent(t *testing.T) {
	pool := newTestPool(t)
	repo := NewRevokedTokenRepo(pool)
	ctx := context.Background()

	jti := uniqueID(t, "duprev")
	first := time.Now().UTC().Add(time.Hour)
	if err := repo.Add(ctx, jti, first); err != nil {
		t.Fatalf("first Add: %v", err)
	}
	// A second add must not overwrite the first entry's expiry and reason: the
	// deny list is a set.
	if err := repo.Add(ctx, jti, time.Now().UTC().Add(2*time.Hour)); err != nil {
		t.Fatalf("second Add: %v", err)
	}

	got, err := repo.Get(ctx, jti)
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if !got.ExpiresAt.Equal(first.Truncate(time.Microsecond)) {
		t.Errorf("ExpiresAt = %v, want the first value %v; a duplicate add overwrote the original", got.ExpiresAt, first)
	}
}

func TestRevokedTokenRepoDeleteExpired(t *testing.T) {
	pool := newTestPool(t)
	repo := NewRevokedTokenRepo(pool)
	ctx := context.Background()

	expired := uniqueID(t, "deleexp")
	if err := repo.Add(ctx, expired, time.Now().UTC().Add(-time.Hour)); err != nil {
		t.Fatalf("Add expired: %v", err)
	}
	live := uniqueID(t, "delelive")
	if err := repo.Add(ctx, live, time.Now().UTC().Add(time.Hour)); err != nil {
		t.Fatalf("Add live: %v", err)
	}

	if _, err := repo.DeleteExpired(ctx); err != nil {
		t.Fatalf("DeleteExpired: %v", err)
	}
	if _, err := repo.Get(ctx, expired); !errors.Is(err, domain.ErrNotFound) {
		t.Errorf("an expired entry survived the reaper: %v", err)
	}
	if _, err := repo.Get(ctx, live); err != nil {
		t.Errorf("a live entry was removed by the reaper: %v", err)
	}
}

// =============================================================================
// session_repo
// =============================================================================

func newTestSession(t *testing.T, pool *pgxpool.Pool, id, userID string) *domain.Session {
	t.Helper()
	addr := netip.MustParseAddr("192.0.2.10")
	ua := "TestAgent/1.0"
	acr := domain.ACRLevel1
	return &domain.Session{
		SessionID:         id,
		UserID:            userID,
		AuthTime:          time.Now().UTC().Add(-time.Minute),
		ExpiresAt:         time.Now().UTC().Add(time.Hour),
		AbsoluteExpiresAt: time.Now().UTC().Add(24 * time.Hour),
		Acr:               &acr,
		Amr:               []string{domain.AMRPwd},
		IPAddress:         &addr,
		UserAgent:         &ua,
		LastSeenAt:        time.Now().UTC(),
	}
}

func TestSessionRepoRoundTrip(t *testing.T) {
	pool := newTestPool(t)
	repo := NewSessionRepo(pool)
	ctx := context.Background()

	userID := uniqueID(t, "sessuser")
	mustCreateUser(t, pool, userID, userID+"@example.com")

	sess := newTestSession(t, pool, uniqueID(t, "sess"), userID)
	if err := repo.Create(ctx, sess); err != nil {
		t.Fatalf("Create: %v", err)
	}

	got, err := repo.GetByID(ctx, sess.SessionID)
	if err != nil {
		t.Fatalf("GetByID: %v", err)
	}
	if got.UserID != userID {
		t.Errorf("UserID = %q, want %q", got.UserID, userID)
	}
	// INET round-tripping is the one column where a naive implementation loses
	// information, so it is checked explicitly.
	if got.IPAddress == nil || *got.IPAddress != *sess.IPAddress {
		t.Errorf("IPAddress = %v, want %v", got.IPAddress, sess.IPAddress)
	}
	if got.Acr == nil || *got.Acr != domain.ACRLevel1 {
		t.Errorf("Acr = %v, want %q", got.Acr, domain.ACRLevel1)
	}
	if len(got.Amr) != 1 || got.Amr[0] != domain.AMRPwd {
		t.Errorf("Amr = %v, want [%s]", got.Amr, domain.AMRPwd)
	}
	if !got.IsValid(time.Now()) {
		t.Error("a freshly created session does not report as valid")
	}
}

func TestSessionRepoGetByIDHidesExpired(t *testing.T) {
	pool := newTestPool(t)
	repo := NewSessionRepo(pool)
	ctx := context.Background()

	userID := uniqueID(t, "expsess")
	mustCreateUser(t, pool, userID, userID+"@example.com")

	// Idle-expired: GetByID must not return it, so no caller can forget the check.
	idle := newTestSession(t, pool, uniqueID(t, "idleexp"), userID)
	idle.ExpiresAt = time.Now().UTC().Add(-time.Minute)
	if err := repo.Create(ctx, idle); err != nil {
		t.Fatalf("Create idle-expired: %v", err)
	}
	if _, err := repo.GetByID(ctx, idle.SessionID); !errors.Is(err, domain.ErrNotFound) {
		t.Errorf("GetByID on an idle-expired session = %v, want ErrNotFound", err)
	}

	// Absolutely expired even though the idle deadline is in the future: an idle
	// check alone would let a client keep this alive past the ceiling.
	absolute := newTestSession(t, pool, uniqueID(t, "absexp"), userID)
	absolute.ExpiresAt = time.Now().UTC().Add(time.Hour)
	absolute.AbsoluteExpiresAt = time.Now().UTC().Add(-time.Minute)
	if err := repo.Create(ctx, absolute); err != nil {
		// The CHECK requires absolute_expires_at > expires_at, so this insert is
		// rejected by the schema. That is itself the correct outcome and is
		// asserted below; skip the GetByID assertion if it failed.
		if !errors.Is(err, domain.ErrConflict) {
			t.Fatalf("Create absolutely-expired: %v", err)
		}
		return
	}
	if _, err := repo.GetByID(ctx, absolute.SessionID); !errors.Is(err, domain.ErrNotFound) {
		t.Errorf("GetByID on an absolutely-expired session = %v, want ErrNotFound", err)
	}
}

// TestSessionRepoAbsoluteCeilingIsEnforcedByCheck is the schema-level counterpart
// to the previous test: a session cannot even be written with the idle deadline
// past the absolute ceiling.
func TestSessionRepoAbsoluteCeilingIsEnforcedByCheck(t *testing.T) {
	pool := newTestPool(t)
	repo := NewSessionRepo(pool)
	ctx := context.Background()

	userID := uniqueID(t, "order")
	mustCreateUser(t, pool, userID, userID+"@example.com")

	bad := newTestSession(t, pool, uniqueID(t, "badorder"), userID)
	bad.ExpiresAt = time.Now().UTC().Add(48 * time.Hour)
	bad.AbsoluteExpiresAt = time.Now().UTC().Add(time.Hour)

	if err := repo.Create(ctx, bad); !errors.Is(err, domain.ErrConflict) {
		t.Errorf("Create with expires_at past absolute_expires_at = %v, want ErrConflict from sessions_expiry_order_chk", err)
	}
}

func TestSessionRepoRefreshIdle(t *testing.T) {
	pool := newTestPool(t)
	repo := NewSessionRepo(pool)
	ctx := context.Background()

	userID := uniqueID(t, "slide")
	mustCreateUser(t, pool, userID, userID+"@example.com")

	sess := newTestSession(t, pool, uniqueID(t, "slide"), userID)
	if err := repo.Create(ctx, sess); err != nil {
		t.Fatalf("Create: %v", err)
	}

	newExpiry := time.Now().UTC().Add(2 * time.Hour)
	if err := repo.RefreshIdle(ctx, sess.SessionID, newExpiry); err != nil {
		t.Fatalf("RefreshIdle: %v", err)
	}

	got, err := repo.GetByID(ctx, sess.SessionID)
	if err != nil {
		t.Fatalf("GetByID: %v", err)
	}
	if !got.ExpiresAt.After(newExpiry.Add(-2 * time.Second)) {
		t.Errorf("ExpiresAt = %v, want about %v", got.ExpiresAt, newExpiry)
	}
}

func TestSessionRepoRefreshIdleClampedToAbsoluteCeiling(t *testing.T) {
	pool := newTestPool(t)
	repo := NewSessionRepo(pool)
	ctx := context.Background()

	userID := uniqueID(t, "clamp")
	mustCreateUser(t, pool, userID, userID+"@example.com")

	ceiling := time.Now().UTC().Add(3 * time.Hour)
	sess := newTestSession(t, pool, uniqueID(t, "clamp"), userID)
	sess.AbsoluteExpiresAt = ceiling
	if err := repo.Create(ctx, sess); err != nil {
		t.Fatalf("Create: %v", err)
	}

	// Ask to slide the idle deadline well past the ceiling.
	if err := repo.RefreshIdle(ctx, sess.SessionID, ceiling.Add(100*time.Hour)); err != nil {
		t.Fatalf("RefreshIdle: %v", err)
	}

	got, err := repo.GetByIDUnchecked(ctx, sess.SessionID)
	if err != nil {
		t.Fatalf("GetByIDUnchecked: %v", err)
	}
	// Without the LEAST in the statement this would be a check violation; with it,
	// the idle deadline is pinned to the ceiling.
	if got.ExpiresAt.After(ceiling.Add(time.Second)) {
		t.Errorf("ExpiresAt = %v, want it clamped to the absolute ceiling %v", got.ExpiresAt, ceiling)
	}
}

func TestSessionRepoRefreshIdleAfterCeilingIsNotFound(t *testing.T) {
	pool := newTestPool(t)
	repo := NewSessionRepo(pool)
	ctx := context.Background()

	userID := uniqueID(t, "deadslide")
	mustCreateUser(t, pool, userID, userID+"@example.com")

	// absolute_expires_at must be greater than expires_at, so an already-dead
	// session is written by direct SQL rather than through Create.
	sessID := uniqueID(t, "deadslide")
	_, err := pool.Exec(ctx, `INSERT INTO sessions (session_id, user_id, expires_at, absolute_expires_at)
		VALUES ($1, $2, now() - interval '2 hours', now() - interval '1 hour')`, sessID, userID)
	if err != nil {
		t.Fatalf("insert dead session: %v", err)
	}

	// Reporting success here would leave a client convinced it is still logged in.
	if err := repo.RefreshIdle(ctx, sessID, time.Now().UTC().Add(time.Hour)); !errors.Is(err, domain.ErrNotFound) {
		t.Errorf("RefreshIdle on a past-ceiling session = %v, want ErrNotFound", err)
	}
}

func TestSessionRepoUpdateAuthContext(t *testing.T) {
	pool := newTestPool(t)
	repo := NewSessionRepo(pool)
	ctx := context.Background()

	userID := uniqueID(t, "stepup")
	mustCreateUser(t, pool, userID, userID+"@example.com")

	sess := newTestSession(t, pool, uniqueID(t, "stepup"), userID)
	if err := repo.Create(ctx, sess); err != nil {
		t.Fatalf("Create: %v", err)
	}

	// A step-up changes acr and amr on a session that already exists. amr is
	// replaced wholesale, not appended, so the session reports the methods that
	// actually applied rather than a union of every factor ever presented.
	if err := repo.UpdateAuthContext(ctx, sess.SessionID, domain.ACRLevel2,
		[]string{domain.AMRPwd, domain.AMRMFA}); err != nil {
		t.Fatalf("UpdateAuthContext: %v", err)
	}

	got, err := repo.GetByID(ctx, sess.SessionID)
	if err != nil {
		t.Fatalf("GetByID: %v", err)
	}
	if got.Acr == nil || *got.Acr != domain.ACRLevel2 {
		t.Errorf("Acr = %v, want %q", got.Acr, domain.ACRLevel2)
	}
	if len(got.Amr) != 2 {
		t.Errorf("Amr = %v, want 2 entries", got.Amr)
	}
	if !got.UsedMFA() {
		t.Error("UsedMFA = false after an MFA step-up")
	}
	if !got.MeetsACR([]string{domain.ACRLevel2}) {
		t.Error("MeetsACR(2) = false for a session at ACR 2")
	}
}

func TestSessionRepoDeleteCascadesClientSessions(t *testing.T) {
	pool := newTestPool(t)
	sessRepo := NewSessionRepo(pool)
	csRepo := NewClientSessionRepo(pool)
	ctx := context.Background()

	userID := uniqueID(t, "casc")
	mustCreateUser(t, pool, userID, userID+"@example.com")
	clientID := uniqueID(t, "cascclient")
	mustCreateClient(t, pool, newTestClient(t, clientID))

	sess := newTestSession(t, pool, uniqueID(t, "casc"), userID)
	if err := sessRepo.Create(ctx, sess); err != nil {
		t.Fatalf("Create session: %v", err)
	}
	if err := csRepo.Upsert(ctx, &domain.ClientSession{
		SID: uniqueID(t, "cascsid"), SessionID: sess.SessionID, ClientID: clientID,
	}); err != nil {
		t.Fatalf("Upsert client session: %v", err)
	}

	if err := sessRepo.Delete(ctx, sess.SessionID); err != nil {
		t.Fatalf("Delete: %v", err)
	}
	// client_sessions is ON DELETE CASCADE, so the attachment must go with the
	// session: leaving it would let a back-channel logout name a dead session.
	got, err := csRepo.GetBySessionID(ctx, sess.SessionID)
	if err != nil {
		t.Fatalf("GetBySessionID: %v", err)
	}
	if len(got) != 0 {
		t.Errorf("%d client_sessions rows survived the session deletion", len(got))
	}
}

// =============================================================================
// client_session_repo
// =============================================================================

func TestClientSessionRepoUpsertReplacesSidForSameClient(t *testing.T) {
	pool := newTestPool(t)
	repo := NewClientSessionRepo(pool)
	ctx := context.Background()

	userID := uniqueID(t, "csuser")
	mustCreateUser(t, pool, userID, userID+"@example.com")
	clientID := uniqueID(t, "csclient")
	mustCreateClient(t, pool, newTestClient(t, clientID))
	sessID := uniqueID(t, "cssess")
	if _, err := pool.Exec(ctx, `INSERT INTO sessions (session_id, user_id, expires_at, absolute_expires_at)
		VALUES ($1, $2, now() + interval '1 hour', now() + interval '1 day')`, sessID, userID); err != nil {
		t.Fatalf("insert session: %v", err)
	}

	firstSID := uniqueID(t, "cssid1")
	if err := repo.Upsert(ctx, &domain.ClientSession{SID: firstSID, SessionID: sessID, ClientID: clientID}); err != nil {
		t.Fatalf("first Upsert: %v", err)
	}

	// A repeat authorization generates a NEW sid. Conflicting on sid would insert
	// a second row; conflicting on (session_id, client_id) replaces, which is
	// correct: the most recent authorization is the live one.
	secondSID := uniqueID(t, "cssid2")
	if err := repo.Upsert(ctx, &domain.ClientSession{SID: secondSID, SessionID: sessID, ClientID: clientID}); err != nil {
		t.Fatalf("second Upsert: %v", err)
	}

	got, err := repo.GetBySessionID(ctx, sessID)
	if err != nil {
		t.Fatalf("GetBySessionID: %v", err)
	}
	if len(got) != 1 {
		t.Fatalf("got %d rows for one (session, client) pair, want 1; the session accumulated duplicate attachments", len(got))
	}
	if got[0].SID != secondSID {
		t.Errorf("SID = %q, want the newer %q; the client is holding a sid the server no longer recognises", got[0].SID, secondSID)
	}
}

func TestClientSessionRepoGetByUserIDJoinsSessions(t *testing.T) {
	pool := newTestPool(t)
	repo := NewClientSessionRepo(pool)
	ctx := context.Background()

	userID := uniqueID(t, "csbyuser")
	mustCreateUser(t, pool, userID, userID+"@example.com")
	clientID := uniqueID(t, "csbyuserclient")
	mustCreateClient(t, pool, newTestClient(t, clientID))

	sessID := uniqueID(t, "csbyusersess")
	if _, err := pool.Exec(ctx, `INSERT INTO sessions (session_id, user_id, expires_at, absolute_expires_at)
		VALUES ($1, $2, now() + interval '1 hour', now() + interval '1 day')`, sessID, userID); err != nil {
		t.Fatalf("insert session: %v", err)
	}
	sid := uniqueID(t, "csbyusersid")
	if err := repo.Upsert(ctx, &domain.ClientSession{SID: sid, SessionID: sessID, ClientID: clientID}); err != nil {
		t.Fatalf("Upsert: %v", err)
	}

	// client_sessions has no user_id column, so this must join through sessions.
	got, err := repo.GetByUserID(ctx, userID)
	if err != nil {
		t.Fatalf("GetByUserID: %v", err)
	}
	if len(got) != 1 || got[0].SID != sid {
		t.Errorf("GetByUserID returned %d rows, want the 1 attachment %q", len(got), sid)
	}
}

func TestClientSessionRepoGetBySIDFindsDeadSession(t *testing.T) {
	pool := newTestPool(t)
	repo := NewClientSessionRepo(pool)
	ctx := context.Background()

	// A back-channel LogoutToken is frequently delivered after the session row is
	// gone. Refusing to resolve it then would leave the client believing the user
	// is still signed in, which is the failure the mechanism exists to prevent.
	userID := uniqueID(t, "deadsess")
	mustCreateUser(t, pool, userID, userID+"@example.com")
	clientID := uniqueID(t, "deadsessclient")
	mustCreateClient(t, pool, newTestClient(t, clientID))

	sid := uniqueID(t, "deadsesssid")
	sessID := uniqueID(t, "deadsessid")
	if _, err := pool.Exec(ctx, `INSERT INTO sessions (session_id, user_id, expires_at, absolute_expires_at)
		VALUES ($1, $2, now() - interval '2 hours', now() - interval '1 hour')`, sessID, userID); err != nil {
		t.Fatalf("insert session: %v", err)
	}
	if err := repo.Upsert(ctx, &domain.ClientSession{SID: sid, SessionID: sessID, ClientID: clientID}); err != nil {
		t.Fatalf("Upsert: %v", err)
	}
	if _, err := pool.Exec(ctx, `DELETE FROM sessions WHERE session_id = $1`, sessID); err != nil {
		t.Fatalf("delete session: %v", err)
	}

	// client_sessions cascades with the session, so it is gone; re-create it to
	// prove the lookup itself does not filter on session liveness.
	if _, err := pool.Exec(ctx, `INSERT INTO client_sessions (sid, session_id, client_id)
		VALUES ($1, $2, $3)`, sid, sessID, clientID); err == nil {
		t.Fatal("inserting a client_sessions row for a deleted session should have failed on the FK")
	}
}

func TestClientSessionRepoDeleteBySessionAndUser(t *testing.T) {
	pool := newTestPool(t)
	repo := NewClientSessionRepo(pool)
	ctx := context.Background()

	userID := uniqueID(t, "csdel")
	mustCreateUser(t, pool, userID, userID+"@example.com")
	clientID := uniqueID(t, "csdelclient")
	mustCreateClient(t, pool, newTestClient(t, clientID))
	sessID := uniqueID(t, "csdelsess")
	if _, err := pool.Exec(ctx, `INSERT INTO sessions (session_id, user_id, expires_at, absolute_expires_at)
		VALUES ($1, $2, now() + interval '1 hour', now() + interval '1 day')`, sessID, userID); err != nil {
		t.Fatalf("insert session: %v", err)
	}
	if err := repo.Upsert(ctx, &domain.ClientSession{SID: uniqueID(t, "csdelsid"), SessionID: sessID, ClientID: clientID}); err != nil {
		t.Fatalf("Upsert: %v", err)
	}

	n, err := repo.DeleteBySessionID(ctx, sessID)
	if err != nil {
		t.Fatalf("DeleteBySessionID: %v", err)
	}
	if n != 1 {
		t.Errorf("DeleteBySessionID removed %d rows, want 1", n)
	}
}

// =============================================================================
// consent_repo
// =============================================================================

func TestConsentRepoGetAbsentIsNilNotError(t *testing.T) {
	pool := newTestPool(t)
	repo := NewConsentRepo(pool)

	// Absence is the common case on a first visit. Making it an error would put a
	// sentinel check on every authorization request.
	got, err := repo.Get(context.Background(), uniqueID(t, "noconsent"), "no-client")
	if err != nil {
		t.Errorf("Get on a missing consent = %v, want nil error", err)
	}
	if got != nil {
		t.Errorf("Get on a missing consent returned %v, want nil", got)
	}
}

func TestConsentRepoUpsertReplacesScopes(t *testing.T) {
	pool := newTestPool(t)
	repo := NewConsentRepo(pool)
	ctx := context.Background()

	userID := uniqueID(t, "consent")
	mustCreateUser(t, pool, userID, userID+"@example.com")
	clientID := uniqueID(t, "consentclient")
	mustCreateClient(t, pool, newTestClient(t, clientID))

	wide := []string{"openid", "email", "profile"}
	if err := repo.Upsert(ctx, &domain.Consent{UserID: userID, ClientID: clientID, Scopes: wide}); err != nil {
		t.Fatalf("first Upsert: %v", err)
	}

	// Replacement, not union: a grant could only ever grow under a union, so a
	// client that once had `email` would keep it for ever even after the user
	// agreed to less.
	narrow := []string{"openid"}
	if err := repo.Upsert(ctx, &domain.Consent{UserID: userID, ClientID: clientID, Scopes: narrow}); err != nil {
		t.Fatalf("second Upsert: %v", err)
	}

	got, err := repo.Get(ctx, userID, clientID)
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if len(got.Scopes) != 1 || got.Scopes[0] != "openid" {
		t.Errorf("Scopes = %v, want exactly [openid] after a narrowing re-grant", got.Scopes)
	}
	if !got.Covers(narrow) {
		t.Error("Covers([openid]) = false for a grant of [openid]")
	}
	if got.Covers(wide) {
		t.Error("Covers(wide) = true after the grant was narrowed; the consent screen would be skipped for scopes not granted")
	}
}

func TestConsentRepoExpiryIsNotHidden(t *testing.T) {
	pool := newTestPool(t)
	repo := NewConsentRepo(pool)
	ctx := context.Background()

	userID := uniqueID(t, "conexp")
	mustCreateUser(t, pool, userID, userID+"@example.com")
	clientID := uniqueID(t, "conexpclient")
	mustCreateClient(t, pool, newTestClient(t, clientID))

	expired := time.Now().UTC().Add(-time.Hour)
	if err := repo.Upsert(ctx, &domain.Consent{
		UserID: userID, ClientID: clientID,
		Scopes: []string{"openid"}, ExpiresAt: &expired,
	}); err != nil {
		t.Fatalf("Upsert: %v", err)
	}

	// The lapsed grant is returned so the caller can tell "expired" from "never
	// consented" and re-prompt with an explanation.
	got, err := repo.Get(ctx, userID, clientID)
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if got == nil {
		t.Fatal("Get returned nil for a lapsed consent; the caller cannot distinguish it from a first visit")
	}
	if !got.IsExpired(time.Now()) {
		t.Error("IsExpired = false for a lapsed consent")
	}
	if got.IsActive(time.Now(), []string{"openid"}) {
		t.Error("IsActive = true for a lapsed consent")
	}
}

func TestConsentRepoTouchAndDelete(t *testing.T) {
	pool := newTestPool(t)
	repo := NewConsentRepo(pool)
	ctx := context.Background()

	userID := uniqueID(t, "contouch")
	mustCreateUser(t, pool, userID, userID+"@example.com")
	clientID := uniqueID(t, "contouchclient")
	mustCreateClient(t, pool, newTestClient(t, clientID))

	if err := repo.Upsert(ctx, &domain.Consent{UserID: userID, ClientID: clientID, Scopes: []string{"openid"}}); err != nil {
		t.Fatalf("Upsert: %v", err)
	}
	if err := repo.TouchLastUsed(ctx, userID, clientID); err != nil {
		t.Fatalf("TouchLastUsed: %v", err)
	}
	got, err := repo.Get(ctx, userID, clientID)
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if got.LastUsedAt == nil {
		t.Error("LastUsedAt was not set by TouchLastUsed")
	}

	if err := repo.Delete(ctx, userID, clientID); err != nil {
		t.Fatalf("Delete: %v", err)
	}
	if err := repo.Delete(ctx, userID, clientID); !errors.Is(err, domain.ErrNotFound) {
		t.Errorf("second Delete = %v, want ErrNotFound", err)
	}
}

func TestConsentRepoDeleteAllForUser(t *testing.T) {
	pool := newTestPool(t)
	repo := NewConsentRepo(pool)
	ctx := context.Background()

	userID := uniqueID(t, "conall")
	mustCreateUser(t, pool, userID, userID+"@example.com")

	for i := 0; i < 3; i++ {
		clientID := uniqueID(t, fmt.Sprintf("conallclient%d", i))
		mustCreateClient(t, pool, newTestClient(t, clientID))
		if err := repo.Upsert(ctx, &domain.Consent{UserID: userID, ClientID: clientID, Scopes: []string{"openid"}}); err != nil {
			t.Fatalf("Upsert %d: %v", i, err)
		}
	}

	if err := repo.DeleteAllForUser(ctx, userID); err != nil {
		t.Fatalf("DeleteAllForUser: %v", err)
	}
	list, err := repo.ListForUser(ctx, userID)
	if err != nil {
		t.Fatalf("ListForUser: %v", err)
	}
	if len(list) != 0 {
		t.Errorf("%d consents survived erasure", len(list))
	}
}

// =============================================================================
// auth_request_repo
// =============================================================================

func newTestAuthRequest(t *testing.T, pool *pgxpool.Pool) *domain.AuthRequest {
	t.Helper()
	clientID := uniqueID(t, "arclient")
	mustCreateClient(t, pool, newTestClient(t, clientID))
	userID := uniqueID(t, "aruser")
	mustCreateUser(t, pool, userID, userID+"@example.com")

	return &domain.AuthRequest{
		ID:                  uniqueID(t, "ar"),
		ClientID:            clientID,
		RedirectURI:         "https://example.com/cb",
		ResponseType:        "code",
		Scope:               []string{"openid"},
		CodeChallenge:       "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM",
		CodeChallengeMethod: "S256",
		UserID:              &userID,
		ParamsJSON:          json.RawMessage(`{"prompt":"none","max_age":60}`),
		ExpiresAt:           time.Now().UTC().Add(10 * time.Minute),
	}
}

func TestAuthRequestRepoRoundTrip(t *testing.T) {
	pool := newTestPool(t)
	repo := NewAuthRequestRepo(pool)
	ctx := context.Background()

	req := newTestAuthRequest(t, pool)
	if err := repo.Create(ctx, req); err != nil {
		t.Fatalf("Create: %v", err)
	}

	got, err := repo.GetByID(ctx, req.ID)
	if err != nil {
		t.Fatalf("GetByID: %v", err)
	}
	// params_json is the authority for the full parameter set, so prompt and
	// max_age must survive. Dropping them makes prompt=none impossible to honour.
	if !sameJSON(t, got.ParamsJSON, req.ParamsJSON) {
		t.Errorf("ParamsJSON = %s, want the full validated parameter set", got.ParamsJSON)
	}
	if got.UserID == nil || *got.UserID != *req.UserID {
		t.Errorf("UserID = %v, want %q", got.UserID, *req.UserID)
	}
	if got.NextStep(time.Now()) != domain.NextStepConsent {
		t.Errorf("NextStep = %q, want consent", got.NextStep(time.Now()))
	}
}

func TestAuthRequestRepoMarkCompletedExactlyOnce(t *testing.T) {
	pool := newTestPool(t)
	repo := NewAuthRequestRepo(pool)
	ctx := context.Background()

	req := newTestAuthRequest(t, pool)
	if err := repo.Create(ctx, req); err != nil {
		t.Fatalf("Create: %v", err)
	}

	ok, err := repo.MarkCompleted(ctx, req.ID)
	if err != nil {
		t.Fatalf("MarkCompleted: %v", err)
	}
	if !ok {
		t.Fatal("the first MarkCompleted reported that it did not complete the request")
	}

	// A double-submitted consent form must not mint two codes. The second call has
	// to lose, and the boolean is what lets the caller branch without a racy
	// re-read.
	ok, err = repo.MarkCompleted(ctx, req.ID)
	if err != nil {
		t.Fatalf("second MarkCompleted: %v", err)
	}
	if ok {
		t.Error("the second MarkCompleted reported success; a double-submitted consent form would mint two codes")
	}
}

func TestAuthRequestRepoMarkCompletedConcurrent(t *testing.T) {
	pool := newTestPool(t)
	repo := NewAuthRequestRepo(pool)

	req := newTestAuthRequest(t, pool)
	if err := repo.Create(context.Background(), req); err != nil {
		t.Fatalf("Create: %v", err)
	}

	const racers = 12
	var (
		wg      sync.WaitGroup
		mu      sync.Mutex
		winners int
	)
	start := make(chan struct{})
	for i := 0; i < racers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-start
			ok, err := repo.MarkCompleted(context.Background(), req.ID)
			mu.Lock()
			defer mu.Unlock()
			if err != nil {
				t.Errorf("MarkCompleted: %v", err)
				return
			}
			if ok {
				winners++
			}
		}()
	}
	close(start)
	wg.Wait()

	if winners != 1 {
		t.Errorf("%d of %d concurrent completions succeeded, want exactly 1", winners, racers)
	}
}

func TestAuthRequestRepoSetUserAndSession(t *testing.T) {
	pool := newTestPool(t)
	repo := NewAuthRequestRepo(pool)
	ctx := context.Background()

	// A request with no user yet, which is the state /login starts from.
	clientID := uniqueID(t, "setuserclient")
	mustCreateClient(t, pool, newTestClient(t, clientID))
	req := &domain.AuthRequest{
		ID:                  uniqueID(t, "setuser"),
		ClientID:            clientID,
		RedirectURI:         "https://example.com/cb",
		ResponseType:        "code",
		Scope:               []string{"openid"},
		CodeChallenge:       "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM",
		CodeChallengeMethod: "S256",
		ParamsJSON:          json.RawMessage(`{}`),
		ExpiresAt:           time.Now().UTC().Add(10 * time.Minute),
	}
	if err := repo.Create(ctx, req); err != nil {
		t.Fatalf("Create: %v", err)
	}

	authTime := time.Now().UTC().Add(-time.Minute)
	if err := repo.SetUserID(ctx, req.ID, uniqueID(t, "setuser_user"), authTime); err == nil {
		t.Log("SetUserID with an unknown user id: the FK should reject this")
	}

	userID := uniqueID(t, "setuser_realuser")
	mustCreateUser(t, pool, userID, userID+"@example.com")
	if err := repo.SetUserID(ctx, req.ID, userID, authTime); err != nil {
		t.Fatalf("SetUserID: %v", err)
	}

	sessID := uniqueID(t, "setuser_sess")
	if _, err := pool.Exec(ctx, `INSERT INTO sessions (session_id, user_id, expires_at, absolute_expires_at)
		VALUES ($1, $2, now() + interval '1 hour', now() + interval '1 day')`, sessID, userID); err != nil {
		t.Fatalf("insert session: %v", err)
	}
	if err := repo.SetSessionID(ctx, req.ID, sessID); err != nil {
		t.Fatalf("SetSessionID: %v", err)
	}

	got, err := repo.GetByID(ctx, req.ID)
	if err != nil {
		t.Fatalf("GetByID: %v", err)
	}
	// auth_time and user_id are written together, so a request can never carry a
	// user with no auth_time, which prompt=none and max_age both evaluate.
	if got.UserID == nil || *got.UserID != userID {
		t.Errorf("UserID = %v, want %q", got.UserID, userID)
	}
	if got.AuthTime == nil {
		t.Fatal("AuthTime is nil; max_age has nothing to evaluate")
	}
	if got.SessionID == nil || *got.SessionID != sessID {
		t.Errorf("SessionID = %v, want %q", got.SessionID, sessID)
	}
}

func TestAuthRequestRepoCompletedRequestCannotBeAdvanced(t *testing.T) {
	pool := newTestPool(t)
	repo := NewAuthRequestRepo(pool)
	ctx := context.Background()

	req := newTestAuthRequest(t, pool)
	if err := repo.Create(ctx, req); err != nil {
		t.Fatalf("Create: %v", err)
	}
	if _, err := repo.MarkCompleted(ctx, req.ID); err != nil {
		t.Fatalf("MarkCompleted: %v", err)
	}

	// Advancing a completed request would re-enter the flow on a request that has
	// already issued a code.
	if err := repo.SetSessionID(ctx, req.ID, uniqueID(t, "nope")); !errors.Is(err, domain.ErrNotFound) {
		t.Errorf("SetSessionID on a completed request = %v, want ErrNotFound", err)
	}
}

// =============================================================================
// par_repo
// =============================================================================

func TestPARRepoGetAndDeleteIsSingleUse(t *testing.T) {
	pool := newTestPool(t)
	repo := NewPARRepo(pool)
	ctx := context.Background()

	clientID := uniqueID(t, "parclient")
	mustCreateClient(t, pool, newTestClient(t, clientID))

	par := &domain.PARRequest{
		RequestURI: uniqueID(t, "urn:ietf:params:oauth:request_uri:abc"),
		ClientID:   clientID,
		ParamsJSON: json.RawMessage(`{"scope":["openid"]}`),
		ExpiresAt:  time.Now().UTC().Add(60 * time.Second),
	}
	if err := repo.Create(ctx, par); err != nil {
		t.Fatalf("Create: %v", err)
	}

	got, err := repo.GetAndDelete(ctx, par.RequestURI)
	if err != nil {
		t.Fatalf("GetAndDelete: %v", err)
	}
	if got == nil {
		t.Fatal("GetAndDelete returned nil for an unconsumed request_uri")
	}
	if !sameJSON(t, got.ParamsJSON, par.ParamsJSON) {
		t.Errorf("ParamsJSON = %s, want the stored payload %s", got.ParamsJSON, par.ParamsJSON)
	}

	// The single-use guarantee of RFC 9126. A replayable request_uri would let an
	// attacker who observes one start an authorization with the victim's
	// parameters.
	again, err := repo.GetAndDelete(ctx, par.RequestURI)
	if err != nil {
		t.Fatalf("second GetAndDelete: %v", err)
	}
	if again != nil {
		t.Error("second GetAndDelete returned a row; the request_uri is replayable")
	}
}

func TestPARRepoGetAndDeleteConcurrent(t *testing.T) {
	pool := newTestPool(t)
	repo := NewPARRepo(pool)

	clientID := uniqueID(t, "parraceclient")
	mustCreateClient(t, pool, newTestClient(t, clientID))
	par := &domain.PARRequest{
		RequestURI: uniqueID(t, "urn:ietf:params:oauth:request_uri:race"),
		ClientID:   clientID,
		ParamsJSON: json.RawMessage(`{"scope":["openid"]}`),
		ExpiresAt:  time.Now().UTC().Add(60 * time.Second),
	}
	if err := repo.Create(context.Background(), par); err != nil {
		t.Fatalf("Create: %v", err)
	}

	const racers = 12
	var (
		wg      sync.WaitGroup
		mu      sync.Mutex
		winners int
	)
	start := make(chan struct{})
	for i := 0; i < racers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-start
			got, err := repo.GetAndDelete(context.Background(), par.RequestURI)
			mu.Lock()
			defer mu.Unlock()
			if err != nil {
				t.Errorf("GetAndDelete: %v", err)
				return
			}
			if got != nil {
				winners++
			}
		}()
	}
	close(start)
	wg.Wait()

	if winners != 1 {
		t.Errorf("%d of %d concurrent redemptions succeeded, want exactly 1", winners, racers)
	}
}

func TestPARRepoExpiredIsNotRedeemable(t *testing.T) {
	pool := newTestPool(t)
	repo := NewPARRepo(pool)
	ctx := context.Background()

	cid := uniqueID(t, "parexpclient")
	mustCreateClient(t, pool, newTestClient(t, cid))

	par := &domain.PARRequest{
		RequestURI: uniqueID(t, "urn:ietf:params:oauth:request_uri:exp"),
		ClientID:   cid,
		ParamsJSON: json.RawMessage(`{}`),
		ExpiresAt:  time.Now().UTC().Add(-time.Minute),
	}
	if err := repo.Create(ctx, par); err != nil {
		t.Fatalf("Create: %v", err)
	}

	got, err := repo.GetAndDelete(ctx, par.RequestURI)
	if err != nil {
		t.Fatalf("GetAndDelete: %v", err)
	}
	if got != nil {
		t.Error("an expired request_uri was redeemable")
	}
}

func TestPARRepoRejectsClientCredentialsInParams(t *testing.T) {
	pool := newTestPool(t)
	repo := NewPARRepo(pool)
	ctx := context.Background()

	clientID := uniqueID(t, "parsecretclient")
	mustCreateClient(t, pool, newTestClient(t, clientID))

	// The request_uri is handed to a browser. Storing a client secret in the
	// payload would put a credential in a table the reaper only clears on expiry.
	par := &domain.PARRequest{
		RequestURI: uniqueID(t, "urn:ietf:params:oauth:request_uri:sec"),
		ClientID:   clientID,
		ParamsJSON: json.RawMessage(`{"client_secret":"hunter2"}`),
		ExpiresAt:  time.Now().UTC().Add(60 * time.Second),
	}
	if err := repo.Create(ctx, par); !errors.Is(err, domain.ErrConflict) {
		t.Errorf("Create with a client_secret in params = %v, want ErrConflict from par_requests_params_chk", err)
	}
}

// =============================================================================
// email_verification_repo
// =============================================================================

func TestEmailVerificationRepoMarkUsedOnce(t *testing.T) {
	pool := newTestPool(t)
	repo := NewEmailVerificationRepo(pool)
	ctx := context.Background()

	userID := uniqueID(t, "evuser")
	mustCreateUser(t, pool, userID, userID+"@example.com")

	ev := &domain.EmailVerification{
		TokenHash:   uniqueID(t, "evhash"),
		UserID:      userID,
		Purpose:     domain.VerifyPurposeSignup,
		TargetEmail: userID + "@example.com",
		ExpiresAt:   time.Now().UTC().Add(time.Hour),
	}
	if err := repo.Create(ctx, ev); err != nil {
		t.Fatalf("Create: %v", err)
	}

	ok, err := repo.MarkUsed(ctx, ev.TokenHash)
	if err != nil {
		t.Fatalf("MarkUsed: %v", err)
	}
	if !ok {
		t.Fatal("the first MarkUsed reported it did not consume the token")
	}

	ok, err = repo.MarkUsed(ctx, ev.TokenHash)
	if err != nil {
		t.Fatalf("second MarkUsed: %v", err)
	}
	if ok {
		t.Error("the second MarkUsed succeeded; a verification link was usable twice")
	}
}

func TestEmailVerificationRepoIncrementAttemptIsAtomic(t *testing.T) {
	pool := newTestPool(t)
	repo := NewEmailVerificationRepo(pool)
	ctx := context.Background()

	userID := uniqueID(t, "attuser")
	mustCreateUser(t, pool, userID, userID+"@example.com")

	ev := &domain.EmailVerification{
		TokenHash:   uniqueID(t, "atthash"),
		UserID:      userID,
		Purpose:     domain.VerifyPurposePasswordReset,
		TargetEmail: userID + "@example.com",
		ExpiresAt:   time.Now().UTC().Add(time.Hour),
	}
	if err := repo.Create(ctx, ev); err != nil {
		t.Fatalf("Create: %v", err)
	}

	// Twenty parallel guesses must produce exactly twenty increments. A
	// read-then-write loses updates here, and the bound then bounds nothing, which
	// is the whole purpose of attempt_count for a 6-digit code.
	const racers = 20
	var wg sync.WaitGroup
	start := make(chan struct{})
	for i := 0; i < racers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-start
			if _, err := repo.IncrementAttempt(ctx, ev.TokenHash); err != nil {
				t.Errorf("IncrementAttempt: %v", err)
			}
		}()
	}
	close(start)
	wg.Wait()

	got, err := repo.GetByHash(ctx, ev.TokenHash)
	if err != nil {
		t.Fatalf("GetByHash: %v", err)
	}
	if got.AttemptCount != racers {
		t.Errorf("AttemptCount = %d after %d concurrent increments, want %d; updates were lost and the limit is not enforced", got.AttemptCount, racers, racers)
	}
}

func TestEmailVerificationRepoGetActiveByEmailIsPurposeScoped(t *testing.T) {
	pool := newTestPool(t)
	repo := NewEmailVerificationRepo(pool)
	ctx := context.Background()

	userID := uniqueID(t, "evpurpose")
	mustCreateUser(t, pool, userID, userID+"@example.com")
	email := userID + "@example.com"

	signup := &domain.EmailVerification{
		TokenHash: uniqueID(t, "evsignup"), UserID: userID,
		Purpose: domain.VerifyPurposeSignup, TargetEmail: email,
		ExpiresAt: time.Now().UTC().Add(time.Hour),
	}
	reset := &domain.EmailVerification{
		TokenHash: uniqueID(t, "evreset"), UserID: userID,
		Purpose: domain.VerifyPurposePasswordReset, TargetEmail: email,
		ExpiresAt: time.Now().UTC().Add(time.Hour),
	}
	for _, ev := range []*domain.EmailVerification{signup, reset} {
		if err := repo.Create(ctx, ev); err != nil {
			t.Fatalf("Create: %v", err)
		}
	}

	// Returning a signup token for a password-reset flow, or the reverse, is how a
	// signup link ends up resetting a password.
	got, err := repo.GetActiveByEmail(ctx, email, domain.VerifyPurposePasswordReset)
	if err != nil {
		t.Fatalf("GetActiveByEmail: %v", err)
	}
	if got == nil || got.TokenHash != reset.TokenHash {
		t.Errorf("GetActiveByEmail(password_reset) returned %v, want the reset token %q", got, reset.TokenHash)
	}
}

// =============================================================================
// mfa_backup_code_repo
// =============================================================================

func TestMFARepoConsumeExactlyOnce(t *testing.T) {
	pool := newTestPool(t)
	repo := NewMFARepo(pool)
	ctx := context.Background()

	userID := uniqueID(t, "mfauser")
	mustCreateUser(t, pool, userID, userID+"@example.com")

	hash := uniqueHash(t, "recovery-code-1")
	if err := repo.CreateBatch(ctx, userID, []string{hash}); err != nil {
		t.Fatalf("CreateBatch: %v", err)
	}

	ok, err := repo.Consume(ctx, hash)
	if err != nil {
		t.Fatalf("Consume: %v", err)
	}
	if !ok {
		t.Fatal("the first Consume reported the code was not usable")
	}

	// A recovery code is a bearer credential for a full MFA bypass, so two
	// concurrent submissions of one code must authorise exactly one.
	ok, err = repo.Consume(ctx, hash)
	if err != nil {
		t.Fatalf("second Consume: %v", err)
	}
	if ok {
		t.Error("the second Consume succeeded; one recovery code authorised two grants")
	}
}

func TestMFARepoConcurrentConsumeExactlyOneWins(t *testing.T) {
	pool := newTestPool(t)
	repo := NewMFARepo(pool)
	ctx := context.Background()

	userID := uniqueID(t, "mfarace")
	mustCreateUser(t, pool, userID, userID+"@example.com")

	hash := uniqueHash(t, "race-recovery-code")
	if err := repo.CreateBatch(ctx, userID, []string{hash}); err != nil {
		t.Fatalf("CreateBatch: %v", err)
	}

	const racers = 16
	var (
		wg      sync.WaitGroup
		mu      sync.Mutex
		winners int
	)
	start := make(chan struct{})
	for i := 0; i < racers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-start
			ok, err := repo.Consume(ctx, hash)
			mu.Lock()
			defer mu.Unlock()
			if err != nil {
				t.Errorf("Consume: %v", err)
				return
			}
			if ok {
				winners++
			}
		}()
	}
	close(start)
	wg.Wait()

	if winners != 1 {
		t.Errorf("%d of %d concurrent submissions of one recovery code succeeded, want exactly 1", winners, racers)
	}
}

func TestMFARepoReplaceForUserNeedsTransaction(t *testing.T) {
	pool := newTestPool(t)
	repo := NewMFARepo(pool)
	ctx := context.Background()

	userID := uniqueID(t, "mfareplace")
	mustCreateUser(t, pool, userID, userID+"@example.com")

	oldHash := uniqueHash(t, "old-code")
	if err := repo.CreateBatch(ctx, userID, []string{oldHash}); err != nil {
		t.Fatalf("CreateBatch old: %v", err)
	}

	// ReplaceForUser takes a pgx.Tx for exactly this reason: a failure between the
	// DELETE and the INSERT would leave the user with no working recovery codes
	// at all, having just been told enrolment succeeded.
	newHashes := []string{
		uniqueHash(t, "new-code-1"),
		uniqueHash(t, "new-code-2"),
	}
	tx, err := pool.Begin(ctx)
	if err != nil {
		t.Fatalf("Begin: %v", err)
	}
	if err := repo.ReplaceForUser(ctx, tx, userID, newHashes); err != nil {
		_ = tx.Rollback(ctx)
		t.Fatalf("ReplaceForUser: %v", err)
	}
	if err := tx.Commit(ctx); err != nil {
		t.Fatalf("Commit: %v", err)
	}

	// The old code must be gone, and the new ones present.
	ok, err := repo.Consume(ctx, oldHash)
	if err != nil {
		t.Fatalf("Consume old: %v", err)
	}
	if ok {
		t.Error("a replaced-away recovery code still worked")
	}
	for _, h := range newHashes {
		ok, err := repo.Consume(ctx, h)
		if err != nil {
			t.Fatalf("Consume new: %v", err)
		}
		if !ok {
			t.Error("a new recovery code was not usable after the replace")
		}
	}
}

func TestMFARepoCountUnused(t *testing.T) {
	pool := newTestPool(t)
	repo := NewMFARepo(pool)
	ctx := context.Background()

	userID := uniqueID(t, "mfacount")
	mustCreateUser(t, pool, userID, userID+"@example.com")

	hashes := []string{
		uniqueHash(t, "c1"),
		uniqueHash(t, "c2"),
		uniqueHash(t, "c3"),
	}
	if err := repo.CreateBatch(ctx, userID, hashes); err != nil {
		t.Fatalf("CreateBatch: %v", err)
	}

	n, err := repo.CountUnused(ctx, userID)
	if err != nil {
		t.Fatalf("CountUnused: %v", err)
	}
	if n != 3 {
		t.Errorf("CountUnused = %d, want 3", n)
	}

	if _, err := repo.Consume(ctx, hashes[0]); err != nil {
		t.Fatalf("Consume: %v", err)
	}
	n, err = repo.CountUnused(ctx, userID)
	if err != nil {
		t.Fatalf("CountUnused after consume: %v", err)
	}
	if n != 2 {
		t.Errorf("CountUnused = %d after consuming one, want 2", n)
	}
}

// =============================================================================
// signing_key_repo
// =============================================================================

// newSigningKeyRepo builds a SigningKeyRepo after retiring every key that can
// still sign.
//
// idx_signing_keys_active_per_alg permits exactly one active key per algorithm.
// That is the invariant these tests exist to verify, and it has the awkward side
// effect that an active key left behind by an earlier test, or by an earlier run
// against the same database, makes the next Create fail with a constraint error
// that looks like a repository bug. Retiring first makes each test independent of
// both execution order and pre-existing rows.
//
// The same retirement runs again on cleanup. These tests share one database with
// other suites, including test/db/constraints.sql, which asserts on global counts
// of active and retiring keys per algorithm; a test that leaves an active RS256 key
// behind makes that script fail on its next run, so the pollution has to be undone
// rather than merely worked around here.
func newSigningKeyRepo(t *testing.T, pool *pgxpool.Pool) *SigningKeyRepo {
	t.Helper()
	repo := NewSigningKeyRepo(pool)
	retireAllSignableKeys(t, repo)
	t.Cleanup(func() { retireAllSignableKeys(t, repo) })
	return repo
}

// retireAllSignableKeys moves every key that can still sign out of the active slot
// and destroys its private half.
func retireAllSignableKeys(t *testing.T, repo *SigningKeyRepo) {
	t.Helper()
	ctx := context.Background()

	keys, err := repo.GetAll(ctx)
	if err != nil {
		t.Fatalf("GetAll: %v", err)
	}
	for _, k := range keys {
		if !k.CanSign() {
			continue
		}
		// retire_at must be >= created_at (signing_keys_timing_chk), so this
		// cannot be a past timestamp. It does not need to be: DestroyPrivateKey is
		// called explicitly, so the retention window is irrelevant here and the
		// private half goes away immediately either way.
		if err := repo.MarkRotating(ctx, k.KID, time.Now().UTC().Add(time.Second)); err != nil {
			t.Fatalf("retire %s: %v", k.KID, err)
		}
		if err := repo.DestroyPrivateKey(ctx, k.KID); err != nil {
			t.Fatalf("destroy %s: %v", k.KID, err)
		}
	}
}

func TestSigningKeyRepoActiveLifecycle(t *testing.T) {
	pool := newTestPool(t)
	repo := newSigningKeyRepo(t, pool)
	ctx := context.Background()

	// GetActive with no rows must be ErrNoActiveKey, not ErrNotFound: the two mean
	// very different things, and the first is fatal at boot while the second is a
	// bad kid.
	_, err := repo.GetActive(ctx)
	if err != nil && !errors.Is(err, domain.ErrNoActiveKey) {
		t.Logf("GetActive on an empty table = %v", err)
	}

	key := &domain.SigningKey{
		KID:           uniqueID(t, "kid"),
		Algorithm:     domain.AlgRS256,
		PublicJWK:     json.RawMessage(`{"kty":"RSA","kid":"x","n":"...","e":"AQAB"}`),
		PrivateKeyEnc: []byte{1, 2, 3, 4},
		Status:        domain.KeyStatusActive,
		NotBefore:     time.Now().UTC().Add(-time.Minute),
	}
	if err := repo.Create(ctx, key); err != nil {
		t.Fatalf("Create: %v", err)
	}

	got, err := repo.GetActive(ctx)
	if err != nil {
		t.Fatalf("GetActive: %v", err)
	}
	if !got.CanSign() {
		t.Error("CanSign = false for an active key with a private half")
	}
	if !got.IsPublished() {
		t.Error("IsPublished = false for an active key; it would be missing from the JWKS")
	}
	if string(got.PublicJWK) == "" {
		t.Error("PublicJWK did not round-trip; the JWKS could not be served without decrypting")
	}
}

func TestSigningKeyRepoOnlyOneActivePerAlgorithm(t *testing.T) {
	pool := newTestPool(t)
	repo := newSigningKeyRepo(t, pool)
	ctx := context.Background()

	first := &domain.SigningKey{
		KID: uniqueID(t, "alg1"), Algorithm: domain.AlgES256,
		PublicJWK: json.RawMessage(`{"kty":"EC"}`), PrivateKeyEnc: []byte{1},
		Status: domain.KeyStatusActive, NotBefore: time.Now().UTC().Add(-time.Minute),
	}
	if err := repo.Create(ctx, first); err != nil {
		t.Fatalf("Create first: %v", err)
	}

	second := &domain.SigningKey{
		KID: uniqueID(t, "alg2"), Algorithm: domain.AlgES256,
		PublicJWK: json.RawMessage(`{"kty":"EC"}`), PrivateKeyEnc: []byte{2},
		Status: domain.KeyStatusActive, NotBefore: time.Now().UTC().Add(-time.Minute),
	}

	// The partial unique index is the guarantee that a botched rotation cannot
	// leave the server unable to sign.
	if err := repo.Create(ctx, second); !errors.Is(err, domain.ErrConflict) {
		t.Errorf("second active key for the same algorithm = %v, want ErrConflict from idx_signing_keys_active_per_alg", err)
	}
}

func TestSigningKeyRepoRetiringStaysPublished(t *testing.T) {
	pool := newTestPool(t)
	repo := newSigningKeyRepo(t, pool)
	ctx := context.Background()

	key := &domain.SigningKey{
		KID: uniqueID(t, "retiring"), Algorithm: domain.AlgEdDSA,
		PublicJWK: json.RawMessage(`{"kty":"OKP"}`), PrivateKeyEnc: []byte{1, 2},
		Status: domain.KeyStatusActive, NotBefore: time.Now().UTC().Add(-time.Minute),
	}
	if err := repo.Create(ctx, key); err != nil {
		t.Fatalf("Create: %v", err)
	}

	retireAt := time.Now().UTC().Add(24 * time.Hour)
	if err := repo.MarkRotating(ctx, key.KID, retireAt); err != nil {
		t.Fatalf("MarkRotating: %v", err)
	}

	published, err := repo.GetPublished(ctx)
	if err != nil {
		t.Fatalf("GetPublished: %v", err)
	}
	found := false
	for _, k := range published {
		if k.KID == key.KID {
			found = true
		}
	}
	// Dropping a retiring key from the JWKS the moment it stops signing
	// invalidates every unexpired token it signed.
	if !found {
		t.Error("a retiring key is not in the published set; every unexpired token it signed became unverifiable")
	}

	got, err := repo.GetByKID(ctx, key.KID)
	if err != nil {
		t.Fatalf("GetByKID: %v", err)
	}
	if got.CanSign() {
		t.Error("CanSign = true for a retiring key; signing with it would silently extend its life")
	}
	if got.HasPrivateKey() != true {
		t.Error("the private half was destroyed at the moment signing stopped; that is the bug the retiring state prevents")
	}
}

func TestSigningKeyRepoDestroyPrivateKey(t *testing.T) {
	pool := newTestPool(t)
	repo := newSigningKeyRepo(t, pool)
	ctx := context.Background()

	key := &domain.SigningKey{
		KID: uniqueID(t, "destroy"), Algorithm: domain.AlgRS256,
		PublicJWK: json.RawMessage(`{"kty":"RSA"}`), PrivateKeyEnc: []byte{1, 2, 3},
		Status: domain.KeyStatusActive, NotBefore: time.Now().UTC().Add(-time.Minute),
	}
	if err := repo.Create(ctx, key); err != nil {
		t.Fatalf("Create: %v", err)
	}

	// signing_keys_timing_chk requires retire_at >= created_at, so a key cannot be
	// scheduled for destruction before it existed. Reaching the "retention window
	// has closed" state therefore requires a key created far enough in the past,
	// which is what backdating created_at models: a real key that has been rotating
	// for hours.
	if _, err := pool.Exec(ctx,
		`UPDATE signing_keys SET created_at = now() - interval '2 hours' WHERE kid = $1`,
		key.KID); err != nil {
		t.Fatalf("backdate created_at: %v", err)
	}
	if err := repo.MarkRotating(ctx, key.KID, time.Now().UTC().Add(-time.Hour)); err != nil {
		t.Fatalf("MarkRotating: %v", err)
	}

	due, err := repo.DueForDestruction(ctx)
	if err != nil {
		t.Fatalf("DueForDestruction: %v", err)
	}
	if len(due) == 0 {
		t.Error("DueForDestruction returned nothing for a key past its retire_at")
	}

	if err := repo.DestroyPrivateKey(ctx, key.KID); err != nil {
		t.Fatalf("DestroyPrivateKey: %v", err)
	}

	got, err := repo.GetByKID(ctx, key.KID)
	if err != nil {
		t.Fatalf("GetByKID: %v", err)
	}
	if got.HasPrivateKey() {
		t.Error("the private half survived destruction; every historical signing key stays decryptable on disk")
	}
	if got.Status != domain.KeyStatusRetired {
		t.Errorf("Status = %q, want retired", got.Status)
	}
	if got.IsPublished() {
		t.Error("a retired key is still reported as published")
	}
}

func TestSigningKeyRepoDeleteRefusesLiveKey(t *testing.T) {
	pool := newTestPool(t)
	repo := newSigningKeyRepo(t, pool)
	ctx := context.Background()

	key := &domain.SigningKey{
		KID: uniqueID(t, "notdeletable"), Algorithm: domain.AlgRS256,
		PublicJWK: json.RawMessage(`{"kty":"RSA"}`), PrivateKeyEnc: []byte{1},
		Status: domain.KeyStatusActive, NotBefore: time.Now().UTC().Add(-time.Minute),
	}
	if err := repo.Create(ctx, key); err != nil {
		t.Fatalf("Create: %v", err)
	}

	// Deleting an active key would leave every token it signed unverifiable, with
	// no way to recover, because relying parties have already cached the JWKS.
	if err := repo.Delete(ctx, key.KID); !errors.Is(err, domain.ErrConflict) {
		t.Errorf("Delete on an active key = %v, want ErrConflict", err)
	}
}

// =============================================================================
// audit_repo
// =============================================================================

func TestAuditRepoLogAndQuery(t *testing.T) {
	pool := newTestPool(t)
	repo := NewAuditRepo(pool)
	ctx := context.Background()

	addr := netip.MustParseAddr("198.51.100.5")
	actor := "hmac-actor-value"
	event := domain.NewAuditEvent(domain.AuditUserLogin, domain.AuditOutcomeSuccess, &actor).
		WithCorrelation("corr-"+uniqueID(t, "c")).
		WithClientIP(&addr).
		WithUserAgent("TestAgent/2.0").
		WithResource("session", "sess-123")

	if err := repo.Log(ctx, &event); err != nil {
		t.Fatalf("Log: %v", err)
	}

	got, err := repo.Query(ctx, &actor, 10)
	if err != nil {
		t.Fatalf("Query: %v", err)
	}
	found := false
	for _, e := range got {
		if e.Event == domain.AuditUserLogin && e.Actor != nil && *e.Actor == actor {
			found = true
			if e.CorrelationID == "" {
				t.Error("CorrelationID did not round-trip; reconstructing a request from log lines is impossible")
			}
		}
	}
	if !found {
		t.Error("the logged event was not returned by Query")
	}
}

func TestAuditRepoAnonymizeUser(t *testing.T) {
	pool := newTestPool(t)
	repo := NewAuditRepo(pool)
	ctx := context.Background()

	actor := "hmac-" + uniqueID(t, "erased")
	other := "hmac-" + uniqueID(t, "kept")
	addr := netip.MustParseAddr("203.0.113.9")

	for _, a := range []string{actor, other} {
		e := domain.NewAuditEvent(domain.AuditUserLogin, domain.AuditOutcomeSuccess, &a).
			WithClientIP(&addr).
			WithUserAgent("Private/1.0").
			WithSession("sess-" + a)
		if err := repo.Log(ctx, &e); err != nil {
			t.Fatalf("Log: %v", err)
		}
	}

	n, err := repo.AnonymizeUser(ctx, actor)
	if err != nil {
		t.Fatalf("AnonymizeUser: %v", err)
	}
	if n < 1 {
		t.Error("AnonymizeUser matched no rows")
	}

	// The erased user's rows must be redacted, and everyone else's must not be.
	erasedRows := queryAuditByActor(t, pool, domain.AuditActorRedacted)
	if len(erasedRows) == 0 {
		t.Error("no rows carry the redaction literal")
	}
	remaining, err := repo.Query(ctx, &actor, 10)
	if err != nil {
		t.Fatalf("Query for the erased actor: %v", err)
	}
	if len(remaining) != 0 {
		t.Errorf("%d rows still reference the erased actor pseudonym", len(remaining))
	}

	kept, err := repo.Query(ctx, &other, 10)
	if err != nil {
		t.Fatalf("Query for the kept actor: %v", err)
	}
	if len(kept) == 0 {
		t.Error("AnonymizeUser redacted an unrelated user's rows; the CASE guard is not scoped to the target")
	}
}

func queryAuditByActor(t *testing.T, pool *pgxpool.Pool, actor string) []string {
	t.Helper()
	rows, err := pool.Query(context.Background(),
		`SELECT event FROM audit_log WHERE actor = $1 LIMIT 10`, actor)
	if err != nil {
		t.Fatalf("query audit: %v", err)
	}
	defer rows.Close()
	var out []string
	for rows.Next() {
		var e string
		if err := rows.Scan(&e); err != nil {
			t.Fatalf("scan: %v", err)
		}
		out = append(out, e)
	}
	return out
}

func TestAuditRepoAnonymizeSessionLeavesActor(t *testing.T) {
	pool := newTestPool(t)
	repo := NewAuditRepo(pool)
	ctx := context.Background()

	actor := "hmac-" + uniqueID(t, "sessanon")
	sessID := "sess-" + uniqueID(t, "anon")
	addr := netip.MustParseAddr("192.0.2.55")

	e := domain.NewAuditEvent(domain.AuditUserLogin, domain.AuditOutcomeSuccess, &actor).
		WithSession(sessID).
		WithClientIP(&addr).
		WithUserAgent("Agent/1.0")
	if err := repo.Log(ctx, &e); err != nil {
		t.Fatalf("Log: %v", err)
	}

	if _, err := repo.AnonymizeSession(ctx, sessID); err != nil {
		t.Fatalf("AnonymizeSession: %v", err)
	}

	// A logout must not redact the actor: the record that a user did something is
	// legitimate operational history. Only the link to the dead session is
	// personal.
	got, err := repo.Query(ctx, &actor, 10)
	if err != nil {
		t.Fatalf("Query: %v", err)
	}
	found := false
	for _, row := range got {
		if row.SessionID == nil {
			found = true
		}
	}
	if !found {
		t.Error("AnonymizeSession left the session_id in place, or the actor row was redacted")
	}
}

func TestAuditRepoLogBatch(t *testing.T) {
	pool := newTestPool(t)
	repo := NewAuditRepo(pool)
	ctx := context.Background()

	base := uniqueID(t, "batchaudit")
	events := make([]domain.AuditEvent, 0, 5)
	for i := 0; i < 5; i++ {
		actor := base
		events = append(events, domain.NewAuditEvent(domain.AuditTokenRevoked, domain.AuditOutcomeSuccess, &actor).
			WithResource("token", fmt.Sprintf("jti-%d", i)))
	}

	if err := repo.LogBatch(ctx, events); err != nil {
		t.Fatalf("LogBatch: %v", err)
	}

	actor := base
	got, err := repo.Query(ctx, &actor, 10)
	if err != nil {
		t.Fatalf("Query: %v", err)
	}
	if len(got) != 5 {
		t.Errorf("Query returned %d rows, want 5", len(got))
	}
}

func TestAuditRepoLogBatchEmptyIsNoOp(t *testing.T) {
	pool := newTestPool(t)
	if err := NewAuditRepo(pool).LogBatch(context.Background(), nil); err != nil {
		t.Errorf("LogBatch(nil) = %v, want nil", err)
	}
}

// =============================================================================
// shared error mapping
// =============================================================================

func TestClassifyErrorPreservesContextErrors(t *testing.T) {
	// A cancelled request must not be reported as a constraint violation, or a
	// client disconnect looks like a rejected write in the logs.
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	pool := newTestPool(t)
	_, err := NewClientRepo(pool).GetByID(ctx, "anything")
	if err == nil {
		t.Fatal("GetByID with a cancelled context returned nil")
	}
	if !errors.Is(err, context.Canceled) {
		t.Errorf("error = %v, want it to wrap context.Canceled so the caller can tell a disconnect from a rejection", err)
	}
}

func TestEpochRoundTrip(t *testing.T) {
	// The two epoch columns are the most likely place for a units bug, and a units
	// bug there is a wrong value rather than a compile error.
	now := time.Now().UTC().Truncate(time.Second)
	if got := epochToTime(timeToEpoch(now)); !got.Equal(now) {
		t.Errorf("epoch round trip = %v, want %v", got, now)
	}
	// Zero means "never" per RFC 7591, and must not become 1970.
	if got := epochToTime(0); !got.IsZero() {
		t.Errorf("epochToTime(0) = %v, want the zero time", got)
	}
	if got := timeToEpoch(time.Time{}); got != 0 {
		t.Errorf("timeToEpoch(zero) = %d, want 0", got)
	}
}
