package config

import (
	"strings"
	"testing"
	"time"

	"github.com/spf13/viper"
)

// testEnv builds a valid environment. Every test that loads a config needs both
// secrets present, because refusing to start without them is itself the behaviour
// under test elsewhere and would otherwise mask what each test is actually checking.
func testEnv() []string {
	return []string{
		"OAUTH_ENV=development",
		"OAUTH_KEY_ENCRYPTION_KEY=0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
		"OAUTH_AUDIT_PEPPER=fedcba9876543210fedcba9876543210fedcba9876543210fedcba9876543210",
	}
}

// withEnv returns the base environment with extra overlaid by NAME.
//
// Overlay by name, not append. A duplicated variable in one environment slice is
// ambiguous, and firstNonEmptyEnv reads the first match, so appending an override
// after the base value would be silently ignored. That is a property of the test
// helper, not of the loader, and it is exactly the kind of thing that makes a test
// pass for the wrong reason.
func withEnv(extra ...string) []string {
	byName := map[string]string{}
	var order []string
	for _, kv := range append(testEnv(), extra...) {
		name, _, _ := strings.Cut(kv, "=")
		if _, seen := byName[name]; !seen {
			order = append(order, name)
		}
		byName[name] = kv
	}
	out := make([]string, 0, len(order))
	for _, name := range order {
		out = append(out, byName[name])
	}
	return out
}

// mustLoadSettings reads config.yaml and returns its settings map, the input
// applyEnvironment mutates.
func mustLoadSettings(t *testing.T) map[string]any {
	t.Helper()

	v := viper.New()
	v.SetConfigType("yaml")
	v.SetConfigFile("../../config.yaml")
	if err := v.ReadInConfig(); err != nil {
		t.Fatalf("read config.yaml: %v", err)
	}
	return v.AllSettings()
}

func loadConfig(t *testing.T, extra ...string) *Config {
	t.Helper()
	cfg, _, err := Load(LoaderOptions{
		Path:        "../../config.yaml",
		Environment: withEnv(extra...),
	})
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	return cfg
}

// TestLoadShippedConfig proves the checked-in config.yaml is internally consistent.
// A file that fails its own validation means every deployment starts by ignoring
// errors, and none of the invariants below are enforced anywhere.
func TestLoadShippedConfig(t *testing.T) {
	cfg := loadConfig(t)

	if cfg.Server.Port != 8080 {
		t.Errorf("Server.Port = %d, want 8080", cfg.Server.Port)
	}
	if cfg.Server.Issuer != "http://localhost:8080" {
		t.Errorf("Server.Issuer = %q", cfg.Server.Issuer)
	}
	// These are the viper nanoseconds trap in one block: bound directly to a
	// time.Duration, access_ttl would read as 900ns and every token would expire
	// before the request that made it returned.
	if got := cfg.Tokens.AccessTTL(); got != 15*time.Minute {
		t.Errorf("AccessTTL = %v, want 15m", got)
	}
	if got := cfg.Tokens.RefreshIdleTTL(); got != 30*24*time.Hour {
		t.Errorf("RefreshIdleTTL = %v, want 720h", got)
	}
	if got := cfg.Tokens.RefreshAbsoluteTTL(); got != 90*24*time.Hour {
		t.Errorf("RefreshAbsoluteTTL = %v, want 2160h", got)
	}
	if got := cfg.Tokens.PARTTL(); got != time.Minute {
		t.Errorf("PARTTL = %v, want 1m", got)
	}
	if got := cfg.Database.StatementTimeout(); got != 5*time.Second {
		t.Errorf("StatementTimeout = %v, want 5s", got)
	}
	if got := cfg.Keys.RotationAfter(); got != 30*24*time.Hour {
		t.Errorf("RotationAfter = %v, want 720h", got)
	}
	if got := cfg.Keys.Retention(); got != 48*time.Hour {
		t.Errorf("Retention = %v, want 48h", got)
	}
	if got := cfg.Security.SessionIdleTimeout(); got != time.Hour {
		t.Errorf("SessionIdleTimeout = %v, want 1h", got)
	}
	if cfg.RateLimit.Login.PerIP.Limit != 5 || cfg.RateLimit.Login.PerIP.WindowSeconds != 60 {
		t.Errorf("Login.PerIP = %+v", cfg.RateLimit.Login.PerIP)
	}
	if !cfg.Email.EnumerationSafeResponses {
		t.Error("EnumerationSafeResponses should be true in the shipped config")
	}
	if cfg.Registration.ClientRegistrationEnabled {
		t.Error("Dynamic client registration must be off by default")
	}
}

// TestEnvironmentOverridesFile is the reason environment beats YAML: a deployment
// must be able to change one value without editing a checked-in file.
func TestEnvironmentOverridesFile(t *testing.T) {
	cfg := loadConfig(t,
		"OAUTH_SERVER_PORT=9999",
		"OAUTH_SERVER_ISSUER=http://localhost:9999",
		"OAUTH_REDIS_URL=redis://cache:6379/3",
	)

	if cfg.Server.Port != 9999 {
		t.Errorf("Server.Port = %d, want 9999 from environment", cfg.Server.Port)
	}
	if cfg.Server.Issuer != "http://localhost:9999" {
		t.Errorf("Server.Issuer = %q, want the environment value", cfg.Server.Issuer)
	}
	if cfg.Redis.URL != "redis://cache:6379/3" {
		t.Errorf("Redis.URL = %q", cfg.Redis.URL)
	}
}

// TestSecretsAreReadFromEnvironmentOnly and are 32 bytes, which is what AES-256-GCM
// requires. A key of any other length fails at cipher construction, in a package far
// from the configuration that produced it.
func TestSecretsAreReadFromEnvironmentOnly(t *testing.T) {
	_, secrets, err := Load(LoaderOptions{Path: "../../config.yaml", Environment: testEnv()})
	if err != nil {
		t.Fatalf("Load: %v", err)
	}

	if len(secrets.KeyEncryptionKey) != 32 {
		t.Errorf("KeyEncryptionKey is %d bytes, want 32", len(secrets.KeyEncryptionKey))
	}
	if len(secrets.AuditPepper) != 32 {
		t.Errorf("AuditPepper is %d bytes, want 32", len(secrets.AuditPepper))
	}
}

// TestMissingSecretRefusesToStart is the important one. A server that boots without
// an encryption key does not fail loudly: it fails to decrypt every stored signing
// key on first use and serves errors until someone reads the log.
func TestMissingSecretRefusesToStart(t *testing.T) {
	env := []string{"OAUTH_ENV=development", "OAUTH_AUDIT_PEPPER=fedcba9876543210fedcba9876543210fedcba9876543210fedcba9876543210"}

	_, _, err := Load(LoaderOptions{Path: "../../config.yaml", Environment: env})
	if err == nil {
		t.Fatal("Load succeeded without OAUTH_KEY_ENCRYPTION_KEY")
	}
	if !strings.Contains(err.Error(), "OAUTH_KEY_ENCRYPTION_KEY") {
		t.Errorf("error does not name the missing secret: %v", err)
	}
}

// TestExampleSecretRefusesToStart covers the deployment that copied .env.example and
// did not change it. Encryption under a published key is not weak encryption.
func TestExampleSecretRefusesToStart(t *testing.T) {
	for _, placeholder := range []string{"changeme", "change-me", "CHANGEME", "  changeme  "} {
		env := withEnv("OAUTH_KEY_ENCRYPTION_KEY=" + placeholder)

		if _, _, err := Load(LoaderOptions{Path: "../../config.yaml", Environment: env}); err == nil {
			t.Errorf("Load accepted the example secret %q", placeholder)
		}
	}
}

func TestMalformedSecretRefusesToStart(t *testing.T) {
	env := withEnv("OAUTH_KEY_ENCRYPTION_KEY=not-valid-hex-or-base64!!")

	if _, _, err := Load(LoaderOptions{Path: "../../config.yaml", Environment: env}); err == nil {
		t.Fatal("Load accepted a malformed secret")
	}
}

// TestShortPepperRefusesToStart: an HMAC key shorter than its own output is
// truncated by construction, so a 16-byte pepper silently yields weaker pseudonyms
// than the documented construction claims.
func TestShortPepperRefusesToStart(t *testing.T) {
	env := []string{
		"OAUTH_ENV=development",
		"OAUTH_KEY_ENCRYPTION_KEY=0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
		"OAUTH_AUDIT_PEPPER=tooshort",
	}

	if _, _, err := Load(LoaderOptions{Path: "../../config.yaml", Environment: env}); err == nil {
		t.Fatal("Load accepted a pepper shorter than 32 bytes")
	}
}

// TestBase64SecretAccepted: operators paste base64 from secret managers far more
// often than hex, and refusing it pushes them toward raw bytes in an env var, which
// does not survive a shell with special characters in it.
func TestBase64SecretAccepted(t *testing.T) {
	const b64 = "MDEyMzQ1Njc4OWFiY2RlZjAxMjM0NTY3ODlhYmNkZWY="
	env := []string{
		"OAUTH_ENV=development",
		"OAUTH_KEY_ENCRYPTION_KEY=" + b64,
		"OAUTH_AUDIT_PEPPER=fedcba9876543210fedcba9876543210fedcba9876543210fedcba9876543210",
	}

	_, secrets, err := Load(LoaderOptions{Path: "../../config.yaml", Environment: env})
	if err != nil {
		t.Fatalf("Load rejected a base64 secret: %v", err)
	}
	if len(secrets.KeyEncryptionKey) != 32 {
		t.Errorf("decoded %d bytes, want 32", len(secrets.KeyEncryptionKey))
	}
}

// TestHttpIssuerRefusedInProduction: an http issuer poisons the `iss` claim in every
// relying party, and nothing downstream can detect it after the fact.
func TestHttpIssuerRefusedInProduction(t *testing.T) {
	env := withEnv(
		"OAUTH_ENV=production",
		"OAUTH_SERVER_ISSUER=http://localhost:8080",
	)

	_, _, err := Load(LoaderOptions{Path: "../../config.yaml", Environment: env})
	if err == nil {
		t.Fatal("Load accepted an http issuer in production")
	}
	if !strings.Contains(err.Error(), "https") {
		t.Errorf("error does not mention https: %v", err)
	}
}

func TestHttpsIssuerAcceptedInProduction(t *testing.T) {
	env := withEnv(
		"OAUTH_ENV=production",
		"OAUTH_SERVER_ISSUER=https://auth.example.com",
		// The cookie pair has to change with the scheme: a browser refuses a
		// __Host- cookie that is not Secure, and will not send a Secure cookie over
		// http. config.yaml ships the development pairing.
		"OAUTH_SECURITY_SESSION_COOKIE_NAME=__Host-oauth_session",
		"OAUTH_SECURITY_SESSION_COOKIE_SECURE=true",
	)

	if _, _, err := Load(LoaderOptions{Path: "../../config.yaml", Environment: env}); err != nil {
		t.Fatalf("Load rejected a valid production config: %v", err)
	}
}

// TestRetentionMustOutliveAccessToken is the invariant that makes rotation safe.
// Destroying a key before every token it signed has expired turns each of those
// tokens into a server error for its holder.
func TestRetentionMustOutliveAccessToken(t *testing.T) {
	// 999999s is ~11.5 days, against 48h of retention. The check is
	// retention_hours >= access_ttl/3600 + 2, so 165600s is the smallest value that
	// trips it; a merely large TTL stays legal and this test would pass for the
	// wrong reason.
	env := withEnv("OAUTH_TOKENS_ACCESS_TTL=999999")

	_, _, err := Load(LoaderOptions{Path: "../../config.yaml", Environment: env})
	if err == nil {
		t.Fatal("Load accepted a retention window shorter than the access token lifetime")
	}
	if !strings.Contains(err.Error(), "retention_hours") {
		t.Errorf("error does not name the setting: %v", err)
	}
}

// TestRefreshAbsoluteTTLMustNotBeBelowIdle: an absolute ceiling below the idle
// lifetime is unreachable, so a family never terminates however long it rotates.
func TestRefreshAbsoluteTTLMustNotBeBelowIdle(t *testing.T) {
	env := withEnv(
		"OAUTH_TOKENS_REFRESH_IDLE_TTL=2592000",
		"OAUTH_TOKENS_REFRESH_ABSOLUTE_TTL=60",
	)

	if _, _, err := Load(LoaderOptions{Path: "../../config.yaml", Environment: env}); err == nil {
		t.Fatal("Load accepted an absolute TTL below the idle TTL")
	}
}

func TestWeakArgon2Refused(t *testing.T) {
	env := withEnv("OAUTH_SECURITY_ARGON2_MEMORY_KIB=8192")

	if _, _, err := Load(LoaderOptions{Path: "../../config.yaml", Environment: env}); err == nil {
		t.Fatal("Load accepted argon2 memory below the OWASP minimum")
	}
}

// TestRateLimitCannotBeDisabled: /token rate limiting is the control that decides
// whether credential stuffing can run at machine speed, so an off switch is not a
// supported configuration.
func TestRateLimitCannotBeDisabled(t *testing.T) {
	env := withEnv("OAUTH_RATE_LIMIT_ENABLED=false")

	if _, _, err := Load(LoaderOptions{Path: "../../config.yaml", Environment: env}); err == nil {
		t.Fatal("Load accepted rate_limit.enabled=false")
	}
}

// TestRateLimitMustFailClosed: an unavailable Redis must deny. Allowing turns a
// Redis outage into a silent removal of the limit.
func TestRateLimitMustFailClosed(t *testing.T) {
	env := withEnv("OAUTH_RATE_LIMIT_FAIL_CLOSED=false")

	if _, _, err := Load(LoaderOptions{Path: "../../config.yaml", Environment: env}); err == nil {
		t.Fatal("Load accepted rate_limit.fail_closed=false")
	}
}

// TestEnumerationSafeResponsesCannotBeDisabled is not a preference. Registration
// that reveals which addresses exist turns account creation into an address
// harvesting tool.
func TestEnumerationSafeResponsesCannotBeDisabled(t *testing.T) {
	env := withEnv("OAUTH_EMAIL_ENUMERATION_SAFE_RESPONSES=false")

	if _, _, err := Load(LoaderOptions{Path: "../../config.yaml", Environment: env}); err == nil {
		t.Fatal("Load accepted enumeration_safe_responses=false")
	}
}

// TestOpenClientRegistrationRequiresInitialAccessToken: open registration lets
// anyone mint a client with a redirect_uri they control, which is the phishing half
// of an attack against the consent screen.
func TestOpenClientRegistrationRequiresInitialAccessToken(t *testing.T) {
	env := withEnv("OAUTH_REGISTRATION_CLIENT_REGISTRATION_ENABLED=true")

	_, _, err := Load(LoaderOptions{Path: "../../config.yaml", Environment: env})
	if err == nil {
		t.Fatal("Load accepted open client registration with no initial access token")
	}
	if !strings.Contains(err.Error(), "initial access token") {
		t.Errorf("error does not explain the missing token: %v", err)
	}
}

func TestClientRegistrationWithTokenIsAccepted(t *testing.T) {
	env := withEnv(
		"OAUTH_REGISTRATION_CLIENT_REGISTRATION_ENABLED=true",
		"OAUTH_CLIENT_REGISTRATION_INITIAL_ACCESS_TOKEN=a-real-token",
	)

	if _, _, err := Load(LoaderOptions{Path: "../../config.yaml", Environment: env}); err != nil {
		t.Fatalf("Load rejected gated client registration: %v", err)
	}
}

// TestSessionCookieMustUseHostPrefixOutsideDevelopment: without __Host- a
// subdomain can set a cookie of the same name for the parent domain and take the
// session over.
func TestSessionCookieMustUseHostPrefixOutsideDevelopment(t *testing.T) {
	env := withEnv(
		"OAUTH_ENV=production",
		"OAUTH_SERVER_ISSUER=https://auth.example.com",
		"OAUTH_SECURITY_SESSION_COOKIE_NAME=oauth_session",
	)

	if _, _, err := Load(LoaderOptions{Path: "../../config.yaml", Environment: env}); err == nil {
		t.Fatal("Load accepted a session cookie without the __Host- prefix in production")
	}
}

// TestSecureCookieRefusedOverHttpDev is the login-loop trap: a Secure cookie is
// never sent over http, so the user bounces between /login and /authorize for ever
// and it looks like a session bug.
func TestSecureCookieRefusedOverHttpDev(t *testing.T) {
	env := withEnv("OAUTH_SECURITY_SESSION_COOKIE_SECURE=true")

	_, _, err := Load(LoaderOptions{Path: "../../config.yaml", Environment: env})
	if err == nil {
		t.Fatal("Load accepted a Secure cookie in a development http deployment")
	}
	if !strings.Contains(err.Error(), "development") {
		t.Errorf("error does not explain why: %v", err)
	}
}

func TestBackchannelMustBeBounded(t *testing.T) {
	env := withEnv("OAUTH_BACKCHANNEL_LOGOUT_MAX_ATTEMPTS=0")

	if _, _, err := Load(LoaderOptions{Path: "../../config.yaml", Environment: env}); err == nil {
		t.Fatal("Load accepted an unbounded back-channel retry count")
	}
}

// TestValidationReportsEveryProblemAtOnce: an operator fixing a config should see
// every problem in one pass, not rediscover them one restart at a time.
func TestValidationReportsEveryProblemAtOnce(t *testing.T) {
	env := withEnv(
		"OAUTH_RATE_LIMIT_ENABLED=false",
		"OAUTH_EMAIL_ENUMERATION_SAFE_RESPONSES=false",
		"OAUTH_SERVER_ISSUER=http://x",
	)

	_, _, err := Load(LoaderOptions{Path: "../../config.yaml", Environment: env})
	if err == nil {
		t.Fatal("expected a validation error")
	}
	// OAUTH_ENV stays development, so the issuer override of http://x does NOT trip
	// the https check; only the two deliberate settings below should.
	msg := err.Error()
	for _, want := range []string{"rate_limit.enabled", "enumeration_safe_responses"} {
		if !strings.Contains(msg, want) {
			t.Errorf("error does not mention %q:\n%s", want, msg)
		}
	}
}

func TestMissingConfigFileIsAnError(t *testing.T) {
	if _, _, err := Load(LoaderOptions{Path: "does-not-exist.yaml", Environment: testEnv()}); err == nil {
		t.Fatal("Load accepted a nonexistent config file")
	}
}
