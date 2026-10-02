// Configuration loading and validation. Loads YAML then overlays environment variables. Contains NO secrets. Durations are integer seconds converted explicitly, never time.Duration, because viper parses bare integers as nanoseconds. Refuses to start when a required secret is missing, malformed, or still set to an example value.

package config

import (
	"bytes"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"net/url"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/spf13/viper"
	"go.yaml.in/yaml/v3"
)

// Config is the whole application configuration.
//
// Secrets are NOT fields here. Key material and peppers are read directly from the
// environment by Secrets and passed to the components that need them, so that a
// Config value can be logged, printed in a crash dump, or serialised into a
// settings page without leaking anything. Every field below is safe to log.
type Config struct {
	Server       ServerConfig
	Database     DatabaseConfig
	Redis        RedisConfig
	Tokens       TokensConfig
	Keys         KeysConfig
	RateLimit    RateLimitConfig
	Security     SecurityConfig
	Registration RegistrationConfig
	Email        EmailConfig
	Backchannel  BackchannelConfig
	Audit        AuditConfig
	Logging      LoggingConfig

	// Env is the deployment environment name, used for the issuer scheme check.
	Env string
}

// ServerConfig is the HTTP listener and issuer identity.
type ServerConfig struct {
	Host string
	Port int

	// Issuer is the `iss` claim value and the base of every endpoint URL.
	Issuer string

	TrustProxyHeaders bool
	TrustedProxies    []string
}

// DatabaseConfig mirrors storage.Config. Duplicated rather than imported so this
// package has no dependency on the storage layer; main converts between them once.
type DatabaseConfig struct {
	URL                   string
	MaxConnections        int32
	MinConnections        int32
	StatementTimeoutMS    int
	ConnectTimeoutSeconds int
}

// RedisConfig covers the cache that holds only losable state.
type RedisConfig struct {
	URL string

	// RevocationTTLPaddingSeconds is added to a revocation entry's remaining
	// lifetime. The deny list may be consulted slightly past token expiry because
	// padding is what stops an entry expiring in the gap between the check and the
	// token's own expiry.
	RevocationTTLPaddingSeconds int

	FailClosedOnIntrospection bool
}

// TokensConfig holds every TTL, in seconds as configured.
//
// The fields are ints rather than time.Duration on purpose; see the package
// comment. Access() and friends convert once, at the edge.
type TokensConfig struct {
	AccessTTLSeconds            int
	RefreshIdleTTLSeconds       int
	RefreshAbsoluteTTLSeconds   int
	ClientCredentialsTTLSeconds int
	IDTokenTTLSeconds           int
	AuthorizationCodeTTLSeconds int
	PARTTLSeconds               int
	AuthRequestTTLSeconds       int
	EmailVerificationTTLSeconds int
	MFAPendingTTLSeconds        int
}

// KeysConfig holds signing key policy.
type KeysConfig struct {
	Algorithm        string
	KeySize          int
	RotationDays     int
	RetentionHours   int
	ClockSkewSeconds int
}

// RateLimitRule is one windowed limit.
type RateLimitRule struct {
	WindowSeconds int
	Limit         int
}

// RateLimitConfig holds the limits. Every one of them is a security control, so the
// loader refuses to produce a config with rate limiting silently disabled on the
// endpoints where it is load-bearing; see Validate.
type RateLimitConfig struct {
	Enabled bool

	Login struct {
		PerIP      RateLimitRule
		PerAccount RateLimitRule
	}
	MFA struct {
		PerPending    RateLimitRule
		TotalAttempts int
	}
	Token struct {
		PerClient            RateLimitRule
		PerIPUnauthenticated RateLimitRule
	}
	PAR struct {
		PerClient RateLimitRule
	}
	Register struct {
		PerIP RateLimitRule
	}
	ClientRegister struct {
		PerIP RateLimitRule
	}

	// FailClosed makes an unavailable Redis deny rather than allow. Required on
	// /authorize and /token; the loader enforces it.
	FailClosed bool
}

// Argon2Config holds the password KDF parameters.
type Argon2Config struct {
	MemoryKiB   uint32
	Iterations  uint32
	Parallelism uint8
	SaltLength  uint32
	KeyLength   uint32
}

// SecurityConfig holds credential, cookie and session policy.
type SecurityConfig struct {
	PasswordMinLength int
	Argon2            Argon2Config
	HighEntropyHash   string
	AuditPepperEnv    string

	MFAIssuer   string
	MFASkewStep int

	SessionIdleTimeoutSeconds     int
	SessionAbsoluteTimeoutSeconds int

	SessionCookieName     string
	SessionCookieSecure   bool
	SessionCookieSameSite string
	AuthRequestCookieName string

	AllowedInternalPaths []string
}

// RegistrationConfig holds registration policy.
type RegistrationConfig struct {
	ClientRegistrationEnabled               bool
	ClientRegistrationInitialAccessTokenEnv string
}

// EmailConfig holds SMTP transport settings. The password is read from the
// environment separately by Secrets, because it is a secret.
type EmailConfig struct {
	SMTPHost     string
	SMTPPort     int
	SMTPUsername string
	FromAddress  string
	FromName     string

	// EnumerationSafeResponses must be true. Registration and verification must
	// not reveal whether an address exists, in the body, the status, or the timing.
	// The loader refuses to start with it false.
	EnumerationSafeResponses bool
}

// BackchannelConfig holds OIDC back-channel logout delivery policy.
type BackchannelConfig struct {
	MaxAttempts    int
	BackoffSeconds []int
	TimeoutSeconds int
	AsyncQueue     bool
}

// AuditConfig holds audit retention policy.
type AuditConfig struct {
	RetainDays int
}

// LoggingConfig holds log output policy.
type LoggingConfig struct {
	Level  string
	Format string
}

// Secrets holds key material read from the environment.
//
// Separated from Config so that the two cannot be confused by accident. A caller
// that has a Config cannot log its way into a secret; a caller that needs a secret
// has to ask for Secrets explicitly, which is the point at which someone notices.
type Secrets struct {
	// KeyEncryptionKey is 32 bytes for AES-256-GCM, protecting signing keys and
	// TOTP secrets at rest.
	KeyEncryptionKey []byte

	// AuditPepper keys the HMAC-SHA256 applied to email addresses before they are
	// written to the audit log.
	AuditPepper []byte

	// ClientRegistrationInitialAccessToken gates POST /register when dynamic
	// registration is enabled. Empty when registration is disabled.
	ClientRegistrationInitialAccessToken string
}

// LoaderOptions control how configuration is found.
type LoaderOptions struct {
	// Path is the YAML file. Defaults to $OAUTH_CONFIG_FILE, then ./config.yaml.
	Path string

	// EnvPrefix is the environment variable prefix. Defaults to OAUTH_.
	EnvPrefix string

	// Environment is the process environment. Nil means os.Environ.
	Environment []string
}

// Load reads configuration from YAML and overlays the environment.
//
// Order: YAML first, then environment. Environment wins, so a deployment can
// override a checked-in file without editing it.
func Load(opts LoaderOptions) (*Config, Secrets, error) {
	env := opts.Environment
	if env == nil {
		env = os.Environ()
	}

	v := viper.New()
	v.SetConfigType("yaml")

	path := opts.Path
	if path == "" {
		path = firstNonEmptyEnv(env, "OAUTH_CONFIG_FILE", "config.yaml")
	}
	v.SetConfigFile(path)

	if err := v.ReadInConfig(); err != nil {
		return nil, Secrets{}, fmt.Errorf("config: read %s: %w", path, err)
	}

	prefix := opts.EnvPrefix
	if prefix == "" {
		prefix = "OAUTH_"
	}
	// The file's settings are snapshotted and the environment is merged into that
	// map, then the result is re-read. Doing it this way rather than calling
	// v.Set per override is not a style choice.
	//
	// v.Set REPLACES the subtree at the given key: Set("audit.pepper") installs a
	// fresh map at "audit", so audit.retain_days from the file is gone. Every
	// nested override therefore silently deleted its siblings, which presented as
	// "the environment variable had no effect" for the wrong reason and would have
	// shipped as a production misconfiguration. Mutating a copy of the settings map
	// and re-reading it cannot have that failure mode.
	settings := v.AllSettings()

	// Overlay the SUPPLIED environment.
	//
	// AutomaticEnv reads os.Environ() and nothing else, so a caller that passes a
	// controlled environment gets it ignored entirely and a test cannot exercise an
	// override at all. The supplied slice is authoritative here.
	// A prefixed variable that matches no settings key is a typo, and a typo in a
	// deployment variable is silent: the server starts with the file's value and
	// the operator believes the override applied. Failing here makes the mistake
	// visible at boot, which is the only moment anyone is watching.
	if err := applyEnvironment(settings, prefix, env, allowedUnsetEnvVars); err != nil {
		return nil, Secrets{}, err
	}

	merged, err := viperFromSettings(settings)
	if err != nil {
		return nil, Secrets{}, err
	}

	cfg := Decode(merged, env)

	secrets, err := LoadSecrets(cfg, env)
	if err != nil {
		return nil, Secrets{}, err
	}
	if err := cfg.Validate(secrets); err != nil {
		return nil, Secrets{}, err
	}
	return cfg, secrets, nil
}

// LoadSecrets reads key material from the environment.
//
// Returns an error rather than a partial Secrets, and never logs a value: a secret
// that failed validation must not be echoed into a startup log where it will be
// captured by whatever ships logs.
func LoadSecrets(cfg *Config, env []string) (Secrets, error) {
	var s Secrets

	key, err := decodeSecret(firstNonEmptyEnv(env, "OAUTH_KEY_ENCRYPTION_KEY", ""))
	if err != nil {
		return s, fmt.Errorf("config: OAUTH_KEY_ENCRYPTION_KEY: %w", err)
	}
	if len(key) != 32 {
		return s, fmt.Errorf("config: OAUTH_KEY_ENCRYPTION_KEY must be 32 bytes, got %d", len(key))
	}
	s.KeyEncryptionKey = key

	pepperEnv := cfg.Security.AuditPepperEnv
	if pepperEnv == "" {
		pepperEnv = "OAUTH_AUDIT_PEPPER"
	}
	pepper, err := decodeSecret(firstNonEmptyEnv(env, pepperEnv, ""))
	if err != nil {
		return s, fmt.Errorf("config: %s: %w", pepperEnv, err)
	}
	if len(pepper) < 32 {
		return s, fmt.Errorf("config: %s must be at least 32 bytes, got %d", pepperEnv, len(pepper))
	}
	s.AuditPepper = pepper

	tokenEnv := cfg.Registration.ClientRegistrationInitialAccessTokenEnv
	if tokenEnv == "" {
		tokenEnv = "OAUTH_CLIENT_REGISTRATION_INITIAL_ACCESS_TOKEN"
	}
	s.ClientRegistrationInitialAccessToken = firstNonEmptyEnv(env, tokenEnv, "")

	return s, nil
}

// exampleSecretValues are the placeholders that appear in .env.example and in
// documentation. A configuration still carrying one of these is a deployment that
// copied the example and did not read it.
//
// Refusing is the point: an AES key of "changeme" is not a weak key, it is no key,
// and the resulting server encrypts TOTP secrets under a value that is public in the
// repository.
var exampleSecretValues = map[string]struct{}{
	"":                                 {},
	"changeme":                         {},
	"change-me":                        {},
	"change_me":                        {},
	"please-change":                    {},
	"please_change":                    {},
	"replace-me":                       {},
	"replace_me":                       {},
	"0123456789abcdef0123456789abcdef": {},
	"secret":                           {},
	"password":                         {},
	"example":                          {},
}

// decodeSecret decodes a hex or base64 secret.
//
// Both encodings are accepted because both are what `openssl rand` and the common
// secret managers emit, and rejecting one of them would push operators toward
// pasting raw bytes into an environment variable, which does not survive a shell
// with any special characters in it.
func decodeSecret(raw string) ([]byte, error) {
	trimmed := strings.TrimSpace(raw)
	if _, isExample := exampleSecretValues[strings.ToLower(trimmed)]; isExample {
		return nil, errors.New("is empty or still set to an example value")
	}

	// Hex first: a 64-character hex string is unambiguous, whereas base64 of 32
	// bytes is 44 characters and can never be mistaken for hex.
	if len(trimmed) == 64 {
		if b, err := hex.DecodeString(trimmed); err == nil {
			return b, nil
		}
	}
	if b, err := base64.StdEncoding.DecodeString(trimmed); err == nil {
		return b, nil
	}
	if b, err := base64.RawStdEncoding.DecodeString(trimmed); err == nil {
		return b, nil
	}
	if b, err := base64.URLEncoding.DecodeString(trimmed); err == nil {
		return b, nil
	}

	return nil, errors.New("is neither valid hex nor base64")
}

// Validate enforces the invariants that configuration cannot express on its own.
//
// Every check here corresponds to a way the server can start and then be insecure,
// which is the failure this function exists to make impossible. A missing
// validation is not a missing feature; it is a server that boots.
func (c *Config) Validate(s Secrets) error {
	var problems []string

	// Issuer scheme. An http issuer outside development poisons the `iss` claim in
	// every relying party, and there is no way to detect that later from a token.
	if c.Server.Issuer == "" {
		problems = append(problems, "server.issuer is required")
	} else if u, err := url.Parse(c.Server.Issuer); err != nil {
		problems = append(problems, "server.issuer is not a URL")
	} else if u.Scheme != "https" && !c.isDevelopment() {
		problems = append(problems, "server.issuer must be https outside development")
	}

	if c.Database.URL == "" {
		problems = append(problems, "database.url is required")
	}
	if c.Redis.URL == "" {
		problems = append(problems, "redis.url is required")
	}

	// Key retention versus token lifetime. A key destroyed before every token it
	// signed has expired turns a valid token into a 500 for its holder, and the
	// cause is not visible from the token.
	if c.Keys.Algorithm != "RS256" && c.Keys.Algorithm != "ES256" {
		problems = append(problems, "keys.algorithm must be RS256 or ES256")
	}
	minRetentionHours := c.Tokens.AccessTTLSeconds/3600 + 2
	if c.Keys.RetentionHours < minRetentionHours {
		problems = append(problems, fmt.Sprintf(
			"keys.retention_hours (%d) must exceed tokens.access_ttl (%ds) plus clock skew; minimum is %d",
			c.Keys.RetentionHours, c.Tokens.AccessTTLSeconds, minRetentionHours))
	}

	if c.Tokens.AccessTTLSeconds <= 0 {
		problems = append(problems, "tokens.access_ttl must be positive")
	}
	if c.Tokens.RefreshIdleTTLSeconds <= 0 {
		problems = append(problems, "tokens.refresh_idle_ttl must be positive")
	}
	if c.Tokens.RefreshAbsoluteTTLSeconds < c.Tokens.RefreshIdleTTLSeconds {
		// An absolute ceiling below the idle lifetime is unreachable, so the
		// family never terminates regardless of activity.
		problems = append(problems, "tokens.refresh_absolute_ttl must be >= tokens.refresh_idle_ttl")
	}

	// Argon2. These are OWASP minimums as of the 2023 guidance; below them the
	// password hash is cheaper to attack than the attacker's budget assumes.
	if c.Security.Argon2.MemoryKiB < 19456 {
		problems = append(problems, "security.argon2.memory_kib must be >= 19456 (19 MiB, OWASP minimum)")
	}
	if c.Security.Argon2.Iterations < 2 {
		problems = append(problems, "security.argon2.iterations must be >= 2")
	}
	if c.Security.Argon2.Parallelism < 1 {
		problems = append(problems, "security.argon2.parallelism must be >= 1")
	}
	if c.Security.PasswordMinLength < 12 {
		problems = append(problems, "security.password_min_length must be >= 12")
	}

	// Rate limiting on the token endpoint is the only thing standing between a
	// credential-stuffing run and a fully automated account compromise.
	if !c.RateLimit.Enabled {
		problems = append(problems, "rate_limit.enabled must be true; there is no safe default off")
	}
	if c.RateLimit.Enabled && !c.RateLimit.FailClosed {
		problems = append(problems, "rate_limit.fail_closed must be true on /authorize and /token")
	}
	if c.RateLimit.Enabled && c.RateLimit.Login.PerIP.Limit <= 0 {
		problems = append(problems, "rate_limit.login.per_ip.limit must be positive")
	}

	// Anti-enumeration is not a tunable preference.
	if !c.Email.EnumerationSafeResponses {
		problems = append(problems, "email.enumeration_safe_responses must be true")
	}
	if c.Email.FromAddress == "" {
		problems = append(problems, "email.from_address is required")
	}

	// Dynamic client registration.
	if c.Registration.ClientRegistrationEnabled && s.ClientRegistrationInitialAccessToken == "" {
		// Open registration lets anyone mint a client with a redirect_uri they
		// control, which is the phishing half of an attack rather than the
		// authentication half.
		problems = append(problems, "registration.client_registration_enabled requires an initial access token")
	}

	// Session cookie hardening.
	if c.Security.SessionCookieName == "" {
		problems = append(problems, "security.session_cookie_name is required")
	} else if !c.isDevelopment() && !strings.HasPrefix(c.Security.SessionCookieName, "__Host-") {
		// Without the __Host- prefix a subdomain can set a cookie of the same
		// name for the parent domain and override the session.
		problems = append(problems, "security.session_cookie_name must use the __Host- prefix outside development")
	}
	// The Secure attribute and the issuer scheme have to agree, and the two
	// directions fail differently.
	if c.isDevelopment() && c.Security.SessionCookieSecure {
		// A browser will not send a Secure cookie over plain http, so this produces
		// an endless /login -> /authorize redirect loop that reads as a session bug
		// and is not one.
		problems = append(problems, "security.session_cookie_secure must be false in development over http")
	}
	if !c.isDevelopment() && !c.Security.SessionCookieSecure {
		// The other direction: without Secure, the session cookie travels in
		// cleartext over every request. Combined with the __Host- prefix required
		// above, which browsers only honour on a Secure cookie, this means the
		// cookie may not be set at all.
		problems = append(problems, "security.session_cookie_secure must be true outside development")
	}

	// Back-channel logout retries must be bounded and must have a timeout.
	if c.Backchannel.MaxAttempts < 1 {
		problems = append(problems, "backchannel_logout.max_attempts must be >= 1")
	}
	if c.Backchannel.TimeoutSeconds <= 0 {
		problems = append(problems, "backchannel_logout.timeout_seconds must be positive")
	}

	if c.Audit.RetainDays <= 0 {
		problems = append(problems, "audit.retain_days must be positive")
	}
	if c.Logging.Format != "json" && c.Logging.Format != "text" {
		problems = append(problems, "logging.format must be json or text")
	}

	if len(problems) > 0 {
		return fmt.Errorf("config: invalid configuration:\n  - %s", strings.Join(problems, "\n  - "))
	}
	return nil
}

func (c *Config) isDevelopment() bool {
	switch strings.ToLower(c.Env) {
	case "dev", "development", "local", "test", "testing":
		return true
	}
	return false
}

// AccessTTL returns tokens.access_ttl.
func (c TokensConfig) AccessTTL() time.Duration { return seconds(c.AccessTTLSeconds) }

// RefreshIdleTTL returns tokens.refresh_idle_ttl.
func (c TokensConfig) RefreshIdleTTL() time.Duration { return seconds(c.RefreshIdleTTLSeconds) }

// RefreshAbsoluteTTL returns tokens.refresh_absolute_ttl.
func (c TokensConfig) RefreshAbsoluteTTL() time.Duration { return seconds(c.RefreshAbsoluteTTLSeconds) }

// ClientCredentialsTTL returns tokens.client_credentials_ttl.
func (c TokensConfig) ClientCredentialsTTL() time.Duration {
	return seconds(c.ClientCredentialsTTLSeconds)
}

// IDTokenTTL returns tokens.id_token_ttl.
func (c TokensConfig) IDTokenTTL() time.Duration { return seconds(c.IDTokenTTLSeconds) }

// AuthorizationCodeTTL returns tokens.authorization_code_ttl.
func (c TokensConfig) AuthorizationCodeTTL() time.Duration {
	return seconds(c.AuthorizationCodeTTLSeconds)
}

// PARTTL returns tokens.par_ttl.
func (c TokensConfig) PARTTL() time.Duration { return seconds(c.PARTTLSeconds) }

// AuthRequestTTL returns tokens.auth_request_ttl.
func (c TokensConfig) AuthRequestTTL() time.Duration { return seconds(c.AuthRequestTTLSeconds) }

// EmailVerificationTTL returns tokens.email_verification_ttl.
func (c TokensConfig) EmailVerificationTTL() time.Duration {
	return seconds(c.EmailVerificationTTLSeconds)
}

// MFAPendingTTL returns tokens.mfa_pending_ttl.
func (c TokensConfig) MFAPendingTTL() time.Duration { return seconds(c.MFAPendingTTLSeconds) }

// StatementTimeout returns database.statement_timeout_ms.
func (c DatabaseConfig) StatementTimeout() time.Duration {
	return time.Duration(c.StatementTimeoutMS) * time.Millisecond
}

// ConnectTimeout returns database.connect_timeout_seconds.
func (c DatabaseConfig) ConnectTimeout() time.Duration { return seconds(c.ConnectTimeoutSeconds) }

// RevocationTTLPadding returns redis.revocation_ttl_padding_seconds.
func (c RedisConfig) RevocationTTLPadding() time.Duration {
	return seconds(c.RevocationTTLPaddingSeconds)
}

// RotationAfter returns keys.rotation_days.
func (c KeysConfig) RotationAfter() time.Duration { return seconds(c.RotationDays * 86400) }

// Retention returns keys.retention_hours.
func (c KeysConfig) Retention() time.Duration { return seconds(c.RetentionHours * 3600) }

// ClockSkew returns keys.clock_skew_seconds.
func (c KeysConfig) ClockSkew() time.Duration { return seconds(c.ClockSkewSeconds) }

// SessionIdleTimeout returns security.session_idle_timeout.
func (c SecurityConfig) SessionIdleTimeout() time.Duration {
	return seconds(c.SessionIdleTimeoutSeconds)
}

// SessionAbsoluteTimeout returns security.session_absolute_timeout.
func (c SecurityConfig) SessionAbsoluteTimeout() time.Duration {
	return seconds(c.SessionAbsoluteTimeoutSeconds)
}

// Decode builds a Config from a viper instance. Exposed for tests, which supply a
// viper directly rather than a file.
func Decode(v *viper.Viper, env []string) *Config {
	if env == nil {
		env = os.Environ()
	}
	cfg := &Config{
		Env: firstNonEmptyEnv(env, "OAUTH_ENV", "production"),
	}

	cfg.Server.Host = v.GetString("server.host")
	if cfg.Server.Host == "" {
		cfg.Server.Host = "0.0.0.0"
	}
	cfg.Server.Port = v.GetInt("server.port")
	if cfg.Server.Port == 0 {
		cfg.Server.Port = 8080
	}
	cfg.Server.Issuer = v.GetString("server.issuer")
	cfg.Server.TrustProxyHeaders = v.GetBool("server.trust_proxy_headers")
	cfg.Server.TrustedProxies = v.GetStringSlice("server.trusted_proxies")

	cfg.Database.URL = v.GetString("database.url")
	cfg.Database.MaxConnections = int32(v.GetInt("database.max_connections"))
	cfg.Database.MinConnections = int32(v.GetInt("database.min_connections"))
	cfg.Database.StatementTimeoutMS = v.GetInt("database.statement_timeout_ms")
	cfg.Database.ConnectTimeoutSeconds = v.GetInt("database.connect_timeout_seconds")

	cfg.Redis.URL = v.GetString("redis.url")
	cfg.Redis.RevocationTTLPaddingSeconds = v.GetInt("redis.revocation_ttl_padding_seconds")
	cfg.Redis.FailClosedOnIntrospection = v.GetBool("redis.fail_closed_on_introspection")

	cfg.Tokens.AccessTTLSeconds = v.GetInt("tokens.access_ttl")
	cfg.Tokens.RefreshIdleTTLSeconds = v.GetInt("tokens.refresh_idle_ttl")
	cfg.Tokens.RefreshAbsoluteTTLSeconds = v.GetInt("tokens.refresh_absolute_ttl")
	cfg.Tokens.ClientCredentialsTTLSeconds = v.GetInt("tokens.client_credentials_ttl")
	cfg.Tokens.IDTokenTTLSeconds = v.GetInt("tokens.id_token_ttl")
	cfg.Tokens.AuthorizationCodeTTLSeconds = v.GetInt("tokens.authorization_code_ttl")
	cfg.Tokens.PARTTLSeconds = v.GetInt("tokens.par_ttl")
	cfg.Tokens.AuthRequestTTLSeconds = v.GetInt("tokens.auth_request_ttl")
	cfg.Tokens.EmailVerificationTTLSeconds = v.GetInt("tokens.email_verification_ttl")
	cfg.Tokens.MFAPendingTTLSeconds = v.GetInt("tokens.mfa_pending_ttl")

	cfg.Keys.Algorithm = v.GetString("keys.algorithm")
	cfg.Keys.KeySize = v.GetInt("keys.key_size")
	cfg.Keys.RotationDays = v.GetInt("keys.rotation_days")
	cfg.Keys.RetentionHours = v.GetInt("keys.retention_hours")
	cfg.Keys.ClockSkewSeconds = v.GetInt("keys.clock_skew_seconds")

	cfg.RateLimit.Enabled = v.GetBool("rate_limit.enabled")
	cfg.RateLimit.FailClosed = v.GetBool("rate_limit.fail_closed")
	decodeRule(v, "rate_limit.login.per_ip", &cfg.RateLimit.Login.PerIP)
	decodeRule(v, "rate_limit.login.per_account", &cfg.RateLimit.Login.PerAccount)
	decodeRule(v, "rate_limit.mfa.per_pending", &cfg.RateLimit.MFA.PerPending)
	cfg.RateLimit.MFA.TotalAttempts = v.GetInt("rate_limit.mfa.total_attempts")
	decodeRule(v, "rate_limit.token.per_client", &cfg.RateLimit.Token.PerClient)
	decodeRule(v, "rate_limit.token.per_ip_unauthenticated", &cfg.RateLimit.Token.PerIPUnauthenticated)
	decodeRule(v, "rate_limit.par.per_client", &cfg.RateLimit.PAR.PerClient)
	decodeRule(v, "rate_limit.register.per_ip", &cfg.RateLimit.Register.PerIP)
	decodeRule(v, "rate_limit.client_register.per_ip", &cfg.RateLimit.ClientRegister.PerIP)

	cfg.Security.PasswordMinLength = v.GetInt("security.password_min_length")
	cfg.Security.Argon2.MemoryKiB = uint32(v.GetInt("security.argon2.memory_kib"))
	cfg.Security.Argon2.Iterations = uint32(v.GetInt("security.argon2.iterations"))
	cfg.Security.Argon2.Parallelism = uint8(v.GetInt("security.argon2.parallelism"))
	cfg.Security.Argon2.SaltLength = uint32(v.GetInt("security.argon2.salt_length"))
	cfg.Security.Argon2.KeyLength = uint32(v.GetInt("security.argon2.key_length"))
	cfg.Security.HighEntropyHash = v.GetString("security.high_entropy_hash")
	cfg.Security.AuditPepperEnv = v.GetString("security.audit_pepper_env")
	cfg.Security.MFAIssuer = v.GetString("security.mfa_issuer")
	cfg.Security.MFASkewStep = v.GetInt("security.mfa_skew_steps")
	cfg.Security.SessionIdleTimeoutSeconds = v.GetInt("security.session_idle_timeout")
	cfg.Security.SessionAbsoluteTimeoutSeconds = v.GetInt("security.session_absolute_timeout")
	cfg.Security.SessionCookieName = v.GetString("security.session_cookie_name")
	cfg.Security.SessionCookieSecure = v.GetBool("security.session_cookie_secure")
	cfg.Security.SessionCookieSameSite = v.GetString("security.session_cookie_same_site")
	cfg.Security.AuthRequestCookieName = v.GetString("security.auth_request_cookie_name")
	cfg.Security.AllowedInternalPaths = v.GetStringSlice("security.allowed_internal_paths")

	cfg.Registration.ClientRegistrationEnabled = v.GetBool("registration.client_registration_enabled")
	cfg.Registration.ClientRegistrationInitialAccessTokenEnv = v.GetString("registration.client_registration_initial_access_token_env")

	cfg.Email.SMTPHost = v.GetString("email.smtp_host")
	cfg.Email.SMTPPort = v.GetInt("email.smtp_port")
	cfg.Email.SMTPUsername = v.GetString("email.smtp_username")
	cfg.Email.FromAddress = v.GetString("email.from_address")
	cfg.Email.FromName = v.GetString("email.from_name")
	cfg.Email.EnumerationSafeResponses = v.GetBool("email.enumeration_safe_responses")

	cfg.Backchannel.MaxAttempts = v.GetInt("backchannel_logout.max_attempts")
	cfg.Backchannel.BackoffSeconds = v.GetIntSlice("backchannel_logout.backoff_seconds")
	cfg.Backchannel.TimeoutSeconds = v.GetInt("backchannel_logout.timeout_seconds")
	cfg.Backchannel.AsyncQueue = v.GetBool("backchannel_logout.async_queue")

	cfg.Audit.RetainDays = v.GetInt("audit.retain_days")

	cfg.Logging.Level = v.GetString("logging.level")
	cfg.Logging.Format = v.GetString("logging.format")

	return cfg
}

// allowedUnsetEnvVars are prefixed variables that legitimately have no counterpart
// in the settings map.
//
// Secrets and the environment name are read directly from the environment rather
// than through viper, so demanding a config key for them would demand a setting that
// must not exist in a file. Treating them as errors would make Load unusable with its
// own documented variables.
var allowedUnsetEnvVars = map[string]struct{}{
	"env":                {},
	"config_file":        {},
	"key_encryption_key": {},
	"audit_pepper":       {},
	"client_registration_initial_access_token": {},
}

// applyEnvironment merges every prefixed variable in env into settings.
//
// Key mapping is the reverse of the naming convention: strip the prefix, lowercase,
// and resolve underscores against the keys the file actually defines. Resolution is
// greedy longest-segment rather than "replace every underscore with a dot", because
// most keys in this file contain underscores inside a single segment —
// session_cookie_name is one key, not three — and a blind replacement produces
// security.session.cookie.name, which matches nothing.
//
// A prefixed variable that resolves to no known key is an error unless it is one of
// allowedUnsetEnvVars. Silently ignoring it would be the worse outcome: a deployment
// sets OAUTH_SERVER_ISSUERR by mistake, the server starts, and the operator believes
// the issuer is overridden when the file's value is still in force.
//
// Empty values are skipped, so that a blank exported variable in a shell profile does
// not blank out a value the file supplies. firstNonEmptyEnv treats empty as absent
// for the same reason.
func applyEnvironment(settings map[string]any, prefix string, env []string, allowed map[string]struct{}) error {
	known := knownKeys(settings)
	up := strings.ToUpper(prefix)
	var unresolved []string

	for _, kv := range env {
		name, value, found := strings.Cut(kv, "=")
		if !found || value == "" {
			continue
		}
		if !strings.HasPrefix(name, up) {
			continue
		}
		raw := strings.ToLower(strings.TrimPrefix(name, up))

		key, ok := resolveKey(raw, known)
		if !ok {
			if _, permitted := allowed[raw]; permitted {
				continue
			}
			unresolved = append(unresolved, name)
			continue
		}
		setKey(settings, key, value)
	}

	if len(unresolved) > 0 {
		return fmt.Errorf("config: %s %s no configuration key; check for a typo",
			strings.Join(unresolved, ", "), plural(len(unresolved), "sets", "set"))
	}
	return nil
}

func plural(n int, one, many string) string {
	if n == 1 {
		return one
	}
	return many
}

// setKey assigns value at a dotted path inside settings, creating intermediate maps.
//
// The existing intermediate maps are reused rather than replaced, which is the whole
// reason this exists instead of v.Set: replacing "tokens" to set one TTL loses every
// other TTL in it.
func setKey(settings map[string]any, key, value string) {
	segments := strings.Split(key, ".")
	current := settings

	for i, seg := range segments {
		if i == len(segments)-1 {
			current[seg] = coerceLike(current[seg], value)
			return
		}
		child, ok := current[seg]
		if !ok {
			// Nothing to preserve here, so a fresh map is correct rather than
			// destructive.
			child = map[string]any{}
			current[seg] = child
		}
		next, ok := child.(map[string]any)
		if !ok {
			// The existing value is a scalar, so it cannot be a parent. Replacing it
			// is forced; the original is kept under its own name so the conflict is
			// visible rather than silent.
			current[seg+"_scalar"] = child
			next = map[string]any{}
			current[seg] = next
		}
		current = next
	}
}

// coerceLike converts a string environment value to the type the file used.
//
// viper does this for keys read through GetInt and friends, but the merged map is
// read the same way, so an integer arriving as "9999" still works. Booleans are the
// case worth handling: "false" is truthy as a non-empty string in several paths, and
// a boolean that reads as true when the deployment set false is a security
// misconfiguration with no other symptom.
func coerceLike(existing any, value string) any {
	switch existing.(type) {
	case bool:
		return strings.EqualFold(value, "true") || value == "1"
	case int, int32, int64:
		if n, err := strconv.Atoi(value); err == nil {
			return n
		}
	case float64, float32:
		if f, err := strconv.ParseFloat(value, 64); err == nil {
			return f
		}
	}
	return value
}

// viperFromSettings builds a viper from an already-decoded settings map.
//
// Round-tripped through YAML because viper has no API for seeding arbitrary nested
// maps. The round trip is safe because the input came out of viper in the first
// place.
func viperFromSettings(settings map[string]any) (*viper.Viper, error) {
	encoded, err := yaml.Marshal(settings)
	if err != nil {
		return nil, fmt.Errorf("config: encode merged settings: %w", err)
	}

	v := viper.New()
	v.SetConfigType("yaml")
	if err := v.ReadConfig(bytes.NewReader(encoded)); err != nil {
		return nil, fmt.Errorf("config: re-read merged settings: %w", err)
	}
	return v, nil
}

// resolveKey maps an environment variable name to a dotted settings path.
//
// Walks the underscore-separated segments left to right, extending the candidate
// while it is a known key, and consumes as many segments as each match covers. So
// "rate_limit_enabled" resolves to rate_limit.enabled in two steps: "rate_limit" is
// not a leaf on its own but "rate_limit.enabled" is.
//
// The second return is false when no prefix of the name resolves, which is what lets
// Load tell a typo from a variable that legitimately has no settings key.
func resolveKey(name string, known map[string]string) (string, bool) {
	segments := strings.Split(name, "_")

	// Longest match first, so a key that itself contains an underscore wins over a
	// shorter match that would leave the remainder dangling.
	for start := 0; start < len(segments); start++ {
		for end := len(segments); end > start; end-- {
			if path, ok := known[strings.Join(segments[start:end], "_")]; ok {
				return path, true
			}
		}
	}
	return "", false
}

// knownKeys maps the underscore-joined form of every leaf key to its real dotted
// path.
//
// The two forms are not interchangeable, and conflating them is the bug this type
// exists to prevent. In this file the leaf under rate_limit is named "enabled" and
// the leaf under tokens is named "access_ttl": one underscore in the environment name
// is a segment separator and the other is part of a key name. A set of underscore
// strings cannot tell them apart, so "rate_limit_enabled" matches and then gets
// re-split into rate.limit.enabled, which is a path nothing reads — the override
// lands in a setting no caller consults, and the deployment believes it changed
// something.
//
// Storing the dotted path alongside makes resolution unambiguous: the underscore form
// is only ever a lookup key, and the answer is whatever the file actually called it.
//
// Leaves only, because a nested map (per_ip: {window_seconds, limit}) is not itself
// addressable and matching against it would let the walk stop one level too early.
func knownKeys(settings map[string]any) map[string]string {
	known := make(map[string]string)

	var walk func(path []string, value any)
	walk = func(path []string, value any) {
		if child, ok := value.(map[string]any); ok {
			for k, grandchild := range child {
				walk(append(path, k), grandchild)
			}
			return
		}
		known[strings.Join(path, "_")] = strings.Join(path, ".")
	}

	for k, raw := range settings {
		walk([]string{k}, raw)
	}
	return known
}

// decodeRule reads one windowed limit.
//
// Nested map keys such as per_ip: { window_seconds: 60, limit: 5 } are read with
// explicit dotted paths. Mapstructure's weak typing would also accept a bare
// integer here and silently read it as a nanosecond duration, which is the trap
// this package exists to avoid.
func decodeRule(v *viper.Viper, prefix string, dst *RateLimitRule) {
	dst.WindowSeconds = v.GetInt(prefix + ".window_seconds")
	dst.Limit = v.GetInt(prefix + ".limit")
}

// seconds converts a configured integer count of seconds to a Duration.
func seconds(n int) time.Duration {
	if n <= 0 {
		return 0
	}
	return time.Duration(n) * time.Second
}

// firstNonEmptyEnv returns the first non-empty value of key in env, falling back to
// fallback.
//
// Read from the supplied environment slice rather than os.Getenv so that a test can
// load a configuration against a controlled environment and be sure nothing leaked
// in from the real one.
func firstNonEmptyEnv(env []string, key, fallback string) string {
	prefix := key + "="
	for _, kv := range env {
		if strings.HasPrefix(kv, prefix) {
			if v := strings.TrimPrefix(kv, prefix); v != "" {
				return v
			}
		}
	}
	return fallback
}
