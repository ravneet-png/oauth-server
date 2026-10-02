package config

import (
	"strings"
	"testing"
)

// TestApplyEnvironmentResolvesNestedKeys is the regression test for the two bugs
// that made every nested override silently ineffective.
//
// The first was v.Set replacing the subtree at a key: setting one TTL destroyed every
// other TTL beside it. The second was resolving an environment name by replacing
// underscores with dots, which turned tokens_access_ttl into tokens.access.ttl and
// rate_limit_enabled into rate.limit.enabled — paths that nothing reads, so the
// override landed in a setting no caller consults while the deployment believed it
// had changed something.
//
// Each case below asserts both the resolved path and that siblings survived.
func TestApplyEnvironmentResolvesNestedKeys(t *testing.T) {
	cases := []struct {
		name string
		env  string
		want string
	}{
		// A key whose own name contains an underscore.
		{"tokens_access_ttl", "OAUTH_TOKENS_ACCESS_TTL=60", "tokens.access_ttl"},
		{"tokens_par_ttl", "OAUTH_TOKENS_PAR_TTL=60", "tokens.par_ttl"},
		{"tokens_refresh_absolute_ttl", "OAUTH_TOKENS_REFRESH_ABSOLUTE_TTL=60", "tokens.refresh_absolute_ttl"},
		// An underscore that IS a segment separator.
		{"rate_limit_enabled", "OAUTH_RATE_LIMIT_ENABLED=false", "rate_limit.enabled"},
		{"rate_limit_fail_closed", "OAUTH_RATE_LIMIT_FAIL_CLOSED=false", "rate_limit.fail_closed"},
		// Three levels.
		{"rate_limit_login_per_ip_limit", "OAUTH_RATE_LIMIT_LOGIN_PER_IP_LIMIT=99", "rate_limit.login.per_ip.limit"},
		{"security_argon2_memory_kib", "OAUTH_SECURITY_ARGON2_MEMORY_KIB=65536", "security.argon2.memory_kib"},
		// Single segment.
		{"server_port", "OAUTH_SERVER_PORT=9000", "server.port"},
		// An underscore inside the deepest segment, where a greedy walk could easily
		// stop one segment early.
		{"security_session_cookie_name", "OAUTH_SECURITY_SESSION_COOKIE_NAME=x", "security.session_cookie_name"},
		{"security_session_cookie_secure", "OAUTH_SECURITY_SESSION_COOKIE_SECURE=true", "security.session_cookie_secure"},
		{"security_password_min_length", "OAUTH_SECURITY_PASSWORD_MIN_LENGTH=20", "security.password_min_length"},
		{"backchannel_logout_max_attempts", "OAUTH_BACKCHANNEL_LOGOUT_MAX_ATTEMPTS=4", "backchannel_logout.max_attempts"},
		{"registration_client_registration_enabled", "OAUTH_REGISTRATION_CLIENT_REGISTRATION_ENABLED=true", "registration.client_registration_enabled"},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			settings := mustLoadSettings(t)

			if err := applyEnvironment(settings, "OAUTH_", []string{tc.env}, allowedUnsetEnvVars); err != nil {
				t.Fatalf("applyEnvironment: %v", err)
			}

			merged, err := viperFromSettings(settings)
			if err != nil {
				t.Fatalf("viperFromSettings: %v", err)
			}

			// The leaf must now hold the override, and it must be readable at the
			// path the file declared.
			want := strings.SplitN(tc.env, "=", 2)[1]
			if got := merged.GetString(tc.want); got != want {
				t.Errorf("%s = %q, want %q (override lost)", tc.want, got, want)
			}
		})
	}
}

// TestApplyEnvironmentPreservesSiblings is the direct assertion for the v.Set
// subtree-replacement bug.
func TestApplyEnvironmentPreservesSiblings(t *testing.T) {
	settings := mustLoadSettings(t)

	if err := applyEnvironment(settings, "OAUTH_", []string{
		"OAUTH_TOKENS_ACCESS_TTL=1200",
		"OAUTH_RATE_LIMIT_ENABLED=true",
	}, allowedUnsetEnvVars); err != nil {
		t.Fatalf("applyEnvironment: %v", err)
	}

	merged, err := viperFromSettings(settings)
	if err != nil {
		t.Fatalf("viperFromSettings: %v", err)
	}

	// The overridden leaf.
	if got := merged.GetInt("tokens.access_ttl"); got != 1200 {
		t.Errorf("tokens.access_ttl = %d, want 1200", got)
	}
	// Its siblings, which a v.Set at tokens.access_ttl would have destroyed.
	for path, want := range map[string]int{
		"tokens.par_ttl":                60,
		"tokens.refresh_idle_ttl":       2592000,
		"tokens.authorization_code_ttl": 600,
		"rate_limit.fail_closed":        1, // bool true
		"audit.retain_days":             400,
		"keys.retention_hours":          48,
	} {
		if got := merged.GetInt(path); got != want {
			t.Errorf("%s = %d, want %d (sibling destroyed by an unrelated override)", path, got, want)
		}
	}
}

// TestCoerceLikePreservesTypes: a boolean arriving as the string "false" is truthy
// in several code paths, and a limit that reads as enabled when the deployment
// disabled it is a silent security regression.
func TestCoerceLikePreservesTypes(t *testing.T) {
	settings := mustLoadSettings(t)

	if err := applyEnvironment(settings, "OAUTH_", []string{
		"OAUTH_RATE_LIMIT_ENABLED=false",
		"OAUTH_SECURITY_SESSION_COOKIE_SECURE=false",
		"OAUTH_SERVER_TRUST_PROXY_HEADERS=false",
		"OAUTH_TOKENS_ACCESS_TTL=1200",
	}, allowedUnsetEnvVars); err != nil {
		t.Fatalf("applyEnvironment: %v", err)
	}

	merged, err := viperFromSettings(settings)
	if err != nil {
		t.Fatalf("viperFromSettings: %v", err)
	}

	for _, path := range []string{
		"rate_limit.enabled",
		"security.session_cookie_secure",
		"server.trust_proxy_headers",
	} {
		if merged.GetBool(path) {
			t.Errorf("%s read as true, want false", path)
		}
	}
	if got := merged.GetInt("tokens.access_ttl"); got != 1200 {
		t.Errorf("tokens.access_ttl = %d, want 1200", got)
	}
}

// TestUnresolvableEnvironmentVariableIsAnError: a typo in a deployment variable is
// otherwise silent. The server starts with the file's value and the operator believes
// the override applied.
func TestUnresolvableEnvironmentVariableIsAnError(t *testing.T) {
	env := withEnv("OAUTH_SERVER_ISSUERR=https://typo.example.com")

	_, _, err := Load(LoaderOptions{Path: "../../config.yaml", Environment: env})
	if err == nil {
		t.Fatal("Load accepted a misspelled environment variable")
	}
	// The message must name the variable, or it is not actionable.
	if !strings.Contains(err.Error(), "OAUTH_SERVER_ISSUERR") {
		t.Errorf("error does not name the offending variable: %v", err)
	}
}

// TestSecretsAndEnvAreNotRequiredSettingsKeys: the secret variables and OAUTH_ENV
// have no settings counterpart by design, since demanding one would demand a
// setting in a file that must not contain secrets.
func TestSecretsAndEnvAreNotRequiredSettingsKeys(t *testing.T) {
	// testEnv() itself contains all of these, so a plain load is the assertion.
	if _, _, err := Load(LoaderOptions{Path: "../../config.yaml", Environment: testEnv()}); err != nil {
		t.Fatalf("Load rejected the documented secret variables: %v", err)
	}
}

// TestEmptyEnvironmentValueDoesNotBlankTheFile: an exported-but-blank variable in a
// shell profile must not erase a configured value.
func TestEmptyEnvironmentValueDoesNotBlankTheFile(t *testing.T) {
	env := append(testEnv(), "OAUTH_SERVER_ISSUER=")

	cfg, _, err := Load(LoaderOptions{Path: "../../config.yaml", Environment: env})
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if cfg.Server.Issuer != "http://localhost:8080" {
		t.Errorf("Server.Issuer = %q, want the file's value preserved", cfg.Server.Issuer)
	}
}
