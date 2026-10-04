package domain

// Tests for the pure functions in this package. Everything here is a table
// driven case with no I/O, because the point of keeping this package free of
// dependencies is that its correctness can be checked without a database, a
// clock or an HTTP server.

import (
	"errors"
	"net/http"
	"reflect"
	"testing"
	"time"
)

func strptr(s string) *string { return &s }

// ----------------------------------------------------------------------------
// Scope normalisation and validation
// ----------------------------------------------------------------------------

func TestNormalizeScope(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		in   string
		want []string
	}{
		{
			name: "sorts so that two orderings of the same set are byte identical",
			in:   "profile openid email",
			want: []string{"email", "openid", "profile"},
		},
		{
			name: "reversed input produces the same result as forward input",
			in:   "email openid profile",
			want: []string{"email", "openid", "profile"},
		},
		{
			name: "deduplicates repeated scopes",
			in:   "openid email openid email",
			want: []string{"email", "openid"},
		},
		{
			name: "collapses runs of spaces",
			in:   "openid    email",
			want: []string{"email", "openid"},
		},
		{
			name: "trims leading and trailing spaces",
			in:   "  openid email  ",
			want: []string{"email", "openid"},
		},
		{
			name: "empty input yields an empty non-nil slice",
			in:   "",
			want: []string{},
		},
		{
			name: "whitespace only input yields an empty non-nil slice",
			in:   "   ",
			want: []string{},
		},
		{
			name: "single scope is left alone",
			in:   "openid",
			want: []string{"openid"},
		},
		{
			name: "colons and dots are inside the grammar",
			in:   "https://example.com/read urn:example:scope:1",
			want: []string{"https://example.com/read", "urn:example:scope:1"},
		},
		{
			name: "digits and underscores are inside the grammar",
			in:   "scope_1 scope2",
			want: []string{"scope2", "scope_1"},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			got := NormalizeScope(tc.in)
			if got == nil {
				t.Fatalf("NormalizeScope(%q) = nil, want non-nil empty-or-populated slice", tc.in)
			}
			if !reflect.DeepEqual(got, tc.want) {
				t.Errorf("NormalizeScope(%q) = %#v, want %#v", tc.in, got, tc.want)
			}
		})
	}
}

func TestNormalizeScopeDropsTokensOutsideGrammar(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		in   string
		want []string
	}{
		{
			// The double quote is the interesting one: it is the only
			// printable ASCII character inside the %x21-7E range that the
			// grammar excludes, and these values are interpolated into HTML.
			name: "double quote is dropped",
			in:   `openid email"`,
			want: []string{"openid"},
		},
		{
			// A control character is not a delimiter, so the whole run is one
			// malformed token and all of it goes. The important assertion is
			// that neither "openid" nor "email" survives as a valid scope.
			name: "control character invalidates the whole run",
			in:   "openid\x07email",
			want: []string{},
		},
		{
			name: "non ascii is dropped",
			in:   "openid \u00e9mail",
			want: []string{"openid"},
		},
		{
			// A non-breaking space is not %x20, so it is not a delimiter. If it
			// were treated as one, "openid email" would parse as two scopes
			// from a value the grammar reads as a single token.
			name: "non breaking space is not a delimiter",
			in:   "openid\u00a0email",
			want: []string{},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			if got := NormalizeScope(tc.in); !reflect.DeepEqual(got, tc.want) {
				t.Errorf("NormalizeScope(%q) = %#v, want %#v", tc.in, got, tc.want)
			}
		})
	}
}

func TestValidateScopeTokens(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		in      string
		wantErr bool
	}{
		{name: "single valid token", in: "openid"},
		{name: "several valid tokens", in: "openid email profile"},
		{name: "empty string is zero tokens and therefore valid", in: ""},
		{name: "double quote is rejected", in: `openid email"`, wantErr: true},
		{name: "backslash is rejected", in: `openid email\`, wantErr: true},
		{name: "non ascii is rejected", in: "openid \u00e9mail", wantErr: true},
		{name: "control character is rejected", in: "openid\x07", wantErr: true},
		{name: "doubled space is rejected rather than collapsed", in: "openid  email", wantErr: true},
		{name: "leading space is rejected", in: " openid", wantErr: true},
		{name: "trailing space is rejected", in: "openid ", wantErr: true},
		{name: "non breaking space is not a delimiter", in: "openid\u00a0email", wantErr: true},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			err := ValidateScopeTokens(tc.in)
			if tc.wantErr {
				if err == nil {
					t.Fatalf("ValidateScopeTokens(%q) = nil, want error", tc.in)
				}
				// The error must be an OAuth invalid_request so the HTTP layer
				// renders it as a protocol error rather than a 500.
				var oauthErr *OAuthError
				if !errors.As(err, &oauthErr) {
					t.Fatalf("ValidateScopeTokens(%q) returned %T, want wrapped *OAuthError", tc.in, err)
				}
				if oauthErr.Code != ErrCodeInvalidRequest {
					t.Errorf("ValidateScopeTokens(%q) code = %q, want %q", tc.in, oauthErr.Code, ErrCodeInvalidRequest)
				}
				return
			}
			if err != nil {
				t.Errorf("ValidateScopeTokens(%q) = %v, want nil", tc.in, err)
			}
		})
	}
}

func TestJoinScopeRoundTrips(t *testing.T) {
	t.Parallel()

	// JoinScope is the only encoder and NormalizeScope the only decoder, so a
	// round trip through both is the property that keeps a stored TEXT[] and a
	// wire string from drifting apart.
	tests := []struct {
		name  string
		scope []string
	}{
		{name: "single", scope: []string{"openid"}},
		{name: "several", scope: []string{"email", "openid", "profile"}},
		{name: "uri shaped", scope: []string{"https://example.com/read"}},
		{name: "empty", scope: []string{}},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			if err := ValidateScopeTokens(JoinScope(tc.scope)); err != nil {
				t.Fatalf("ValidateScopeTokens(JoinScope(%#v)) = %v", tc.scope, err)
			}
			if got := NormalizeScope(JoinScope(tc.scope)); !reflect.DeepEqual(got, NormalizeScopeSet(tc.scope)) {
				t.Errorf("round trip of %#v produced %#v", tc.scope, got)
			}
		})
	}
}

func TestScopeSetOperations(t *testing.T) {
	t.Parallel()

	granted := []string{"openid", "email", "profile"}
	allowed := []string{"openid", "email", "profile", "offline_access"}
	other := []string{"openid", "unknown_scope"}

	tests := []struct {
		name string
		got  bool
		want bool
	}{
		{name: "Contains finds a member", got: ScopeContains(granted, "email"), want: true},
		{name: "Contains rejects a non-member", got: ScopeContains(granted, "admin"), want: false},
		{name: "Contains rejects an empty set", got: ScopeContains(nil, "email"), want: false},

		{name: "ContainsAll is satisfied by a superset", got: ScopeContainsAll(granted, []string{"openid", "email"}), want: true},
		{name: "ContainsAll rejects partial coverage", got: ScopeContainsAll(granted, []string{"openid", "admin"}), want: false},
		{name: "ContainsAll accepts an empty request", got: ScopeContainsAll(granted, nil), want: true},

		{name: "IsSubset accepts a registered scope", got: ScopeIsSubset(granted, allowed), want: true},
		{name: "IsSubset rejects an unregistered scope", got: ScopeIsSubset(other, allowed), want: false},

		{name: "Equal is order insensitive", got: ScopeEqual([]string{"openid", "email"}, []string{"email", "openid"}), want: true},
		{name: "Equal rejects different lengths", got: ScopeEqual([]string{"openid"}, []string{"openid", "email"}), want: false},
		{name: "Equal rejects different members", got: ScopeEqual([]string{"openid"}, []string{"email"}), want: false},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			if tc.got != tc.want {
				t.Errorf("got %v, want %v", tc.got, tc.want)
			}
		})
	}
}

func TestScopeMissing(t *testing.T) {
	t.Parallel()

	granted := []string{"openid", "email"}
	requested := []string{"email", "profile", "offline_access", "address"}

	got := ScopeMissing(granted, requested)
	want := []string{"address", "offline_access", "profile"}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("ScopeMissing = %#v, want %#v (sorted)", got, want)
	}

	if got := ScopeMissing(granted, granted); len(got) != 0 {
		t.Errorf("ScopeMissing on a fully granted request = %#v, want empty", got)
	}
}

// ----------------------------------------------------------------------------
// Error constructors and HTTP status mapping
// ----------------------------------------------------------------------------

func TestErrorConstructors(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name       string
		err        *OAuthError
		wantCode   string
		wantStatus int
	}{
		{name: "invalid_request", err: NewInvalidRequest("d"), wantCode: ErrCodeInvalidRequest, wantStatus: http.StatusBadRequest},
		{name: "invalid_client", err: NewInvalidClient("d"), wantCode: ErrCodeInvalidClient, wantStatus: http.StatusUnauthorized},
		{name: "invalid_token", err: NewOAuthError(ErrCodeInvalidToken, "d"), wantCode: ErrCodeInvalidToken, wantStatus: http.StatusUnauthorized},
		{name: "invalid_grant", err: NewInvalidGrant("d"), wantCode: ErrCodeInvalidGrant, wantStatus: http.StatusBadRequest},
		{name: "unauthorized_client", err: NewUnauthorizedClient("d"), wantCode: ErrCodeUnauthorizedClient, wantStatus: http.StatusBadRequest},
		{name: "unsupported_grant_type", err: NewUnsupportedGrantType("d"), wantCode: ErrCodeUnsupportedGrantType, wantStatus: http.StatusBadRequest},
		{name: "invalid_scope", err: NewInvalidScope("d"), wantCode: ErrCodeInvalidScope, wantStatus: http.StatusBadRequest},
		{name: "access_denied", err: NewAccessDenied("d"), wantCode: ErrCodeAccessDenied, wantStatus: http.StatusForbidden},
		{name: "server_error", err: NewServerError("d"), wantCode: ErrCodeServerError, wantStatus: http.StatusInternalServerError},
		{name: "temporarily_unavailable", err: NewTemporarilyUnavailable("d"), wantCode: ErrCodeTemporarilyUnavailable, wantStatus: http.StatusServiceUnavailable},
		{name: "unsupported_response_type", err: NewUnsupportedResponseType("d"), wantCode: ErrCodeUnsupportedResponseType, wantStatus: http.StatusBadRequest},
		{name: "login_required", err: NewLoginRequired("d"), wantCode: ErrCodeLoginRequired, wantStatus: http.StatusBadRequest},
		{name: "consent_required", err: NewConsentRequired("d"), wantCode: ErrCodeConsentRequired, wantStatus: http.StatusBadRequest},
		{name: "interaction_required", err: NewInteractionRequired("d"), wantCode: ErrCodeInteractionRequired, wantStatus: http.StatusBadRequest},
		{name: "unsupported_token_type", err: NewUnsupportedTokenType("d"), wantCode: ErrCodeUnsupportedTokenType, wantStatus: http.StatusBadRequest},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			if tc.err.Code != tc.wantCode {
				t.Errorf("Code = %q, want %q", tc.err.Code, tc.wantCode)
			}
			if tc.err.HTTPStatus != tc.wantStatus {
				t.Errorf("HTTPStatus = %d, want %d", tc.err.HTTPStatus, tc.wantStatus)
			}
			if tc.err.Description != "d" {
				t.Errorf("Description = %q, want %q", tc.err.Description, "d")
			}
		})
	}
}

func TestNewOAuthErrorMapsStatus(t *testing.T) {
	t.Parallel()

	// NewOAuthError must not be able to invent a status: every code it accepts
	// goes through the same table the named constructors use.
	tests := []struct {
		code       string
		wantStatus int
	}{
		{code: ErrCodeInvalidClient, wantStatus: http.StatusUnauthorized},
		{code: ErrCodeInvalidToken, wantStatus: http.StatusUnauthorized},
		{code: ErrCodeAccessDenied, wantStatus: http.StatusForbidden},
		{code: ErrCodeServerError, wantStatus: http.StatusInternalServerError},
		{code: ErrCodeTemporarilyUnavailable, wantStatus: http.StatusServiceUnavailable},
		{code: ErrCodeInvalidGrant, wantStatus: http.StatusBadRequest},
		// An unregistered code must fall back to the default rather than panic
		// or invent a success status.
		{code: "some_future_code", wantStatus: http.StatusBadRequest},
	}

	for _, tc := range tests {
		t.Run(tc.code, func(t *testing.T) {
			t.Parallel()
			err := NewOAuthError(tc.code, "description")
			if err.HTTPStatus != tc.wantStatus {
				t.Errorf("status for %q = %d, want %d", tc.code, err.HTTPStatus, tc.wantStatus)
			}
		})
	}
}

func TestOAuthErrorError(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		err  *OAuthError
		want string
	}{
		{
			name: "code alone when there is no description",
			err:  &OAuthError{Code: ErrCodeInvalidGrant},
			want: ErrCodeInvalidGrant,
		},
		{
			name: "code and description when there is one",
			err:  &OAuthError{Code: ErrCodeInvalidGrant, Description: "expired"},
			want: ErrCodeInvalidGrant + ": expired",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			if got := tc.err.Error(); got != tc.want {
				t.Errorf("Error() = %q, want %q", got, tc.want)
			}
		})
	}
}

func TestOAuthErrorWithReturnsCopies(t *testing.T) {
	t.Parallel()

	// WithDescription and WithURI return copies. A shared error rewritten in
	// place would let one request's description leak into another's response.
	original := NewInvalidRequest("first")
	described := original.WithDescription("second")
	withURI := original.WithURI("https://example.com/e")

	if original.Description != "first" {
		t.Errorf("WithDescription mutated the original: %q", original.Description)
	}
	if original.URI != "" {
		t.Errorf("WithURI mutated the original: %q", original.URI)
	}
	if described.Description != "second" {
		t.Errorf("WithDescription = %q, want %q", described.Description, "second")
	}
	if withURI.URI != "https://example.com/e" {
		t.Errorf("WithURI = %q, want the supplied URI", withURI.URI)
	}
	if described.Code != original.Code || described.HTTPStatus != original.HTTPStatus {
		t.Errorf("the copy lost fields: %+v", described)
	}
}

func TestAsOAuthError(t *testing.T) {
	t.Parallel()

	direct := NewInvalidGrant("expired")
	wrapped := Wrapf(direct, "redeeming code %s", "abc")

	tests := []struct {
		name     string
		err      error
		wantOK   bool
		wantCode string
	}{
		{name: "unwrapped", err: direct, wantOK: true, wantCode: ErrCodeInvalidGrant},
		{name: "wrapped still matches through the chain", err: wrapped, wantOK: true, wantCode: ErrCodeInvalidGrant},
		{name: "internal sentinel is not an OAuth error", err: ErrNotFound},
		{name: "nil is not an OAuth error", err: nil},
		{name: "plain error is not an OAuth error", err: errors.New("boom")},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			got, ok := AsOAuthError(tc.err)
			if ok != tc.wantOK {
				t.Fatalf("AsOAuthError ok = %v, want %v", ok, tc.wantOK)
			}
			if ok && got.Code != tc.wantCode {
				t.Errorf("Code = %q, want %q", got.Code, tc.wantCode)
			}
		})
	}
}

func TestWrapf(t *testing.T) {
	t.Parallel()

	if got := Wrapf(nil, "context %d", 1); got != nil {
		t.Errorf("Wrapf(nil) = %v, want nil", got)
	}

	// errors.Is must survive the wrap; that is the entire purpose of Wrapf
	// existing alongside fmt.Errorf.
	err := Wrapf(ErrAlreadyConsumed, "consuming code %s for client %s", "hash", "client")
	if !errors.Is(err, ErrAlreadyConsumed) {
		t.Errorf("errors.Is could not find ErrAlreadyConsumed through %v", err)
	}

	sentinels := []error{
		ErrNotFound, ErrConflict, ErrAlreadyConsumed,
		ErrExpired, ErrNoActiveKey, ErrDisabled,
	}
	for _, sentinel := range sentinels {
		if !errors.Is(Wrapf(sentinel, "ctx"), sentinel) {
			t.Errorf("sentinel %v does not survive Wrapf", sentinel)
		}
	}
}

// ----------------------------------------------------------------------------
// Client redirect URI exact matching
// ----------------------------------------------------------------------------

func TestRedirectURIAllowedIsExact(t *testing.T) {
	t.Parallel()

	// Every case below is a way a looser matcher would accept a URI that was
	// never registered. The registered set is:
	//   https://app.example.com/callback
	//   https://app.example.com/callback2
	//   http://localhost:9000/callback
	//   com.example.app:/oauth2redirect
	client := &Client{
		ClientID: "app",
		RedirectURIs: []string{
			"https://app.example.com/callback",
			"https://app.example.com/callback2",
			"http://localhost:9000/callback",
			"com.example.app:/oauth2redirect",
		},
		PostLogoutRedirectURIs: []string{"https://app.example.com/logged-out"},
	}

	tests := []struct {
		name string
		uri  string
		want bool
	}{
		{name: "exact https match", uri: "https://app.example.com/callback", want: true},
		{name: "exact private-scheme match", uri: "com.example.app:/oauth2redirect", want: true},
		{name: "exact loopback match", uri: "http://localhost:9000/callback", want: true},

		{name: "prefix is not a match", uri: "https://app.example.com/callback/../evil", want: false},
		{name: "trailing slash is not a match", uri: "https://app.example.com/callback/", want: false},
		{name: "missing trailing slash is not a match", uri: "https://app.example.com", want: false},
		{name: "case differs in the path", uri: "https://app.example.com/Callback", want: false},
		{name: "case differs in the host", uri: "https://APP.example.com/callback", want: false},
		{name: "scheme downgrade to http", uri: "http://app.example.com/callback", want: false},
		{name: "scheme upgrade to wss", uri: "wss://app.example.com/callback", want: false},
		{name: "added port", uri: "https://app.example.com:443/callback", want: false},
		{name: "different loopback port", uri: "http://localhost:9001/callback", want: false},
		{name: "userinfo injection", uri: "https://evil.example.com@app.example.com/callback", want: false},
		{name: "attacker host", uri: "https://evil.example.com/callback", want: false},
		{name: "extra query is not a match", uri: "https://app.example.com/callback?next=https://evil.example.com", want: false},
		{name: "extra fragment is not a match", uri: "https://app.example.com/callback#x", want: false},
		{name: "subdomain is not a match", uri: "https://evil.app.example.com/callback", want: false},
		{name: "sibling name is not a match", uri: "https://app.example.com/callback2/evil", want: false},
		{name: "empty is not a match", uri: "", want: false},
		{name: "private scheme with a path is not a match", uri: "com.example.app:/oauth2redirect/extra", want: false},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			if got := client.RedirectURIAllowed(tc.uri); got != tc.want {
				t.Errorf("RedirectURIAllowed(%q) = %v, want %v", tc.uri, got, tc.want)
			}
		})
	}
}

func TestPostLogoutRedirectURIAllowedIsExact(t *testing.T) {
	t.Parallel()

	client := &Client{
		ClientID:               "app",
		PostLogoutRedirectURIs: []string{"https://app.example.com/logged-out"},
	}

	tests := []struct {
		name string
		uri  string
		want bool
	}{
		{name: "exact match", uri: "https://app.example.com/logged-out", want: true},
		// An unregistered post-logout URI must render a local confirmation page
		// instead of redirecting, so a false here is an open redirect.
		{name: "attacker host is refused", uri: "https://evil.example.com/", want: false},
		{name: "prefix is refused", uri: "https://app.example.com/logged-out/../evil", want: false},
		{name: "scheme downgrade is refused", uri: "http://app.example.com/logged-out", want: false},
		{name: "empty is refused", uri: "", want: false},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			if got := client.PostLogoutRedirectURIAllowed(tc.uri); got != tc.want {
				t.Errorf("PostLogoutRedirectURIAllowed(%q) = %v, want %v", tc.uri, got, tc.want)
			}
		})
	}
}

func TestClientConfidentialityIsDerived(t *testing.T) {
	t.Parallel()

	// There is no stored IsConfidential field, so the method is the only answer
	// and it must key off the auth method alone.
	tests := []struct {
		authMethod string
		want       bool
	}{
		{authMethod: AuthMethodClientSecretBasic, want: true},
		{authMethod: AuthMethodClientSecretPost, want: true},
		{authMethod: AuthMethodPrivateKeyJWT, want: true},
		{authMethod: AuthMethodNone, want: false},
		// An empty value is not a registered method, but it must not be
		// treated as public either; only the explicit `none` is public.
		{authMethod: "", want: true},
	}

	for _, tc := range tests {
		t.Run(tc.authMethod, func(t *testing.T) {
			t.Parallel()
			client := &Client{TokenEndpointAuthMethod: tc.authMethod}
			if got := client.IsConfidential(); got != tc.want {
				t.Errorf("IsConfidential() for %q = %v, want %v", tc.authMethod, got, tc.want)
			}
		})
	}
}

func TestClientState(t *testing.T) {
	t.Parallel()

	now := time.Now()
	disabledAt := now.Add(-time.Hour)

	enabled := &Client{
		GrantTypes:              []string{GrantAuthorizationCode, GrantRefreshToken},
		RedirectURIs:            []string{"https://app.example.com/callback"},
		PARRequired:             true,
		TokenEndpointAuthMethod: AuthMethodNone,
	}
	disabled := &Client{DisabledAt: &disabledAt}

	tests := []struct {
		name string
		got  bool
		want bool
	}{
		{name: "enabled client is enabled", got: enabled.IsEnabled(), want: true},
		{name: "disabled client is not enabled", got: disabled.IsEnabled(), want: false},
		{name: "supports a registered grant", got: enabled.SupportsGrant(GrantRefreshToken), want: true},
		{name: "rejects an unregistered grant", got: enabled.SupportsGrant(GrantClientCredentials), want: false},
		{name: "rejects the removed password grant", got: enabled.SupportsGrant("password"), want: false},
		{name: "requires PAR", got: enabled.RequiresPAR(), want: true},
		{name: "code grant can use a redirect", got: enabled.CanUseRedirect(GrantAuthorizationCode), want: true},
		{name: "client_credentials needs no redirect", got: enabled.CanUseRedirect(GrantClientCredentials), want: false},
		{name: "a code grant with no registered redirect cannot proceed", got: (&Client{}).CanUseRedirect(GrantAuthorizationCode), want: false},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			if tc.got != tc.want {
				t.Errorf("got %v, want %v", tc.got, tc.want)
			}
		})
	}
}

// ----------------------------------------------------------------------------
// Single-use marker helpers
// ----------------------------------------------------------------------------

func TestAuthCodeSingleUseMarker(t *testing.T) {
	t.Parallel()

	now := time.Now()
	usedAt := now.Add(-time.Minute)
	sessionID := "session-1"
	sid := "sid-1"

	tests := []struct {
		name           string
		code           *AuthCode
		wantUsable     bool
		wantConsumed   bool
		wantHasSession bool
	}{
		{
			name:       "unused and unexpired",
			code:       &AuthCode{ExpiresAt: now.Add(time.Minute)},
			wantUsable: true,
		},
		{
			name:         "used is not usable",
			code:         &AuthCode{ExpiresAt: now.Add(time.Minute), UsedAt: &usedAt},
			wantUsable:   false,
			wantConsumed: true,
		},
		{
			name:       "expired is not usable",
			code:       &AuthCode{ExpiresAt: now.Add(-time.Minute)},
			wantUsable: false,
		},
		{
			// The marker is the authority, so a used code stays used even if
			// the expiry has somehow been pushed into the future.
			name:         "used beats a future expiry",
			code:         &AuthCode{ExpiresAt: now.Add(time.Hour), UsedAt: &usedAt},
			wantUsable:   false,
			wantConsumed: true,
		},
		{
			name:       "expiry is exclusive at the boundary",
			code:       &AuthCode{ExpiresAt: now},
			wantUsable: false,
		},
		{
			name:           "session id present",
			code:           &AuthCode{ExpiresAt: now.Add(time.Minute), SessionID: &sessionID, SID: &sid},
			wantUsable:     true,
			wantHasSession: true,
		},
		{
			name:       "session id absent",
			code:       &AuthCode{ExpiresAt: now.Add(time.Minute), SessionID: strptr("")},
			wantUsable: true,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			if got := tc.code.IsUsable(now); got != tc.wantUsable {
				t.Errorf("IsUsable = %v, want %v", got, tc.wantUsable)
			}
			if got := tc.code.IsConsumed(); got != tc.wantConsumed {
				t.Errorf("IsConsumed = %v, want %v", got, tc.wantConsumed)
			}
			if got := tc.code.HasSession(); got != tc.wantHasSession {
				t.Errorf("HasSession = %v, want %v", got, tc.wantHasSession)
			}
		})
	}
}

func TestAuthRequestLifecycle(t *testing.T) {
	t.Parallel()

	now := time.Now()
	completedAt := now.Add(-time.Second)
	authTime := now.Add(-10 * time.Minute)
	userID := "user-1"
	sessionID := "session-1"

	live := &AuthRequest{ExpiresAt: now.Add(10 * time.Minute), UserID: &userID}
	expired := &AuthRequest{ExpiresAt: now.Add(-time.Second), UserID: &userID}
	completed := &AuthRequest{ExpiresAt: now.Add(10 * time.Minute), UserID: &userID, CompletedAt: &completedAt}
	unauthenticated := &AuthRequest{ExpiresAt: now.Add(10 * time.Minute)}

	tests := []struct {
		name          string
		req           *AuthRequest
		wantLive      bool
		wantExpired   bool
		wantCompleted bool
		wantNext      NextStep
	}{
		{name: "live and authenticated", req: live, wantLive: true, wantNext: NextStepConsent},
		// An expired request must be discarded, not shown a consent screen and
		// not silently restarted with parameters that can no longer succeed.
		{name: "expired", req: expired, wantLive: false, wantExpired: true, wantNext: NextStepExpired},
		// Completion is checked before anything else, so a double-submitted
		// consent form cannot re-enter the flow.
		{name: "completed is not live", req: completed, wantLive: false, wantCompleted: true, wantNext: NextStepComplete},
		{name: "no user yet", req: unauthenticated, wantLive: true, wantNext: NextStepLogin},
		// Completion outranks expiry: a request that was completed and then
		// aged out is still finished, not pending.
		{name: "completed outranks expiry", req: &AuthRequest{ExpiresAt: now.Add(-time.Minute), UserID: &userID, CompletedAt: &completedAt}, wantLive: false, wantExpired: true, wantCompleted: true, wantNext: NextStepComplete},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			if got := tc.req.IsLive(now); got != tc.wantLive {
				t.Errorf("IsLive = %v, want %v", got, tc.wantLive)
			}
			if got := tc.req.IsExpired(now); got != tc.wantExpired {
				t.Errorf("IsExpired = %v, want %v", got, tc.wantExpired)
			}
			if got := tc.req.IsCompleted(); got != tc.wantCompleted {
				t.Errorf("IsCompleted = %v, want %v", got, tc.wantCompleted)
			}
			if got := tc.req.NextStep(now); got != tc.wantNext {
				t.Errorf("NextStep = %q, want %q", got, tc.wantNext)
			}
		})
	}

	if !live.IsAuthenticated() {
		t.Error("live.IsAuthenticated() = false, want true")
	}
	if unauthenticated.IsAuthenticated() {
		t.Error("unauthenticated.IsAuthenticated() = true, want false")
	}

	withSession := &AuthRequest{SessionID: &sessionID}
	if !withSession.HasSession() {
		t.Error("HasSession = false, want true")
	}
	if (&AuthRequest{SessionID: strptr("")}).HasSession() {
		t.Error("HasSession with an empty id = true, want false")
	}

	_ = authTime
}

func TestPARRequestSingleUseMarker(t *testing.T) {
	t.Parallel()

	now := time.Now()
	consumedAt := now.Add(-time.Minute)

	tests := []struct {
		name           string
		req            *PARRequest
		wantConsumed   bool
		wantExpired    bool
		wantRedeemable bool
		wantOwnedBy    bool
	}{
		{
			name:           "fresh and unconsumed",
			req:            &PARRequest{ClientID: "app", ExpiresAt: now.Add(5 * time.Minute)},
			wantRedeemable: true,
			wantOwnedBy:    true,
		},
		{
			name:           "consumed is not redeemable",
			req:            &PARRequest{ClientID: "app", ExpiresAt: now.Add(5 * time.Minute), ConsumedAt: &consumedAt},
			wantConsumed:   true,
			wantRedeemable: false,
			wantOwnedBy:    true,
		},
		{
			name:           "expired is not redeemable",
			req:            &PARRequest{ClientID: "app", ExpiresAt: now.Add(-time.Minute)},
			wantExpired:    true,
			wantRedeemable: false,
			wantOwnedBy:    true,
		},
		{
			name:           "another client does not own it",
			req:            &PARRequest{ClientID: "other-app", ExpiresAt: now.Add(5 * time.Minute)},
			wantRedeemable: true,
			wantOwnedBy:    false,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			if got := tc.req.IsConsumed(); got != tc.wantConsumed {
				t.Errorf("IsConsumed = %v, want %v", got, tc.wantConsumed)
			}
			if got := tc.req.IsExpired(now); got != tc.wantExpired {
				t.Errorf("IsExpired = %v, want %v", got, tc.wantExpired)
			}
			if got := tc.req.IsRedeemable(now); got != tc.wantRedeemable {
				t.Errorf("IsRedeemable = %v, want %v", got, tc.wantRedeemable)
			}
			if got := tc.req.OwnedBy("app"); got != tc.wantOwnedBy {
				t.Errorf("OwnedBy = %v, want %v", got, tc.wantOwnedBy)
			}
		})
	}
}

func TestRefreshTokenSingleUseMarker(t *testing.T) {
	t.Parallel()

	now := time.Now()
	revokedAt := now.Add(-time.Minute)
	rotatedReason := RevocationReasonRotated
	reuseReason := RevocationReasonReuseCascade
	replacedBy := "next-hash"
	familyID := "family-1"

	tests := []struct {
		name        string
		token       *RefreshToken
		wantRevoked bool
		wantRotated bool
		wantExpired bool
		wantUsable  bool
		wantOwnedBy bool
	}{
		{
			name:        "active token",
			token:       &RefreshToken{ClientID: "app", ExpiresAt: now.Add(time.Hour), FamilyID: familyID},
			wantUsable:  true,
			wantOwnedBy: true,
		},
		{
			name:        "rotated token is revoked and not usable",
			token:       &RefreshToken{ClientID: "app", ExpiresAt: now.Add(time.Hour), FamilyID: familyID, RevokedAt: &revokedAt, RevocationReason: &rotatedReason, ReplacedByHash: &replacedBy},
			wantRevoked: true,
			wantRotated: true,
			wantUsable:  false,
			wantOwnedBy: true,
		},
		{
			// Reuse-cascade revocation is not a rotation. Collapsing the two
			// would make a stolen-token family look like a benign concurrent
			// refresh and suppress the reuse alarm.
			name:        "reuse cascade is revoked but not rotated",
			token:       &RefreshToken{ClientID: "app", ExpiresAt: now.Add(time.Hour), FamilyID: familyID, RevokedAt: &revokedAt, RevocationReason: &reuseReason},
			wantRevoked: true,
			wantRotated: false,
			wantUsable:  false,
			wantOwnedBy: true,
		},
		{
			name:        "expired token",
			token:       &RefreshToken{ClientID: "app", ExpiresAt: now.Add(-time.Minute), FamilyID: familyID},
			wantExpired: true,
			wantUsable:  false,
			wantOwnedBy: true,
		},
		{
			name:        "another client does not own it",
			token:       &RefreshToken{ClientID: "other-app", ExpiresAt: now.Add(time.Hour), FamilyID: familyID},
			wantUsable:  true,
			wantOwnedBy: false,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			if got := tc.token.IsRevoked(); got != tc.wantRevoked {
				t.Errorf("IsRevoked = %v, want %v", got, tc.wantRevoked)
			}
			if got := tc.token.WasRotated(); got != tc.wantRotated {
				t.Errorf("WasRotated = %v, want %v", got, tc.wantRotated)
			}
			if got := tc.token.IsExpired(now); got != tc.wantExpired {
				t.Errorf("IsExpired = %v, want %v", got, tc.wantExpired)
			}
			if got := tc.token.IsUsable(now); got != tc.wantUsable {
				t.Errorf("IsUsable = %v, want %v", got, tc.wantUsable)
			}
			if got := tc.token.OwnedBy("app"); got != tc.wantOwnedBy {
				t.Errorf("OwnedBy = %v, want %v", got, tc.wantOwnedBy)
			}
		})
	}
}

func TestMFABackupCodeSingleUseMarker(t *testing.T) {
	t.Parallel()

	now := time.Now()
	usedAt := now.Add(-time.Minute)

	tests := []struct {
		name       string
		code       *MFABackupCode
		wantUsed   bool
		wantUsable bool
	}{
		{name: "unused", code: &MFABackupCode{UserID: "user-1"}, wantUsable: true},
		{name: "used", code: &MFABackupCode{UserID: "user-1", UsedAt: &usedAt}, wantUsed: true, wantUsable: false},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			if got := tc.code.IsUsed(); got != tc.wantUsed {
				t.Errorf("IsUsed = %v, want %v", got, tc.wantUsed)
			}
			if got := tc.code.IsUsable(); got != tc.wantUsable {
				t.Errorf("IsUsable = %v, want %v", got, tc.wantUsable)
			}
		})
	}

	// A code presented against the wrong account must fail without being
	// burned, so ownership is checked before consumption.
	code := &MFABackupCode{UserID: "user-1"}
	if !code.BelongsTo("user-1") {
		t.Error("BelongsTo(owner) = false, want true")
	}
	if code.BelongsTo("user-2") {
		t.Error("BelongsTo(other) = true, want false")
	}
}

func TestEmailVerificationSingleUseMarker(t *testing.T) {
	t.Parallel()

	now := time.Now()
	usedAt := now.Add(-time.Minute)
	limit := 5

	tests := []struct {
		name        string
		v           *EmailVerification
		wantUsed    bool
		wantExpired bool
		wantRedeem  bool
	}{
		{
			name:       "fresh",
			v:          &EmailVerification{ExpiresAt: now.Add(time.Hour), TargetEmail: "user@example.com"},
			wantRedeem: true,
		},
		{
			name:     "used",
			v:        &EmailVerification{ExpiresAt: now.Add(time.Hour), TargetEmail: "user@example.com", UsedAt: &usedAt},
			wantUsed: true,
		},
		{
			name:        "expired",
			v:           &EmailVerification{ExpiresAt: now.Add(-time.Minute), TargetEmail: "user@example.com"},
			wantExpired: true,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			if got := tc.v.IsUsed(); got != tc.wantUsed {
				t.Errorf("IsUsed = %v, want %v", got, tc.wantUsed)
			}
			if got := tc.v.IsExpired(now); got != tc.wantExpired {
				t.Errorf("IsExpired = %v, want %v", got, tc.wantExpired)
			}
			if got := tc.v.IsRedeemable(now); got != tc.wantRedeem {
				t.Errorf("IsRedeemable = %v, want %v", got, tc.wantRedeem)
			}
		})
	}

	// The target is normalised to lower case, so the comparison must be too,
	// otherwise a mixed-case link address fails verification for no reason.
	v := &EmailVerification{TargetEmail: "user@example.com", ExpiresAt: now.Add(time.Hour)}
	if !v.CoversAddress("user@example.com") {
		t.Error("CoversAddress(exact) = false, want true")
	}
	if !v.CoversAddress("User@Example.com") {
		t.Error("CoversAddress(mixed case) = false, want true, comparison must be case insensitive")
	}
	if v.CoversAddress("other@example.com") {
		t.Error("CoversAddress(other) = true, want false")
	}

	if got := v.AttemptsRemaining(limit); got != limit {
		t.Errorf("AttemptsRemaining at zero attempts = %d, want %d", got, limit)
	}
	v.AttemptCount = 3
	if got := v.AttemptsRemaining(limit); got != 2 {
		t.Errorf("AttemptsRemaining at 3 attempts = %d, want 2", got)
	}
	v.AttemptCount = 99
	if got := v.AttemptsRemaining(limit); got != 0 {
		t.Errorf("AttemptsRemaining past the limit = %d, want 0, never negative", got)
	}
}
