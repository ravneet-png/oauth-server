// Shared test helpers for the integration suite.

package integration

import (
	"context"
	"net/http"
	"net/url"
	"strings"
	"testing"

	"oauth-server/internal/crypto"
	"oauth-server/internal/domain"
	"oauth-server/test/fixtures"
)

const testRedirectURI = "https://app.example.test/callback"

// newConfidentialFlow registers a confidential authorization_code client and builds the PKCE pair.
func newConfidentialFlow(t *testing.T, e *env, clientID, secret string) *flow {
	t.Helper()

	client, secret := fixtures.ConfidentialClient(
		clientID, secret, "Example App",
		[]string{testRedirectURI},
		[]string{"authorization_code", "refresh_token"},
		[]string{"openid", "profile", "email", "offline_access"},
	)
	if err := e.App.Deps.Clients.Create(context.Background(), client); err != nil {
		t.Fatalf("create client: %v", err)
	}

	verifier := "test-verifier-that-is-long-enough-for-s256-checks-01"
	params := url.Values{
		"client_id":             {client.ClientID},
		"redirect_uri":          {testRedirectURI},
		"response_type":         {"code"},
		"scope":                 {"openid profile email"},
		"state":                 {"xyz-state-123"},
		"nonce":                 {"test-nonce"},
		"code_challenge":        {crypto.S256Challenge(verifier)},
		"code_challenge_method": {"S256"},
	}

	return &flow{
		client:     client,
		secret:     secret,
		verifier:   verifier,
		challenge:  params.Get("code_challenge"),
		state:      params.Get("state"),
		authParams: params,
	}
}

// newPublicFlow registers a public authorization_code client (no secret) with PKCE.
func newPublicFlow(t *testing.T, e *env, clientID string) *flow {
	t.Helper()

	client := fixtures.PublicClient(
		clientID, "Public App",
		[]string{testRedirectURI},
		[]string{"authorization_code", "refresh_token"},
		[]string{"openid", "profile", "email", "offline_access"},
	)
	if err := e.App.Deps.Clients.Create(context.Background(), client); err != nil {
		t.Fatalf("create public client: %v", err)
	}

	verifier := "test-verifier-that-is-long-enough-for-s256-checks-01"
	params := url.Values{
		"client_id":             {client.ClientID},
		"redirect_uri":          {testRedirectURI},
		"response_type":         {"code"},
		"scope":                 {"openid profile email"},
		"state":                 {"xyz-state-123"},
		"nonce":                 {"test-nonce"},
		"code_challenge":        {crypto.S256Challenge(verifier)},
		"code_challenge_method": {"S256"},
	}

	return &flow{
		client:     client,
		secret:     "",
		verifier:   verifier,
		challenge:  params.Get("code_challenge"),
		state:      params.Get("state"),
		authParams: params,
	}
}

// newFlowWithBackchannel creates a confidential client with optional backchannel logout URI.
func newFlowWithBackchannel(t *testing.T, e *env, clientID, secret, backchannelURI string) *flow {
	t.Helper()

	client, secret := fixtures.ConfidentialClient(
		clientID, secret, "Example App",
		[]string{testRedirectURI},
		[]string{"authorization_code", "refresh_token"},
		[]string{"openid", "profile", "email", "offline_access"},
	)
	if backchannelURI != "" {
		client.BackchannelLogoutURI = &backchannelURI
	}
	if err := e.App.Deps.Clients.Create(context.Background(), client); err != nil {
		t.Fatalf("create client: %v", err)
	}

	verifier := "test-verifier-that-is-long-enough-for-s256-checks-01"
	params := url.Values{
		"client_id":             {client.ClientID},
		"redirect_uri":          {testRedirectURI},
		"response_type":         {"code"},
		"scope":                 {"openid profile email"},
		"state":                 {"xyz-state-123"},
		"nonce":                 {"test-nonce"},
		"code_challenge":        {crypto.S256Challenge(verifier)},
		"code_challenge_method": {"S256"},
	}

	return &flow{
		client:     client,
		secret:     secret,
		verifier:   verifier,
		challenge:  params.Get("code_challenge"),
		state:      params.Get("state"),
		authParams: params,
	}
}

// flow drives one authorization request through the browser endpoints.
type flow struct {
	client     *domain.Client
	secret     string
	verifier   string
	challenge  string
	state      string
	authReqID  string
	authParams url.Values

	// startedWithCode is set when start found /authorize had already issued a code,
	// which happens when consent auto-skips. nextScreen is the path /authorize chose.
	startedWithCode *url.URL
	nextScreen      string
}

// start issues GET /authorize and returns the auth_request_id from the redirect to the
// next screen.
//
// The next screen depends on prior state: /login without a session, /consent with one.
// Both are recorded, because which one the server chose is exactly what decides whether
// the consent screen was skipped.
func (f *flow) start(t *testing.T, e *env) string {
	t.Helper()

	resp := e.get("/authorize?" + f.authParams.Encode())
	if resp.StatusCode != http.StatusSeeOther {
		t.Fatalf("authorize status = %d, want 303; body = %s", resp.StatusCode, body(t, resp))
	}

	loc, err := url.Parse(location(t, resp))
	if err != nil {
		t.Fatalf("parse Location: %v", err)
	}

	switch loc.Path {
	case "/login", "/consent", "/mfa":
	default:
		// A client redirect carrying a code means consent was auto-skipped and
		// /authorize answered the request itself.
		if loc.Query().Get("code") != "" {
			f.startedWithCode = loc
			return ""
		}
		t.Fatalf("authorize redirected to %q, want /login or /consent", loc.Path)
	}

	id := loc.Query().Get("auth_request_id")
	if id == "" {
		t.Fatalf("no auth_request_id in %q", loc)
	}
	f.authReqID = id
	f.nextScreen = loc.Path
	return id
}

// signIn submits the login form and returns the consent redirect.
func (f *flow) signIn(t *testing.T, e *env, email, password string) *response {
	t.Helper()

	page := e.get("/login?auth_request_id=" + url.QueryEscape(f.authReqID))
	if page.StatusCode != http.StatusOK {
		t.Fatalf("login page status = %d; body = %s", page.StatusCode, body(t, page))
	}

	resp := e.postForm("/login", url.Values{
		"csrf_token":      {hiddenInput(t, page, "csrf_token")},
		"auth_request_id": {f.authReqID},
		"email":           {email},
		"password":        {password},
	})
	if resp.StatusCode != http.StatusSeeOther {
		t.Fatalf("login submit status = %d, want 303; body = %s", resp.StatusCode, body(t, resp))
	}
	// Auto-skip returns the code to the client rather than stopping at /consent.
	if loc := location(t, resp); !strings.HasPrefix(loc, "/consent") && !strings.HasPrefix(loc, "/") {
		t.Fatalf("after login redirected to %q, want /consent", loc)
	}
	return resp
}

// allow grants consent and returns the authorization code from the client redirect.
func (f *flow) allow(t *testing.T, e *env) string {
	t.Helper()

	page := e.get("/consent?auth_request_id=" + url.QueryEscape(f.authReqID))
	if page.StatusCode != http.StatusOK {
		t.Fatalf("consent page status = %d; body = %s", page.StatusCode, body(t, page))
	}

	resp := e.postForm("/consent", url.Values{
		"csrf_token":      {hiddenInput(t, page, "csrf_token")},
		"auth_request_id": {f.authReqID},
		"decision":        {"allow"},
		"scope":           strings.Fields(f.authParams.Get("scope")),
	})
	if resp.StatusCode != http.StatusSeeOther {
		t.Fatalf("consent submit status = %d, want 303; location = %q; body = %s",
			resp.StatusCode, resp.Header.Get("Location"), body(t, resp))
	}

	loc, err := url.Parse(location(t, resp))
	if err != nil {
		t.Fatalf("parse redirect: %v", err)
	}

	code := loc.Query().Get("code")
	if code == "" {
		t.Fatalf("no code in redirect %q", loc)
	}
	return code
}

// exchange swaps the code for tokens at the token endpoint (confidential client).
func (f *flow) exchange(t *testing.T, e *env, code string) *tokenResponse {
	t.Helper()

	resp := e.postFormBasic("/token", url.Values{
		"grant_type":    {"authorization_code"},
		"code":          {code},
		"code_verifier": {f.verifier},
		"redirect_uri":  {testRedirectURI},
	}, f.client.ClientID, f.secret)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("token status = %d; body = %s", resp.StatusCode, body(t, resp))
	}

	var out tokenResponse
	decodeJSON(t, resp, &out)
	return &out
}

// exchangePublic swaps the code for tokens at the token endpoint (public client, no auth).
func (f *flow) exchangePublic(t *testing.T, e *env, code string) *tokenResponse {
	t.Helper()

	resp := e.postForm("/token", url.Values{
		"grant_type":    {"authorization_code"},
		"code":          {code},
		"code_verifier": {f.verifier},
		"redirect_uri":  {testRedirectURI},
		"client_id":     {f.client.ClientID},
	})
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("token status = %d; body = %s", resp.StatusCode, body(t, resp))
	}

	var out tokenResponse
	decodeJSON(t, resp, &out)
	return &out
}

// refresh uses a refresh token to get new tokens.
func (f *flow) refresh(t *testing.T, e *env, refreshToken string) *tokenResponse {
	t.Helper()

	resp := e.postFormBasic("/token", url.Values{
		"grant_type":    {"refresh_token"},
		"refresh_token": {refreshToken},
	}, f.client.ClientID, f.secret)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("refresh status = %d; body = %s", resp.StatusCode, body(t, resp))
	}

	var out tokenResponse
	decodeJSON(t, resp, &out)
	return &out
}

// tokenResponse is the token endpoint's JSON.
type tokenResponse struct {
	AccessToken  string `json:"access_token"`
	TokenType    string `json:"token_type"`
	ExpiresIn    int    `json:"expires_in"`
	RefreshToken string `json:"refresh_token"`
	IDToken      string `json:"id_token"`
	Scope        string `json:"scope"`
}

type parResponse struct {
	RequestURI string `json:"request_uri"`
	ExpiresIn  int    `json:"expires_in"`
}

// getSessionCookie extracts the session cookie value from the client's jar.
func getSessionCookie(t *testing.T, e *env) string {
	t.Helper()
	serverURL, _ := url.Parse(e.Server.URL)
	for _, c := range e.Client.Jar.Cookies(serverURL) {
		if c.Name == "session" {
			return c.Value
		}
	}
	t.Fatal("no session cookie found")
	return ""
}

// createUserWithPassword creates a user and returns the user + password.
func createUserWithPassword(t *testing.T, e *env, userID, email, password string, emailVerified bool) *domain.User {
	t.Helper()
	user, _ := fixtures.UserWithPassword(userID, email, password)
	user.EmailVerified = emailVerified
	if err := e.App.Deps.Users.Create(context.Background(), user); err != nil {
		t.Fatalf("create user: %v", err)
	}
	return user
}
