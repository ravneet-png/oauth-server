// Private key JWT client authentication: a valid assertion authenticates the client
// at the token endpoint, a replayed one is refused.

package integration

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"encoding/json"
	"net/http"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/lestrrat-go/jwx/v2/jwa"
	"github.com/lestrrat-go/jwx/v2/jwk"
	"github.com/lestrrat-go/jwx/v2/jws"
	"github.com/lestrrat-go/jwx/v2/jwt"

	"oauth-server/internal/crypto"
	"oauth-server/internal/domain"
)

const assertionType = "urn:ietf:params:oauth:client-assertion-type:jwt-bearer"

// pkjwtClient builds a private_key_jwt client publishing pub as its verification key.
func pkjwtClient(t *testing.T, clientID string, pub jwk.Key) *domain.Client {
	t.Helper()

	pub.Set(jwk.KeyIDKey, "pkjwt-key-1")
	pub.Set(jwk.AlgorithmKey, jwa.RS256)

	set := jwk.NewSet()
	if err := set.AddKey(pub); err != nil {
		t.Fatalf("build jwk set: %v", err)
	}
	encoded, err := json.Marshal(set)
	if err != nil {
		t.Fatalf("encode jwk set: %v", err)
	}

	// A private_key_jwt client is confidential: the schema requires a secret hash for
	// every method except `none`, even though authentication never uses it.
	hash := crypto.SHA256Hex("unused-for-private-key-jwt")
	now := time.Now().UTC()

	return &domain.Client{
		ClientID:                clientID,
		ClientSecretHash:        &hash,
		ClientIDIssuedAt:        now,
		ClientSecretExpiresAt:   now.Add(365 * 24 * time.Hour),
		ClientName:              "PKJWT App",
		RedirectURIs:            []string{testRedirectURI},
		GrantTypes:              []string{"authorization_code", "refresh_token"},
		ResponseTypes:           []string{"code"},
		Scopes:                  []string{"openid", "profile", "email", "offline_access"},
		Contacts:                []string{},
		PostLogoutRedirectURIs:  []string{},
		TokenEndpointAuthMethod: domain.AuthMethodPrivateKeyJWT,
		TokenTTL:                15 * time.Minute,
		RefreshIdleTTL:          30 * 24 * time.Hour,
		ClientCredentialsTTL:    15 * time.Minute,
		SubjectType:             domain.SubjectTypePublic,
		JWKSet:                  encoded,
	}
}

// signAssertion produces a client_assertion for clientID, signed by key.
func signAssertion(t *testing.T, key *rsa.PrivateKey, clientID, tokenURL, jti string) string {
	t.Helper()

	now := time.Now().UTC()
	tok, err := jwt.NewBuilder().
		Issuer(clientID).
		Subject(clientID).
		Audience([]string{tokenURL}).
		IssuedAt(now).
		Expiration(now.Add(5 * time.Minute)).
		JwtID(jti).
		Build()
	if err != nil {
		t.Fatalf("build assertion: %v", err)
	}

	hdrs := jws.NewHeaders()
	if err := hdrs.Set(jws.KeyIDKey, "pkjwt-key-1"); err != nil {
		t.Fatalf("set kid: %v", err)
	}

	signed, err := jwt.Sign(tok,
		jwt.WithKey(jwa.RS256, key, jws.WithProtectedHeaders(hdrs)))
	if err != nil {
		t.Fatalf("sign assertion: %v", err)
	}
	return string(signed)
}

// grantCode drives the browser half of the flow and returns an authorization code.
//
// Which screens appear depends on prior state: /authorize routes to /login without a
// session and /consent with one, and /consent itself auto-skips when a standing grant
// already covers the request. This helper follows whatever path the server chose and
// asserts only the thing the caller cares about, that a code came back.
func grantCode(t *testing.T, e *env, f *flow, user *domain.User) string {
	t.Helper()

	// A fresh authorization request each time: auth_requests rows are single-use, so
	// reusing f.authReqID makes the second login fail on a row that no longer exists.
	f.authReqID = ""
	f.startedWithCode = nil
	f.nextScreen = ""

	// codeFrom pulls the code out of a redirect that already carries one.
	codeFrom := func(resp *response, what string) string {
		t.Helper()
		loc, err := url.Parse(location(t, resp))
		if err != nil {
			t.Fatalf("parse %s redirect: %v", what, err)
		}
		code := loc.Query().Get("code")
		if code == "" {
			t.Fatalf("%s redirect carried no code: %q", what, loc)
		}
		return code
	}

	f.start(t, e)

	// Consent auto-skipped and /authorize answered the request itself.
	if u := f.startedWithCode; u != nil {
		return u.Query().Get("code")
	}

	if f.nextScreen == "/login" {
		page := e.get("/login?auth_request_id=" + url.QueryEscape(f.authReqID))
		if page.StatusCode != http.StatusOK {
			t.Fatalf("login page status = %d; body = %s", page.StatusCode, body(t, page))
		}
		resp := e.postForm("/login", url.Values{
			"csrf_token":      {hiddenInput(t, page, "csrf_token")},
			"auth_request_id": {f.authReqID},
			"email":           {user.Email},
			"password":        {"correct horse battery"},
		})
		if resp.StatusCode != http.StatusSeeOther {
			t.Fatalf("login submit status = %d, want 303; body = %s", resp.StatusCode, body(t, resp))
		}
		// Establishes the session, then routes to /consent.
		if !strings.HasPrefix(location(t, resp), "/consent") {
			return codeFrom(resp, "login")
		}
	}

	// Either /authorize chose /consent directly, or login just handed us to it.
	page := e.get("/consent?auth_request_id=" + url.QueryEscape(f.authReqID))
	switch {
	case page.StatusCode == http.StatusSeeOther:
		// Auto-skipped: the grant covered the request and the code is already issued.
		return codeFrom(page, "consent")
	case page.StatusCode != http.StatusOK:
		t.Fatalf("consent page status = %d; body = %s", page.StatusCode, body(t, page))
	}

	resp := e.postForm("/consent", url.Values{
		"csrf_token":      {hiddenInput(t, page, "csrf_token")},
		"auth_request_id": {f.authReqID},
		"decision":        {"allow"},
		"scope":           strings.Fields(f.authParams.Get("scope")),
	})
	if resp.StatusCode != http.StatusSeeOther {
		t.Fatalf("consent submit status = %d, want 303; body = %s", resp.StatusCode, body(t, resp))
	}
	return codeFrom(resp, "consent")
}

func TestPrivateKeyJWTAuthenticatesTokenRequest(t *testing.T) {
	e := newEnv(t)

	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	pub, err := jwk.FromRaw(key.Public())
	if err != nil {
		t.Fatalf("derive public jwk: %v", err)
	}

	client := pkjwtClient(t, "pkjwt-app-1", pub)
	if err := e.App.Deps.Clients.Create(context.Background(), client); err != nil {
		t.Fatalf("create client: %v", err)
	}

	user := createUserWithPassword(t, e, "user-pkjwt-1", "alice@example.test", "correct horse battery", true)

	f := &flow{
		client:   client,
		secret:   "",
		verifier: "test-verifier-that-is-long-enough-for-s256-checks-01",
		authParams: url.Values{
			"client_id":             {client.ClientID},
			"redirect_uri":          {testRedirectURI},
			"response_type":         {"code"},
			"scope":                 {"openid profile email"},
			"state":                 {"xyz-state-pkjwt"},
			"nonce":                 {"test-nonce-pkjwt"},
			"code_challenge":        {crypto.S256Challenge("test-verifier-that-is-long-enough-for-s256-checks-01")},
			"code_challenge_method": {"S256"},
		},
	}

	code := grantCode(t, e, f, user)

	// The expected aud is the configured issuer's token endpoint, which is not the
	// httptest listener URL: app.go builds it from config before the server exists.
	assertion := signAssertion(t, key, client.ClientID, "http://localhost:8080/token", "jti-pkjwt-1")

	resp := e.postForm("/token", url.Values{
		"grant_type":            {"authorization_code"},
		"code":                  {code},
		"redirect_uri":          {testRedirectURI},
		"client_id":             {client.ClientID},
		"code_verifier":         {f.verifier},
		"client_assertion_type": {assertionType},
		"client_assertion":      {assertion},
	})
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("token status = %d, want 200; body = %s", resp.StatusCode, body(t, resp))
	}

	var tokens tokenResponse
	decodeJSON(t, resp, &tokens)
	if tokens.AccessToken == "" {
		t.Error("no access_token issued")
	}
	if tokens.IDToken == "" {
		t.Error("no id_token issued")
	}
}

func TestPrivateKeyJWTRejectsReplayedAssertion(t *testing.T) {
	e := newEnv(t)

	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	pub, err := jwk.FromRaw(key.Public())
	if err != nil {
		t.Fatalf("derive public jwk: %v", err)
	}

	client := pkjwtClient(t, "pkjwt-app-2", pub)
	if err := e.App.Deps.Clients.Create(context.Background(), client); err != nil {
		t.Fatalf("create client: %v", err)
	}

	user := createUserWithPassword(t, e, "user-pkjwt-2", "bob@example.test", "correct horse battery", true)

	f := &flow{
		client:   client,
		verifier: "test-verifier-that-is-long-enough-for-s256-checks-01",
		authParams: url.Values{
			"client_id":             {client.ClientID},
			"redirect_uri":          {testRedirectURI},
			"response_type":         {"code"},
			"scope":                 {"openid profile email"},
			"state":                 {"xyz-state-pkjwt-2"},
			"nonce":                 {"test-nonce-pkjwt-2"},
			"code_challenge":        {crypto.S256Challenge("test-verifier-that-is-long-enough-for-s256-checks-01")},
			"code_challenge_method": {"S256"},
		},
	}

	code := grantCode(t, e, f, user)

	// The same jti twice. The first request consumes the code, so the replay must be
	// refused for the jti as well - which is asserted first, before the code check.
	assertion := signAssertion(t, key, client.ClientID, "http://localhost:8080/token", "jti-pkjwt-replay")

	first := e.postForm("/token", url.Values{
		"grant_type":            {"authorization_code"},
		"code":                  {code},
		"redirect_uri":          {testRedirectURI},
		"client_id":             {client.ClientID},
		"code_verifier":         {f.verifier},
		"client_assertion_type": {assertionType},
		"client_assertion":      {assertion},
	})
	if first.StatusCode != http.StatusOK {
		t.Fatalf("first token status = %d, want 200; body = %s", first.StatusCode, body(t, first))
	}

	// A second authorization code, exchanged with the already-used assertion.
	code2 := grantCode(t, e, f, user)

	second := e.postForm("/token", url.Values{
		"grant_type":            {"authorization_code"},
		"code":                  {code2},
		"redirect_uri":          {testRedirectURI},
		"client_id":             {client.ClientID},
		"code_verifier":         {f.verifier},
		"client_assertion_type": {assertionType},
		"client_assertion":      {assertion},
	})
	if second.StatusCode != http.StatusUnauthorized {
		t.Fatalf("replayed assertion status = %d, want 401; body = %s", second.StatusCode, body(t, second))
	}
}
