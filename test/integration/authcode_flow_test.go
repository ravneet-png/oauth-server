// The authorization code flow end to end, through the real browser endpoints.
//
// Every step goes through the router: /authorize redirects a sessionless user to
// /login, the form is submitted with the CSRF token the page rendered, consent is
// recorded, and the code is exchanged at /token with PKCE. A test that inserts an
// authorization request row directly would skip the redirect chain, the session and the
// consent decision, which are the parts most likely to be wrong.

package integration

import (
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/url"
	"strings"
	"testing"
)

// parseIDToken parses the ID token claims without verification (the server already verified).
func parseIDToken(t *testing.T, token string) map[string]any {
	t.Helper()
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		t.Fatalf("malformed ID token")
	}
	payload, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		t.Fatalf("decode ID token: %v", err)
	}
	var claims map[string]any
	if err := json.Unmarshal(payload, &claims); err != nil {
		t.Fatalf("unmarshal ID token: %v", err)
	}
	return claims
}

func TestAuthorizationCodeFlowEndToEnd(t *testing.T) {
	e := newEnv(t)

	// Create user with verified email
	user := createUserWithPassword(t, e, "user-1", "alice@example.test", "correct horse battery", true)

	f := newConfidentialFlow(t, e, "app-1", "client-secret-for-app-1")
	f.start(t, e)
	f.signIn(t, e, user.Email, "correct horse battery")
	code := f.allow(t, e)

	tokens := f.exchange(t, e, code)
	if tokens.AccessToken == "" {
		t.Error("no access_token issued")
	}
	if tokens.IDToken == "" {
		t.Error("no id_token issued for a request carrying openid")
	}
	if tokens.RefreshToken == "" {
		t.Error("no refresh_token issued")
	}

	// Verify ID token claims: iss, sub, aud, email (since verified), sid
	claims := parseIDToken(t, tokens.IDToken)
	if claims["iss"] != "http://localhost:8080" {
		t.Errorf("id_token iss = %q, want http://localhost:8080", claims["iss"])
	}
	if claims["sub"] != user.UserID {
		t.Errorf("id_token sub = %q, want %q", claims["sub"], user.UserID)
	}
	// aud may be string or []string per RFC 7519; accept both
	audOK := false
	switch v := claims["aud"].(type) {
	case string:
		audOK = v == f.client.ClientID
	case []any:
		for _, a := range v {
			if s, ok := a.(string); ok && s == f.client.ClientID {
				audOK = true
				break
			}
		}
	}
	if !audOK {
		t.Errorf("id_token aud = %v, want %q", claims["aud"], f.client.ClientID)
	}
	// email should be present because user is verified
	if claims["email"] != user.Email {
		t.Errorf("id_token email = %q, want %q", claims["email"], user.Email)
	}
	// sid (session ID) must be present for back-channel logout correlation
	if claims["sid"] == nil {
		t.Error("id_token missing sid claim")
	}

	// The access token must carry the user's identity to /userinfo.
	resp := e.getBearer("/userinfo", tokens.AccessToken)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("userinfo status = %d; body = %s", resp.StatusCode, body(t, resp))
	}
	var uiClaims struct {
		Sub   string `json:"sub"`
		Email string `json:"email"`
	}
	decodeJSON(t, resp, &uiClaims)
	if uiClaims.Sub != user.UserID {
		t.Errorf("userinfo sub = %q, want %q", uiClaims.Sub, user.UserID)
	}
	if uiClaims.Email != user.Email {
		t.Errorf("userinfo email = %q, want %q", uiClaims.Email, user.Email)
	}
}

// TestAuthorizationCodeFlowEmailOnlyWhenVerified checks that email claim is absent
// in ID token when the user's email is not verified.
func TestAuthorizationCodeFlowEmailOnlyWhenVerified(t *testing.T) {
	e := newEnv(t)

	// Create user with UNVERIFIED email
	user := createUserWithPassword(t, e, "user-unverified", "bob@example.test", "another good password", false)

	f := newConfidentialFlow(t, e, "app-unverified", "client-secret-for-unverified")
	f.start(t, e)
	f.signIn(t, e, user.Email, "another good password")
	code := f.allow(t, e)

	tokens := f.exchange(t, e, code)
	claims := parseIDToken(t, tokens.IDToken)

	// email claim must be absent when email is not verified
	if claims["email"] != nil {
		t.Errorf("id_token email = %q, want absent for unverified email", claims["email"])
	}
	// sid must still be present
	if claims["sid"] == nil {
		t.Error("id_token missing sid claim even for unverified email")
	}
}

func TestAuthorizationCodeIsSingleUse(t *testing.T) {
	e := newEnv(t)

	user := createUserWithPassword(t, e, "user-2", "bob@example.test", "another good password", true)

	f := newConfidentialFlow(t, e, "app-2", "client-secret-for-app-2")
	f.start(t, e)
	f.signIn(t, e, user.Email, "another good password")
	code := f.allow(t, e)

	f.exchange(t, e, code)

	// The second exchange must fail. A replayed code is the classic way to steal a
	// token, so the whole token family is revoked rather than just this call refused.
	replay := e.postFormBasic("/token", url.Values{
		"grant_type":    {"authorization_code"},
		"code":          {code},
		"code_verifier": {f.verifier},
		"redirect_uri":  {testRedirectURI},
	}, f.client.ClientID, f.secret)

	if replay.StatusCode != http.StatusBadRequest {
		t.Fatalf("replayed code status = %d, want 400; body = %s", replay.StatusCode, body(t, replay))
	}
	var oerr struct {
		Error string `json:"error"`
	}
	decodeJSON(t, replay, &oerr)
	if oerr.Error != "invalid_grant" {
		t.Errorf("error = %q, want invalid_grant", oerr.Error)
	}
}
