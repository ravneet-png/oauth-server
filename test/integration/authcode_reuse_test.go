// Code reuse detection, including that a presentation from the wrong client neither succeeds nor destroys the code.

package integration

import (
	"context"
	"net/http"
	"net/url"
	"testing"
)

func TestAuthorizationCodeReuseSameClientInvalidGrant(t *testing.T) {
	e := newEnv(t)

	user := createUserWithPassword(t, e, "user-reuse-1", "alice@example.test", "correct horse battery", true)

	f := newConfidentialFlow(t, e, "app-reuse-1", "client-secret-for-reuse-1")
	f.start(t, e)
	f.signIn(t, e, user.Email, "correct horse battery")
	code := f.allow(t, e)

	tokens := f.exchange(t, e, code)
	if tokens.AccessToken == "" {
		t.Fatal("first exchange failed")
	}

	// Second exchange with SAME code from SAME client must return invalid_grant
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

	// Verify the original tokens are revoked: access token should fail introspection
	resp := e.postFormBasic("/introspect", url.Values{
		"token": {tokens.AccessToken},
	}, f.client.ClientID, f.secret)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("introspect status = %d", resp.StatusCode)
	}
	var intr struct {
		Active bool `json:"active"`
	}
	decodeJSON(t, resp, &intr)
	if intr.Active {
		t.Error("access token still active after code reuse, expected revoked")
	}

	// Verify refresh token is also revoked (family cascade)
	revokedResp := e.postFormBasic("/token", url.Values{
		"grant_type":    {"refresh_token"},
		"refresh_token": {tokens.RefreshToken},
	}, f.client.ClientID, f.secret)
	if revokedResp.StatusCode != http.StatusBadRequest {
		t.Fatalf("refresh after code reuse status = %d, want 400", revokedResp.StatusCode)
	}
	var revErr struct {
		Error string `json:"error"`
	}
	decodeJSON(t, revokedResp, &revErr)
	if revErr.Error != "invalid_grant" {
		t.Errorf("refresh error = %q, want invalid_grant (family cascade)", revErr.Error)
	}

	// Verify audit log has "code.reuse_detected"
	var auditCount int
	err := e.DB.QueryRow(context.Background(),
		`SELECT count(*) FROM audit_log WHERE event = 'code.reuse_detected'`).Scan(&auditCount)
	if err != nil {
		t.Fatalf("audit query: %v", err)
	}
	if auditCount != 1 {
		t.Errorf("audit_log code.reuse_detected count = %d, want 1", auditCount)
	}
}

func TestAuthorizationCodeReuseWrongClientInvalidGrantNoCascade(t *testing.T) {
	e := newEnv(t)

	user := createUserWithPassword(t, e, "user-reuse-2", "bob@example.test", "correct horse battery", true)

	// First client gets the code
	f1 := newConfidentialFlow(t, e, "app-reuse-2a", "client-secret-for-reuse-2a")
	f1.start(t, e)
	f1.signIn(t, e, user.Email, "correct horse battery")
	code := f1.allow(t, e)

	// Second, DIFFERENT client tries to reuse the same code
	f2 := newConfidentialFlow(t, e, "app-reuse-2b", "client-secret-for-reuse-2b")
	// Reuse the same code with different client credentials
	replay := e.postFormBasic("/token", url.Values{
		"grant_type":    {"authorization_code"},
		"code":          {code},
		"code_verifier": {f1.verifier}, // same verifier
		"redirect_uri":  {testRedirectURI},
	}, f2.client.ClientID, f2.secret)

	// Must return invalid_grant
	if replay.StatusCode != http.StatusBadRequest {
		t.Fatalf("wrong-client replay status = %d, want 400; body = %s", replay.StatusCode, body(t, replay))
	}
	var oerr struct {
		Error string `json:"error"`
	}
	decodeJSON(t, replay, &oerr)
	if oerr.Error != "invalid_grant" {
		t.Errorf("error = %q, want invalid_grant", oerr.Error)
	}

	// But the code is NOT consumed: the first client should still be able to use it
	tokens := f1.exchange(t, e, code)
	if tokens.AccessToken == "" {
		t.Error("first client should still be able to exchange the code after wrong-client replay")
	}

	// Verify no cascade revocation for the first client's tokens (since wrong client)
	resp := e.postFormBasic("/introspect", url.Values{
		"token": {tokens.AccessToken},
	}, f1.client.ClientID, f1.secret)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("introspect status = %d", resp.StatusCode)
	}
	var intr struct {
		Active bool `json:"active"`
	}
	decodeJSON(t, resp, &intr)
	if !intr.Active {
		t.Error("first client's token was revoked by wrong-client replay; should not cascade")
	}
}

// Helper to count rows in revoked_tokens for a specific client
func countRevokedTokens(t *testing.T, e *env, clientID string) int {
	var count int
	err := e.DB.QueryRow(context.Background(),
		`SELECT count(*) FROM revoked_tokens WHERE client_id = $1`, clientID).Scan(&count)
	if err != nil {
		t.Fatalf("count revoked_tokens: %v", err)
	}
	return count
}

// Helper to count rows in refresh_tokens for a specific client
func countRefreshTokens(t *testing.T, e *env, clientID string) int {
	var count int
	err := e.DB.QueryRow(context.Background(),
		`SELECT count(*) FROM refresh_tokens WHERE client_id = $1`, clientID).Scan(&count)
	if err != nil {
		t.Fatalf("count refresh_tokens: %v", err)
	}
	return count
}
