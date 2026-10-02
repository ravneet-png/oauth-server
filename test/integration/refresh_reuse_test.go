// Replay of a rotated token revokes the family; replay of a logged out token does not.

package integration

import (
	"net/http"
	"net/url"
	"testing"
)

func TestRefreshReuseRevokesFamily(t *testing.T) {
	e := newEnv(t)

	user := createUserWithPassword(t, e, "user-refresh-1", "alice@example.test", "correct horse battery", true)

	f := newConfidentialFlow(t, e, "app-refresh-1", "client-secret-for-refresh-1")
	f.start(t, e)
	f.signIn(t, e, user.Email, "correct horse battery")
	code := f.allow(t, e)

	tokens := f.exchange(t, e, code)
	if tokens.RefreshToken == "" {
		t.Fatal("no refresh token")
	}

	// First use of refresh token: R1 -> R2
	tokens2 := f.refresh(t, e, tokens.RefreshToken)
	if tokens2.RefreshToken == "" {
		t.Fatal("second refresh token missing")
	}

	// Replay R1 (the already-used token) should fail with invalid_grant
	replay := e.postFormBasic("/token", url.Values{
		"grant_type":    {"refresh_token"},
		"refresh_token": {tokens.RefreshToken},
	}, f.client.ClientID, f.secret)

	if replay.StatusCode != http.StatusBadRequest {
		t.Fatalf("replay R1 status = %d, want 400; body = %s", replay.StatusCode, body(t, replay))
	}
	var oerr struct {
		Error string `json:"error"`
	}
	decodeJSON(t, replay, &oerr)
	if oerr.Error != "invalid_grant" {
		t.Errorf("error = %q, want invalid_grant", oerr.Error)
	}

	// R2 (the newly issued token) must ALSO be revoked by the cascade
	replay2 := e.postFormBasic("/token", url.Values{
		"grant_type":    {"refresh_token"},
		"refresh_token": {tokens2.RefreshToken},
	}, f.client.ClientID, f.secret)

	if replay2.StatusCode != http.StatusBadRequest {
		t.Fatalf("use R2 after R1 replay status = %d, want 400; body = %s", replay2.StatusCode, body(t, replay2))
	}
	decodeJSON(t, replay2, &oerr)
	if oerr.Error != "invalid_grant" {
		t.Errorf("error on R2 = %q, want invalid_grant (family cascade)", oerr.Error)
	}
}

// TestRefreshReuseAfterLogoutNoCascade checks that using a refresh token revoked
// by logout returns invalid_grant WITHOUT revoking the family.
func TestRefreshReuseAfterLogoutNoCascade(t *testing.T) {
	e := newEnv(t)

	user := createUserWithPassword(t, e, "user-refresh-2", "bob@example.test", "correct horse battery", true)

	f := newConfidentialFlow(t, e, "app-refresh-2", "client-secret-for-refresh-2")
	f.start(t, e)
	f.signIn(t, e, user.Email, "correct horse battery")
	code := f.allow(t, e)

	tokens := f.exchange(t, e, code)
	if tokens.RefreshToken == "" {
		t.Fatal("no refresh token")
	}

	// Perform logout for this session
	_ = getSessionCookie(t, e)

	// Logout via the session cookie (GET /logout)
	logoutResp := e.get("/logout")
	if logoutResp.StatusCode != http.StatusOK {
		t.Fatalf("logout status = %d", logoutResp.StatusCode)
	}

	// Now try to use the refresh token - should fail with invalid_grant
	replay := e.postFormBasic("/token", url.Values{
		"grant_type":    {"refresh_token"},
		"refresh_token": {tokens.RefreshToken},
	}, f.client.ClientID, f.secret)

	if replay.StatusCode != http.StatusBadRequest {
		t.Fatalf("refresh after logout status = %d, want 400; body = %s", replay.StatusCode, body(t, replay))
	}
	var oerr struct {
		Error string `json:"error"`
	}
	decodeJSON(t, replay, &oerr)
	if oerr.Error != "invalid_grant" {
		t.Errorf("error = %q, want invalid_grant", oerr.Error)
	}
}
