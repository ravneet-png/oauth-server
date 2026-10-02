// Session scoped logout, including that another session on a second device survives.

package integration

import (
	"net/http"
	"net/url"
	"testing"
)

func TestLogoutRevokesOnlyCurrentSession(t *testing.T) {
	e := newEnv(t)
	eB := newEnv(t)
	e2 := newEnv(t)

	// Create user after all envs (newEnv truncates the DB)
	user := createUserWithPassword(t, e2, "user-logout-1", "alice@example.test", "correct horse battery", true)

	// Client A
	fA := newConfidentialFlow(t, e, "app-logout-a", "client-secret-a")
	fA.start(t, e)
	fA.signIn(t, e, user.Email, "correct horse battery")
	codeA := fA.allow(t, e)
	tokensA := fA.exchange(t, e, codeA)

	// Client B (separate auth flow, separate env for independent session)
	fB := newConfidentialFlow(t, eB, "app-logout-b", "client-secret-b")
	fB.start(t, eB)
	fB.signIn(t, eB, user.Email, "correct horse battery")
	codeB := fB.allow(t, eB)
	_ = fB.exchange(t, eB, codeB)

	// Get session cookie for device 1
	sessionCookie1 := getSessionCookie(t, e)

	// Get session cookie for device 2 - need a separate env with its own cookie jar
	f2 := newConfidentialFlow(t, e2, "app-logout-device2", "client-secret-device2")
	f2.start(t, e2)
	f2.signIn(t, e2, user.Email, "correct horse battery")
	code2 := f2.allow(t, e2)
	tokens2 := f2.exchange(t, e2, code2)

	// Now logout from first session (device 1)
	logoutReq, _ := http.NewRequest(http.MethodGet, e.url("/logout"), nil)
	logoutReq.Header.Set("Cookie", "session="+sessionCookie1)
	logoutResp := e.do(logoutReq)
	if logoutResp.StatusCode != http.StatusOK {
		t.Fatalf("logout status = %d", logoutResp.StatusCode)
	}

	// Verify device 1's tokens are revoked
	resp1 := e.postFormBasic("/introspect", url.Values{"token": {tokensA.AccessToken}}, fA.client.ClientID, fA.secret)
	if resp1.StatusCode != http.StatusOK {
		t.Fatalf("introspect: %d", resp1.StatusCode)
	}
	var intr1 struct{ Active bool }
	decodeJSON(t, resp1, &intr1)
	if intr1.Active {
		t.Error("device 1 access token should be revoked after logout")
	}

	// Verify device 1's refresh token is revoked
	refresh1 := e.postFormBasic("/token", url.Values{
		"grant_type":    {"refresh_token"},
		"refresh_token": {tokensA.RefreshToken},
	}, fA.client.ClientID, fA.secret)
	if refresh1.StatusCode != http.StatusBadRequest {
		t.Fatalf("device 1 refresh after logout: %d", refresh1.StatusCode)
	}

	// Verify device 2's tokens STILL WORK (separate session)
	resp2 := e2.postFormBasic("/introspect", url.Values{"token": {tokens2.AccessToken}}, f2.client.ClientID, f2.secret)
	if resp2.StatusCode != http.StatusOK {
		t.Fatalf("device 2 introspect: %d", resp2.StatusCode)
	}
	var intr2 struct{ Active bool }
	decodeJSON(t, resp2, &intr2)
	if !intr2.Active {
		t.Error("device 2 access token should still be active after device 1 logout")
	}

	// Verify device 2's refresh token still works
	refresh2 := e2.postFormBasic("/token", url.Values{
		"grant_type":    {"refresh_token"},
		"refresh_token": {tokens2.RefreshToken},
	}, f2.client.ClientID, f2.secret)
	if refresh2.StatusCode != http.StatusOK {
		t.Errorf("device 2 refresh token revoked by device 1 logout; status = %d", refresh2.StatusCode)
	}
}

// TestLogoutTwoDevices verifies scoped logout: user has two sessions, logout session 1 only
func TestLogoutTwoDevices(t *testing.T) {
	e := newEnv(t)
	e2 := newEnv(t)

	// Create user after all envs (newEnv truncates the DB)
	user := createUserWithPassword(t, e2, "user-logout-2", "bob@example.test", "correct horse battery", true)

	// Device 1
	f1 := newConfidentialFlow(t, e, "app-logout-d1", "client-secret-d1")
	f1.start(t, e)
	f1.signIn(t, e, user.Email, "correct horse battery")
	code1 := f1.allow(t, e)
	tokens1 := f1.exchange(t, e, code1)

	sessionCookie1 := getSessionCookie(t, e)

	// Device 2 (separate env)
	f2 := newConfidentialFlow(t, e2, "app-logout-d2", "client-secret-d2")
	f2.start(t, e2)
	f2.signIn(t, e2, user.Email, "correct horse battery")
	code2 := f2.allow(t, e2)
	tokens2 := f2.exchange(t, e2, code2)

	_ = getSessionCookie(t, e2)

	// Logout session 1
	logoutReq, _ := http.NewRequest(http.MethodGet, e.url("/logout"), nil)
	logoutReq.Header.Set("Cookie", "session="+sessionCookie1)
	logoutResp := e.do(logoutReq)
	if logoutResp.StatusCode != http.StatusOK {
		t.Fatalf("logout session 1: %d", logoutResp.StatusCode)
	}

	// Session 1 tokens revoked
	resp1 := e.postFormBasic("/introspect", url.Values{"token": {tokens1.AccessToken}}, f1.client.ClientID, f1.secret)
	var intr1 struct{ Active bool }
	decodeJSON(t, resp1, &intr1)
	if intr1.Active {
		t.Error("session 1 token should be revoked")
	}

	// Session 2 tokens still valid
	resp2 := e2.postFormBasic("/introspect", url.Values{"token": {tokens2.AccessToken}}, f2.client.ClientID, f2.secret)
	var intr2 struct{ Active bool }
	decodeJSON(t, resp2, &intr2)
	if !intr2.Active {
		t.Error("session 2 token should survive session 1 logout")
	}

	// Session 2 refresh works
	refresh2 := e2.postFormBasic("/token", url.Values{
		"grant_type":    {"refresh_token"},
		"refresh_token": {tokens2.RefreshToken},
	}, f2.client.ClientID, f2.secret)
	if refresh2.StatusCode != http.StatusOK {
		t.Error("session 2 refresh should work after session 1 logout")
	}
}
