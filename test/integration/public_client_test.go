// Public client authentication using only client_id and PKCE.

package integration

import (
	"net/http"
	"testing"
)

func TestPublicClientAuthCodeFlowWithPKCE(t *testing.T) {
	e := newEnv(t)

	user := createUserWithPassword(t, e, "user-public-1", "alice@example.test", "correct horse battery", true)

	f := newPublicFlow(t, e, "public-app-1")
	f.start(t, e)
	f.signIn(t, e, user.Email, "correct horse battery")
	code := f.allow(t, e)

	tokens := f.exchangePublic(t, e, code)
	if tokens.AccessToken == "" {
		t.Error("no access_token issued")
	}
	if tokens.IDToken == "" {
		t.Error("no id_token issued")
	}
	if tokens.RefreshToken == "" {
		t.Error("no refresh_token issued")
	}

	// Verify the access token works at /userinfo
	resp := e.getBearer("/userinfo", tokens.AccessToken)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("userinfo status = %d; body = %s", resp.StatusCode, body(t, resp))
	}
	var claims struct {
		Sub   string `json:"sub"`
		Email string `json:"email"`
	}
	decodeJSON(t, resp, &claims)
	if claims.Sub != user.UserID {
		t.Errorf("userinfo sub = %q, want %q", claims.Sub, user.UserID)
	}
	if claims.Email != user.Email {
		t.Errorf("userinfo email = %q, want %q", claims.Email, user.Email)
	}
}
