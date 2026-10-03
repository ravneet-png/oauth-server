// Dynamic client registration gating, and that post-logout redirect validation refuses an unregistered target.

package integration

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/url"
	"testing"
)

func TestDynamicClientRegistrationGating(t *testing.T) {
	e := newEnv(t)

	postRegister := func(bearer string, payload map[string]any) *response {
		t.Helper()
		raw, err := json.Marshal(payload)
		if err != nil {
			t.Fatalf("marshal payload: %v", err)
		}
		req, err := http.NewRequest(http.MethodPost, e.url("/register"), bytes.NewReader(raw))
		if err != nil {
			t.Fatalf("new request: %v", err)
		}
		req.Header.Set("Content-Type", "application/json")
		if bearer != "" {
			req.Header.Set("Authorization", "Bearer "+bearer)
		}
		return e.do(req)
	}

	validMeta := map[string]any{
		"client_name":                "Dynamic App",
		"redirect_uris":              []string{"https://dyn.example.test/callback"},
		"grant_types":                []string{"authorization_code", "refresh_token", "client_credentials"},
		"response_types":             []string{"code"},
		"token_endpoint_auth_method": "client_secret_basic",
		"scope":                      "openid profile email",
		"post_logout_redirect_uris":  []string{"https://dyn.example.test/logged-out"},
	}

	// 1. Disabled by default -> 404 Not Found.
	disabledResp := postRegister("any-token", validMeta)
	if disabledResp.StatusCode != http.StatusNotFound {
		t.Fatalf("disabled register status = %d, want 404; body = %s", disabledResp.StatusCode, body(t, disabledResp))
	}

	// Enable registration with an initial access token.
	e.App.Deps.Config.ClientRegistrationEnabled = true
	e.App.Deps.Config.InitialAccessToken = "initial-registration-bearer-token-123"

	// 2. Missing or wrong bearer -> 401 Unauthorized.
	noAuthResp := postRegister("", validMeta)
	if noAuthResp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("missing bearer status = %d, want 401; body = %s", noAuthResp.StatusCode, body(t, noAuthResp))
	}
	wrongAuthResp := postRegister("wrong-bearer-token", validMeta)
	if wrongAuthResp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("wrong bearer status = %d, want 401; body = %s", wrongAuthResp.StatusCode, body(t, wrongAuthResp))
	}

	// 3. Implicit grant rejected -> 400 Bad Request.
	implicitMeta := map[string]any{
		"client_name":   "Implicit App",
		"redirect_uris": []string{"https://dyn.example.test/callback"},
		"grant_types":   []string{"implicit"},
	}
	badGrantResp := postRegister(e.App.Deps.Config.InitialAccessToken, implicitMeta)
	if badGrantResp.StatusCode != http.StatusBadRequest {
		t.Fatalf("implicit grant register status = %d, want 400; body = %s", badGrantResp.StatusCode, body(t, badGrantResp))
	}

	// 4. Valid registration -> 201 Created with client_id and client_secret.
	okResp := postRegister(e.App.Deps.Config.InitialAccessToken, validMeta)
	if okResp.StatusCode != http.StatusCreated {
		t.Fatalf("valid register status = %d, want 201; body = %s", okResp.StatusCode, body(t, okResp))
	}
	var regOut struct {
		ClientID     string `json:"client_id"`
		ClientSecret string `json:"client_secret"`
		ClientName   string `json:"client_name"`
	}
	decodeJSON(t, okResp, &regOut)
	if regOut.ClientID == "" || regOut.ClientSecret == "" {
		t.Fatalf("registered client missing credentials: %+v", regOut)
	}

	// Verify the dynamically registered client can immediately obtain a client_credentials token.
	tokResp := e.postFormBasic("/token", url.Values{
		"grant_type": {"client_credentials"},
		"scope":      {"openid"},
	}, regOut.ClientID, regOut.ClientSecret)
	if tokResp.StatusCode != http.StatusOK {
		t.Fatalf("token with registered client status = %d, want 200; body = %s", tokResp.StatusCode, body(t, tokResp))
	}
}

func TestPostLogoutRedirectValidationRefusesUnregisteredTarget(t *testing.T) {
	e := newEnv(t)

	user := createUserWithPassword(t, e, "user-reg-logout-1", "alice-logout@example.test", "correct horse battery", true)

	f := newConfidentialFlow(t, e, "app-reg-logout-1", "secret-reg-logout-1")
	f.start(t, e)
	f.signIn(t, e, user.Email, "correct horse battery")
	code := f.allow(t, e)
	tokens := f.exchange(t, e, code)
	if tokens.IDToken == "" {
		t.Fatal("expected id_token from openid flow")
	}

	// Request RP-initiated logout with an unregistered post_logout_redirect_uri.
	q := url.Values{
		"id_token_hint":            {tokens.IDToken},
		"post_logout_redirect_uri": {"https://evil.example.test/phish"},
		"state":                    {"logout-state-1"},
	}
	resp := e.get("/logout?" + q.Encode())
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("unregistered post_logout_redirect_uri status = %d, want 400; body = %s", resp.StatusCode, body(t, resp))
	}
	if loc := resp.Header.Get("Location"); loc != "" {
		t.Errorf("unexpected Location header %q on refused post-logout redirect", loc)
	}
}
