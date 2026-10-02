// PKCE required for public clients.

package integration

import (
	"net/http"
	"testing"

	"net/url"
	"strings"
)

func TestPKCERequiredForPublicClient(t *testing.T) {
	e := newEnv(t)

	user := createUserWithPassword(t, e, "user-pkce-1", "bob@example.test", "correct horse battery", true)

	f := newPublicFlow(t, e, "pkce-required-app")

	// Start authorization
	resp := e.get("/authorize?" + f.authParams.Encode())
	if resp.StatusCode != http.StatusSeeOther {
		t.Fatalf("authorize status = %d, want 303", resp.StatusCode)
	}

	loc, err := url.Parse(location(t, resp))
	if err != nil {
		t.Fatalf("parse Location: %v", err)
	}
	if loc.Path != "/login" {
		t.Fatalf("authorize redirected to %q, want /login", loc.Path)
	}

	authReqID := loc.Query().Get("auth_request_id")
	if authReqID == "" {
		t.Fatalf("no auth_request_id in %q", loc)
	}

	// Login
	page := e.get("/login?auth_request_id=" + url.QueryEscape(authReqID))
	if page.StatusCode != http.StatusOK {
		t.Fatalf("login page status = %d; body = %s", page.StatusCode, body(t, page))
	}

	resp = e.postForm("/login", url.Values{
		"csrf_token":      {hiddenInput(t, page, "csrf_token")},
		"auth_request_id": {authReqID},
		"email":           {user.Email},
		"password":        {"correct horse battery"},
	})
	if resp.StatusCode != http.StatusSeeOther {
		t.Fatalf("login submit status = %d, want 303", resp.StatusCode)
	}

	// Get consent and allow
	page = e.get("/consent?auth_request_id=" + url.QueryEscape(authReqID))
	if page.StatusCode != http.StatusOK {
		t.Fatalf("consent page status = %d; body = %s", page.StatusCode, body(t, page))
	}

	resp = e.postForm("/consent", url.Values{
		"csrf_token":      {hiddenInput(t, page, "csrf_token")},
		"auth_request_id": {authReqID},
		"decision":        {"allow"},
		"scope":           strings.Fields(f.authParams.Get("scope")),
	})
	if resp.StatusCode != http.StatusSeeOther {
		t.Fatalf("consent submit status = %d, want 303", resp.StatusCode)
	}

	// Try to exchange code WITHOUT code_verifier - should fail
	loc2, err := url.Parse(location(t, resp))
	if err != nil {
		t.Fatalf("parse redirect: %v", err)
	}
	code := loc2.Query().Get("code")
	if code == "" {
		t.Fatalf("no code in redirect %q", loc2)
	}

	resp = e.postForm("/token", url.Values{
		"grant_type":   {"authorization_code"},
		"code":         {code},
		"redirect_uri": {testRedirectURI},
		"client_id":    {f.client.ClientID},
	})
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("token without PKCE status = %d, want 400; body = %s", resp.StatusCode, body(t, resp))
	}
}
