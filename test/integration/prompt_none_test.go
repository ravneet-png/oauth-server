// prompt=none and max_age behaviour, which must never present an interactive page.

package integration

import (
	"context"
	"net/http"
	"net/url"
	"testing"

	"oauth-server/internal/crypto"
)

func TestPromptNoneWithoutSessionReturnsLoginRequired(t *testing.T) {
	e := newEnv(t)

	f := newConfidentialFlow(t, e, "app-pnone-1", "secret-pnone-1")
	f.authParams.Set("prompt", "none")
	f.authParams.Set("state", "state-pnone-1")

	resp := e.get("/authorize?" + f.authParams.Encode())
	if resp.StatusCode != http.StatusSeeOther {
		t.Fatalf("authorize prompt=none status = %d, want 303; body = %s", resp.StatusCode, body(t, resp))
	}

	loc, err := url.Parse(location(t, resp))
	if err != nil {
		t.Fatalf("parse Location: %v", err)
	}
	if got := loc.Query().Get("error"); got != "login_required" {
		t.Errorf("error = %q, want login_required (Location = %s)", got, loc)
	}
	if got := loc.Query().Get("state"); got != "state-pnone-1" {
		t.Errorf("state = %q, want state-pnone-1", got)
	}
}

func TestPromptNoneWithoutConsentReturnsConsentRequired(t *testing.T) {
	e := newEnv(t)

	user := createUserWithPassword(t, e, "user-pnone-2", "alice-pnone@example.test", "correct horse battery", true)

	// Sign in and consent on Client A so the cookie jar holds an active session.
	fA := newConfidentialFlow(t, e, "app-pnone-2a", "secret-pnone-2a")
	fA.start(t, e)
	fA.signIn(t, e, user.Email, "correct horse battery")
	_ = fA.allow(t, e)

	// Client B has no standing consent grant for this user.
	fB := newConfidentialFlow(t, e, "app-pnone-2b", "secret-pnone-2b")
	fB.authParams.Set("prompt", "none")
	fB.authParams.Set("state", "state-pnone-2b")

	authResp := e.get("/authorize?" + fB.authParams.Encode())
	if authResp.StatusCode != http.StatusSeeOther {
		t.Fatalf("authorize status = %d, want 303; body = %s", authResp.StatusCode, body(t, authResp))
	}

	loc, err := url.Parse(location(t, authResp))
	if err != nil {
		t.Fatalf("parse Location: %v", err)
	}
	if loc.Path == "/consent" {
		authReqID := loc.Query().Get("auth_request_id")
		consentResp := e.get("/consent?auth_request_id=" + url.QueryEscape(authReqID))
		if consentResp.StatusCode != http.StatusSeeOther {
			t.Fatalf("consent with prompt=none rendered page (status %d), want 303 redirect", consentResp.StatusCode)
		}
		loc, err = url.Parse(location(t, consentResp))
		if err != nil {
			t.Fatalf("parse consent Location: %v", err)
		}
	}

	if got := loc.Query().Get("error"); got != "consent_required" {
		t.Errorf("error = %q, want consent_required (Location = %s)", got, loc)
	}
	if got := loc.Query().Get("state"); got != "state-pnone-2b" {
		t.Errorf("state = %q, want state-pnone-2b", got)
	}
}

func TestPromptNoneWithSessionAndConsentAndMaxAge(t *testing.T) {
	e := newEnv(t)

	user := createUserWithPassword(t, e, "user-pnone-3", "bob-pnone@example.test", "correct horse battery", true)

	f := newConfidentialFlow(t, e, "app-pnone-3", "secret-pnone-3")
	f.start(t, e)
	f.signIn(t, e, user.Email, "correct horse battery")
	firstCode := f.allow(t, e)
	_ = f.exchange(t, e, firstCode)

	// Silent re-authorization with prompt=none succeeds when session + consent exist.
	silentParams := url.Values{
		"client_id":             {f.client.ClientID},
		"redirect_uri":          {testRedirectURI},
		"response_type":         {"code"},
		"scope":                 {"openid profile email"},
		"state":                 {"state-silent-ok"},
		"nonce":                 {"nonce-silent-ok"},
		"code_challenge":        {crypto.S256Challenge(f.verifier)},
		"code_challenge_method": {"S256"},
		"prompt":                {"none"},
	}
	authResp := e.get("/authorize?" + silentParams.Encode())
	if authResp.StatusCode != http.StatusSeeOther {
		t.Fatalf("silent authorize status = %d, want 303", authResp.StatusCode)
	}
	loc, err := url.Parse(location(t, authResp))
	if err != nil {
		t.Fatalf("parse Location: %v", err)
	}
	if loc.Path == "/consent" {
		consentResp := e.get("/consent?auth_request_id=" + url.QueryEscape(loc.Query().Get("auth_request_id")))
		if consentResp.StatusCode != http.StatusSeeOther {
			t.Fatalf("silent consent status = %d, want 303", consentResp.StatusCode)
		}
		loc, err = url.Parse(location(t, consentResp))
		if err != nil {
			t.Fatalf("parse consent Location: %v", err)
		}
	}
	silentCode := loc.Query().Get("code")
	if silentCode == "" {
		t.Fatalf("expected silent code on prompt=none redirect, got %s", loc)
	}
	if tok := f.exchange(t, e, silentCode); tok.AccessToken == "" {
		t.Fatal("failed to exchange silent code")
	}

	// Age the session's auth_time past max_age and verify prompt=none returns login_required.
	if _, err := e.DB.Exec(context.Background(), `UPDATE sessions SET auth_time = now() - interval '300 seconds'`); err != nil {
		t.Fatalf("age session auth_time: %v", err)
	}
	silentParams.Set("max_age", "10")
	silentParams.Set("state", "state-max-age-expired")

	agedResp := e.get("/authorize?" + silentParams.Encode())
	if agedResp.StatusCode != http.StatusSeeOther {
		t.Fatalf("aged authorize status = %d, want 303", agedResp.StatusCode)
	}
	agedLoc, err := url.Parse(location(t, agedResp))
	if err != nil {
		t.Fatalf("parse aged Location: %v", err)
	}
	if got := agedLoc.Query().Get("error"); got != "login_required" {
		t.Errorf("aged max_age + prompt=none error = %q, want login_required (Location = %s)", got, agedLoc)
	}
}
