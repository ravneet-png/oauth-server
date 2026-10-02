// Consent auto-skip: when an active grant already covers the grantable scope set,
// /authorize redirects past the consent screen straight to the client.

package integration

import (
	"net/http"
	"net/url"
	"testing"

	"oauth-server/internal/crypto"
)

func TestConsentAutoSkip(t *testing.T) {
	e := newEnv(t)

	user := createUserWithPassword(t, e, "user-asc-1", "alice@example.test", "correct horse battery", true)

	f := newConfidentialFlow(t, e, "app-asc-1", "client-secret-for-asc-1")

	// First authorization: no grant exists, so the user must consent.
	f.start(t, e)
	f.signIn(t, e, user.Email, "correct horse battery")
	first := f.allow(t, e)
	if first == "" {
		t.Fatal("first authorization produced no code")
	}
	if tokens := f.exchange(t, e, first); tokens.AccessToken == "" {
		t.Fatal("first flow issued no access token")
	}

	// Second authorization for the same user and client, same scopes: the existing
	// grant covers the set, so login must not land on /consent.
	second := &flow{
		client:   f.client,
		secret:   f.secret,
		verifier: f.verifier,
		authParams: url.Values{
			"client_id":             {f.client.ClientID},
			"redirect_uri":          {testRedirectURI},
			"response_type":         {"code"},
			"scope":                 {"openid profile email"},
			"state":                 {"xyz-state-asc-2"},
			"nonce":                 {"test-nonce-asc-2"},
			"code_challenge":        {crypto.S256Challenge(f.verifier)},
			"code_challenge_method": {"S256"},
		},
	}
	second.start(t, e)

	// With the standing grant, /authorize may already have issued the code without a
	// second visit to the login page at all.
	if u := second.startedWithCode; u != nil {
		if got := u.Query().Get("state"); got != "xyz-state-asc-2" {
			t.Errorf("state = %q, want xyz-state-asc-2", got)
		}
		if code := u.Query().Get("code"); code != "" {
			if tokens := second.exchange(t, e, code); tokens.AccessToken == "" {
				t.Fatal("auto-skipped flow issued no access token")
			}
			return
		}
	}

	// /authorize chose /consent because a session is live. That redirect is not the
	// answer: login and /authorize both hand the browser to /consent, and only the
	// consent handler decides whether the screen is necessary. So follow it there.
	if second.nextScreen != "/consent" {
		t.Fatalf("second /authorize routed to %q, want /consent", second.nextScreen)
	}

	// The standing grant should carry this request straight back to the client.
	consentResp := e.get("/consent?auth_request_id=" + url.QueryEscape(second.authReqID))
	if consentResp.StatusCode != http.StatusSeeOther {
		t.Fatalf("consent for an already-granted request = %d, want 303 (auto-skip); body = %s",
			consentResp.StatusCode, body(t, consentResp))
	}

	loc, err := url.Parse(location(t, consentResp))
	if err != nil {
		t.Fatalf("parse redirect %q: %v", location(t, consentResp), err)
	}
	code := loc.Query().Get("code")
	if code == "" {
		t.Fatalf("auto-skipped authorization returned no code; redirect = %q", loc)
	}
	if got := loc.Query().Get("state"); got != "xyz-state-asc-2" {
		t.Errorf("state = %q, want xyz-state-asc-2", got)
	}

	if tokens := second.exchange(t, e, code); tokens.AccessToken == "" {
		t.Fatal("auto-skipped flow issued no access token")
	}
}
