// An unrelated client cannot introspect a token that is not its own.

package integration

import (
	"net/http"
	"net/url"
	"testing"
)

func TestIntrospectionRequiresClientAuthentication(t *testing.T) {
	e := newEnv(t)

	resp := e.postForm("/introspect", url.Values{"token": {"some-token"}})
	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("unauthenticated introspect status = %d, want 401; body = %s", resp.StatusCode, body(t, resp))
	}
}

func TestPublicClientCanIntrospectItsOwnAccessToken(t *testing.T) {
	e := newEnv(t)
	user := createUserWithPassword(t, e, "user-intr-public", "public-intr@example.test", "correct horse battery", true)
	f := newPublicFlow(t, e, "public-intr-owner")
	f.start(t, e)
	f.signIn(t, e, user.Email, "correct horse battery")
	code := f.allow(t, e)
	tokens := f.exchangePublic(t, e, code)

	response := e.postForm("/introspect", url.Values{
		"client_id": {f.client.ClientID},
		"token":     {tokens.AccessToken},
	})
	if response.StatusCode != http.StatusOK {
		t.Fatalf("public-client introspection status = %d, want 200; body = %s", response.StatusCode, body(t, response))
	}
	var out struct {
		Active   bool     `json:"active"`
		ClientID string   `json:"client_id"`
		Sub      string   `json:"sub"`
		Iss      string   `json:"iss"`
		Aud      []string `json:"aud"`
	}
	decodeJSON(t, response, &out)
	if !out.Active {
		t.Fatal("the public client could not introspect its own access token")
	}
	if out.ClientID != f.client.ClientID || out.Sub != user.UserID {
		t.Errorf("introspection identity = client %q sub %q; want client %q sub %q", out.ClientID, out.Sub, f.client.ClientID, user.UserID)
	}
	if out.Iss != "http://localhost:8080" || len(out.Aud) == 0 {
		t.Errorf("introspection omitted issuer or audience claims: %+v", out)
	}
}

func TestUnknownTokenIntrospectsInactiveWithoutClaims(t *testing.T) {
	e := newEnv(t)
	owner := newConfidentialFlow(t, e, "app-intr-unknown", "unknown-token-secret")
	response := e.postFormBasic("/introspect", url.Values{"token": {"not-a-token"}}, owner.client.ClientID, owner.secret)
	if response.StatusCode != http.StatusOK {
		t.Fatalf("introspection status = %d, want 200; body = %s", response.StatusCode, body(t, response))
	}
	var out struct {
		Active   bool   `json:"active"`
		ClientID string `json:"client_id"`
		Sub      string `json:"sub"`
	}
	decodeJSON(t, response, &out)
	if out.Active || out.ClientID != "" || out.Sub != "" {
		t.Errorf("unknown token response disclosed claims: %+v", out)
	}
}

func TestUnrelatedClientCannotIntrospectAccessOrRefreshToken(t *testing.T) {
	e := newEnv(t)

	user := createUserWithPassword(t, e, "user-intr-1", "alice-intr@example.test", "correct horse battery", true)

	owner := newConfidentialFlow(t, e, "app-intr-owner", "owner-secret-intr-1")
	stranger := newConfidentialFlow(t, e, "app-intr-stranger", "stranger-secret-intr-1")

	owner.start(t, e)
	owner.signIn(t, e, user.Email, "correct horse battery")
	code := owner.allow(t, e)
	tokens := owner.exchange(t, e, code)

	// Owner can introspect both its access token and refresh token.
	if !e.introspectActive(t, tokens.AccessToken, owner.client.ClientID, owner.secret) {
		t.Error("owner could not introspect its own access token")
	}
	if !e.introspectActive(t, tokens.RefreshToken, owner.client.ClientID, owner.secret) {
		t.Error("owner could not introspect its own refresh token")
	}

	// Stranger receives active=false for both tokens and learns no claims.
	for _, tok := range []string{tokens.AccessToken, tokens.RefreshToken} {
		resp := e.postFormBasic("/introspect", url.Values{"token": {tok}}, stranger.client.ClientID, stranger.secret)
		if resp.StatusCode != http.StatusOK {
			t.Fatalf("stranger introspect status = %d, want 200; body = %s", resp.StatusCode, body(t, resp))
		}
		var out struct {
			Active   bool   `json:"active"`
			ClientID string `json:"client_id"`
			Sub      string `json:"sub"`
		}
		decodeJSON(t, resp, &out)
		if out.Active {
			t.Errorf("stranger introspected owner token as active: %+v", out)
		}
		if out.ClientID != "" || out.Sub != "" {
			t.Errorf("stranger introspection leaked metadata: %+v", out)
		}
	}
}
