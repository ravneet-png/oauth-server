// Client credentials: the simplest grant, and the one that exercises the token
// endpoint, client authentication, scope filtering and token issuance without a browser
// in the way.

package integration

import (
	"context"
	"net/http"
	"net/url"
	"testing"

	"oauth-server/test/fixtures"
)

func TestClientCredentialsIssuesAndIntrospectsAToken(t *testing.T) {
	e := newEnv(t)

	client, secret := fixtures.ConfidentialClient(
		"svc-1", "correct-horse-battery-staple", "Billing Service",
		nil, []string{"client_credentials"}, []string{"billing.read", "billing.write"},
	)
	if err := e.App.Deps.Clients.Create(context.Background(), client); err != nil {
		t.Fatalf("create client: %v", err)
	}

	resp := e.postFormBasic("/token", url.Values{
		"grant_type": {"client_credentials"},
		"scope":      {"billing.read"},
	}, client.ClientID, secret)

	if resp.StatusCode != http.StatusOK {
		t.Fatalf("token status = %d, body = %s", resp.StatusCode, body(t, resp))
	}

	var token struct {
		AccessToken string `json:"access_token"`
		TokenType   string `json:"token_type"`
		ExpiresIn   int    `json:"expires_in"`
		Scope       string `json:"scope"`
	}
	decodeJSON(t, resp, &token)

	if token.AccessToken == "" {
		t.Fatal("no access_token in response")
	}
	if token.TokenType != "Bearer" {
		t.Errorf("token_type = %q, want Bearer", token.TokenType)
	}
	if token.ExpiresIn <= 0 {
		t.Errorf("expires_in = %d, want > 0", token.ExpiresIn)
	}
	if token.Scope != "billing.read" {
		t.Errorf("scope = %q, want billing.read", token.Scope)
	}

	// The issued token must be introspectable and active, which proves the token was
	// persisted rather than only signed.
	intro := e.postFormBasic("/introspect", url.Values{"token": {token.AccessToken}}, client.ClientID, secret)
	if intro.StatusCode != http.StatusOK {
		t.Fatalf("introspect status = %d, body = %s", intro.StatusCode, body(t, intro))
	}
	var active struct {
		Active bool   `json:"active"`
		Sub    string `json:"sub"`
		Scope  string `json:"scope"`
	}
	decodeJSON(t, intro, &active)
	if !active.Active {
		t.Fatalf("freshly issued token is not active: %s", body(t, intro))
	}
}

func TestClientCredentialsRejectsBadSecret(t *testing.T) {
	e := newEnv(t)

	client, _ := fixtures.ConfidentialClient(
		"svc-2", "the-real-secret", "Service",
		nil, []string{"client_credentials"}, []string{"read"},
	)
	if err := e.App.Deps.Clients.Create(context.Background(), client); err != nil {
		t.Fatalf("create client: %v", err)
	}

	resp := e.postFormBasic("/token", url.Values{"grant_type": {"client_credentials"}}, client.ClientID, "wrong-secret")
	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("status = %d, want 401; body = %s", resp.StatusCode, body(t, resp))
	}
	var oerr struct {
		Error string `json:"error"`
	}
	decodeJSON(t, resp, &oerr)
	if oerr.Error != "invalid_client" {
		t.Errorf("error = %q, want invalid_client", oerr.Error)
	}
}

func TestClientCredentialsRejectsGrantTheClientLacks(t *testing.T) {
	e := newEnv(t)

	client, secret := fixtures.ConfidentialClient(
		"svc-3", "another-secret-value", "Web App",
		[]string{"https://app.example/cb"}, []string{"authorization_code"}, []string{"openid"},
	)
	if err := e.App.Deps.Clients.Create(context.Background(), client); err != nil {
		t.Fatalf("create client: %v", err)
	}

	resp := e.postFormBasic("/token", url.Values{"grant_type": {"client_credentials"}}, client.ClientID, secret)
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400; body = %s", resp.StatusCode, body(t, resp))
	}
	var oerr struct {
		Error string `json:"error"`
	}
	decodeJSON(t, resp, &oerr)
	if oerr.Error != "unauthorized_client" {
		t.Errorf("error = %q, want unauthorized_client", oerr.Error)
	}
}
