// Revocation (RFC 7009) and its observable effect. The assertions here are about what a
// resource server sees afterwards, not about what the endpoint returns: revocation that
// returns 200 while the token still introspects as active is not revocation.

package integration

import (
	"context"
	"net/http"
	"net/url"
	"testing"

	"oauth-server/test/fixtures"
)

// issueToken mints an access token through the real /token endpoint.
func (e *env) issueToken(t *testing.T, clientID, secret string) string {
	t.Helper()
	resp := e.postFormBasic("/token", url.Values{
		"grant_type": {"client_credentials"},
		"scope":      {"read"},
	}, clientID, secret)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("token status = %d, body = %s", resp.StatusCode, body(t, resp))
	}
	var tok struct {
		AccessToken string `json:"access_token"`
	}
	decodeJSON(t, resp, &tok)
	if tok.AccessToken == "" {
		t.Fatal("no access token issued")
	}
	return tok.AccessToken
}

func (e *env) introspectActive(t *testing.T, token, clientID, secret string) bool {
	t.Helper()
	resp := e.postFormBasic("/introspect", url.Values{"token": {token}}, clientID, secret)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("introspect status = %d, body = %s", resp.StatusCode, body(t, resp))
	}
	var out struct {
		Active bool `json:"active"`
	}
	decodeJSON(t, resp, &out)
	return out.Active
}

func TestRevokedTokenIsNoLongerActive(t *testing.T) {
	e := newEnv(t)

	client, secret := fixtures.ConfidentialClient(
		"rev-1", "revocation-secret-value", "Revoker",
		nil, []string{"client_credentials"}, []string{"read"},
	)
	if err := e.App.Deps.Clients.Create(context.Background(), client); err != nil {
		t.Fatalf("create client: %v", err)
	}

	token := e.issueToken(t, client.ClientID, secret)
	if !e.introspectActive(t, token, client.ClientID, secret) {
		t.Fatal("token is not active immediately after issue")
	}

	revoke := e.postFormBasic("/revoke", url.Values{"token": {token}}, client.ClientID, secret)
	// RFC 7009 section 2.2: the endpoint responds 200 whether or not the token existed.
	if revoke.StatusCode != http.StatusOK {
		t.Fatalf("revoke status = %d, want 200; body = %s", revoke.StatusCode, body(t, revoke))
	}

	if e.introspectActive(t, token, client.ClientID, secret) {
		t.Error("revoked token still introspects as active")
	}
}

func TestRevokingAnUnknownTokenStillSucceeds(t *testing.T) {
	e := newEnv(t)

	client, secret := fixtures.ConfidentialClient(
		"rev-2", "another-revocation-secret", "Revoker",
		nil, []string{"client_credentials"}, []string{"read"},
	)
	if err := e.App.Deps.Clients.Create(context.Background(), client); err != nil {
		t.Fatalf("create client: %v", err)
	}

	// A token this client never had must not be distinguishable from one it revoked.
	resp := e.postFormBasic("/revoke", url.Values{"token": {"not-a-token-this-server-issued"}}, client.ClientID, secret)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want 200; body = %s", resp.StatusCode, body(t, resp))
	}
}

func TestClientCannotIntrospectAnotherClientsToken(t *testing.T) {
	e := newEnv(t)

	owner, ownerSecret := fixtures.ConfidentialClient(
		"own-1", "owner-secret-value-here", "Owner",
		nil, []string{"client_credentials"}, []string{"read"},
	)
	stranger, strangerSecret := fixtures.ConfidentialClient(
		"str-1", "stranger-secret-value-1", "Stranger",
		nil, []string{"client_credentials"}, []string{"read"},
	)
	if err := e.App.Deps.Clients.Create(context.Background(), owner); err != nil {
		t.Fatalf("create owner: %v", err)
	}
	if err := e.App.Deps.Clients.Create(context.Background(), stranger); err != nil {
		t.Fatalf("create stranger: %v", err)
	}

	token := e.issueToken(t, owner.ClientID, ownerSecret)

	// Disclosure must be refused, not merely refused-with-details: the stranger learns
	// only that the token is not theirs, which is the same answer as for a token that
	// does not exist.
	if e.introspectActive(t, token, stranger.ClientID, strangerSecret) {
		t.Error("a client was able to introspect another client's token")
	}
}
