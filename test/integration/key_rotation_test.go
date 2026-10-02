// Signing key rotation: the JWKS grows rather than replacing, and a token minted before
// a rotation still verifies after it.

package integration

import (
	"context"
	"net/http"
	"net/url"
	"testing"
)

func TestKeyRotationKeepsRetiredKeysVerifiable(t *testing.T) {
	e := newEnv(t)

	user := createUserWithPassword(t, e, "user-kr-1", "bob@example.test", "correct horse battery", true)

	f := newConfidentialFlow(t, e, "app-kr-1", "client-secret-for-kr-1")
	f.start(t, e)
	f.signIn(t, e, user.Email, "correct horse battery")
	code := f.allow(t, e)

	tokens := f.exchange(t, e, code)
	if tokens.AccessToken == "" {
		t.Fatal("no access token issued")
	}

	before := jwksKeyIDs(t, e)
	if len(before) == 0 {
		t.Fatal("JWKS published no keys before rotation")
	}

	// Force a rotation. The token above is signed by the key that is about to retire.
	newKey, err := e.App.Deps.KeyRotator.ForceRotate(context.Background())
	if err != nil {
		t.Fatalf("force rotate: %v", err)
	}

	after := jwksKeyIDs(t, e)

	// The retired key must stay published: dropping it the moment it retires would
	// invalidate every token already issued, which is the opposite of a rotation.
	if !contains(after, before[0]) {
		t.Errorf("retired key %q vanished from JWKS after rotation; before=%v after=%v",
			before[0], before, after)
	}
	found := false
	for _, id := range after {
		if id == newKey.KID {
			found = true
		}
	}
	if !found {
		t.Errorf("new key %q not published in JWKS; got %v", newKey.KID, after)
	}

	// A token signed by the retired key must still be accepted.
	resp := e.getBearer("/userinfo", tokens.AccessToken)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("userinfo after rotation = %d, want 200; body = %s", resp.StatusCode, body(t, resp))
	}

	// A fresh token is signed by the new key and introspects normally.
	resp = e.postFormBasic("/introspect",
		url.Values{"token": {tokens.AccessToken}}, f.client.ClientID, f.secret)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("introspect after rotation = %d; body = %s", resp.StatusCode, body(t, resp))
	}
	var intr struct {
		Active bool `json:"active"`
	}
	decodeJSON(t, resp, &intr)
	if !intr.Active {
		t.Error("token signed by the retired key reports inactive after rotation")
	}
}

// jwksKeyIDs returns the kid of every published verification key.
func jwksKeyIDs(t *testing.T, e *env) []string {
	t.Helper()

	resp := e.get("/.well-known/jwks.json")
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("jwks status = %d; body = %s", resp.StatusCode, body(t, resp))
	}

	var set struct {
		Keys []struct {
			KID string `json:"kid"`
		} `json:"keys"`
	}
	decodeJSON(t, resp, &set)

	ids := make([]string, 0, len(set.Keys))
	for _, k := range set.Keys {
		ids = append(ids, k.KID)
	}
	return ids
}

func contains(haystack []string, needle string) bool {
	for _, s := range haystack {
		if s == needle {
			return true
		}
	}
	return false
}
