// Discovery and JWKS: the two unauthenticated documents a relying party fetches before
// it can do anything else. If these are wrong, every other endpoint is unreachable in
// practice, so they are the first thing worth asserting against the real router.

package integration

import (
	"net/http"
	"testing"
)

func TestDiscoveryDocumentAdvertisesTheRealEndpoints(t *testing.T) {
	e := newEnv(t)

	resp := e.get("/.well-known/openid-configuration")
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, body = %s", resp.StatusCode, body(t, resp))
	}

	var doc map[string]any
	decodeJSON(t, resp, &doc)

	if got := doc["issuer"]; got != "http://localhost:8080" {
		t.Errorf("issuer = %v, want http://localhost:8080", got)
	}

	// The URLs are derived from the issuer at boot. Asserting each one pins the
	// derivation: a discovery document whose token_endpoint disagrees with where the
	// router actually serves /token is a document that sends every client to a 404.
	want := map[string]string{
		"authorization_endpoint":                "http://localhost:8080/authorize",
		"token_endpoint":                        "http://localhost:8080/token",
		"userinfo_endpoint":                     "http://localhost:8080/userinfo",
		"jwks_uri":                              "http://localhost:8080/.well-known/jwks.json",
		"revocation_endpoint":                   "http://localhost:8080/revoke",
		"introspection_endpoint":                "http://localhost:8080/introspect",
		"pushed_authorization_request_endpoint": "http://localhost:8080/par",
		"end_session_endpoint":                  "http://localhost:8080/logout",
	}
	for key, expected := range want {
		if got, _ := doc[key].(string); got != expected {
			t.Errorf("discovery %s = %q, want %q", key, got, expected)
		}
	}

	methods, _ := doc["code_challenge_methods_supported"].([]any)
	if len(methods) == 0 {
		t.Error("code_challenge_methods_supported is empty; PKCE is mandatory for public clients")
	}
}

func TestJWKSExposesAnActiveVerificationKey(t *testing.T) {
	e := newEnv(t)

	resp := e.get("/.well-known/jwks.json")
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, body = %s", resp.StatusCode, body(t, resp))
	}

	var jwks struct {
		Keys []struct {
			KID string `json:"kid"`
			Use string `json:"use"`
			KTY string `json:"kty"`
			N   string `json:"n"`
			E   string `json:"e"`
		} `json:"keys"`
	}
	decodeJSON(t, resp, &jwks)

	if len(jwks.Keys) == 0 {
		t.Fatal("no keys published; a relying party cannot verify any token")
	}

	var found bool
	for _, k := range jwks.Keys {
		if k.KID == "" {
			t.Error("published key has no kid; tokens would be unverifiable after rotation")
		}
		// Only public parameters may appear. If a private exponent ever leaked into
		// this document the signing key would be compromised to every caller.
		if k.N != "" && k.E != "" && k.KTY == "RSA" {
			found = true
		}
	}
	if !found {
		t.Error("no usable RSA verification key in JWKS")
	}
}

func TestHealthReportsReady(t *testing.T) {
	e := newEnv(t)

	resp := e.get("/health")
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, body = %s", resp.StatusCode, body(t, resp))
	}
}
