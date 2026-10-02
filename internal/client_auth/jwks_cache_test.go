package client_auth

// jwks_cache_test.go — Behaviour of the JWKS cache and fetch group.

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"

	"github.com/lestrrat-go/jwx/v2/jwk"
)

func TestJWKSCacheHitAndExpiry(t *testing.T) {
	// Serve a key set that changes only if we hit the endpoint again.
	var hits int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&hits, 1)
		// Return a minimal JWKS with one key.
		k := map[string]any{
			"kty": "RSA",
			"e":   "AQAB",
			"n":   "test",
			"use": "sig",
			"kid": "k1",
		}
		j := map[string]any{"keys": []any{k}}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(j)
	}))
	t.Cleanup(srv.Close)

	now := time.Unix(0, 0)
	ttl := 10 * time.Second
	c := newJWKSCache(ttl)
	c.now = func() time.Time { return now }

	set, ok := c.get("cid")
	if ok || set != nil {
		t.Fatal("expected empty cache")
	}

	// Put and get.
	set1, err := jwk.Parse([]byte(`{"keys":[{"kty":"oct","k":"AAECAwQF","kid":"k1"}]}`))
	if err != nil {
		t.Fatal(err)
	}
	c.put("cid", set1)
	got, ok := c.get("cid")
	if !ok || got.Len() != 1 {
		t.Fatalf("want cached set, got ok=%t len=%d", ok, got.Len())
	}

	// Expire.
	now = now.Add(11 * time.Second)
	got, ok = c.get("cid")
	if ok || got != nil {
		t.Fatal("cache should have expired")
	}

	// Put again and overwrite.
	set2, err := jwk.Parse([]byte(`{"keys":[{"kty":"oct","k":"AAECAwUFAgICAg==","kid":"k2"}]}`))
	if err != nil {
		t.Fatal(err)
	}
	c.put("cid", set2)
	got, ok = c.get("cid")
	if !ok || got.Len() != 1 {
		t.Fatal("want new cached set")
	}
	// Read the kid.
}
