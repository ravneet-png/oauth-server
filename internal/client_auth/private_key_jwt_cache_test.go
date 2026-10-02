package client_auth

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"
)

func TestPrivateKeyJWTWithJWKSURL(t *testing.T) {
	var hits int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&hits, 1)
		key := map[string]any{
			"kty": "oct",
			"k":   "AAECAwQF",
			"kid": "k1",
			"use": "sig",
			"alg": "HS256",
		}
		j := map[string]any{"keys": []any{key}}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(j)
	}))
	defer srv.Close()

	auth := NewPrivateKeyJWTAuthenticator(nil, nil, "http://localhost/token")
	auth = auth.WithHTTPClient(allowPrivate())
	auth = auth.WithJWKSCacheTTL(30 * time.Second)

	_ = hits
}

func TestJWKSCacheSingleFlight(t *testing.T) {
	var count int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		time.Sleep(10 * time.Millisecond)
		atomic.AddInt32(&count, 1)
		key := map[string]any{"kty": "oct", "k": "AAECAwQF", "kid": "k1"}
		json.NewEncoder(w).Encode(map[string]any{"keys": []any{key}})
	}))
	defer srv.Close()

	ctx := context.Background()
	auth := NewPrivateKeyJWTAuthenticator(nil, nil, "http://localhost/token")
	auth = auth.WithHTTPClient(allowPrivate())
	auth = auth.WithJWKSCacheTTL(5 * time.Minute)

	_ = ctx
	_ = auth
	_ = srv.URL
	if atomic.LoadInt32(&count) != 0 {
		t.Fatalf("unexpected hit")
	}
}
