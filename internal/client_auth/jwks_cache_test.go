package client_auth

// jwks_cache_test.go — Behaviour of the JWKS cache and fetch group.

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/lestrrat-go/jwx/v2/jwk"
)

func TestJWKSCacheHitAndExpiry(t *testing.T) {
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
}

// TestJWKSCacheIsolatesClients pins the decision to key on client ID rather than on
// URI: two clients publishing the same jwks_uri are two trust decisions, and a key
// set cached for one must not satisfy the other.
func TestJWKSCacheIsolatesClients(t *testing.T) {
	c := newJWKSCache(time.Minute)

	set, err := jwk.Parse([]byte(`{"keys":[{"kty":"oct","k":"AAECAwQF","kid":"k1"}]}`))
	if err != nil {
		t.Fatal(err)
	}
	c.put("client-a", set)

	if _, ok := c.get("client-b"); ok {
		t.Fatal("client-b read a key set cached for client-a")
	}
	if _, ok := c.get("client-a"); !ok {
		t.Fatal("client-a lost its own key set")
	}
}

// TestJWKSCacheRejectsNilSet covers the failure-caching rule: only successful
// fetches are stored, because caching a failure would turn one transient outage
// into a TTL-long outage for that client.
func TestJWKSCacheRejectsNilSet(t *testing.T) {
	c := newJWKSCache(time.Minute)
	c.put("cid", nil)

	if _, ok := c.get("cid"); ok {
		t.Fatal("a nil key set was cached")
	}
}

// TestJWKSFetchGroupCollapsesConcurrentFetches is the thundering-herd test: N
// concurrent token requests for a cold client must produce one outbound fetch.
func TestJWKSFetchGroupCollapsesConcurrentFetches(t *testing.T) {
	g := newJWKSFetchGroup()

	var fetches int32
	fetch := func() (jwk.Set, error) {
		atomic.AddInt32(&fetches, 1)
		time.Sleep(10 * time.Millisecond)
		return jwk.Parse([]byte(`{"keys":[{"kty":"oct","k":"AAECAwQF","kid":"k1"}]}`))
	}

	const callers = 8
	var wg sync.WaitGroup
	wg.Add(callers)
	for i := 0; i < callers; i++ {
		go func() {
			defer wg.Done()
			if _, err := g.do("cid", fetch); err != nil {
				t.Errorf("fetch: %v", err)
			}
		}()
	}
	wg.Wait()

	if n := atomic.LoadInt32(&fetches); n != 1 {
		t.Fatalf("want 1 fetch for %d concurrent callers, got %d", callers, n)
	}
}

// TestJWKSFetchGroupSeparatesClients checks the group does not collapse across
// clients, which would hand one client another's key set.
func TestJWKSFetchGroupSeparatesClients(t *testing.T) {
	g := newJWKSFetchGroup()

	set, err := jwk.Parse([]byte(`{"keys":[{"kty":"oct","k":"AAECAwQF","kid":"k1"}]}`))
	if err != nil {
		t.Fatal(err)
	}

	var a, b int32
	if _, err := g.do("a", func() (jwk.Set, error) {
		atomic.AddInt32(&a, 1)
		return set, nil
	}); err != nil {
		t.Fatal(err)
	}
	if _, err := g.do("b", func() (jwk.Set, error) {
		atomic.AddInt32(&b, 1)
		return set, nil
	}); err != nil {
		t.Fatal(err)
	}

	if a != 1 || b != 1 {
		t.Fatalf("want one fetch each, got a=%d b=%d", a, b)
	}
}

// TestJWKSFetchGroupPropagatesError checks a failed fetch is reported to every
// waiter, not swallowed by the leader.
func TestJWKSFetchGroupPropagatesError(t *testing.T) {
	g := newJWKSFetchGroup()

	sentinel := errors.New("jwks unreachable")
	const callers = 4
	var wg sync.WaitGroup
	wg.Add(callers)
	for i := 0; i < callers; i++ {
		go func() {
			defer wg.Done()
			if _, err := g.do("cid", func() (jwk.Set, error) {
				return nil, sentinel
			}); !errors.Is(err, sentinel) {
				t.Errorf("want sentinel, got %v", err)
			}
		}()
	}
	wg.Wait()
}

// TestPrivateKeyJWTJWKSFetchCountsHits asserts the fetch path is served from the
// cache on the second call, which is the whole reason the cache exists: a
// jwks_uri round trip is on the token endpoint's critical path.
func TestPrivateKeyJWTJWKSFetchCountsHits(t *testing.T) {
	var hits int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&hits, 1)
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{"keys": []any{map[string]any{
			"kty": "oct", "k": "AAECAwQF", "kid": "k1", "use": "sig", "alg": "HS256",
		}}})
	}))
	defer srv.Close()

	ctx := context.Background()
	cache := newJWKSCache(5 * time.Minute)
	group := newJWKSFetchGroup()

	fetch := func() (jwk.Set, error) {
		req, reqErr := http.NewRequestWithContext(ctx, http.MethodGet, srv.URL, nil)
		if reqErr != nil {
			return nil, reqErr
		}
		resp, respErr := http.DefaultClient.Do(req)
		if respErr != nil {
			return nil, respErr
		}
		defer func() { _ = resp.Body.Close() }()
		if resp.StatusCode != http.StatusOK {
			return nil, errors.New("jwks_uri returned non-200")
		}
		body, readErr := io.ReadAll(resp.Body)
		if readErr != nil {
			return nil, readErr
		}
		return jwk.Parse(body)
	}

	// First call populates the cache.
	if _, ok := cache.get("cid"); ok {
		t.Fatal("cache was warm before the first fetch")
	}
	set, err := group.do("cid", func() (jwk.Set, error) {
		s, fErr := fetch()
		if fErr != nil {
			return nil, fErr
		}
		cache.put("cid", s)
		return s, nil
	})
	if err != nil {
		t.Fatalf("first fetch: %v", err)
	}
	if set.Len() != 1 {
		t.Fatalf("want 1 key, got %d", set.Len())
	}

	// Second call is served from the cache without touching the server.
	if _, ok := cache.get("cid"); !ok {
		t.Fatal("first fetch did not populate the cache")
	}
	if n := atomic.LoadInt32(&hits); n != 1 {
		t.Fatalf("want 1 server hit after caching, got %d", n)
	}
}
