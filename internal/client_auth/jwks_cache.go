package client_auth

// jwks_cache.go — Short-lived cache of fetched client key sets.
//
// A jwks_uri fetch is an outbound network round trip on the token endpoint's critical
// path, made once per token request for every private_key_jwt client. Caching it removes
// that from the request path entirely after the first hit.
//
// The TTL is short on purpose. A cached key set is a stale trust decision: a client that
// revokes a compromised key and publishes a new one needs the server to notice, and the
// revocation cache that backs jti replay detection gives the same key material a much
// longer life than this. A short TTL bounds how long a withdrawn key is still honoured
// while still removing the fetch from nearly every request.

import (
	"sync"
	"time"

	"github.com/lestrrat-go/jwx/v2/jwk"
)

// jwksCacheTTL is how long a fetched key set is reused.
//
// Five minutes is a compromise rather than a derived number: long enough that a busy
// client fetches once per TTL instead of once per request, short enough that a rotated
// key propagates without an operator restart.
const jwksCacheTTL = 5 * time.Minute

// jwksCache holds fetched key sets keyed by client ID.
//
// Keyed by client ID rather than by URI: the same URI published by two clients is two
// trust decisions, and a key set cached for one must not satisfy the other.
type jwksCache struct {
	mu      sync.RWMutex
	entries map[string]jwksCacheEntry
	ttl     time.Duration

	// now is injectable so the expiry behaviour is testable without sleeping.
	now func() time.Time
}

type jwksCacheEntry struct {
	set       jwk.Set
	fetchedAt time.Time
}

func newJWKSCache(ttl time.Duration) *jwksCache {
	return &jwksCache{
		entries: make(map[string]jwksCacheEntry),
		ttl:     ttl,
		now:     time.Now,
	}
}

// get returns the cached key set for clientID, or false when absent or expired.
func (c *jwksCache) get(clientID string) (jwk.Set, bool) {
	if c == nil {
		return nil, false
	}

	c.mu.RLock()
	entry, ok := c.entries[clientID]
	c.mu.RUnlock()

	if !ok {
		return nil, false
	}
	if c.now().Sub(entry.fetchedAt) >= c.ttl {
		// Expired. Left in place for the writer to replace; returning false is what
		// forces the fetch, and the entry is overwritten on the way back.
		return nil, false
	}
	return entry.set, true
}

// put stores a key set for clientID.
//
// Only successful fetches are stored. Caching a failure would let one transient outage
// become a TTL-long outage for that client.
func (c *jwksCache) put(clientID string, set jwk.Set) {
	if c == nil || set == nil {
		return
	}

	c.mu.Lock()
	defer c.mu.Unlock()
	c.entries[clientID] = jwksCacheEntry{set: set, fetchedAt: c.now()}
}

// invalidate drops the cached key set for clientID.
func (c *jwksCache) invalidate(clientID string) {
	if c == nil {
		return
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	delete(c.entries, clientID)
}

// singleflight prevents a thundering herd.
//
// Without it, N concurrent token requests for a cold client each see a cache miss and
// each perform the fetch. The entry is what they are all racing to produce, so the work
// is deduplicated rather than repeated.
type jwksFetchGroup struct {
	mu    sync.Mutex
	calls map[string]*jwksFetchCall
}

type jwksFetchCall struct {
	wg  sync.WaitGroup
	set jwk.Set
	err error
}

func newJWKSFetchGroup() *jwksFetchGroup {
	return &jwksFetchGroup{calls: make(map[string]*jwksFetchCall)}
}

// do runs fetch for clientID unless an identical fetch is already in flight, in which case
// it waits for that one and returns its result.
func (g *jwksFetchGroup) do(clientID string, fetch func() (jwk.Set, error)) (jwk.Set, error) {
	if g == nil {
		return fetch()
	}

	g.mu.Lock()
	if call, ok := g.calls[clientID]; ok {
		g.mu.Unlock()
		call.wg.Wait()
		return call.set, call.err
	}
	call := &jwksFetchCall{}
	call.wg.Add(1)
	g.calls[clientID] = call
	g.mu.Unlock()

	call.set, call.err = fetch()

	g.mu.Lock()
	delete(g.calls, clientID)
	g.mu.Unlock()
	call.wg.Done()

	return call.set, call.err
}
