package cache

// Redis-backed store tests.
//
// Requires TEST_REDIS_URL and is skipped without it. The behaviour worth testing here
// is Redis's behaviour: SET NX atomics, TTL enforcement and INCR semantics are the
// entire point of a replay cache, and a mock that returns what the assertion expects
// proves only that the mock does.
//
// These tests DO run in parallel with each other. Every key is namespaced by a random
// suffix generated per test, so unlike the storage tests there is no shared table to
// collide over and no need to serialise.

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"os"
	"strconv"
	"sync"
	"testing"
	"time"

	"github.com/redis/go-redis/v9"
)

// testClient returns a Client pointed at TEST_REDIS_URL, or skips.
func testClient(t *testing.T) *Client {
	t.Helper()

	url := os.Getenv("TEST_REDIS_URL")
	if url == "" {
		t.Skip("TEST_REDIS_URL is not set; skipping Redis-backed test")
	}

	// A per-test prefix so these tests can run concurrently and cannot disturb a
	// developer's other keys on the same instance.
	cfg := DefaultConfig()
	cfg.URL = url
	cfg.Prefix = DefaultPrefix + "test:" + uniqueSuffix(t) + ":"

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	c, err := New(ctx, cfg, nil)
	if err != nil {
		t.Fatalf("cache.New: %v", err)
	}
	t.Cleanup(func() {
		if err := c.FlushPrefix(context.Background()); err != nil {
			t.Errorf("FlushPrefix: %v", err)
		}
		_ = c.Close()
	})
	return c
}

// uniqueSuffix returns a random, log-friendly test identifier.
func uniqueSuffix(t *testing.T) string {
	t.Helper()
	b := make([]byte, 8)
	if _, err := rand.Read(b); err != nil {
		t.Fatalf("rand: %v", err)
	}
	return base64.RawURLEncoding.EncodeToString(b)
}

// FlushPrefix removes every key this client's prefix covers.
//
// Scans rather than FLUSHDB: the test instance is shared, and FLUSHDB would destroy a
// developer's running server's rate limit counters and revocation cache.
func (c *Client) FlushPrefix(ctx context.Context) error {
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()

	var cursor uint64
	for {
		keys, next, err := c.redis.Scan(ctx, cursor, c.prefix+"*", 256).Result()
		if err != nil {
			return err
		}
		if len(keys) > 0 {
			if err := c.redis.Del(ctx, keys...).Err(); err != nil {
				return err
			}
		}
		if next == 0 {
			return nil
		}
		cursor = next
	}
}

// TestGetMissingKeyReportsNotFound distinguishes absence from failure.
//
// An authentication path must be able to tell "no replay entry, therefore unused" from
// "the cache is unreachable, therefore unknown". Collapsing them into one error is how a
// Redis outage turns into a bypass.
func TestGetMissingKeyReportsNotFound(t *testing.T) {
	c := testClient(t)

	_, err := c.Get(context.Background(), c.Key("nothing", "here"))
	if !errors.Is(err, ErrNotFound) {
		t.Fatalf("error = %v, want ErrNotFound", err)
	}
}

// TestSetGetRoundTrip checks the basic path with a TTL that actually applies.
func TestSetGetRoundTrip(t *testing.T) {
	c := testClient(t)
	ctx := context.Background()

	if err := c.Set(ctx, c.Key("k"), "v", time.Minute); err != nil {
		t.Fatalf("Set: %v", err)
	}
	got, err := c.Get(ctx, c.Key("k"))
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if got != "v" {
		t.Errorf("value = %q, want v", got)
	}
}

// TestSetRefusesNonPositiveTTL guards the TTL precondition.
//
// Redis's behaviour for EX 0 differs across commands and versions; a caller that means
// "expire immediately" and gets "never expire" has created an unbounded replay cache.
func TestSetRefusesNonPositiveTTL(t *testing.T) {
	c := testClient(t)
	ctx := context.Background()

	for _, ttl := range []time.Duration{0, -time.Second} {
		if err := c.Set(ctx, c.Key("k"), "v", ttl); err == nil {
			t.Errorf("Set accepted ttl %s", ttl)
		}
	}
}

// TestSetAppliesTTL checks expiry actually happens rather than being silently dropped.
//
// Asserted by observing the key disappear, not by reading TTL. TTL is reported in whole
// seconds and rounds down, so a 200ms TTL legitimately reads as 0s — a TTL assertion
// here would be testing Redis's rounding, not this package's behaviour.
func TestSetAppliesTTL(t *testing.T) {
	c := testClient(t)
	ctx := context.Background()

	key := c.Key("expiring")
	if err := c.Set(ctx, key, "v", 200*time.Millisecond); err != nil {
		t.Fatalf("Set: %v", err)
	}
	// Present before expiry, so a later failure is about expiry and not about the
	// write having failed.
	if _, err := c.Get(ctx, key); err != nil {
		t.Fatalf("value missing immediately after Set: %v", err)
	}

	time.Sleep(500 * time.Millisecond)
	if _, err := c.Get(ctx, key); !errors.Is(err, ErrNotFound) {
		t.Errorf("after expiry error = %v, want ErrNotFound", err)
	}
}

// TestMarkSeenIsAtomicUnderConcurrency is the reason MarkSeen exists.
//
// A get-then-set replay check has a window in which N concurrent replays all read
// "absent" and all proceed. SET NX closes it. This test races many goroutines at one
// key and asserts exactly one winner.
func TestMarkSeenIsAtomicUnderConcurrency(t *testing.T) {
	c := testClient(t)
	ctx := context.Background()
	key := c.Key("replay", "jti")

	const racers = 64

	var wg sync.WaitGroup
	results := make([]bool, racers)
	start := make(chan struct{})

	for i := 0; i < racers; i++ {
		wg.Add(1)
		go func(idx int) {
			defer wg.Done()
			<-start
			seen, err := c.MarkSeen(ctx, key, "1", time.Minute)
			if err != nil {
				t.Errorf("MarkSeen: %v", err)
				return
			}
			// seen == false means this caller was first and recorded the value.
			results[idx] = !seen
		}(i)
	}
	close(start)
	wg.Wait()

	winners := 0
	for _, first := range results {
		if first {
			winners++
		}
	}
	if winners != 1 {
		t.Errorf("%d callers recorded the value, want exactly 1", winners)
	}
}

// TestMarkSeenSecondCallReportsSeen checks the replay signal itself.
func TestMarkSeenSecondCallReportsSeen(t *testing.T) {
	c := testClient(t)
	ctx := context.Background()
	key := c.Key("replay", "jti")

	seen, err := c.MarkSeen(ctx, key, "1", time.Minute)
	if err != nil {
		t.Fatalf("first MarkSeen: %v", err)
	}
	if seen {
		t.Error("first MarkSeen reported the value as already seen")
	}

	seen, err = c.MarkSeen(ctx, key, "1", time.Minute)
	if err != nil {
		t.Fatalf("second MarkSeen: %v", err)
	}
	if !seen {
		t.Error("second MarkSeen did not report a replay")
	}
}

// TestMarkSeenRefusesNonPositiveTTL guards the same precondition as Set.
func TestMarkSeenRefusesNonPositiveTTL(t *testing.T) {
	c := testClient(t)

	if _, err := c.MarkSeen(context.Background(), c.Key("k"), "1", 0); err == nil {
		t.Error("MarkSeen accepted a zero TTL")
	}
}

// TestIncrSetsTTLOnFirstUse checks the counter expires.
//
// Without the TTL a counter lives forever and the limit it feeds becomes permanent.
func TestIncrSetsTTLOnFirstUse(t *testing.T) {
	c := testClient(t)
	ctx := context.Background()
	key := c.Key("counter")

	for want := int64(1); want <= 3; want++ {
		got, err := c.Incr(ctx, key, time.Minute)
		if err != nil {
			t.Fatalf("Incr: %v", err)
		}
		if got != want {
			t.Errorf("Incr = %d, want %d", got, want)
		}
	}

	ttl := c.redis.TTL(ctx, key).Val()
	if ttl <= 0 || ttl > 2*time.Minute {
		t.Errorf("TTL = %s, want a positive expiry near one minute", ttl)
	}
}

// TestIncrConcurrentIsAtomic checks the counter cannot lose increments.
//
// A read-then-write counter under concurrency lets N simultaneous requests all read the
// same value and all write the same result, so a limit of 10 admits an unbounded burst.
func TestIncrConcurrentIsAtomic(t *testing.T) {
	c := testClient(t)
	ctx := context.Background()
	key := c.Key("counter", "concurrent")

	const racers = 100
	var wg sync.WaitGroup
	start := make(chan struct{})
	errs := make(chan error, racers)

	for i := 0; i < racers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-start
			if _, err := c.Incr(ctx, key, time.Minute); err != nil {
				errs <- err
			}
		}()
	}
	close(start)
	wg.Wait()
	close(errs)

	for err := range errs {
		t.Errorf("Incr: %v", err)
	}

	final, err := c.Get(ctx, key)
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if final != strconv.Itoa(racers) {
		t.Errorf("counter = %s, want %d", final, racers)
	}
}

// TestIncrRefusesNonPositiveTTL guards the expiry precondition.
func TestIncrRefusesNonPositiveTTL(t *testing.T) {
	c := testClient(t)
	if _, err := c.Incr(context.Background(), c.Key("k"), 0); err == nil {
		t.Error("Incr accepted a zero TTL")
	}
}

// TestTakePendingIsSingleUse is the property that makes a partial login safe to carry
// in Redis.
//
// A pending MFA id plus a code guessable at three tries a minute must redeem once.
// Get-then-Delete would let two concurrent requests both read the state and both pass.
func TestTakePendingIsSingleUse(t *testing.T) {
	c := testClient(t)
	ctx := context.Background()

	id, err := c.SavePending(ctx, PendingState{
		UserID:        "user-1",
		Stage:         StageMFA,
		AuthRequestID: "authreq-1",
		ClientID:      "client-1",
		RedirectURI:   "https://client.example.com/cb",
		Amr:           []string{"pwd", "otp"},
		Acr:           "urn:mace:incommon:iap:silver",
	})
	if err != nil {
		t.Fatalf("SavePending: %v", err)
	}

	state, err := c.TakePending(ctx, id)
	if err != nil {
		t.Fatalf("TakePending: %v", err)
	}
	if state.UserID != "user-1" {
		t.Errorf("UserID = %q, want user-1", state.UserID)
	}
	if state.Stage != StageMFA {
		t.Errorf("Stage = %q, want %q", state.Stage, StageMFA)
	}
	// Round-tripped rather than dropped: amr is what lets a later consent screen
	// know the session is MFA-authenticated.
	if len(state.Amr) != 2 || state.Amr[0] != "pwd" {
		t.Errorf("Amr = %v, want [pwd otp]", state.Amr)
	}
	if state.RedirectURI != "https://client.example.com/cb" {
		t.Errorf("RedirectURI = %q", state.RedirectURI)
	}

	if _, err := c.TakePending(ctx, id); !errors.Is(err, ErrNotFound) {
		t.Errorf("second TakePending error = %v, want ErrNotFound", err)
	}
}

// TestTakePendingConcurrentHasOneWinner checks the delete-on-read path under races.
func TestTakePendingConcurrentHasOneWinner(t *testing.T) {
	c := testClient(t)
	ctx := context.Background()

	id, err := c.SavePending(ctx, PendingState{UserID: "user-1"})
	if err != nil {
		t.Fatalf("SavePending: %v", err)
	}

	const racers = 16
	var wg sync.WaitGroup
	start := make(chan struct{})
	winners := make(chan struct{}, racers)

	for i := 0; i < racers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-start
			if _, err := c.TakePending(ctx, id); err == nil {
				winners <- struct{}{}
			}
		}()
	}
	close(start)
	wg.Wait()
	close(winners)

	if n := len(winners); n != 1 {
		t.Errorf("%d concurrent redemptions succeeded, want 1", n)
	}
}

// TestSavePendingRejectsEmptyUser guards against a state record that identifies nobody.
func TestSavePendingRejectsEmptyUser(t *testing.T) {
	c := testClient(t)
	if _, err := c.SavePending(context.Background(), PendingState{}); err == nil {
		t.Error("SavePending accepted an empty user id")
	}
}

// TestPendingIDsAreUnguessable checks two ids do not collide and are long enough.
func TestPendingIDsAreUnguessable(t *testing.T) {
	seen := make(map[string]bool, 1000)
	for i := 0; i < 1000; i++ {
		id, err := NewPendingID()
		if err != nil {
			t.Fatalf("NewPendingID: %v", err)
		}
		// 32 bytes base64url without padding.
		if len(id) != 43 {
			t.Fatalf("id length = %d, want 43", len(id))
		}
		if seen[id] {
			t.Fatal("NewPendingID repeated a value")
		}
		seen[id] = true
	}
}

// TestPendingKeyIsHashed checks the raw id never appears as a Redis key.
//
// Defence in depth: the id is already 256 bits, so the key is not guessable either
// way, but hashing means the id cannot be read straight out of a key listing by anyone
// with access to the Redis instance.
func TestPendingKeyIsHashed(t *testing.T) {
	c := testClient(t)
	id, err := NewPendingID()
	if err != nil {
		t.Fatalf("NewPendingID: %v", err)
	}
	if key := pendingKey(c, id); key == c.Key("mfa", "pending", id) {
		t.Error("pending key contains the raw pending id")
	}
}

// TestReplayCacheRefusesSecondUse is the reuse-detection contract for client
// assertions and PAR request URIs.
func TestReplayCacheRefusesSecondUse(t *testing.T) {
	c := testClient(t)
	ctx := context.Background()
	rc := NewReplayCache(c)

	if err := rc.Check(ctx, "jti", "jti-1", time.Minute); err != nil {
		t.Fatalf("first Check: %v", err)
	}
	err := rc.Check(ctx, "jti", "jti-1", time.Minute)
	if !errors.Is(err, ErrReplay) {
		t.Fatalf("second Check error = %v, want ErrReplay", err)
	}
}

// TestReplayCacheScopesByKind checks one artefact's use does not block another's.
func TestReplayCacheScopesByKind(t *testing.T) {
	c := testClient(t)
	ctx := context.Background()
	rc := NewReplayCache(c)

	if err := rc.Check(ctx, "jti", "shared", time.Minute); err != nil {
		t.Fatalf("Check jti: %v", err)
	}
	if err := rc.Check(ctx, "par", "shared", time.Minute); err != nil {
		t.Errorf("Check par was blocked by the jti entry: %v", err)
	}
}

// TestReplayCacheConcurrentHasOneWinner checks one-time enforcement under races.
func TestReplayCacheConcurrentHasOneWinner(t *testing.T) {
	c := testClient(t)
	ctx := context.Background()
	rc := NewReplayCache(c)

	const racers = 32
	var wg sync.WaitGroup
	start := make(chan struct{})
	accepted := make(chan struct{}, racers)

	for i := 0; i < racers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-start
			if err := rc.Check(ctx, "jti", "contended", time.Minute); err == nil {
				accepted <- struct{}{}
			}
		}()
	}
	close(start)
	wg.Wait()
	close(accepted)

	if n := len(accepted); n != 1 {
		t.Errorf("%d concurrent replays were accepted, want 1", n)
	}
}

// TestReplayCacheRejectsEmptyJTI checks an artefact with no identifier is refused
// rather than silently bucketed under one shared key.
func TestReplayCacheRejectsEmptyJTI(t *testing.T) {
	c := testClient(t)
	if err := NewReplayCache(c).Check(context.Background(), "jti", "", time.Minute); err == nil {
		t.Error("Check accepted an empty jti")
	}
}

// TestReplayCacheFailsClosedOnRedisError checks an unreachable cache refuses rather than
// allowing.
//
// The deliberate asymmetry with the rate limiter: a limit that stops working is an
// availability problem, whereas a replay cache that stops working turns a single-use
// assertion into a reusable credential.
func TestReplayCacheFailsClosedOnRedisError(t *testing.T) {
	// Built without pinging so it points at a dead address.
	cfg := DefaultConfig()
	cfg.Addr = "127.0.0.1:1"
	c, err := NewClient(cfg, nil)
	if err != nil {
		t.Fatalf("NewClient: %v", err)
	}
	defer c.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()

	err = NewReplayCache(c).Check(ctx, "jti", "jti-1", time.Minute)
	if err == nil {
		t.Fatal("Check succeeded against an unreachable Redis")
	}
	if errors.Is(err, ErrReplay) {
		t.Error("an unreachable cache reported a replay rather than an error")
	}
}

// TestKeyNamespaces confirms every key this client writes is prefixed.
//
// Two deployments sharing a Redis instance with an unprefixed key silently merge their
// rate limit counters, so one environment can throttle the other.
func TestKeyNamespaces(t *testing.T) {
	c := testClient(t)
	if got := c.Key("a", "b"); got[:len(c.prefix)] != c.prefix {
		t.Errorf("Key = %q, want prefix %q", got, c.prefix)
	}
}

// TestKeyIsInjective checks distinct part sequences cannot collide.
//
// This is the property the separator exists for. Identifiers reaching Key include IPv6
// literals, which contain colons: with a ":" separator, Key("ratelimit", "2001:db8::1")
// and Key("ratelimit", "2001:db8", "1") would be one Redis key, so two unrelated
// addresses would share a rate limit counter and each could throttle the other.
func TestKeyIsInjective(t *testing.T) {
	c := testClient(t)

	tests := [][2][]string{
		{{"a", "b"}, {"a:b"}},
		{{"ratelimit", "2001:db8::1"}, {"ratelimit", "2001:db8", "1"}},
		{{"ratelimit", "::1"}, {"ratelimit", "", "1"}},
		{{"a", "", "b"}, {"a", "b"}},
		{{"replay", "jti", "a"}, {"replay", "jti:a"}},
	}

	for _, tc := range tests {
		if c.Key(tc[0]...) == c.Key(tc[1]...) {
			t.Errorf("Key(%q) collides with Key(%q)", tc[0], tc[1])
		}
	}
}

// TestKeyIsStable checks the same parts always produce the same key, which is what
// makes a rate limit counter a counter rather than a series of unrelated keys.
func TestKeyIsStable(t *testing.T) {
	c := testClient(t)
	if c.Key("a", "b", "c") != c.Key("a", "b", "c") {
		t.Error("Key is not deterministic")
	}
}

// TestNewRequiresAnAddress checks startup fails rather than defaulting to localhost.
func TestNewRequiresAnAddress(t *testing.T) {
	if _, err := New(context.Background(), DefaultConfig(), nil); err == nil {
		t.Error("New accepted a config with no address")
	}
}

// TestNewReportsUnreachableRedis checks New's contract that a configured cache is a
// reachable cache.
func TestNewReportsUnreachableRedis(t *testing.T) {
	cfg := DefaultConfig()
	cfg.Addr = "127.0.0.1:1"

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	if _, err := New(ctx, cfg, nil); err == nil {
		t.Error("New succeeded against an unreachable Redis")
	}
}

// TestParseURLRejectsGarbage checks a bad URL is a startup error, not a default.
func TestParseURLRejectsGarbage(t *testing.T) {
	cfg := DefaultConfig()
	cfg.URL = "://not a url"
	if _, err := New(context.Background(), cfg, nil); err == nil {
		t.Error("New accepted a malformed URL")
	}
}

// TestPingReportsUnreachable checks the explicit health path.
func TestPingReportsUnreachable(t *testing.T) {
	cfg := DefaultConfig()
	cfg.Addr = "127.0.0.1:1"
	c, err := NewClient(cfg, nil)
	if err != nil {
		t.Fatalf("NewClient: %v", err)
	}
	defer c.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	if err := c.Ping(ctx); err == nil {
		t.Error("Ping succeeded against an unreachable Redis")
	}
}

// TestDeleteMissingKeyIsNotAnError checks cleanup paths do not have to pre-check.
func TestDeleteMissingKeyIsNotAnError(t *testing.T) {
	c := testClient(t)
	if err := c.Delete(context.Background(), c.Key("absent")); err != nil {
		t.Errorf("Delete: %v", err)
	}
	if err := c.Delete(context.Background()); err != nil {
		t.Errorf("Delete with no keys: %v", err)
	}
}

// TestEncodeDecodePendingRoundTrip checks serialisation survives fields containing the
// characters a delimiter-joined format would break on.
//
// redirect_uri is the reason: a URI legitimately contains '/' and ':' and can contain
// '|' when a client registers one.
func TestEncodeDecodePendingRoundTrip(t *testing.T) {
	original := PendingState{
		UserID:        "user|1",
		Stage:         StageMFA,
		AuthRequestID: "authreq-1",
		ClientID:      "client:1",
		RedirectURI:   "https://client.example.com/cb?x=1|y=2",
		Amr:           []string{"pwd", "mfa"},
		Acr:           "urn:mace:incommon:iap:silver",
	}

	decoded, err := decodePending(encodePending(original))
	if err != nil {
		t.Fatalf("decodePending: %v", err)
	}
	if decoded.UserID != original.UserID {
		t.Errorf("UserID = %q, want %q", decoded.UserID, original.UserID)
	}
	if decoded.RedirectURI != original.RedirectURI {
		t.Errorf("RedirectURI = %q, want %q", decoded.RedirectURI, original.RedirectURI)
	}
	if len(decoded.Amr) != 2 {
		t.Errorf("Amr = %v, want two entries", decoded.Amr)
	}
}

// TestPendingDecodeRejectsGarbage checks a corrupted value is an error rather than a
// zero-value PendingState identifying no user.
func TestPendingDecodeRejectsGarbage(t *testing.T) {
	if _, err := decodePending("not json"); err == nil {
		t.Error("decodePending accepted garbage")
	}
}

// TestMarkSeenUsesTheProvidedValue confirms the stored value is what was asked for, so a
// future caller can store a hash rather than a bare identifier.
func TestMarkSeenUsesTheProvidedValue(t *testing.T) {
	c := testClient(t)
	ctx := context.Background()
	key := c.Key("replay", "value")

	if _, err := c.MarkSeen(ctx, key, "value-under-test", time.Minute); err != nil {
		t.Fatalf("MarkSeen: %v", err)
	}
	got, err := c.Get(ctx, key)
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if got != "value-under-test" {
		t.Errorf("stored value = %q", got)
	}
}

// TestRedisNilIsTranslated guards the specific error mapping callers depend on.
func TestRedisNilIsTranslated(t *testing.T) {
	c := testClient(t)

	// Written directly through the underlying client so the value is definitely
	// absent, then read through the wrapper.
	_, err := c.Get(context.Background(), c.Key("definitely", "absent"))
	if err == nil {
		t.Fatal("Get on an absent key succeeded")
	}
	if !errors.Is(err, ErrNotFound) {
		t.Errorf("error = %v (%T), want ErrNotFound", err, err)
	}
	// And specifically not the driver's sentinel leaking through untranslated.
	if errors.Is(err, redis.Nil) {
		t.Error("the redis.Nil sentinel leaked to the caller")
	}
}
