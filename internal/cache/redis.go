package cache

// Redis client construction and the lossy-state stores built on it.
//
// Everything Redis holds here is state the server can afford to lose: rate limit
// counters, revocation lookups (authoritative in PostgreSQL), MFA pending state
// (backed by a session row), and client assertion replay caches. Nothing in Redis is
// the sole copy of a security decision. That is the property to preserve when adding
// a key: if losing it means a revoked token becomes valid, the key is the wrong place
// to keep it.

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"
	"log/slog"
	"strings"
	"time"

	"github.com/redis/go-redis/v9"

	"oauth-server/internal/crypto"
)

// Config is the Redis connection configuration.
type Config struct {
	// URL is a redis:// or rediss:// connection string, or a bare host:port.
	URL string

	// Addr is used when URL is empty.
	Addr string

	Password string

	DB int

	// Prefix namespaces every key this process writes.
	//
	// Not optional in practice. Without it a shared Redis instance silently merges
	// two deployments' rate limit counters and revocation caches, so a test run
	// limits production's traffic and neither notices.
	Prefix string

	MaxRetries int

	PoolSize int

	DialTimeout  time.Duration
	ReadTimeout  time.Duration
	WriteTimeout time.Duration
}

// DefaultPrefix is used when Config.Prefix is empty.
const DefaultPrefix = "oauth:"

// DefaultConfig returns a Config with the timeouts a request handler needs.
func DefaultConfig() Config {
	return Config{
		Prefix:       DefaultPrefix,
		MaxRetries:   2,
		PoolSize:     10,
		DialTimeout:  5 * time.Second,
		ReadTimeout:  2 * time.Second,
		WriteTimeout: 2 * time.Second,
	}
}

// ErrNotFound is returned when a key is absent or expired.
//
// Distinct from a Redis error so callers can tell "no replay cache entry, therefore
// this assertion has not been seen" from "the cache is unreachable, so we cannot
// tell". Those need opposite responses on an authentication path.
var ErrNotFound = errors.New("cache: key not found")

// Client wraps a Redis client with the key prefix applied.
//
// A named type rather than a bare *redis.Client so the prefix cannot be bypassed by
// a caller reaching for the embedded client and building an unprefixed key.
type Client struct {
	redis  *redis.Client
	prefix string
	log    *slog.Logger
}

// New builds a Client from cfg.
//
// Returns an error when no address can be determined rather than defaulting to
// localhost:6379. A server that starts without Redis and then silently has no rate
// limiting is a worse failure than one that refuses to start.
func New(ctx context.Context, cfg Config, log *slog.Logger) (*Client, error) {
	if log == nil {
		log = slog.Default()
	}

	opts, err := redisOptions(cfg)
	if err != nil {
		return nil, err
	}

	rc := redis.NewClient(opts)

	// Pinged at construction because New's contract is that a configured cache is a
	// reachable cache. Callers that would rather tolerate an unreachable Redis build
	// their own client with NewClient and check lazily.
	if err := rc.Ping(ctx).Err(); err != nil {
		_ = rc.Close()
		return nil, fmt.Errorf("cache: redis ping: %w", err)
	}

	prefix := cfg.Prefix
	if prefix == "" {
		prefix = DefaultPrefix
	}

	return &Client{redis: rc, prefix: prefix, log: log}, nil
}

// Raw exposes the underlying go-redis client.
//
// Exists for the components that were written against go-redis directly rather than
// against this wrapper: the rate limiter and CSRF store run Lua scripts and need the
// client's Eval, and the MFA pending store predates this package. Two clients to one
// Redis is acceptable; two *connection pools* is not, and building a second here would
// mean a caller could not tell which pool it was closing.
//
// The prefix is not applied to keys obtained through Raw. Callers using it are
// responsible for namespacing, and each of them already does.
func (c *Client) Raw() *redis.Client {
	if c == nil {
		return nil
	}
	return c.redis
}

// NewClient builds a Client without connecting.
//
// Used where the process must start regardless, and the first operation reports the
// failure.
func NewClient(cfg Config, log *slog.Logger) (*Client, error) {
	if log == nil {
		log = slog.Default()
	}
	opts, err := redisOptions(cfg)
	if err != nil {
		return nil, err
	}
	prefix := cfg.Prefix
	if prefix == "" {
		prefix = DefaultPrefix
	}
	return &Client{redis: redis.NewClient(opts), prefix: prefix, log: log}, nil
}

// redisOptions translates Config into go-redis options.
func redisOptions(cfg Config) (*redis.Options, error) {
	opts := &redis.Options{
		MaxRetries:   cfg.MaxRetries,
		PoolSize:     cfg.PoolSize,
		DialTimeout:  cfg.DialTimeout,
		ReadTimeout:  cfg.ReadTimeout,
		WriteTimeout: cfg.WriteTimeout,
	}

	switch {
	case cfg.URL != "":
		// ParseURL rather than hand-parsing, so rediss://, a password with reserved
		// characters, and a trailing path are all handled by the library.
		parsed, err := redis.ParseURL(cfg.URL)
		if err != nil {
			return nil, fmt.Errorf("cache: parse redis url: %w", err)
		}
		parsed.MaxRetries = opts.MaxRetries
		parsed.PoolSize = opts.PoolSize
		parsed.DialTimeout = opts.DialTimeout
		parsed.ReadTimeout = opts.ReadTimeout
		parsed.WriteTimeout = opts.WriteTimeout
		if cfg.Password != "" {
			parsed.Password = cfg.Password
		}
		if cfg.DB != 0 {
			parsed.DB = cfg.DB
		}
		return parsed, nil

	case cfg.Addr != "":
		opts.Addr = cfg.Addr
		opts.Password = cfg.Password
		opts.DB = cfg.DB
		return opts, nil

	default:
		return nil, errors.New("cache: neither URL nor Addr is set")
	}
}

// keySep separates key parts.
//
// Not ":" because the parts are not all under this package's control. An identifier
// that is an IPv6 literal contains colons, and "ratelimit" + "2001:db8::1" would
// collide with "ratelimit" + "2001:db8" + "1" — two different counters sharing a key,
// so one address's traffic suppresses another's. Two bytes that cannot appear in a
// client_id, a redirect URI or an IP literal make the encoding injective by
// construction rather than by inspection.
const keySep = "\x00"

// Key namespaces one key.
//
// Injective in its parts: distinct part sequences always produce distinct keys.
func (c *Client) Key(parts ...string) string {
	var b strings.Builder
	b.Grow(len(c.prefix) + 16)
	b.WriteString(c.prefix)
	for _, p := range parts {
		b.WriteString(keySep)
		b.WriteString(p)
	}
	return b.String()
}

// Ping checks connectivity.
func (c *Client) Ping(ctx context.Context) error {
	if err := c.redis.Ping(ctx).Err(); err != nil {
		return fmt.Errorf("cache: ping: %w", err)
	}
	return nil
}

// Close releases the connection pool.
func (c *Client) Close() error {
	return c.redis.Close()
}

// Get returns a string value.
//
// The redis.Nil case is translated to ErrNotFound so a caller on an authentication
// path can distinguish "not cached" from "cache broken".
func (c *Client) Get(ctx context.Context, key string) (string, error) {
	val, err := c.redis.Get(ctx, key).Result()
	if errors.Is(err, redis.Nil) {
		return "", ErrNotFound
	}
	if err != nil {
		return "", fmt.Errorf("cache: get %s: %w", key, err)
	}
	return val, nil
}

// Set stores a string value with a TTL.
//
// A zero or negative TTL is rejected rather than applied: Redis treats EX 0 as a
// deletion instruction in some paths and as "never expire" in others depending on the
// command, and the difference between "the replay cache entry vanishes" and "it
// lives forever" is the difference between a bounded authentication check and an
// unbounded one.
func (c *Client) Set(ctx context.Context, key, value string, ttl time.Duration) error {
	if ttl <= 0 {
		return fmt.Errorf("cache: set %s: ttl must be positive, got %s", key, ttl)
	}
	if err := c.redis.Set(ctx, key, value, ttl).Err(); err != nil {
		return fmt.Errorf("cache: set %s: %w", key, err)
	}
	return nil
}

// Delete removes a key. Missing keys are not an error.
func (c *Client) Delete(ctx context.Context, keys ...string) error {
	if len(keys) == 0 {
		return nil
	}
	if err := c.redis.Del(ctx, keys...).Err(); err != nil {
		return fmt.Errorf("cache: delete: %w", err)
	}
	return nil
}

// MarkSeen records a value and reports whether it was already present.
//
// The whole point of a replay cache: true means the value has been seen before and the
// caller must refuse it. Implemented with SET NX so the check and the write are one
// atomic step — a caller that did GET then SET has a window in which two concurrent
// replays of the same assertion both read absent and both proceed.
//
// ttl bounds the memory. It should be at least as long as the artefact is valid,
// because the entry is what makes a second use detectable.
func (c *Client) MarkSeen(ctx context.Context, key, value string, ttl time.Duration) (bool, error) {
	if ttl <= 0 {
		return false, fmt.Errorf("cache: mark seen %s: ttl must be positive, got %s", key, ttl)
	}
	stored, err := c.redis.SetArgs(ctx, key, value, redis.SetArgs{Mode: "NX", TTL: ttl}).Result()
	switch {
	case errors.Is(err, redis.Nil):
		// NX and the key already exists: this value has been seen.
		return true, nil
	case err != nil:
		return false, fmt.Errorf("cache: mark seen %s: %w", key, err)
	default:
		if stored == "OK" {
			return false, nil
		}
		// SetArgs returns an empty string when NX did not take effect.
		return true, nil
	}
}

// Incr counts a key and applies a TTL on first use.
//
// INCR then EXPIRE is not atomic in two round trips, but here that is acceptable and
// the alternative is a Lua script for no benefit: the window is milliseconds and the
// worst outcome is a counter that never expires, which is a leak rather than a
// security hole. TTL is only applied when EXPIRE reports the key was created, so a
// busy counter is not extended indefinitely.
func (c *Client) Incr(ctx context.Context, key string, ttl time.Duration) (int64, error) {
	if ttl <= 0 {
		return 0, fmt.Errorf("cache: incr %s: ttl must be positive, got %s", key, ttl)
	}
	n, err := c.redis.Incr(ctx, key).Result()
	if err != nil {
		return 0, fmt.Errorf("cache: incr %s: %w", key, err)
	}
	if n == 1 {
		if err := c.redis.Expire(ctx, key, ttl).Err(); err != nil {
			return n, fmt.Errorf("cache: set ttl on %s: %w", key, err)
		}
	}
	return n, nil
}

// PendingState is short-lived state for an in-progress authentication.
//
// Deliberately minimal: an opaque id, the user it belongs to, and what stage the flow
// reached. The MFA secret, the password and the granted scopes do not belong here —
// this key is reachable by anyone who obtains the pending id, and the flow can read
// them back from the session row instead.
type PendingState struct {
	// UserID is the account being authenticated.
	UserID string

	// Stage is where the flow has reached, e.g. "mfa".
	Stage string

	// AuthRequestID is the authorization request this login belongs to.
	AuthRequestID string

	// RedirectURI and ClientID are echoed back so the MFA handler can finish the
	// request without re-reading the session.
	ClientID    string
	RedirectURI string

	// Amr and Acr are the authentication methods recorded for the eventual session,
	// so a password-only login that upgrades to MFA ends up with amr containing both.
	Amr []string
	Acr string
}

// MFA stages.
const (
	StagePassword = "password"
	StageMFA      = "mfa"
)

// PendingTTL is how long a partially completed login stays usable.
//
// Short. It covers the user reading a code and typing it, and nothing more; a longer
// window would let an id captured from a shared machine be redeemed hours later.
const PendingTTL = 5 * time.Minute

// SavePending stores MFA pending state under a fresh, unguessable id.
//
// The id is generated here rather than by the caller so no caller can accidentally
// issue a sequential or timestamp-derived one. It is the only thing standing between
// "whoever has this string" and "whoever this user is".
func (c *Client) SavePending(ctx context.Context, state PendingState) (string, error) {
	if state.UserID == "" {
		return "", errors.New("cache: SavePending: user id is empty")
	}
	id, err := NewPendingID()
	if err != nil {
		return "", err
	}
	payload := PendingState{
		UserID:        state.UserID,
		Stage:         state.Stage,
		AuthRequestID: state.AuthRequestID,
		ClientID:      state.ClientID,
		RedirectURI:   state.RedirectURI,
		Amr:           state.Amr,
		Acr:           state.Acr,
	}
	if payload.Stage == "" {
		payload.Stage = StageMFA
	}
	if err := c.Set(ctx, pendingKey(c, id), encodePending(payload), PendingTTL); err != nil {
		return "", err
	}
	return id, nil
}

// pendingKey is the storage key for one pending id.
func pendingKey(c *Client, id string) string {
	return c.Key("mfa", "pending", HashPendingID(id))
}

// takePendingScript fetches and deletes in one round trip.
//
// A GET followed by a DEL is two round trips, and between them every other request
// carrying the same pending id reads the same value. The MFA code is guessable at three
// attempts a minute, so a window that lets N concurrent redemptions of one id all pass
// turns that limit into N attempts per window — the rate limit and the single-use
// guarantee are the same control, and this is where the single-use half lives.
//
// Lua rather than GETDEL so the behaviour does not depend on the Redis version in
// front of the deployment. The script is trivial enough to read in full, which is the
// main thing to want from a script that runs on an authentication path.
var takePendingScript = redis.NewScript(`
	local value = redis.call('GET', KEYS[1])
	if not value then
		return false
	end
	redis.call('DEL', KEYS[1])
	return value
`)

// TakePending fetches and deletes pending state.
//
// Single use, atomically.
func (c *Client) TakePending(ctx context.Context, id string) (*PendingState, error) {
	if id == "" {
		return nil, ErrNotFound
	}

	value, err := takePendingScript.Run(ctx, c.redis, []string{pendingKey(c, id)}).Text()
	if errors.Is(err, redis.Nil) {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, fmt.Errorf("cache: take pending: %w", err)
	}
	if value == "" {
		// The script returns false for a missing key, which go-redis surfaces as an
		// empty string. Treated as absent rather than as a state record with no fields.
		return nil, ErrNotFound
	}

	state, err := decodePending(value)
	if err != nil {
		return nil, err
	}
	return state, nil
}

// ReplayCache tracks one-time artefacts for reuse detection.
//
// Client assertion JTIs and PAR request URIs both fall here: each is valid exactly
// once, and the cache is what turns "valid" into "not already used".
type ReplayCache struct {
	client *Client
}

// NewReplayCache builds a ReplayCache.
func NewReplayCache(c *Client) *ReplayCache {
	return &ReplayCache{client: c}
}

// ErrReplay is returned when a one-time artefact is presented a second time.
var ErrReplay = errors.New("cache: artefact has already been used")

// Check records a JTI and reports ErrReplay if it was already present.
//
// Fails closed on a Redis error. This is the deliberate asymmetry with the rate
// limiter, which fails open: a rate limit that stops working under load is an
// availability problem, whereas a replay cache that stops working under load turns a
// single-use client assertion into a reusable credential.
func (r *ReplayCache) Check(ctx context.Context, kind, jti string, ttl time.Duration) error {
	if jti == "" {
		return errors.New("cache: replay check: jti is empty")
	}
	seen, err := r.client.MarkSeen(ctx, r.client.Key("replay", kind, jti), "1", ttl)
	if err != nil {
		return fmt.Errorf("cache: replay check: %w", err)
	}
	if seen {
		return fmt.Errorf("%w: %s %s", ErrReplay, kind, jti)
	}
	return nil
}

// NewPendingID returns an unguessable pending-state identifier.
//
// 32 bytes of CSPRNG output, base64url. Not a UUID: the id is presented in a form and
// typed by a user, and it is the sole bearer of "which account is authenticating".
func NewPendingID() (string, error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", fmt.Errorf("cache: generate pending id: %w", err)
	}
	return base64.RawURLEncoding.EncodeToString(b), nil
}

// HashPendingID returns the storage key for a pending id.
//
// Present so a caller cannot accidentally use the raw id as a Redis key. It is defence
// in depth: the id is already 256 bits of entropy, so the key is not guessable either
// way, but hashing makes it impossible for the id to appear verbatim in a Redis key
// listing or in a slowlog captured by someone with access to the instance.
func HashPendingID(id string) string {
	return crypto.SHA256Hex(id)
}

// encodePending serialises pending state.
func encodePending(s PendingState) string {
	// JSON rather than a pipe-joined string: the fields contain client ids and
	// redirect URIs, and a delimiter present in any of them would corrupt the record.
	return marshalJSON(s)
}

// decodePending parses pending state.
func decodePending(v string) (*PendingState, error) {
	var s PendingState
	if err := unmarshalJSON(v, &s); err != nil {
		return nil, fmt.Errorf("cache: decode pending state: %w", err)
	}
	return &s, nil
}
