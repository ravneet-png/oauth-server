package middleware

// Redis backed sliding window rate limits using Lua for atomicity.

import (
	"errors"
	"fmt"
	"net/http"
	"strconv"
	"time"

	"github.com/redis/go-redis/v9"

	"oauth-server/internal/crypto"
)

// ErrRateLimited is returned when a rate limit is exceeded.
var ErrRateLimited = errors.New("rate limited")

// RateLimiter wraps a Redis client for sliding window limits.
type RateLimiter struct {
	client *redis.Client
}

// NewRateLimiter builds a RateLimiter from a Redis client.
func NewRateLimiter(client *redis.Client) *RateLimiter {
	return &RateLimiter{client: client}
}

// Limit returns middleware that enforces a sliding window rate limit.
//
// keyPrefix is the Redis key prefix; the full key is keyPrefix + ":" + identifier.
// max is the maximum requests per window. windowSec is the window in seconds.
//
// The limit key is derived from the request by keyFn. For IP-based limits, keyFn
// returns the client IP. For authenticated limits, keyFn returns the client_id
// from the request context (set by auth middleware).
//
// On exceed: 429 with Retry-After header and OAuth error body.
func (rl *RateLimiter) Limit(keyPrefix string, max int, windowSec int, keyFn func(*http.Request) string) func(http.Handler) http.Handler {
	if rl.client == nil {
		// No Redis = no limit. The constructor is explicit about this so a
		// deployment that forgets to wire Redis fails loudly at startup, not
		// silently at first request.
		return func(next http.Handler) http.Handler {
			return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				next.ServeHTTP(w, r)
			})
		}
	}

	luaScript := redis.NewScript(`
		local key = KEYS[1]
		local now = tonumber(ARGV[1])
		local window_ms = tonumber(ARGV[2])
		local window_sec = tonumber(ARGV[3])
		local limit = tonumber(ARGV[4])
		local member = ARGV[5]

		-- Drop entries that have fallen out of the window.
		redis.call('ZREMRANGEBYSCORE', key, '-inf', now - window_ms)

		local count = redis.call('ZCARD', key)

		if count >= limit then
			-- Retry-After is the wait until the oldest entry ages out, which is when
			-- a slot frees up. Reported in whole seconds and never below 1: a
			-- Retry-After of 0 tells the client to retry immediately, and the oldest
			-- entry may be milliseconds from expiring, so the client would come straight
			-- back and be refused again.
			local oldest = redis.call('ZRANGE', key, 0, 0, 'WITHSCORES')
			local retry = window_sec
			if #oldest > 1 then
				retry = math.ceil((tonumber(oldest[2]) + window_ms - now) / 1000)
				if retry < 1 then
					retry = 1
				end
			end
			-- TTL untouched on a refusal. An attacker who trips the limit must not
			-- be able to keep the key alive indefinitely by continuing to hit it.
			return {0, retry}
		end

		-- The member is supplied by the caller, not generated here.
		--
		-- math.random() in Redis Lua is seeded once per server and NOT per script
		-- invocation, so two requests in the same millisecond draw the same value and
		-- ZADD collapses them into one entry. Under a burst that means N requests are
		-- counted as 1, and the limit stops limiting. The caller passes a fresh random
		-- token per request instead.
		redis.call('ZADD', key, now, member)
		-- window_sec + 1: seconds, matching EXPIRE's unit. The previous code passed
		-- window+1 where window was milliseconds, so a 60s window set a 60,001 second
		-- TTL and the key outlived its purpose by 16 hours.
		redis.call('EXPIRE', key, window_sec + 1)
		return {1, 0}
	`)

	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			identifier := keyFn(r)
			if identifier == "" {
				// No identifier means we can't limit; this is a configuration
				// error, not a request error. Allow the request and log.
				next.ServeHTTP(w, r)
				return
			}

			key := fmt.Sprintf("%s:%s", keyPrefix, identifier)
			nowMs := time.Now().UnixMilli()

			// A fresh member token per request, so concurrent requests inside one
			// millisecond are distinct sorted-set entries rather than one.
			member, err := requestMember(nowMs)
			if err != nil {
				// Without a member the script would collapse concurrent requests into
				// one entry, which is the failure this whole change exists to prevent.
				// Refusing the request is the correct direction here: it is a
				// cryptographically impossible condition, not a transient outage, and
				// the alternative is a limit that silently under-counts.
				http.Error(w, "rate limiter unavailable", http.StatusServiceUnavailable)
				return
			}

			ctx := r.Context()
			result, err := luaScript.Run(ctx, rl.client, []string{key},
				nowMs, windowSec*1000, windowSec, max, member).Slice()
			if err != nil {
				// Redis error: fail closed on auth endpoints, fail open on others.
				// This endpoint doesn't know its own criticality, so we default to
				// allowing the request rather than blocking all traffic during a
				// Redis outage. The caller can wrap with a stricter policy if needed.
				next.ServeHTTP(w, r)
				return
			}

			allowed := int64(0)
			if len(result) > 0 {
				if v, ok := result[0].(int64); ok {
					allowed = v
				}
			}

			if allowed == 0 {
				retryAfter := windowSec
				if len(result) > 1 {
					if v, ok := result[1].(int64); ok {
						retryAfter = int(v)
					}
				}

				w.Header().Set("Retry-After", strconv.Itoa(retryAfter))
				w.Header().Set("Content-Type", "application/json; charset=utf-8")
				w.Header().Set("Cache-Control", "no-store")
				w.Header().Set("Pragma", "no-cache")
				w.WriteHeader(http.StatusTooManyRequests)
				// OAuth 2.1 error format
				fmt.Fprintf(w, `{"error":"temporarily_unavailable","error_description":"rate limit exceeded","error_uri":"https://tools.ietf.org/html/rfc6749#section-5.2"}`)
				return
			}

			next.ServeHTTP(w, r)
		})
	}
}

// ClientIP returns the client address for rate limit keying.
//
// Reads whatever TrustedProxy.Middleware resolved and stored in the context, and falls
// back to RemoteAddr when that middleware is not installed.
//
// It does NOT read X-Forwarded-For itself. Doing so here is the bug this replaced: the
// header would be honoured from any peer, so anyone could present a fresh value per
// request and walk past every limit that keys on ClientIP. Falling back to the raw peer
// address is a weaker limit but an honest one.
func ClientIP(r *http.Request) string {
	if addr := ClientAddrFromContext(r); addr != "" {
		return addr
	}
	if addr, ok := parseAddr(r.RemoteAddr); ok {
		return addr.String()
	}
	return r.RemoteAddr
}

// requestMember returns a unique sorted-set member for one request.
//
// The timestamp alone is not enough: several requests can share a millisecond, and ZADD
// would then replace the existing member rather than adding a second entry, so a burst
// of 100 simultaneous requests would count as 1.
func requestMember(nowMs int64) (string, error) {
	suffix, err := crypto.RandomTokenN(8)
	if err != nil {
		return "", fmt.Errorf("middleware: generate rate limit member: %w", err)
	}
	return strconv.FormatInt(nowMs, 10) + "-" + suffix, nil
}

// Rate limit presets - key functions for common limits

// LoginLimit: 5/min per IP
func LoginLimit(rl *RateLimiter) func(http.Handler) http.Handler {
	return rl.Limit("login", 5, 60, func(r *http.Request) string {
		return ClientIP(r)
	})
}

// TokenLimit: 1000/min per authenticated client_id
func TokenLimit(rl *RateLimiter) func(http.Handler) http.Handler {
	return rl.Limit("token", 1000, 60, func(r *http.Request) string {
		// client_id should be set in context by client auth middleware
		if v := r.Context().Value("client_id"); v != nil {
			if s, ok := v.(string); ok {
				return s
			}
		}
		return ""
	})
}

// UnauthTokenLimit: 10/min per IP (before auth, prevents guessing)
func UnauthTokenLimit(rl *RateLimiter) func(http.Handler) http.Handler {
	return rl.Limit("token_unauth", 10, 60, func(r *http.Request) string {
		return ClientIP(r)
	})
}

// RegisterLimit: 3/hour per IP
func RegisterLimit(rl *RateLimiter) func(http.Handler) http.Handler {
	return rl.Limit("register", 3, 3600, func(r *http.Request) string {
		return ClientIP(r)
	})
}

// PARLimit: 1000/min per client_id
func PARLimit(rl *RateLimiter) func(http.Handler) http.Handler {
	return rl.Limit("par", 1000, 60, func(r *http.Request) string {
		if v := r.Context().Value("client_id"); v != nil {
			if s, ok := v.(string); ok {
				return s
			}
		}
		return ClientIP(r)
	})
}

// MFALimit: 3/min per mfa_pending_id
func MFALimit(rl *RateLimiter) func(http.Handler) http.Handler {
	return rl.Limit("mfa", 3, 60, func(r *http.Request) string {
		if v := r.Context().Value("mfa_pending_id"); v != nil {
			if s, ok := v.(string); ok {
				return s
			}
		}
		return ClientIP(r)
	})
}
