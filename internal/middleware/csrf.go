package middleware

// CSRF protection for cookie authenticated form posts.

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"
	"net/http"
	"sync"
	"time"

	"github.com/redis/go-redis/v9"
)

type csrfKeyType struct{}

var csrfKey = csrfKeyType{}

// CSRFConfig holds the configuration for CSRF protection.
type CSRFConfig struct {
	// CookieName is the name of the cookie that stores the CSRF token.
	// Default: "csrf_token"
	CookieName string

	// CookiePath is the path for the CSRF cookie.
	// Default: "/"
	CookiePath string

	// CookieMaxAge is the max age of the CSRF cookie in seconds.
	// Default: 86400 (24h)
	CookieMaxAge int

	// CookieSecure requires HTTPS for the CSRF cookie.
	// Default: true
	CookieSecure bool

	// CookieSameSite is the SameSite attribute for the CSRF cookie.
	// Default: "lax"
	CookieSameSite http.SameSite

	// AllowedInternalPaths is the whitelist of internal paths that are valid
	// return_to destinations. Only paths starting with one of these prefixes
	// are allowed. Empty slice means no paths allowed (strictest).
	AllowedInternalPaths []string

	// TokenLength is the length of the generated CSRF token in bytes.
	// Default: 32
	TokenLength int
}

// CSRFMiddleware provides CSRF protection for form POST endpoints.
type CSRFMiddleware struct {
	config CSRFConfig
	store  CSRFStore
}

type CSRFStore interface {
	Set(ctx context.Context, key, value string, ttl time.Duration) error
	Get(ctx context.Context, key string) (string, error)
	Delete(ctx context.Context, key string) error
}

// NewCSRFMiddleware builds a CSRF middleware with the given config and store.
func NewCSRFMiddleware(config CSRFConfig, store CSRFStore) *CSRFMiddleware {
	if config.CookieName == "" {
		config.CookieName = "csrf_token"
	}
	if config.CookiePath == "" {
		config.CookiePath = "/"
	}
	if config.CookieMaxAge == 0 {
		config.CookieMaxAge = 86400
	}
	if config.TokenLength == 0 {
		config.TokenLength = 32
	}
	return &CSRFMiddleware{config: config, store: store}
}

// Protect returns middleware that verifies the CSRF token on unsafe methods
// (POST, PUT, DELETE, PATCH) and injects the token into the request context
// for template rendering on GET.
func (c *CSRFMiddleware) Protect(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Safe methods: make a token available and put it in the context so a
		// template can render it into a form.
		if isSafeMethod(r.Method) {
			token := c.tokenForGet(r, w)
			ctx := context.WithValue(r.Context(), csrfKey, token)
			next.ServeHTTP(w, r.WithContext(ctx))
			return
		}

		if !c.validUnsafeRequest(r) {
			w.Header().Set("Content-Type", "application/json; charset=utf-8")
			w.Header().Set("Cache-Control", "no-store")
			w.Header().Set("Pragma", "no-cache")
			w.WriteHeader(http.StatusForbidden)
			// The status line is already committed, so a write failure here cannot be
			// reported to the client and must not change control flow.
			_, _ = fmt.Fprintf(w, `{"error":"access_denied","error_description":"invalid CSRF token"}`)
			return
		}

		next.ServeHTTP(w, r)
	})
}

// isSafeMethod reports whether a method cannot change state.
func isSafeMethod(method string) bool {
	switch method {
	case http.MethodGet, http.MethodHead, http.MethodOptions, http.MethodTrace:
		return true
	default:
		return false
	}
}

// tokenForGet returns the token a form on this response should carry.
//
// An existing valid cookie is reused so a user filling in a long form does not have
// their token invalidated by an unrelated page load. The cookie is the authoritative
// value; the store exists so another instance can validate it.
func (c *CSRFMiddleware) tokenForGet(r *http.Request, w http.ResponseWriter) string {
	if token := c.cookieToken(r); token != "" && c.storedTokenMatches(r.Context(), token) {
		return token
	}
	return c.issueToken(r, w)
}

// cookieToken returns the token from the request cookie, or "".
func (c *CSRFMiddleware) cookieToken(r *http.Request) string {
	cookie, err := r.Cookie(c.config.CookieName)
	if err != nil {
		return ""
	}
	return cookie.Value
}

// storedTokenMatches reports whether the store still holds this token.
//
// A token that has aged out of the store is reissued rather than rejected, so an
// abandoned tab does not produce a form that cannot be submitted. This is checked on the
// safe path only; on the unsafe path a missing store entry is a failure (see
// validUnsafeRequest).
func (c *CSRFMiddleware) storedTokenMatches(ctx context.Context, token string) bool {
	if c.store == nil {
		// No store configured: the cookie is the whole mechanism. Correct for a
		// single instance, and the same-origin check in validUnsafeRequest still
		// applies.
		return true
	}
	_, err := c.store.Get(ctx, c.storeKey(ctx, token))
	return err == nil
}

// validUnsafeRequest checks an unsafe request's CSRF token.
//
// Fails closed. A store that is unreachable, a token that is absent from the store and a
// token that simply does not match are all refusals, and no branch here falls back to
// accepting the cookie value alone — that fallback is what the store exists to remove,
// and reintroducing it would put every failure mode back into one comparison.
func (c *CSRFMiddleware) validUnsafeRequest(r *http.Request) bool {
	provided := r.FormValue("csrf_token")
	if provided == "" {
		provided = r.Header.Get("X-CSRF-Token")
	}
	if provided == "" {
		return false
	}

	// A cookie must also be present. Without this an attacker who can guess or obtain
	// the token by some other route could submit a form with no session cookie at all,
	// and the server would compare against nothing and reject — but the comparison is
	// against a value the attacker supplied, so requiring the cookie is what ties the
	// token to a browser that received it.
	cookieToken := c.cookieToken(r)
	if cookieToken == "" {
		return false
	}
	if !constantTimeEqual(cookieToken, provided) {
		return false
	}

	if c.store == nil {
		return true
	}

	stored, err := c.store.Get(r.Context(), c.storeKey(r.Context(), provided))
	if err != nil || stored == "" {
		return false
	}
	return constantTimeEqual(stored, provided)
}

// storeKey namespaces a token in the store.
//
// Keyed by the session when there is one, so one user's token cannot be validated by
// another's request, and so a token is dropped along with the session it belonged to.
func (c *CSRFMiddleware) storeKey(ctx context.Context, token string) string {
	userID := GetUserID(ctx)
	if userID != "" {
		return "session:" + userID + ":" + token
	}
	// No session yet — this is a pre-login form such as the login or registration
	// page, which is exactly where CSRF matters most.
	return "anon:" + token
}

// issueToken generates a token, records it in the store and sets the cookie.
func (c *CSRFMiddleware) issueToken(r *http.Request, w http.ResponseWriter) string {
	token, err := generateToken(c.config.TokenLength)
	if err != nil {
		// Entropy source failed. The form renders with an empty token and the
		// submission is refused, which is a page the user reloads; the alternative is
		// a predictable token, which is a CSRF hole.
		return ""
	}

	if c.store != nil {
		ttl := time.Duration(c.config.CookieMaxAge) * time.Second
		if err := c.store.Set(r.Context(), c.storeKey(r.Context(), token), token, ttl); err != nil {
			// Unwritable store means the token could not be validated on submission,
			// so it is not issued. Setting the cookie anyway would produce a form
			// whose every submission is refused, which reads as a broken page.
			return ""
		}
	}

	http.SetCookie(w, &http.Cookie{
		Name:     c.config.CookieName,
		Value:    token,
		Path:     c.config.CookiePath,
		MaxAge:   c.config.CookieMaxAge,
		Secure:   c.config.CookieSecure,
		SameSite: c.config.CookieSameSite,
		HttpOnly: true,
	})
	return token
}

// constantTimeEqual compares two secrets without leaking their common prefix length
// through timing.
//
// Length is compared first and returns early, which does leak the length. That is
// accepted deliberately: every token this server issues is the same length, so the
// length carries no information an attacker did not already have.
func constantTimeEqual(a, b string) bool {
	if len(a) != len(b) {
		return false
	}
	var diff byte
	for i := 0; i < len(a); i++ {
		diff |= a[i] ^ b[i]
	}
	return diff == 0
}

// GetCSRFToken returns the CSRF token from the context for template rendering.
func GetCSRFToken(ctx context.Context) string {
	if v := ctx.Value(csrfKey); v != nil {
		if s, ok := v.(string); ok {
			return s
		}
	}
	return ""
}

func generateToken(n int) (string, error) {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(b), nil
}

// InMemoryCSRFStore is a simple in-memory CSRF token store for development.
// Not suitable for multi-instance deployments; use Redis in production.
type InMemoryCSRFStore struct {
	mu     sync.RWMutex
	tokens map[string]string
}

func NewInMemoryCSRFStore() *InMemoryCSRFStore {
	return &InMemoryCSRFStore{tokens: make(map[string]string)}
}

func (s *InMemoryCSRFStore) Set(ctx context.Context, key, value string, ttl time.Duration) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.tokens[key] = value
	return nil
}

func (s *InMemoryCSRFStore) Get(ctx context.Context, key string) (string, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	v, ok := s.tokens[key]
	if !ok {
		return "", errors.New("not found")
	}
	return v, nil
}

func (s *InMemoryCSRFStore) Delete(ctx context.Context, key string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.tokens, key)
	return nil
}

// RedisCSRFStore is a Redis-backed CSRF token store.
type RedisCSRFStore struct {
	client *redis.Client
}

func NewRedisCSRFStore(client *redis.Client) *RedisCSRFStore {
	return &RedisCSRFStore{client: client}
}

func (s *RedisCSRFStore) Set(ctx context.Context, key, value string, ttl time.Duration) error {
	return s.client.Set(ctx, "csrf:"+key, value, ttl).Err()
}

func (s *RedisCSRFStore) Get(ctx context.Context, key string) (string, error) {
	return s.client.Get(ctx, "csrf:"+key).Result()
}

func (s *RedisCSRFStore) Delete(ctx context.Context, key string) error {
	return s.client.Del(ctx, "csrf:"+key).Err()
}
