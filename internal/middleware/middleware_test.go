package middleware

// Middleware tests.
//
// No database and no SMTP. The properties under test are the ones a browser or an
// attacker controls: which forwarded headers are believed, where a redirect is allowed
// to point, whether a token survives an expired store entry, and that a panic does not
// reach the client as a stack trace.

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"
)

// --- trusted proxy -------------------------------------------------------------

func newRequest(remoteAddr string, xff ...string) *http.Request {
	r := httptest.NewRequest(http.MethodGet, "/", nil)
	r.RemoteAddr = remoteAddr
	for _, v := range xff {
		r.Header.Add("X-Forwarded-For", v)
	}
	return r
}

// TestForwardedHeadersIgnoredFromUntrustedPeer is the core reason this middleware
// exists.
//
// Without the trust check, an attacker rotates X-Forwarded-For per request and every
// IP-keyed rate limit becomes unlimited.
func TestForwardedHeadersIgnoredFromUntrustedPeer(t *testing.T) {
	tp, err := NewTrustedProxy([]string{"10.0.0.0/8"})
	if err != nil {
		t.Fatalf("NewTrustedProxy: %v", err)
	}

	r := newRequest("203.0.113.9:54321", "1.2.3.4")
	got := tp.Resolve(r)

	if got != "203.0.113.9" {
		t.Errorf("Resolve = %q, want 203.0.113.9 (the peer, not the header)", got)
	}
}

// TestForwardedHeadersHonouredFromTrustedProxy checks the headers are read when the peer
// is trusted.
func TestForwardedHeadersHonouredFromTrustedProxy(t *testing.T) {
	tp, err := NewTrustedProxy([]string{"10.0.0.0/8"})
	if err != nil {
		t.Fatalf("NewTrustedProxy: %v", err)
	}

	r := newRequest("10.0.0.1:443", "203.0.113.9")
	if got := tp.Resolve(r); got != "203.0.113.9" {
		t.Errorf("Resolve = %q, want 203.0.113.9", got)
	}
}

// TestChainWalkTakesTheLastUntrustedHop is where the design decision lives.
//
// The leftmost entry is what an untrusted hop chose to write, and it is chosen by the
// party being rate limited. Walking right and stopping at the first non-proxy is the
// only entry this server can honestly attribute.
func TestChainWalkTakesTheLastUntrustedHop(t *testing.T) {
	tp, err := NewTrustedProxy([]string{"10.0.0.0/8", "172.16.0.0/12"})
	if err != nil {
		t.Fatalf("NewTrustedProxy: %v", err)
	}

	// Proxy chain: client -> 172.16.0.5 -> 10.0.0.1 -> server
	r := newRequest("10.0.0.1:443", "203.0.113.9, 172.16.0.5")
	if got := tp.Resolve(r); got != "203.0.113.9" {
		t.Errorf("Resolve = %q, want 203.0.113.9", got)
	}

	// An attacker prepended to their own entry in front of a real proxy hop. The
	// leftmost value is attacker-chosen; the hop the trusted proxy actually saw is not.
	r = newRequest("10.0.0.1:443", "6.6.6.6, 203.0.113.9, 172.16.0.5")
	if got := tp.Resolve(r); got != "203.0.113.9" {
		t.Errorf("Resolve = %q, want 203.0.113.9 (the attacker-prepended entry must lose)", got)
	}
}

// TestChainWalkStopsAtTheBound checks the walk cannot be made unbounded.
//
// The chain is attacker-supplied even when the first hop is trusted, so entries can be
// prepended without limit. Cost must stay constant.
func TestChainWalkStopsAtTheBound(t *testing.T) {
	tp, err := NewTrustedProxy([]string{"10.0.0.0/8"})
	if err != nil {
		t.Fatalf("NewTrustedProxy: %v", err)
	}

	var entries []string
	for i := 0; i < maxForwardedHops+10; i++ {
		entries = append(entries, "172.16.0.5")
	}
	r := newRequest("10.0.0.1:443", strings.Join(entries, ", "))

	got := tp.Resolve(r)
	if got == "" {
		t.Error("Resolve returned nothing; an over-long chain must fall back, not vanish")
	}
	if strings.Count(got, ".") != 3 {
		t.Errorf("Resolve = %q, want a single address", got)
	}
}

// TestMultipleHeaderLinesAreJoined checks RFC 7230's repeated-header form.
func TestMultipleHeaderLinesAreJoined(t *testing.T) {
	tp, err := NewTrustedProxy([]string{"10.0.0.0/8"})
	if err != nil {
		t.Fatalf("NewTrustedProxy: %v", err)
	}

	r := newRequest("10.0.0.1:443")
	r.Header.Add("X-Forwarded-For", "172.16.0.5")
	r.Header.Add("X-Forwarded-For", "203.0.113.9")

	if got := tp.Resolve(r); got != "203.0.113.9" {
		t.Errorf("Resolve = %q, want 203.0.113.9", got)
	}
}

// TestNonAddressEntriesAreNotTrusted checks a token the server cannot parse ends the
// chain rather than being skipped.
func TestNonAddressEntriesAreNotTrusted(t *testing.T) {
	tp, err := NewTrustedProxy([]string{"10.0.0.0/8"})
	if err != nil {
		t.Fatalf("NewTrustedProxy: %v", err)
	}

	for _, entry := range []string{"unknown", "_hidden", "not-an-ip"} {
		r := newRequest("10.0.0.1:443", entry+", 172.16.0.5")
		if got := tp.Resolve(r); got == entry {
			t.Errorf("entry %q was accepted as an address", entry)
		}
	}

	// A chain whose only entries are unparseable must not fall through to a value the
	// client supplied.
	r := newRequest("10.0.0.1:443", "unknown, _hidden")
	if got := tp.Resolve(r); strings.HasPrefix(got, "unknown") || got == "_hidden" {
		t.Errorf("Resolve = %q, want the peer address", got)
	}
}

// TestNoTrustedProxiesMeansHeadersAreIgnored checks the unconfigured default.
func TestNoTrustedProxiesMeansHeadersAreIgnored(t *testing.T) {
	tp, err := NewTrustedProxy(nil)
	if err != nil {
		t.Fatalf("NewTrustedProxy: %v", err)
	}

	r := newRequest("203.0.113.9:1234", "1.2.3.4")
	if got := tp.Resolve(r); got != "203.0.113.9" {
		t.Errorf("Resolve = %q, want the peer address", got)
	}
}

// TestBareProxyAddressIsAHostNotANetwork checks a single address is not widened.
//
// Reading "10.0.0.5" as the whole 10/8 would trust every host in the datacentre.
func TestBareProxyAddressIsAHostNotANetwork(t *testing.T) {
	tp, err := NewTrustedProxy([]string{"10.0.0.5"})
	if err != nil {
		t.Fatalf("NewTrustedProxy: %v", err)
	}

	if tp.Trusts("10.0.0.5:443") != true {
		t.Error("the configured proxy is not trusted")
	}
	if tp.Trusts("10.0.0.6:443") {
		t.Error("a neighbouring address is trusted; a bare address must be a single host")
	}
}

// TestInvalidProxyConfigIsAStartupError checks a typo fails loudly.
//
// Silently dropping an unparseable entry would leave a deployment believing its proxies
// are trusted while every forwarded header is ignored, which reads as rate limiting that
// stopped working.
func TestInvalidProxyConfigIsAStartupError(t *testing.T) {
	for _, entry := range []string{"not-a-cidr", "10.0.0.0/99", "999.1.1.1", "10.0.0.0/8/16"} {
		if _, err := NewTrustedProxy([]string{entry}); err == nil {
			t.Errorf("NewTrustedProxy accepted %q", entry)
		}
	}
}

// TestIPv6PeersAreParsed checks IPv6 literals, which contain colons.
func TestIPv6PeersAreParsed(t *testing.T) {
	tp, err := NewTrustedProxy([]string{"2001:db8::/32"})
	if err != nil {
		t.Fatalf("NewTrustedProxy: %v", err)
	}

	// The client address must be OUTSIDE the trusted range. Inside it, the chain walk
	// would correctly treat it as another proxy hop and keep looking.
	r := newRequest("[2001:db8::1]:443", "2001:db9:aaaa::9")
	if got := tp.Resolve(r); got != "2001:db9:aaaa::9" {
		t.Errorf("Resolve = %q, want 2001:db9:aaaa::9", got)
	}

	// Untrusted IPv6 peer must not have its header believed.
	r = newRequest("[2001:db9::1]:443", "2001:db8::9")
	if got := tp.Resolve(r); got != "2001:db9::1" {
		t.Errorf("Resolve = %q, want 2001:db9::1", got)
	}

	// A bracketed IPv6 peer with no header falls back to itself, brackets stripped.
	r = newRequest("[2001:db9::1]:443")
	if got := tp.Resolve(r); got != "2001:db9::1" {
		t.Errorf("Resolve = %q, want 2001:db9::1", got)
	}
}

// TestChainWalkSkipsTrustedIPv6Hops checks a real multi-hop IPv6 chain.
func TestChainWalkSkipsTrustedIPv6Hops(t *testing.T) {
	tp, err := NewTrustedProxy([]string{"2001:db8::/32"})
	if err != nil {
		t.Fatalf("NewTrustedProxy: %v", err)
	}

	// client -> 2001:db8::2 -> 2001:db8::1 -> server
	r := newRequest("[2001:db8::1]:443", "2001:db9::9, 2001:db8::2")
	if got := tp.Resolve(r); got != "2001:db9::9" {
		t.Errorf("Resolve = %q, want 2001:db9::9", got)
	}
}

// TestClientIPUsesTheResolvedContextValue checks the two halves agree.
func TestClientIPUsesTheResolvedContextValue(t *testing.T) {
	tp, err := NewTrustedProxy([]string{"10.0.0.0/8"})
	if err != nil {
		t.Fatalf("NewTrustedProxy: %v", err)
	}

	var got string
	handler := tp.Middleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		got = ClientIP(r)
	}))

	handler.ServeHTTP(httptest.NewRecorder(), newRequest("10.0.0.1:443", "203.0.113.9"))
	if got != "203.0.113.9" {
		t.Errorf("ClientIP = %q, want 203.0.113.9", got)
	}
}

// TestClientIPFallsBackToPeerWithoutMiddleware checks an unwired deployment still
// produces a stable key rather than an empty one.
func TestClientIPFallsBackToPeerWithoutMiddleware(t *testing.T) {
	r := newRequest("203.0.113.9:54321", "1.2.3.4")
	if got := ClientIP(r); got != "203.0.113.9" {
		t.Errorf("ClientIP = %q, want the peer address; the header must not be read", got)
	}
}

// TestClientIPNeverReadsTheHeaderDirectly is the regression guard.
//
// The old implementation took the leftmost X-Forwarded-For entry from any peer. This
// asserts it cannot come back, whatever the request looks like.
func TestClientIPNeverReadsTheHeaderDirectly(t *testing.T) {
	r := newRequest("203.0.113.9:54321", "1.2.3.4")
	if got := ClientIP(r); strings.Contains(got, "1.2.3.4") {
		t.Errorf("ClientIP = %q, which came from the header", got)
	}
}

// --- redirect guard -----------------------------------------------------------

// TestReturnPathAllowedRejectsOffsiteTargets covers the forms that pass a naive
// "starts with /" check and still navigate to an attacker's site.
func TestReturnPathAllowedRejectsOffsiteTargets(t *testing.T) {
	allowed := []string{"/", "/account", "/settings"}

	rejected := map[string]string{
		"absolute url":      "https://evil.example/",
		"protocol relative": "//evil.example/",
		"backslash host":    "/\\evil.example/",
		"mixed slash":       "/\\/evil.example/",
		"no leading slash":  "account/settings",
		"relative":          "settings",
		"empty":             "",
		"javascript":        "javascript:alert(1)",
		"newline":           "/account\nSet-Cookie: x=1",
		"nul byte":          "/account\x00",
		"del char":          "/account\x7f",
		"cr":                "/account\rLocation: https://evil.example",
	}

	for name, target := range rejected {
		t.Run(name, func(t *testing.T) {
			if ReturnPathAllowed(target, allowed) {
				t.Errorf("ReturnPathAllowed(%q) = true, want false", target)
			}
		})
	}
}

// TestReturnPathAllowedAcceptsRealPaths checks the guard is not so strict that legitimate
// navigation breaks.
func TestReturnPathAllowedAcceptsRealPaths(t *testing.T) {
	allowed := []string{"/", "/account", "/settings"}

	accepted := []string{
		"/",
		"/account",
		"/account/",
		"/account/security",
		"/settings/profile?tab=email",
	}

	for _, target := range accepted {
		if !ReturnPathAllowed(target, allowed) {
			t.Errorf("ReturnPathAllowed(%q) = false, want true", target)
		}
	}
}

// TestReturnPathAllowedWithNoPrefixesRejectsEverything checks the strictest setting.
func TestReturnPathAllowedWithNoPrefixesRejectsEverything(t *testing.T) {
	if ReturnPathAllowed("/account", nil) {
		t.Error("a path was allowed with no configured prefixes")
	}
}

// TestReturnPathAllowedIgnoresRelativePrefixes checks a misconfigured prefix cannot open
// a hole.
func TestReturnPathAllowedIgnoresRelativePrefixes(t *testing.T) {
	// A prefix that is not itself a path is skipped rather than treated as a match-all.
	if ReturnPathAllowed("/account", []string{"account"}) {
		t.Error("a relative prefix matched")
	}
}

// TestSafeReturnURLReturnsEmptyRatherThanTheInput is the API's safety property.
//
// Returning the rejected value would let a caller redirect to exactly what it was told
// not to.
func TestSafeReturnURLReturnsEmptyRatherThanTheInput(t *testing.T) {
	if got := SafeReturnURL("https://evil.example/", []string{"/"}); got != "" {
		t.Errorf("SafeReturnURL = %q, want empty", got)
	}
	if got := SafeReturnURL("/account", []string{"/"}); got != "/account" {
		t.Errorf("SafeReturnURL = %q, want /account", got)
	}
	// Backslash forms are normalised on the way out, so a caller that redirects to the
	// return value cannot reintroduce the protocol-relative form.
	if got := SafeReturnURL("/\\evil.example/", []string{"/"}); got != "" {
		t.Errorf("SafeReturnURL = %q, want empty", got)
	}
}

// --- CSRF ---------------------------------------------------------------------

// memoryCSRFStore is a CSRFStore with a controllable failure mode.
type memoryCSRFStore struct {
	mu     sync.Mutex
	tokens map[string]string
	setErr error
	getErr error
}

func newMemoryCSRFStore() *memoryCSRFStore {
	return &memoryCSRFStore{tokens: make(map[string]string)}
}

func (s *memoryCSRFStore) Set(ctx context.Context, key, value string, ttl time.Duration) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.setErr != nil {
		return s.setErr
	}
	s.tokens[key] = value
	return nil
}

func (s *memoryCSRFStore) Get(ctx context.Context, key string) (string, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.getErr != nil {
		return "", s.getErr
	}
	v, ok := s.tokens[key]
	if !ok {
		return "", errors.New("not found")
	}
	return v, nil
}

func (s *memoryCSRFStore) Delete(ctx context.Context, key string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.tokens, key)
	return nil
}

func (s *memoryCSRFStore) size() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return len(s.tokens)
}

// csrfTestRequest builds a GET that mints a token and returns the cookie value.
//
// The cookie is the token: issueToken generates one value and uses it for both the
// cookie and the store, so a form rendered from the context carries the same string the
// next request presents.
func csrfTestRequest(t *testing.T, c *CSRFMiddleware) (string, *httptest.ResponseRecorder) {
	t.Helper()
	rec := httptest.NewRecorder()

	var contextToken string
	handler := c.Protect(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		contextToken = GetCSRFToken(r.Context())
	}))
	handler.ServeHTTP(rec, newRequest("203.0.113.9:1234"))

	var cookieValue string
	for _, cookie := range rec.Result().Cookies() {
		if cookie.Name == "csrf_token" {
			cookieValue = cookie.Value
		}
	}
	if cookieValue == "" {
		t.Fatal("no csrf cookie was set")
	}
	// The template reads the context token and the browser sends the cookie. If these
	// ever diverge, every form on the page fails to submit.
	if contextToken != cookieValue {
		t.Errorf("context token %q and cookie %q differ", contextToken, cookieValue)
	}
	return cookieValue, rec
}

// csrfPost builds a POST carrying the cookie and token.
func csrfPost(cookieValue, token string) *http.Request {
	r := httptest.NewRequest(http.MethodPost, "/login", strings.NewReader("email=a@b.c"))
	r.RemoteAddr = "203.0.113.9:1234"
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	r.AddCookie(&http.Cookie{Name: "csrf_token", Value: cookieValue})
	if token != "" {
		r.PostForm = map[string][]string{"csrf_token": {token}}
	}
	return r
}

// TestCSRFRoundTripAcceptsAMintedToken is the happy path with a store in play.
func TestCSRFRoundTripAcceptsAMintedToken(t *testing.T) {
	store := newMemoryCSRFStore()
	c := NewCSRFMiddleware(CSRFConfig{CookieSecure: true, CookieSameSite: http.SameSiteLaxMode}, store)

	token, _ := csrfTestRequest(t, c)
	if token == "" {
		t.Fatal("no token was issued")
	}
	// The store must actually have been written. This is the regression: the store was
	// declared and threaded through but never called, so a second instance could not
	// validate a token the first one issued.
	if store.size() == 0 {
		t.Fatal("the store was never written to")
	}

	rec := httptest.NewRecorder()
	reached := false
	handler := c.Protect(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		reached = true
	}))
	handler.ServeHTTP(rec, csrfPost(token, token))

	if !reached {
		t.Errorf("request was refused (status %d); a valid token must pass", rec.Code)
	}
}

// TestCSRFRejectsATokenAbsentFromTheStore checks the store is authoritative.
func TestCSRFRejectsATokenAbsentFromTheStore(t *testing.T) {
	store := newMemoryCSRFStore()
	c := NewCSRFMiddleware(CSRFConfig{}, store)

	token, _ := csrfTestRequest(t, c)

	// Simulate the token ageing out — the cookie survives, the store entry does not.
	store.mu.Lock()
	store.tokens = make(map[string]string)
	store.mu.Unlock()

	rec := httptest.NewRecorder()
	reached := false
	handler := c.Protect(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		reached = true
	}))
	handler.ServeHTTP(rec, csrfPost(token, token))

	if reached {
		t.Error("a token absent from the store was accepted")
	}
	if rec.Code != http.StatusForbidden {
		t.Errorf("status = %d, want 403", rec.Code)
	}
}

// TestCSRFRejectsWhenTheStoreIsUnreachable checks it fails closed.
func TestCSRFRejectsWhenTheStoreIsUnreachable(t *testing.T) {
	store := newMemoryCSRFStore()
	c := NewCSRFMiddleware(CSRFConfig{}, store)

	token, _ := csrfTestRequest(t, c)

	store.mu.Lock()
	store.getErr = errors.New("redis unavailable")
	store.mu.Unlock()

	rec := httptest.NewRecorder()
	reached := false
	handler := c.Protect(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		reached = true
	}))
	handler.ServeHTTP(rec, csrfPost(token, token))

	if reached {
		t.Error("a request was accepted while the store was unreachable")
	}
}

// TestCSRFRefusesToIssueWhenTheStoreCannotWrite checks no unusable token is handed out.
func TestCSRFRefusesToIssueWhenTheStoreCannotWrite(t *testing.T) {
	store := newMemoryCSRFStore()
	store.setErr = errors.New("redis unavailable")
	c := NewCSRFMiddleware(CSRFConfig{}, store)

	rec := httptest.NewRecorder()
	handler := c.Protect(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	handler.ServeHTTP(rec, newRequest("203.0.113.9:1234"))

	// No cookie is better than a cookie whose every submission is refused.
	for _, cookie := range rec.Result().Cookies() {
		if cookie.Name == "csrf_token" {
			t.Error("a token cookie was issued that could never be validated")
		}
	}
}

// TestCSRFRequiresTheCookieToMatchTheSubmittedToken checks a token alone is not enough.
func TestCSRFRequiresTheCookieToMatchTheSubmittedToken(t *testing.T) {
	store := newMemoryCSRFStore()
	c := NewCSRFMiddleware(CSRFConfig{}, store)

	token, _ := csrfTestRequest(t, c)

	// Correct form token, but the cookie carries something else: a page that can
	// submit a form without the victim's cookie must not succeed.
	rec := httptest.NewRecorder()
	reached := false
	handler := c.Protect(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		reached = true
	}))
	handler.ServeHTTP(rec, csrfPost("a-different-token", token))

	if reached {
		t.Error("a mismatched cookie was accepted")
	}
}

// TestCSRFRefusesWithNoCookie checks the no-cookie case.
func TestCSRFRefusesWithNoCookie(t *testing.T) {
	store := newMemoryCSRFStore()
	c := NewCSRFMiddleware(CSRFConfig{}, store)

	r := httptest.NewRequest(http.MethodPost, "/login", nil)
	r.RemoteAddr = "203.0.113.9:1234"
	r.PostForm = map[string][]string{"csrf_token": {"whatever"}}

	rec := httptest.NewRecorder()
	reached := false
	handler := c.Protect(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		reached = true
	}))
	handler.ServeHTTP(rec, r)

	if reached {
		t.Error("a request with no cookie was accepted")
	}
}

// TestCSRFWithoutAStoreStillRequiresTheCookie checks the single-instance path.
func TestCSRFWithoutAStoreStillRequiresTheCookie(t *testing.T) {
	c := NewCSRFMiddleware(CSRFConfig{}, nil)

	token, _ := csrfTestRequest(t, c)

	rec := httptest.NewRecorder()
	reached := false
	handler := c.Protect(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		reached = true
	}))
	handler.ServeHTTP(rec, csrfPost(token, token))
	if !reached {
		t.Error("a valid single-instance submission was refused")
	}
}

// TestCSRFRejectsAMismatchedToken checks the comparison itself.
func TestCSRFRejectsAMismatchedToken(t *testing.T) {
	store := newMemoryCSRFStore()
	c := NewCSRFMiddleware(CSRFConfig{}, store)

	token, _ := csrfTestRequest(t, c)

	rec := httptest.NewRecorder()
	reached := false
	handler := c.Protect(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		reached = true
	}))
	handler.ServeHTTP(rec, csrfPost(token, "not-the-token"))

	if reached {
		t.Error("a wrong token was accepted")
	}
}

// TestSafeMethodsGetAToken checks GETs are not blocked.
func TestSafeMethodsGetAToken(t *testing.T) {
	c := NewCSRFMiddleware(CSRFConfig{}, newMemoryCSRFStore())

	for _, method := range []string{http.MethodGet, http.MethodHead, http.MethodOptions} {
		t.Run(method, func(t *testing.T) {
			rec := httptest.NewRecorder()
			reached := false
			handler := c.Protect(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				reached = true
			}))
			r := httptest.NewRequest(method, "/login", nil)
			r.RemoteAddr = "203.0.113.9:1234"
			handler.ServeHTTP(rec, r)

			if !reached {
				t.Errorf("%s was blocked", method)
			}
		})
	}
}

// TestCSRFResponseIsNotCacheable checks the 403 does not get cached.
func TestCSRFResponseIsNotCacheable(t *testing.T) {
	c := NewCSRFMiddleware(CSRFConfig{}, newMemoryCSRFStore())

	rec := httptest.NewRecorder()
	handler := c.Protect(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	handler.ServeHTTP(rec, csrfPost("x", "y"))

	if got := rec.Header().Get("Cache-Control"); got != "no-store" {
		t.Errorf("Cache-Control = %q, want no-store", got)
	}
}

// TestCSRFTokenIsRandom checks issued tokens differ.
func TestCSRFTokenIsRandom(t *testing.T) {
	c := NewCSRFMiddleware(CSRFConfig{}, newMemoryCSRFStore())

	seen := make(map[string]bool)
	for i := 0; i < 50; i++ {
		token, _ := csrfTestRequest(t, c)
		if token == "" {
			t.Fatal("empty token issued")
		}
		if seen[token] {
			t.Fatal("a token was repeated")
		}
		seen[token] = true
	}
}

// --- recover ------------------------------------------------------------------

// TestRecoverDoesNotLeakTheStack is the whole reason the file changed.
func TestRecoverDoesNotLeakTheStack(t *testing.T) {
	handler := RecoverMiddleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		panic("a secret internal detail")
	}))

	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, newRequest("203.0.113.9:1234"))

	body := rec.Body.String()

	if strings.Contains(body, "a secret internal detail") {
		t.Errorf("the panic value reached the client: %s", body)
	}
	for _, leak := range []string{"goroutine", ".go:", "middleware.", "runtime"} {
		if strings.Contains(body, leak) {
			t.Errorf("body contains %q:\n%s", leak, body)
		}
	}
	if rec.Code != http.StatusInternalServerError {
		t.Errorf("status = %d, want 500", rec.Code)
	}
}

// TestRecoverPassesThroughWithoutAPanic checks it is transparent normally.
func TestRecoverPassesThroughWithoutAPanic(t *testing.T) {
	handler := RecoverMiddleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusTeapot)
		_, _ = w.Write([]byte("brewing"))
	}))

	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, newRequest("203.0.113.9:1234"))

	if rec.Code != http.StatusTeapot {
		t.Errorf("status = %d, want 418", rec.Code)
	}
	if rec.Body.String() != "brewing" {
		t.Errorf("body = %q", rec.Body.String())
	}
}

// TestRecoverResponseIsNotCacheable checks the 500 carries the right headers.
func TestRecoverResponseIsNotCacheable(t *testing.T) {
	handler := RecoverMiddleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		panic("boom")
	}))

	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, newRequest("203.0.113.9:1234"))

	if got := rec.Header().Get("Cache-Control"); got != "no-store" {
		t.Errorf("Cache-Control = %q, want no-store", got)
	}
}

// --- status recorder ----------------------------------------------------------

// TestAccessLogRecordsAnImplicit200 checks a handler that only writes a body.
//
// Without the Write override the log records 0, which reads as an unrouted request.
func TestAccessLogRecordsAnImplicit200(t *testing.T) {
	logger := &captureLogger{}
	var recorded int

	handler := AccessLogMiddleware(logger)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte("body only"))
	}))

	handler.ServeHTTP(httptest.NewRecorder(), newRequest("203.0.113.9:1234"))

	recorded = logger.statusOf(t, "status")
	if recorded != http.StatusOK {
		t.Errorf("logged status = %d, want 200", recorded)
	}
}

// TestAccessLogKeepsTheFirstStatus checks a second WriteHeader does not rewrite history.
func TestAccessLogKeepsTheFirstStatus(t *testing.T) {
	logger := &captureLogger{}

	handler := AccessLogMiddleware(logger)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusCreated)
		w.WriteHeader(http.StatusTeapot)
	}))

	handler.ServeHTTP(httptest.NewRecorder(), newRequest("203.0.113.9:1234"))

	if got := logger.statusOf(t, "status"); got != http.StatusCreated {
		t.Errorf("logged status = %d, want 201 (the first one)", got)
	}
}

// TestStatusRecorderForwardsFlush keeps streaming endpoints working through the
// wrapper.
func TestStatusRecorderForwardsFlush(t *testing.T) {
	var flushed bool
	inner := &flushRecorder{flushed: &flushed}

	sr := &statusRecorder{ResponseWriter: inner}
	sr.Flush()

	if !flushed {
		t.Error("Flush did not reach the underlying writer")
	}
	if sr.status != http.StatusOK {
		t.Errorf("status = %d, want 200", sr.status)
	}
}

type flushRecorder struct {
	http.ResponseWriter
	flushed *bool
}

func (f *flushRecorder) Flush() { *f.flushed = true }

// TestStatusRecorderRejectsHijackOnAnUnsupportingWriter checks it errors rather than
// panicking.
func TestStatusRecorderRejectsHijackOnAnUnsupportingWriter(t *testing.T) {
	sr := &statusRecorder{ResponseWriter: httptest.NewRecorder()}
	if _, _, err := sr.Hijack(); err == nil {
		t.Error("Hijack on a non-hijackable writer should return an error")
	}
}

// captureLogger records log calls for assertions.
type captureLogger struct {
	mu   sync.Mutex
	args []any
}

func (l *captureLogger) Info(msg string, args ...any) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.args = append(l.args, args...)
}

// statusOf finds a named argument in the recorded call.
func (l *captureLogger) statusOf(t *testing.T, key string) int {
	t.Helper()
	l.mu.Lock()
	defer l.mu.Unlock()

	for i := 0; i+1 < len(l.args); i += 2 {
		if k, ok := l.args[i].(string); ok && k == key {
			if v, ok := l.args[i+1].(int); ok {
				return v
			}
			t.Fatalf("argument %q is %T, not int", key, l.args[i+1])
		}
	}
	t.Fatalf("no %q argument was logged", key)
	return 0
}
