package ui

// Renderer tests.
//
// No HTTP server and no database: what matters here is that a page renders, that the
// security headers are present, and that caller-supplied values cannot inject markup or
// break out of an attribute. A full browser test belongs in test/integration.

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func newTestRenderer(t *testing.T) *Renderer {
	t.Helper()
	r, err := NewRenderer("https://auth.example.com")
	if err != nil {
		t.Fatalf("NewRenderer: %v", err)
	}
	return r
}

// TestEveryPageRenders walks the full page set.
//
// The reason this is a loop rather than individual tests: a template that references a
// field its page type does not have only fails at Execute time, for that one page, in
// production. Every page type exists to be rendered.
func TestEveryPageRenders(t *testing.T) {
	r := newTestRenderer(t)

	pages := []struct {
		name string
		data any
	}{
		{PageLogin, LoginData{
			Base:       Base{Nonce: "n1", CSRFToken: "c1", Title: "Sign in", RequestID: "r1"},
			Email:      "user@example.com",
			ClientName: "Example App",
			Scope:      []string{"openid", "email"},
			ClientID:   "client-1",
		}},
		{PageRegister, RegisterData{
			Base:           Base{Nonce: "n1", CSRFToken: "c1", Title: "Create account"},
			MinPasswordLen: 12,
		}},
		{PageConsent, ConsentData{
			Base:              Base{Nonce: "n1", CSRFToken: "c1", Title: "Authorize"},
			ClientName:        "Example App",
			ClientURI:         "https://example.com/",
			AuthRequestID:     "authreq-1",
			RequestedScopes:   []ScopeItem{{Name: "email", Title: "Your email address", Description: "Read your email"}},
			PreviouslyGranted: []string{"openid"},
		}},
		{PageMFAChallenge, MFAChallengeData{
			Base:                 Base{Nonce: "n1", CSRFToken: "c1", Title: "Two-factor authentication"},
			PendingID:            "pending-1",
			Email:                "u***@example.com",
			BackupCodesRemaining: 3,
		}},
		{PageMFAEnroll, MFAEnrollData{
			Base:            Base{Nonce: "n1", CSRFToken: "c1", Title: "Set up two-factor authentication"},
			Secret:          "JBSWY3DPEHPK3PXP",
			ProvisioningURI: "otpauth://totp/auth:user@example.com?secret=JBSWY3DPEHPK3PXP",
			BackupCodes:     []string{"AAAA-BBBB", "CCCC-DDDD"},
		}},
		{PageVerifyEmail, VerifyEmailData{
			Base:     Base{Nonce: "n1", Title: "Email confirmed"},
			Success:  true,
			LoginURL: "/login",
		}},
		{PageError, ErrorData{
			Base: Base{Nonce: "n1", Title: "Something went wrong", RequestID: "req-abc"},
			Code: "invalid_request",
		}},
		{PageLoggedOut, LoggedOutData{
			Base:     Base{Nonce: "n1", Title: "Signed out"},
			LoginURL: "/login",
		}},
		{PageUnauthorized, UnauthorizedData{
			Base:   Base{Nonce: "n1", Title: "Not allowed"},
			Reason: "Administrator access is required.",
		}},
		{PageHome, HomeData{
			Base:          Base{Nonce: "n1", CSRFToken: "c1", Title: "OAuth 2.1 Developer Console"},
			Issuer:        "http://localhost:8080",
			DemoClientID:  "demo-client",
			CallbackURL:   "http://localhost:8080/callback",
			ActiveKeyID:   "kid-1",
			Authenticated: true,
			UserID:        "user-1",
			UserEmail:     "alice@example.com",
			UserName:      "Alice",
		}},
		{PageCallback, CallbackData{
			Base:         Base{Nonce: "n1", Title: "OAuth 2.1 Callback & Token Inspector"},
			Issuer:       "http://localhost:8080",
			DemoClientID: "demo-client",
			CallbackURL:  "http://localhost:8080/callback",
			Code:         "code-123",
			State:        "xyz123",
			ReturnedIss:  "http://localhost:8080",
		}},
	}

	for _, tc := range pages {
		t.Run(tc.name, func(t *testing.T) {
			w := httptest.NewRecorder()
			if err := r.Render(w, tc.name, http.StatusOK, tc.data); err != nil {
				t.Fatalf("Render: %v", err)
			}
			if w.Code != http.StatusOK {
				t.Errorf("status = %d, want 200", w.Code)
			}
			body := w.Body.String()
			if !strings.Contains(body, "<!DOCTYPE html>") {
				t.Error("output is not an HTML document")
			}
			if !strings.Contains(body, "/assets/style.css") {
				t.Error("page does not link the stylesheet")
			}
			if strings.Contains(body, "{{") {
				t.Error("page contains unrendered template syntax")
			}
		})
	}
}

// TestRenderSetsSecurityHeaders checks the headers no handler should have to remember.
func TestRenderSetsSecurityHeaders(t *testing.T) {
	r := newTestRenderer(t)
	w := httptest.NewRecorder()

	err := r.Render(w, PageLogin, http.StatusOK, LoginData{
		Base: Base{Nonce: "testnonce", CSRFToken: "c", Title: "Sign in"},
	})
	if err != nil {
		t.Fatalf("Render: %v", err)
	}

	want := map[string]string{
		"Cache-Control":          "no-store",
		"Pragma":                 "no-cache",
		"X-Content-Type-Options": "nosniff",
		"Referrer-Policy":        "no-referrer",
		"X-Frame-Options":        "DENY",
		"Content-Type":           "text/html; charset=utf-8",
	}
	for header, expected := range want {
		if got := w.Header().Get(header); got != expected {
			t.Errorf("%s = %q, want %q", header, got, expected)
		}
	}
}

// TestCSPNonceIsUnique checks the per-response nonce, which is what makes an injected
// script unsourceable.
func TestCSPNonceIsUnique(t *testing.T) {
	seen := make(map[string]bool)
	for i := 0; i < 32; i++ {
		nonce, err := NewNonce()
		if err != nil {
			t.Fatalf("NewNonce: %v", err)
		}
		if len(nonce) < 20 {
			t.Errorf("nonce %q is too short to be unguessable", nonce)
		}
		if seen[nonce] {
			t.Fatalf("NewNonce repeated %q", nonce)
		}
		seen[nonce] = true
	}
}

// TestCSPMatchesTheRenderedNonce checks the policy and the page agree.
//
// If they diverge the page's own script is blocked by its own policy, which presents as
// a form that silently does nothing.
func TestCSPMatchesTheRenderedNonce(t *testing.T) {
	r := newTestRenderer(t)
	w := httptest.NewRecorder()

	err := r.Render(w, PageError, http.StatusOK, ErrorData{
		Base: Base{Nonce: "the-nonce-value", Title: "Error"},
		Code: "invalid_request",
	})
	if err != nil {
		t.Fatalf("Render: %v", err)
	}

	csp := w.Header().Get("Content-Security-Policy")
	if !strings.Contains(csp, "script-src 'nonce-the-nonce-value'") {
		t.Errorf("CSP does not carry the rendered nonce: %s", csp)
	}
}

// TestCSPLocksDownTheDangerousDirections checks the directives that matter here.
//
// base-uri stops a <base> tag rewriting every relative link; frame-ancestors stops a
// clickjacking overlay over the consent or password form; form-action stops a
// cross-origin form post from looking like a legitimate submission.
func TestCSPLocksDownTheDangerousDirections(t *testing.T) {
	r := newTestRenderer(t)
	w := httptest.NewRecorder()

	err := r.Render(w, PageConsent, http.StatusOK, ConsentData{
		Base: Base{Nonce: "n", Title: "Authorize"},
	})
	if err != nil {
		t.Fatalf("Render: %v", err)
	}

	csp := w.Header().Get("Content-Security-Policy")
	for _, directive := range []string{
		"default-src 'none'",
		"base-uri 'none'",
		"frame-ancestors 'none'",
		"form-action 'self'",
		"style-src 'self'",
	} {
		if !strings.Contains(csp, directive) {
			t.Errorf("CSP is missing %q: %s", directive, csp)
		}
	}
	// 'unsafe-inline' anywhere would defeat the nonce.
	if strings.Contains(csp, "unsafe-inline") {
		t.Errorf("CSP permits unsafe-inline: %s", csp)
	}
}

// TestCSRFTokenAppearsOnEveryPostPage checks the token is rendered where it is needed.
func TestCSRFTokenAppearsOnEveryPostPage(t *testing.T) {
	r := newTestRenderer(t)

	postPages := []struct {
		name string
		data any
	}{
		{PageLogin, LoginData{Base: Base{Nonce: "n", CSRFToken: "csrf-login"}}},
		{PageRegister, RegisterData{Base: Base{Nonce: "n", CSRFToken: "csrf-register"}}},
		{PageConsent, ConsentData{Base: Base{Nonce: "n", CSRFToken: "csrf-consent"}, AuthRequestID: "a"}},
		{PageMFAChallenge, MFAChallengeData{Base: Base{Nonce: "n", CSRFToken: "csrf-mfa"}, PendingID: "p"}},
		{PageMFAEnroll, MFAEnrollData{Base: Base{Nonce: "n", CSRFToken: "csrf-enroll"}}},
	}

	// The token value is checked as a pair with the field name, because a page with
	// the field but an empty value is the failure that actually happens.
	tokens := []string{"csrf-login", "csrf-register", "csrf-consent", "csrf-mfa", "csrf-enroll"}

	for i, tc := range postPages {
		t.Run(tc.name, func(t *testing.T) {
			w := httptest.NewRecorder()
			if err := r.Render(w, tc.name, http.StatusOK, tc.data); err != nil {
				t.Fatalf("Render: %v", err)
			}
			body := w.Body.String()
			if !strings.Contains(body, `name="csrf_token"`) {
				t.Error("page has no csrf_token field")
			}
			if !strings.Contains(body, tokens[i]) {
				t.Errorf("page does not carry the token value %q", tokens[i])
			}
		})
	}
}

// TestCallerSuppliedValuesAreEscaped checks a value that reached a page field cannot
// inject markup.
//
// Client names, scope titles and error text all ultimately originate from client
// registration data, which is attacker-chosen: anyone can register a client named
// "<script>...".
func TestCallerSuppliedValuesAreEscaped(t *testing.T) {
	r := newTestRenderer(t)

	hostile := `<script>alert(1)</script>`

	tests := []struct {
		name string
		page string
		data any
	}{
		{"client name", PageConsent, ConsentData{
			Base: Base{Nonce: "n", Title: "Authorize"}, ClientName: hostile,
		}},
		{"scope title", PageConsent, ConsentData{
			Base:            Base{Nonce: "n", Title: "Authorize"},
			RequestedScopes: []ScopeItem{{Title: hostile}},
		}},
		{"error message", PageLogin, LoginData{
			Base: Base{Nonce: "n", Title: "Sign in", Error: hostile},
		}},
		{"flash message", PageLogin, LoginData{
			Base: Base{Nonce: "n", Title: "Sign in", Flash: hostile},
		}},
		{"error code", PageError, ErrorData{
			Base: Base{Nonce: "n", Title: "Error"}, Code: hostile,
		}},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			w := httptest.NewRecorder()
			if err := r.Render(w, tc.page, http.StatusOK, tc.data); err != nil {
				t.Fatalf("Render: %v", err)
			}
			body := w.Body.String()
			if strings.Contains(body, "<script>alert(1)</script>") {
				t.Errorf("unescaped markup in output:\n%s", body)
			}
			if !strings.Contains(body, "&lt;script&gt;") {
				t.Errorf("expected escaped markup, got:\n%s", body)
			}
		})
	}
}

// TestURLFieldsCannotInjectAnAttribute checks a value landing inside href= or an
// attribute is escaped as markup, not merely as text.
func TestURLFieldsCannotInjectAnAttribute(t *testing.T) {
	r := newTestRenderer(t)
	w := httptest.NewRecorder()

	// A javascript: URL is the dangerous case: it is not markup, so plain text
	// escaping would leave it intact and the user could click it.
	err := r.Render(w, PageLoggedOut, http.StatusOK, LoggedOutData{
		Base:     Base{Nonce: "n", Title: "Signed out"},
		LoginURL: `javascript:alert(1)"`,
	})
	if err != nil {
		t.Fatalf("Render: %v", err)
	}

	body := w.Body.String()
	if strings.Contains(body, `href="javascript:`) {
		t.Errorf("javascript: URL survived into an href:\n%s", body)
	}
}

// TestRenderFailsWithoutWritingOnTemplateError checks a broken template produces an
// error rather than a half-written 200.
//
// A render that fails midway has already committed the status line and part of the
// body; the user sees a truncated page and no indication anything failed.
func TestRenderFailsWithoutWritingOnTemplateError(t *testing.T) {
	r := newTestRenderer(t)
	w := httptest.NewRecorder()

	err := r.Render(w, "no_such_page", http.StatusOK, LoginData{
		Base: Base{Nonce: "n", Title: "Sign in"},
	})
	if err == nil {
		t.Fatal("expected an error for an unknown page")
	}
	if w.Body.Len() != 0 {
		t.Errorf("body was written despite the failure: %q", w.Body.String())
	}
	if w.Code != http.StatusOK {
		// httptest defaults Code to 200 until WriteHeader is called, so this confirms
		// nothing was written.
		t.Logf("writer code = %d", w.Code)
	}
}

// TestRenderHonoursTheGivenStatus checks error pages carry their status.
func TestRenderHonoursTheGivenStatus(t *testing.T) {
	r := newTestRenderer(t)
	w := httptest.NewRecorder()

	err := r.Render(w, PageUnauthorized, http.StatusForbidden, UnauthorizedData{
		Base: Base{Nonce: "n", Title: "Not allowed"},
	})
	if err != nil {
		t.Fatalf("Render: %v", err)
	}
	if w.Code != http.StatusForbidden {
		t.Errorf("status = %d, want 403", w.Code)
	}
}

// TestCorrelationIDIsEchoed checks a user reporting a problem gives the operator a
// value to search for.
func TestCorrelationIDIsEchoed(t *testing.T) {
	r := newTestRenderer(t)
	w := httptest.NewRecorder()

	err := r.Render(w, PageError, http.StatusOK, ErrorData{
		Base: Base{Nonce: "n", Title: "Error", RequestID: "req-xyz"},
		Code: "invalid_request",
	})
	if err != nil {
		t.Fatalf("Render: %v", err)
	}
	if got := w.Header().Get("X-Correlation-ID"); got != "req-xyz" {
		t.Errorf("X-Correlation-ID = %q, want req-xyz", got)
	}
	if !strings.Contains(w.Body.String(), "req-xyz") {
		t.Error("reference id is not shown to the user")
	}
}

// TestNewRendererRequiresABaseURL checks construction validates its input.
func TestNewRendererRequiresABaseURL(t *testing.T) {
	if _, err := NewRenderer(""); err == nil {
		t.Error("NewRenderer accepted an empty base URL")
	}
}

// TestStaticAssetsAreServed checks the stylesheet the pages link is actually present.
//
// A missing asset is a 404 on every page and looks like a styling bug rather than a
// build problem, so it is worth pinning at startup-test level.
func TestStaticAssetsAreServed(t *testing.T) {
	fsys, err := StaticFS()
	if err != nil {
		t.Fatalf("StaticFS: %v", err)
	}
	f, err := fsys.Open("style.css")
	if err != nil {
		t.Fatalf("style.css is not in the embedded filesystem: %v", err)
	}
	defer f.Close()

	info, err := f.Stat()
	if err != nil {
		t.Fatalf("Stat: %v", err)
	}
	if info.Size() == 0 {
		t.Error("style.css is empty")
	}
}

// TestWritePlainSetsNoStore checks the non-HTML path gets the same caching guarantee.
func TestWritePlain(t *testing.T) {
	w := httptest.NewRecorder()
	WritePlain(w, http.StatusOK, "application/json; charset=utf-8", `{"ok":true}`)

	if got := w.Header().Get("Cache-Control"); got != "no-store" {
		t.Errorf("Cache-Control = %q, want no-store", got)
	}
	if got := w.Header().Get("Content-Type"); got != "application/json; charset=utf-8" {
		t.Errorf("Content-Type = %q", got)
	}
	if w.Body.String() != `{"ok":true}` {
		t.Errorf("body = %q", w.Body.String())
	}
}

// TestRenderPageRejectsANilRenderer checks the defensive path.
func TestRenderPageRejectsANilRenderer(t *testing.T) {
	w := httptest.NewRecorder()
	if err := RenderPage(w, nil, PageLogin, http.StatusOK, LoginData{}); err == nil {
		t.Error("RenderPage accepted a nil renderer")
	}
}
