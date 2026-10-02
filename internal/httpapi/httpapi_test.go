package httpapi

import (
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"oauth-server/internal/domain"
	"oauth-server/internal/oautherr"
)

func TestTokenResponseAlwaysCarriesTokenType(t *testing.T) {
	w := httptest.NewRecorder()
	// A caller that forgets token_type is the case this guards: RFC 6749 section 5.1
	// makes it required even though every other field is optional.
	TokenResponse(w, http.StatusOK, map[string]any{"access_token": "x"})

	var body map[string]any
	if err := json.Unmarshal(w.Body.Bytes(), &body); err != nil {
		t.Fatalf("body is not JSON: %v", err)
	}
	if body["token_type"] != "Bearer" {
		t.Fatalf("token_type = %v, want Bearer", body["token_type"])
	}
	if body["access_token"] != "x" {
		t.Fatalf("access_token = %v, want x", body["access_token"])
	}
}

func TestTokenResponseOmitsAbsentFieldsRatherThanEmpty(t *testing.T) {
	w := httptest.NewRecorder()
	TokenResponse(w, http.StatusOK, map[string]any{"access_token": "x"})

	var body map[string]any
	if err := json.Unmarshal(w.Body.Bytes(), &body); err != nil {
		t.Fatalf("body is not JSON: %v", err)
	}
	// refresh_token and expires_in were not supplied, so they must not appear at all.
	for _, absent := range []string{"refresh_token", "expires_in", "scope"} {
		if _, present := body[absent]; present {
			t.Errorf("%s is present with an empty value; want omitted", absent)
		}
	}
}

func TestEveryJSONResponseCarriesNoStore(t *testing.T) {
	w := httptest.NewRecorder()
	JSON(w, http.StatusOK, map[string]string{"a": "b"})

	for header, want := range map[string]string{
		"Cache-Control": "no-store",
		"Pragma":        "no-cache",
	} {
		if got := w.Header().Get(header); got != want {
			t.Errorf("%s = %q, want %q", header, got, want)
		}
	}
}

func TestOAuthErrorOmitsSuppressedDescription(t *testing.T) {
	w := httptest.NewRecorder()
	// The suppression case: a description that exists internally but must not reach the
	// client. An empty error_description would still be a field the client displays.
	OAuthError(w, oautherr.New(domain.NewInvalidClient("secret was wrong")).SuppressDescription())

	var body map[string]any
	if err := json.Unmarshal(w.Body.Bytes(), &body); err != nil {
		t.Fatalf("body is not JSON: %v", err)
	}
	if _, present := body["error_description"]; present {
		t.Errorf("error_description leaked: %v", body["error_description"])
	}
	if body["error"] != domain.ErrCodeInvalidClient {
		t.Errorf("error = %v, want invalid_client", body["error"])
	}
}

func TestInvalidClientIs401WithChallenge(t *testing.T) {
	w := httptest.NewRecorder()
	OAuthError(w, oautherr.New(domain.NewInvalidClient("nope")))

	// RFC 6749 section 5.2: invalid_client is 401 with a challenge. A 400 makes
	// clients retry a credential failure as though it were an authorization problem.
	if w.Code != http.StatusUnauthorized {
		t.Errorf("status = %d, want 401", w.Code)
	}
	if got := w.Header().Get("WWW-Authenticate"); !strings.HasPrefix(got, "Basic ") {
		t.Errorf("WWW-Authenticate = %q, want a Basic challenge", got)
	}
}

func TestOtherErrorsAreNot401(t *testing.T) {
	for _, tc := range []struct {
		name string
		err  *oautherr.Error
		want int
	}{
		{"invalid_grant", oautherr.New(domain.NewInvalidGrant("expired")), http.StatusBadRequest},
		{"invalid_request", oautherr.New(domain.NewInvalidRequest("bad")), http.StatusBadRequest},
		{"server_error", oautherr.New(domain.NewServerError("boom")), http.StatusInternalServerError},
	} {
		t.Run(tc.name, func(t *testing.T) {
			w := httptest.NewRecorder()
			OAuthError(w, tc.err)

			if w.Code != tc.want {
				t.Errorf("status = %d, want %d", w.Code, tc.want)
			}
			if got := w.Header().Get("WWW-Authenticate"); got != "" {
				t.Errorf("WWW-Authenticate = %q, want none for a non-auth failure", got)
			}
		})
	}
}

func TestErrorFromCollapsesUnknownErrorsToServerError(t *testing.T) {
	// The internal-text leak: a database error whose message names a table or column
	// must not reach the client.
	w := httptest.NewRecorder()
	ErrorFrom(w, errors.New("pq: relation \"users_secret_column\" does not exist"))

	if w.Code != http.StatusInternalServerError {
		t.Errorf("status = %d, want 500", w.Code)
	}
	body := w.Body.String()
	if strings.Contains(body, "users_secret_column") {
		t.Errorf("internal error text reached the client: %s", body)
	}
}

func TestRedirectURIMatchesExact(t *testing.T) {
	const registered = "https://client.example.com/callback"

	accepted := []string{
		registered,
		"  https://client.example.com/callback  ", // surrounding whitespace only
	}
	for _, supplied := range accepted {
		if !RedirectURIMatchesExact(registered, supplied) {
			t.Errorf("RedirectURIMatchesExact(%q, %q) = false, want true", registered, supplied)
		}
	}

	// Each of these is a relaxation somebody writes to "fix" a client, and each is a
	// hole: the relaxed forms either address a different endpoint or a different origin.
	refused := []struct {
		name     string
		supplied string
	}{
		{"trailing slash", "https://client.example.com/callback/"},
		{"case difference in path", "https://client.example.com/CallBack"},
		{"explicit default port", "https://client.example.com:443/callback"},
		{"uppercase host", "https://CLIENT.example.com/callback"},
		{"path traversal", "https://client.example.com/callback/../other"},
		{"subdomain", "https://evil.client.example.com/callback"},
		{"empty", ""},
		{"prefix", "https://client.example.com/callback-evil"},
		{"percent encoding difference", "https://client.example.com/%63allback"},
	}
	for _, tc := range refused {
		t.Run(tc.name, func(t *testing.T) {
			if RedirectURIMatchesExact(registered, tc.supplied) {
				t.Errorf("RedirectURIMatchesExact(%q, %q) = true, want false", registered, tc.supplied)
			}
		})
	}
}

func TestRedirectURIValidRejectsUnusableTargets(t *testing.T) {
	// The open-redirect primitives. Each is absolute or nearly so, and each is refused
	// before any comparison happens.
	refused := []struct {
		name string
		uri  string
	}{
		{"relative", "/callback"},
		{"empty", ""},
		{"scheme only", "https://"},
		{"javascript", "javascript:alert(1)"},
		{"data", "data:text/html,<script>"},
		{"file", "file:///etc/passwd"},
		{"vbscript", "vbscript:msgbox"},
		{"control character", "https://example.com/cb\n"},
	}
	for _, tc := range refused {
		t.Run(tc.name, func(t *testing.T) {
			if err := RedirectURIValid(tc.uri); err == nil {
				t.Errorf("RedirectURIValid(%q) = nil, want an error", tc.uri)
			}
		})
	}

	if err := RedirectURIValid("https://client.example.com/cb"); err != nil {
		t.Errorf("RedirectURIValid on an ordinary https URI = %v, want nil", err)
	}
}

func TestRedirectURIValidAllowsRegisteredFragment(t *testing.T) {
	// RFC 6749 section 3.1.2 permits a fragment on the registered URI, and ErrorRedirectURL
	// has to preserve it rather than fold it into the query.
	if err := RedirectURIValid("https://client.example.com/cb#frag"); err != nil {
		t.Errorf("RedirectURIValid with a fragment = %v, want nil", err)
	}
}

func TestErrorRedirectURLKeepsFragmentInTheFragment(t *testing.T) {
	got, err := ErrorRedirectURL("https://client.example.com/cb#frag", "state-1",
		oautherr.New(domain.NewAccessDenied("nope")))
	if err != nil {
		t.Fatalf("ErrorRedirectURL: %v", err)
	}

	u, parseErr := url.Parse(got)
	if parseErr != nil {
		t.Fatalf("result does not parse: %v", parseErr)
	}
	if u.Fragment != "frag" {
		t.Errorf("fragment = %q, want frag", u.Fragment)
	}
	// "frag" appearing in the query would mean the client looks in the wrong place.
	if u.Query().Has("frag") {
		t.Errorf("fragment leaked into the query: %s", u.RawQuery)
	}
	if u.Query().Get("error") != domain.ErrCodeAccessDenied {
		t.Errorf("error = %q, want access_denied", u.Query().Get("error"))
	}
	if u.Query().Get("state") != "state-1" {
		t.Errorf("state = %q, want state-1", u.Query().Get("state"))
	}
}

func TestErrorRedirectURLDoesNotEchoEmptyState(t *testing.T) {
	got, err := ErrorRedirectURL("https://client.example.com/cb", "",
		oautherr.New(domain.NewAccessDenied("nope")))
	if err != nil {
		t.Fatalf("ErrorRedirectURL: %v", err)
	}
	u, parseErr := url.Parse(got)
	if parseErr != nil {
		t.Fatalf("result does not parse: %v", parseErr)
	}
	// A client comparing its state byte-for-byte treats absence and empty as different.
	if u.Query().Has("state") {
		t.Errorf("state present when none was sent: %s", u.RawQuery)
	}
}

func TestErrorRedirectURIRefusesEmptyTarget(t *testing.T) {
	// Redirecting to an empty or unparseable target with an error is the open-redirect
	// primitive this function exists to prevent, so it fails instead.
	if _, err := ErrorRedirectURL("", "s", oautherr.New(domain.NewAccessDenied("x"))); err == nil {
		t.Error("ErrorRedirectURL with an empty URI = nil error, want a refusal")
	}
}

func TestRedirectErrorRendersALocal500WhenTheTargetIsUnusable(t *testing.T) {
	w := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/authorize", nil)

	// Must not redirect. If it did, the error would be delivered to whatever the
	// browser resolves, which is precisely the attack.
	RedirectError(w, req, "", "s", oautherr.New(domain.NewAccessDenied("x")))

	if w.Code != http.StatusInternalServerError {
		t.Errorf("status = %d, want 500", w.Code)
	}
	if loc := w.Header().Get("Location"); loc != "" {
		t.Errorf("Location = %q, want none", loc)
	}
}

func TestSeeOtherNotFoundRedirect(t *testing.T) {
	w := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/login", nil)

	// 303 rather than 302: a 302 on a POST is resubmitted by several browsers on
	// refresh, which turns a one-time login form into a form that fires twice.
	SeeOther(w, req, "/")

	if w.Code != http.StatusSeeOther {
		t.Errorf("status = %d, want 303", w.Code)
	}
	if loc := w.Header().Get("Location"); loc != "/" {
		t.Errorf("Location = %q, want /", loc)
	}
	if got := w.Header().Get("Cache-Control"); got != "no-store" {
		t.Errorf("Cache-Control = %q, want no-store on a redirect that follows a login", got)
	}
}

func TestRetryAfterNeverZero(t *testing.T) {
	w := httptest.NewRecorder()
	// A Retry-After of 0 tells the client to retry immediately, so a limited client is
	// refused again and keeps trying.
	WithRetryAfter(w, 0)

	if got := w.Header().Get("Retry-After"); got != "1" {
		t.Errorf("Retry-After = %q, want 1", got)
	}

	w2 := httptest.NewRecorder()
	WithRetryAfter(w2, 42)
	if got := w2.Header().Get("Retry-After"); got != "42" {
		t.Errorf("Retry-After = %q, want 42", got)
	}
}

func TestMethodNotAllowedSetsAllow(t *testing.T) {
	w := httptest.NewRecorder()
	MethodNotAllowed(w, http.MethodGet, http.MethodPost)

	// RFC 9110 section 15.5.6: 405 for a known resource with the wrong verb.
	if w.Code != http.StatusMethodNotAllowed {
		t.Errorf("status = %d, want 405", w.Code)
	}
	if got := w.Header().Get("Allow"); got != "GET, POST" {
		t.Errorf("Allow = %q, want %q", got, "GET, POST")
	}

	// The body stays in the OAuth shape. Generic clients parse this body regardless of
	// status, and a 405 with an HTML body breaks them while the Allow header works.
	var body struct {
		Error string `json:"error"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &body); err != nil {
		t.Fatalf("body is not JSON: %v; %s", err, w.Body.String())
	}
	if body.Error != "invalid_request" {
		t.Errorf("error = %q, want invalid_request", body.Error)
	}
}

func TestGuardRejectsDuplicateParameters(t *testing.T) {
	g := NewGuard()
	req := httptest.NewRequest(http.MethodGet, "/token?scope=a&scope=b", nil)

	err := g.CheckQuery(req)
	if !errors.Is(err, ErrDuplicateParameter) {
		t.Fatalf("error = %v, want ErrDuplicateParameter", err)
	}
	if !strings.Contains(err.Error(), "scope") {
		t.Errorf("error %q does not name the offending parameter", err)
	}
}

func TestGuardRejectsOversizedValue(t *testing.T) {
	g := NewGuard()
	g.MaxLength = 16
	req := httptest.NewRequest(http.MethodGet, "/token?state="+strings.Repeat("x", 64), nil)

	if err := g.CheckQuery(req); !errors.Is(err, ErrParameterTooLong) {
		t.Fatalf("error = %v, want ErrParameterTooLong", err)
	}
}

func TestGuardRejectsUnexpectedParameterWhenRestricted(t *testing.T) {
	g := NewGuard().Only("grant_type", "code")
	req := httptest.NewRequest(http.MethodGet, "/token?grant_type=authorization_code&surprise=1", nil)

	if err := g.CheckQuery(req); err == nil {
		t.Fatal("error = nil, want a refusal for the unexpected parameter")
	}
}

func TestGuardAcceptsAWellFormedQuery(t *testing.T) {
	g := NewGuard().Only("grant_type", "code", "client_id")
	req := httptest.NewRequest(http.MethodGet,
		"/token?grant_type=authorization_code&code=abc&client_id=example", nil)

	if err := g.CheckQuery(req); err != nil {
		t.Errorf("CheckQuery = %v, want nil", err)
	}
}

func TestGuardRejectsOversizedBody(t *testing.T) {
	g := NewGuard()
	g.MaxFormMemory = 64
	body := strings.NewReader("grant_type=" + strings.Repeat("x", 512))
	req := httptest.NewRequest(http.MethodPost, "/token", body)
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	if err := g.CheckForm(req); !errors.Is(err, ErrParameterTooLong) {
		t.Fatalf("error = %v, want ErrParameterTooLong", err)
	}
}

func TestGuardAcceptsAWellFormedForm(t *testing.T) {
	g := NewGuard()
	body := strings.NewReader("grant_type=authorization_code&code=abc")
	req := httptest.NewRequest(http.MethodPost, "/token", body)
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	if err := g.CheckForm(req); err != nil {
		t.Errorf("CheckForm = %v, want nil", err)
	}
	if got := req.PostFormValue("code"); got != "abc" {
		t.Errorf("code = %q, want abc", got)
	}
}

func TestExtractRedirectURIPrefersToTheForm(t *testing.T) {
	body := strings.NewReader("redirect_uri=https%3A%2F%2Fclient.example.com%2Fcb")
	req := httptest.NewRequest(http.MethodPost, "/token", body)
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.URL.RawQuery = "redirect_uri=https%3A%2F%2Fclient.example.com%2Fcb"
	// Force the body to be parsed so PostFormValue sees it.
	if err := req.ParseForm(); err != nil {
		t.Fatalf("ParseForm: %v", err)
	}

	got, err := ExtractRedirectURI(req)
	if err != nil {
		t.Fatalf("ExtractRedirectURI: %v", err)
	}
	if got != "https://client.example.com/cb" {
		t.Errorf("redirect_uri = %q", got)
	}
}

func TestExtractRedirectURIRejectsDisagreeingCopies(t *testing.T) {
	// The same value in two places is acceptable; two different values is either a bug
	// or a proxy/server disagreement, and guessing which one wins is parametrised.
	body := strings.NewReader("redirect_uri=https%3A%2F%2Fa.example.com%2Fcb")
	req := httptest.NewRequest(http.MethodPost, "/token", body)
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.URL.RawQuery = "redirect_uri=https%3A%2F%2Fb.example.com%2Fcb"
	if err := req.ParseForm(); err != nil {
		t.Fatalf("ParseForm: %v", err)
	}

	if _, err := ExtractRedirectURI(req); !errors.Is(err, ErrDuplicateParameter) {
		t.Fatalf("error = %v, want ErrDuplicateParameter", err)
	}
}

func TestExtractRedirectURIFallsBackToTheQuery(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet,
		"/authorize?redirect_uri=https%3A%2F%2Fclient.example.com%2Fcb", nil)

	got, err := ExtractRedirectURI(req)
	if err != nil {
		t.Fatalf("ExtractRedirectURI: %v", err)
	}
	if got != "https://client.example.com/cb" {
		t.Errorf("redirect_uri = %q", got)
	}
}
