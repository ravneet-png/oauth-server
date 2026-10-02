package middleware

// Tests for administrative access control.
//
// The cases that matter here are the ones a session-based check gets wrong by
// omission: a demoted administrator, a disabled one, and a browser asking for admin
// access with no session. A guard that only tests "is the session valid" passes all of
// them.

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"oauth-server/internal/domain"
)

// fakeUserRepo presents administrators and non-administrators without a database.
//
// The domain.User fields read here are IsAdmin and DisabledAt, which is the whole
// decision. Everything else is left zero, because RequireAdmin must not depend on it.
type fakeUserRepo struct {
	users   map[string]*domain.User
	getErr  error
	getCall int
}

func newFakeUserRepo() *fakeUserRepo {
	return &fakeUserRepo{users: map[string]*domain.User{}}
}

func (f *fakeUserRepo) GetByID(ctx context.Context, userID string) (*domain.User, error) {
	f.getCall++
	if f.getErr != nil {
		return nil, f.getErr
	}
	u, ok := f.users[userID]
	if !ok {
		return nil, domain.ErrNotFound
	}
	return u, nil
}

func (f *fakeUserRepo) add(userID string, isAdmin bool) {
	f.users[userID] = &domain.User{UserID: userID, IsAdmin: isAdmin}
}

func (f *fakeUserRepo) disable(userID string) {
	f.users[userID] = &domain.User{
		UserID:     userID,
		IsAdmin:    true,
		DisabledAt: ptr(time.Now().UTC()),
	}
}

func ptr[T any](v T) *T { return &v }

// withSession builds a request carrying a session in context, as SessionMiddleware
// would.
func withSession(userID string) *http.Request {
	r := httptest.NewRequest(http.MethodDelete, "/users/u-target", nil)
	ctx := context.WithValue(r.Context(), userIDKey, userID)
	ctx = context.WithValue(ctx, sessionKey, &domain.Session{SessionID: "s-1", UserID: userID})
	return r.WithContext(ctx)
}

// adminRequest runs one request through RequireAdmin and reports the response.
func adminRequest(t *testing.T, repo adminUserLookup, r *http.Request) *httptest.ResponseRecorder {
	t.Helper()
	w := httptest.NewRecorder()
	RequireAdmin("/login", repo)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"ok":true}`))
	})).ServeHTTP(w, r)
	return w
}

func TestRequireAdminAdmitsAnAdministrator(t *testing.T) {
	repo := newFakeUserRepo()
	repo.add("admin-1", true)

	w := adminRequest(t, repo, withSession("admin-1"))

	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body %s", w.Code, w.Body)
	}
	if !strings.Contains(w.Body.String(), `"ok":true`) {
		t.Errorf("the wrapped handler did not run; body = %s", w.Body)
	}
}

func TestRequireAdminRefusesANonAdministrator(t *testing.T) {
	repo := newFakeUserRepo()
	repo.add("user-1", false)

	w := adminRequest(t, repo, withSession("user-1"))

	if w.Code != http.StatusForbidden {
		t.Errorf("status = %d, want 403", w.Code)
	}
	// 403 rather than 401: the session is valid, so telling the client to
	// authenticate again invites a re-authentication that ends in the same refusal.
	if strings.Contains(w.Body.String(), "login_required") {
		t.Errorf("a non-admin was told to log in again: %s", w.Body)
	}
}

func TestRequireAdminRefusesADemotedAdministratorOnTheSameLiveSession(t *testing.T) {
	// The bug this test exists for. The session is valid and was created while the
	// user was an administrator. If is_admin were snapshotted into the session at
	// login, this request would succeed until the session expired — hours, given an
	// absolute timeout — which is exactly how a demotion silently fails to take
	// effect.
	repo := newFakeUserRepo()
	repo.users["ex-admin"] = &domain.User{UserID: "ex-admin", IsAdmin: false}

	r := withSession("ex-admin")
	// A session that is unambiguously live.
	s := r.Context().Value(sessionKey).(*domain.Session)
	now := time.Now()
	s.CreatedAt = now.Add(-time.Minute)
	s.ExpiresAt = now.Add(time.Hour)

	w := adminRequest(t, repo, r)

	if w.Code != http.StatusForbidden {
		t.Errorf("status = %d, want 403; a demoted administrator kept admin access", w.Code)
	}
}

func TestRequireAdminRefusesADisabledAdministrator(t *testing.T) {
	// SessionMiddleware checks the session's own expiry and knows nothing about the
	// user's status, so a disabled admin with a live session would otherwise keep
	// access until the session lapsed.
	repo := newFakeUserRepo()
	repo.disable("disabled-admin")

	w := adminRequest(t, repo, withSession("disabled-admin"))

	if w.Code != http.StatusForbidden {
		t.Errorf("status = %d, want 403", w.Code)
	}
}

func TestRequireAdminRedirectsABrowserWithNoSession(t *testing.T) {
	repo := newFakeUserRepo()

	r := httptest.NewRequest(http.MethodDelete, "/users/u-target", nil)
	w := adminRequest(t, repo, r)

	if w.Code != http.StatusFound {
		t.Fatalf("status = %d, want 302 for a browser", w.Code)
	}
	loc := w.Header().Get("Location")
	if !strings.HasPrefix(loc, "/login?") {
		t.Errorf("Location = %q, want a redirect to /login", loc)
	}
	// return_to has to survive the round trip, or an admin who follows the redirect
	// lands on the login form and then has no way back to the page they wanted.
	if !strings.Contains(loc, "return_to=") {
		t.Errorf("Location = %q, want a return_to parameter", loc)
	}
	if !strings.Contains(loc, "%2Fusers%2Fu-target") {
		t.Errorf("Location = %q, want the encoded original path in return_to", loc)
	}
}

func TestRequireAdminAnswersAnAPICallerWithJSON(t *testing.T) {
	repo := newFakeUserRepo()
	repo.add("user-1", false)

	r := withSession("user-1")
	r.Header.Set("Accept", "application/json")

	w := adminRequest(t, repo, r)

	if w.Code != http.StatusForbidden {
		t.Fatalf("status = %d, want 403", w.Code)
	}
	// An API client must not receive an HTML login page: it would report a parse
	// error instead of the access_denied it needs to act on.
	var body map[string]string
	if err := json.Unmarshal(w.Body.Bytes(), &body); err != nil {
		t.Fatalf("body is not JSON: %v (%s)", err, w.Body)
	}
	if body["error"] != "access_denied" {
		t.Errorf("error = %q, want access_denied", body["error"])
	}
	// invalid_token would make the client re-authenticate into the same refusal.
	if body["error"] == "invalid_token" {
		t.Error("error = invalid_token; that tells a client its session expired")
	}
}

func TestRequireAdminAnswersAnXHRWithJSON(t *testing.T) {
	repo := newFakeUserRepo()
	repo.add("user-1", false)

	r := withSession("user-1")
	r.Header.Set("X-Requested-With", "XMLHttpRequest")

	w := adminRequest(t, repo, r)

	if w.Code != http.StatusForbidden {
		t.Fatalf("status = %d, want 403", w.Code)
	}
	var body map[string]string
	if err := json.Unmarshal(w.Body.Bytes(), &body); err != nil {
		t.Fatalf("body is not JSON: %v (%s)", err, w.Body)
	}
	if body["error"] != "access_denied" {
		t.Errorf("error = %q, want access_denied", body["error"])
	}
}

func TestRequireAdminMissingSessionForAnAPICallerIs401NotARedirect(t *testing.T) {
	repo := newFakeUserRepo()

	r := httptest.NewRequest(http.MethodDelete, "/users/u-target", nil)
	r.Header.Set("Accept", "application/json")

	w := adminRequest(t, repo, r)

	if w.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d, want 401", w.Code)
	}
	// A redirect here is the failure mode: an API client follows it, receives the
	// login form, and reports a parse error rather than a missing session.
	if loc := w.Header().Get("Location"); loc != "" {
		t.Errorf("Location = %q, want none for an API caller", loc)
	}
	var body map[string]string
	if err := json.Unmarshal(w.Body.Bytes(), &body); err != nil {
		t.Fatalf("body is not JSON: %v (%s)", err, w.Body)
	}
	if body["error"] != "login_required" {
		t.Errorf("error = %q, want login_required", body["error"])
	}
}

func TestRequireAdminLookupFailureIsNotTreatedAsUnauthenticated(t *testing.T) {
	// A database failure must not render as 401. 401 says "log in again", the
	// operator logs in again, and it fails again — while the real fault, which is
	// that the user table is unreachable, goes unmentioned.
	repo := newFakeUserRepo()
	repo.getErr = errors.New("pq: connection refused")

	r := withSession("admin-1")
	r.Header.Set("Accept", "application/json")

	w := adminRequest(t, repo, r)

	if w.Code != http.StatusInternalServerError {
		t.Errorf("status = %d, want 500", w.Code)
	}
	var body map[string]string
	if err := json.Unmarshal(w.Body.Bytes(), &body); err != nil {
		t.Fatalf("body is not JSON: %v (%s)", err, w.Body)
	}
	if body["error"] != "server_error" {
		t.Errorf("error = %q, want server_error", body["error"])
	}
	// The driver's message names infrastructure and must not be forwarded.
	if strings.Contains(w.Body.String(), "connection refused") {
		t.Errorf("database error text reached the client: %s", w.Body)
	}
}

func TestRequireAdminUnknownUserIsRefused(t *testing.T) {
	repo := newFakeUserRepo()
	// The session names a user with no row. Not found is not a privilege grant.
	r := withSession("ghost")
	r.Header.Set("Accept", "application/json")

	w := adminRequest(t, repo, r)

	if w.Code == http.StatusOK {
		t.Fatal("a session naming a nonexistent user was admitted")
	}
}

func TestRequireAdminRefusalsCarryNoStore(t *testing.T) {
	repo := newFakeUserRepo()
	repo.add("user-1", false)

	r := withSession("user-1")
	r.Header.Set("Accept", "application/json")
	w := adminRequest(t, repo, r)

	if got := w.Header().Get("Cache-Control"); got != "no-store" {
		t.Errorf("Cache-Control = %q, want no-store on an administrative refusal", got)
	}
}

func TestRequireAdminDoesNotCacheTheBrowserRedirect(t *testing.T) {
	repo := newFakeUserRepo()

	r := httptest.NewRequest(http.MethodDelete, "/users/u-target", nil)
	w := adminRequest(t, repo, r)

	// The redirect carries return_to, which includes the target user id. A cached
	// redirect would serve one admin's target to the next browser through the cache.
	if got := w.Header().Get("Cache-Control"); got != "no-store" {
		t.Errorf("Cache-Control = %q, want no-store", got)
	}
}

func TestWantsJSONAgreesWithRequireSession(t *testing.T) {
	// The two must classify callers identically. If RequireAdmin sends JSON and
	// RequireSession redirects for the same request, the user is bounced between the
	// two with no explanation.
	jsonReq := httptest.NewRequest(http.MethodGet, "/", nil)
	jsonReq.Header.Set("Accept", "application/json")

	browserReq := httptest.NewRequest(http.MethodGet, "/", nil)
	browserReq.Header.Set("Accept", "text/html,application/xhtml+xml")

	if !wantsJSON(jsonReq) {
		t.Error("wantsJSON says an explicit JSON Accept is a browser")
	}
	if wantsJSON(browserReq) {
		t.Error("wantsJSON says a browser Accept is an API caller")
	}

	xhr := httptest.NewRequest(http.MethodGet, "/", nil)
	xhr.Header.Set("X-Requested-With", "fetch")
	if !wantsJSON(xhr) {
		t.Error("wantsJSON ignores X-Requested-With")
	}
}
