package middleware

// Administrative access control. Requires a live session whose user carries the admin
// role, and answers with the correct shape for a browser or an API caller.

import (
	"context"
	"encoding/json"
	"net/http"
	"net/url"

	"oauth-server/internal/domain"
)

// RequireAdmin returns middleware that admits only requests from an administrator.
//
// It is deliberately layered on top of RequireSession rather than replacing it. The
// ordering matters: RequireSession answers a missing session with a redirect to
// /login, which is right for a browser and wrong for an API caller, and RequireAdmin
// needs a session before it can even ask whether the session is an admin's. Mounting
// them as RequireSession then RequireAdmin means each answers only the question it can
// answer.
//
// The role is read from the user row rather than from the session or a claim. A session
// does not carry is_admin, and it must not: the session outlives the flag. An
// administrator who is demoted keeps a valid session until it expires, and a check
// against a snapshot taken at login would let them act on that demotion for up to the
// session lifetime — which for an absolute-timeout session is hours.
func RequireAdmin(loginPath string, userRepo adminUserLookup) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			userID := GetUserID(r.Context())
			if userID == "" {
				writeUnauthenticated(w, r, loginPath)
				return
			}

			user, err := userRepo.GetByID(r.Context(), userID)
			if err != nil {
				// A session naming a user the database cannot resolve is not a
				// privilege condition, it is an inconsistent state, and it must not
				// fall through as though the caller were anonymous: an anonymous
				// caller is redirected to log in again, whereas this caller has
				// proved possession of a session and is owed a 500. Logging in again
				// would not help.
				AdminAuthFailure(w, r)
				return
			}

			// A disabled account is refused even if its session is still inside its
			// window. SessionMiddleware validates the session's own expiry and knows
			// nothing about the user's status, so an administrator disabled
			// mid-session would otherwise retain admin until the session lapsed.
			if user.DisabledAt != nil {
				writeForbidden(w, r)
				return
			}

			if !user.IsAdmin {
				// 403, not 404 and not 401. The session is valid, so telling the
				// caller to authenticate again would be a lie; and confirming that the
				// resource exists is acceptable here because these endpoints are not
				// enumerable by ID without already being an authenticated user.
				writeForbidden(w, r)
				return
			}

			next.ServeHTTP(w, r)
		})
	}
}

// adminUserLookup is the slice of the user repository RequireAdmin needs.
//
// An interface rather than *storage.UserRepo so this file does not import the storage
// layer, and so a test can present an administrator without a database. Only two
// fields of the user are read, which is what makes the narrow interface honest.
type adminUserLookup interface {
	GetByID(ctx context.Context, userID string) (*domain.User, error)
}

// AdminAuthFailure renders a failed administrative lookup.
//
// Split out so the failure is one obvious call site rather than an inline write: a
// lookup error that rendered as 401 would tell the operator to log in again, and the
// operator would log in again, and it would fail again.
func AdminAuthFailure(w http.ResponseWriter, r *http.Request) {
	if wantsJSON(r) {
		NoStoreJSONError(w, http.StatusInternalServerError, "server_error",
			"administrative request could not be authorised")
		return
	}
	http.Error(w, "administrative request could not be authorised", http.StatusInternalServerError)
}

// writeForbidden renders an authenticated-but-not-permitted answer.
func writeForbidden(w http.ResponseWriter, r *http.Request) {
	if wantsJSON(r) {
		// access_denied rather than invalid_token: the token is fine, the holder
		// simply is not allowed. invalid_token makes a client believe its session
		// expired and re-authenticate into the same refusal.
		NoStoreJSONError(w, http.StatusForbidden, "access_denied",
			"administrative access is required for this operation")
		return
	}
	noStore(w)
	http.Error(w, "administrative access is required for this operation", http.StatusForbidden)
}

// writeUnauthenticated renders a missing-session answer.
func writeUnauthenticated(w http.ResponseWriter, r *http.Request, loginPath string) {
	if wantsJSON(r) {
		NoStoreJSONError(w, http.StatusUnauthorized, "login_required", "session required")
		return
	}

	noStore(w)
	returnTo := r.URL.Path
	if r.URL.RawQuery != "" {
		returnTo += "?" + r.URL.RawQuery
	}
	http.Redirect(w, r, loginPath+"?return_to="+url.QueryEscape(returnTo), http.StatusFound)
}

// wantsJSON reports whether the caller is an API client rather than a browser.
//
// Same signal RequireSession uses. A browser navigating to an admin endpoint sends no
// Accept that names JSON, or sends one that does; an API caller either asks for JSON
// explicitly or sets X-Requested-With. Guessing wrong in either direction is a real
// bug — a browser served JSON sees raw text, and an API client follows a redirect into
// a login page — so the two must agree.
func wantsJSON(r *http.Request) bool {
	if r.Header.Get("X-Requested-With") != "" {
		return true
	}
	accept := r.Header.Get("Accept")
	return accept == "application/json" || accept == "application/problem+json"
}

// noStore sets the headers an administrative response must carry.
func noStore(w http.ResponseWriter) {
	h := w.Header()
	h.Set("Cache-Control", "no-store")
	h.Set("Pragma", "no-cache")
	h.Set("Expires", "0")
}

// NoStoreJSONError writes an OAuth-shaped error with no-store headers.
//
// Exported because the admin handlers write their own refusals — a handler that must
// act before the middleware can tell (a user-id that does not exist, for instance) needs
// the same rendering without reaching into this file's unexported helpers.
func NoStoreJSONError(w http.ResponseWriter, status int, code, description string) {
	noStore(w)
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(map[string]string{
		"error":             code,
		"error_description": description,
	})
}
