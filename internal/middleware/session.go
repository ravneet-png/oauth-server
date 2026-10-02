package middleware

// Session loading and the requirement that a request carry a valid session.

import (
	"context"
	"fmt"
	"net/http"
	"net/url"
	"time"

	"oauth-server/internal/domain"
	"oauth-server/internal/storage"
)

type sessionKeyType struct{}
type userIDKeyType struct{}

var sessionKey = sessionKeyType{}
var userIDKey = userIDKeyType{}

// SessionCookieName is the cookie carrying the browser session id.
//
// Exported because the login handler must set the cookie this middleware reads, and two
// literals that must agree is a login that works in development and fails in production
// after the name is changed in one place.
const SessionCookieName = "session"

// SetSessionCookie writes the session cookie.
//
// HttpOnly unconditionally: no script has a reason to read the session id, and a cookie
// that is readable makes every XSS a full account takeover. SameSite=Lax because the
// session must survive top-level navigations back from an identity provider, which
// SameSite=Strict would drop, while still not being attached to cross-site POSTs.
func SetSessionCookie(w http.ResponseWriter, sessionID string, expires time.Time, secure bool) {
	maxAge := int(time.Until(expires).Seconds())
	if maxAge < 1 {
		maxAge = 1
	}
	http.SetCookie(w, &http.Cookie{
		Name:     SessionCookieName,
		Value:    sessionID,
		Path:     "/",
		MaxAge:   maxAge,
		Secure:   secure,
		HttpOnly: true,
		SameSite: http.SameSiteLaxMode,
	})
}

// ClearSessionCookie expires the session cookie by setting a MaxAge of -1.
//
// The value is left empty deliberately: a logout that only shortens the lifetime leaves
// the id on the user's disk, where a borrowed laptop can read it.
func ClearSessionCookie(w http.ResponseWriter, secure bool) {
	http.SetCookie(w, &http.Cookie{
		Name:     SessionCookieName,
		Value:    "",
		Path:     "/",
		MaxAge:   -1,
		Secure:   secure,
		HttpOnly: true,
		SameSite: http.SameSiteLaxMode,
	})
}

// SessionMiddleware loads the session from the session cookie, refreshes its
// idle expiry, and puts user_id + session_id in the context.
//
// If the cookie is missing or the session is invalid/expired, the request
// continues without a session in context. Use RequireSession to enforce presence.
func SessionMiddleware(repo *storage.SessionRepo) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			cookie, err := r.Cookie(SessionCookieName)
			if err != nil {
				next.ServeHTTP(w, r)
				return
			}

			sessionID := cookie.Value
			if sessionID == "" {
				next.ServeHTTP(w, r)
				return
			}

			ctx := r.Context()
			session, err := repo.GetByID(ctx, sessionID)
			if err != nil {
				next.ServeHTTP(w, r)
				return
			}

			now := time.Now()
			if !session.IsValid(now) {
				next.ServeHTTP(w, r)
				return
			}

			// Refresh idle expiry if it's in the last 25% of its life
			// (matching the RefreshIdle policy in storage)
			remaining := session.RemainingIdle(now)
			if remaining > 0 && remaining < session.ExpiresAt.Sub(session.CreatedAt)/4 {
				newExpiry := now.Add(session.ExpiresAt.Sub(session.CreatedAt))
				if err := repo.RefreshIdle(ctx, sessionID, newExpiry); err == nil {
					session.ExpiresAt = newExpiry
				}
			}

			ctx = context.WithValue(ctx, sessionKey, session)
			ctx = context.WithValue(ctx, userIDKey, session.UserID)
			r = r.WithContext(ctx)

			next.ServeHTTP(w, r)
		})
	}
}

// GetSession returns the session from the context, or nil if none.
func GetSession(ctx context.Context) *domain.Session {
	if v := ctx.Value(sessionKey); v != nil {
		if s, ok := v.(*domain.Session); ok {
			return s
		}
	}
	return nil
}

// GetUserID returns the user ID from the context, or empty string if none.
func GetUserID(ctx context.Context) string {
	if v := ctx.Value(userIDKey); v != nil {
		if s, ok := v.(string); ok {
			return s
		}
	}
	return ""
}

// RequireSession returns middleware that enforces a valid session in the context.
//
// For API requests (Accept: application/json, or no Accept, or X-Requested-With),
// returns 401 with OAuth error format. For browser requests, redirects to /login
// with a return_to parameter pointing back to the original request.
func RequireSession(loginPath string) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if GetSession(r.Context()) == nil {
				// API client: check Accept header and X-Requested-With
				accept := r.Header.Get("Accept")
				if accept == "application/json" || r.Header.Get("X-Requested-With") != "" {
					w.Header().Set("Content-Type", "application/json; charset=utf-8")
					w.Header().Set("Cache-Control", "no-store")
					w.Header().Set("Pragma", "no-cache")
					w.WriteHeader(http.StatusUnauthorized)
					// Status is already committed, so a write failure cannot be reported.
					_, _ = fmt.Fprintf(w, `{"error":"invalid_token","error_description":"session required"}`)
					return
				}

				// Browser: redirect to login with return_to
				returnTo := r.URL.Path
				if r.URL.RawQuery != "" {
					returnTo += "?" + r.URL.RawQuery
				}
				http.Redirect(w, r, loginPath+"?return_to="+url.QueryEscape(returnTo), http.StatusFound)
				return
			}
			next.ServeHTTP(w, r)
		})
	}
}
