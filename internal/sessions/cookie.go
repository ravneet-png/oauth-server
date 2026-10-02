package sessions

// Cookie helpers for session and auth request cookies.

import (
	"net/http"
	"time"
)

// SessionCookieName is the name of the session cookie.
const SessionCookieName = "session"

// AuthRequestCookieName is the name of the auth request cookie.
const AuthRequestCookieName = "auth_request"

// SetSessionCookie sets the session cookie on the response.
//
// HttpOnly; Secure; SameSite=Lax; Path=/; maxAge as provided.
func SetSessionCookie(w http.ResponseWriter, sessionID string, maxAge time.Duration) {
	cookie := &http.Cookie{
		Name:     SessionCookieName,
		Value:    sessionID,
		Path:     "/",
		MaxAge:   int(maxAge.Seconds()),
		Secure:   true,
		HttpOnly: true,
		SameSite: http.SameSiteLaxMode,
	}
	http.SetCookie(w, cookie)
}

// SetAuthRequestCookie sets the auth request cookie on the response.
//
// HttpOnly; Secure; SameSite=Lax; Path=/; Max-Age=900 (15 min).
func SetAuthRequestCookie(w http.ResponseWriter, authRequestID string) {
	cookie := &http.Cookie{
		Name:     AuthRequestCookieName,
		Value:    authRequestID,
		Path:     "/",
		MaxAge:   900,
		Secure:   true,
		HttpOnly: true,
		SameSite: http.SameSiteLaxMode,
	}
	http.SetCookie(w, cookie)
}

// ClearCookie removes a cookie by setting it to expired.
func ClearCookie(w http.ResponseWriter, name string) {
	cookie := &http.Cookie{
		Name:     name,
		Value:    "",
		Path:     "/",
		MaxAge:   -1,
		Secure:   true,
		HttpOnly: true,
		SameSite: http.SameSiteLaxMode,
	}
	http.SetCookie(w, cookie)
}

// GetCookie retrieves a cookie value from the request, or empty string.
func GetCookie(r *http.Request, name string) string {
	cookie, err := r.Cookie(name)
	if err != nil {
		return ""
	}
	return cookie.Value
}

// ClearSessionCookie clears the session cookie.
func ClearSessionCookie(w http.ResponseWriter) {
	ClearCookie(w, SessionCookieName)
}

// ClearAuthRequestCookie clears the auth request cookie.
func ClearAuthRequestCookie(w http.ResponseWriter) {
	ClearCookie(w, AuthRequestCookieName)
}
