package middleware

// Renders an OAuth error into the correct response shape.

import (
	"context"
	"encoding/json"
	"net/http"

	"oauth-server/internal/domain"
)

// OAuthErrorHandler catches *domain.OAuthError from the request chain and
// formats it as the standard OAuth 2.1 error response.
//
// For machine endpoints (/token, /revoke, /introspect, /par, /userinfo, JWKS)
// the response is JSON with the standard fields. For /authorize the OAuthError
// is converted to redirect parameters by the handler, not here.
//
// The middleware also sets the mandatory no-cache headers.
func OAuthErrorHandler(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		defer func() {
			if rec := recover(); rec != nil {
				if oauthErr, ok := rec.(*domain.OAuthError); ok {
					writeOAuthError(w, oauthErr)
					return
				}
				// Not an OAuthError: re-panic for the recover middleware
				panic(rec)
			}
		}()

		// Wrap ResponseWriter to catch WriteHeader and inject headers before body
		rw := &oauthResponseWriter{ResponseWriter: w}
		next.ServeHTTP(rw, r)
	})
}

type oauthResponseWriter struct {
	http.ResponseWriter
	status  int
	headers http.Header
	written bool
}

func (rw *oauthResponseWriter) WriteHeader(status int) {
	rw.status = status
	if rw.headers == nil {
		rw.headers = make(http.Header)
	}
	for k, v := range rw.Header() {
		rw.headers[k] = v
	}
	rw.ResponseWriter.WriteHeader(status)
}

func (rw *oauthResponseWriter) Write(b []byte) (int, error) {
	if !rw.written {
		// First write: inject no-cache headers
		rw.Header().Set("Cache-Control", "no-store")
		rw.Header().Set("Pragma", "no-cache")
		rw.Header().Set("Content-Type", "application/json; charset=utf-8")
		rw.written = true
	}
	return rw.ResponseWriter.Write(b)
}

func writeOAuthError(w http.ResponseWriter, oe *domain.OAuthError) {
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Pragma", "no-cache")
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(oe.HTTPStatus)
	json.NewEncoder(w).Encode(map[string]string{
		"error":             oe.Code,
		"error_description": oe.Description,
		"error_uri":         oe.URI,
	})
}

// OAuthErrorFromContext extracts an OAuthError stored in the request context
// by a handler, and writes it. Returns true if an error was written.
func OAuthErrorFromContext(w http.ResponseWriter, r *http.Request) bool {
	if err, ok := r.Context().Value(oauthErrorKey).(*domain.OAuthError); ok {
		writeOAuthError(w, err)
		return true
	}
	return false
}

type oauthErrorKeyType struct{}

var oauthErrorKey = oauthErrorKeyType{}

// SetOAuthError stores an OAuthError in the request context for the error
// middleware to pick up.
func SetOAuthError(r *http.Request, err *domain.OAuthError) *http.Request {
	return r.WithContext(context.WithValue(r.Context(), oauthErrorKey, err))
}
