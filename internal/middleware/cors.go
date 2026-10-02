package middleware

// CORS policies. Wildcard origins are never combined with credentials, and CORS is never applied to the authorization endpoint, which is a browser navigation.

import (
	"net/http"
)

// CorsPolicy is a named CORS configuration.
//
// The two policies cover all endpoints that need CORS: public endpoints that
// any origin may call (discovery, JWKS), and OAuth endpoints that must restrict
// to registered client origins.
type CorsPolicy string

const (
	// PolicyPublic is for discovery/JWKS: Allow-Origin: *, GET only.
	PolicyPublic CorsPolicy = "public"

	// PolicyOAuth is for /token, /revoke, /introspect, /par: origins from
	// registered client redirect_uris, POST, specific allowed headers.
	PolicyOAuth CorsPolicy = "oauth"
)

// CORSFor returns middleware that applies the named policy.
//
// The middleware is a no-op on OPTIONS (handled by the preflight handler
// below), and is explicitly skipped for /authorize because that endpoint is a
// top-level browser navigation, not an XHR/fetch. Adding CORS headers to a
// redirect confuses browsers and provides no benefit.
func CORSFor(policy CorsPolicy, clientOrigins func(*http.Request) []string) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			// Skip CORS entirely for the authorization endpoint.
			if r.URL.Path == "/authorize" {
				next.ServeHTTP(w, r)
				return
			}

			origin := r.Header.Get("Origin")
			if origin == "" {
				next.ServeHTTP(w, r)
				return
			}

			var allowOrigin string
			var allowMethods string
			var allowHeaders string

			switch policy {
			case PolicyPublic:
				allowOrigin = "*"
				allowMethods = "GET, OPTIONS"
				allowHeaders = ""

			case PolicyOAuth:
				// Origins come from registered client redirect_uris, resolved per-request
				// so that a newly registered client works immediately without reload.
				origins := clientOrigins(r)
				matched := false
				for _, o := range origins {
					if o == origin {
						matched = true
						allowOrigin = origin
						break
					}
				}
				if !matched {
					next.ServeHTTP(w, r)
					return
				}
				allowMethods = "POST, OPTIONS"
				allowHeaders = "Content-Type, Authorization"

			default:
				next.ServeHTTP(w, r)
				return
			}

			// Preflight
			if r.Method == http.MethodOptions {
				w.Header().Set("Access-Control-Allow-Origin", allowOrigin)
				w.Header().Set("Access-Control-Allow-Methods", allowMethods)
				if allowHeaders != "" {
					w.Header().Set("Access-Control-Allow-Headers", allowHeaders)
				}
				w.Header().Set("Access-Control-Max-Age", "86400")
				w.Header().Set("Vary", "Origin, Access-Control-Request-Method, Access-Control-Request-Headers")
				w.WriteHeader(http.StatusNoContent)
				return
			}

			// Actual request
			w.Header().Set("Access-Control-Allow-Origin", allowOrigin)
			if policy == PolicyOAuth {
				// Vary on Origin so caches don't serve a response with the wrong
				// Allow-Origin to a different caller.
				w.Header().Set("Vary", "Origin")
			}
			next.ServeHTTP(w, r)
		})
	}
}
