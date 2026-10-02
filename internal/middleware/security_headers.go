package middleware

// Response security headers.

import (
	"net/http"
)

// SecurityHeadersMiddleware adds the standard security headers.
//
// HSTS: only when the request is HTTPS, max-age 1 year, include subdomains,
// preload. The max-age is intentionally not configurable: a shorter value
// weakens the guarantee and the header exists to make HTTPS the only path.
//
// X-Frame-Options: DENY — this server must never be framed.
//
// X-Content-Type-Options: nosniff — prevents MIME sniffing.
//
// Referrer-Policy: no-referrer — no referrer sent on navigation away.
//
// Permissions-Policy: minimal set, no sensors, no camera, no microphone,
// no geolocation. The server does not need any browser features.
func SecurityHeadersMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// HSTS only on HTTPS
		if r.TLS != nil {
			w.Header().Set("Strict-Transport-Security", "max-age=31536000; includeSubDomains; preload")
		}

		w.Header().Set("X-Frame-Options", "DENY")
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("Referrer-Policy", "no-referrer")
		w.Header().Set("Permissions-Policy", "accelerometer=(), camera=(), geolocation=(), gyroscope=(), magnetometer=(), microphone=(), payment=(), usb=()")

		next.ServeHTTP(w, r)
	})
}
