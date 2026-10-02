package middleware

// Panic recovery.
//
// A panic must produce a 500 and nothing else. The stack trace goes to the log, where
// the operator who has to fix it can read it — never to the response, where it names
// internal packages, file paths and line numbers to whoever triggered it.

import (
	"log/slog"
	"net/http"
	"runtime/debug"
)

// RecoverMiddleware catches panics, logs the stack trace, and returns 500.
func RecoverMiddleware(next http.Handler) http.Handler {
	return RecoverMiddlewareWithLogger(slog.Default())(next)
}

// RecoverMiddlewareWithLogger is RecoverMiddleware with an explicit logger.
func RecoverMiddlewareWithLogger(log *slog.Logger) func(http.Handler) http.Handler {
	if log == nil {
		log = slog.Default()
	}

	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			// nolint:contextcheck // A deferred recovery closure reads the request's
			// context for the correlation id; it takes no parameters by construction.
			defer func() {
				rec := recover()
				if rec == nil {
					return
				}

				// Deliberately not logging the recovered value's own stack in the
				// response. It is logged here with the request's correlation id, so a
				// user reporting a failure gives the operator something to search for.
				log.Error("panic recovered",
					"error", rec,
					"method", r.Method,
					"path", r.URL.Path,
					"correlation_id", GetCorrelationID(r.Context()),
					"stack", string(debug.Stack()),
				)

				// A handler that already wrote a status and body cannot be corrected
				// here, but writing a 500 anyway is better than leaving the connection
				// with a truncated response: net/http logs the superfluous WriteHeader
				// and the client sees a complete body. The alternative — silently
				// returning — produces a response that hangs.
				writeServerError(w)
			}()
			next.ServeHTTP(w, r)
		})
	}
}

// writeServerError emits a 500 in the OAuth error shape.
//
// Used by several places that must not leak an internal failure reason, so the shape
// lives in one function: any code path producing a 500 produces the same body, and a
// caller cannot accidentally add a detail string.
func writeServerError(w http.ResponseWriter) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Pragma", "no-cache")
	w.WriteHeader(http.StatusInternalServerError)
	_, _ = w.Write([]byte(`{"error":"server_error","error_description":"internal server error"}`))
}
