package middleware

// Correlation identifiers and access logging.

import (
	"bufio"
	"context"
	"errors"
	"net"
	"net/http"
	"time"

	"github.com/google/uuid"
)

type correlationKeyType struct{}

var correlationKey = correlationKeyType{}

// CorrelationIDMiddleware injects X-Correlation-ID into the request context.
// If the incoming request has the header, it is validated and used; otherwise
// a new UUID is generated.
func CorrelationIDMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		cid := r.Header.Get("X-Correlation-ID")
		if cid == "" || !isValidUUID(cid) {
			cid = uuid.New().String()
		}
		r = r.WithContext(context.WithValue(r.Context(), correlationKey, cid))
		w.Header().Set("X-Correlation-ID", cid)
		next.ServeHTTP(w, r)
	})
}

// GetCorrelationID returns the correlation ID from the context, or empty string
// if none is set.
func GetCorrelationID(ctx context.Context) string {
	if v := ctx.Value(correlationKey); v != nil {
		if s, ok := v.(string); ok {
			return s
		}
	}
	return ""
}

// WithCorrelationID returns a new context with the correlation ID set.
func WithCorrelationID(ctx context.Context, cid string) context.Context {
	return context.WithValue(ctx, correlationKey, cid)
}

func isValidUUID(s string) bool {
	_, err := uuid.Parse(s)
	return err == nil
}

// AccessLogMiddleware logs each request with correlation ID, method, path, status, latency.
// Intended to wrap the entire server, not individual routes.
func AccessLogMiddleware(logger interface{ Info(string, ...any) }) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			start := time.Now()
			cid := GetCorrelationID(r.Context())

			rw := &statusRecorder{ResponseWriter: w, status: http.StatusOK}
			next.ServeHTTP(rw, r)

			duration := time.Since(start)
			logger.Info("http request",
				"correlation_id", cid,
				"method", r.Method,
				"path", r.URL.Path,
				"status", rw.status,
				"duration_ms", duration.Milliseconds(),
			)
		})
	}
}

// statusRecorder remembers the status code and nothing else.
//
// Implements Flusher and Hijacker because wrapping a ResponseWriter that does not
// forward those interfaces silently breaks streaming endpoints and WebSocket upgrades:
// net/http type-asserts the writer, and a wrapper that hides the methods makes the
// handler fall back to buffering or fail outright.
type statusRecorder struct {
	http.ResponseWriter
	status int
	// wrote reports whether WriteHeader has been called, so a second call does not
	// overwrite the first. net/http ignores the second, and recording it would make
	// the access log disagree with what the client received.
	wrote bool
}

func (sr *statusRecorder) WriteHeader(status int) {
	if !sr.wrote {
		sr.status = status
		sr.wrote = true
	}
	sr.ResponseWriter.WriteHeader(status)
}

// Write records an implicit 200.
//
// Called on the first Write without an explicit WriteHeader, which is how a handler
// that just writes a body signals success. Without this the log would report 0.
func (sr *statusRecorder) Write(b []byte) (int, error) {
	if !sr.wrote {
		sr.status = http.StatusOK
		sr.wrote = true
	}
	return sr.ResponseWriter.Write(b)
}

// Flush forwards to the underlying writer when it supports flushing.
//
// Records 200 when nothing else was written. A streaming handler that flushes headers
// before its first Write has, by net/http's semantics, already committed a 200 — so
// without this the access log reports 0 for every streaming endpoint.
func (sr *statusRecorder) Flush() {
	if !sr.wrote {
		sr.status = http.StatusOK
		sr.wrote = true
	}
	if f, ok := sr.ResponseWriter.(http.Flusher); ok {
		f.Flush()
	}
}

// Hijack forwards to the underlying writer when it supports hijacking.
func (sr *statusRecorder) Hijack() (net.Conn, *bufio.ReadWriter, error) {
	if h, ok := sr.ResponseWriter.(http.Hijacker); ok {
		return h.Hijack()
	}
	// Reported as an error rather than a panic: a handler that needs to hijack on a
	// server that cannot should get an error it can handle.
	return nil, nil, errors.New("middleware: underlying ResponseWriter does not support hijacking")
}
