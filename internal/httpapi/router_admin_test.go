package httpapi

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"oauth-server/internal/middleware"
)

// adminProbe records that it ran, so a test can distinguish "the route reached the
// handler and the handler refused" from "the guard refused before the handler".
var adminProbeHit bool

func adminProbe() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		adminProbeHit = true
		w.WriteHeader(http.StatusNoContent)
	})
}

// adminChain builds a router with the admin gate present.
func adminChain() *Router {
	adminProbeHit = false
	return NewRouter(Handlers{
		EraseUser:  adminProbe(),
		RotateKeys: adminProbe(),
	}, MiddlewareConfig{
		Admin: func(next http.Handler) http.Handler {
			// Mirrors what middleware.RequireAdmin's refusal does. The router does
			// not set no-store itself: a gate is responsible for its own refusal, and
			// asserting on a stub that skips that would test the stub.
			return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				middleware.NoStoreJSONError(w, http.StatusForbidden, "access_denied",
					"administrative access is required for this operation")
			})
		},
	})
}

func TestAdminRoutesAreRegisteredBehindTheAdminGate(t *testing.T) {
	r := adminChain()

	for _, tc := range []struct {
		method string
		path   string
	}{
		{http.MethodDelete, "/users/u-1"},
		{http.MethodPost, "/keys/rotate"},
	} {
		w := httptest.NewRecorder()
		req := httptest.NewRequest(tc.method, tc.path, nil)
		r.ServeHTTP(w, req)

		if w.Code != http.StatusForbidden {
			t.Errorf("%s %s: status = %d, want 403 from the admin gate", tc.method, tc.path, w.Code)
		}
		if adminProbeHit {
			t.Errorf("%s %s: the handler ran, so the gate did not protect it", tc.method, tc.path)
		}
	}
}

func TestAdminRoutesFailClosedWhenNoGateIsConfigured(t *testing.T) {
	// The case this defends against: a test harness constructs a router without
	// setting MiddlewareConfig.Admin, and the erasure endpoint is mounted with no
	// protection at all. It must instead refuse everything.
	adminProbeHit = false
	r := NewRouter(Handlers{
		EraseUser:  adminProbe(),
		RotateKeys: adminProbe(),
	}, MiddlewareConfig{})

	w := httptest.NewRecorder()
	r.ServeHTTP(w, httptest.NewRequest(http.MethodDelete, "/users/u-1", nil))

	if w.Code != http.StatusInternalServerError {
		t.Fatalf("status = %d, want 500 from the fail-closed guard", w.Code)
	}
	if adminProbeHit {
		t.Error("the erasure handler ran with no admin gate configured")
	}
	if !strings.Contains(w.Body.String(), "administrative access control is not configured") {
		t.Errorf("body = %s, want a message naming the missing control", w.Body)
	}
}

func TestAdminRoutesCarryNoStore(t *testing.T) {
	r := adminChain()

	w := httptest.NewRecorder()
	r.ServeHTTP(w, httptest.NewRequest(http.MethodDelete, "/users/u-1", nil))

	// The path segment is a user id, and an intermediary cache holding a response
	// keyed by it would serve one admin's erasure result to the next.
	if got := w.Header().Get("Cache-Control"); !strings.Contains(got, "no-store") {
		t.Errorf("Cache-Control = %q, want no-store", got)
	}
}

func TestAdminRoutesAreAbsentWhenNoHandlerIsSupplied(t *testing.T) {
	// No handler means no route, so a deployment that has not built the admin
	// handlers does not expose a path that 404s while claiming to exist.
	r := NewRouter(Handlers{}, MiddlewareConfig{})

	w := httptest.NewRecorder()
	r.ServeHTTP(w, httptest.NewRequest(http.MethodDelete, "/users/u-1", nil))

	if w.Code == http.StatusNoContent || adminProbeHit {
		t.Error("the erasure route responded as though it were implemented")
	}
}

func TestUnknownPathStillFallsThroughToNotFound(t *testing.T) {
	// The wildcard /users/{id} pattern must not swallow unrelated paths, or a typo in
	// an admin URL starts returning erasure semantics.
	r := NewRouter(Handlers{
		EraseUser: adminProbe(),
	}, MiddlewareConfig{})

	adminProbeHit = false
	w := httptest.NewRecorder()
	r.ServeHTTP(w, httptest.NewRequest(http.MethodDelete, "/user/u-1", nil))

	if adminProbeHit {
		t.Error("/user/u-1 reached the erasure handler")
	}
}
