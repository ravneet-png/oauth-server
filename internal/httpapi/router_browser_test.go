package httpapi

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

func routeProbe(name string) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("X-Test-Route", name)
		w.WriteHeader(http.StatusNoContent)
	})
}

func TestRecoveryPagesAndProtocolFlowsAreRoutedByMethod(t *testing.T) {
	csrfCalls := 0
	router := NewRouter(Handlers{
		PAR:            routeProbe("par"),
		Introspect:     routeProbe("introspect"),
		ForgotPassword: routeProbe("forgot-password"),
		PasswordReset:  routeProbe("reset-password-page"),
		ResetPassword:  routeProbe("reset-password-submit"),
	}, MiddlewareConfig{
		CSRF: func(next http.Handler) http.Handler {
			return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				csrfCalls++
				next.ServeHTTP(w, r)
			})
		},
	})

	tests := []struct {
		method string
		path   string
		want   string
	}{
		{http.MethodGet, "/forgot-password", "forgot-password"},
		{http.MethodPost, "/forgot-password", "forgot-password"},
		{http.MethodGet, "/reset-password?token=one-time", "reset-password-page"},
		{http.MethodPost, "/reset-password", "reset-password-submit"},
		{http.MethodPost, "/par", "par"},
		{http.MethodPost, "/introspect", "introspect"},
	}
	for _, tc := range tests {
		t.Run(tc.method+" "+tc.path, func(t *testing.T) {
			w := httptest.NewRecorder()
			router.ServeHTTP(w, httptest.NewRequest(tc.method, tc.path, nil))
			if w.Code != http.StatusNoContent {
				t.Fatalf("status = %d, want 204", w.Code)
			}
			if got := w.Header().Get("X-Test-Route"); got != tc.want {
				t.Errorf("route = %q, want %q", got, tc.want)
			}
		})
	}

	// Only browser page GETs are behind CSRF middleware. Their JSON API submissions,
	// PAR, and introspection remain machine endpoints and must not require a cookie token.
	if csrfCalls != 2 {
		t.Errorf("CSRF middleware ran %d times, want only the two recovery page GETs", csrfCalls)
	}
}
