package handlers

import (
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"oauth-server/internal/ui"
)

func newPlaygroundTestDeps(t *testing.T) *Deps {
	t.Helper()
	renderer, err := ui.NewRenderer("https://auth.example.com")
	if err != nil {
		t.Fatalf("NewRenderer: %v", err)
	}
	return &Deps{
		Config:   &Config{Issuer: "https://auth.example.com", MinPasswordLen: 12},
		Renderer: renderer,
		Logger:   slog.New(slog.NewTextHandler(io.Discard, nil)),
	}
}

func TestHomeHandlerRendersDeveloperConsole(t *testing.T) {
	d := newPlaygroundTestDeps(t)
	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodGet, "/", nil)

	d.Home(w, r)

	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body = %s", w.Code, w.Body.String())
	}
	for _, want := range []string{"OAuth 2.1 Developer Console", "id=\"developer-console\"", "POST /par", "client_credentials"} {
		if !strings.Contains(w.Body.String(), want) {
			t.Errorf("home page does not contain %q", want)
		}
	}
}

func TestHomeHandlerRejectsWrongPathAndMethod(t *testing.T) {
	d := newPlaygroundTestDeps(t)

	wrongPath := httptest.NewRecorder()
	d.Home(wrongPath, httptest.NewRequest(http.MethodGet, "/not-home", nil))
	if wrongPath.Code != http.StatusNotFound {
		t.Errorf("wrong path status = %d, want 404", wrongPath.Code)
	}

	wrongMethod := httptest.NewRecorder()
	d.Home(wrongMethod, httptest.NewRequest(http.MethodPost, "/", nil))
	if wrongMethod.Code != http.StatusMethodNotAllowed {
		t.Errorf("wrong method status = %d, want 405", wrongMethod.Code)
	}
}

func TestCallbackHandlerPreservesExactIssuerAndResponseParameters(t *testing.T) {
	d := newPlaygroundTestDeps(t)
	d.Config.Issuer = "https://auth.example.com/"
	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodGet,
		"/callback?code=code-123&state=state-456&iss=https%3A%2F%2Fauth.example.com%2F", nil)

	d.Callback(w, r)

	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body = %s", w.Code, w.Body.String())
	}
	body := w.Body.String()
	for _, want := range []string{
		`data-issuer="https://auth.example.com/"`,
		`data-callback-url="https://auth.example.com/callback"`,
		`data-code="code-123"`,
		`data-state="state-456"`,
		`data-iss="https://auth.example.com/"`,
		`data-state-present="true"`,
		`data-iss-present="true"`,
		`data-response-valid="true"`,
	} {
		if !strings.Contains(body, want) {
			t.Errorf("callback output missing %q", want)
		}
	}
}

func TestCallbackHandlerMarksDuplicateParametersInvalid(t *testing.T) {
	d := newPlaygroundTestDeps(t)
	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodGet,
		"/callback?code=first&code=second&state=state-1&iss=https%3A%2F%2Fauth.example.com", nil)

	d.Callback(w, r)

	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", w.Code)
	}
	if !strings.Contains(w.Body.String(), `data-response-valid="false"`) {
		t.Error("duplicate code parameter was not marked invalid")
	}
}

func TestCallbackHandlerRejectsNonGet(t *testing.T) {
	d := newPlaygroundTestDeps(t)
	w := httptest.NewRecorder()
	d.Callback(w, httptest.NewRequest(http.MethodPost, "/callback", nil))
	if w.Code != http.StatusMethodNotAllowed {
		t.Errorf("status = %d, want 405", w.Code)
	}
}

func TestRecoveryPagesRenderAndForgotPasswordResponseIsUniform(t *testing.T) {
	d := newPlaygroundTestDeps(t)

	forgotPage := httptest.NewRecorder()
	d.ForgotPassword(forgotPage, httptest.NewRequest(http.MethodGet, "/forgot-password", nil))
	if forgotPage.Code != http.StatusOK || !strings.Contains(forgotPage.Body.String(), `id="forgot-password-form"`) {
		t.Fatalf("forgot-password page did not render: status=%d body=%s", forgotPage.Code, forgotPage.Body.String())
	}

	resetPage := httptest.NewRecorder()
	d.PasswordResetPage(resetPage, httptest.NewRequest(http.MethodGet, "/reset-password?token=one-time-token", nil))
	if resetPage.Code != http.StatusOK || !strings.Contains(resetPage.Body.String(), `data-reset-token="one-time-token"`) {
		t.Fatalf("password-reset page did not render token: status=%d body=%s", resetPage.Code, resetPage.Body.String())
	}

	request := httptest.NewRequest(http.MethodPost, "/forgot-password", strings.NewReader(`{"email":"unknown@example.com"}`))
	request.Header.Set("Content-Type", "application/json")
	forgotPost := httptest.NewRecorder()
	d.ForgotPassword(forgotPost, request)
	if forgotPost.Code != http.StatusAccepted {
		t.Fatalf("forgot-password status = %d, want 202; body=%s", forgotPost.Code, forgotPost.Body.String())
	}
	if !strings.Contains(forgotPost.Body.String(), "If that address has an account") {
		t.Errorf("forgot-password response is not the enumeration-safe message: %s", forgotPost.Body.String())
	}
}

func TestPasswordResetPageRejectsDuplicateTokens(t *testing.T) {
	d := newPlaygroundTestDeps(t)
	w := httptest.NewRecorder()
	d.PasswordResetPage(w, httptest.NewRequest(http.MethodGet, "/reset-password?token=one&token=two", nil))
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", w.Code)
	}
	if !strings.Contains(w.Body.String(), `data-reset-token=""`) {
		t.Error("duplicate reset tokens were not rejected")
	}
}

func TestPARAndIntrospectionRejectDuplicateFormParameters(t *testing.T) {
	for _, tc := range []struct {
		name    string
		handler http.HandlerFunc
		body    string
	}{
		{"par", (&Deps{}).PAR, "client_id=client-a&client_id=client-b"},
		{"introspection", (&Deps{}).Introspect, "token=token-a&token=token-b"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			w := httptest.NewRecorder()
			r := httptest.NewRequest(http.MethodPost, "/"+tc.name, strings.NewReader(tc.body))
			r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
			tc.handler(w, r)
			if w.Code != http.StatusBadRequest {
				t.Errorf("status = %d, want 400; body = %s", w.Code, w.Body.String())
			}
		})
	}
}
