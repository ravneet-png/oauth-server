package integration

import (
	"net/http"
	"strings"
	"testing"
)

func TestResetPasswordUnknownTokenReturns401(t *testing.T) {
	e := newEnv(t)
	request, err := http.NewRequest(http.MethodPost, e.url("/reset-password"), strings.NewReader(
		`{"token":"not-a-reset-token","password":"long-enough-new-password"}`,
	))
	if err != nil {
		t.Fatalf("new request: %v", err)
	}
	request.Header.Set("Content-Type", "application/json")
	response := e.do(request)
	if response.StatusCode != http.StatusUnauthorized {
		t.Fatalf("status = %d, want 401; body = %s", response.StatusCode, body(t, response))
	}
	var out struct {
		Error string `json:"error"`
	}
	decodeJSON(t, response, &out)
	if out.Error != "invalid_token" {
		t.Errorf("error = %q, want invalid_token", out.Error)
	}
}

func TestUserInfoInvalidBearerTokenReturns401Challenge(t *testing.T) {
	e := newEnv(t)
	response := e.getBearer("/userinfo", "not-an-access-token")
	if response.StatusCode != http.StatusUnauthorized {
		t.Fatalf("status = %d, want 401; body = %s", response.StatusCode, body(t, response))
	}
	challenge := response.Header.Get("WWW-Authenticate")
	if !strings.Contains(challenge, `error="invalid_token"`) {
		t.Errorf("WWW-Authenticate = %q, want invalid_token bearer challenge", challenge)
	}
}
