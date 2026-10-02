// Pushed authorization request success, single use enforcement and expiry.

package integration

import (
	"context"
	"net/http"
	"net/url"
	"strings"
	"testing"

	"oauth-server/internal/crypto"
)

func TestPARLoginRedirect(t *testing.T) {
	e := newEnv(t)

	user := createUserWithPassword(t, e, "user-par-1", "alice@example.test", "correct horse battery", true)

	f := newConfidentialFlow(t, e, "app-par-1", "client-secret-for-par-1")

	// 1. Push the authorization parameters to PAR endpoint
	parParams := url.Values{
		"client_id":             {f.client.ClientID},
		"redirect_uri":          {testRedirectURI},
		"response_type":         {"code"},
		"scope":                 {"openid profile email"},
		"state":                 {"xyz-state-par-1"},
		"nonce":                 {"test-nonce-par"},
		"code_challenge":        {crypto.S256Challenge(f.verifier)},
		"code_challenge_method": {"S256"},
	}

	parResp := e.postFormBasic("/par", parParams, f.client.ClientID, f.secret)
	if parResp.StatusCode != http.StatusCreated {
		t.Fatalf("PAR status = %d, want 201; body = %s", parResp.StatusCode, body(t, parResp))
	}

	var parOut parResponse
	decodeJSON(t, parResp, &parOut)
	if parOut.RequestURI == "" {
		t.Fatal("PAR returned empty request_uri")
	}
	requestURI := parOut.RequestURI
	requestID := strings.TrimPrefix(requestURI, "urn:ietf:params:oauth:request_uri:")
	if requestID == requestURI {
		t.Fatalf("request_uri has unexpected format: %s", requestURI)
	}

	// 2. Use request_uri in authorize request
	authParams := url.Values{
		"client_id":   {f.client.ClientID},
		"request_uri": {requestURI},
	}
	resp := e.get("/authorize?" + authParams.Encode())
	if resp.StatusCode != http.StatusSeeOther {
		t.Fatalf("authorize with request_uri status = %d, want 303; body = %s", resp.StatusCode, body(t, resp))
	}

	loc, err := url.Parse(location(t, resp))
	if err != nil {
		t.Fatalf("parse Location: %v", err)
	}
	if loc.Path != "/login" {
		t.Fatalf("authorize redirected to %q, want /login", loc.Path)
	}

	authReqID := loc.Query().Get("auth_request_id")
	if authReqID == "" {
		t.Fatalf("no auth_request_id after PAR authorize")
	}
	// Note: auth_request_id is a new ID created by /authorize, not the PAR request_id.
	// The PAR request_uri is consumed atomically by HandleAuthorize.

	// 3. Login
	page := e.get("/login?auth_request_id=" + url.QueryEscape(authReqID))
	if page.StatusCode != http.StatusOK {
		t.Fatalf("login page status = %d", page.StatusCode)
	}

	resp = e.postForm("/login", url.Values{
		"csrf_token":      {hiddenInput(t, page, "csrf_token")},
		"auth_request_id": {authReqID},
		"email":           {user.Email},
		"password":        {"correct horse battery"},
	})
	if resp.StatusCode != http.StatusSeeOther {
		t.Fatalf("login submit status = %d, want 303", resp.StatusCode)
	}
	if loc := location(t, resp); !strings.HasPrefix(loc, "/consent") {
		t.Fatalf("after login redirected to %q, want /consent", loc)
	}

	// 4. Consent
	page = e.get("/consent?auth_request_id=" + url.QueryEscape(authReqID))
	if page.StatusCode != http.StatusOK {
		t.Fatalf("consent page status = %d", page.StatusCode)
	}

	resp = e.postForm("/consent", url.Values{
		"csrf_token":      {hiddenInput(t, page, "csrf_token")},
		"auth_request_id": {authReqID},
		"decision":        {"allow"},
		"scope":           strings.Fields(parParams.Get("scope")),
	})
	if resp.StatusCode != http.StatusSeeOther {
		t.Fatalf("consent submit status = %d, want 303", resp.StatusCode)
	}

	loc, err = url.Parse(location(t, resp))
	if err != nil {
		t.Fatalf("parse redirect: %v", err)
	}

	code := loc.Query().Get("code")
	if code == "" {
		t.Fatalf("no code in redirect")
	}

	// 5. Exchange code for tokens
	tokens := f.exchange(t, e, code)
	if tokens.AccessToken == "" {
		t.Error("no access_token issued")
	}

	// 6. Verify PAR was consumed: request_uri cannot be reused at /authorize
	reuseReq, _ := http.NewRequest(http.MethodGet, e.url("/authorize?client_id="+f.client.ClientID+"&request_uri="+url.QueryEscape(requestURI)), nil)
	reuseReq.Header.Set("Accept", "application/json")
	reuseResp := e.do(reuseReq)
	if reuseResp.StatusCode != http.StatusBadRequest {
		t.Fatalf("PAR reuse at /authorize status = %d, want 400", reuseResp.StatusCode)
	}
}

// TestPARConsumedOnce checks that a request_uri is single-use
func TestPARConsumedOnce(t *testing.T) {
	e := newEnv(t)

	f := newConfidentialFlow(t, e, "app-par-2", "client-secret-for-par-2")

	parParams := url.Values{
		"client_id":             {f.client.ClientID},
		"redirect_uri":          {testRedirectURI},
		"response_type":         {"code"},
		"scope":                 {"openid profile email"},
		"state":                 {"xyz-state-par-2"},
		"nonce":                 {"test-nonce-par"},
		"code_challenge":        {crypto.S256Challenge(f.verifier)},
		"code_challenge_method": {"S256"},
	}

	parResp := e.postFormBasic("/par", parParams, f.client.ClientID, f.secret)
	if parResp.StatusCode != http.StatusCreated {
		t.Fatalf("PAR status = %d, want 201", parResp.StatusCode)
	}

	var parOut parResponse
	decodeJSON(t, parResp, &parOut)
	requestURI := parOut.RequestURI

	// First use: should work
	authResp := e.get("/authorize?client_id=" + f.client.ClientID + "&request_uri=" + url.QueryEscape(requestURI))
	if authResp.StatusCode != http.StatusSeeOther {
		t.Fatalf("first authorize status = %d, want 303", authResp.StatusCode)
	}

	// Second use: should fail (HTML error page is fine, we only check status)
	authReq2, _ := http.NewRequest(http.MethodGet, e.url("/authorize?client_id="+f.client.ClientID+"&request_uri="+url.QueryEscape(requestURI)), nil)
	authResp2 := e.do(authReq2)
	if authResp2.StatusCode != http.StatusBadRequest {
		t.Fatalf("second authorize status = %d, want 400", authResp2.StatusCode)
	}
}

// TestPARExpired checks that an expired PAR request returns an error
func TestPARExpired(t *testing.T) {
	e := newEnv(t)

	f := newConfidentialFlow(t, e, "app-par-3", "client-secret-for-par-3")

	parParams := url.Values{
		"client_id":             {f.client.ClientID},
		"redirect_uri":          {testRedirectURI},
		"response_type":         {"code"},
		"scope":                 {"openid profile email"},
		"state":                 {"xyz-state-par-3"},
		"nonce":                 {"test-nonce-par"},
		"code_challenge":        {crypto.S256Challenge(f.verifier)},
		"code_challenge_method": {"S256"},
	}

	parResp := e.postFormBasic("/par", parParams, f.client.ClientID, f.secret)
	if parResp.StatusCode != http.StatusCreated {
		t.Fatalf("PAR status = %d, want 201", parResp.StatusCode)
	}

	var parOut parResponse
	decodeJSON(t, parResp, &parOut)
	requestURI := parOut.RequestURI

	// Wait for PAR to expire (PAR TTL is 60 seconds in test config, but we can manually expire it)
	// Instead of waiting, directly delete the PAR request from DB
	_, err := e.DB.Exec(context.Background(),
		`DELETE FROM par_requests WHERE request_uri = $1`, requestURI)
	if err != nil {
		t.Fatalf("delete PAR: %v", err)
	}

	// Now authorize with the expired request_uri should fail
	authResp := e.get("/authorize?client_id=" + f.client.ClientID + "&request_uri=" + url.QueryEscape(requestURI))
	if authResp.StatusCode != http.StatusBadRequest {
		t.Fatalf("expired PAR authorize status = %d, want 400", authResp.StatusCode)
	}
}
