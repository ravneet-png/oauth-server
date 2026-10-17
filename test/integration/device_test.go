// The device authorization grant (RFC 8628), end to end through the real router.
//
// The grant has two halves that must be tested together: the machine half at
// /device_authorization and /token, and the browser half at /device that a person
// drives to say yes or no. A test that only polled the token endpoint would pass
// against a server where nobody could ever approve anything, and a test that only
// rendered the page would pass against a server that never issued a token.

package integration

import (
	"context"
	"net/http"
	"net/url"
	"strings"
	"testing"

	"oauth-server/internal/domain"
	"oauth-server/test/fixtures"
)

// deviceGrant is the grant_type value from RFC 8628.
const deviceGrant = "urn:ietf:params:oauth:grant-type:device_code"

// deviceAuthorization mirrors the JSON the device authorization endpoint returns.
type deviceAuthorization struct {
	DeviceCode              string `json:"device_code"`
	UserCode                string `json:"user_code"`
	VerificationURI         string `json:"verification_uri"`
	VerificationURIComplete string `json:"verification_uri_complete"`
	ExpiresIn               int    `json:"expires_in"`
	Interval                int    `json:"interval"`
	Scope                   string `json:"scope"`
}

// newDeviceClient registers a public client that may use the device grant.
func newDeviceClient(t *testing.T, e *env, clientID string, scopes []string) *domain.Client {
	t.Helper()

	client := fixtures.PublicClient(clientID, "Device App", nil, []string{domain.GrantDeviceCode}, scopes)
	if err := e.App.Deps.Clients.Create(context.Background(), client); err != nil {
		t.Fatalf("create device client: %v", err)
	}
	return client
}

// signInBrowser establishes a session cookie in the env's jar by running a normal
// login. The device verification page needs a session, and this is the one way the
// suite produces one without reaching past the router.
func signInBrowser(t *testing.T, e *env, email, password string) {
	t.Helper()

	f := newConfidentialFlow(t, e, "device-login-app", "device-login-secret-value")
	f.start(t, e)
	f.signIn(t, e, email, password)
}

// deviceAuthorize requests a device authorization for client and returns the JSON.
func deviceAuthorize(t *testing.T, e *env, client *domain.Client, scope string) deviceAuthorization {
	t.Helper()

	form := url.Values{"client_id": {client.ClientID}}
	if scope != "" {
		form.Set("scope", scope)
	}
	resp := e.postForm("/device_authorization", form)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("device_authorization status = %d; body = %s", resp.StatusCode, body(t, resp))
	}

	var out deviceAuthorization
	decodeJSON(t, resp, &out)
	if out.DeviceCode == "" || out.UserCode == "" {
		t.Fatalf("device_authorization returned no codes: %s", body(t, resp))
	}
	return out
}

// pollDeviceOne drives one poll of the device grant and returns the raw response.
func pollDeviceOne(t *testing.T, e *env, client *domain.Client, deviceCode string) *response {
	t.Helper()

	return e.postForm("/token", url.Values{
		"grant_type":  {deviceGrant},
		"device_code": {deviceCode},
		"client_id":   {client.ClientID},
	})
}

// oauthErrCode decodes the error member of a failed token response.
func oauthErrCode(t *testing.T, resp *response) string {
	t.Helper()

	var oerr struct {
		Error string `json:"error"`
	}
	decodeJSON(t, resp, &oerr)
	return oerr.Error
}

// TestDeviceAuthorizationApprovalIssuesTokens walks the full grant: device asks, a
// logged-in browser approves, and the device's next poll yields a usable token set.
func TestDeviceAuthorizationApprovalIssuesTokens(t *testing.T) {
	e := newEnv(t)
	user := createUserWithPassword(t, e, "device-user-1", "device@example.test", "correct horse battery", true)

	dev := newDeviceClient(t, e, "device-app-1", []string{"openid", "profile"})
	signInBrowser(t, e, user.Email, "correct horse battery")

	auth := deviceAuthorize(t, e, dev, "openid profile")

	// The response must carry both codes and the two verification URIs. The complete
	// URI has to embed the user_code, or a QR scan lands on an empty entry form.
	//
	// The URIs are built from the configured issuer, not from the address the test
	// server happens to listen on, exactly as the discovery document is.
	if auth.VerificationURI != "http://localhost:8080/device" {
		t.Errorf("verification_uri = %q, want %q", auth.VerificationURI, "http://localhost:8080/device")
	}
	if !strings.HasPrefix(auth.VerificationURIComplete, "http://localhost:8080/device?user_code=") {
		t.Errorf("verification_uri_complete = %q, want it to carry user_code", auth.VerificationURIComplete)
	}
	if auth.ExpiresIn <= 0 || auth.Interval <= 0 {
		t.Errorf("expires_in/interval = %d/%d, want both positive", auth.ExpiresIn, auth.Interval)
	}
	if auth.Scope != "openid profile" {
		t.Errorf("scope = %q, want %q", auth.Scope, "openid profile")
	}

	// Before approval the device must be told to wait, not handed a token.
	pending := pollDeviceOne(t, e, dev, auth.DeviceCode)
	if pending.StatusCode != http.StatusBadRequest {
		t.Fatalf("pending poll status = %d, want 400; body = %s", pending.StatusCode, body(t, pending))
	}
	if code := oauthErrCode(t, pending); code != "authorization_pending" {
		t.Fatalf("pending poll error = %q, want authorization_pending", code)
	}

	// The browser scans the complete URI and is sent straight to the consent screen.
	page := e.get("/device?user_code=" + url.QueryEscape(auth.UserCode))
	if page.StatusCode != http.StatusOK {
		t.Fatalf("device consent page status = %d; body = %s", page.StatusCode, body(t, page))
	}
	if !strings.Contains(body(t, page), "Device App") {
		t.Errorf("consent page does not name the client: %s", body(t, page))
	}

	approve := e.postForm("/device", url.Values{
		"csrf_token": {hiddenInput(t, page, "csrf_token")},
		"user_code":  {auth.UserCode},
		"decision":   {"allow"},
	})
	if approve.StatusCode != http.StatusOK {
		t.Fatalf("approve status = %d; body = %s", approve.StatusCode, body(t, approve))
	}
	if !strings.Contains(body(t, approve), "is now connected") {
		t.Errorf("approval page did not confirm the connection: %s", body(t, approve))
	}

	// The next poll is the payoff: a real token set.
	granted := pollDeviceOne(t, e, dev, auth.DeviceCode)
	if granted.StatusCode != http.StatusOK {
		t.Fatalf("approved poll status = %d; body = %s", granted.StatusCode, body(t, granted))
	}
	var tokens tokenResponse
	decodeJSON(t, granted, &tokens)
	if tokens.AccessToken == "" || tokens.RefreshToken == "" {
		t.Fatalf("no access/refresh token in %s", body(t, granted))
	}
	if tokens.IDToken == "" {
		t.Error("openid was granted but no id_token was issued")
	}
	if tokens.Scope != "openid profile" {
		t.Errorf("granted scope = %q, want %q", tokens.Scope, "openid profile")
	}

	// The access token must identify the approver at /userinfo, which proves the
	// subject became the user who clicked approve and not the device.
	ui := e.getBearer("/userinfo", tokens.AccessToken)
	if ui.StatusCode != http.StatusOK {
		t.Fatalf("userinfo status = %d; body = %s", ui.StatusCode, body(t, ui))
	}
	var claims struct {
		Sub string `json:"sub"`
	}
	decodeJSON(t, ui, &claims)
	if claims.Sub != user.UserID {
		t.Errorf("userinfo sub = %q, want %q", claims.Sub, user.UserID)
	}

	// A device code is single use: the same code must not mint a second set.
	if again := pollDeviceOne(t, e, dev, auth.DeviceCode); again.StatusCode != http.StatusBadRequest ||
		oauthErrCode(t, again) != "invalid_grant" {
		t.Errorf("second poll = %d/%s, want 400/invalid_grant", again.StatusCode, oauthErrCode(t, again))
	}

	// The refresh token the device received must rotate like any other.
	refreshed := e.postForm("/token", url.Values{
		"grant_type":    {"refresh_token"},
		"refresh_token": {tokens.RefreshToken},
		"client_id":     {dev.ClientID},
	})
	if refreshed.StatusCode != http.StatusOK {
		t.Fatalf("refresh status = %d; body = %s", refreshed.StatusCode, body(t, refreshed))
	}
}

// TestDeviceAuthorizationDenialSurfacesToTheDevice covers the no-vote path.
func TestDeviceAuthorizationDenialSurfacesToTheDevice(t *testing.T) {
	e := newEnv(t)
	user := createUserWithPassword(t, e, "device-user-2", "deny@example.test", "correct horse battery", true)

	dev := newDeviceClient(t, e, "device-app-2", []string{"openid"})
	signInBrowser(t, e, user.Email, "correct horse battery")

	auth := deviceAuthorize(t, e, dev, "openid")

	page := e.get("/device?user_code=" + url.QueryEscape(auth.UserCode))
	if page.StatusCode != http.StatusOK {
		t.Fatalf("device consent page status = %d; body = %s", page.StatusCode, body(t, page))
	}

	deny := e.postForm("/device", url.Values{
		"csrf_token": {hiddenInput(t, page, "csrf_token")},
		"user_code":  {auth.UserCode},
		"decision":   {"deny"},
	})
	if deny.StatusCode != http.StatusOK {
		t.Fatalf("deny status = %d; body = %s", deny.StatusCode, body(t, deny))
	}
	if !strings.Contains(body(t, deny), "was denied") {
		t.Errorf("denial page did not confirm the refusal: %s", body(t, deny))
	}

	// access_denied is 400 on the token endpoint, unlike the 403 the authorize
	// endpoint uses; the device client branches on the RFC 8628 error code.
	poll := pollDeviceOne(t, e, dev, auth.DeviceCode)
	if poll.StatusCode != http.StatusBadRequest {
		t.Fatalf("denied poll status = %d, want 400; body = %s", poll.StatusCode, body(t, poll))
	}
	if code := oauthErrCode(t, poll); code != "access_denied" {
		t.Errorf("denied poll error = %q, want access_denied", code)
	}
}

// TestDeviceAuthorizationEnforcesThePollInterval checks that a second poll inside
// the advertised interval is refused with slow_down rather than answered.
func TestDeviceAuthorizationEnforcesThePollInterval(t *testing.T) {
	e := newEnv(t)
	dev := newDeviceClient(t, e, "device-app-3", []string{"openid"})

	auth := deviceAuthorize(t, e, dev, "openid")

	first := pollDeviceOne(t, e, dev, auth.DeviceCode)
	if first.StatusCode != http.StatusBadRequest || oauthErrCode(t, first) != "authorization_pending" {
		t.Fatalf("first poll = %d/%s, want 400/authorization_pending", first.StatusCode, oauthErrCode(t, first))
	}

	second := pollDeviceOne(t, e, dev, auth.DeviceCode)
	if second.StatusCode != http.StatusBadRequest {
		t.Fatalf("second poll status = %d, want 400; body = %s", second.StatusCode, body(t, second))
	}
	if code := oauthErrCode(t, second); code != "slow_down" {
		t.Errorf("second poll error = %q, want slow_down", code)
	}
}

// TestDeviceAuthorizationRejectsForeignClient checks that a device code is only
// redeemable by the client it was issued to.
func TestDeviceAuthorizationRejectsForeignClient(t *testing.T) {
	e := newEnv(t)
	issuer := newDeviceClient(t, e, "device-app-4a", []string{"openid"})
	other := newDeviceClient(t, e, "device-app-4b", []string{"openid"})

	auth := deviceAuthorize(t, e, issuer, "openid")

	poll := pollDeviceOne(t, e, other, auth.DeviceCode)
	if poll.StatusCode != http.StatusBadRequest {
		t.Fatalf("foreign poll status = %d, want 400; body = %s", poll.StatusCode, body(t, poll))
	}
	if code := oauthErrCode(t, poll); code != "invalid_grant" {
		t.Errorf("foreign poll error = %q, want invalid_grant", code)
	}
}

// TestDeviceAuthorizationUnknownCodeIsExpiredToken checks the reaped/unknown case,
// which RFC 8628 tells the client to treat as a dead code.
func TestDeviceAuthorizationUnknownCodeIsExpiredToken(t *testing.T) {
	e := newEnv(t)
	dev := newDeviceClient(t, e, "device-app-5", []string{"openid"})

	poll := pollDeviceOne(t, e, dev, "a-device-code-that-was-never-issued")
	if poll.StatusCode != http.StatusBadRequest {
		t.Fatalf("unknown code status = %d, want 400; body = %s", poll.StatusCode, body(t, poll))
	}
	if code := oauthErrCode(t, poll); code != "expired_token" {
		t.Errorf("unknown code error = %q, want expired_token", code)
	}
}

// TestDeviceAuthorizationRejectsClientWithoutTheGrant checks the registration check
// on the enrollment endpoint itself.
func TestDeviceAuthorizationRejectsClientWithoutTheGrant(t *testing.T) {
	e := newEnv(t)

	// A client registered only for authorization_code.
	client, secret := fixtures.ConfidentialClient(
		"web-only", "web-only-secret-value", "Web App",
		[]string{testRedirectURI}, []string{"authorization_code"}, []string{"openid"},
	)
	if err := e.App.Deps.Clients.Create(context.Background(), client); err != nil {
		t.Fatalf("create client: %v", err)
	}

	resp := e.postFormBasic("/device_authorization", url.Values{"scope": {"openid"}}, client.ClientID, secret)
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400; body = %s", resp.StatusCode, body(t, resp))
	}
	if code := oauthErrCode(t, resp); code != "unauthorized_client" {
		t.Errorf("error = %q, want unauthorized_client", code)
	}
}

// TestDevicePageRequiresASession checks that the verification page, the whole point
// of which is a human in the loop, cannot be reached anonymously.
func TestDevicePageRequiresASession(t *testing.T) {
	e := newEnv(t)

	resp := e.get("/device")
	if resp.StatusCode != http.StatusSeeOther {
		t.Fatalf("anonymous /device status = %d, want 303; body = %s", resp.StatusCode, body(t, resp))
	}
	if loc := location(t, resp); !strings.HasPrefix(loc, "/login") {
		t.Errorf("/device redirected to %q, want /login", loc)
	}
}
