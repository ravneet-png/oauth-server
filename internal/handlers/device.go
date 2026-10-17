package handlers

// POST /device_authorization — the device authorization endpoint (RFC 8628 section
// 3.1); GET and POST /device — the verification page a user opens on a second device
// to approve or deny a request.
//
// The two halves are secured very differently, on purpose. The endpoint is a machine
// endpoint: authenticated like /token, JSON in and JSON out, no session. The
// verification page is a browser page with a session and a CSRF token, because the
// whole security property of the grant is that a *user* is in the middle of it. A
// user_code that could be redeemed without a browser session would be a password
// printed on a screen.

import (
	"net/http"
	"net/url"

	"oauth-server/internal/domain"
	"oauth-server/internal/flows"
	"oauth-server/internal/httpapi"
	"oauth-server/internal/oautherr"
	"oauth-server/internal/ui"
)

// DeviceAuthorization handles the device authorization endpoint.
func (d *Deps) DeviceAuthorization(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		httpapi.MethodNotAllowed(w, http.MethodPost)
		return
	}
	// Parsed before client authentication, exactly as on /token: client_secret_post
	// carries its credential in this very form, so authenticating first would reject a
	// correctly formed request.
	if !parseForm(r) {
		httpapi.OAuthError(w, oautherr.Newf("invalid_request", "malformed request body"))
		return
	}

	client, err := d.ClientAuth.Authenticate(r.Context(), r)
	if err != nil {
		httpapi.OAuthError(w, oautherr.From(err).SuppressDescription())
		return
	}

	auth, err := flows.IssueDeviceAuthorization(
		r.Context(),
		client,
		scopes(stringParam(r, "scope")),
		d.DeviceCodes,
		d.Audit,
		d.Config.DeviceCodeTTL,
		d.Config.DeviceCodeInterval,
	)
	if err != nil {
		oauthErr := oautherr.From(err)
		if oauthErr.Code() == "server_error" {
			d.Logger.Error("device_authorization: issue failed",
				"client_id", client.ClientID,
				"error", err.Error(),
				"correlation_id", d.state(r).correlationID,
			)
		}
		httpapi.OAuthError(w, oauthErr)
		return
	}

	// verification_uri is where the user goes; verification_uri_complete carries the
	// code so a QR scan need not make the user type it. The complete form is assembled
	// here rather than in the flow because it is presentation, and it depends on the
	// endpoint this server actually advertises.
	verificationURI := d.Config.DeviceVerificationEndpoint
	fields := map[string]any{
		"device_code":               auth.DeviceCode,
		"user_code":                 auth.UserCode,
		"verification_uri":          verificationURI,
		"verification_uri_complete": verificationURI + "?user_code=" + url.QueryEscape(auth.UserCode),
		"expires_in":                auth.ExpiresIn,
		"interval":                  auth.Interval,
	}
	if len(auth.Scope) > 0 {
		fields["scope"] = domain.JoinScope(auth.Scope)
	}
	httpapi.JSON(w, http.StatusOK, fields)
}

// Device handles the verification page.
func (d *Deps) Device(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		d.deviceGet(w, r)
	case http.MethodPost:
		d.devicePost(w, r)
	default:
		httpapi.MethodNotAllowed(w, http.MethodGet, http.MethodPost)
	}
}

// deviceGet renders the entry form, or goes straight to the consent screen when a
// user_code arrived in the query.
//
// verification_uri_complete lands here with ?user_code=..., which is why a present
// code advances to the decision rather than forcing the user to retype what they just
// scanned. A code that does not resolve falls back to the entry form with a generic
// message instead of an error page: the user can look at their device again.
func (d *Deps) deviceGet(w http.ResponseWriter, r *http.Request) {
	if !d.state(r).hasSession() {
		// No session: send the browser through login. The device code is short lived
		// and the user still has it on the other screen, so losing the round trip to a
		// pre-login landing page costs nothing but a retype.
		httpapi.SeeOther(w, r, "/login")
		return
	}

	rawCode := stringParam(r, "user_code")
	if rawCode == "" {
		d.renderDeviceEntry(w, r, "", "")
		return
	}

	dc, client, ok := d.loadDeviceRequest(w, r, rawCode)
	if !ok {
		return
	}
	if dc == nil {
		d.renderDeviceEntry(w, r, rawCode, "That code is not valid, or it has expired.")
		return
	}
	if dc.IsApproved() {
		d.renderDeviceResult(w, r, ui.DeviceStageApproved, client.ClientName)
		return
	}
	d.renderDeviceConsent(w, r, dc, client)
}

// devicePost records the user's decision, or advances a submitted code to the consent
// screen.
func (d *Deps) devicePost(w http.ResponseWriter, r *http.Request) {
	if !parseForm(r) {
		d.renderDeviceEntry(w, r, "", "The form could not be read. Please try again.")
		return
	}
	st := d.state(r)
	if !st.hasSession() {
		httpapi.SeeOther(w, r, "/login")
		return
	}

	rawCode := stringParam(r, "user_code")
	if domain.NormalizeUserCode(rawCode) == "" {
		d.renderDeviceEntry(w, r, "", "Enter the code shown on your device.")
		return
	}

	dc, client, ok := d.loadDeviceRequest(w, r, rawCode)
	if !ok {
		return
	}
	if dc == nil {
		// Nothing is disambiguated: whether the code never existed, was mistyped,
		// lapsed or was already decided is not something a page a stranger can reach
		// should reveal.
		d.renderDeviceEntry(w, r, rawCode, "That code is not valid, or it has expired.")
		return
	}

	// An already-approved request is not an error. The user may have refreshed or
	// approved in another tab, and telling them so is more useful than re-asking.
	if dc.IsApproved() {
		d.renderDeviceResult(w, r, ui.DeviceStageApproved, client.ClientName)
		return
	}

	switch stringParam(r, "decision") {
	case "deny":
		if err := d.DeviceCodes.Deny(r.Context(), dc.DeviceCodeHash); err != nil {
			d.Logger.Error("device: deny", "error", err.Error(), "correlation_id", st.correlationID)
			d.renderError(w, r, http.StatusInternalServerError, "server_error")
			return
		}
		_ = d.AuditLog.DeviceDenied(r.Context(), st.auditRC(), st.userID, client.ClientID)
		d.renderDeviceResult(w, r, ui.DeviceStageDenied, client.ClientName)

	case "allow":
		d.deviceApprove(w, r, st, dc, client)

	default:
		// The code was submitted but no decision was made yet: show what is being
		// asked for.
		d.renderDeviceConsent(w, r, dc, client)
	}
}

// loadDeviceRequest resolves a typed user_code to its live row and client.
//
// A nil DeviceCode with ok=true is the "not valid" outcome, which the caller answers
// with the entry form. ok=false means the response has already been written.
func (d *Deps) loadDeviceRequest(w http.ResponseWriter, r *http.Request, rawCode string) (*domain.DeviceCode, *domain.Client, bool) {
	userCode := domain.NormalizeUserCode(rawCode)
	if userCode == "" {
		return nil, nil, true
	}

	dc, err := d.DeviceCodes.GetLiveByUserCode(r.Context(), userCode)
	if err != nil {
		d.Logger.Error("device: lookup", "error", err.Error(), "correlation_id", d.state(r).correlationID)
		d.renderError(w, r, http.StatusInternalServerError, "server_error")
		return nil, nil, false
	}
	if dc == nil {
		return nil, nil, true
	}

	client, err := d.Clients.GetByID(r.Context(), dc.ClientID)
	if err != nil {
		d.Logger.Error("device: load client", "error", err.Error(), "correlation_id", d.state(r).correlationID)
		d.renderError(w, r, http.StatusInternalServerError, "server_error")
		return nil, nil, false
	}
	return dc, client, true
}

// renderDeviceEntry renders the code-entry form.
func (d *Deps) renderDeviceEntry(w http.ResponseWriter, r *http.Request, userCode, message string) {
	base := d.base(r, "Device authorization")
	base.Error = message
	d.render(w, r, ui.PageDevice, http.StatusOK, ui.DeviceData{
		Base:     base,
		Stage:    ui.DeviceStageEnter,
		UserCode: userCode,
	})
}

// renderDeviceConsent renders the approval screen for a live code.
func (d *Deps) renderDeviceConsent(w http.ResponseWriter, r *http.Request, dc *domain.DeviceCode, client *domain.Client) {
	st := d.state(r)
	// The exclusions are collected, not just the survivors: the screen has to be able
	// to say why a requested scope is missing, or the user concludes the application
	// received it.
	grantable, excluded, err := d.ConsentMgr.ExplainScopeExclusions(r.Context(), st.userID, dc.Scope, client.Scopes)
	if err != nil {
		d.Logger.Error("device: filter scopes", "error", err.Error(), "correlation_id", st.correlationID)
		d.renderError(w, r, http.StatusInternalServerError, "server_error")
		return
	}
	d.render(w, r, ui.PageDevice, http.StatusOK, ui.DeviceData{
		Base:            d.base(r, "Device authorization"),
		Stage:           ui.DeviceStageConsent,
		UserCode:        dc.UserCode,
		ClientName:      client.ClientName,
		RequestedScopes: scopeItems(grantable),
		ExcludedScopes:  excludedScopeItems(excluded),
	})
}

// renderDeviceResult renders the terminal approved or denied screen.
func (d *Deps) renderDeviceResult(w http.ResponseWriter, r *http.Request, stage, clientName string) {
	d.render(w, r, ui.PageDevice, http.StatusOK, ui.DeviceData{
		Base:       d.base(r, "Device authorization"),
		Stage:      stage,
		ClientName: clientName,
	})
}

// deviceApprove records consent and approves the device authorization.
func (d *Deps) deviceApprove(w http.ResponseWriter, r *http.Request, st reqState, dc *domain.DeviceCode, client *domain.Client) {
	// Re-resolve the grantable set at approval time rather than trusting what the
	// screen showed. Verification state can change between render and submit, and the
	// set that is granted must be the one the server computes now.
	grantable, err := d.ConsentMgr.FilterGrantableScopes(r.Context(), st.userID, dc.Scope, client.Scopes)
	if err != nil {
		d.Logger.Error("device: filter scopes", "error", err.Error(), "correlation_id", st.correlationID)
		d.renderError(w, r, http.StatusInternalServerError, "server_error")
		return
	}

	if err := d.ConsentMgr.GrantConsent(r.Context(), st.userID, client.ClientID, grantable); err != nil {
		d.Logger.Error("device: grant consent", "error", err.Error(), "correlation_id", st.correlationID)
		d.renderError(w, r, http.StatusInternalServerError, "server_error")
		return
	}

	approved, err := d.DeviceCodes.Approve(r.Context(), dc.DeviceCodeHash, st.userID)
	if err != nil {
		d.Logger.Error("device: approve", "error", err.Error(), "correlation_id", st.correlationID)
		d.renderError(w, r, http.StatusInternalServerError, "server_error")
		return
	}
	// A concurrent decision won the race between the lookup above and here, so the
	// code is no longer pending. The correct answer is the same invalid-code fallback
	// a stale form gets anywhere else, not an approval of a decision this request did
	// not make.
	if approved == nil {
		d.renderDeviceEntry(w, r, dc.UserCode, "That code is not valid, or it has expired.")
		return
	}

	_ = d.AuditLog.DeviceAuthorized(r.Context(), st.auditRC(), st.userID, client.ClientID)
	d.renderDeviceResult(w, r, ui.DeviceStageApproved, client.ClientName)
}
