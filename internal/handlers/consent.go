package handlers

// GET and POST /consent — the user-visible authorization decision.
//
// This is where an authorization request stops being a URL and becomes a decision. The
// handler owns three things the flow deliberately does not: whether an existing grant
// makes the screen unnecessary, what the screen says, and turning the user's click into
// an authorization code or a denial.
//
// The rule that governs every branch here: under prompt=none the server may not render
// anything. It either already has consent and proceeds silently, or it returns
// consent_required to the validated redirect_uri. Rendering a page on a prompt=none
// request breaks the client, which by definition is not watching for one.

import (
	"encoding/json"
	"net/http"
	"net/url"
	"time"

	"oauth-server/internal/consent"
	"oauth-server/internal/domain"
	"oauth-server/internal/flows"
	"oauth-server/internal/httpapi"
	"oauth-server/internal/oautherr"
	"oauth-server/internal/ui"
)

// ConsentDecision handles the authorization decision.
func (d *Deps) ConsentDecision(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		d.consentScreen(w, r, "")
	case http.MethodPost:
		d.consentSubmit(w, r)
	default:
		httpapi.MethodNotAllowed(w, http.MethodGet, http.MethodPost)
	}
}

// consentScreen evaluates consent and either renders the screen or resolves it.
func (d *Deps) consentScreen(w http.ResponseWriter, r *http.Request, message string) {
	st := d.state(r)
	if !st.hasSession() {
		// No session: send the browser through login, preserving the request. The login
		// handler attaches the user back to this authorization request.
		httpapi.SeeOther(w, r, "/login?auth_request_id="+url.QueryEscape(stringParam(r, "auth_request_id")))
		return
	}

	req, client, ok := d.loadConsentRequest(w, r, st)
	if !ok {
		return
	}

	// The exclusions are collected here, not just the survivors: the screen has to be
	// able to say why a requested scope is missing, or the user concludes the
	// application received it.
	grantable, excluded, err := d.ConsentMgr.ExplainScopeExclusions(r.Context(), st.userID, req.Scope, client.Scopes)
	if err != nil {
		d.Logger.Error("consent: filter scopes", "error", err.Error(), "correlation_id", st.correlationID)
		d.renderError(w, r, http.StatusInternalServerError, "server_error")
		return
	}

	granted, err := d.ConsentMgr.HasFullConsent(r.Context(), st.userID, req.ClientID, grantable)
	if err != nil {
		d.Logger.Error("consent: check existing consent", "error", err.Error(), "correlation_id", st.correlationID)
		d.renderError(w, r, http.StatusInternalServerError, "server_error")
		return
	}

	prompt := consentPrompt(req)

	// prompt=consent forces the screen even when a grant exists. The client asked to
	// re-confirm; answering from the stored grant would be the silent ignore OIDC
	// forbids.
	if granted && !hasString(prompt, "consent") {
		d.resolveConsent(w, r, st, req, grantable)
		return
	}

	if hasString(prompt, "none") {
		// The client promised the user agent no interaction. We need one, so the only
		// honest answer is consent_required, delivered to the client.
		d.redirectConsentError(w, r, req, domain.NewConsentRequired("consent is required but prompt=none was requested"))
		return
	}

	base := d.base(r, "Authorize application")
	base.Error = message
	d.render(w, r, ui.PageConsent, http.StatusOK, ui.ConsentData{
		Base:              base,
		ClientID:          client.ClientID,
		ClientName:        client.ClientName,
		ClientURI:         deref(client.ClientURI),
		AuthRequestID:     req.ID,
		RequestedScopes:   scopeItems(grantable),
		PreviouslyGranted: previouslyGranted(req.Scope, grantable),
		ExcludedScopes:    excludedScopeItems(excluded),
	})
}

// consentSubmit records the user's decision and completes the authorization.
func (d *Deps) consentSubmit(w http.ResponseWriter, r *http.Request) {
	// scope repeats: one value per box the user ticked.
	if !parseFormAllowing(r, "scope") {
		d.consentScreen(w, r, "The form could not be read. Please try again.")
		return
	}

	st := d.state(r)
	if !st.hasSession() {
		httpapi.SeeOther(w, r, "/login?auth_request_id="+url.QueryEscape(stringParam(r, "auth_request_id")))
		return
	}

	req, client, ok := d.loadConsentRequest(w, r, st)
	if !ok {
		return
	}

	if stringParam(r, "decision") == "deny" {
		if err := flows.DenyAuthorization(r.Context(), d.AuthReqs, req.ID); err != nil {
			d.Logger.Error("consent: deny", "error", err.Error(), "correlation_id", st.correlationID)
			d.renderError(w, r, http.StatusInternalServerError, "server_error")
			return
		}
		_ = d.AuditLog.Record(r.Context(), st.auditRC(),
			domain.NewAuditEvent(domain.AuditConsentRevoked, domain.AuditOutcomeSuccess, &st.userID), req.ClientID)
		d.redirectConsentError(w, r, req, domain.NewAccessDenied("the user denied the request"))
		return
	}

	grantable, err := d.ConsentMgr.FilterGrantableScopes(r.Context(), st.userID, req.Scope, client.Scopes)
	if err != nil {
		d.Logger.Error("consent: filter scopes", "error", err.Error(), "correlation_id", st.correlationID)
		d.renderError(w, r, http.StatusInternalServerError, "server_error")
		return
	}

	// The submitted set is intersected with what is actually grantable. Never trust the
	// form: a browser can post any scope name, and intersection means a hand-crafted
	// POST can only ever grant something the server already decided was grantable.
	selected := intersectScopes(r.Form["scope"], grantable)
	if len(selected) == 0 && len(grantable) > 0 {
		d.consentScreen(w, r, "Select at least one permission, or deny the request.")
		return
	}

	if err := d.ConsentMgr.GrantConsent(r.Context(), st.userID, req.ClientID, selected); err != nil {
		d.Logger.Error("consent: grant", "error", err.Error(), "correlation_id", st.correlationID)
		d.renderError(w, r, http.StatusInternalServerError, "server_error")
		return
	}
	_ = d.AuditLog.Record(r.Context(), st.auditRC(),
		domain.NewAuditEvent(domain.AuditConsentGranted, domain.AuditOutcomeSuccess, &st.userID), req.ClientID)

	d.resolveConsent(w, r, st, req, selected)
}

// resolveConsent issues an authorization code and redirects to the client.
func (d *Deps) resolveConsent(w http.ResponseWriter, r *http.Request, st reqState, req *domain.AuthRequest, scopes []string) {
	sessionID := st.sessionID
	_, code, err := flows.ApproveAuthorization(r.Context(),
		d.AuthReqs, d.Codes, d.ClientSess, d.Families,
		flows.ApproveParams{
			AuthRequestID:      req.ID,
			UserID:             st.userID,
			SessionID:          sessionID,
			Scope:              scopes,
			CodeTTL:            d.Config.AuthCodeTTL,
			RefreshAbsoluteTTL: d.Config.RefreshAbsoluteTTL,
		})
	if err != nil {
		d.consentFailure(w, r, req, err)
		return
	}
	_ = d.AuditLog.Record(r.Context(), st.auditRC(),
		domain.NewAuditEvent(domain.AuditTokenIssued, domain.AuditOutcomeSuccess, &st.userID), req.ClientID)

	target, buildErr := authorizationRedirectURL(req.RedirectURI, code, deref(req.State), d.Config.Issuer)
	if buildErr != nil {
		// The stored redirect_uri was validated at /authorize, so a build failure now is
		// a server inconsistency, not a client error.
		d.renderError(w, r, http.StatusInternalServerError, "server_error")
		return
	}
	httpapi.SeeOther(w, r, target)
}

// consentFailure routes an approval error to the client when it is deliverable.
func (d *Deps) consentFailure(w http.ResponseWriter, r *http.Request, req *domain.AuthRequest, err error) {
	// The client is told only `server_error`, by design. That is precisely why the
	// reason has to be logged here: a failure that reaches the client with no log line
	// is indistinguishable from a broken client, and gets debugged in the wrong place.
	d.Logger.Error("consent: approve failed",
		"error", err.Error(),
		"correlation_id", d.state(r).correlationID,
		"client_id", req.ClientID)
	d.redirectConsentError(w, r, req, err)
}

// redirectConsentError delivers an authorization error to the client.
func (d *Deps) redirectConsentError(w http.ResponseWriter, r *http.Request, req *domain.AuthRequest, err error) {
	oe := oautherr.From(err).WithIssuer(d.Config.Issuer)
	httpapi.RedirectError(w, r, req.RedirectURI, deref(req.State), oe)
}

// loadConsentRequest loads and re-checks the authorization request and client.
//
// The request is re-checked against the session user rather than trusted: a consent page
// left open across a logout must not complete for the previous user. Returns ok=false
// after it has written the response.
func (d *Deps) loadConsentRequest(w http.ResponseWriter, r *http.Request, st reqState) (*domain.AuthRequest, *domain.Client, bool) {
	id := stringParam(r, "auth_request_id")
	if id == "" {
		d.renderError(w, r, http.StatusBadRequest, "invalid_request")
		return nil, nil, false
	}
	req, err := d.AuthReqs.GetByID(r.Context(), id)
	if err != nil || req.IsExpired(time.Now().UTC()) {
		d.renderError(w, r, http.StatusBadRequest, "invalid_request")
		return nil, nil, false
	}
	if req.UserID == nil || *req.UserID != st.userID {
		// Belongs to someone else, or login never completed. Both are access_denied and
		// both are delivered to the client, because the redirect_uri is already known
		// good from /authorize.
		d.redirectConsentError(w, r, req, domain.NewAccessDenied("authorization request does not belong to this session"))
		return nil, nil, false
	}
	client, err := d.Clients.GetByID(r.Context(), req.ClientID)
	if err != nil {
		d.renderError(w, r, http.StatusInternalServerError, "server_error")
		return nil, nil, false
	}
	return req, client, true
}

// authorizationRedirectURL builds a successful authorization response.
//
// Includes iss per RFC 9207 so a client can tell which issuer produced the code, and
// preserves any fragment the registered redirect_uri carries: moving it into the query
// would change where the client reads the code.
func authorizationRedirectURL(redirectURI, code, state, issuer string) (string, error) {
	base, err := url.Parse(redirectURI)
	if err != nil {
		return "", err
	}
	fragment := base.Fragment
	q := base.Query()
	q.Set("code", code)
	if state != "" {
		q.Set("state", state)
	}
	if issuer != "" {
		q.Set("iss", issuer)
	}
	base.RawQuery = q.Encode()
	base.Fragment = fragment
	return base.String(), nil
}

// consentPrompt decodes the stored prompt parameter from the authorization request.
//
// A decode failure yields no prompt rather than an error: the request was validated
// before it was stored, and refusing to read a corrupt copy would strand the user on an
// error page for a decision that can still be made correctly.
func consentPrompt(req *domain.AuthRequest) []string {
	if len(req.ParamsJSON) == 0 {
		return nil
	}
	var params flows.Params
	if err := json.Unmarshal(req.ParamsJSON, &params); err != nil {
		return nil
	}
	return params.Prompt
}

// hasString reports whether values contains want.
func hasString(values []string, want string) bool {
	for _, v := range values {
		if v == want {
			return true
		}
	}
	return false
}

// intersectScopes returns the members of submitted that are also in allowed, in
// allowed's order, without duplicates.
func intersectScopes(submitted, allowed []string) []string {
	if len(allowed) == 0 {
		return nil
	}
	sub := make(map[string]struct{}, len(submitted))
	for _, s := range submitted {
		sub[s] = struct{}{}
	}
	out := make([]string, 0, len(allowed))
	for _, s := range allowed {
		if _, ok := sub[s]; ok {
			out = append(out, s)
		}
	}
	return out
}

// previouslyGranted is the requested scopes an existing grant already covers, listed on
// the screen so the user is not asked to re-approve something silently reused.
func previouslyGranted(requested, grantable []string) []string {
	inGrantable := make(map[string]struct{}, len(grantable))
	for _, s := range grantable {
		inGrantable[s] = struct{}{}
	}
	var out []string
	for _, s := range requested {
		if _, ok := inGrantable[s]; !ok {
			out = append(out, s)
		}
	}
	return out
}

// scopeItems describes scopes for the consent screen.
//
// Unknown scopes render under their own name rather than being dropped: a client
// registered for a custom scope must still be able to explain what it is asking for, and
// dropping it would let a client obtain a scope the user never saw.
func scopeItems(scopes []string) []ui.ScopeItem {
	items := make([]ui.ScopeItem, 0, len(scopes))
	for _, s := range scopes {
		entry, ok := scopeCatalog[s]
		if !ok {
			entry = [2]string{s, ""}
		}
		items = append(items, ui.ScopeItem{Name: s, Title: entry[0], Description: entry[1]})
	}
	return items
}

// excludedScopeItems describes withheld scopes for the consent screen.
//
// Title falls back to the scope string, matching scopeItems: a withheld custom scope
// still needs to be identifiable, or the user sees a reason attached to nothing.
func excludedScopeItems(exclusions []consent.ScopeExclusion) []ui.ExcludedScope {
	if len(exclusions) == 0 {
		return nil
	}
	items := make([]ui.ExcludedScope, 0, len(exclusions))
	for _, e := range exclusions {
		title := ""
		if entry, ok := scopeCatalog[e.Scope]; ok {
			title = entry[0]
		}
		items = append(items, ui.ExcludedScope{Name: e.Scope, Title: title, Reason: e.Reason})
	}
	return items
}

// scopeCatalog is the display text for standard scopes. Unknown scopes fall back to the
// scope string itself.
var scopeCatalog = map[string][2]string{
	"openid":         {"Verify your identity", "Sign you in and confirm who you are"},
	"profile":        {"Your basic profile", "Your name and profile details"},
	"email":          {"Your email address", "Read the email address on your account"},
	"offline_access": {"Keep access when you are away", "Stay signed in without you being present"},
	"address":        {"Your postal address", "Read the postal address on your account"},
	"phone":          {"Your phone number", "Read the phone number on your account"},
}

// deref returns the pointed-to string, or "".
func deref(s *string) string {
	if s == nil {
		return ""
	}
	return *s
}
