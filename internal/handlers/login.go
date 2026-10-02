package handlers

// GET and POST /login — the interactive sign-in endpoint.
//
// Session creation happens here, and it is the only handler that writes the session
// cookie. Everything else either reads the session (via middleware) or destroys it
// (/logout). Keeping cookie issuance in one place is what makes "which requests can
// mint a session" an answerable question.

import (
	"errors"
	"net/http"
	"time"

	"oauth-server/internal/authn"
	"oauth-server/internal/domain"
	"oauth-server/internal/httpapi"
	"oauth-server/internal/middleware"
	"oauth-server/internal/ui"
)

// Login handles sign-in.
func (d *Deps) Login(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		d.loginForm(w, r, "")
	case http.MethodPost:
		d.loginSubmit(w, r)
	default:
		httpapi.MethodNotAllowed(w, http.MethodGet, http.MethodPost)
	}
}

// loginForm renders the sign-in page.
func (d *Deps) loginForm(w http.ResponseWriter, r *http.Request, message string) {
	authRequestID := stringParam(r, "auth_request_id")

	base := d.base(r, "Sign in")
	base.Error = message
	data := ui.LoginData{
		Base:          base,
		Email:         stringParam(r, "login_hint"),
		AuthRequestID: authRequestID,
	}

	// When the sign-in page is the first step of an authorization request, it names the
	// client. A user who types a password into a page that does not say which
	// application is asking cannot notice that they are on the wrong application's
	// page, which is the phishing scenario the display exists to defeat.
	if req := d.loadAuthRequest(r, authRequestID); req != nil {
		data.ClientID = req.ClientID
		data.Scope = req.Scope
		if client, err := d.Clients.GetByID(r.Context(), req.ClientID); err == nil {
			data.ClientName = client.ClientName
		}
	}

	d.render(w, r, ui.PageLogin, http.StatusOK, data)
}

// loginSubmit processes a sign-in.
func (d *Deps) loginSubmit(w http.ResponseWriter, r *http.Request) {
	if !parseForm(r) {
		d.loginForm(w, r, "The form could not be read. Please try again.")
		return
	}

	email := stringParam(r, "email")
	password := stringParam(r, "password")
	authRequestID := stringParam(r, "auth_request_id")
	st := d.state(r)

	result, err := d.Passwords.VerifyPassword(r.Context(), email, password)
	if err != nil {
		// One message for a wrong password, an unknown address and a disabled account.
		// The API contract is explicit that these are indistinguishable; a user who
		// mistyped their address still sees "check your details", which is true.
		_ = d.AuditLog.Record(r.Context(), st.auditRC(),
			domain.NewAuditEvent(domain.AuditUserLoginFailed, domain.AuditOutcomeFailure, nil),
			email)
		// A database failure is not a credential failure. Reporting it as one sends a
		// user to reset a password that was never wrong, and hides an outage.
		if !errors.Is(err, authn.ErrInvalidCredentials) && !errors.Is(err, authn.ErrAccountLocked) {
			d.Logger.Error("login: credential check failed", "error", err.Error(), "correlation_id", st.correlationID)
		}
		d.loginForm(w, r, "Email or password is incorrect.")
		return
	}

	// A second factor is outstanding. The session is NOT created yet: creating it here
	// and marking it unverified later means a crash between the two leaves a fully
	// valid session that never passed MFA.
	if result.User.MFAEnabled {
		pendingID := newOpaqueID()
		if pendingID == "" || d.MFAPending == nil {
			d.renderError(w, r, http.StatusInternalServerError, "server_error")
			return
		}
		if err := d.MFAPending.Store(r.Context(), pendingID, result.User.UserID, authRequestID); err != nil {
			d.Logger.Error("login: store mfa pending", "error", err.Error(), "correlation_id", st.correlationID)
			d.renderError(w, r, http.StatusInternalServerError, "server_error")
			return
		}
		httpapi.SeeOther(w, r, "/mfa?pending_id="+pendingID)
		return
	}

	d.establishSession(w, r, result.User, result.AuthTime, result.AMR, authRequestID)
}

// establishSession creates the session, sets the cookie, and resumes the flow.
func (d *Deps) establishSession(w http.ResponseWriter, r *http.Request, user *domain.User, authTime time.Time, amr []string, authRequestID string) {
	st := d.state(r)

	session, err := d.SessionMgr.Create(r.Context(), user.UserID, authTime, amr)
	if err != nil {
		d.Logger.Error("login: create session", "error", err.Error(), "correlation_id", st.correlationID)
		d.renderError(w, r, http.StatusInternalServerError, "server_error")
		return
	}

	middleware.SetSessionCookie(w, session.SessionID, session.ExpiresAt, d.Config.SessionCookieSecure)

	// Attach the authenticated user to the authorization request before redirecting,
	// so the consent step does not have to re-establish who is asking. A failure here
	// is fatal to the flow: continuing would send a request with no user to /consent.
	if authRequestID != "" {
		if err := d.AuthReqs.SetUserID(r.Context(), authRequestID, user.UserID, authTime); err != nil {
			d.Logger.Error("login: attach user to auth request", "error", err.Error(), "correlation_id", st.correlationID)
			d.renderError(w, r, http.StatusInternalServerError, "server_error")
			return
		}
		if err := d.AuthReqs.SetSessionID(r.Context(), authRequestID, session.SessionID); err != nil {
			d.Logger.Error("login: attach session to auth request", "error", err.Error(), "correlation_id", st.correlationID)
			d.renderError(w, r, http.StatusInternalServerError, "server_error")
			return
		}
	}

	_ = d.AuditLog.Record(r.Context(), st.auditRC(),
		domain.NewAuditEvent(domain.AuditUserLogin, domain.AuditOutcomeSuccess, nil),
		user.Email)

	if authRequestID != "" {
		httpapi.SeeOther(w, r, "/consent?auth_request_id="+authRequestID)
		return
	}
	httpapi.SeeOther(w, r, "/")
}

// loadAuthRequest fetches an authorization request, or nil.
//
// Errors are swallowed to nil: the login page is renderable without it, and a request
// that expired between the redirect and the page load should show a sign-in form rather
// than an error the user cannot act on.
func (d *Deps) loadAuthRequest(r *http.Request, id string) *domain.AuthRequest {
	if id == "" {
		return nil
	}
	req, err := d.AuthReqs.GetByID(r.Context(), id)
	if err != nil || req.IsExpired(time.Now().UTC()) {
		return nil
	}
	return req
}

// render renders a page, falling back to a plain error when no renderer is configured.
func (d *Deps) render(w http.ResponseWriter, r *http.Request, page string, status int, data any) {
	if d.Renderer == nil {
		renderPlainError(w, status, "template_renderer_unavailable")
		return
	}
	httpapi.RenderPage(w, d.Renderer, page, status, data)
}
