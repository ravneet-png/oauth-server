package handlers

// Interactive browser flows: GET /, GET|POST /signup, POST /signup/verify-dev, and GET /callback.

import (
	"net/http"
	"net/url"
	"strings"
	"time"

	"oauth-server/internal/crypto"
	"oauth-server/internal/domain"
	"oauth-server/internal/httpapi"
	"oauth-server/internal/ui"
)

const demoClientID = "demo-client"

// Home renders GET / — the interactive OAuth 2.1 + OIDC Developer Console.
func (d *Deps) Home(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path != "/" {
		http.NotFound(w, r)
		return
	}
	if r.Method != http.MethodGet {
		httpapi.MethodNotAllowed(w, http.MethodGet)
		return
	}

	st := d.state(r)
	issuer := d.Config.Issuer
	data := ui.HomeData{
		Base:         d.base(r, "OAuth 2.1 Developer Console"),
		Issuer:       issuer,
		DemoClientID: demoClientID,
		CallbackURL:  strings.TrimRight(issuer, "/") + "/callback",
	}
	if d.Keys != nil {
		if active, err := d.Keys.GetSigningKey(); err == nil && active != nil {
			data.ActiveKeyID = active.KID
		}
	}

	if st.hasSession() && d.Users != nil {
		if user, err := d.Users.GetByID(r.Context(), st.userID); err == nil && user != nil {
			data.Authenticated = true
			data.UserID = user.UserID
			data.UserEmail = user.Email
			data.UserName = user.DisplayName()
			data.EmailVerified = user.EmailVerified
			data.MFAEnabled = user.MFAEnabled
		}
	}

	d.render(w, r, ui.PageHome, http.StatusOK, data)
}

// Callback renders GET /callback — the OAuth redirect receiver and token inspector.
//
// Security-critical response parameters are read as singletons. Ambiguous duplicate
// code, state, issuer, or error values are rejected by the browser UI before a token
// exchange can occur.
func (d *Deps) Callback(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		httpapi.MethodNotAllowed(w, http.MethodGet)
		return
	}

	q, parseErr := url.ParseQuery(r.URL.RawQuery)
	data := ui.CallbackData{
		Base:          d.base(r, "OAuth 2.1 Callback & Token Inspector"),
		Issuer:        d.Config.Issuer,
		DemoClientID:  demoClientID,
		CallbackURL:   strings.TrimRight(d.Config.Issuer, "/") + "/callback",
		ResponseValid: parseErr == nil,
	}
	readSingle := func(name string) (string, bool) {
		values, present := q[name]
		if len(values) > 1 {
			data.ResponseValid = false
			return "", present
		}
		if !present || len(values) == 0 {
			return "", false
		}
		return values[0], true
	}

	data.Code, data.CodePresent = readSingle("code")
	data.State, data.StatePresent = readSingle("state")
	data.ReturnedIss, data.IssuerPresent = readSingle("iss")
	data.OAuthError, data.OAuthErrorPresent = readSingle("error")
	data.OAuthDesc, _ = readSingle("error_description")
	if data.CodePresent && data.OAuthErrorPresent {
		data.ResponseValid = false
	}
	if _, hasErrorDescription := q["error_description"]; hasErrorDescription && !data.OAuthErrorPresent {
		data.ResponseValid = false
	}

	d.render(w, r, ui.PageCallback, http.StatusOK, data)
}

// Signup handles GET /signup and POST /signup for browser-based account creation.
func (d *Deps) Signup(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		d.signupGet(w, r)
	case http.MethodPost:
		d.signupPost(w, r)
	default:
		httpapi.MethodNotAllowed(w, http.MethodGet, http.MethodPost)
	}
}

func (d *Deps) signupGet(w http.ResponseWriter, r *http.Request) {
	authRequestID := stringParam(r, "auth_request_id")
	minLen := d.Config.MinPasswordLen
	if minLen <= 0 {
		minLen = 12
	}
	d.render(w, r, ui.PageRegister, http.StatusOK, ui.RegisterData{
		Base:           d.base(r, "Create account"),
		AuthRequestID:  authRequestID,
		MinPasswordLen: minLen,
	})
}

func (d *Deps) signupPost(w http.ResponseWriter, r *http.Request) {
	if !parseForm(r) {
		d.renderError(w, r, http.StatusBadRequest, "invalid_request")
		return
	}
	st := d.state(r)

	name := strings.TrimSpace(stringParam(r, "name"))
	emailAddr := strings.ToLower(strings.TrimSpace(stringParam(r, "email")))
	password := stringParam(r, "password")
	passwordConfirm := stringParam(r, "password_confirm")
	authRequestID := stringParam(r, "auth_request_id")

	minLen := d.Config.MinPasswordLen
	if minLen <= 0 {
		minLen = 12
	}

	renderSignupError := func(msg string) {
		base := d.base(r, "Create account")
		base.Error = msg
		d.render(w, r, ui.PageRegister, http.StatusOK, ui.RegisterData{
			Base:           base,
			Email:          emailAddr,
			AuthRequestID:  authRequestID,
			MinPasswordLen: minLen,
		})
	}

	if !validSignupInput(emailAddr, password, minLen) {
		renderSignupError("Please enter a valid email address and a password meeting the minimum length.")
		return
	}
	if passwordConfirm != "" && passwordConfirm != password {
		renderSignupError("Passwords do not match.")
		return
	}

	hash, err := crypto.HashPassword(password, d.argonParams())
	if err != nil {
		d.Logger.Error("signup: hash password", "error", err.Error(), "correlation_id", st.correlationID)
		d.renderError(w, r, http.StatusInternalServerError, "server_error")
		return
	}

	var namePtr *string
	if name != "" {
		namePtr = &name
	}

	now := time.Now().UTC()
	user := &domain.User{
		UserID:       newOpaqueID(),
		Email:        emailAddr,
		PasswordHash: hash,
		Name:         namePtr,
		CreatedAt:    now,
	}
	if user.UserID == "" || d.Users == nil {
		d.renderError(w, r, http.StatusInternalServerError, "server_error")
		return
	}

	created, err := d.Users.CreateIfNotExists(r.Context(), user)
	if err != nil {
		d.Logger.Error("signup: create user", "error", err.Error(), "correlation_id", st.correlationID)
		d.renderError(w, r, http.StatusInternalServerError, "server_error")
		return
	}

	if !created {
		d.sendSignupNotice(r, emailAddr, true)
		renderSignupError("An account with this email already exists. Please sign in instead.")
		return
	}

	_ = d.AuditLog.Record(r.Context(), st.auditRC(),
		domain.NewAuditEvent(domain.AuditUserRegistered, domain.AuditOutcomeSuccess, nil), emailAddr)

	d.sendSignupNotice(r, emailAddr, false)

	d.establishSession(w, r, user, now, []string{domain.AMRPwd}, authRequestID)
}

// VerifyEmailDev handles POST /signup/verify-dev to mark the signed-in user's email verified in local dev.
func (d *Deps) VerifyEmailDev(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		httpapi.MethodNotAllowed(w, http.MethodPost)
		return
	}
	st := d.state(r)
	if !st.hasSession() || d.Users == nil {
		httpapi.SeeOther(w, r, "/login")
		return
	}

	if err := d.Users.UpdateEmailVerified(r.Context(), st.userID, true); err != nil {
		d.Logger.Error("verify_email_dev: update verified", "error", err.Error(), "correlation_id", st.correlationID)
		d.renderError(w, r, http.StatusInternalServerError, "server_error")
		return
	}

	httpapi.SeeOther(w, r, "/")
}
