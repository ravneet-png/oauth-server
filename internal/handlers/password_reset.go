package handlers

// Password reset, as machine endpoints.
//
// The contract mirrors registration: the request endpoint's response never depends on
// whether the address has an account, and the completion endpoint reports one error for
// every unusable token. The email package owns the actual work; this file only adapts
// HTTP to it.

import (
	"encoding/json"
	"errors"
	"io"
	"net/http"

	"oauth-server/internal/domain"
	"oauth-server/internal/email"
	"oauth-server/internal/httpapi"
	"oauth-server/internal/ui"
)

// forgotPasswordRequest is the body of POST /forgot-password.
type forgotPasswordRequest struct {
	Email string `json:"email"`
}

// resetPasswordRequest is the body of POST /reset-password.
type resetPasswordRequest struct {
	Token       string `json:"token"`
	NewPassword string `json:"password"`
}

// PasswordResetPage renders the one-time reset form at the path in the email.
//
// The token is carried in the page only long enough for its same-origin script to submit
// it to POST /reset-password. The script removes it from the address bar and never puts
// it in browser storage.
func (d *Deps) PasswordResetPage(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		httpapi.MethodNotAllowed(w, http.MethodGet)
		return
	}
	values := r.URL.Query()["token"]
	token := ""
	if len(values) == 1 {
		token = values[0]
	}
	d.render(w, r, ui.PagePasswordReset, http.StatusOK, ui.PasswordResetData{
		Base:           d.base(r, "Reset your password"),
		Token:          token,
		MinPasswordLen: d.minPasswordLen(),
	})
}

// ForgotPassword serves the recovery form on GET and issues a reset request on POST.
// The POST response remains uniform for existing, unknown, and malformed addresses.
func (d *Deps) ForgotPassword(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodGet {
		d.render(w, r, ui.PageForgotPassword, http.StatusOK, ui.ForgotPasswordData{
			Base: d.base(r, "Forgot your password?"),
		})
		return
	}
	if r.Method != http.MethodPost {
		httpapi.MethodNotAllowed(w, http.MethodGet, http.MethodPost)
		return
	}
	var req forgotPasswordRequest
	if err := decodeJSONBody(r, &req); err != nil {
		// Even a malformed body gets the uniform answer, so the endpoint cannot be used
		// to probe anything by varying the shape of the request.
		d.forgotPasswordResponse(w)
		return
	}

	if err := email.RequestReset(r.Context(), d.resetParams(), req.Email); err != nil {
		// Logged, not surfaced. The user learns nothing and the operator learns SMTP
		// is broken.
		d.Logger.Error("forgot_password: request reset", "error", err.Error(), "correlation_id", d.state(r).correlationID)
	}
	d.forgotPasswordResponse(w)
}

// forgotPasswordResponse is the one response every caller receives.
func (d *Deps) forgotPasswordResponse(w http.ResponseWriter) {
	httpapi.JSON(w, http.StatusAccepted, map[string]string{
		"message": "If that address has an account, a reset link is on its way",
	})
}

// ResetPassword completes a reset.
func (d *Deps) ResetPassword(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		httpapi.MethodNotAllowed(w, http.MethodPost)
		return
	}
	var req resetPasswordRequest
	if err := decodeJSONBody(r, &req); err != nil {
		httpapi.JSON(w, http.StatusBadRequest, map[string]string{"error": "invalid_request"})
		return
	}
	if len(req.NewPassword) < d.minPasswordLen() {
		httpapi.JSON(w, http.StatusBadRequest, map[string]string{"error": "invalid_request", "error_description": "password is too short"})
		return
	}

	err := email.CompleteReset(r.Context(), d.resetParams(), req.Token, req.NewPassword)
	if err != nil {
		if errors.Is(err, email.ErrResetTokenInvalid) {
			// One response for unknown, expired, used and wrong-purpose tokens. Invalid
			// credentials are 401 so browser clients and OAuth clients map the token
			// failure consistently.
			httpapi.JSON(w, http.StatusUnauthorized, map[string]string{"error": domain.ErrCodeInvalidToken})
			return
		}
		d.Logger.Error("reset_password: complete", "error", err.Error(), "correlation_id", d.state(r).correlationID)
		httpapi.ServerError(w)
		return
	}

	_ = d.AuditLog.Record(r.Context(), d.state(r).auditRC(),
		domain.NewAuditEvent(domain.AuditPasswordReset, domain.AuditOutcomeSuccess, nil), "")
	httpapi.JSON(w, http.StatusOK, map[string]string{"message": "Password updated"})
}

// resetParams builds the email package's parameter block.
func (d *Deps) resetParams() email.ResetParams {
	return email.ResetParams{
		TokenTTL:    d.Config.PasswordResetTTL,
		BaseURL:     d.Config.Issuer,
		SessionRepo: d.Sessions,
		RefreshRepo: d.RefreshToks,
		UserRepo:    d.Users,
		VerifyRepo:  d.EmailVerif,
		Sender:      d.Sender,
		Logger:      d.Logger,
		ArgonParams: d.argonParams(),
	}
}

// minPasswordLen returns the configured minimum, or a safe default.
func (d *Deps) minPasswordLen() int {
	if d.Config.MinPasswordLen <= 0 {
		return 8
	}
	return d.Config.MinPasswordLen
}

// decodeJSONBody decodes a small JSON object, refusing oversized bodies.
func decodeJSONBody(r *http.Request, v any) error {
	dec := json.NewDecoder(io.LimitReader(r.Body, 16<<10))
	return dec.Decode(v)
}
