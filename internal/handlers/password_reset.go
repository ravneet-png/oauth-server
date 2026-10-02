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

// PasswordResetPage renders guidance at the path the emailed link points at.
//
// The link must resolve to something, but the reset itself is submitted by the
// application over the JSON endpoint. A dead end here would make a correctly issued
// reset look broken, which is the one thing a recovery link must never do.
func (d *Deps) PasswordResetPage(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		httpapi.MethodNotAllowed(w, http.MethodGet)
		return
	}
	base := d.base(r, "Reset your password")
	base.Error = "Open this page from the application to choose a new password. The link itself is only valid once."
	d.render(w, r, ui.PageError, http.StatusOK, ui.ErrorData{Base: base, Code: "reset_required"})
}

// ForgotPassword handles a reset request.
func (d *Deps) ForgotPassword(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		httpapi.MethodNotAllowed(w, http.MethodPost)
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
			// One response for unknown, expired, used and wrong-purpose tokens.
			httpapi.JSON(w, http.StatusBadRequest, map[string]string{"error": "invalid_token"})
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
