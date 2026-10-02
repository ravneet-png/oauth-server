package handlers

// GET /users/verify-email (also served at /verify-email, which is the path the email
// templates generate) — redeems a signup token.
//
// The token is consumed atomically and the address is marked verified in the same
// request. A token that is expired, already used, or of the wrong purpose all produce the
// same page, because the differences are only useful to someone probing tokens.

import (
	"net/http"
	"time"

	"oauth-server/internal/crypto"
	"oauth-server/internal/domain"
	"oauth-server/internal/httpapi"
	"oauth-server/internal/ui"
)

// EmailVerify handles signup token redemption.
func (d *Deps) EmailVerify(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		httpapi.MethodNotAllowed(w, http.MethodGet)
		return
	}
	st := d.state(r)

	token := stringParam(r, "token")
	base := d.base(r, "Verify your email")
	data := ui.VerifyEmailData{
		Base:        base,
		Success:     false,
		LoginURL:    "/login",
		NextStepURL: "/login",
	}

	if token == "" {
		d.renderVerify(w, r, ui.VerifyEmailData{
			Base:        base,
			Success:     false,
			LoginURL:    "/login",
			ResendURL:   "/login",
			NextStepURL: "/login",
		})
		return
	}

	record, err := d.EmailVerif.GetByHash(r.Context(), crypto.SHA256Hex(token))
	if err != nil {
		d.renderVerify(w, r, ui.VerifyEmailData{
			Base:        base,
			Success:     false,
			LoginURL:    "/login",
			NextStepURL: "/login",
		})
		return
	}

	now := time.Now().UTC()
	// Purpose is checked here rather than trusted from the URL: a password-reset token
	// presented at this endpoint must not mark an address verified.
	if record.Purpose != domain.VerifyPurposeSignup ||
		!record.IsRedeemable(now) ||
		!record.CoversAddress(record.TargetEmail) {
		d.renderVerify(w, r, ui.VerifyEmailData{
			Base:        base,
			Success:     false,
			LoginURL:    "/login",
			NextStepURL: "/login",
		})
		return
	}

	consumed, err := d.EmailVerif.MarkUsed(r.Context(), record.TokenHash)
	if err != nil {
		d.Logger.Error("verify_email: consume token", "error", err.Error(), "correlation_id", st.correlationID)
		d.renderError(w, r, http.StatusInternalServerError, "server_error")
		return
	}
	if !consumed {
		// Lost the race with a concurrent redemption. The other request verified the
		// address; reporting success here would be a lie told to one of two tabs, so
		// this one says the link is no longer valid.
		d.renderVerify(w, r, ui.VerifyEmailData{
			Base:        base,
			Success:     false,
			LoginURL:    "/login",
			NextStepURL: "/login",
		})
		return
	}

	if err := d.Users.UpdateEmailVerified(r.Context(), record.UserID, true); err != nil {
		d.Logger.Error("verify_email: mark verified", "error", err.Error(), "correlation_id", st.correlationID)
		d.renderError(w, r, http.StatusInternalServerError, "server_error")
		return
	}

	_ = d.AuditLog.Record(r.Context(), st.auditRC(),
		domain.NewAuditEvent(domain.AuditUserRegistered, domain.AuditOutcomeSuccess, &record.UserID), record.TargetEmail)

	data.Success = true
	data.Email = record.TargetEmail
	d.renderVerify(w, r, data)
}

// renderVerify renders the verification result page.
func (d *Deps) renderVerify(w http.ResponseWriter, r *http.Request, data ui.VerifyEmailData) {
	d.render(w, r, ui.PageVerifyEmail, http.StatusOK, data)
}
