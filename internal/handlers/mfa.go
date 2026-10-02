package handlers

// GET and POST /mfa — the second-factor challenge.
//
// The pending state lives in Redis, not in the session, because no session exists until
// the second factor succeeds. That is the whole design: a login that has passed a
// password but not the second factor has no session cookie, so there is nothing for an
// attacker with the password to steal between the two steps.

import (
	"errors"
	"net/http"
	"time"

	"oauth-server/internal/domain"
	"oauth-server/internal/httpapi"
	"oauth-server/internal/sessions"
	"oauth-server/internal/ui"
)

// MFAChallenge handles the second-factor challenge.
func (d *Deps) MFAChallenge(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		d.mfaForm(w, r, "")
	case http.MethodPost:
		d.mfaSubmit(w, r)
	default:
		httpapi.MethodNotAllowed(w, http.MethodGet, http.MethodPost)
	}
}

// mfaForm renders the challenge page.
func (d *Deps) mfaForm(w http.ResponseWriter, r *http.Request, message string) {
	pendingID := stringParam(r, "pending_id")
	userID, authRequestID, err := d.pendingUser(r, pendingID)
	if err != nil {
		// The pending state expired or was already consumed. The user restarts at
		// /login; there is nothing to challenge.
		httpapi.SeeOther(w, r, "/login")
		return
	}
	user, err := d.Users.GetByID(r.Context(), userID)
	if err != nil {
		httpapi.SeeOther(w, r, "/login")
		return
	}

	remaining := 0
	if d.MFAVerify != nil {
		if n, err := d.MFAVerify.BackupCodesRemaining(r.Context(), userID); err == nil {
			remaining = n
		}
	}

	base := d.base(r, "Two-factor authentication")
	base.Error = message
	d.render(w, r, ui.PageMFAChallenge, http.StatusOK, ui.MFAChallengeData{
		Base:                 base,
		PendingID:            pendingID,
		Email:                maskEmail(user.Email),
		Method:               stringParam(r, "method"),
		AuthRequestID:        authRequestID,
		BackupCodesRemaining: remaining,
	})
}

// mfaSubmit verifies a second factor and completes the login.
func (d *Deps) mfaSubmit(w http.ResponseWriter, r *http.Request) {
	if !parseForm(r) {
		d.mfaForm(w, r, "The form could not be read. Please try again.")
		return
	}

	pendingID := stringParam(r, "pending_id")
	code := stringParam(r, "code")
	method := stringParam(r, "method")

	userID, authRequestID, err := d.pendingUser(r, pendingID)
	if err != nil {
		httpapi.SeeOther(w, r, "/login")
		return
	}

	user, err := d.Users.GetByID(r.Context(), userID)
	if err != nil {
		httpapi.SeeOther(w, r, "/login")
		return
	}
	st := d.state(r)

	var verifyErr error
	if method == "backup_code" {
		var ok bool
		ok, verifyErr = d.MFAVerify.VerifyBackupCode(r.Context(), userID, code)
		if verifyErr == nil && !ok {
			verifyErr = ErrSecondFactor
		}
	} else {
		secret, decErr := d.decryptMFASecret(user)
		if decErr != nil {
			d.Logger.Error("mfa: decrypt secret", "error", decErr.Error(), "correlation_id", st.correlationID)
			d.renderError(w, r, http.StatusInternalServerError, "server_error")
			return
		}
		_, verifyErr = d.MFAVerify.VerifyTOTP(r.Context(), userID, secret, code)
	}

	if verifyErr != nil {
		event := domain.AuditMFAFailed
		_ = d.AuditLog.Record(r.Context(), st.auditRC(),
			domain.NewAuditEvent(event, domain.AuditOutcomeFailure, nil), user.Email)
		// One message for a wrong code, a replayed code and an exhausted budget. The
		// distinction is exactly what an attacker probing the second factor wants.
		d.mfaForm(w, r, "The code is not valid. Please try again.")
		return
	}

	// Consume the pending state before creating the session, so a replayed POST cannot
	// create a second session from one challenge.
	_ = d.MFAPending.Delete(r.Context(), pendingID)

	if method == "backup_code" {
		_ = d.AuditLog.Record(r.Context(), st.auditRC(),
			domain.NewAuditEvent(domain.AuditMFABackupCodeUsed, domain.AuditOutcomeSuccess, nil), user.Email)
	}

	// The session records both factors: pwd was established before the challenge was
	// shown, so a session created here without it would publish amr and acr claims
	// that understate what the user actually did.
	amr := []string{domain.AMRPwd, domain.AMROTP}
	if method == "backup_code" {
		amr = []string{domain.AMRPwd, domain.AMRMFA}
	}

	d.establishSession(w, r, user, time.Now().UTC(), amr, authRequestID)
}

// pendingUser resolves a pending MFA state.
func (d *Deps) pendingUser(r *http.Request, pendingID string) (userID, authRequestID string, err error) {
	if pendingID == "" || d.MFAPending == nil {
		return "", "", sessions.ErrMFANotFound
	}
	userID, authRequestID, err = d.MFAPending.Get(r.Context(), pendingID)
	if err != nil {
		return "", "", err
	}
	return userID, authRequestID, nil
}

// ErrSecondFactor is returned when a backup code was valid but not for this user.
var ErrSecondFactor = errors.New("handlers: invalid second factor")

// decryptMFASecret opens the stored TOTP seed.
//
// The user id is the additional authenticated data, matching how the seed was sealed at
// enrolment. A seed copied from another user's row therefore fails to open rather than
// silently verifying codes for the wrong account.
func (d *Deps) decryptMFASecret(user *domain.User) (string, error) {
	if d.Cipher == nil {
		return "", errors.New("handlers: no record cipher configured")
	}
	plaintext, err := d.Cipher.Open(user.MFASecretEnc, []byte(user.UserID))
	if err != nil {
		return "", err
	}
	return string(plaintext), nil
}

// maskEmail partially hides an address for display.
//
// Enough that the user recognises their own account, not enough to turn the challenge
// page into an enumeration endpoint: the local part keeps its first character and the
// domain is shown whole, because seeing the right domain is most of what makes the
// display reassuring.
func maskEmail(email string) string {
	at := -1
	for i := 0; i < len(email); i++ {
		if email[i] == '@' {
			at = i
			break
		}
	}
	if at <= 0 {
		return ""
	}
	local, domain := email[:at], email[at:]
	if len(local) <= 2 {
		return string(local[0]) + "*" + domain
	}
	return local[:1] + "***" + local[len(local)-1:] + domain
}
