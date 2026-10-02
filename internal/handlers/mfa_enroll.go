package handlers

// GET and POST /mfa/enroll — self-service second-factor enrolment.
//
// Enrolment is two requests because it has to be: the server generates a secret it has
// not committed to, shows it, and only persists it once the user proves their
// authenticator can produce a valid code. A single request that both showed and enabled
// would lock out any user whose scanner failed on the first try.
//
// The half-finished state lives in Redis under an opaque id, never in a cookie the
// browser can edit and never in the user row: an abandoned enrolment must leave no
// enabled second factor behind.

import (
	"encoding/json"
	"net/http"
	"time"

	"oauth-server/internal/crypto"
	"oauth-server/internal/domain"
	"oauth-server/internal/httpapi"
	"oauth-server/internal/ui"
)

// mfaEnrollTTL bounds how long a scanned-but-unconfirmed secret stays valid.
const mfaEnrollTTL = 10 * time.Minute

// mfaEnrollState is the pending enrolment record.
type mfaEnrollState struct {
	UserID string `json:"user_id"`
	// SecretEnc is the seed sealed under the user id, matching how it will be stored.
	// The server never keeps the plaintext at rest, even for ten minutes.
	SecretEnc []byte `json:"secret_enc"`
	// Hashes are the backup-code hashes. The plaintexts exist only in the rendered page.
	Hashes []string `json:"hashes"`
}

// MFAEnroll handles enrolment.
func (d *Deps) MFAEnroll(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		d.mfaEnrollForm(w, r, "")
	case http.MethodPost:
		d.mfaEnrollSubmit(w, r)
	default:
		httpapi.MethodNotAllowed(w, http.MethodGet, http.MethodPost)
	}
}

// mfaEnrollForm generates a fresh secret and renders the enrolment page.
func (d *Deps) mfaEnrollForm(w http.ResponseWriter, r *http.Request, message string) {
	st := d.state(r)
	if !st.hasSession() {
		httpapi.SeeOther(w, r, "/login")
		return
	}
	user, err := d.Users.GetByID(r.Context(), st.userID)
	if err != nil {
		d.renderError(w, r, http.StatusInternalServerError, "server_error")
		return
	}

	if user.HasMFA() {
		// Already enrolled. Re-enrolling would silently replace a working factor; an
		// explicit disable step is the safe way to change it, and that is out of scope
		// here. Render the plain error rather than a half-form.
		d.renderError(w, r, http.StatusBadRequest, "already_enrolled")
		return
	}

	if d.Cipher == nil || d.Cache == nil {
		d.renderError(w, r, http.StatusInternalServerError, "server_error")
		return
	}

	secret, err := crypto.GenerateSecret()
	if err != nil {
		d.renderError(w, r, http.StatusInternalServerError, "server_error")
		return
	}

	secretEnc, err := d.Cipher.SealString(secret, []byte(user.UserID))
	if err != nil {
		d.renderError(w, r, http.StatusInternalServerError, "server_error")
		return
	}

	plaintexts, hashes, err := crypto.GenerateBackupCodes(10)
	if err != nil {
		d.renderError(w, r, http.StatusInternalServerError, "server_error")
		return
	}

	pendingID := newOpaqueID()
	if pendingID == "" {
		d.renderError(w, r, http.StatusInternalServerError, "server_error")
		return
	}
	state := mfaEnrollState{UserID: user.UserID, SecretEnc: secretEnc, Hashes: hashes}
	blob, err := json.Marshal(state)
	if err != nil {
		d.renderError(w, r, http.StatusInternalServerError, "server_error")
		return
	}
	if err := d.Cache.Set(r.Context(), d.Cache.Key("mfa_enroll", pendingID), string(blob), mfaEnrollTTL); err != nil {
		d.Logger.Error("mfa_enroll: store pending", "error", err.Error(), "correlation_id", st.correlationID)
		d.renderError(w, r, http.StatusInternalServerError, "server_error")
		return
	}

	params := crypto.DefaultTOTPParams(d.Config.MFAIssuer, user.Email)
	params.Secret = secret
	uri, err := crypto.ProvisioningURI(params)
	if err != nil {
		d.renderError(w, r, http.StatusInternalServerError, "server_error")
		return
	}

	qrDataURL, err := crypto.QRCodeDataURL(uri)
	if err != nil {
		d.renderError(w, r, http.StatusInternalServerError, "server_error")
		return
	}

	base := d.base(r, "Set up two-factor authentication")
	base.Error = message
	d.render(w, r, ui.PageMFAEnroll, http.StatusOK, ui.MFAEnrollData{
		Base:            base,
		Secret:          secret,
		PendingID:       pendingID,
		ProvisioningURI: uri,
		QRCodeDataURL:   qrDataURL,
		BackupCodes:     plaintexts,
	})
}

// mfaEnrollSubmit confirms the authenticator and persists the second factor.
func (d *Deps) mfaEnrollSubmit(w http.ResponseWriter, r *http.Request) {
	if !parseForm(r) {
		d.mfaEnrollForm(w, r, "The form could not be read. Please try again.")
		return
	}
	st := d.state(r)
	if !st.hasSession() {
		httpapi.SeeOther(w, r, "/login")
		return
	}

	pendingID := stringParam(r, "pending_id")
	code := stringParam(r, "code")
	if pendingID == "" || d.Cache == nil {
		d.renderError(w, r, http.StatusBadRequest, "invalid_request")
		return
	}

	raw, err := d.Cache.Get(r.Context(), d.Cache.Key("mfa_enroll", pendingID))
	if err != nil {
		// Expired or never existed. The safe answer is to restart, not to enable
		// anything: without the pending state there is no secret to bind the code to.
		d.mfaEnrollForm(w, r, "Your setup session expired. Please start again.")
		return
	}
	var state mfaEnrollState
	if err := json.Unmarshal([]byte(raw), &state); err != nil {
		d.renderError(w, r, http.StatusInternalServerError, "server_error")
		return
	}
	// The pending record must belong to the signed-in user. Without this a leaked
	// pending id would let one session complete another account's enrolment.
	if state.UserID != st.userID {
		d.renderError(w, r, http.StatusForbidden, "access_denied")
		return
	}

	secret, err := d.Cipher.Open(state.SecretEnc, []byte(state.UserID))
	if err != nil {
		d.renderError(w, r, http.StatusInternalServerError, "server_error")
		return
	}

	// Verify against the pending secret directly rather than through authn.Verifier:
	// that verifier reads the user row, which does not carry the secret yet, and it
	// advances the replay counter, which is meaningless for an uncommitted enrolment.
	params := crypto.DefaultTOTPParams("", "")
	params.Secret = string(secret)
	counter, err := crypto.VerifyTOTP(params, normalizeTOTPInput(code), time.Now().UTC(), 0)
	if err != nil {
		d.mfaEnrollForm(w, r, "That code is not valid. Check the time on your device and try again.")
		return
	}

	// Persist codes first, then enable. If enabling fails, unreachable hashed codes
	// remain; the reverse order could enable MFA with no recovery codes, which is the
	// one state that can lock a user out permanently.
	if err := d.Users.UpdateBackupCodes(r.Context(), st.userID, state.Hashes); err != nil {
		d.Logger.Error("mfa_enroll: store backup codes", "error", err.Error(), "correlation_id", st.correlationID)
		d.renderError(w, r, http.StatusInternalServerError, "server_error")
		return
	}
	if err := d.Users.UpdateMFA(r.Context(), st.userID, state.SecretEnc, true); err != nil {
		d.Logger.Error("mfa_enroll: enable mfa", "error", err.Error(), "correlation_id", st.correlationID)
		d.renderError(w, r, http.StatusInternalServerError, "server_error")
		return
	}
	// The counter observed at confirmation is the floor for replay protection. A failure
	// to persist it is not fatal: the next login re-derives it.
	if err := d.Users.UpdateMFALastCounter(r.Context(), st.userID, int64(counter)); err != nil {
		d.Logger.Warn("mfa_enroll: persist counter", "error", err.Error(), "correlation_id", st.correlationID)
	}

	_ = d.Cache.Delete(r.Context(), d.Cache.Key("mfa_enroll", pendingID))
	_ = d.AuditLog.Record(r.Context(), st.auditRC(),
		domain.NewAuditEvent(domain.AuditMFAEnrolled, domain.AuditOutcomeSuccess, &st.userID), st.userID)

	httpapi.SeeOther(w, r, "/")
}

// normalizeTOTPInput strips the separators an authenticator app may display.
func normalizeTOTPInput(code string) string {
	out := make([]byte, 0, len(code))
	for i := 0; i < len(code); i++ {
		switch code[i] {
		case ' ', '-', '\t':
		default:
			out = append(out, code[i])
		}
	}
	return string(out)
}
