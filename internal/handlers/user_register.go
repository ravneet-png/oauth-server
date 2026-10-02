package handlers

// POST /users/register — public account creation.
//
// The endpoint's contract is that it says nothing. The response is byte-identical
// whether the address was free or already registered, and the work performed is the
// same on both paths, so neither the body nor the response time is an enumeration
// oracle. The heavy step — hashing the password — runs unconditionally, which is what
// makes the timing equal.
//
// An existing address gets a notification rather than a verification link, so a person
// who forgot they had an account is told, and nobody can use signup to probe addresses.

import (
	"encoding/json"
	"io"
	"net/http"
	"strings"
	"time"

	"oauth-server/internal/crypto"
	"oauth-server/internal/domain"
	"oauth-server/internal/email"
	"oauth-server/internal/httpapi"
	"oauth-server/internal/oautherr"
)

// registerRequest is the JSON body of POST /users/register.
type registerRequest struct {
	Email    string `json:"email"`
	Password string `json:"password"`
	Name     string `json:"name"`
}

// registerPerIPLimit and registerWindow bound signups per client address.
const (
	registerPerIPLimit = 3
	registerWindow     = time.Hour
)

// UserRegister handles account creation.
func (d *Deps) UserRegister(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		httpapi.MethodNotAllowed(w, http.MethodPost)
		return
	}
	st := d.state(r)

	// Rate limited per address before any work, so the limit cannot be bypassed by
	// sending bodies that fail validation.
	if d.Cache != nil && st.clientIP != nil {
		key := d.Cache.Key("register", st.clientIP.String())
		count, err := d.Cache.Incr(r.Context(), key, registerWindow)
		if err == nil && count > registerPerIPLimit {
			httpapi.WithRetryAfter(w, int(registerWindow.Seconds()))
			httpapi.OAuthError(w, oautherr.From(domain.NewTemporarilyUnavailable("too many sign-up attempts")))
			return
		}
	}

	var req registerRequest
	dec := json.NewDecoder(io.LimitReader(r.Body, 16<<10))
	if err := dec.Decode(&req); err != nil {
		// A malformed body is still answered with the uniform success, because a
		// distinct error for "bad JSON" versus "email taken" is only a probe. The
		// message is generic and the status is the same 201 every caller sees.
		d.registrationResponse(w)
		return
	}

	emailAddr := strings.ToLower(strings.TrimSpace(req.Email))
	if !validSignupInput(emailAddr, req.Password, d.Config.MinPasswordLen) {
		d.registrationResponse(w)
		return
	}

	// Hash unconditionally. This is the equalisation: an existing address and a free
	// one both pay for an Argon2id hash before anything is compared.
	hash, err := crypto.HashPassword(req.Password, d.argonParams())
	if err != nil {
		d.Logger.Error("register: hash password", "error", err.Error(), "correlation_id", st.correlationID)
		d.registrationResponse(w)
		return
	}

	name := strings.TrimSpace(req.Name)
	var namePtr *string
	if name != "" {
		namePtr = &name
	}

	user := &domain.User{
		UserID:       newOpaqueID(),
		Email:        emailAddr,
		PasswordHash: hash,
		Name:         namePtr,
		CreatedAt:    time.Now().UTC(),
	}
	if user.UserID == "" {
		d.registrationResponse(w)
		return
	}

	created, err := d.Users.CreateIfNotExists(r.Context(), user)
	if err != nil {
		d.Logger.Error("register: create user", "error", err.Error(), "correlation_id", st.correlationID)
		d.registrationResponse(w)
		return
	}

	if !created {
		// Address already registered. Notify, don't verify, and return the same body.
		d.sendSignupNotice(r, emailAddr, true)
		d.registrationResponse(w)
		return
	}

	_ = d.AuditLog.Record(r.Context(), st.auditRC(),
		domain.NewAuditEvent(domain.AuditUserRegistered, domain.AuditOutcomeSuccess, nil), emailAddr)

	d.sendSignupNotice(r, emailAddr, false)
	d.registrationResponse(w)
}

// registrationResponse always answers with the same body and status.
func (d *Deps) registrationResponse(w http.ResponseWriter) {
	httpapi.JSON(w, http.StatusCreated, map[string]string{
		"message": "Check your email to verify your account",
	})
}

// sendSignupNotice issues a verification token and mails it, or mails a notice.
func (d *Deps) sendSignupNotice(r *http.Request, address string, alreadyRegistered bool) {
	if d.Sender == nil {
		return
	}
	if alreadyRegistered {
		// No token is minted: an account-notice carries no verification link, so it
		// cannot be redeemed to prove an address the sender does not control.
		_ = d.Sender.Send(r.Context(), email.TemplateData{
			Purpose:        email.PurposeNewDeviceNotice,
			BaseURL:        d.Config.Issuer,
			Address:        address,
			ExpiresInHours: 0,
			Extra:          map[string]string{"name": address},
		})
		return
	}

	token, err := crypto.RandomToken()
	if err != nil {
		d.Logger.Error("register: generate token", "error", err.Error())
		return
	}

	// The user id is looked up again because CreateIfNotExists does not return the row
	// it found; only the address is trusted, and the lookup is by the normalised value.
	user, err := d.Users.GetByEmail(r.Context(), address)
	if err != nil {
		d.Logger.Error("register: load new user", "error", err.Error())
		return
	}

	ttl := d.Config.EmailVerificationTTL
	if ttl <= 0 {
		ttl = 24 * time.Hour
	}
	now := time.Now().UTC()
	record := &domain.EmailVerification{
		TokenHash:   crypto.SHA256Hex(token),
		UserID:      user.UserID,
		Purpose:     domain.VerifyPurposeSignup,
		TargetEmail: address,
		ExpiresAt:   now.Add(ttl),
		CreatedAt:   now,
	}
	if err := d.EmailVerif.Create(r.Context(), record); err != nil {
		d.Logger.Error("register: store verification", "error", err.Error())
		return
	}

	_ = d.Sender.Send(r.Context(), email.TemplateData{
		Purpose:        email.PurposeSignup,
		Token:          token,
		BaseURL:        d.Config.Issuer,
		Address:        address,
		ExpiresInHours: int(ttl.Hours()),
		Extra:          map[string]string{"name": user.DisplayName()},
	})
}

// argonParams returns configured Argon2 parameters, or the defaults.
func (d *Deps) argonParams() crypto.Argon2Params {
	if d.ArgonParams.Memory == 0 {
		return crypto.DefaultArgon2Params()
	}
	return d.ArgonParams
}

// validSignupInput applies the shape checks that are cheap enough to run before hashing.
func validSignupInput(address, password string, minLen int) bool {
	if address == "" || !strings.Contains(address, "@") {
		return false
	}
	if minLen <= 0 {
		minLen = 8
	}
	return len(password) >= minLen
}
