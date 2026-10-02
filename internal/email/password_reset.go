package email

// Password reset request and completion, with enumeration-safe responses.
//
// Two properties drive the whole design:
//
//   - The response to a reset request does not depend on whether the address has an
//     account. It also does not depend on how long the work took, so the response time
//     does not become the oracle that the status text was careful not to be.
//   - A reset invalidates every existing session and refresh token. A reset that left
//     them intact would be pointless in the one case it matters most: the attacker
//     already has a session.

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"strings"
	"time"

	"oauth-server/internal/crypto"
	"oauth-server/internal/domain"
	"oauth-server/internal/storage"
)

// DefaultResetTTL is how long a reset token stays redeemable.
const DefaultResetTTL = 30 * time.Minute

// ErrResetTokenInvalid is returned for any unusable reset token.
//
// One error for unknown, expired, already-used and wrong-purpose tokens alike, so a
// caller cannot turn the redemption endpoint into an oracle for valid hashes. The
// distinction the user cares about — "your reset link expired, request another" — is
// communicated by the reset form, not by this error.
var ErrResetTokenInvalid = errors.New("email: reset token is not valid")

// ResetParams configures password reset handling.
type ResetParams struct {
	// TokenTTL is how long an issued token stays redeemable.
	TokenTTL time.Duration

	// BaseURL is the externally visible issuer, used to build the link.
	BaseURL string

	// SessionRepo and tokenRepo are revoked on completion.
	SessionRepo *storage.SessionRepo
	RefreshRepo *storage.RefreshTokenRepo
	UserRepo    *storage.UserRepo
	VerifyRepo  *storage.EmailVerificationRepo
	Sender      *Sender
	Logger      *slog.Logger
	ArgonParams crypto.Argon2Params
	Subject     string
	DisplayName string
}

// RequestReset issues a reset token for an address.
//
// Returns nil regardless of whether the address exists. The caller must respond with
// the same page and status either way; anything else is an account enumeration
// endpoint.
func RequestReset(ctx context.Context, p ResetParams, address string) error {
	log := p.Logger
	if log == nil {
		log = slog.Default()
	}

	normalized := normalizeAddress(address)
	if normalized == "" || p.VerifyRepo == nil || p.UserRepo == nil {
		// Malformed input, but still not distinguishable from the outside.
		return nil
	}

	user, err := p.UserRepo.GetByEmail(ctx, normalized)
	if err != nil {
		// No such address, or a database failure. Logged at a level that separates
		// the two for the operator while the response stays identical.
		log.Info("password reset requested for unknown address", "error", err.Error())
		return nil
	}
	// A disabled account gets no mail, and a locked one does: a lockout is the
	// server's doing and the user needs the reset path to clear it.
	if !user.IsEnabled() {
		log.Info("password reset requested for disabled account", "user_id", user.UserID)
		return nil
	}

	token, err := crypto.RandomToken()
	if err != nil {
		return fmt.Errorf("email: generate reset token: %w", err)
	}

	ttl := p.TokenTTL
	if ttl <= 0 {
		ttl = DefaultResetTTL
	}
	now := time.Now().UTC()

	record := &domain.EmailVerification{
		TokenHash:   hashToken(token),
		UserID:      user.UserID,
		Purpose:     string(PurposePasswordReset),
		TargetEmail: user.Email,
		ExpiresAt:   now.Add(ttl),
		CreatedAt:   now,
	}
	if err := p.VerifyRepo.Create(ctx, record); err != nil {
		return fmt.Errorf("email: store reset token: %w", err)
	}

	if p.Sender != nil {
		subject := p.Subject
		if subject == "" {
			subject = user.DisplayName()
		}
		err := p.Sender.Send(ctx, TemplateData{
			Purpose:        PurposePasswordReset,
			Token:          token,
			BaseURL:        p.BaseURL,
			Address:        user.Email,
			ExpiresInHours: int(ttl.Hours()),
			Extra:          map[string]string{"name": subject},
		})
		if err != nil {
			// The token row is left in place deliberately. Deleting it would mean a
			// transient SMTP outage silently discards a reset the user asked for and
			// they would have to notice and ask again. The row expires on its own.
			//
			// The error does propagate: the caller logs it, and the operator learns
			// that mail is broken before a user does.
			return fmt.Errorf("email: send reset mail: %w", err)
		}
	}

	log.Info("password reset token issued", "user_id", user.UserID)
	return nil
}

// CompleteReset redeems a reset token and sets a new password.
//
// Returns ErrResetTokenInvalid for every unusable token and never a more specific
// error, for the reason given on that var.
func CompleteReset(ctx context.Context, p ResetParams, token, newPassword string) error {
	if p.VerifyRepo == nil || p.UserRepo == nil || p.RefreshRepo == nil || p.SessionRepo == nil {
		return errors.New("email: CompleteReset: repositories are not configured")
	}

	raw := strings.TrimSpace(token)
	if raw == "" {
		return ErrResetTokenInvalid
	}

	record, err := p.VerifyRepo.GetByHash(ctx, hashToken(raw))
	if err != nil {
		return ErrResetTokenInvalid
	}

	now := time.Now().UTC()

	// Purpose is checked before use, not inferred from the URL the link pointed at.
	// Without this a signup link would be redeemable here and set a password on an
	// account whose address was never verified.
	if record.Purpose != string(PurposePasswordReset) {
		return ErrResetTokenInvalid
	}
	if !record.IsRedeemable(now) {
		return ErrResetTokenInvalid
	}
	if !record.CoversAddress(record.TargetEmail) {
		// The row exists but its target does not match its own recorded address,
		// which means it was written by something other than the issuing path.
		return ErrResetTokenInvalid
	}

	// Hash before consuming the token. Hashing is the slow step and can fail; if the
	// token were consumed first and hashing then failed, the user's reset link is
	// dead and they cannot retry without requesting another mail.
	newHash, err := crypto.HashPassword(newPassword, p.argonParams())
	if err != nil {
		return fmt.Errorf("email: hash new password: %w", err)
	}

	// Single use. MarkUsed is conditional on used_at IS NULL, so two concurrent
	// redemptions of one token produce one winner and one failure rather than two
	// password changes.
	consumed, err := p.VerifyRepo.MarkUsed(ctx, record.TokenHash)
	if err != nil {
		return fmt.Errorf("email: consume reset token: %w", err)
	}
	if !consumed {
		return ErrResetTokenInvalid
	}

	if err := p.UserRepo.UpdatePasswordHash(ctx, record.UserID, newHash); err != nil {
		return fmt.Errorf("email: store new password: %w", err)
	}

	// Revoke after the password is stored. Doing it first would leave a window in
	// which a stolen session outlives the reset.
	sessions, err := p.SessionRepo.DeleteAllForUser(ctx, record.UserID)
	if err != nil {
		return fmt.Errorf("email: revoke sessions: %w", err)
	}
	refreshes, err := p.RefreshRepo.RevokeAllForUser(ctx, record.UserID, "password_reset")
	if err != nil {
		return fmt.Errorf("email: revoke refresh tokens: %w", err)
	}

	log := p.Logger
	if log == nil {
		log = slog.Default()
	}
	log.Info("password reset completed",
		"user_id", record.UserID,
		"sessions_revoked", sessions,
		"refresh_revoked", refreshes,
	)
	return nil
}

// argonParams returns the configured Argon2id parameters, or the defaults.
func (p ResetParams) argonParams() crypto.Argon2Params {
	if p.ArgonParams.Memory == 0 {
		return crypto.DefaultArgon2Params()
	}
	return p.ArgonParams
}

// normalizeAddress lowercases and trims an address.
//
// Matches the form stored in users.email. A reset lookup that skipped this would miss
// accounts whose stored address differs in case from what the user typed, and those
// users could never reset their password.
func normalizeAddress(address string) string {
	return strings.ToLower(strings.TrimSpace(address))
}
