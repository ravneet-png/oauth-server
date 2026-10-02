package domain

// An email verification or change-email token.

import (
	"strings"
	"time"
)

// Verification purposes.
const (
	VerifyPurposeSignup        = "signup"
	VerifyPurposeChangeEmail   = "change_email"
	VerifyPurposePasswordReset = "password_reset"
)

// EmailVerification is a single-use token proving control of an address.
//
// Purpose and TargetEmail are what stop a token issued for one address from
// confirming a different one. A verification token must bind to the ADDRESS
// BEING CLAIMED, not to the address already on the account: without
// TargetEmail an attacker who can trigger a reset for an address they do not
// control would receive a token whose lookup matched the victim's row and marked
// the victim's address verified, or worse, redirected the account to the
// attacker's.
//
// AttemptCount bounds guessing per token, independently of the global rate
// limiter, so that a low-entropy 6-digit code cannot be brute forced by
// distributing attempts across many source addresses.
type EmailVerification struct {
	// TokenHash, not the token. Same reasoning as authorization codes: a
	// plaintext in the table would make a database read equivalent to
	// account takeover.
	TokenHash string
	UserID    string

	Purpose string

	// TargetEmail is the address being claimed, normalised to lower case.
	TargetEmail string

	ExpiresAt time.Time

	// UsedAt is the single-use marker. NULL means unused; there is no Used bool.
	UsedAt *time.Time

	// AttemptCount counts failed submissions against this token.
	AttemptCount int

	CreatedAt time.Time
}

// IsUsed reports whether the token has been consumed.
func (v *EmailVerification) IsUsed() bool {
	return v.UsedAt != nil
}

// IsExpired reports whether the token has passed its expiry at time now.
func (v *EmailVerification) IsExpired(now time.Time) bool {
	return !v.ExpiresAt.After(now)
}

// IsRedeemable reports whether the token can still be used, and whether it may
// still be attempted.
//
// Expired and already-used both stop redemption; exhausted stops only further
// guessing. Collapsing all three into one state would either let a used token
// be retried, or tell an attacker they have run out of attempts.
func (v *EmailVerification) IsRedeemable(now time.Time) bool {
	return v.UsedAt == nil && v.ExpiresAt.After(now)
}

// AttemptsRemaining returns how many more guesses this token tolerates given
// limit, or zero if the limit has been reached.
func (v *EmailVerification) AttemptsRemaining(limit int) int {
	if limit <= 0 {
		return 0
	}
	remaining := limit - v.AttemptCount
	if remaining < 0 {
		return 0
	}
	return remaining
}

// CoversAddress reports whether this token verifies target, which is what makes
// TargetEmail load-bearing.
//
// Both sides are lower-cased here rather than trusting the caller to have
// normalised first. TargetEmail is documented as stored lower case, but a
// comparison that silently fails on a case difference is a lockout bug: the
// user clicks a link, the address is correct, and verification is refused
// because one code path forgot. Normalising at the comparison is idempotent, so
// doing it again costs nothing and removes the dependency on caller
// discipline.
func (v *EmailVerification) CoversAddress(target string) bool {
	return strings.ToLower(v.TargetEmail) == strings.ToLower(target)
}
