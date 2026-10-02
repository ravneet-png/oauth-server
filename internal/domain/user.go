// End user. Email is stored lowercased and uniquely indexed on lower(email).
// MFA backup codes live in their own table, not on this struct.

package domain

import (
	"time"
)

// User is a registered end user.
type User struct {
	UserID string

	// Email is stored lowercased. The unique index is on lower(email) rather
	// than on the column, so a row written before normalisation still cannot
	// create a case-variant duplicate.
	Email        string
	PasswordHash string
	Name         *string

	EmailVerified bool

	MFAEnabled bool
	// AES-256-GCM ciphertext, bound to UserID as additional authenticated
	// data. []byte because the GCM output is binary; the schema column is BYTEA.
	// Converting to a string would mean hex or base64 somewhere, and a
	// base64-encoded key in a struct invites someone comparing two ciphertexts
	// with == as though they were plaintext.
	MFASecretEnc []byte
	// Highest TOTP counter consumed. A code is accepted only if its counter is
	// strictly greater, and both are updated in one statement, so two
	// concurrent submissions of the same code cannot both win.
	MFALastCounter int64

	FailedLoginCount  int
	LockedUntil       *time.Time
	PasswordChangedAt time.Time
	LastLoginAt       *time.Time

	IsAdmin    bool
	DisabledAt *time.Time

	CreatedAt time.Time
	UpdatedAt time.Time
}

// IsEnabled reports whether the user may currently authenticate.
func (u *User) IsEnabled() bool {
	return u.DisabledAt == nil
}

// IsLocked reports whether the account is inside its lockout window.
//
// Compared against an injected now rather than time.Now() so that lockout
// behaviour is testable and so that one request cannot disagree with itself
// across a slow database round-trip.
func (u *User) IsLocked(now time.Time) bool {
	return u.LockedUntil != nil && u.LockedUntil.After(now)
}

// HasMFA reports whether a second factor is enrolled and usable.
func (u *User) HasMFA() bool {
	return u.MFAEnabled && len(u.MFASecretEnc) > 0
}

// DisplayName returns Name if set, otherwise the local part of the address.
// Used for the consent screen, where showing a raw address where a name was
// available looks like a phishing page.
func (u *User) DisplayName() string {
	if u.Name != nil && *u.Name != "" {
		return *u.Name
	}
	for i := 0; i < len(u.Email); i++ {
		if u.Email[i] == '@' {
			return u.Email[:i]
		}
	}
	return u.Email
}
