package domain

// A lineage of refresh tokens from one authorization grant. Holds the absolute
// expiry that stops rotation from extending a session forever.

import "time"

// TokenFamily is the set of refresh tokens descending from one authorization
// grant, plus the absolute ceiling that bounds all of them.
//
// Without the ceiling a client rotating every 29 days holds one grant open
// indefinitely, and neither logout nor idle expiry can ever catch it: the
// lineage is never idle because it is always being rotated. Revoking a family
// is what makes reuse detection able to respond to a stolen token at all,
// since a stolen refresh token can otherwise be rotated forever alongside the
// legitimate one.
//
// Assigned at authorization-code insert time, never by a later UPDATE.
type TokenFamily struct {
	FamilyID string
	UserID   string
	ClientID string

	// SourceAuthCodeHash records which code seeded this family. No foreign
	// key, deliberately: codes are reaped long before the refresh tokens they
	// seeded expire.
	SourceAuthCodeHash *string

	AbsoluteExpiresAt time.Time

	RevokedAt        *time.Time
	RevocationReason *string

	CreatedAt time.Time
}

// IsRevoked reports whether the family has been revoked.
func (f *TokenFamily) IsRevoked() bool {
	return f.RevokedAt != nil
}

// IsUsable reports whether the family is still within its absolute lifetime at
// time now. A rotated token can be individually unexpired while its family is
// spent, so this check is not implied by RefreshToken.IsUsable.
func (f *TokenFamily) IsUsable(now time.Time) bool {
	return f.RevokedAt == nil && f.AbsoluteExpiresAt.After(now)
}

// IsExhausted reports whether the family's absolute ceiling has passed, which is
// the signal to stop accepting rotation even if the presented token is
// individually live.
func (f *TokenFamily) IsExhausted(now time.Time) bool {
	return !f.AbsoluteExpiresAt.After(now)
}

// OwnedBy reports whether this family was granted to clientID.
func (f *TokenFamily) OwnedBy(clientID string) bool {
	return f.ClientID == clientID
}
