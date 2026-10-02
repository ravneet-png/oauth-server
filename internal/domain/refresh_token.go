package domain

// A rotated refresh token. FamilyID links every token descending from one
// authorization grant, which is what makes reuse detection able to revoke a whole
// lineage.

import "time"

// Revocation reasons.
//
// This set is what lets a replay be told apart from an ordinary revocation.
// `rotated` means the presented token was already exchanged, which is the
// signature of a stolen token and cascades to the entire family. Every other
// value means the token was deliberately invalidated, and replaying it must NOT
// nuke the family: a user who logged out on one device and then retried a
// refresh from another would otherwise lose every session they have.
const (
	RevocationReasonRotated      = "rotated"
	RevocationReasonLogout       = "logout"
	RevocationReasonExplicit     = "explicit"
	RevocationReasonReuseCascade = "reuse_cascade"
	RevocationReasonGDPR         = "gdpr"
	RevocationReasonAdmin        = "admin"
)

// RefreshToken is an issued refresh token, stored by hash only.
//
// As with authorization codes, the plaintext exists only in the token response.
// Everything here is recoverable from the digest.
type RefreshToken struct {
	TokenHash string
	FamilyID  string
	ClientID  string
	UserID    string
	SessionID *string

	// SourceAuthCodeHash is the code this token descends from. No foreign key:
	// codes are reaped long before the refresh tokens they seeded expire, so
	// the reference is intentionally dangling. It is what lets reuse detection
	// find the access tokens issued alongside a replayed code.
	SourceAuthCodeHash *string

	// ReplacedByHash points at the token that superseded this one, which is
	// what supports the grace window that keeps a benign concurrent refresh from
	// being read as theft.
	ReplacedByHash *string

	Scope []string

	ExpiresAt time.Time

	// RevokedAt is the single marker for both rotation and revocation. There is
	// no Revoked bool: see AuthCode.UsedAt for why a nullable timestamp is the
	// only marker. RevocationReason must be non-nil exactly when RevokedAt is,
	// which refresh_tokens_revocation_chk enforces.
	RevokedAt        *time.Time
	RevocationReason *string

	CreatedAt time.Time
}

// IsRevoked reports whether the revocation marker is set.
func (t *RefreshToken) IsRevoked() bool {
	return t.RevokedAt != nil
}

// WasRotated reports whether this token was consumed by a rotation rather than
// revoked for any other reason. This is the exact condition that means "someone
// is replaying a token that already succeeded", and the only one that cascades.
func (t *RefreshToken) WasRotated() bool {
	return t.RevokedAt != nil && t.RevocationReason != nil &&
		*t.RevocationReason == RevocationReasonRotated
}

// IsExpired reports whether the token is past its idle expiry at time now.
func (t *RefreshToken) IsExpired(now time.Time) bool {
	return !t.ExpiresAt.After(now)
}

// IsUsable reports whether the token is neither revoked nor expired.
//
// As with AuthCode.IsUsable this is for pre-flight and display only. The
// authoritative rotation is the conditional UPDATE in the repository, which
// resolves the "exactly one of ten concurrent requests wins" requirement in the
// database rather than in application code.
func (t *RefreshToken) IsUsable(now time.Time) bool {
	return t.RevokedAt == nil && t.ExpiresAt.After(now)
}

// SameFamily reports whether other descends from the same authorization grant.
// Used as a guard before cascading a revocation: a replay must never be able to
// name an arbitrary family.
func (t *RefreshToken) SameFamily(other *RefreshToken) bool {
	return other != nil && t.FamilyID == other.FamilyID
}

// OwnedBy reports whether this token was issued to clientID. Reuse detection
// compares this before revoking anything: a token replayed by a different client
// must fail without touching the family, otherwise an attacker holding a stolen
// token can revoke a legitimate user's entire session.
func (t *RefreshToken) OwnedBy(clientID string) bool {
	return t.ClientID == clientID
}
