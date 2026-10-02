package domain

// Record of an issued access token, keyed by jti. Retained so that revocation,
// introspection and audit can resolve a self-contained JWT back to its origin.

import "time"

// IssuedAccessToken is the durable record of an access token this server minted.
//
// Access tokens are self-contained JWTs, which is what makes them cheap to
// verify but impossible to revoke without a lookup. This row is what that
// lookup resolves against. It answers four questions the JWT alone cannot: is
// this jti revoked, which access tokens descend from a replayed authorization
// code, which are attached to a browser session for scoped logout, and what was
// issued to whom for audit.
//
// JTI, not the token string. The token is self-describing; the jti is the only
// handle on it that is short, indexed, and safe to store.
type IssuedAccessToken struct {
	// JTI is the token's unique identifier claim. Primary key.
	JTI string

	// UserID is nil for a client_credentials grant, where there is no resource
	// owner. It is also set to nil on erasure rather than deleted, because the
	// record must outlive the user in order for the token to stay revocable.
	UserID *string

	ClientID           string
	SessionID          *string
	SourceAuthCodeHash *string

	Scope []string

	IssuedAt  time.Time
	ExpiresAt time.Time
}

// IsExpired reports whether the token is past its expiry at time now. The value
// to cache is the remaining lifetime, so this is the call that keeps a local
// validation cache honest.
func (t *IssuedAccessToken) IsExpired(now time.Time) bool {
	return !t.ExpiresAt.After(now)
}

// RemainingTTL returns how long the token is still valid at time now, or zero
// if it has expired.
func (t *IssuedAccessToken) RemainingTTL(now time.Time) time.Duration {
	if t.IsExpired(now) {
		return 0
	}
	return t.ExpiresAt.Sub(now)
}

// BelongsToSession reports whether this token was issued into a browser session,
// which is the predicate for scoped logout. A client_credentials token has no
// session and must survive a user logout.
func (t *IssuedAccessToken) BelongsToSession(sessionID string) bool {
	return t.SessionID != nil && *t.SessionID == sessionID
}

// IssuedFromCode reports whether this token descends from the given code hash.
func (t *IssuedAccessToken) IssuedFromCode(codeHash string) bool {
	return t.SourceAuthCodeHash != nil && *t.SourceAuthCodeHash == codeHash
}

// HasUser reports whether the token has a resource owner.
func (t *IssuedAccessToken) HasUser() bool {
	return t.UserID != nil && *t.UserID != ""
}
