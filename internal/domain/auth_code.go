package domain

// A single-use authorization code. Carries session_id and sid so that tokens
// derived from it can be revoked on scoped logout.

import "time"

// AuthCode is an authorization code, stored by hash only.
//
// The plaintext code exists exactly once, in the 302 redirect to the client.
// Nothing in this system persists it: storing the code means a database read is
// sufficient to impersonate the user at /token, so only the SHA-256 digest is
// kept. Compare in constant time when checking a presented code.
type AuthCode struct {
	CodeHash string
	ClientID string
	UserID   string

	// SessionID and SID are denormalised from the session that authorised this
	// code. Without them a token derived from this code cannot be traced back
	// to the browser session, and scoped logout has nothing to find.
	//
	// SID is the per-client session identifier that appears in ID tokens and
	// back-channel LogoutTokens. It must be unguessable: an attacker who can
	// predict a sid can forge a LogoutToken and terminate arbitrary sessions.
	SessionID *string
	SID       *string

	// FamilyID is assigned AT INSERT TIME by the consent step, not by a later
	// UPDATE. Writing it afterwards means a crash in between leaves a consumed
	// code with no family, and reuse detection has nothing to cascade over.
	FamilyID *string

	// Scope as presented at /authorize and to be re-verified at /token. Stored
	// per code rather than read back from the client row: the value presented at
	// /token must equal the value presented at /authorize, byte for byte.
	Scope []string

	// RedirectURI stored per code for the same reason as Scope.
	RedirectURI string

	CodeChallenge       string
	CodeChallengeMethod string
	Nonce               *string
	AuthTime            *time.Time

	ExpiresAt time.Time

	// UsedAt is the single-use marker. NULL means unused.
	//
	// There is no Used bool. A boolean alongside a timestamp is two sources of
	// truth that can drift, and the drift is always in the unsafe direction:
	// used=false with a non-null used_at would let the code be redeemed twice.
	// Consumption is one conditional UPDATE whose predicate carries every check
	// including ownership and expiry, and returns the row only if it won.
	UsedAt *time.Time

	CreatedAt time.Time
}

// IsUsable reports whether the code may still be redeemed at time now.
//
// This is a convenience for display and for pre-flight checks. It is NOT
// sufficient to decide redemption: the authoritative test is the conditional
// UPDATE in the repository, because a check-then-act pair here would reintroduce
// the race that the atomic UPDATE exists to remove.
func (c *AuthCode) IsUsable(now time.Time) bool {
	return c.UsedAt == nil && c.ExpiresAt.After(now)
}

// IsConsumed reports whether the single-use marker is set.
func (c *AuthCode) IsConsumed() bool {
	return c.UsedAt != nil
}

// WasIssuedFromSession reports whether this code was authorised by a browser
// session, which is what distinguishes it from a client_credentials grant.
func (c *AuthCode) HasSession() bool {
	return c.SessionID != nil && *c.SessionID != ""
}
