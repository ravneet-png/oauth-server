package domain

// Browser login session. Carries both idle and absolute expiry, plus the
// authentication context (acr, amr) established at login or MFA.

import (
	"net/netip"
	"time"
)

// Authentication method references. Used in Session.Amr and in the `amr` ID
// token claim.
const (
	AMRPwd  = "pwd"
	AMROTP  = "otp"
	AMRMFA  = "mfa"
	AMRBack = "backchannel"
)

// Authentication context class values. The levels are ordered by strength and
// are what `acr_values` is matched against.
const (
	ACRLevel0 = "0" // no authenticated factor
	ACRLevel1 = "1" // password
	ACRLevel2 = "2" // password plus second factor
)

// Session is a browser login session.
//
// It carries two expiries because they answer different questions. ExpiresAt
// is idle: it slides forward on activity. AbsoluteExpiresAt is a hard ceiling
// that never moves, so a session cannot be kept alive forever by a client that
// keeps sending requests. Sessions have the same pair as refresh token
// families, one level down.
//
// AuthTime alone is not enough to describe the login. It records when the user
// authenticated but not how, and "how" is what an `amr` claim, an `acr` value
// and a back-channel LogoutToken each need.
type Session struct {
	SessionID string
	UserID    string

	AuthTime time.Time

	// ExpiresAt is the idle deadline.
	ExpiresAt time.Time
	// AbsoluteExpiresAt is the hard ceiling regardless of activity.
	AbsoluteExpiresAt time.Time

	// Acr and Amr are the assurance established at authentication. Amr is
	// TEXT[] because one login can carry several methods: a password followed
	// by a second factor is ["pwd","otp"], not either one alone.
	Acr *string
	Amr []string

	// IPAddress is netip.Addr rather than a string because the schema column is
	// INET: the type rejects malformed input and compares natively. Recorded as
	// the peer address, and only trusted from X-Forwarded-For when the peer is
	// inside the configured trusted proxy set.
	IPAddress *netip.Addr

	UserAgent  *string
	CreatedAt  time.Time
	LastSeenAt time.Time
}

// IsIdleExpired reports whether the session has passed its sliding deadline.
func (s *Session) IsIdleExpired(now time.Time) bool {
	return !s.ExpiresAt.After(now)
}

// IsAbsolutelyExpired reports whether the session has passed its hard ceiling.
// Checked on every load: an idle check alone would let activity past the
// ceiling keep the session alive.
func (s *Session) IsAbsolutelyExpired(now time.Time) bool {
	return !s.AbsoluteExpiresAt.After(now)
}

// IsValid reports whether the session may still be used at time now.
func (s *Session) IsValid(now time.Time) bool {
	return !s.IsIdleExpired(now) && !s.IsAbsolutelyExpired(now)
}

// RemainingIdle returns how much longer the session survives without activity.
func (s *Session) RemainingIdle(now time.Time) time.Duration {
	if s.IsIdleExpired(now) {
		return 0
	}
	return s.ExpiresAt.Sub(now)
}

// MeetsACR reports whether the session satisfied a requested acr_values level.
// Comparison is exact string equality, not ordinal, because acr_values is a set
// of opaque identifiers defined by the profile in force and this server defines
// exactly two.
func (s *Session) MeetsACR(required []string) bool {
	if len(required) == 0 {
		return true
	}
	if s.Acr == nil {
		return false
	}
	for _, want := range required {
		if *s.Acr == want {
			return true
		}
	}
	return false
}

// UsedMFA reports whether this login involved a second factor. Consulted when
// deciding whether a step-up is required for a sensitive operation.
func (s *Session) UsedMFA() bool {
	return ScopeContains(s.Amr, AMRMFA) || ScopeContains(s.Amr, AMROTP)
}
