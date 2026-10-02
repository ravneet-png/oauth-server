package domain

// A user grant of scopes to a client. Scope comparison is set containment,
// never equality, so a narrowed request cannot silently shrink a prior grant.

import "time"

// Consent is a user's standing grant of scopes to one client.
//
// Comparison against a new request is set containment, not equality. A grant of
// [openid, email, profile] satisfies a later request for [openid, email] and
// must not re-prompt; equality would re-prompt on every narrowing, which trains
// users to click through the consent screen without reading it, and that habit
// is exactly what a malicious client is counting on.
//
// The reverse also holds: an expanded request must re-prompt, because consent to
// `email` is not consent to `profile`.
type Consent struct {
	UserID   string
	ClientID string

	Scopes    []string
	GrantedAt time.Time

	// LastUsedAt is updated whenever this grant authorises a request. It is the
	// signal a "revoke this app" screen sorts by, and the input to the
	// inactivity-based revocation prompt.
	LastUsedAt *time.Time

	// ExpiresAt drives periodic re-prompting. nil means consent does not expire
	// on its own, which is the correct default: indefinite consent that the user
	// granted deliberately is not a security problem, and nagging is.
	ExpiresAt *time.Time
}

// Covers reports whether this consent is sufficient for the given scopes, which
// is what lets /consent auto-skip.
func (c *Consent) Covers(requested []string) bool {
	return ScopeContainsAll(c.Scopes, requested)
}

// IsExpired reports whether the grant has passed its expiry at time now.
func (c *Consent) IsExpired(now time.Time) bool {
	return c.ExpiresAt != nil && !c.ExpiresAt.After(now)
}

// IsActive reports whether the consent currently satisfies requested: unexpired
// and a superset of it. Expiry is checked here rather than only at display,
// because a grant that lapsed an hour ago must still prompt.
func (c *Consent) IsActive(now time.Time, requested []string) bool {
	return !c.IsExpired(now) && c.Covers(requested)
}

// ScopeDelta returns the requested scopes this consent does not yet cover, which
// is what the consent screen shows as newly requested rather than merely
// permitted.
func (c *Consent) ScopeDelta(requested []string) []string {
	return ScopeMissing(c.Scopes, requested)
}
