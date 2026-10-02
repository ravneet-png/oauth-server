package domain

// A client attached to a session. SID is the per-client session identifier that
// appears in ID tokens and back-channel LogoutTokens.

import "time"

// ClientSession binds one client to one browser session.
//
// SID is the only identifier. An earlier draft carried both `id` and `sid` for
// the same value; two names for one thing invites divergence, and a divergence
// here is a LogoutToken that does not match the sid in the ID token.
//
// There is deliberately NO UserID. It is derivable through SessionID, and a
// denormalised copy can silently drift. The failure mode of that drift is
// specific and bad: the erasure flow gathers rows by user_id to send back-channel
// logout, and a stale copy means no logout is sent, so the client keeps
// believing the user is still signed in after their account has been deleted.
//
// SID must be unguessable. It is a bearer identifier for the session: anything
// that can present a valid sid, or forge a LogoutToken carrying it, can terminate
// that client's session.
type ClientSession struct {
	// SID is the primary key.
	SID string

	SessionID string
	ClientID  string

	CreatedAt time.Time
}

// SameClient reports whether other is an attachment for the same client and
// session. Used to make Upsert idempotent rather than inserting a duplicate sid
// on every repeat authorization.
func (cs *ClientSession) SameClient(other *ClientSession) bool {
	return other != nil &&
		cs.SessionID == other.SessionID &&
		cs.ClientID == other.ClientID
}

// BelongsToSession reports whether this attachment belongs to sessionID.
func (cs *ClientSession) BelongsToSession(sessionID string) bool {
	return cs.SessionID == sessionID
}
