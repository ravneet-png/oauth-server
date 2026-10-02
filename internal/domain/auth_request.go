// In-flight authorization request. Exists so that parameters survive the
// redirect chain through login and MFA. All validated request parameters are
// held in ParamsJSON, not in hand-picked columns.

package domain

import (
	"encoding/json"
	"time"
)

// NextStep is where the authorization flow should resume after a redirect. Not
// persisted: it is derived on read from which columns are populated, because a
// stored step can disagree with the columns it claims to describe.
type NextStep string

const (
	// NextStepLogin means no valid session; authenticate the user.
	NextStepLogin NextStep = "login"
	// NextStepMFA means authenticated but a second factor is outstanding.
	NextStepMFA NextStep = "mfa"
	// NextStepConsent means authenticated and assured; show or skip consent.
	NextStepConsent NextStep = "consent"
	// NextStepComplete means the code has been issued.
	NextStepComplete NextStep = "complete"
	// NextStepExpired means the request outlived its TTL. The caller must
	// discard it and restart from /authorize rather than resuming it.
	NextStepExpired NextStep = "expired"
)

// AuthRequest is an authorization request in flight, addressed by an opaque id
// carried in a cookie through the login and MFA redirects.
//
// This table is not tidy bookkeeping. Two requirements make it necessary:
//
//  1. PAR. A request_uri is single-use, so once consumed at /authorize a
//     refresh of the login page finds nothing and every validated parameter is
//     gone. The browser cannot carry them in the URL without exposing them in
//     history and referrer headers.
//
//  2. prompt and max_age. These must survive to the login decision. A request
//     validated at /authorize and partially re-parsed at /login loses them, and
//     prompt=none becomes impossible to honour, which is a silent security
//     downgrade rather than a visible failure.
//
// The full validated parameter set therefore lives in ParamsJSON rather than in
// columns chosen by hand. Every parameter validated at /authorize and then
// dropped is a bug waiting to happen, and one copy in JSON is exactly one parser.
type AuthRequest struct {
	ID string

	ClientID     string
	RedirectURI  string
	ResponseType string

	// Scope and the request parameters are denormalised onto columns for
	// indexing, but ParamsJSON remains the authority.
	Scope []string
	State *string
	Nonce *string

	CodeChallenge       string
	CodeChallengeMethod string

	// Filled in as the flow progresses. NULL until the relevant step is done.
	UserID    *string
	SessionID *string
	AuthTime  *time.Time

	// ParamsJSON holds the complete validated request verbatim.
	ParamsJSON json.RawMessage

	ExpiresAt time.Time

	// CompletedAt is the single-use marker. The consent handler completes this
	// with a completed_at IS NULL guard; without that guard a double-submitted
	// consent form mints two authorization codes from one request.
	CompletedAt *time.Time

	CreatedAt time.Time
}

// IsCompleted reports whether a code has already been issued for this request.
func (r *AuthRequest) IsCompleted() bool {
	return r.CompletedAt != nil
}

// IsExpired reports whether the request has outlived its TTL at time now.
func (r *AuthRequest) IsExpired(now time.Time) bool {
	return !r.ExpiresAt.After(now)
}

// IsLive reports whether the request may still be advanced. Expiry is checked
// here rather than only when the request is created, because a user who leaves
// a login tab open must not be able to complete it an hour later.
func (r *AuthRequest) IsLive(now time.Time) bool {
	return r.CompletedAt == nil && r.ExpiresAt.After(now)
}

// IsAuthenticated reports whether a user has been established for this request.
func (r *AuthRequest) IsAuthenticated() bool {
	return r.UserID != nil && *r.UserID != ""
}

// HasSession reports whether a browser session has been attached.
func (r *AuthRequest) HasSession() bool {
	return r.SessionID != nil && *r.SessionID != ""
}

// NextStep derives where to resume at time now.
//
// Derived, never stored. A persisted step column has to be updated at every
// transition and can drift from the columns it describes; deriving it means
// there is nothing to keep in sync.
//
// The ordering is deliberate and is a security property, not a style choice:
//
//  1. Completion first, so a double-submitted consent form cannot re-enter.
//  2. Expiry second, so a request that timed out while the user was logging in
//     is discarded instead of being shown a consent screen. Falling through to
//     NextStepLogin would silently restart the flow with the same expired
//     parameters, which cannot succeed and looks like a login loop to the user.
//  3. Authentication last, so an unestablished user goes to login.
//
// A completed request may legitimately have a user and still must not re-enter,
// which is why completion is tested before authentication.
func (r *AuthRequest) NextStep(now time.Time) NextStep {
	switch {
	case r.IsCompleted():
		return NextStepComplete
	case r.IsExpired(now):
		return NextStepExpired
	case !r.IsAuthenticated():
		return NextStepLogin
	default:
		return NextStepConsent
	}
}
