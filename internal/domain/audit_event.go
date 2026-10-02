package domain

// A typed audit event. Structurally incapable of carrying free-form PII, so
// that erasure can be provably complete.

import (
	"encoding/json"
	"net/netip"
)

// Audit event names. A closed set, because `event` is the index every incident
// response starts from: an unlisted value is an unqueryable one.
const (
	AuditUserLogin            = "user.login"
	AuditUserLoginFailed      = "user.login_failed"
	AuditUserLogout           = "user.logout"
	AuditUserRegistered       = "user.registered"
	AuditEmailVerified        = "user.email_verified"
	AuditEmailChangeRequested = "user.email_change_requested"
	AuditPasswordChanged      = "user.password_changed"
	AuditPasswordReset        = "user.password_reset"
	AuditAccountLocked        = "user.account_locked"
	AuditMFAEnrolled          = "user.mfa_enrolled"
	AuditMFADisabled          = "user.mfa_disabled"
	AuditMFAFailed            = "user.mfa_failed"
	AuditMFABackupCodeUsed    = "user.mfa_backup_code_used"
	AuditConsentGranted       = "consent.granted"
	AuditConsentRevoked       = "consent.revoked"

	AuditCodeIssued         = "code.issued"
	AuditCodeReuseDetected  = "code.reuse_detected"
	AuditTokenIssued        = "token.issued"
	AuditTokenRefreshed     = "token.refreshed"
	AuditTokenFamilyRevoked = "token.family_revoked"
	AuditTokenRevoked       = "token.revoked"
	AuditTokenIntrospected  = "token.introspected"

	AuditClientRegistered = "client.registered"
	AuditClientUpdated    = "client.updated"
	AuditClientDisabled   = "client.disabled"
	AuditClientAuthFailed = "client.auth_failed"

	AuditKeyGenerated = "key.generated"
	AuditKeyRotated   = "key.rotated"
	AuditKeyDestroyed = "key.destroyed"

	AuditUserErased            = "user.erased"
	AuditBackchannelLogoutSent = "logout.backchannel_sent"
	AuditBackchannelLogoutFail = "logout.backchannel_failed"
)

// AuditOutcomes. Recorded as a closed set so that filtering on "did this
// succeed" is a query, not a substring search.
const (
	AuditOutcomeSuccess = "success"
	AuditOutcomeFailure = "failure"
	AuditOutcomeDenied  = "denied"
)

// AuditActorRedacted is the placeholder written over an actor or target during
// erasure.
//
// A fixed literal rather than a hash or a truncation. A pseudonymised value
// that is still stable is still a join key: an attacker holding a candidate list
// of email addresses re-identifies the row by recomputing the digest. Erasure
// has to be irreversible to be erasure.
const AuditActorRedacted = "DELETED"

// AuditEvent is one row of the audit log.
//
// Every field that could hold personal data is a named column, not a slot in a
// free-form map. An earlier draft used `Details map[string]interface{}`, and
// `Details - 'email'` was the erasure plan; that is unsound, because JSONB
// minus only removes top-level keys and leaves {"ctx":{"email":...}} intact.
// Naming the fields makes the set of places PII can live closed and known,
// which is the only way "erasure is complete" is a statement you can check
// rather than assert.
//
// Actor and Target hold pseudonymous identifiers, not raw email addresses: an
// HMAC-SHA256 of the lowercased address under a server-side pepper, because an
// email address is low entropy and a bare SHA-256 is reversible from any
// rainbow table.
type AuditEvent struct {
	// Event is one of the Audit* constants above.
	Event string

	// Outcome is one of the AuditOutcome* constants.
	Outcome string

	// Actor is the pseudonymised principal who caused the event: a user, a
	// client, or an administrator. nil for anonymous or system-initiated.
	Actor *string

	// Target is the pseudonymised subject the event acted on. nil when not
	// applicable.
	Target *string

	// SessionID is the browser session the event occurred in, nil when the
	// request was not session-authenticated.
	SessionID *string

	// IPAddress is netip.Addr, matching the INET column.
	IPAddress *netip.Addr

	UserAgent     *string
	CorrelationID string

	// ClientID is a non-personal identifier recorded separately so that
	// per-client investigations do not have to reason about Actor.
	ClientID *string

	// The remaining fields are the closed set of extra facts a given event type
	// may carry. Each is optional and each is a known shape, so the audit writer
	// knows exactly what it is serialising.
	ResourceType  string
	ResourceID    string
	Reason        string
	FailureReason string
}

// NewAuditEvent returns an event with the common fields set. Taking an actor as
// a pointer rather than a string keeps "no actor" distinguishable from "empty
// actor", which would otherwise be silently pseudonymised into a digest of "".
func NewAuditEvent(event, outcome string, actor *string) AuditEvent {
	return AuditEvent{
		Event:   event,
		Outcome: outcome,
		Actor:   actor,
	}
}

// WithTarget returns a copy attributed to a target.
func (e AuditEvent) WithTarget(target *string) AuditEvent {
	e.Target = target
	return e
}

// WithCorrelation returns a copy carrying a correlation ID, which is what lets
// an investigator reconstruct one request across log lines.
func (e AuditEvent) WithCorrelation(correlationID string) AuditEvent {
	e.CorrelationID = correlationID
	return e
}

// WithReason returns a copy carrying a machine-readable reason.
//
// The reason for a successful event: what was done.
func (e AuditEvent) WithReason(reason string) AuditEvent {
	e.Reason = reason
	return e
}

// WithFailureReason returns a copy carrying the reason a request was refused.
//
// Separate from Reason rather than a shared field because the two are read by
// different queries: `reason` answers "what did this event do", and
// `failure_reason` answers "why was this denied", which is the one an incident
// response filters on. Overloading one column means every failure query also
// matches successful events whose reason happens to share a word.
func (e AuditEvent) WithFailureReason(reason string) AuditEvent {
	e.FailureReason = reason
	return e
}

// WithClient returns a copy attributed to a client.
func (e AuditEvent) WithClient(clientID string) AuditEvent {
	id := clientID
	e.ClientID = &id
	return e
}

// WithResource returns a copy identifying the object acted on.
func (e AuditEvent) WithResource(resourceType, resourceID string) AuditEvent {
	e.ResourceType = resourceType
	e.ResourceID = resourceID
	return e
}

// WithSession returns a copy tied to a browser session.
func (e AuditEvent) WithSession(sessionID string) AuditEvent {
	id := sessionID
	e.SessionID = &id
	return e
}

// WithClientIP returns a copy carrying the peer address.
func (e AuditEvent) WithClientIP(addr *netip.Addr) AuditEvent {
	e.IPAddress = addr
	return e
}

// WithUserAgent returns a copy carrying the request's user agent.
func (e AuditEvent) WithUserAgent(ua string) AuditEvent {
	e.UserAgent = &ua
	return e
}

// MarshalDetails serialises the closed set of detail fields into the JSONB
// details column.
//
// omitempty throughout: an absent field writes no key, so the stored document
// contains exactly the facts that apply to this event type and nothing else.
// That is what makes the erasure argument checkable by reading one row.
func (e AuditEvent) MarshalDetails() (json.RawMessage, error) {
	payload := struct {
		ResourceType  string `json:"resource_type,omitempty"`
		ResourceID    string `json:"resource_id,omitempty"`
		Reason        string `json:"reason,omitempty"`
		FailureReason string `json:"failure_reason,omitempty"`
		ClientID      string `json:"client_id,omitempty"`
		Outcome       string `json:"outcome,omitempty"`
	}{
		ResourceType:  e.ResourceType,
		ResourceID:    e.ResourceID,
		Reason:        e.Reason,
		FailureReason: e.FailureReason,
		ClientID:      derefOrEmpty(e.ClientID),
		Outcome:       e.Outcome,
	}
	return json.Marshal(payload)
}

// derefOrEmpty returns the pointed-to string, or "" for nil.
func derefOrEmpty(s *string) string {
	if s == nil {
		return ""
	}
	return *s
}
