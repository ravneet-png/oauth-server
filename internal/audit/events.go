package audit

// The typed event catalogue. Denials are recorded as well as grants; a failed registration attempt is not logged as a successful registration.

import (
	"context"

	"oauth-server/internal/domain"
)

// This file is the catalogue: one function per security-relevant action, each
// building the exact domain.AuditEvent for that action.
//
// The reason these exist rather than having call sites assemble events inline is
// drift. A login failure recorded with AuditOutcomeSuccess because a caller passed
// the wrong constant is invisible in review and fatal in investigation, and the
// only reliable defence is that there is exactly one place that decides what a
// "failed login" event looks like. Every function here takes the identifiers and
// nothing else: no free-form description, no map of extra facts.

// UserLoggedIn records a successful password authentication.
//
// sessionID is recorded because "which session was this" is the first question of
// any account-takeover investigation, and it cannot be reconstructed from timestamps
// alone when a user has several concurrent sessions.
func (l *Logger) UserLoggedIn(ctx context.Context, rc RequestContext, userID, sessionID string) error {
	ev := domain.NewAuditEvent(domain.AuditUserLogin, domain.AuditOutcomeSuccess, nil).
		WithReason("password authentication succeeded")
	if sessionID != "" {
		ev = ev.WithSession(sessionID)
	}
	return l.Log(ctx, rc.Apply(ev))
}

// UserLoginFailed records a rejected authentication.
//
// The reason is a controlled vocabulary rather than free text. The operational
// distinction that matters is lockout: a burst of failures that all say
// "account_locked" is an attack on a specific account, and a burst of
// "bad_credentials" is a credential-stuffing run across many accounts. Those two
// look identical in an access log and completely different here.
//
// The username is recorded when one was supplied, so repeated failures against one
// address are visible, but the password never reaches this function at all.
func (l *Logger) UserLoginFailed(ctx context.Context, rc RequestContext, userID, reason string) error {
	ev := domain.NewAuditEvent(domain.AuditUserLoginFailed, domain.AuditOutcomeFailure, nil).
		WithReason(reason).
		WithFailureReason(reason)
	return l.recordWithActor(ctx, rc, ev, userID)
}

// UserAccountLocked records the transition into a locked state.
//
// A separate event from the failure that caused it. "Someone tried the wrong
// password" is noise at any volume; "this account is now locked" is the signal that
// warrants paging, and it is the event that must not be lost if the failure events
// are dropped for volume.
func (l *Logger) UserAccountLocked(ctx context.Context, rc RequestContext, userID string) error {
	ev := domain.NewAuditEvent(domain.AuditAccountLocked, domain.AuditOutcomeDenied, nil).
		WithReason("too many failed authentications")
	return l.recordWithActor(ctx, rc, ev, userID)
}

// UserRegistered records account creation.
//
// userEmail is required here, unlike most events: registration is the one moment
// where the address is the subject of the record rather than an attribute of an
// existing subject. It is pseudonymised on the way in like everything else.
func (l *Logger) UserRegistered(ctx context.Context, rc RequestContext, userID, userEmail string) error {
	ev := domain.NewAuditEvent(domain.AuditUserRegistered, domain.AuditOutcomeSuccess, nil).
		WithReason("account created")
	return l.Log(ctx, l.attach(rc, ev, userEmail))
}

// UserEmailVerified records successful verification of an address.
func (l *Logger) UserEmailVerified(ctx context.Context, rc RequestContext, userID, userEmail string) error {
	ev := domain.NewAuditEvent(domain.AuditEmailVerified, domain.AuditOutcomeSuccess, nil).
		WithReason("address verified")
	return l.Log(ctx, l.attach(rc, ev, userEmail))
}

// PasswordChanged records a successful credential change.
//
// SessionID is included when the change was made from an authenticated session,
// which is what lets an operator answer "was this the user's own action or a
// takeover" by comparing against the sessions active at the time.
func (l *Logger) PasswordChanged(ctx context.Context, rc RequestContext, userID, sessionID string) error {
	ev := domain.NewAuditEvent(domain.AuditPasswordChanged, domain.AuditOutcomeSuccess, nil).
		WithReason("password changed")
	if sessionID != "" {
		ev = ev.WithSession(sessionID)
	}
	return l.recordWithActor(ctx, rc, ev, userID)
}

// MFAEnrolled records a second factor being added.
//
// Including the session is the point of the event: enrolling a factor is the single
// most valuable preparation step for an account takeover, because it converts a
// password-only compromise into a two-step one. An enrolment from a session the user
// did not open moments ago is the finding.
func (l *Logger) MFAEnrolled(ctx context.Context, rc RequestContext, userID, sessionID string) error {
	ev := domain.NewAuditEvent(domain.AuditMFAEnrolled, domain.AuditOutcomeSuccess, nil).
		WithReason("second factor enrolled")
	if sessionID != "" {
		ev = ev.WithSession(sessionID)
	}
	return l.recordWithActor(ctx, rc, ev, userID)
}

// MFADisabled records a second factor being removed.
//
// Also includes the session, for the same reason in reverse: disabling MFA is how an
// attacker prevents a takeover from being interrupted.
func (l *Logger) MFADisabled(ctx context.Context, rc RequestContext, userID, sessionID string) error {
	ev := domain.NewAuditEvent(domain.AuditMFADisabled, domain.AuditOutcomeSuccess, nil).
		WithReason("second factor removed")
	if sessionID != "" {
		ev = ev.WithSession(sessionID)
	}
	return l.recordWithActor(ctx, rc, ev, userID)
}

// MFAFailed records a rejected second factor.
//
// A separate event from UserLoginFailed because the response to each is different:
// a lockout triggered by MFA failures is the strongest available signal of an
// attacker who already holds the password, which is precisely the case where
// letting them keep trying is the wrong outcome.
func (l *Logger) MFAFailed(ctx context.Context, rc RequestContext, userID, reason string) error {
	ev := domain.NewAuditEvent(domain.AuditMFAFailed, domain.AuditOutcomeFailure, nil).
		WithReason(reason).
		WithFailureReason(reason)
	return l.recordWithActor(ctx, rc, ev, userID)
}

// MFABackupCodeUsed records a successful recovery-code authentication.
//
// Recorded distinctly from MFASucceeded-with-TOTP because consuming a backup code is
// a signal in itself: it means either the user lost their authenticator, or someone
// else has it. The count of these against one account is the input to that judgement.
func (l *Logger) MFABackupCodeUsed(ctx context.Context, rc RequestContext, userID, sessionID string) error {
	ev := domain.NewAuditEvent(domain.AuditMFABackupCodeUsed, domain.AuditOutcomeSuccess, nil).
		WithReason("backup code accepted")
	if sessionID != "" {
		ev = ev.WithSession(sessionID)
	}
	return l.recordWithActor(ctx, rc, ev, userID)
}

// ConsentGranted records a user authorising a client.
//
// clientID goes in the dedicated column rather than the actor slot, because it is a
// non-personal identifier and per-client investigation must not require reasoning
// about the pseudonymous actor.
func (l *Logger) ConsentGranted(ctx context.Context, rc RequestContext, userID, clientID string) error {
	ev := domain.NewAuditEvent(domain.AuditConsentGranted, domain.AuditOutcomeSuccess, nil).
		WithClient(clientID).
		WithResource("client", clientID).
		WithReason("scopes granted")
	return l.recordWithActor(ctx, rc, ev, userID)
}

// ConsentRevoked records a grant being withdrawn.
func (l *Logger) ConsentRevoked(ctx context.Context, rc RequestContext, userID, clientID string) error {
	ev := domain.NewAuditEvent(domain.AuditConsentRevoked, domain.AuditOutcomeSuccess, nil).
		WithClient(clientID).
		WithResource("client", clientID).
		WithReason("scopes revoked")
	return l.recordWithActor(ctx, rc, ev, userID)
}

// TokenIssued records an access token grant.
//
// grantType and clientID are what make this searchable; the token itself never
// appears, because a log full of bearer credentials is a log that has to be
// treated as a credential store and rotated on its own schedule.
func (l *Logger) TokenIssued(ctx context.Context, rc RequestContext, clientID, userID, grantType string) error {
	ev := domain.NewAuditEvent(domain.AuditTokenIssued, domain.AuditOutcomeSuccess, nil).
		WithClient(clientID).
		WithResource("client", clientID).
		WithReason(grantType)
	return l.recordWithActor(ctx, rc, ev, userID)
}

// TokenRefreshed records a successful rotation.
//
// Not an informational event. A refresh token presented from an address or session
// that never obtained it is the detectable form of token theft, and the only way to
// see that is a per-refresh record with an actor attached.
func (l *Logger) TokenRefreshed(ctx context.Context, rc RequestContext, clientID, userID string) error {
	ev := domain.NewAuditEvent(domain.AuditTokenRefreshed, domain.AuditOutcomeSuccess, nil).
		WithClient(clientID).
		WithResource("client", clientID).
		WithReason("refresh_token grant")
	return l.recordWithActor(ctx, rc, ev, userID)
}

// TokenFamilyRevoked records the cascade that follows reuse detection.
//
// The highest-value event in the token catalogue: reuse of a rotated refresh token
// is proof that a token was captured, and the family revocation is the containment
// action. Recorded with outcome denied because the presented token was, in fact,
// refused.
func (l *Logger) TokenFamilyRevoked(ctx context.Context, rc RequestContext, clientID, userID, reason string) error {
	ev := domain.NewAuditEvent(domain.AuditTokenFamilyRevoked, domain.AuditOutcomeDenied, nil).
		WithClient(clientID).
		WithReason(reason).
		WithFailureReason(reason)
	return l.recordWithActor(ctx, rc, ev, userID)
}

// TokenRevoked records an explicit revocation.
func (l *Logger) TokenRevoked(ctx context.Context, rc RequestContext, clientID, userID, tokenType string) error {
	ev := domain.NewAuditEvent(domain.AuditTokenRevoked, domain.AuditOutcomeSuccess, nil).
		WithClient(clientID).
		WithReason(tokenType + " revoked")
	return l.recordWithActor(ctx, rc, ev, userID)
}

// TokenIntrospected records an introspection call.
//
// Logged because introspection is an oracle: a client that can introspect can ask the
// server what it thinks about a token it does not hold. The event stream is what
// makes that observable.
func (l *Logger) TokenIntrospected(ctx context.Context, rc RequestContext, clientID string, active bool) error {
	outcome := domain.AuditOutcomeSuccess
	if !active {
		outcome = domain.AuditOutcomeDenied
	}
	ev := domain.NewAuditEvent(domain.AuditTokenIntrospected, outcome, nil).
		WithClient(clientID).
		WithReason("introspection")
	return l.Log(ctx, rc.Apply(ev))
}

// ClientAuthFailed records a rejected client credential.
//
// A failure only: a successful client authentication is not a distinct event in the
// closed set, because the token-issued row that immediately follows it is the record,
// and the two share a correlation ID. Recording both would double the write volume
// of the busiest endpoint in the system for no investigative gain.
//
// The method name is recorded because "the client authenticated with
// client_secret_post" and "with private_key_jwt" are materially different security
// postures, and a downgrade to the weaker one after a registration change is a real
// finding.
func (l *Logger) ClientAuthFailed(ctx context.Context, rc RequestContext, clientID, method string) error {
	ev := domain.NewAuditEvent(domain.AuditClientAuthFailed, domain.AuditOutcomeFailure, nil).
		WithClient(clientID).
		WithReason(method).
		WithFailureReason(method)
	return l.Log(ctx, rc.Apply(ev))
}

// KeyRotated records a signing key rotation.
//
// Admin-only operations are audited because the audit log is the only record that
// the person holding the admin role rotated keys rather than an attacker who
// escalated to it.
func (l *Logger) KeyRotated(ctx context.Context, rc RequestContext, actor string, keyID string) error {
	ev := domain.NewAuditEvent(domain.AuditKeyRotated, domain.AuditOutcomeSuccess, nil).
		WithResource("key", keyID).
		WithReason("signing key rotated")
	return l.recordWithActor(ctx, rc, ev, actor)
}

// UserErased records completion of a GDPR erasure.
//
// Recorded after the transaction commits, not before. An erasure event that exists
// for a transaction that rolled back is worse than a missing one: it tells a data
// subject their data was deleted when it was not.
func (l *Logger) UserErased(ctx context.Context, rc RequestContext, adminActor string, targetUserID string) error {
	ev := domain.NewAuditEvent(domain.AuditUserErased, domain.AuditOutcomeSuccess, nil).
		WithReason("gdpr erasure completed")
	// The administrator is the actor; the erased subject is the target. Getting
	// these the wrong way round makes the event unreadable during an investigation
	// into who performed the erasure, so the two are set from distinct inputs.
	e := l.attach(rc, ev, adminActor)
	if targetUserID != "" {
		e.Target = pseudonymPtr(targetUserID, l.pepper)
	}
	return l.Log(ctx, e)
}

// BackchannelLogoutSent records a delivered logout token.
func (l *Logger) BackchannelLogoutSent(ctx context.Context, rc RequestContext, clientID string) error {
	ev := domain.NewAuditEvent(domain.AuditBackchannelLogoutSent, domain.AuditOutcomeSuccess, nil).
		WithClient(clientID).
		WithReason("logout token delivered")
	return l.Log(ctx, rc.Apply(ev))
}

// BackchannelLogoutFailed records a delivery failure.
//
// Recorded even though the logout itself succeeded, because an RP that silently
// stopped receiving logout tokens still believes it holds sessions that the
// authorization server has already terminated. That divergence is worth an alert and
// is invisible without this event.
func (l *Logger) BackchannelLogoutFailed(ctx context.Context, rc RequestContext, clientID, reason string) error {
	ev := domain.NewAuditEvent(domain.AuditBackchannelLogoutFail, domain.AuditOutcomeFailure, nil).
		WithClient(clientID).
		WithReason(reason).
		WithFailureReason(reason)
	return l.Log(ctx, rc.Apply(ev))
}

// recordWithActor pseudonymises the actor and writes.
func (l *Logger) recordWithActor(ctx context.Context, rc RequestContext, e domain.AuditEvent, actor string) error {
	if actor != "" {
		e.Actor = pseudonymPtr(actor, l.pepper)
	}
	return l.Log(ctx, rc.Apply(e))
}

// attach pseudonymises the actor and stamps the request context, without writing,
// for events that need further field assignment before a single Log call.
func (l *Logger) attach(rc RequestContext, e domain.AuditEvent, actor string) domain.AuditEvent {
	if actor != "" {
		e.Actor = pseudonymPtr(actor, l.pepper)
	}
	return rc.Apply(e)
}

// pseudonymPtr returns a pointer to the pseudonym, or nil for an empty input, so
// that "no actor" stays distinguishable from "actor whose pseudonym is empty".
func pseudonymPtr(identifier string, pepper []byte) *string {
	if identifier == "" {
		return nil
	}
	p := pseudonymousIdentifier(identifier, pepper)
	return &p
}
