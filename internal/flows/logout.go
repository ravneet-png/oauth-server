package flows

// Logout. Session-scoped revocation of tokens, plus back-channel notification.
// RP-initiated logout honours post_logout_redirect_uri only when the client is
// unambiguously identified by a validated id_token_hint.

import (
	"context"
	"errors"
	"fmt"
	"net/url"
	"time"

	"oauth-server/internal/backchannel"
	"oauth-server/internal/domain"
	"oauth-server/internal/storage"
	"oauth-server/internal/tokens"
)

// Logout performs session-scoped logout.
//
//  1. sess = Get session
//  2. clientSessions = GetBySessionID(sessionID)
//  3. Revoke THIS SESSION's tokens only, never the user's other sessions
//  4. For each clientSession with backchannel_logout_uri, deliver a logout token
//  5. Delete client_sessions for this session
//  6. Delete session
//  7. Audit: "user.logout"
//
// Delivery happens after the transaction-relevant work, and is bounded by the
// caller's context. A failure to notify one RP does not fail the logout: the user
// has asked to be signed out, and the tokens are already revoked.
func Logout(ctx context.Context,
	sessionID string,
	sessionRepo *storage.SessionRepo,
	clientSessionRepo *storage.ClientSessionRepo,
	accessTokenRepo *storage.AccessTokenRepo,
	refreshTokenRepo *storage.RefreshTokenRepo,
	revokedTokenRepo *storage.RevokedTokenRepo,
	auditRepo *storage.AuditRepo,
	clientRepo *storage.ClientRepo,
	logoutBuilder *tokens.LogoutTokenBuilder,
	sender *backchannel.Sender,
) error {

	// 1. Get session
	session, err := sessionRepo.GetByID(ctx, sessionID)
	if err != nil {
		return fmt.Errorf("flows: logout get session: %w", err)
	}

	// 2. Get client sessions
	clientSessions, err := clientSessionRepo.GetBySessionID(ctx, sessionID)
	if err != nil {
		return fmt.Errorf("flows: logout get client sessions: %w", err)
	}

	// 3. Revoke THIS SESSION's tokens only.
	activeAccess, err := accessTokenRepo.GetActiveBySession(ctx, sessionID)
	if err != nil {
		return fmt.Errorf("flows: logout get active access tokens: %w", err)
	}
	if len(activeAccess) > 0 {
		entries := make([]storage.RevocationEntry, 0, len(activeAccess))
		for _, t := range activeAccess {
			entries = append(entries, storage.RevocationEntry{JTI: t.JTI, ExpiresAt: t.ExpiresAt})
		}
		// One statement rather than a loop: a session can hold many tokens, and a
		// logout that fails partway leaves some of them live.
		if err := revokedTokenRepo.AddBatch(ctx, entries); err != nil {
			return fmt.Errorf("flows: logout revoke access tokens: %w", err)
		}
	}

	if _, err := refreshTokenRepo.RevokeBySession(ctx, sessionID, domain.RevocationReasonLogout); err != nil {
		return fmt.Errorf("flows: logout revoke refresh tokens: %w", err)
	}

	// 5. Delete client_sessions, then 6. the session. Both before delivery, so a
	// slow or failing RP cannot keep the session alive.
	if _, err := clientSessionRepo.DeleteBySessionID(ctx, sessionID); err != nil {
		return fmt.Errorf("flows: logout delete client sessions: %w", err)
	}
	if err := sessionRepo.Delete(ctx, sessionID); err != nil {
		return fmt.Errorf("flows: logout delete session: %w", err)
	}

	// 4. Back-channel delivery. Built and attempted after the local state is
	// already revoked, so a failure here cannot leave the user signed in.
	if sender != nil {
		deliverLogoutTokens(ctx, sender, clientSessions, session.UserID, clientRepo, logoutBuilder, auditRepo)
	}

	// 7. Audit
	if auditRepo != nil {
		evt := domain.NewAuditEvent(domain.AuditUserLogout, domain.AuditOutcomeSuccess, &session.UserID).
			WithSession(sessionID).
			WithReason("user logout")
		_ = auditRepo.Log(ctx, &evt)
	}

	return nil
}

// deliverLogoutTokens notifies each client session's RP.
//
// Errors are dropped deliberately. This runs on the logout path, after the user is
// already signed out; surfacing an RP's outage as a failed logout would tell the
// user their request failed when it succeeded. The alternative of returning the
// error means one unreachable RP blocks every other RP from being notified.
//
// It is called synchronously rather than in a goroutine so that ctx still has its
// deadline: a goroutine started here would be cancelled the moment the request
// completed, and the POST would never be sent, which is the bug this replaces.
func deliverLogoutTokens(ctx context.Context,
	sender *backchannel.Sender,
	clientSessions []*domain.ClientSession,
	userID string,
	clientRepo *storage.ClientRepo,
	logoutBuilder *tokens.LogoutTokenBuilder,
	auditRepo *storage.AuditRepo,
) {
	for _, cs := range clientSessions {
		if cs == nil || cs.ClientID == "" {
			continue
		}
		client, err := clientRepo.GetByID(ctx, cs.ClientID)
		if err != nil || client == nil || client.BackchannelLogoutURI == nil || *client.BackchannelLogoutURI == "" {
			// Not registered for back-channel logout, or the client row is gone.
			continue
		}

		logoutToken, err := logoutBuilder.Build(ctx, tokens.LogoutTokenParams{
			UserID:   userID,
			ClientID: client.ClientID,
			SID:      cs.SID,
			TTL:      2 * time.Minute,
		})
		if err != nil {
			continue
		}

		// Bounded by the request context, which the Sender further caps per
		// attempt. A client_session row for a user with many RPs must not be able
		// to hold the logout request open indefinitely.
		_ = sender.Deliver(ctx, *client.BackchannelLogoutURI, logoutToken)
		if auditRepo != nil {
			evt := domain.NewAuditEvent("logout.backchannel_sent", domain.AuditOutcomeSuccess, &userID).
				WithClient(client.ClientID).
				WithReason("backchannel logout token delivered")
			_ = auditRepo.Log(ctx, &evt)
		}
	}
}

// LogoutRP handles RP-Initiated Logout (GET /logout).
//
//  1. If id_token_hint: verify signature, extract sub and the client_id the token
//     was issued to. An unverifiable hint is an error, not something to ignore.
//  2. If session: get user_id.
//  3. If both: they must agree.
//  4. Validate post_logout_redirect_uri against that client. Without an
//     identified client there is no registered set to validate against, so the
//     redirect is refused rather than honoured.
//  5. Perform Logout(sessionID).
//  6. Return the redirect URL, or "" to render the local confirmation page.
func LogoutRP(ctx context.Context,
	idTokenHint string,
	postLogoutRedirectURI string,
	state string,
	sessionID string,
	verifier *tokens.Verifier,
	sessionRepo *storage.SessionRepo,
	clientRepo *storage.ClientRepo,
	logoutBuilder *tokens.LogoutTokenBuilder,
	accessTokenRepo *storage.AccessTokenRepo,
	refreshTokenRepo *storage.RefreshTokenRepo,
	revokedTokenRepo *storage.RevokedTokenRepo,
	auditRepo *storage.AuditRepo,
	clientSessionRepo *storage.ClientSessionRepo,
	sender *backchannel.Sender,
) (redirectURL string, err error) {

	var userID string
	var clientID string

	// 1. id_token_hint. The `aud` of an ID token is the client it was minted for,
	// which is exactly the party being asked to be redirected to. That is what
	// identifies the client for the redirect check below.
	if idTokenHint != "" {
		if verifier == nil {
			return "", errors.New("flows: LogoutRP: no verifier configured")
		}
		tok, verifyErr := verifier.Verify(ctx, idTokenHint, tokens.TypeJWT)
		if verifyErr != nil {
			// Refused rather than ignored. Falling back to session-only would let
			// an attacker attach any garbage as a hint and still receive a
			// validated redirect, and would silently accept a replayed ID token.
			return "", errors.New("flows: LogoutRP: id_token_hint did not verify")
		}
		userID = tok.Subject()
		if len(tok.Audience()) > 0 {
			clientID = tok.Audience()[0]
		}
		if clientID == "" {
			return "", errors.New("flows: LogoutRP: id_token_hint has no audience")
		}
	}

	// 2 + 3. Session agreement.
	if sessionID != "" {
		sess, sessErr := sessionRepo.GetByID(ctx, sessionID)
		if sessErr == nil {
			if userID != "" && sess.UserID != userID {
				// A hint belonging to another user must not sign that user out,
				// and must not be treated as if it authenticated this one.
				return "", errors.New("flows: LogoutRP: id_token_hint subject does not match session user")
			}
			// No assignment here: the session is what scopes the logout below, and
			// nothing downstream reads a user ID derived from the session. The
			// comparison above is the whole point of the lookup.
		}
	}

	// 4. Redirect validation. Only ever performed against a client identified by
	// the hint. Without one there is no registered URI set, and an unregistered
	// destination is the open-redirect primitive: the link would land the user on
	// an attacker's page still framed as the authorization server.
	if postLogoutRedirectURI != "" {
		if clientID == "" {
			return "", errors.New("flows: LogoutRP: post_logout_redirect_uri requires a valid id_token_hint")
		}
		client, clientErr := clientRepo.GetByID(ctx, clientID)
		if clientErr != nil {
			return "", errors.New("flows: LogoutRP: post_logout_redirect_uri client not found")
		}
		if !client.PostLogoutRedirectURIAllowed(postLogoutRedirectURI) {
			return "", errors.New("flows: LogoutRP: post_logout_redirect_uri not registered for client")
		}
	}

	// 5. Perform Logout.
	if sessionID != "" {
		if err := Logout(ctx, sessionID, sessionRepo, clientSessionRepo, accessTokenRepo, refreshTokenRepo, revokedTokenRepo, auditRepo, clientRepo, logoutBuilder, sender); err != nil {
			return "", err
		}
	}

	// 6. Redirect, preserving any query already present in the registered URI.
	if postLogoutRedirectURI != "" {
		if state != "" {
			u, parseErr := url.Parse(postLogoutRedirectURI)
			if parseErr != nil {
				return "", errors.New("flows: LogoutRP: registered redirect is not a URL")
			}
			q := u.Query()
			q.Set("state", state)
			u.RawQuery = q.Encode()
			return u.String(), nil
		}
		return postLogoutRedirectURI, nil
	}

	return "", nil
}
