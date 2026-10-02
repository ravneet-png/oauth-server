package flows

// Authorization code exchange. Consumes the code with a conditional update that carries
// client_id and expiry in the predicate. Implements FIX 5 (code reuse cascade), 🔧1 (atomic mark used),
// 🔧6 (access token tracking), 🔧7 (refresh token family), and audit events.

import (
	"context"
	"errors"
	"fmt"
	"time"

	"oauth-server/internal/crypto"
	"oauth-server/internal/domain"
	"oauth-server/internal/storage"
	"oauth-server/internal/tokens"
)

// TokenResponse is the standard OAuth token response.
type TokenResponse struct {
	AccessToken  string
	TokenType    string
	ExpiresIn    int
	RefreshToken string
	IDToken      string
	Scope        string
}

// ExchangeAuthorizationCode exchanges an authorization code for tokens.
//
// Implements the critical security fixes:
// 1. Atomic mark-used (🔧1)
// 2. Code reuse detection with cascade revocation (FIX 5)
// 3. Access token tracking (🔧6)
// 4. Refresh token family creation (🔧7)
// 5. PKCE verification
// 6. Audit logging
func ExchangeAuthorizationCode(ctx context.Context,
	client *domain.Client,
	code string,
	verifier string,
	redirectURI string,
	authCodeRepo *storage.AuthCodeRepo,
	accessTokenRepo *storage.AccessTokenRepo,
	refreshTokenRepo *storage.RefreshTokenRepo,
	familyRepo *storage.TokenFamilyRepo,
	revokedTokenRepo *storage.RevokedTokenRepo,
	userRepo *storage.UserRepo,
	auditRepo *storage.AuditRepo,
	accessBuilder *tokens.AccessTokenBuilder,
	idBuilder *tokens.IDTokenBuilder,
	accessTTL time.Duration,
	refreshTTL time.Duration,
	idTTL time.Duration,
	familyAbsoluteTTL time.Duration,
	tokenEndpoint string, // for aud claim
) (*TokenResponse, error) {

	// 1. codeHash = SHA256Hex(code)
	codeHash := crypto.SHA256Hex(code)

	// 2. PRE-CHECK: Read the code to validate client ownership before consuming
	// atomically. This prevents a wrong-client probe from consuming a code the
	// legitimate client still holds.
	preCheck, err := authCodeRepo.GetByHash(ctx, codeHash)
	if err != nil {
		if errors.Is(err, domain.ErrNotFound) {
			return nil, domain.NewInvalidGrant("code not found")
		}
		return nil, fmt.Errorf("flows: get code for pre-check: %w", err)
	}

	now := time.Now().UTC()

	// 3. If the code was already used, fall into the reuse-detection path
	// without consuming it again.
	if !preCheck.IsUsable(now) {
		// REUSE DETECTED: verify it's for the correct client
		if preCheck.ClientID != client.ClientID {
			return nil, domain.NewInvalidGrant("code already used")
		}

		// REUSE CONFIRMED for correct client. CASCADE REVOCATION:
		if preCheck.FamilyID != nil {
			// Revoke the entire refresh token family
			if _, err := refreshTokenRepo.RevokeFamily(ctx, *preCheck.FamilyID, domain.RevocationReasonReuseCascade); err != nil {
				return nil, fmt.Errorf("flows: revoke family on reuse: %w", err)
			}

			// Revoke access tokens issued alongside this code
			issuedTokens, err := accessTokenRepo.GetBySourceAuthCode(ctx, codeHash)
			if err != nil {
				return nil, fmt.Errorf("flows: get issued tokens for reuse: %w", err)
			}
			for _, t := range issuedTokens {
				if err := revokedTokenRepo.Add(ctx, t.JTI, t.ExpiresAt); err != nil {
					// Log but don't fail - we already have the family revoked
					fmt.Printf("flows: failed to revoke access token %s on reuse: %v\n", t.JTI, err)
				}
			}
		}

		// Audit: code.reuse_detected
		if auditRepo != nil {
			evt := domain.NewAuditEvent(domain.AuditCodeReuseDetected, domain.AuditOutcomeFailure, nil).
				WithClient(client.ClientID).
				WithTarget(&preCheck.UserID).
				WithSession(derefOrEmpty(preCheck.SessionID)).
				WithReason("code reuse detected")
			_ = auditRepo.Log(ctx, &evt)
		}

		return nil, domain.NewInvalidGrant("code already used")
	}

	// 4. Wrong client: return invalid_grant WITHOUT consuming the code.
	if preCheck.ClientID != client.ClientID {
		return nil, domain.NewInvalidGrant("client mismatch")
	}

	// 5. ATOMIC MARK-USED: consumes the code atomically.
	// If another request raced and consumed it, AtomicMarkUsed returns nil
	// and we fall into the reuse path.
	authCode, err := authCodeRepo.AtomicMarkUsed(ctx, codeHash)
	if err != nil {
		return nil, fmt.Errorf("flows: atomic mark used: %w", err)
	}

	// 6. IF authCode == nil (race: someone else consumed it)
	if authCode == nil {
		// Re-fetch for reuse detection
		existingCode, gerr := authCodeRepo.GetByHash(ctx, codeHash)
		if gerr != nil {
			if errors.Is(gerr, domain.ErrNotFound) {
				return nil, domain.NewInvalidGrant("code not found")
			}
			return nil, fmt.Errorf("flows: get existing code after race: %w", gerr)
		}

		if existingCode.ClientID != client.ClientID {
			return nil, domain.NewInvalidGrant("code already used")
		}

		// REUSE CONFIRMED for correct client. CASCADE REVOCATION:
		if existingCode.FamilyID != nil {
			if _, rerr := refreshTokenRepo.RevokeFamily(ctx, *existingCode.FamilyID, domain.RevocationReasonReuseCascade); rerr != nil {
				return nil, fmt.Errorf("flows: revoke family on reuse: %w", rerr)
			}

			issuedTokens, ierr := accessTokenRepo.GetBySourceAuthCode(ctx, codeHash)
			if ierr != nil {
				return nil, fmt.Errorf("flows: get issued tokens for reuse: %w", ierr)
			}
			for _, t := range issuedTokens {
				if err := revokedTokenRepo.Add(ctx, t.JTI, t.ExpiresAt); err != nil {
					fmt.Printf("flows: failed to revoke access token %s on reuse: %v\n", t.JTI, err)
				}
			}
		}

		if auditRepo != nil {
			evt := domain.NewAuditEvent(domain.AuditCodeReuseDetected, domain.AuditOutcomeFailure, nil).
				WithClient(client.ClientID).
				WithTarget(&existingCode.UserID).
				WithSession(derefOrEmpty(existingCode.SessionID)).
				WithReason("code reuse detected")
			_ = auditRepo.Log(ctx, &evt)
		}

		return nil, domain.NewInvalidGrant("code already used")
	}

	// 7. Code freshly marked used. Validate:
	// expires_at > now
	if !authCode.ExpiresAt.After(now) {
		return nil, domain.NewInvalidGrant("code expired")
	}
	// authCode.RedirectURI == redirectURI
	if authCode.RedirectURI != redirectURI {
		return nil, domain.NewInvalidGrant("redirect_uri mismatch")
	}
	// Verify PKCE
	if err := crypto.VerifyPKCE(verifier, authCode.CodeChallenge, authCode.CodeChallengeMethod); err != nil {
		// invalid_grant rather than invalid_request: the request was well formed
		// and authenticated, but the verifier does not match the challenge this
		// code was issued under. The reason is not echoed back, because telling
		// the caller which half was wrong helps someone guessing a verifier.
		return nil, domain.NewInvalidGrant("code verifier is invalid")
	}

	// 5. familyID
	//
	// The consent step normally assigned this at insert time, so the code carries
	// it and this path must use that value rather than a fresh one: the refresh
	// token minted below is what reuse detection cascades over, and a family id on
	// the token that differs from the one on its source code makes the cascade
	// target a family nobody holds.
	//
	// A code created without one — by an older row — gets a fresh id via the
	// idempotent EnsureFamilyID, which leaves an existing value untouched.
	familyID := derefOrEmpty(authCode.FamilyID)
	if familyID == "" {
		familyID, err = crypto.RandomToken()
		if err != nil {
			return nil, fmt.Errorf("flows: generate family ID: %w", err)
		}
		if err := authCodeRepo.EnsureFamilyID(ctx, codeHash, familyID); err != nil {
			return nil, fmt.Errorf("flows: ensure family ID: %w", err)
		}
	}
	// A code minted before the consent step created its family, or one written by an
	// older release, carries an id with no row behind it. refresh_tokens.family_id is
	// a foreign key, so the row has to exist before the insert below, not after.
	if err := familyRepo.Ensure(ctx, &domain.TokenFamily{
		FamilyID:          familyID,
		UserID:            authCode.UserID,
		ClientID:          client.ClientID,
		AbsoluteExpiresAt: getAuthTime(authCode.AuthTime, time.Now().UTC()).Add(familyAbsoluteTTL),
	}); err != nil {
		return nil, fmt.Errorf("flows: ensure token family: %w", err)
	}

	// 6. user = userRepo.GetByID(authCode.UserID)
	user, err := userRepo.GetByID(ctx, authCode.UserID)
	if err != nil {
		return nil, fmt.Errorf("flows: get user: %w", err)
	}

	// 7. accessJWT, jti, exp = accessBuilder.Build(...)
	accessTokenResp, err := accessBuilder.Build(ctx, tokens.AccessTokenParams{
		UserID:   user.UserID,
		ClientID: client.ClientID,
		Audience: tokenEndpoint,
		Scopes:   authCode.Scope,
		TTL:      accessTTL,
	})
	if err != nil {
		return nil, fmt.Errorf("flows: build access token: %w", err)
	}

	accessToken := accessTokenResp.Token
	jti := accessTokenResp.JTI
	exp := accessTokenResp.ExpiresAt

	// 8. accessRepo.Track(&IssuedAccessToken{...})
	issuedAccess := &domain.IssuedAccessToken{
		JTI:                jti,
		UserID:             &user.UserID,
		ClientID:           client.ClientID,
		Scope:              authCode.Scope,
		SessionID:          authCode.SessionID,
		SourceAuthCodeHash: &codeHash,
		ExpiresAt:          exp,
	}
	if err := accessTokenRepo.Track(ctx, issuedAccess); err != nil {
		return nil, fmt.Errorf("flows: track access token: %w", err)
	}

	// 9. refreshOpaque, refreshHash = refreshToken.Generate()
	rt, err := tokens.GenerateRefreshToken()
	if err != nil {
		return nil, fmt.Errorf("flows: generate refresh token: %w", err)
	}

	refreshExpiresAt := now.Add(refreshTTL)
	refreshToken := &domain.RefreshToken{
		TokenHash:          rt.Hash,
		FamilyID:           familyID,
		ClientID:           client.ClientID,
		UserID:             user.UserID,
		SessionID:          authCode.SessionID,
		SourceAuthCodeHash: &codeHash,
		Scope:              authCode.Scope,
		ExpiresAt:          refreshExpiresAt,
		CreatedAt:          now,
	}
	if err := refreshTokenRepo.Create(ctx, refreshToken); err != nil {
		return nil, fmt.Errorf("flows: create refresh token: %w", err)
	}

	// 10. IF "openid" in scope: build ID token
	var idToken string
	if domain.ScopeContains(authCode.Scope, "openid") {
		idToken, err = idBuilder.Build(ctx, tokens.IDTokenParams{
			User:        user,
			ClientID:    client.ClientID,
			Nonce:       derefOrEmpty(authCode.Nonce),
			AccessToken: accessToken,
			SID:         getSID(authCode.SID),
			AuthTime:    getAuthTime(authCode.AuthTime, now),
			Scopes:      authCode.Scope,
			TTL:         idTTL,
		})
		if err != nil {
			return nil, fmt.Errorf("flows: build ID token: %w", err)
		}
	}

	// 11. Audit: token.issued
	if auditRepo != nil {
		evt := domain.NewAuditEvent(domain.AuditTokenIssued, domain.AuditOutcomeSuccess, &user.UserID).
			WithClient(client.ClientID).
			WithSession(derefOrEmpty(authCode.SessionID)).
			WithReason("access token issued")
		_ = auditRepo.Log(ctx, &evt)
	}

	// 12. Return tokens
	return &TokenResponse{
		AccessToken:  accessToken,
		TokenType:    "Bearer",
		ExpiresIn:    int(accessTTL.Seconds()),
		RefreshToken: rt.Opaque,
		IDToken:      idToken,
		Scope:        domain.JoinScope(authCode.Scope),
	}, nil
}

// getAuthTime returns the auth time from the auth code, or now if not set.
func getAuthTime(t *time.Time, fallback time.Time) time.Time {
	if t != nil {
		return *t
	}
	return fallback
}

// getSID returns the SID from the auth code, or empty string if not set.
func getSID(s *string) string {
	if s != nil {
		return *s
	}
	return ""
}

// derefOrEmpty returns the pointed-to string, or "" for nil.
func derefOrEmpty(s *string) string {
	if s == nil {
		return ""
	}
	return *s
}
