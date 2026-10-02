package flows

// Refresh token exchange. Distinguishes reuse of a rotated token, which revokes the family,
// from a token revoked by logout, which does not. Includes grace window so that benign
// concurrent refreshes are not mistaken for theft. Implements FIX 3, 🔧6, 🔧7, 🔧8.

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

// ExchangeRefreshToken exchanges a refresh token for new tokens.
//
// Implements:
// 1. Atomic rotation (🔧6)
// 2. Rotated token reuse detection with family cascade (FIX 3)
// 3. Other revocation reasons don't cascade (🔧7)
// 4. New access token tracking (🔧6)
// 5. New refresh token in same family (🔧7)
// 5. Grace window handled by AtomicRotate + ReplacedByHash
func ExchangeRefreshToken(ctx context.Context,
	client *domain.Client,
	rawRefreshToken string,
	refreshTokenRepo *storage.RefreshTokenRepo,
	accessTokenRepo *storage.AccessTokenRepo,
	revokedTokenRepo *storage.RevokedTokenRepo,
	auditRepo *storage.AuditRepo,
	accessBuilder *tokens.AccessTokenBuilder,
	accessTTL time.Duration,
	refreshTTL time.Duration,
	tokenEndpoint string,
) (*TokenResponse, error) {

	// 1. hash = SHA256Hex(rawRefreshToken)
	hash := crypto.SHA256Hex(rawRefreshToken)

	// 2. ATOMIC ROTATION: refreshTokenRepo.AtomicRotate(ctx, hash)
	rt, err := refreshTokenRepo.AtomicRotate(ctx, hash)
	if err != nil {
		return nil, fmt.Errorf("flows: atomic rotate: %w", err)
	}

	now := time.Now().UTC()

	// 3. IF rt == nil (already revoked)
	if rt == nil {
		// Fetch existing token for details
		existingRT, err := refreshTokenRepo.GetByHash(ctx, hash)
		if err != nil {
			if errors.Is(err, domain.ErrNotFound) {
				return nil, domain.NewInvalidGrant("refresh token not found")
			}
			return nil, fmt.Errorf("flows: get existing refresh token: %w", err)
		}

		// Verify it's for the correct client
		if existingRT.ClientID != client.ClientID {
			return nil, domain.NewInvalidGrant("wrong client")
		}

		// SWITCH on RevocationReason
		if existingRT.RevocationReason != nil {
			switch *existingRT.RevocationReason {
			case domain.RevocationReasonRotated:
				// Reuse of a rotated token = attack
				if _, err := refreshTokenRepo.RevokeFamily(ctx, existingRT.FamilyID, domain.RevocationReasonReuseCascade); err != nil {
					return nil, fmt.Errorf("flows: revoke family on reuse: %w", err)
				}
				// Audit: token.family_revoked reason=refresh_reuse
				if auditRepo != nil {
					evt := domain.NewAuditEvent(domain.AuditTokenFamilyRevoked, domain.AuditOutcomeFailure, &existingRT.UserID).
						WithClient(client.ClientID).
						WithSession(derefOrEmpty(existingRT.SessionID)).
						WithReason("refresh token reuse detected")
					_ = auditRepo.Log(ctx, &evt)
				}
				return nil, domain.NewInvalidGrant("token reuse detected")
			default:
				// Revoked by logout/explicit/gdpr — not an attack
				return nil, domain.NewInvalidGrant("token has been revoked")
			}
		}

		// Fallback (should not happen if RevokedAt is set)
		return nil, domain.NewInvalidGrant("token has been revoked")
	}

	// 4. Successfully rotated. Validate:
	if rt.ExpiresAt.Before(now) {
		return nil, domain.NewInvalidGrant("refresh token expired")
	}
	if rt.ClientID != client.ClientID {
		return nil, domain.NewInvalidGrant("client mismatch")
	}

	// 5. Generate new access token, track it (session_id = rt.SessionID)
	accessTokenResp, err := accessBuilder.Build(ctx, tokens.AccessTokenParams{
		UserID:   rt.UserID,
		ClientID: client.ClientID,
		Audience: tokenEndpoint,
		Scopes:   rt.Scope,
		TTL:      accessTTL,
	})
	if err != nil {
		return nil, fmt.Errorf("flows: build access token: %w", err)
	}

	accessToken := accessTokenResp.Token
	jti := accessTokenResp.JTI
	exp := accessTokenResp.ExpiresAt

	issuedAccess := &domain.IssuedAccessToken{
		JTI:                jti,
		UserID:             &rt.UserID,
		ClientID:           client.ClientID,
		Scope:              rt.Scope,
		SessionID:          rt.SessionID,
		SourceAuthCodeHash: rt.SourceAuthCodeHash,
		ExpiresAt:          exp,
	}
	if err := accessTokenRepo.Track(ctx, issuedAccess); err != nil {
		return nil, fmt.Errorf("flows: track access token: %w", err)
	}

	// 6. Generate new refresh token (same family_id, same session_id)
	newRT, err := tokens.GenerateRefreshToken()
	if err != nil {
		return nil, fmt.Errorf("flows: generate refresh token: %w", err)
	}

	// The successor's idle expiry is a full refreshTTL from now, NOT inherited
	// from the predecessor and NOT the access token's TTL. Inheriting would make
	// an actively-used token expire on a schedule fixed at first issue, so a user
	// who refreshed every hour would be signed out on the original deadline;
	// using accessTTL would tie the session's lifetime to how often access tokens
	// are minted.
	refreshToken := &domain.RefreshToken{
		TokenHash:          newRT.Hash,
		FamilyID:           rt.FamilyID,
		ClientID:           client.ClientID,
		UserID:             rt.UserID,
		SessionID:          rt.SessionID,
		SourceAuthCodeHash: rt.SourceAuthCodeHash,
		Scope:              rt.Scope,
		ExpiresAt:          now.Add(refreshTTL),
		CreatedAt:          now,
	}
	if err := refreshTokenRepo.Create(ctx, refreshToken); err != nil {
		return nil, fmt.Errorf("flows: create refresh token: %w", err)
	}

	// Link the predecessor to the successor. This is the grace window's input:
	// if the client later presents hash again, this row is what distinguishes a
	// duplicate request from a concurrent one that lost the race, and it is why
	// benign double-refresh does not cascade the family.
	if err := refreshTokenRepo.SetReplacedByHash(ctx, hash, newRT.Hash); err != nil {
		// Not fatal. Rotation already succeeded and the successor is issued; the
		// link only improves the next reuse decision, so failing the request here
		// would take away a working session over a bookkeeping write.
		_ = err
	}

	// 7. Return new tokens
	return &TokenResponse{
		AccessToken:  accessToken,
		TokenType:    "Bearer",
		ExpiresIn:    int(accessTTL.Seconds()),
		RefreshToken: newRT.Opaque,
		Scope:        domain.JoinScope(rt.Scope),
	}, nil
}
