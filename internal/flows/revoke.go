package flows

// Token revocation. Always answers 200 whether or not the token existed,
// so the endpoint cannot be used to probe for valid tokens.

import (
	"context"
	"time"

	"oauth-server/internal/crypto"
	"oauth-server/internal/domain"
	"oauth-server/internal/storage"
	"oauth-server/internal/tokens"
)

// RevokeToken revokes an access token or refresh token.
//
// The signature is verified before an access token's jti is recorded, so a caller
// cannot revoke another client's token by guessing its jti. The raw token is
// never used as a jti: the revoked_tokens table is keyed by jti, and a resource
// server checking a JWT looks up the jti claim, so inserting the whole token
// would produce a row nothing ever reads.
//
// Always returns nil. RFC 7009 section 2.2 requires a 200 whether or not the
// token existed, and requires that the response not reveal which.
func RevokeToken(ctx context.Context,
	client *domain.Client,
	token string,
	verifier *tokens.Verifier,
	accessTokenRepo *storage.AccessTokenRepo,
	refreshTokenRepo *storage.RefreshTokenRepo,
	revokedTokenRepo *storage.RevokedTokenRepo,
) error {

	if token == "" {
		return nil
	}

	// Try as refresh token: the stored form is SHA-256 of the opaque value, so a
	// single lookup covers it without a table scan.
	hash := crypto.SHA256Hex(token)
	rt, err := refreshTokenRepo.GetByHash(ctx, hash)
	if err == nil && rt != nil {
		// A client may only revoke its own tokens. Another client's token is
		// left untouched and the caller still receives 200, so the response
		// cannot be used to confirm that the token exists.
		if rt.ClientID != client.ClientID {
			return nil
		}
		if _, err := refreshTokenRepo.RevokeFamily(ctx, rt.FamilyID, domain.RevocationReasonExplicit); err != nil {
			return err
		}
		return nil
	}

	// Try as access token. The token must verify before its jti is honoured:
	// without that check any caller could revoke a chosen jti.
	if verifier == nil {
		return nil
	}
	tok, err := verifier.Verify(ctx, token, tokens.TypeJWT)
	if err != nil {
		// Unverifiable: it is either not a token of ours, or a forged one.
		// Either way there is nothing to revoke. RFC 7009 requires 200 either
		// way, so the error is deliberately swallowed here.
		return nil // nolint:nilerr // Required by RFC 7009.
	}

	tokenClientID, _ := tok.Get("client_id")
	id, _ := tokenClientID.(string)
	if id != client.ClientID {
		return nil
	}

	jti := tok.JwtID()
	if jti == "" {
		return nil
	}

	// Expiry bounds the deny-list entry: once the token would have expired
	// anyway there is nothing left to protect, and the row would otherwise
	// accumulate forever.
	exp := time.Now().Add(24 * time.Hour)
	if e := tok.Expiration(); !e.IsZero() {
		exp = e
	}
	if !exp.After(time.Now()) {
		return nil
	}

	return revokedTokenRepo.Add(ctx, jti, exp)
}
