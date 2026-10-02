package flows

// Token introspection. Authorises the caller before disclosing anything: an authenticated
// client must not be able to introspect tokens belonging to an unrelated client.

import (
	"context"
	"time"

	"github.com/lestrrat-go/jwx/v2/jwt"

	"oauth-server/internal/crypto"
	"oauth-server/internal/domain"
	"oauth-server/internal/storage"
	"oauth-server/internal/tokens"
)

// IntrospectionResponse is the RFC 7662 response.
type IntrospectionResponse struct {
	Active    bool     `json:"active"`
	Scope     string   `json:"scope,omitempty"`
	ClientID  string   `json:"client_id,omitempty"`
	Username  string   `json:"username,omitempty"`
	TokenType string   `json:"token_type,omitempty"`
	Exp       int64    `json:"exp,omitempty"`
	Iat       int64    `json:"iat,omitempty"`
	Sub       string   `json:"sub,omitempty"`
	Aud       []string `json:"aud,omitempty"`
	Iss       string   `json:"iss,omitempty"`
	JTI       string   `json:"jti,omitempty"`
}

// IntrospectToken introspects an access token or refresh token.
//
// 1. Try JWT: verify signature, exp, revoked → active:true + claims
// 2. Try refresh: check not revoked, not expired → active:true
// 3. Else → active:false
//
// The caller must be authenticated (client credentials or private_key_jwt).
// The token must belong to the calling client.
func IntrospectToken(ctx context.Context,
	client *domain.Client,
	token string,
	verifier *tokens.Verifier,
	accessTokenRepo *storage.AccessTokenRepo,
	refreshTokenRepo *storage.RefreshTokenRepo,
	revokedTokenRepo *storage.RevokedTokenRepo,
	userRepo *storage.UserRepo,
) (*IntrospectionResponse, error) {

	// Try as JWT access token.
	tok, err := verifier.Verify(ctx, token, tokens.TypeJWT)
	if err == nil {
		// Ownership is read from the client_id claim, never from `aud`. The
		// audience names the resource server, not the client, so comparing it
		// here would reject tokens for this server's own API and, on a
		// multi-tenant deployment, hand one client details of another's.
		if claimClientID(tok) == client.ClientID {
			return buildIntrospectionFromJWT(tok), nil
		}
	}

	// Try as refresh token
	hash := crypto.SHA256Hex(token)
	rt, err := refreshTokenRepo.GetByHash(ctx, hash)
	if err == nil && rt != nil {
		if rt.ClientID == client.ClientID {
			if rt.IsUsable(time.Now()) {
				return &IntrospectionResponse{
					Active:    true,
					TokenType: "refresh_token",
					Scope:     domain.JoinScope(rt.Scope),
					ClientID:  rt.ClientID,
					Exp:       rt.ExpiresAt.Unix(),
					Iat:       rt.CreatedAt.Unix(),
				}, nil
			}
		}
	}

	// Not found or not owned by this client
	return &IntrospectionResponse{Active: false}, nil
}

// claimString reads a string claim, reporting the empty string when it is absent
// or is not a string.
//
// The type is checked rather than asserted. An access token minted with no
// granted scope legitimately has no `scope` claim, and an unchecked assertion
// there turns an introspection request into a panic inside a handler.
func claimString(tok jwt.Token, name string) string {
	v, ok := tok.Get(name)
	if !ok {
		return ""
	}
	s, ok := v.(string)
	if !ok {
		return ""
	}
	return s
}

// claimClientID reads the client_id claim.
func claimClientID(tok jwt.Token) string {
	return claimString(tok, "client_id")
}

func buildIntrospectionFromJWT(tok jwt.Token) *IntrospectionResponse {
	return &IntrospectionResponse{
		Active:    true,
		TokenType: "access_token",
		Scope:     claimString(tok, "scope"),
		ClientID:  claimClientID(tok),
		Exp:       tok.Expiration().Unix(),
		Iat:       tok.IssuedAt().Unix(),
		Sub:       tok.Subject(),
		Aud:       tok.Audience(),
		Iss:       tok.Issuer(),
		JTI:       tok.JwtID(),
	}
}
