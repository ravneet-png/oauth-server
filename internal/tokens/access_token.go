package tokens

// Access token construction.
//
// An access token is a bearer credential, and every choice here follows from that.
// It is self-contained so a resource server can verify it without a database call,
// which is why it is a JWT at all; it carries no personal data beyond an opaque
// subject identifier for the same reason; and its `jti` exists so it can be put on
// a deny list when a session ends before the token would have expired.

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/lestrrat-go/jwx/v2/jwt"

	"oauth-server/internal/crypto"
	"oauth-server/internal/domain"
)

// AccessToken is a freshly minted access token and the metadata that must be
// persisted alongside it.
//
// The three returned values are not interchangeable. A caller that stores the token
// instead of the jti cannot revoke it, and a caller that stores only the jti cannot
// answer an introspection request for the token itself.
type AccessToken struct {
	// Token is the signed compact serialisation, for the client.
	Token string

	// JTI is the unique token identifier, for the issued_access_tokens and
	// revoked_tokens tables.
	JTI string

	// ExpiresAt is when the token stops being valid. Stored so the deny list can be
	// pruned: an entry for a token that expired an hour ago is dead weight.
	ExpiresAt time.Time

	// Scopes is the granted scope set, recorded so introspection can report it
	// without parsing the token.
	Scopes []string
}

// newJTI returns a fresh unique token identifier.
//
// One place for all three token types, so a jti is always 32 bytes of CSPRNG output
// in base64url and never a UUID, a timestamp or a counter. A jti is the key of the
// deny list, which means two tokens sharing one would let revoking either revoke
// both, and a guessable jti would let an attacker deny-list tokens they have never
// seen.
func newJTI() (string, error) {
	jti, err := crypto.RandomToken()
	if err != nil {
		return "", fmt.Errorf("tokens: generate jti: %w", err)
	}
	return jti, nil
}

// AccessTokenBuilder mints access tokens for one issuer.
type AccessTokenBuilder struct {
	signer *Signer
	issuer string
}

// NewAccessTokenBuilder builds an AccessTokenBuilder.
//
// issuer is the `iss` claim and must be the server's externally visible identifier.
// A wrong issuer here is not cosmetic: a resource server that trusts tokens from
// two issuers will accept a token minted for a staging deployment as though it came
// from production.
func NewAccessTokenBuilder(signer *Signer, issuer string) (*AccessTokenBuilder, error) {
	if signer == nil {
		return nil, errors.New("tokens: NewAccessTokenBuilder: signer is nil")
	}
	if issuer == "" {
		return nil, errors.New("tokens: NewAccessTokenBuilder: issuer is empty")
	}
	return &AccessTokenBuilder{signer: signer, issuer: issuer}, nil
}

// AccessTokenParams are the inputs to one access token.
//
// A struct rather than a long positional argument list: the parameters are all
// strings, and a caller that transposes aud and client_id gets a token that is
// valid, signed, and accepted by nobody, with no error anywhere.
type AccessTokenParams struct {
	UserID   string
	ClientID string

	// Audience is the resource server the token is for. May be empty, in which case
	// the token carries no `aud` claim, which is only correct when the client and
	// the resource server are the same deployment.
	Audience string

	// Scopes are the granted scopes, already intersected with what the client is
	// allowed and what the user consented to. This builder does not widen them.
	Scopes []string

	// TTL is the access token lifetime. Must be positive.
	TTL time.Duration
}

// Build mints an access token.
func (b *AccessTokenBuilder) Build(ctx context.Context, p AccessTokenParams) (*AccessToken, error) {
	if p.UserID == "" {
		return nil, errors.New("tokens: access token: subject is empty")
	}
	if p.ClientID == "" {
		return nil, errors.New("tokens: access token: client_id is empty")
	}
	if p.TTL <= 0 {
		// Checked rather than defaulted. A zero or negative TTL produces a token that
		// is already expired, which every relying party rejects, and the resulting
		// symptom is an authorization code that appears to work and a resource
		// server that returns 401.
		return nil, fmt.Errorf("tokens: access token: ttl must be positive, got %s", p.TTL)
	}

	now := time.Now().UTC()
	exp := now.Add(p.TTL)

	// A fresh jti per token, not a counter. Two tokens for the same user and client
	// must be independently revocable, and a counter that reset on restart or
	// collided across instances would put a deny-list entry for one token in front
	// of an unrelated one.
	jti, err := newJTI()
	if err != nil {
		return nil, err
	}

	builder := jwt.NewBuilder().
		Issuer(b.issuer).
		Subject(p.UserID).
		IssuedAt(now).
		Expiration(exp).
		JwtID(jti).
		Claim("client_id", p.ClientID)

	if p.Audience != "" {
		builder = builder.Audience([]string{p.Audience})
	}
	// scope is a space-delimited string, not a JSON array. That is what RFC 6749
	// specifies and what every existing resource server already parses; an array
	// here is silently ignored by anything that expects the string.
	//
	// domain.JoinScope rather than strings.Join, so the delimiter is defined in one
	// place next to the parser that has to read it back.
	if len(p.Scopes) > 0 {
		builder = builder.Claim("scope", domain.JoinScope(p.Scopes))
	}

	tok, err := builder.Build()
	if err != nil {
		return nil, fmt.Errorf("tokens: access token: build claims: %w", err)
	}

	signed, err := b.signer.SignJWT(ctx, tok, TypeJWT)
	if err != nil {
		return nil, err
	}

	return &AccessToken{
		Token:     signed,
		JTI:       jti,
		ExpiresAt: exp,
		Scopes:    append([]string(nil), p.Scopes...),
	}, nil
}
