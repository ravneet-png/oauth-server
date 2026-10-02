package tokens

// ID token construction.
//
// An ID token is the most dangerous artefact this server issues, because it is sent
// to a client and describes a person. Two rules follow from that and are enforced
// here rather than left to the caller: an unverified email address is never
// included, and the claims that are included are the ones the client has actually
// been granted scope for.

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"fmt"
	"time"

	"github.com/lestrrat-go/jwx/v2/jwt"

	"oauth-server/internal/domain"
)

// IDTokenBuilder mints ID tokens for one issuer.
type IDTokenBuilder struct {
	signer *Signer
	issuer string
}

// NewIDTokenBuilder builds an IDTokenBuilder.
func NewIDTokenBuilder(signer *Signer, issuer string) (*IDTokenBuilder, error) {
	if signer == nil {
		return nil, errors.New("tokens: NewIDTokenBuilder: signer is nil")
	}
	if issuer == "" {
		return nil, errors.New("tokens: NewIDTokenBuilder: issuer is empty")
	}
	return &IDTokenBuilder{signer: signer, issuer: issuer}, nil
}

// IDTokenParams are the inputs to one ID token.
type IDTokenParams struct {
	// User is whose identity the token asserts. Required.
	User *domain.User

	// ClientID is the audience. Required.
	ClientID string

	// Nonce is the value from the authorization request, echoed back so the client
	// can bind the token to the request it started. Optional: it is absent for a
	// plain authorization code flow with no nonce, and echoing an empty string
	// would be wrong, so the claim is omitted rather than set to "".
	Nonce string

	// AccessToken is the access token issued alongside this ID token. Required,
	// because at_hash is computed from it. Passing an empty string would produce an
	// ID token whose at_hash matches nothing, which is a silent failure a client
	// cannot detect.
	AccessToken string

	// SID is the session identifier, letting a client correlate the ID token with
	// a session it can log out. Optional.
	SID string

	// AuthTime is when the user actually authenticated, which may be much earlier
	// than now for a session that has been reused. Optional: when zero the claim is
	// omitted rather than set to the current time, because a fabricated auth_time
	// defeats the point of the claim.
	AuthTime time.Time

	// Scopes are the scopes granted to this client. Decides whether the profile
	// claims are included at all; see below.
	Scopes []string

	// TTL is the ID token lifetime. Must be positive.
	TTL time.Duration
}

// Build mints an ID token.
//
// The profile claims are gated on the granted scopes, per OpenID Connect: `name`
// needs the `profile` scope and `email`/`email_verified` need the `email` scope. A
// client that was granted neither receives none of them. Passing the user's name to
// a client that did not ask for it is a data disclosure that no signature or
// transport control can undo.
//
// `email` and `email_verified` are additionally omitted entirely when
// User.EmailVerified is false, rather than being sent as `email_verified: false`.
// An unverified address is one the user has never proven they control, so
// publishing it lets a client key an account on an address an attacker chose. The
// specification permits `email_verified: false`; omitting is the conservative
// reading, and it means a client cannot tell "unverified" from "not requested",
// which is the correct amount of information to give it.
func (b *IDTokenBuilder) Build(ctx context.Context, p IDTokenParams) (string, error) {
	if p.User == nil {
		return "", errors.New("tokens: id token: user is nil")
	}
	if p.User.UserID == "" {
		return "", errors.New("tokens: id token: user has no id")
	}
	if p.ClientID == "" {
		return "", errors.New("tokens: id token: client_id is empty")
	}
	if p.AccessToken == "" {
		return "", errors.New("tokens: id token: access token is required; at_hash is computed from it")
	}
	if p.TTL <= 0 {
		return "", fmt.Errorf("tokens: id token: ttl must be positive, got %s", p.TTL)
	}

	now := time.Now().UTC()
	exp := now.Add(p.TTL)

	jti, err := newJTI()
	if err != nil {
		return "", err
	}

	builder := jwt.NewBuilder().
		Issuer(b.issuer).
		Subject(p.User.UserID).
		Audience([]string{p.ClientID}).
		IssuedAt(now).
		Expiration(exp).
		JwtID(jti).
		Claim("at_hash", AtHash(p.AccessToken)).
		Claim("client_id", p.ClientID)

	if p.Nonce != "" {
		builder = builder.Claim("nonce", p.Nonce)
	}
	if p.SID != "" {
		builder = builder.Claim("sid", p.SID)
	}
	// Only when the caller knows it. Defaulting to now would assert an
	// authentication that may have happened hours ago, which is the one thing
	// auth_time exists to prevent a client from assuming.
	if !p.AuthTime.IsZero() {
		builder = builder.Claim("auth_time", p.AuthTime.UTC())
	}

	if domain.ScopeContains(p.Scopes, "profile") {
		if name := p.User.DisplayName(); name != "" {
			builder = builder.Claim("name", name)
		}
	}
	if domain.ScopeContains(p.Scopes, "email") && p.User.EmailVerified {
		builder = builder.
			Claim("email", p.User.Email).
			Claim("email_verified", true)
	}

	tok, err := builder.Build()
	if err != nil {
		return "", fmt.Errorf("tokens: id token: build claims: %w", err)
	}
	return b.signer.SignJWT(ctx, tok, TypeJWT)
}

// AtHash returns the OpenID Connect `at_hash` for an access token.
//
// base64url of the LEFT HALF of the SHA-256 digest, per OpenID Connect Core section
// 3.1.3.6. The left half, not the whole digest, and base64url without padding:
// taking the whole digest would make the value longer than the specification defines
// and a client that checks at_hash would reject a correctly implemented token.
//
// SHA-256 rather than SHA-1, which older drafts of the specification used. This
// server only ever issues RS256, and the hash length has to match the signature
// size for the check to mean anything; SHA-256 keeps the two aligned and is not
// broken for this purpose.
func AtHash(accessToken string) string {
	sum := sha256.Sum256([]byte(accessToken))
	// The left-most half of the digest. sum[:16] is exactly that: 32 bytes in half.
	return base64.RawURLEncoding.EncodeToString(sum[:16])
}
