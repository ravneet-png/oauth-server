package tokens

// Back-channel logout tokens.
//
// Sent from the authorization server to a relying party's backchannel to say "this
// session has ended". They are the one token type in this package that is NOT
// presented to this server by anyone, which changes how they must be built: a
// logout token that this server would accept if handed back to it is a logout token
// an attacker can forge a replay of.

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/lestrrat-go/jwx/v2/jwt"

	"oauth-server/internal/crypto"
)

// LogoutTokenBuilder mints back-channel logout tokens.
//
// A struct rather than free functions, so a caller cannot pass the issuer in a
// different position and produce a token aimed at the wrong relying party.
type LogoutTokenBuilder struct {
	signer *Signer
	issuer string
}

// NewLogoutTokenBuilder builds a LogoutTokenBuilder.
func NewLogoutTokenBuilder(signer *Signer, issuer string) (*LogoutTokenBuilder, error) {
	if signer == nil {
		return nil, errors.New("tokens: NewLogoutTokenBuilder: signer is nil")
	}
	if issuer == "" {
		return nil, errors.New("tokens: NewLogoutTokenBuilder: issuer is empty")
	}
	return &LogoutTokenBuilder{signer: signer, issuer: issuer}, nil
}

// LogoutEventName is the event member that marks a token as a logout notification.
//
// The value is fixed by the OpenID Connect Back-Channel Logout specification. It
// goes in `events` as a map whose single key is this name with an empty object as
// its value; the empty object is what distinguishes the "logged out" event from
// other event types the specification allows to be added later.
const LogoutEventName = "http://schemas.openid.net/event/backchannel-logout"

// LogoutTokenParams are the inputs to one logout token.
//
// Sub is omitted rather than optional-when-empty, because a logout token with
// neither `sub` nor `sid` identifies nobody and tells the RP to do nothing. The
// builder requires at least one, which is the specification's own rule.
type LogoutTokenParams struct {
	// UserID is the `sub` claim. Optional if SID is set.
	UserID string

	// ClientID is the audience: the relying party to notify. Required.
	ClientID string

	// SID is the session identifier, so the RP can end that session specifically
	// rather than every session for the user. Optional if UserID is set.
	SID string

	// TTL bounds how long the notification stays acceptable to the RP.
	//
	// Not in the prompt's claim list, and included anyway. The specification makes
	// `exp` optional for logout tokens, but a notification that never expires is a
	// replayable instruction to terminate a session, and an RP that receives it
	// twice must not be forced to handle it twice. Callers get a default when this
	// is zero so that omitting it is a deliberate choice rather than an oversight.
	TTL time.Duration
}

// DefaultLogoutTokenTTL bounds a logout token's validity when the caller does not
// choose.
//
// 2 minutes. Long enough to survive a slow backchannel call and a clock skew
// between the two servers, short enough that a captured notification is useless
// within a single coffee break. Not longer, because the token is delivered over a
// network to a third party and treated as bearer material by anyone who intercepts
// it.
const DefaultLogoutTokenTTL = 2 * time.Minute

// Build mints a logout token.
//
// The `typ` is logout+jwt and the claims are exactly the ones the specification
// requires: iss, sub, aud, iat, jti, events and sid.
//
// There is deliberately NO `nonce` claim. A nonce's entire purpose is to bind a
// response to a request the client made, and this server makes no request that a
// logout token answers. Echoing a nonce here would be copying a field from a
// request this server never received, and it would give an attacker who can
// influence one request's nonce a way to make a logout token look like a response
// to a request they made. The absence is enforced by never having a field to set,
// rather than by a runtime check that a future edit could route around.
func (b *LogoutTokenBuilder) Build(ctx context.Context, p LogoutTokenParams) (string, error) {
	if p.ClientID == "" {
		return "", errors.New("tokens: logout token: client_id is empty")
	}
	if p.UserID == "" && p.SID == "" {
		// Neither subject nor session: the RP is told to log out nobody in
		// particular, which every compliant RP will ignore, and an RP that does not
		// ignore it logs out every session it has.
		return "", errors.New("tokens: logout token: at least one of sub or sid is required")
	}

	ttl := p.TTL
	if ttl <= 0 {
		ttl = DefaultLogoutTokenTTL
	}

	now := time.Now().UTC()
	jti, err := crypto.RandomToken()
	if err != nil {
		return "", fmt.Errorf("tokens: logout token: generate jti: %w", err)
	}

	builder := jwt.NewBuilder().
		Issuer(b.issuer).
		Audience([]string{p.ClientID}).
		IssuedAt(now).
		Expiration(now.Add(ttl)).
		JwtID(jti).
		// An empty object, not a string and not a boolean. The specification encodes
		// the event as a JSON object with no members, and an RP that parses this
		// strictly will reject anything else.
		Claim("events", map[string]any{LogoutEventName: map[string]any{}})

	if p.UserID != "" {
		builder = builder.Subject(p.UserID)
	}
	if p.SID != "" {
		builder = builder.Claim("sid", p.SID)
	}

	tok, err := builder.Build()
	if err != nil {
		return "", fmt.Errorf("tokens: logout token: build claims: %w", err)
	}
	return b.signer.SignJWT(ctx, tok, TypeLogoutJWT)
}
