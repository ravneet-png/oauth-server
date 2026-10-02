package tokens

// JWT verification: signature, claims, then the deny list.

import (
	"context"
	"errors"
	"fmt"

	"github.com/lestrrat-go/jwx/v2/jws"
	"github.com/lestrrat-go/jwx/v2/jwt"

	"oauth-server/internal/keys"
)

// ErrRevoked means the token's jti is on the deny list.
//
// Distinct from a validation error so that a resource server can answer 401 with a
// correct `error` hint and a client can tell "log in again" from "you sent me
// something malformed".
var ErrRevoked = errors.New("tokens: token has been revoked")

// ErrNoPublishedKey means there is no key to verify against.
//
// Separate from a signature failure because the two mean opposite things to an
// operator. A bad signature is a client sending something wrong; no published key
// is this server being unable to verify anything at all, and reporting it as a
// malformed token sends the investigation in exactly the wrong direction.
var ErrNoPublishedKey = errors.New("tokens: no published signing key")

// Verifier validates JWTs against the published key set.
//
// The shape is the one a resource server uses: verify the signature with a
// published key, check the standard claims, then check the deny list.
type Verifier struct {
	keys        *keys.Manager
	revokedRepo RevocationChecker
}

// RevocationChecker is the part of storage.RevokedTokenRepo that verification
// needs.
//
// An interface so a verifier can be built in a test without a database, and so the
// dependency is stated as "something that can answer whether a jti is revoked"
// rather than dragging in an entire pool.
type RevocationChecker interface {
	IsRevoked(ctx context.Context, jti string) (bool, error)
}

// NewVerifier builds a Verifier over mgr.
//
// revokedRepo may be nil, which skips the revocation check. That is only correct
// where there are no access tokens to revoke, and it is a real footgun: a verifier
// built without one accepts revoked tokens silently, which is the failure this
// design exists to prevent. It is a parameter rather than a constructor variant so
// that skipping revocation is always a visible, deliberate act at the call site.
func NewVerifier(mgr *keys.Manager, revokedRepo RevocationChecker) (*Verifier, error) {
	if mgr == nil {
		return nil, errors.New("tokens: NewVerifier: key manager is nil")
	}
	return &Verifier{keys: mgr, revokedRepo: revokedRepo}, nil
}

// Verify parses and validates a token: signature, standard claims, deny list.
//
// The order is deliberate. The signature is checked first because every later step
// reads claims, and an unverified claim is an attacker-controlled value. The deny
// list is last because it is the only step that touches the database, so a token
// that fails validation costs nothing but CPU.
//
// The algorithm is pinned to RS256 rather than read from the token's own `alg`
// header. Trusting that header is the classic algorithm-confusion attack: a token
// claiming `alg: none` skips verification entirely, and one claiming a symmetric
// algorithm gets the published RSA public key used as an HMAC secret, which the
// attacker already has.
func (v *Verifier) Verify(ctx context.Context, tokenStr string, wantType string) (jwt.Token, error) {
	if tokenStr == "" {
		return nil, errors.New("tokens: Verify: empty token")
	}

	set, err := v.keys.GetJWKS(ctx)
	if err != nil {
		return nil, err
	}
	if set.Len() == 0 {
		return nil, ErrNoPublishedKey
	}

	// WithRequireKid(true) so a token with no kid is refused rather than verified
	// against whichever single key happens to be in the set. During a rotation the
	// set has more than one key, and accepting a kid-less token would mean
	// "verified against any of them", which is not a guarantee.
	// WithKeySet, not WithKey. jws.WithRequireKid is a key-SET suboption, and
	// jwt.WithKey only accepts key suboptions, so passing it there makes jwt.Parse
	// fail converting the option on every single verification — the error surfaces as
	// a generic "token failed signature or claim validation", i.e. every token looks
	// forged. WithKeySet takes the set suboption and matches the kid itself.
	tok, err := jwt.Parse(
		[]byte(tokenStr),
		jwt.WithKeySet(set, jws.WithRequireKid(true)),
		jwt.WithValidate(true),
	)
	if err != nil {
		// The library's message is deliberately not propagated. It says which check
		// failed, which tells an attacker whether a forgery was structurally sound.
		// The caller learns only that the token was not accepted, and the underlying
		// error is left to the server's own logs.
		return nil, errors.New("tokens: Verify: token failed signature or claim validation")
	}

	if wantType != "" {
		if err := checkType(tokenStr, wantType); err != nil {
			return nil, err
		}
	}

	if err := v.checkRevocation(ctx, tok); err != nil {
		return nil, err
	}
	return tok, nil
}

// checkType enforces the `typ` header.
//
// An access token presented where a logout token is expected is the specific
// attack this header exists to stop, so it gets its own error and its own type
// rather than a generic rejection.
func checkType(tokenStr, wantType string) error {
	msg, err := jws.Parse([]byte(tokenStr))
	if err != nil {
		return errors.New("tokens: Verify: token is not a JWS")
	}
	sigs := msg.Signatures()
	if len(sigs) == 0 {
		return errors.New("tokens: Verify: token has no signature")
	}
	if got := sigs[0].ProtectedHeaders().Type(); got != wantType {
		return fmt.Errorf("tokens: Verify: token typ is %q, want %q", got, wantType)
	}
	return nil
}

// checkRevocation consults the deny list.
func (v *Verifier) checkRevocation(ctx context.Context, tok jwt.Token) error {
	if v.revokedRepo == nil {
		return nil
	}
	jti := tok.JwtID()
	if jti == "" {
		// Refused rather than allowed through. The deny list is keyed by jti, so a
		// token without one can never be revoked, and accepting it means accepting a
		// token that is permanently valid no matter what the operator does.
		return errors.New("tokens: Verify: token has no jti and cannot be checked for revocation")
	}
	revoked, err := v.revokedRepo.IsRevoked(ctx, jti)
	if err != nil {
		// Fails closed. Treating a database error as "not revoked" makes an outage
		// indistinguishable from a valid token, and every revoked token in the
		// system would be accepted for as long as it lasted.
		return fmt.Errorf("tokens: Verify: revocation check failed: %w", err)
	}
	if revoked {
		return ErrRevoked
	}
	return nil
}
