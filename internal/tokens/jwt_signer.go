package tokens

// JWT signing. See jwt_verifier.go for the other half of the pair.

import (
	"context"
	"errors"
	"fmt"

	"github.com/lestrrat-go/jwx/v2/jwa"
	"github.com/lestrrat-go/jwx/v2/jws"
	"github.com/lestrrat-go/jwx/v2/jwt"

	"oauth-server/internal/keys"
)

// Token `typ` header values.
//
// RFC 8725 (JWT BCP) section 3.11 requires `typ` on every JWT so that a token
// minted for one purpose cannot be replayed into a context that accepts another
// type. These two are the only values this server emits.
const (
	// TypeJWT is for access tokens and ID tokens.
	TypeJWT = "JWT"

	// TypeLogoutJWT is for back-channel logout tokens.
	//
	// A distinct type, and the reason this header is set explicitly rather than
	// left to a library default: an RP that accepts a logout token without checking
	// `typ` will also accept an access token as a logout notification and log the
	// user out on presentation of any token at all. This is the value the OpenID
	// Connect Back-Channel Logout specification names.
	TypeLogoutJWT = "logout+jwt"
)

// ErrNoActiveKey is returned when signing is attempted before a key is loaded.
//
// An alias for keys.ErrNoActiveKey rather than a second sentinel, so errors.Is
// succeeds for a caller that only knows about the keys package.
var ErrNoActiveKey = keys.ErrNoActiveKey

// Signer mints JWTs with the server's active signing key.
//
// Stateless apart from the key manager, so any number of goroutines may sign
// concurrently. It holds no clock and no counters: `iat`, `exp` and `jti` belong
// to the claims, built by the token builders, not here.
type Signer struct {
	keys *keys.Manager
}

// NewSigner builds a Signer over a key manager.
func NewSigner(mgr *keys.Manager) (*Signer, error) {
	if mgr == nil {
		return nil, errors.New("tokens: NewSigner: key manager is nil")
	}
	return &Signer{keys: mgr}, nil
}

// SignJWT signs an already-populated token with the active key.
//
// typ becomes the JWS `typ` header. It is a required parameter rather than a
// defaulted one so that no call site can forget it: a token with no `typ` is
// exactly the ambiguity RFC 8725 exists to remove, and a default argument would let
// the first caller to omit it set the policy for every caller after.
//
// The `kid` and `alg` headers come from the JWK itself, which is why the key manager
// sets them when it builds the signing key. They are not passed here on purpose: a
// `kid` that disagrees with the key that actually signed the token yields a token
// no relying party can verify, and that mistake is much harder to make when the
// library derives the header from the key.
func (s *Signer) SignJWT(ctx context.Context, token jwt.Token, typ string) (string, error) {
	if token == nil {
		return "", errors.New("tokens: SignJWT: token is nil")
	}
	switch typ {
	case TypeJWT, TypeLogoutJWT:
	default:
		// Rejected rather than passed through. An arbitrary `typ` is not cosmetic:
		// it is what a relying party uses to decide whether this token is
		// acceptable in the context it is being presented in, so the set of legal
		// values is a policy decision, not a free-text field.
		return "", fmt.Errorf("tokens: SignJWT: unsupported typ %q", typ)
	}

	active, err := s.keys.GetSigningKey()
	if err != nil {
		return "", err
	}

	hdrs := jws.NewHeaders()
	if err := hdrs.Set(jws.TypeKey, typ); err != nil {
		return "", fmt.Errorf("tokens: SignJWT: set typ header: %w", err)
	}

	signed, err := jwt.Sign(token,
		jwt.WithKey(jwa.RS256, active.JWK, jws.WithProtectedHeaders(hdrs)),
	)
	if err != nil {
		return "", fmt.Errorf("tokens: SignJWT: %w", err)
	}
	return string(signed), nil
}
