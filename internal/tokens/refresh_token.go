package tokens

// Opaque refresh tokens.
//
// A refresh token is not a JWT, and the reason is worth stating because the obvious
// design is wrong. If it were a JWT, every resource server that could verify an
// access token could verify a refresh token, and a refresh token that is valid
// everywhere is a refresh token an attacker can use anywhere. Making it opaque
// means only this server can check it, and revocation is a row rather than a policy
// decision made by someone else's code.

import (
	"errors"
	"fmt"

	"oauth-server/internal/crypto"
)

// RefreshToken is a generated refresh token and the hash to store for it.
//
// Both values are returned together because the pairing is the security property:
// the opaque value goes to the client, the hash stays here, and neither is
// derivable from the other. A caller that stores the opaque value has written a
// credential into the database in plaintext, and one that stores the hash in the
// response has handed the client a token it cannot use.
type RefreshToken struct {
	// Opaque is the value sent to the client.
	Opaque string

	// Hash is the SHA-256 hex digest to store in refresh_tokens.token_hash.
	Hash string
}

// GenerateRefreshToken creates a refresh token and its stored hash.
//
// The opaque value is 32 bytes of CSPRNG output, base64url encoded. 256 bits cannot
// be brute forced, so unlike a user-chosen password it needs no work factor, and
// unlike a JWT it carries nothing that a holder could read or modify.
//
// The hash is an unsalted SHA-256. That is the correct choice here specifically
// because the input is 256 bits of uniform randomness: there is no dictionary to
// attack, so a slow hash would only add latency to every refresh. Passwords get
// Argon2id for the opposite reason, and the difference is not an inconsistency.
func GenerateRefreshToken() (*RefreshToken, error) {
	opaque, err := crypto.RandomToken()
	if err != nil {
		return nil, fmt.Errorf("tokens: generate refresh token: %w", err)
	}
	return &RefreshToken{
		Opaque: opaque,
		Hash:   crypto.SHA256Hex(opaque),
	}, nil
}

// VerifyRefreshToken reports whether presented is the plaintext behind storedHash,
// in constant time.
func VerifyRefreshToken(presented, storedHash string) (bool, error) {
	if presented == "" {
		return false, errors.New("tokens: verify refresh token: presented token is empty")
	}
	if storedHash == "" {
		// A row with no stored hash cannot be verified, and treating that as a match
		// would authenticate anyone against a user whose enrolment never completed.
		return false, errors.New("tokens: verify refresh token: no stored hash")
	}
	return crypto.VerifySHA256Hex(presented, storedHash), nil
}
