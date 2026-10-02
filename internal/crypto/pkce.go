package crypto

// PKCE verification. S256 only, plain rejected unconditionally.
//
// The rejection is unconditional, not conditional on the stored method. RFC 7636
// permits `plain`, and OAuth 2.1 removes it, because `plain` provides no
// protection against an attacker who can see the authorization request: they
// read the code_challenge out of the URL and send the same value as the verifier.

import (
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"errors"
	"fmt"
)

// MethodS256 is the only PKCE challenge method this server accepts.
const MethodS256 = "S256"

// MethodPlain is defined only so that a stored `plain` can be named in an error
// message. It is never a valid value to verify against.
const MethodPlain = "plain"

// ErrPKCEInvalid means the verifier did not match the challenge, or the method
// is not S256.
var ErrPKCEInvalid = errors.New("crypto: pkce verification failed")

// S256Challenge computes the code challenge for a verifier.
//
// The encoding is base64url WITHOUT padding, per RFC 7636 section 4.2. Standard
// base64 is wrong here in a way that is easy to miss: its '+' and '/' are
// percent-encoded on the way through a query string and the client may not
// decode them, so the challenge silently mismatches.
func S256Challenge(verifier string) string {
	sum := sha256.Sum256([]byte(verifier))
	return base64.RawURLEncoding.EncodeToString(sum[:])
}

// VerifyPKCE checks a verifier against a stored challenge.
//
// It returns ErrPKCEInvalid for a mismatch AND for any method other than S256.
// The two are not distinguished to the caller, because telling them apart would
// tell an attacker whether their guessed verifier was the right shape.
func VerifyPKCE(verifier, challenge, method string) error {
	if method != MethodS256 {
		// Includes `plain`, which is refused even if the challenge happens to
		// equal the verifier. The error text names the method so a client
		// integrator can debug, and the caller returns invalid_grant without
		// this detail.
		return fmt.Errorf("%w: method %q is not supported, only %s", ErrPKCEInvalid, method, MethodS256)
	}

	computed := S256Challenge(verifier)

	// Constant time. A short-circuiting comparison here leaks the number of
	// matching leading bytes of the expected challenge, and the challenge is
	// visible to the client anyway, so this is about not giving an attacker a
	// shortcut through the token endpoint.
	if subtle.ConstantTimeCompare([]byte(computed), []byte(challenge)) != 1 {
		return ErrPKCEInvalid
	}
	return nil
}

// ValidCodeChallenge reports whether s is a well-formed S256 challenge.
//
// This is a shape check for /authorize, where the challenge arrives from an
// untrusted client and must be rejected as invalid_request rather than stored
// and only rejected later at /token. A challenge here is always the output of
// S256Challenge, which is 43 base64url characters of SHA-256 output.
func ValidCodeChallenge(s string) bool {
	// SHA-256 is 32 bytes; RawURLEncoding emits ceil(32*4/3) = 43 characters.
	if len(s) != 43 {
		return false
	}
	// Decoding is the real test: it rejects '+', '/', '=' and any non-base64
	// byte, which is what a regex for [A-Za-z0-9_-] might let through by
	// accident.
	decoded, err := base64.RawURLEncoding.DecodeString(s)
	if err != nil {
		return false
	}
	return len(decoded) == sha256.Size
}

// ValidCodeVerifier reports whether s is a well-formed PKCE verifier.
//
// RFC 7636 section 4.1 sets the range at 43 to 128 characters, drawn from
// unreserved ASCII. The lower bound is not arbitrary: a shorter verifier cannot
// carry 256 bits of entropy, and accepting one would let a client choose a
// challenge that is trivially precomputed.
func ValidCodeVerifier(s string) bool {
	const minLen, maxLen = 43, 128
	if len(s) < minLen || len(s) > maxLen {
		return false
	}
	for i := 0; i < len(s); i++ {
		c := s[i]
		// unreserved = ALPHA / DIGIT / "-" / "." / "_" / "~"
		isAlpha := (c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z')
		isDigit := c >= '0' && c <= '9'
		isPunct := c == '-' || c == '.' || c == '_' || c == '~'
		if !isAlpha && !isDigit && !isPunct {
			return false
		}
	}
	return true
}
