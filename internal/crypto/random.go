package crypto

// Cryptographically secure random values.
//
// crypto/rand only. There is deliberately no math/rand fallback anywhere in
// this package: a silent fallback to a predictable source turns every token in
// the system into a guessable value while the service still appears to work.

import (
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"io"
)

// TokenBytes is the entropy of an opaque token.
//
// 32 bytes = 256 bits. The reasoning is that a bearer token is a password with
// no rate limit in front of it at the storage layer, so the only defence
// against guessing is the size of the space: at 256 bits an attacker gets
// exactly one attempt before needing more time than the universe has left, at
// 128 bits the space is small enough to matter in decades, and at 64 bits it is
// exhausted in hours. Client secrets and MFA backup codes use the same size
// because they face the same threat.
const TokenBytes = 32

// RandomBytes returns n cryptographically secure random bytes.
//
// It returns an error rather than panicking and never returns short or zeroed
// data on failure. Every caller here is on an authentication path, so a caller
// that received predictable bytes would have a working system with no
// authentication; propagating the error keeps that failure visible.
func RandomBytes(n int) (b []byte, err error) {
	if n <= 0 {
		return nil, fmt.Errorf("crypto: random byte count must be positive, got %d", n)
	}
	b = make([]byte, n)
	// crypto/rand.Read documents that it never returns a short read without an
	// error, so a single call is sufficient; the loop is not needed.
	if _, err := io.ReadFull(rand.Reader, b); err != nil {
		// The slice is zeroed before the error is returned. It is not reachable
		// by the caller, but a partially filled buffer sitting in a heap dump
		// or core file is a needless thing to have to reason about.
		for i := range b {
			b[i] = 0
		}
		return nil, fmt.Errorf("crypto: read random bytes: %w", err)
	}
	return b, nil
}

// RandomToken returns a URL-safe 256-bit opaque token.
//
// base64.RawURLEncoding, not the standard alphabet: the value is carried in URL
// path segments, query parameters and cookies, and the standard alphabet's '+'
// and '/' must be percent-encoded to survive a round trip. Raw removes the
// padding '=' for the same reason. RFC 6750 section 2.1 treats these characters
// as unreserved, so the value needs no escaping at all.
func RandomToken() (string, error) {
	b, err := RandomBytes(TokenBytes)
	if err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(b), nil
}

// RandomTokenN returns a URL-safe token carrying n bytes of entropy, for the
// few places that need a different size, such as a session id that must be
// shorter than a token.
func RandomTokenN(n int) (string, error) {
	b, err := RandomBytes(n)
	if err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(b), nil
}

// RandomNonce returns a fresh AES-GCM nonce.
//
// 12 bytes is not a preference: NIST SP 800-38D specifies 96-bit nonces for
// GCM, and that is the size for which the internal counter construction has no
// collision risk at all. A random nonce of any other length needs an explicit
// birthday analysis, and for a long-lived key the 96-bit case still gives more
// messages than could ever be encrypted.
func RandomNonce() ([]byte, error) {
	return RandomBytes(12)
}
