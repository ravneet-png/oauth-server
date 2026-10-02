package crypto

// SHA-256 helpers for opaque codes and tokens.
//
// No pepper is used here, and that is a considered decision rather than an
// omission. The values passed to these functions are 256 bits of CSPRNG output:
// authorization codes, refresh tokens, PAR request URIs, email verification
// tokens, MFA backup codes and client secrets. A pepper exists to defeat offline
// dictionary attacks, and a value with 256 bits of entropy has no dictionary. A
// pepper would add a second secret to rotate, and rotating it invalidates every
// outstanding code and token in the database.
//
// HMAC-SHA256 with a pepper IS used for low-entropy identifiers, where the
// reasoning inverts: an email address can be looked up in any rainbow table, so
// hashing it for an audit record leaks the address. See HMACIdentifier.

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
)

// SHA256Hex returns the hex-encoded SHA-256 digest of s, lowercase.
//
// Lowercase and hex rather than base64 because these digests become SQL primary
// keys and index entries. Hex is twice the length of base64 for the same
// entropy, but it sorts and compares predictably, needs no escaping in a URL or
// a log line, and cannot produce a '+' or '/' that a careless caller would
// eventually forget to encode.
func SHA256Hex(s string) string {
	sum := sha256.Sum256([]byte(s))
	return hex.EncodeToString(sum[:])
}

// SHA256Bytes returns the raw 32-byte digest of b, for callers that need the
// bytes rather than a string, such as a persisted BYTEA column.
func SHA256Bytes(b []byte) []byte {
	sum := sha256.Sum256(b)
	return sum[:]
}

// VerifySHA256Hex reports whether presented hashes to the hex digest of
// plaintext, in constant time.
//
// Constant time is the whole point. A byte-by-byte comparison returns as soon as
// it finds a mismatch, so the time taken reveals how many leading bytes were
// correct. For a 64-character hex digest that turns a blind forgery attempt into
// an oracle that reports progress, and it is exactly the kind of timing
// difference a statistical attacker over a network can measure.
//
// Note the argument order: expected comes first because hmac.Equal and
// subtle.ConstantTimeCompare both run in time proportional to the SHORTER
// input, so a caller must not be able to skip the comparison by passing a
// different length and rely on the result being rejected later.
func VerifySHA256Hex(plaintext, expectedHex string) bool {
	actual := SHA256Hex(plaintext)
	return hmac.Equal([]byte(actual), []byte(expectedHex))
}

// HMACIdentifier returns a keyed digest of a low-entropy identifier, for audit
// records.
//
// This is the one place a pepper is used, and the reason is the opposite of the
// argument against peppering tokens. An email address has very little entropy,
// so a bare SHA-256 of it is reversible from a precomputed table in seconds; a
// keyed digest cannot be attacked offline at all without the key. The audit log
// needs to answer "did this event concern this user" across events, and it never
// needs to recover the address itself, which is why the output is safe to store
// where a plaintext address would not be.
//
// The pepper is a server secret from the environment, never from config.yaml.
// A different pepper produces different output for the same address, so
// rotating it makes historical audit rows unlinkable; that is acceptable and is
// documented rather than worked around.
func HMACIdentifier(identifier string, pepper []byte) []byte {
	mac := hmac.New(sha256.New, pepper)
	// Hash.Write never returns an error, so the error is discarded explicitly
	// rather than ignored with _ on its own line.
	_, _ = mac.Write([]byte(identifier))
	return mac.Sum(nil)
}

// HMACIdentifierHex is HMACIdentifier returning hex, for storage in a text
// column.
func HMACIdentifierHex(identifier string, pepper []byte) string {
	return hex.EncodeToString(HMACIdentifier(identifier, pepper))
}

// ParseSHA256Hex validates and decodes a stored digest.
//
// Repositories use this to reject a corrupt row loudly rather than silently
// comparing against something that can never match. A malformed digest in the
// database otherwise presents as "this code is always invalid", which looks
// like a user error and is investigated in the wrong place entirely.
func ParseSHA256Hex(s string) ([]byte, error) {
	raw, err := hex.DecodeString(s)
	if err != nil {
		return nil, fmt.Errorf("crypto: malformed sha256 hex: %w", err)
	}
	if len(raw) != sha256.Size {
		return nil, fmt.Errorf("crypto: sha256 hex is %d bytes, want %d", len(raw), sha256.Size)
	}
	return raw, nil
}
