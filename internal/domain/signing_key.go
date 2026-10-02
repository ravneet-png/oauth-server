package domain

// A signing key lifecycle record. Status transitions active to retiring to
// retired; a retired key keeps its public half for verification and has its
// private half destroyed.

import (
	"encoding/json"
	"time"
)

// Signing algorithms. Asymmetric only: an HMAC key shared with every relying
// party is a symmetric secret, so a compromised client can mint tokens that
// validate.
const (
	AlgRS256 = "RS256"
	AlgPS256 = "PS256"
	AlgES256 = "ES256"
	AlgEdDSA = "EdDSA"
)

// Signing key lifecycle states.
//
//	active   : signs, and is published in the JWKS
//	retiring : published for verification only, does not sign; private half is
//	           destroyed after its retention window
//	retired  : not published, private half already destroyed
const (
	KeyStatusActive   = "active"
	KeyStatusRetiring = "retiring"
	KeyStatusRetired  = "retired"
)

// SigningKey is one key in the server's signing lifecycle.
//
// A status enum rather than the `active bool` an earlier draft used. A boolean
// cannot express "no longer signing, but still published for verification",
// which is precisely the state a key passes through during rotation, and it is
// the state that matters most: dropping a key from the JWKS the moment it stops
// signing invalidates every token it signed that has not yet expired.
type SigningKey struct {
	// KID is the key identifier published in the JWKS and carried in the
	// `kid` header of every token this key signs.
	KID string

	Algorithm string

	// PublicJWK is stored so the published set can be served without
	// decrypting anything. Regenerated from the private key on write and never
	// edited by hand. json.RawMessage because the domain layer does not need to
	// understand JWK structure and should not depend on a JOSE library.
	PublicJWK json.RawMessage

	// PrivateKeyEnc is AES-256-GCM ciphertext, nil once destroyed.
	PrivateKeyEnc []byte

	Status string

	CreatedAt time.Time

	// NotBefore is the earliest instant this key may be used for verification.
	// A key must not be accepted before it was published, or a token signed
	// during a botched rotation validates against a key nobody could have
	// fetched.
	NotBefore time.Time

	// RetireAt is when a retiring key's private half is destroyed. RetireAt is
	// not a deadline for deleting the public half.
	RetireAt *time.Time

	// RetiredAt records when the key completed retirement. Non-nil exactly when
	// status is retired, enforced by signing_keys_retired_chk.
	RetiredAt *time.Time
}

// IsActive reports whether this key currently signs.
func (k *SigningKey) IsActive() bool {
	return k.Status == KeyStatusActive
}

// IsPublished reports whether this key belongs in the JWKS: everything except
// retired. This is the set that must keep growing during a rotation.
func (k *SigningKey) IsPublished() bool {
	return k.Status == KeyStatusActive || k.Status == KeyStatusRetiring
}

// CanSign reports whether this key may be used to sign. Also requires a private
// half, because a retiring key that still holds one is a bug, and signing with
// it would silently extend its life.
func (k *SigningKey) CanSign() bool {
	return k.IsActive() && len(k.PrivateKeyEnc) > 0
}

// HasPrivateKey reports whether the private half is still present.
func (k *SigningKey) HasPrivateKey() bool {
	return len(k.PrivateKeyEnc) > 0
}

// IsVerifiable reports whether the key may be used to verify a token, honouring
// NotBefore.
func (k *SigningKey) IsVerifiable(now time.Time) bool {
	return k.IsPublished() && !k.NotBefore.After(now)
}

// PrivateDestroyedDue reports whether this key is past its retention window and
// its private half should now be destroyed.
//
// Retention must exceed access_ttl plus clock skew. Anything shorter destroys a
// key while tokens it signed are still inside their lifetime, and those tokens
// become unverifiable the moment the JWKS stops publishing it.
func (k *SigningKey) PrivateDestroyedDue(now time.Time) bool {
	if k.Status != KeyStatusRetiring || k.RetireAt == nil {
		return false
	}
	return !k.RetireAt.After(now)
}

// Age reports how long the key has existed, which is what the rotator compares
// against the configured rotation interval.
func (k *SigningKey) Age(now time.Time) time.Duration {
	return now.Sub(k.CreatedAt)
}
