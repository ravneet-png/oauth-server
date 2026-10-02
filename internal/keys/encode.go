package keys

// Private key serialisation and key identifier generation.
//
// One format, chosen once and applied on both sides of the encrypt/decrypt pair.
// The ambiguity this file exists to remove is the failure where a key is written by
// one version of the server and read by another that guesses a different encoding:
// the ciphertext is valid GCM output, the decryption succeeds, and the parse then
// fails on data that was never wrong in transit.

import (
	"crypto/rsa"
	"crypto/x509"
	"errors"
	"fmt"

	"oauth-server/internal/crypto"
)

// kidBytes is the entropy in a generated key identifier.
//
// 16 bytes. A KID is a public, non-secret label, so its only requirement is that
// two keys generated at the same moment never collide, and that a collision is not
// something an attacker could search for. 128 bits of CSPRNG output makes both
// hold without thought.
const kidBytes = 16

// kidPrefix makes a KID recognisable in logs and in a JWKS response.
//
// "sk_" for signing key. Purely cosmetic: LookupKeyID treats it as opaque, and
// including it means an operator reading a token header can tell at a glance which
// subsystem the key belongs to.
const kidPrefix = "sk_"

// newKID returns a fresh key identifier.
func newKID() (string, error) {
	tok, err := crypto.RandomTokenN(kidBytes)
	if err != nil {
		return "", fmt.Errorf("keys: newKID: %w", err)
	}
	return kidPrefix + tok, nil
}

// marshalRSAPrivateKey encodes priv as PKCS#8 DER.
//
// PKCS#8 rather than PKCS#1, because PKCS#1 encodes the modulus, the public
// exponent and the private exponent with no algorithm field, so the same bytes
// cannot be told apart from a different key type that happens to be the same
// length. PKCS#8 names the algorithm, which means the parser rejects a mismatched
// key instead of producing a private key with nonsensical parameters.
//
// DER rather than PEM because the ciphertext is stored in a BYTEA column, and PEM
// would wrap binary data in ASCII armour purely so that a human could paste it
// somewhere. Nothing pastes a key by hand here: the value is encrypted the instant
// it is produced and only ever decrypted by this package.
func marshalRSAPrivateKey(priv *rsa.PrivateKey) ([]byte, error) {
	der, err := x509.MarshalPKCS8PrivateKey(priv)
	if err != nil {
		return nil, fmt.Errorf("keys: marshal rsa private key: %w", err)
	}
	return der, nil
}

// parseRSAPrivateKey reverses marshalRSAPrivateKey.
//
// Reports a non-RSA key as its own error, because a row containing an EC key means
// the deployment is mid-migration to ES256 and the operator needs to know that,
// not that "something went wrong with a key".
func parseRSAPrivateKey(der []byte) (*rsa.PrivateKey, error) {
	if len(der) == 0 {
		return nil, errors.New("keys: private key is empty")
	}
	parsed, err := x509.ParsePKCS8PrivateKey(der)
	if err != nil {
		return nil, fmt.Errorf("keys: parse pkcs8 private key: %w", err)
	}
	priv, ok := parsed.(*rsa.PrivateKey)
	if !ok {
		return nil, fmt.Errorf("keys: stored key is %T, want *rsa.PrivateKey; this deployment is not configured for RSA signing", parsed)
	}
	// Validate rather than trust. A PKCS#8 blob can parse into an rsa.PrivateKey
	// whose primes do not actually produce the stored public key, and using such a
	// key yields a signature that fails verification at every relying party with no
	// error here at all.
	if err := priv.Validate(); err != nil {
		return nil, fmt.Errorf("keys: stored rsa private key is inconsistent: %w", err)
	}
	priv.Precompute()
	return priv, nil
}
