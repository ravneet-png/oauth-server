package crypto

// AES-256-GCM for secrets at rest.
//
// The additional authenticated data is the important part of this file. GCM's
// authentication tag proves a ciphertext was not modified, but it does not prove
// the ciphertext belongs to the row you are reading. Without AAD, an attacker
// with write access to the database can copy the encrypted private key from row
// A to row B and every integrity check still passes. Binding the row
// identifier into the tag makes a transplanted ciphertext fail to decrypt.

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/subtle"
	"errors"
	"fmt"
	"io"
)

// ErrDecryptFailed means the ciphertext was truncated, corrupted, or was
// encrypted under a different key or different AAD.
//
// These are deliberately indistinguishable to the caller. Reporting "wrong AAD"
// separately from "wrong key" would confirm to an attacker that a guessed row
// identifier is correct, and GCM gives no way to tell the cases apart anyway.
var ErrDecryptFailed = errors.New("crypto: decryption failed")

// KeyLength is the required AES-256 key size in bytes.
const KeyLength = 32

// AESCipher seals and opens individual records with AES-256-GCM.
type AESCipher struct {
	aead cipher.AEAD
}

// NewAESCipher builds a cipher from a 32-byte key.
//
// The key comes from the environment or a KMS, never from a config file. It is
// copied into a fresh slice so a caller that later zeroes its own buffer cannot
// corrupt the cipher, and the caller's slice is not retained.
func NewAESCipher(key []byte) (*AESCipher, error) {
	if len(key) != KeyLength {
		// Rejecting a wrong length rather than hashing the key to fit: a 16
		// byte key silently upgraded to 32 would make it look stronger than it
		// is, and the operator would have no way to notice.
		return nil, fmt.Errorf("crypto: key is %d bytes, want %d for AES-256", len(key), KeyLength)
	}

	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("crypto: init aes: %w", err)
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("crypto: init gcm: %w", err)
	}

	keyCopy := make([]byte, len(key))
	copy(keyCopy, key)

	return &AESCipher{aead: aead}, nil
}

// GenerateKey returns a fresh 32-byte AES key.
//
// Used to create a deployment's first key. The output goes straight to an
// environment variable or a secret manager; writing it to a file would defeat
// the point of having it.
func GenerateKey() ([]byte, error) {
	return RandomBytes(KeyLength)
}

// Seal encrypts plaintext and returns nonce || ciphertext || tag.
//
// The returned slice is nonce||ciphertext||tag as ONE value rather than separate
// parts, so the nonce can never be stored without the ciphertext, mismatched with
// it, or omitted. A lost or reused nonce destroys the security of GCM entirely,
// and a representation that makes that mistake hard to make is worth the loss of
// tidiness.
func (c *AESCipher) Seal(plaintext []byte, aad []byte) ([]byte, error) {
	nonce, err := RandomNonce()
	if err != nil {
		return nil, err
	}
	// Seal appends to nonce, producing nonce || ciphertext || tag.
	return c.aead.Seal(nonce, nonce, plaintext, aad), nil
}

// SealString is Seal for a string, returning a value suitable for a BYTEA column.
func (c *AESCipher) SealString(plaintext string, aad []byte) ([]byte, error) {
	return c.Seal([]byte(plaintext), aad)
}

// Open decrypts a value produced by Seal.
//
// aad MUST be byte-identical to the value passed to Seal. Passing the wrong one
// is not a bug that produces garbage output, it produces ErrDecryptFailed, which
// is the intended behaviour: that is the row-transplant detection.
func (c *AESCipher) Open(ciphertext []byte, aad []byte) ([]byte, error) {
	nonceSize := c.aead.NonceSize()
	// The minimum valid length is nonce + tag with an empty plaintext.
	if len(ciphertext) < nonceSize+c.aead.Overhead() {
		return nil, fmt.Errorf("%w: ciphertext is %d bytes, minimum is %d",
			ErrDecryptFailed, len(ciphertext), nonceSize+c.aead.Overhead())
	}

	nonce, sealed := ciphertext[:nonceSize], ciphertext[nonceSize:]

	plaintext, err := c.aead.Open(nil, nonce, sealed, aad)
	if err != nil {
		return nil, ErrDecryptFailed
	}
	return plaintext, nil
}

// OpenString is Open returning a string.
func (c *AESCipher) OpenString(ciphertext []byte, aad []byte) (string, error) {
	plaintext, err := c.Open(ciphertext, aad)
	if err != nil {
		return "", err
	}
	return string(plaintext), nil
}

// KeyFingerprint returns a short, non-reversible identifier for a key, safe to
// log.
//
// This is a hash, not the key, and not a truncated key either. It exists so that
// two processes can confirm they hold the same encryption key without either
// disclosing it, which is the one operation that is otherwise impossible with a
// symmetric key.
func KeyFingerprint(key []byte) string {
	return SHA256Hex(string(key))[:16]
}

// EqualKey reports whether two keys are identical, in constant time.
//
// Used at boot to detect a key rotation that left two instances holding
// different keys. A plain bytes.Equal would leak the matching prefix length,
// which for a 32-byte key is enough to reconstruct it given a handful of
// measurements.
func EqualKey(a, b []byte) bool {
	return subtle.ConstantTimeCompare(a, b) == 1
}

// ReadFull is re-exported for callers that stream nonces. It exists so that this
// package has a single place that wraps io.ReadFull for crypto purposes.
func ReadFull(r io.Reader, buf []byte) error {
	if _, err := io.ReadFull(r, buf); err != nil {
		return fmt.Errorf("crypto: short read: %w", err)
	}
	return nil
}
