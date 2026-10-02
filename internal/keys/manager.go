// Package keys owns the server's signing keys: generating them, keeping the
// active private half in memory, and publishing the public halves as a JWKS.
//
// The division of labour with storage.SigningKeyRepo is deliberate. The repository
// is the source of truth and knows nothing about cryptography; this package knows
// nothing about SQL. Neither one can make a mistake the other would have to work
// around, because neither one can see the other's failure modes.
package keys

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"encoding/json"
	"errors"
	"fmt"
	"sync"
	"time"

	"github.com/lestrrat-go/jwx/v2/jwa"
	"github.com/lestrrat-go/jwx/v2/jwk"

	"oauth-server/internal/crypto"
	"oauth-server/internal/domain"
	"oauth-server/internal/storage"
)

// ErrNoActiveKey is returned when the manager holds no signing key and none can be
// loaded. It is a distinct sentinel rather than domain.ErrNotFound because the
// operator response is completely different: this is "the server cannot sign, it
// is fatal at boot", not "the caller asked for the wrong row".
var ErrNoActiveKey = errors.New("keys: no active signing key")

// RSAKeyBits is the modulus size for generated signing keys.
//
// 2048, not 4096, and not 1024. 1024 has been factored in the public literature
// and buys nothing. 4096 roughly quintuples sign latency and CPU per token, which
// matters because signing happens on every /authorize completion and every
// refresh. 2048 with RS256 is what current guidance recommends for signatures; the
// 3072-bit option is available via KeyBits if a deployment's threat model asks for
// it, and nothing in the rest of this package assumes 2048 specifically.
const RSAKeyBits = 2048

// aadPrefix namespaces the additional authenticated data for signing keys.
//
// The AAD binds a ciphertext to the row it belongs to, so a private key copied
// from one row to another fails to decrypt instead of silently working. Prefixing
// the row id keeps that AAD from colliding with any other AAD in the system, which
// would otherwise let a ciphertext be replayed into a different table that happens
// to use the same column name.
const aadPrefix = "signing_keys:private:"

// Manager generates, caches and publishes signing keys.
//
// Safe for concurrent use. Every request that signs reads the active key, while a
// rotation replaces it, so the cache is behind a RWMutex and the signing path takes
// the read lock.
type Manager struct {
	repo   *storage.SigningKeyRepo
	cipher *crypto.AESCipher

	// mu guards active. A plain mutex rather than atomic.Pointer because the cached
	// value is a struct of two fields that must be swapped together; an atomic
	// pointer to it would work too, but a reader would still need the lock to
	// observe a consistent pair, and the extra indirection buys nothing.
	mu     sync.RWMutex
	active *ActiveKey
}

// ActiveKey is a signing key ready to use: the parsed private key and the
// identity that goes in the JWS header.
type ActiveKey struct {
	// KID is published as the `kid` header and is the AAD for the stored
	// ciphertext, so it must be the same value at encrypt and decrypt time.
	KID string

	// Algorithm is always domain.AlgRS256 in this implementation. It is carried on
	// the key rather than hardcoded at the signing site so that a future PS256 or
	// ES256 key can be loaded without touching the signer.
	Algorithm string

	// Private is the parsed RSA key. Never serialised into a response, a log line
	// or an error message.
	Private *rsa.PrivateKey

	// JWK is the private key in JWK form, carrying kid and alg. The signer needs a
	// jwk.Key so that the JOSE library sets the `kid` and `alg` headers itself
	// rather than relying on the caller to remember them; a token whose `kid` is
	// missing is unverifiable by every relying party, and that is a failure mode
	// worth removing rather than documenting.
	JWK jwk.Key

	// NotBefore mirrors the stored value, so the signer can refuse a key that is
	// not yet valid for verification.
	NotBefore time.Time
}

// NewManager builds a Manager over repo, encrypting private halves with encKey.
//
// encKey must be 32 bytes for AES-256. It comes from the environment or a KMS and
// is the only thing standing between a database dump and the ability to mint tokens
// as this server, so it is never written to the database or logged.
func NewManager(repo *storage.SigningKeyRepo, encKey []byte) (*Manager, error) {
	if repo == nil {
		return nil, errors.New("keys: NewManager: repo is nil")
	}
	c, err := crypto.NewAESCipher(encKey)
	if err != nil {
		return nil, fmt.Errorf("keys: NewManager: %w", err)
	}
	return &Manager{repo: repo, cipher: c}, nil
}

// privateAAD returns the additional authenticated data for a key's private half.
//
// Derived from the KID only. The purpose of the AAD is to make a ciphertext
// transplanted into another row fail to decrypt, and the row identity is the KID.
func privateAAD(kid string) []byte {
	return []byte(aadPrefix + kid)
}

// LoadActive loads the active key from the database, decrypts its private half,
// and caches it for signing.
//
// Called at boot and again after every rotation. Returns ErrNoActiveKey when there
// is no active key, which at boot means the deployment has never generated one.
func (m *Manager) LoadActive(ctx context.Context) (*ActiveKey, error) {
	k, err := m.repo.GetActive(ctx)
	if err != nil {
		if errors.Is(err, domain.ErrNoActiveKey) {
			return nil, ErrNoActiveKey
		}
		return nil, fmt.Errorf("keys: LoadActive: %w", err)
	}

	priv, err := m.decryptPrivate(k)
	if err != nil {
		return nil, err
	}
	active, err := newActiveKey(k, priv)
	if err != nil {
		return nil, err
	}

	m.mu.Lock()
	m.active = active
	m.mu.Unlock()
	return active, nil
}

// decryptPrivate decrypts a key's private half.
//
// A missing private half on an active key is reported as an error rather than
// skipped, because an active key that cannot sign means the server is about to
// fail every token request, and "no error, no key" would turn that into a confusing
// downstream failure instead of a clear one here.
func (m *Manager) decryptPrivate(k *domain.SigningKey) (*rsa.PrivateKey, error) {
	if len(k.PrivateKeyEnc) == 0 {
		return nil, fmt.Errorf("keys: key %q is active but has no private half; it cannot sign", k.KID)
	}
	pem, err := m.cipher.Open(k.PrivateKeyEnc, privateAAD(k.KID))
	if err != nil {
		// Deliberately does not include the key material or the KID's row contents.
		// A decryption failure here means the encryption key does not match the one
		// the row was written with, which is a deployment problem, and the fix is to
		// correct the environment variable rather than to re-encrypt from a backup.
		return nil, fmt.Errorf("keys: decrypt private half of %q: %w (the encryption key does not match the one this key was stored with)", k.KID, err)
	}
	priv, err := parseRSAPrivateKey(pem)
	if err != nil {
		return nil, fmt.Errorf("keys: parse private half of %q: %w", k.KID, err)
	}
	return priv, nil
}

// GetSigningKey returns the cached active key.
//
// Errors rather than returning nil, so that a caller cannot accidentally sign with
// a nil key and produce a token with an empty signature. The cached value is a
// pointer that is only ever replaced, never mutated, so reading it under the lock
// and using it after releasing the lock is safe.
func (m *Manager) GetSigningKey() (*ActiveKey, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	if m.active == nil {
		return nil, ErrNoActiveKey
	}
	return m.active, nil
}

// GetJWKS returns every key that belongs in the published set: active and
// retiring, and nothing not yet valid for verification.
//
// The set must GROW through a rotation. Dropping a retiring key the moment it
// stops signing invalidates every unexpired token it signed, because a relying
// party has no way to verify a token signed by a key it can no longer fetch. That
// is why this reads IsVerifiable rather than filtering on IsActive.
//
// Keys whose NotBefore is in the future are excluded, so a token signed during a
// botched rotation cannot validate against a key that was never published.
//
// The private halves are not involved. The public JWK is read straight from the
// column the repository stored at write time, so serving a JWKS request decrypts
// nothing.
func (m *Manager) GetJWKS(ctx context.Context) (jwk.Set, error) {
	keys, err := m.repo.GetPublished(ctx)
	if err != nil {
		return nil, fmt.Errorf("keys: GetJWKS: %w", err)
	}

	set := jwk.NewSet()
	now := time.Now()
	for _, k := range keys {
		if !k.IsVerifiable(now) {
			continue
		}
		pub, err := jwk.ParseKey(k.PublicJWK)
		if err != nil {
			// One corrupt row must not take the whole JWKS down. If this key is
			// skipped, tokens it signed stop verifying, which is loud and
			// diagnosable; if the endpoint returns 500 instead, nothing verifies at
			// all and the cause is invisible to every relying party at once.
			continue
		}
		if err := set.AddKey(pub); err != nil {
			return nil, fmt.Errorf("keys: GetJWKS: add %s: %w", k.KID, err)
		}
	}
	return set, nil
}

// GenerateAndStore creates a new RSA signing key, encrypts its private half, and
// stores it as the active key.
//
// Returns the domain record. The private half is NOT returned to the caller: it
// exists only inside the returned record, already encrypted, and the plaintext only
// ever lives in this function and in memory afterwards via LoadActive. Handing
// back a decrypted private key would make it easy to log it by accident.
//
// This is the FIRST key only. Calling it when a key is already active is rejected
// by the schema's partial unique index, which is the correct outcome: a second
// active key for the same algorithm cannot exist, so replacing an active key is
// Rotate's job, not this one's.
func (m *Manager) GenerateAndStore(ctx context.Context) (*domain.SigningKey, error) {
	rec, err := m.Generate()
	if err != nil {
		return nil, err
	}
	if err := m.repo.Create(ctx, rec); err != nil {
		return nil, fmt.Errorf("keys: GenerateAndStore: %w", err)
	}
	return rec, nil
}

// Generate builds a signing key record and encrypts its private half WITHOUT storing
// it.
//
// This is what a rotation needs, and the reason it is separate from GenerateAndStore is
// a database constraint rather than a style preference.
//
// GenerateAndStore inserts with status = 'active', which is correct for the first key
// and fatal for a replacement: signing_keys has a partial unique index permitting one
// active row per algorithm, so persisting a second active key is rejected outright. A
// rotator that generates and stores before calling Rotate therefore fails at the
// insert, every tick, and the key silently never rotates while the log shows a
// duplicate-key error nobody reads.
//
// Generate leaves the decision of status and timing to the caller, and Rotate owns
// both by writing the row inside its own transaction next to the row it is retiring.
//
// The private half is returned only as ciphertext. The plaintext key lives in rec's
// encryption and nowhere else, so a caller cannot log it by mistake.
func (m *Manager) Generate() (*domain.SigningKey, error) {
	priv, err := rsa.GenerateKey(rand.Reader, RSAKeyBits)
	if err != nil {
		return nil, fmt.Errorf("keys: GenerateAndStore: generate rsa: %w", err)
	}

	kid, err := newKID()
	if err != nil {
		return nil, err
	}
	notBefore := time.Now().UTC()

	// The public JWK is generated from the same private key that is about to be
	// encrypted, never assembled separately. A public JWK that does not match its
	// private half produces tokens nobody can verify, and that failure is
	// invisible until a relying party complains.
	pub, err := jwk.FromRaw(priv.Public())
	if err != nil {
		return nil, fmt.Errorf("keys: GenerateAndStore: public jwk: %w", err)
	}
	if err := pub.Set(jwk.KeyIDKey, kid); err != nil {
		return nil, fmt.Errorf("keys: GenerateAndStore: set kid: %w", err)
	}
	if err := pub.Set(jwk.AlgorithmKey, jwa.RS256); err != nil {
		return nil, fmt.Errorf("keys: GenerateAndStore: set alg: %w", err)
	}
	// json.Marshal rather than a MarshalJSON method: jwk.Key's interface does not
	// declare one, but every concrete implementation satisfies json.Marshaler, so
	// the standard encoder produces the canonical JWK JSON.
	pubJSON, err := json.Marshal(pub)
	if err != nil {
		return nil, fmt.Errorf("keys: GenerateAndStore: marshal public jwk: %w", err)
	}

	pem, err := marshalRSAPrivateKey(priv)
	if err != nil {
		return nil, err
	}
	enc, err := m.cipher.Seal(pem, privateAAD(kid))
	if err != nil {
		return nil, fmt.Errorf("keys: GenerateAndStore: encrypt private half: %w", err)
	}

	rec := &domain.SigningKey{
		KID:           kid,
		Algorithm:     domain.AlgRS256,
		PublicJWK:     pubJSON,
		PrivateKeyEnc: enc,
		Status:        domain.KeyStatusActive,
		CreatedAt:     notBefore,
		NotBefore:     notBefore,
	}
	return rec, nil
}

// newActiveKey pairs a stored record with its parsed private key.
func newActiveKey(k *domain.SigningKey, priv *rsa.PrivateKey) (*ActiveKey, error) {
	privJWK, err := jwk.FromRaw(priv)
	if err != nil {
		return nil, fmt.Errorf("keys: build signing jwk for %q: %w", k.KID, err)
	}
	if err := privJWK.Set(jwk.KeyIDKey, k.KID); err != nil {
		return nil, fmt.Errorf("keys: set kid on signing jwk: %w", err)
	}
	if err := privJWK.Set(jwk.AlgorithmKey, jwa.SignatureAlgorithm(k.Algorithm)); err != nil {
		return nil, fmt.Errorf("keys: set alg on signing jwk: %w", err)
	}
	return &ActiveKey{
		KID:       k.KID,
		Algorithm: k.Algorithm,
		Private:   priv,
		JWK:       privJWK,
		NotBefore: k.NotBefore,
	}, nil
}
