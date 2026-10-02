package crypto

// Tests for the primitives. Every claim in this file is checked against a
// published test vector or a property that must hold, never against a
// previously recorded output of this same code, which would only prove the code
// has not changed.

import (
	"context"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/pquerna/otp"
)

// ----------------------------------------------------------------------------
// random.go
// ----------------------------------------------------------------------------

func TestRandomBytes(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		n       int
		wantErr bool
	}{
		{name: "32 bytes for a token", n: TokenBytes},
		{name: "12 bytes for a GCM nonce", n: 12},
		{name: "1 byte", n: 1},
		{name: "4096 bytes", n: 4096},
		{name: "zero is rejected", n: 0, wantErr: true},
		{name: "negative is rejected", n: -1, wantErr: true},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			got, err := RandomBytes(tc.n)
			if tc.wantErr {
				if err == nil {
					t.Fatalf("RandomBytes(%d) = nil error, want an error", tc.n)
				}
				if got != nil {
					t.Errorf("RandomBytes(%d) returned %d bytes alongside an error, want nil", tc.n, len(got))
				}
				return
			}
			if err != nil {
				t.Fatalf("RandomBytes(%d): %v", tc.n, err)
			}
			if len(got) != tc.n {
				t.Errorf("len = %d, want %d", len(got), tc.n)
			}
		})
	}
}

func TestRandomBytesAreNotConstant(t *testing.T) {
	t.Parallel()

	// Two calls returning identical bytes would mean the source is broken. This
	// is not a statistical test; a single collision is a hard failure, so there
	// is no flakiness to tolerate.
	a, err := RandomBytes(TokenBytes)
	if err != nil {
		t.Fatal(err)
	}
	b, err := RandomBytes(TokenBytes)
	if err != nil {
		t.Fatal(err)
	}
	if string(a) == string(b) {
		t.Error("two calls to RandomBytes returned identical output")
	}
}

func TestRandomTokenEncoding(t *testing.T) {
	t.Parallel()

	token, err := RandomToken()
	if err != nil {
		t.Fatal(err)
	}

	// 32 bytes raw-base64url is 43 characters: ceil(32 * 4 / 3) with no padding.
	if len(token) != 43 {
		t.Errorf("len(RandomToken()) = %d, want 43 for 32 raw-base64 bytes", len(token))
	}

	// The value is carried in URLs, query strings and cookies, so the standard
	// base64 alphabet's '+' and '/' and the padding '=' must all be absent.
	for _, forbidden := range []string{"+", "/", "="} {
		if strings.Contains(token, forbidden) {
			t.Errorf("token %q contains %q, which is not URL-safe", token, forbidden)
		}
	}

	// It must round-trip as raw URL base64.
	decoded, err := base64.RawURLEncoding.DecodeString(token)
	if err != nil {
		t.Fatalf("token is not valid raw URL base64: %v", err)
	}
	if len(decoded) != TokenBytes {
		t.Errorf("decoded %d bytes, want %d", len(decoded), TokenBytes)
	}
}

func TestRandomTokenN(t *testing.T) {
	t.Parallel()

	tests := []struct {
		n         int
		wantChars int
	}{
		{n: 16, wantChars: 22}, // backup codes
		{n: 20, wantChars: 27}, // TOTP-sized material
		{n: 32, wantChars: 43},
	}

	for _, tc := range tests {
		t.Run(strconv.Itoa(tc.n), func(t *testing.T) {
			t.Parallel()
			token, err := RandomTokenN(tc.n)
			if err != nil {
				t.Fatal(err)
			}
			if len(token) != tc.wantChars {
				t.Errorf("len = %d, want %d", len(token), tc.wantChars)
			}
		})
	}

	if _, err := RandomTokenN(0); err == nil {
		t.Error("RandomTokenN(0) = nil error, want an error")
	}
}

func TestRandomNonceIsTwelveBytes(t *testing.T) {
	t.Parallel()

	// GCM's nonce size is fixed by the standard. A nonce of any other length
	// requires an explicit birthday analysis and is not what the key was sized
	// for.
	for i := 0; i < 100; i++ {
		n, err := RandomNonce()
		if err != nil {
			t.Fatal(err)
		}
		if len(n) != 12 {
			t.Fatalf("nonce is %d bytes, want 12", len(n))
		}
	}
}

func TestRandomNoncesDoNotRepeat(t *testing.T) {
	t.Parallel()

	// A repeated nonce under one key is catastrophic for GCM: it leaks the XOR
	// of two plaintexts and allows forgery. 1000 samples must all differ.
	seen := make(map[string]bool, 1000)
	for i := 0; i < 1000; i++ {
		n, err := RandomNonce()
		if err != nil {
			t.Fatal(err)
		}
		key := string(n)
		if seen[key] {
			t.Fatal("RandomNonce produced a duplicate nonce")
		}
		seen[key] = true
	}
}

// ----------------------------------------------------------------------------
// hash.go
// ----------------------------------------------------------------------------

func TestSHA256HexKnownVectors(t *testing.T) {
	t.Parallel()

	// Published SHA-256 vectors. If these fail, everything derived from them is
	// wrong and every existing row in the database becomes unreadable.
	tests := []struct {
		in   string
		want string
	}{
		{in: "", want: "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"},
		{in: "abc", want: "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"},
		{
			in:   "abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq",
			want: "248d6a61d20638b8e5c026930c3e6039a33ce45964ff2167f6ecedd419db06c1",
		},
	}

	for _, tc := range tests {
		t.Run(tc.in, func(t *testing.T) {
			t.Parallel()
			if got := SHA256Hex(tc.in); got != tc.want {
				t.Errorf("SHA256Hex(%q) = %s, want %s", tc.in, got, tc.want)
			}
		})
	}
}

func TestSHA256HexIsLowercase(t *testing.T) {
	t.Parallel()

	// These values become SQL primary keys and index entries. Uppercase hex
	// would make an index entry sort differently from the same value typed in
	// a WHERE clause by a human, which is a silent full-scan.
	got := SHA256Hex("some-opaque-token")
	if got != strings.ToLower(got) {
		t.Errorf("SHA256Hex returned %q, want lowercase", got)
	}
	if len(got) != 64 {
		t.Errorf("len = %d, want 64 hex characters for 32 bytes", len(got))
	}
}

func TestVerifySHA256Hex(t *testing.T) {
	t.Parallel()

	stored := SHA256Hex("correct-horse-battery-staple")

	tests := []struct {
		name      string
		plaintext string
		stored    string
		want      bool
	}{
		{name: "correct", plaintext: "correct-horse-battery-staple", stored: stored, want: true},
		{name: "wrong secret", plaintext: "wrong", stored: stored, want: false},
		{name: "empty plaintext", plaintext: "", stored: stored, want: false},
		{name: "empty stored digest", plaintext: "correct-horse-battery-staple", stored: "", want: false},
		{name: "truncated stored digest", plaintext: "correct-horse-battery-staple", stored: stored[:63], want: false},
		{name: "uppercase stored digest", plaintext: "correct-horse-battery-staple", stored: strings.ToUpper(stored), want: false},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			if got := VerifySHA256Hex(tc.plaintext, tc.stored); got != tc.want {
				t.Errorf("VerifySHA256Hex = %v, want %v", got, tc.want)
			}
		})
	}
}

func TestParseSHA256Hex(t *testing.T) {
	t.Parallel()

	valid := SHA256Hex("x")
	raw, err := ParseSHA256Hex(valid)
	if err != nil {
		t.Fatalf("ParseSHA256Hex on a valid digest: %v", err)
	}
	if len(raw) != 32 {
		t.Errorf("decoded %d bytes, want 32", len(raw))
	}
	if hex.EncodeToString(raw) != valid {
		t.Errorf("round trip changed the value")
	}

	tests := []struct {
		name string
		in   string
	}{
		{name: "odd length", in: "abc"},
		{name: "non hex characters", in: strings.Repeat("z", 64)},
		{name: "too short", in: valid[:62]},
		{name: "empty", in: ""},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			if _, err := ParseSHA256Hex(tc.in); err == nil {
				t.Errorf("ParseSHA256Hex(%q) = nil error, want an error", tc.in)
			}
		})
	}
}

func TestHMACIdentifier(t *testing.T) {
	t.Parallel()

	pepper := []byte("a-pepper-from-the-environment")

	// Deterministic for the same input and pepper, which is what makes an audit
	// row joinable across events.
	a := HMACIdentifierHex("user@example.com", pepper)
	b := HMACIdentifierHex("user@example.com", pepper)
	if a != b {
		t.Error("HMACIdentifierHex is not deterministic for the same input")
	}

	// Different for a different address, so two users are distinguishable.
	if HMACIdentifierHex("other@example.com", pepper) == a {
		t.Error("two different addresses produced the same digest")
	}

	// Unkeyed SHA-256 of an email is trivially reversible, so the keyed digest
	// must NOT equal it. This is the whole reason HMACIdentifier exists.
	if a == SHA256Hex("user@example.com") {
		t.Error("HMACIdentifierHex matches the unkeyed SHA-256, so the pepper is not being applied")
	}

	// A different pepper must produce a different digest, which is what makes
	// rotation meaningful.
	if HMACIdentifierHex("user@example.com", []byte("other-pepper")) == a {
		t.Error("a different pepper produced the same digest")
	}
}

// ----------------------------------------------------------------------------
// password.go
// ----------------------------------------------------------------------------

func TestHashPasswordFormat(t *testing.T) {
	t.Parallel()

	// Reduced cost for test runtime. The format under test is identical.
	p := Argon2Params{Memory: 8 * 1024, Iterations: 1, Parallelism: 1, SaltLength: 16, KeyLength: 32}
	if err := p.Validate(); err != nil {
		t.Fatalf("test params invalid: %v", err)
	}

	hash, err := HashPassword("correct horse battery staple", p)
	if err != nil {
		t.Fatal(err)
	}

	// PHC format: $argon2id$v=19$m=...,t=...,p=...$salt$hash
	// Split yields 6 elements: the empty marker plus five values.
	parts := strings.Split(hash, "$")
	if len(parts) != 6 || parts[0] != "" {
		t.Fatalf("hash %q does not have 5 $-separated fields (got %d elements)", hash, len(parts))
	}
	if parts[1] != "argon2id" {
		t.Errorf("algorithm = %q, want argon2id", parts[1])
	}
	if parts[2] != "v=19" {
		t.Errorf("version = %q, want v=19", parts[2])
	}
	if !strings.HasPrefix(parts[3], "m=") || !strings.Contains(parts[3], ",t=") || !strings.Contains(parts[3], ",p=") {
		t.Errorf("cost field = %q, want m=,t=,p=", parts[3])
	}
}

func TestHashPasswordIsSalted(t *testing.T) {
	t.Parallel()

	p := Argon2Params{Memory: 8 * 1024, Iterations: 1, Parallelism: 1, SaltLength: 16, KeyLength: 32}

	// Two hashes of the SAME password must differ. A shared salt would make
	// every user with the same password visibly identical and let one
	// precomputation attack all of them.
	a, err := HashPassword("same-password", p)
	if err != nil {
		t.Fatal(err)
	}
	b, err := HashPassword("same-password", p)
	if err != nil {
		t.Fatal(err)
	}
	if a == b {
		t.Error("two hashes of the same password are identical, so the salt is not random")
	}
}

func TestVerifyPassword(t *testing.T) {
	t.Parallel()

	p := Argon2Params{Memory: 8 * 1024, Iterations: 1, Parallelism: 1, SaltLength: 16, KeyLength: 32}
	hash, err := HashPassword("correct horse battery staple", p)
	if err != nil {
		t.Fatal(err)
	}

	tests := []struct {
		name      string
		plaintext string
		hash      string
		wantOK    bool
		wantErr   bool
	}{
		{name: "correct", plaintext: "correct horse battery staple", hash: hash, wantOK: true},
		{name: "wrong", plaintext: "wrong", hash: hash, wantOK: false},
		{name: "empty", plaintext: "", hash: hash, wantOK: false},
		{name: "case differs", plaintext: "Correct Horse Battery Staple", hash: hash, wantOK: false},
		{name: "trailing space", plaintext: "correct horse battery staple ", hash: hash, wantOK: false},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			ok, err := VerifyPassword(tc.plaintext, tc.hash)
			if tc.wantErr {
				if err == nil {
					t.Fatalf("VerifyPassword = nil error, want an error for %q", tc.hash)
				}
				return
			}
			if err != nil {
				t.Fatalf("VerifyPassword: %v", err)
			}
			if ok != tc.wantOK {
				t.Errorf("VerifyPassword = %v, want %v", ok, tc.wantOK)
			}
		})
	}
}

func TestVerifyPasswordMalformedHashIsAnError(t *testing.T) {
	t.Parallel()

	// An error, not false. false means "wrong password"; an error means "this
	// user's record is corrupt". Collapsing them makes a database problem
	// present as every user having forgotten their password.
	tests := []struct {
		name string
		hash string
	}{
		{name: "empty", hash: ""},
		{name: "not a hash", hash: "hunter2"},
		{name: "wrong algorithm", hash: "$argon2i$v=19$m=8192,t=1,p=1$c2FsdA$aGFzaA"},
		{name: "truncated", hash: "$argon2id$v=19$m=8192,t=1,p=1"},
		{name: "bad cost", hash: "$argon2id$v=19$m=x,t=1,p=1$c2FsdA$aGFzaA"},
		{name: "bad version", hash: "$argon2id$v=99$m=8192,t=1,p=1$c2FsdA$aGFzaA"},
		{name: "unknown cost key", hash: "$argon2id$v=19$m=8192,t=1,p=1,x=9$c2FsdA$aGFzaA"},
		{name: "zero cost", hash: "$argon2id$v=19$m=0,t=0,p=0$c2FsdA$aGFzaA"},
		{name: "bad base64 salt", hash: "$argon2id$v=19$m=8192,t=1,p=1$!!!$aGFzaA"},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			ok, err := VerifyPassword("anything", tc.hash)
			if err == nil {
				t.Fatalf("VerifyPassword(%q) = %v, nil, want an error", tc.hash, ok)
			}
			if ok {
				t.Error("VerifyPassword returned true alongside an error")
			}
		})
	}
}

func TestVerifyPasswordIgnoresConfiguredParams(t *testing.T) {
	t.Parallel()

	// The whole point: a hash created under one cost must still verify when the
	// server's configured cost is different. If verification used config, raising
	// the cost would make every existing password unverifiable.
	p := Argon2Params{Memory: 8 * 1024, Iterations: 1, Parallelism: 1, SaltLength: 16, KeyLength: 32}
	hash, err := HashPassword("password", p)
	if err != nil {
		t.Fatal(err)
	}

	stronger := Argon2Params{Memory: 64 * 1024, Iterations: 3, Parallelism: 4, SaltLength: 16, KeyLength: 32}
	ok, err := VerifyPassword("password", hash)
	if err != nil {
		t.Fatal(err)
	}
	if !ok {
		t.Error("a hash created with weak parameters failed to verify")
	}

	// And it must be reported as needing a rehash.
	needs, err := NeedsRehash(hash, stronger)
	if err != nil {
		t.Fatal(err)
	}
	if !needs {
		t.Error("NeedsRehash = false, want true for a hash weaker than the configured parameters")
	}
}

func TestNeedsRehash(t *testing.T) {
	t.Parallel()

	weak := Argon2Params{Memory: 8 * 1024, Iterations: 1, Parallelism: 1, SaltLength: 16, KeyLength: 32}
	strong := Argon2Params{Memory: 64 * 1024, Iterations: 3, Parallelism: 4, SaltLength: 16, KeyLength: 32}

	weakHash, err := HashPassword("p", weak)
	if err != nil {
		t.Fatal(err)
	}
	strongHash, err := HashPassword("p", strong)
	if err != nil {
		t.Fatal(err)
	}

	tests := []struct {
		name string
		hash string
		p    Argon2Params
		want bool
	}{
		{name: "weak hash against strong params needs rehash", hash: weakHash, p: strong, want: true},
		{name: "strong hash against strong params is fine", hash: strongHash, p: strong, want: false},
		{name: "strong hash against weak params is fine", hash: strongHash, p: weak, want: false},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			got, err := NeedsRehash(tc.hash, tc.p)
			if err != nil {
				t.Fatal(err)
			}
			if got != tc.want {
				t.Errorf("NeedsRehash = %v, want %v", got, tc.want)
			}
		})
	}
}

func TestArgon2ParamsValidate(t *testing.T) {
	t.Parallel()

	good := DefaultArgon2Params()

	tests := []struct {
		name    string
		mutate  func(p *Argon2Params)
		wantErr bool
	}{
		{name: "defaults are valid", mutate: func(p *Argon2Params) {}},
		{name: "memory below minimum", mutate: func(p *Argon2Params) { p.Memory = 1024 }, wantErr: true},
		{name: "memory above ceiling", mutate: func(p *Argon2Params) { p.Memory = 2 * 1024 * 1024 }, wantErr: true},
		{name: "zero iterations", mutate: func(p *Argon2Params) { p.Iterations = 0 }, wantErr: true},
		{name: "iterations above ceiling", mutate: func(p *Argon2Params) { p.Iterations = 100 }, wantErr: true},
		{name: "zero parallelism", mutate: func(p *Argon2Params) { p.Parallelism = 0 }, wantErr: true},
		{name: "parallelism above ceiling", mutate: func(p *Argon2Params) { p.Parallelism = 64 }, wantErr: true},
		{name: "short salt", mutate: func(p *Argon2Params) { p.SaltLength = 8 }, wantErr: true},
		{name: "short key", mutate: func(p *Argon2Params) { p.KeyLength = 8 }, wantErr: true},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			p := good
			tc.mutate(&p)
			err := p.Validate()
			if tc.wantErr && err == nil {
				t.Errorf("Validate = nil, want an error")
			}
			if !tc.wantErr && err != nil {
				t.Errorf("Validate = %v, want nil", err)
			}
		})
	}
}

func TestDefaultArgon2ParamsMatchConfig(t *testing.T) {
	t.Parallel()

	// config.yaml declares 65536 KiB / 3 iterations / 4 lanes. If these drift
	// apart, an operator raising the config value sees no change in behaviour.
	p := DefaultArgon2Params()
	if p.Memory != 65536 {
		t.Errorf("Memory = %d KiB, want 65536 to match config.yaml", p.Memory)
	}
	if p.Iterations != 3 {
		t.Errorf("Iterations = %d, want 3 to match config.yaml", p.Iterations)
	}
	if p.Parallelism != 4 {
		t.Errorf("Parallelism = %d, want 4 to match config.yaml", p.Parallelism)
	}
}

// ----------------------------------------------------------------------------
// aes.go
// ----------------------------------------------------------------------------

func TestAESCipherRoundTrip(t *testing.T) {
	t.Parallel()

	key, err := GenerateKey()
	if err != nil {
		t.Fatal(err)
	}
	c, err := NewAESCipher(key)
	if err != nil {
		t.Fatal(err)
	}

	aad := []byte("signing_keys:k1")

	tests := []struct {
		name      string
		plaintext string
	}{
		{name: "typical", plaintext: "-----BEGIN PRIVATE KEY-----\nMIIE...\n-----END PRIVATE KEY-----"},
		{name: "short", plaintext: "x"},
		{name: "empty", plaintext: ""},
		{name: "utf8", plaintext: "clé-de-chiffrement-é€"},
		{name: "large", plaintext: strings.Repeat("a", 100_000)},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			sealed, err := c.SealString(tc.plaintext, aad)
			if err != nil {
				t.Fatal(err)
			}
			opened, err := c.OpenString(sealed, aad)
			if err != nil {
				t.Fatalf("OpenString: %v", err)
			}
			if opened != tc.plaintext {
				t.Errorf("round trip changed the value")
			}
		})
	}
}

func TestAESNonceIsFreshPerRecord(t *testing.T) {
	t.Parallel()

	key, _ := GenerateKey()
	c, err := NewAESCipher(key)
	if err != nil {
		t.Fatal(err)
	}
	aad := []byte("aad")

	// Encrypting the SAME plaintext twice must produce different ciphertexts.
	// Identical output would mean a reused nonce, which under GCM leaks the XOR
	// of the plaintexts and permits forgery.
	a, err := c.SealString("identical plaintext", aad)
	if err != nil {
		t.Fatal(err)
	}
	b, err := c.SealString("identical plaintext", aad)
	if err != nil {
		t.Fatal(err)
	}
	if string(a) == string(b) {
		t.Error("two seals of the same plaintext are byte-identical, so the nonce is being reused")
	}
}

func TestAESTamperDetection(t *testing.T) {
	t.Parallel()

	key, _ := GenerateKey()
	c, _ := NewAESCipher(key)
	aad := []byte("signing_keys:k1")
	sealed, err := c.SealString("secret material", aad)
	if err != nil {
		t.Fatal(err)
	}

	t.Run("flipped ciphertext bit", func(t *testing.T) {
		t.Parallel()
		tampered := make([]byte, len(sealed))
		copy(tampered, sealed)
		tampered[len(tampered)-1] ^= 0x01
		if _, err := c.OpenString(tampered, aad); err == nil {
			t.Error("a modified ciphertext decrypted, so the GCM tag is not being checked")
		}
	})

	t.Run("flipped nonce bit", func(t *testing.T) {
		t.Parallel()
		tampered := make([]byte, len(sealed))
		copy(tampered, sealed)
		tampered[0] ^= 0x01
		if _, err := c.OpenString(tampered, aad); err == nil {
			t.Error("a modified nonce decrypted, so authentication is not covering the nonce")
		}
	})

	t.Run("truncated", func(t *testing.T) {
		t.Parallel()
		if _, err := c.OpenString(sealed[:len(sealed)-1], aad); err == nil {
			t.Error("a truncated ciphertext decrypted")
		}
	})

	t.Run("too short", func(t *testing.T) {
		t.Parallel()
		if _, err := c.OpenString([]byte{1, 2, 3}, aad); err == nil {
			t.Error("a 3 byte value decrypted")
		}
	})
}

func TestAADPreventsRowTransplant(t *testing.T) {
	t.Parallel()

	key, _ := GenerateKey()
	c, _ := NewAESCipher(key)

	// This is the reason AAD is mandatory here. An attacker with write access to
	// signing_keys copies k1's encrypted private key over k2's row. Without AAD
	// every integrity check still passes and the server decrypts k1's key while
	// believing it is k2's, so a key can be substituted undetectably.
	rowOne := []byte("signing_keys:k1")
	rowTwo := []byte("signing_keys:k2")

	sealedForRowOne, err := c.SealString("private key of k1", rowOne)
	if err != nil {
		t.Fatal(err)
	}

	if _, err := c.OpenString(sealedForRowOne, rowTwo); err == nil {
		t.Fatal("a ciphertext sealed for row k1 decrypted under row k2's AAD; row transplant is possible")
	}
}

func TestNewAESCipherRejectsWrongKeyLength(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		size int
	}{
		{name: "16 bytes is AES-128, not accepted", size: 16},
		{name: "24 bytes is AES-192, not accepted", size: 24},
		{name: "31 bytes", size: 31},
		{name: "33 bytes", size: 33},
		{name: "empty", size: 0},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			// Rejected rather than hashed up to 32: a 16 byte key silently
			// upgraded would look stronger than it is and the operator would have
			// no way to notice.
			if _, err := NewAESCipher(make([]byte, tc.size)); err == nil {
				t.Errorf("NewAESCipher with %d bytes = nil, want an error", tc.size)
			}
		})
	}
}

func TestNewAESCipherDoesNotAliasCallerKey(t *testing.T) {
	t.Parallel()

	key, _ := GenerateKey()
	c, err := NewAESCipher(key)
	if err != nil {
		t.Fatal(err)
	}

	// The caller zeroing its own buffer, as a careful secret handler would, must
	// not break the cipher.
	for i := range key {
		key[i] = 0
	}

	sealed, err := c.SealString("still works", []byte("aad"))
	if err != nil {
		t.Fatal(err)
	}
	opened, err := c.OpenString(sealed, []byte("aad"))
	if err != nil {
		t.Fatalf("cipher broke when the caller zeroed its key copy: %v", err)
	}
	if opened != "still works" {
		t.Error("decrypted value is wrong")
	}
}

func TestWrongKeyFails(t *testing.T) {
	t.Parallel()

	keyA, _ := GenerateKey()
	keyB, _ := GenerateKey()
	cipherA, _ := NewAESCipher(keyA)

	sealed, err := cipherA.SealString("secret", []byte("aad"))
	if err != nil {
		t.Fatal(err)
	}

	cipherB, _ := NewAESCipher(keyB)
	if _, err := cipherB.OpenString(sealed, []byte("aad")); err == nil {
		t.Error("a ciphertext decrypted under the wrong key")
	}
}

func TestKeyFingerprint(t *testing.T) {
	t.Parallel()

	key, _ := GenerateKey()
	fp := KeyFingerprint(key)

	if len(fp) != 16 {
		t.Errorf("len(KeyFingerprint) = %d, want 16", len(fp))
	}
	// Deterministic, so two processes holding the same key agree without
	// disclosing it.
	if KeyFingerprint(key) != fp {
		t.Error("KeyFingerprint is not deterministic")
	}
	other, _ := GenerateKey()
	if KeyFingerprint(other) == fp {
		t.Error("two different keys produced the same fingerprint")
	}
	// It must not be a prefix of the key itself.
	if strings.HasPrefix(hex.EncodeToString(key), fp) {
		t.Error("KeyFingerprint is a prefix of the key, so it discloses key material")
	}
}

func TestEqualKey(t *testing.T) {
	t.Parallel()

	a, _ := GenerateKey()
	b, _ := GenerateKey()

	if !EqualKey(a, append([]byte(nil), a...)) {
		t.Error("a key is not equal to a copy of itself")
	}
	if EqualKey(a, b) {
		t.Error("two different keys compared equal")
	}
}

// ----------------------------------------------------------------------------
// pkce.go
// ----------------------------------------------------------------------------

func TestS256ChallengeRFC7636Vector(t *testing.T) {
	t.Parallel()

	// The worked example from RFC 7636 appendix B.
	const verifier = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"
	const want = "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM"

	if got := S256Challenge(verifier); got != want {
		t.Errorf("S256Challenge(%q) = %q, want %q", verifier, got, want)
	}
}

func TestS256ChallengeEncoding(t *testing.T) {
	t.Parallel()

	// Raw URL base64 with no padding. Standard base64's '+' and '/' break when
	// carried in a query string unless percent-encoded, and the client may not
	// decode them.
	got := S256Challenge("some-verifier")
	if len(got) != 43 {
		t.Errorf("len = %d, want 43", len(got))
	}
	for _, forbidden := range []string{"+", "/", "=", " "} {
		if strings.Contains(got, forbidden) {
			t.Errorf("challenge %q contains %q", got, forbidden)
		}
	}
	decoded, err := base64.RawURLEncoding.DecodeString(got)
	if err != nil {
		t.Fatalf("challenge is not raw URL base64: %v", err)
	}
	if len(decoded) != 32 {
		t.Errorf("decoded %d bytes, want 32", len(decoded))
	}
}

func TestVerifyPKCE(t *testing.T) {
	t.Parallel()

	const verifier = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"
	challenge := S256Challenge(verifier)

	tests := []struct {
		name      string
		verifier  string
		challenge string
		method    string
		wantErr   bool
	}{
		{name: "valid S256", verifier: verifier, challenge: challenge, method: MethodS256},
		{name: "wrong verifier", verifier: "wrong", challenge: challenge, method: MethodS256, wantErr: true},
		{name: "empty verifier", verifier: "", challenge: challenge, method: MethodS256, wantErr: true},

		// OAuth 2.1 removes plain. It is refused even when the challenge equals
		// the verifier, which is exactly the case that would otherwise work.
		{name: "plain is refused even when the values match", verifier: "abc", challenge: "abc", method: MethodPlain, wantErr: true},
		{name: "empty method is refused", verifier: verifier, challenge: challenge, method: "", wantErr: true},
		{name: "lowercase s256 is refused", verifier: verifier, challenge: challenge, method: "s256", wantErr: true},
		{name: "S512 is refused", verifier: verifier, challenge: challenge, method: "S512", wantErr: true},
		{name: "wrong challenge", verifier: verifier, challenge: S256Challenge("other"), method: MethodS256, wantErr: true},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			err := VerifyPKCE(tc.verifier, tc.challenge, tc.method)
			if tc.wantErr && err == nil {
				t.Errorf("VerifyPKCE = nil, want an error")
			}
			if !tc.wantErr && err != nil {
				t.Errorf("VerifyPKCE = %v, want nil", err)
			}
		})
	}
}

func TestValidCodeChallenge(t *testing.T) {
	t.Parallel()

	valid := S256Challenge("verifier")

	tests := []struct {
		name string
		in   string
		want bool
	}{
		{name: "a real challenge", in: valid, want: true},
		{name: "too short", in: valid[:42], want: false},
		{name: "too long", in: valid + "A", want: false},
		{name: "empty", in: "", want: false},
		{name: "all A is 43 valid base64 characters", in: strings.Repeat("A", 43), want: true},
		{name: "padded", in: valid + "=", want: false},
		{name: "non base64 characters", in: strings.Repeat("!", 43), want: false},
		{name: "space is not base64", in: strings.Repeat("A", 42) + " ", want: false},

		// A 43 character verifier and a 43 character challenge are the same set
		// of characters, so a shape check cannot tell them apart and must not
		// try. Rejecting a verifier here would reject a legitimate client that
		// generated one with a high-entropy alphabet. This is asserted
		// explicitly because the correct behaviour is genuinely surprising.
		{name: "a verifier is indistinguishable by shape and is accepted", in: "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk", want: true},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			if got := ValidCodeChallenge(tc.in); got != tc.want {
				t.Errorf("ValidCodeChallenge(%q) = %v, want %v", tc.in, got, tc.want)
			}
		})
	}
}

func TestValidCodeVerifier(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		in   string
		want bool
	}{
		{name: "at the 43 character minimum", in: strings.Repeat("a", 43), want: true},
		{name: "at the 128 character maximum", in: strings.Repeat("a", 128), want: true},
		{name: "42 characters is too short", in: strings.Repeat("a", 42), want: false},
		{name: "129 characters is too long", in: strings.Repeat("a", 129), want: false},
		{name: "empty", in: "", want: false},
		{name: "all unreserved punctuation", in: "aA0-._~" + strings.Repeat("b", 36), want: true},
		{name: "contains a slash", in: strings.Repeat("a", 42) + "/", want: false},
		{name: "contains a plus", in: strings.Repeat("a", 42) + "+", want: false},
		{name: "contains a space", in: strings.Repeat("a", 42) + " ", want: false},
		{name: "contains a percent", in: strings.Repeat("a", 42) + "%", want: false},
		{name: "contains a non ascii byte", in: strings.Repeat("a", 42) + "\u00e9", want: false},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			if got := ValidCodeVerifier(tc.in); got != tc.want {
				t.Errorf("ValidCodeVerifier(%q) = %v, want %v", tc.in, got, tc.want)
			}
		})
	}
}

// ----------------------------------------------------------------------------
// timing.go
// ----------------------------------------------------------------------------

// TestDefaultJitterIsProtective asserts the state a server is in before anything
// calls ConfigureTiming.
//
// Every other test in this file configures jitter before asserting on it, so
// before this test existed the package default was never checked by anything. The
// entire safety argument for this file rests on that default being live: it is
// what protects a partially-wired server, and what an operator inherits without
// opting in. A regression that disabled the default would have passed every other
// test in this file.
func TestDefaultJitterIsProtective(t *testing.T) {
	min, max, enabled, read := currentJitter()

	if !enabled {
		t.Fatal("package default has jitter disabled; init() must enable it so a partially wired server is still protected")
	}
	if read == nil {
		t.Error("package default has no randomness source; SleepJitter would silently no-op")
	}
	if min < 25*time.Millisecond {
		t.Errorf("default min %v is too narrow to swamp an argon2id hash at 64 MiB", min)
	}
	if max <= min {
		t.Errorf("default max %v must exceed min %v or there is no window to draw from", max, min)
	}
	if max > time.Second {
		t.Errorf("default max %v is long enough to be a denial-of-service vector", max)
	}
}

// TestTimingStatusIsObservable pins the exported diagnostic accessor.
func TestTimingStatusIsObservable(t *testing.T) {
	t.Cleanup(func() { _ = ConfigureTiming(defaultJitterMin, defaultJitterMax) })

	if err := ConfigureTiming(30*time.Millisecond, 90*time.Millisecond); err != nil {
		t.Fatal(err)
	}
	min, max, enabled := TimingStatus()
	if !enabled || min != 30*time.Millisecond || max != 90*time.Millisecond {
		t.Errorf("TimingStatus() = %v..%v enabled=%v, want 30ms..90ms enabled=true", min, max, enabled)
	}

	// Disabling must be visible too, otherwise a health check cannot report a
	// control that was turned off.
	if err := ConfigureTiming(0, 0); err != nil {
		t.Fatal(err)
	}
	if _, _, enabled := TimingStatus(); enabled {
		t.Error("TimingStatus() reports enabled after ConfigureTiming(0, 0)")
	}
}

// The four tests below all reconfigure the process-global jitter window, so they
// deliberately do NOT call t.Parallel. Previously they all did, which meant each
// test overwrote the window its siblings were still measuring; they passed only
// because the windows happened to be similar. Jitter tests must run serially
// against shared state, so serialising them is the correct fix, not slower tests.
func TestConfigureTimingRejectsInvertedWindow(t *testing.T) {
	tests := []struct {
		name    string
		min     time.Duration
		max     time.Duration
		wantErr bool
	}{
		{name: "min after max", min: 100 * time.Millisecond, max: 10 * time.Millisecond, wantErr: true},
		{name: "negative min", min: -time.Second, max: time.Second, wantErr: true},
		{name: "zero window disables jitter", min: 0, max: 0},
		{name: "equal bounds is valid", min: 10 * time.Millisecond, max: 10 * time.Millisecond},
	}

	// Restore the configured defaults once, after all cases, rather than per case.
	t.Cleanup(func() { _ = ConfigureTiming(defaultJitterMin, defaultJitterMax) })

	for _, tc := range tests {
		err := ConfigureTiming(tc.min, tc.max)
		if tc.wantErr && err == nil {
			t.Errorf("ConfigureTiming(%v, %v) = nil, want an error", tc.min, tc.max)
		}
		if !tc.wantErr && err != nil {
			t.Errorf("ConfigureTiming(%v, %v) = %v, want nil", tc.min, tc.max, err)
		}
	}
}

func TestSleepJitterIsInWindow(t *testing.T) {
	const min, max = 20 * time.Millisecond, 60 * time.Millisecond
	if err := ConfigureTiming(min, max); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = ConfigureTiming(defaultJitterMin, defaultJitterMax) })

	for i := 0; i < 20; i++ {
		start := time.Now()
		if err := SleepJitter(context.Background()); err != nil {
			t.Fatal(err)
		}
		elapsed := time.Since(start)
		// The lower bound is exact: the sleep is never shorter than min. The
		// upper bound is loose, because a sleep that returns late under load is
		// not a correctness failure and flaking here would be worse than
		// tolerating a late return.
		if elapsed < min {
			t.Errorf("jitter was %v, shorter than the %v minimum", elapsed, min)
		}
		if elapsed > 500*time.Millisecond {
			t.Errorf("jitter was %v, far beyond the %v maximum", elapsed, max)
		}
	}
}

func TestSleepJitterVaries(t *testing.T) {
	// The whole purpose is that two identical failed requests do not return after
	// identical durations. Identical delays would leave the account-existence
	// signal intact, so variation is the property that actually matters.
	const min, max = 10 * time.Millisecond, 100 * time.Millisecond
	if err := ConfigureTiming(min, max); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = ConfigureTiming(defaultJitterMin, defaultJitterMax) })

	seen := make(map[time.Duration]bool)
	for i := 0; i < 15; i++ {
		start := time.Now()
		if err := SleepJitter(context.Background()); err != nil {
			t.Fatal(err)
		}
		seen[time.Since(start).Round(time.Millisecond)] = true
	}
	if len(seen) < 5 {
		t.Errorf("only %d distinct delays across 15 calls, want a spread", len(seen))
	}
}

func TestSleepJitterHonoursContext(t *testing.T) {
	if err := ConfigureTiming(500*time.Millisecond, time.Second); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = ConfigureTiming(defaultJitterMin, defaultJitterMax) })

	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
	defer cancel()

	start := time.Now()
	err := SleepJitter(ctx)
	elapsed := time.Since(start)

	// A cancelled or expired context must return promptly rather than holding the
	// request open for the full jitter window.
	if err == nil {
		t.Error("SleepJitter with an expired context = nil, want context.DeadlineExceeded")
	}
	if elapsed > 200*time.Millisecond {
		t.Errorf("SleepJitter took %v after the context expired, want an early return", elapsed)
	}
}

func TestSleepJitterDisabledReturnsImmediately(t *testing.T) {
	// A zero window is the "jitter off" configuration, used by tests and local
	// development. It must be instant rather than slow.
	if err := ConfigureTiming(0, 0); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = ConfigureTiming(defaultJitterMin, defaultJitterMax) })

	start := time.Now()
	if err := SleepJitter(context.Background()); err != nil {
		t.Fatal(err)
	}
	if elapsed := time.Since(start); elapsed > 20*time.Millisecond {
		t.Errorf("SleepJitter with jitter disabled took %v", elapsed)
	}
}

func TestConstantTimeEqual(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		a    string
		b    string
		want bool
	}{
		{name: "identical", a: "token-value", b: "token-value", want: true},
		{name: "different", a: "token-value", b: "token-vAlue", want: false},
		{name: "prefix only", a: "token", b: "token-value", want: false},
		{name: "both empty", a: "", b: "", want: true},
		{name: "one empty", a: "", b: "x", want: false},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			if got := ConstantTimeEqual(tc.a, tc.b); got != tc.want {
				t.Errorf("ConstantTimeEqual(%q, %q) = %v, want %v", tc.a, tc.b, got, tc.want)
			}
		})
	}
}

// ----------------------------------------------------------------------------
// totp.go
// ----------------------------------------------------------------------------

func TestGenerateSecret(t *testing.T) {
	t.Parallel()

	secret, err := GenerateSecret()
	if err != nil {
		t.Fatal(err)
	}
	// RFC 4226 recommends 160 bits, which is 32 base32 characters.
	if len(secret) != 32 {
		t.Errorf("len(secret) = %d, want 32 base32 characters for 20 bytes", len(secret))
	}

	other, err := GenerateSecret()
	if err != nil {
		t.Fatal(err)
	}
	if secret == other {
		t.Error("two generated secrets are identical")
	}
}

func TestTOTPCodeAndVerifyAgree(t *testing.T) {
	t.Parallel()

	secret, err := GenerateSecret()
	if err != nil {
		t.Fatal(err)
	}
	p := DefaultTOTPParams("OAuth Server", "user@example.com")
	p.Secret = secret

	now := time.Unix(1_700_000_000, 0).UTC()
	code, err := TOTPCode(p, now)
	if err != nil {
		t.Fatal(err)
	}
	if len(code) != 6 {
		t.Errorf("len(code) = %d, want 6 digits", len(code))
	}
	for _, c := range code {
		if c < '0' || c > '9' {
			t.Fatalf("code %q contains a non-digit", code)
		}
	}

	counter, err := VerifyTOTP(p, code, now, 0)
	if err != nil {
		t.Fatalf("VerifyTOTP rejected a freshly generated code: %v", err)
	}
	if counter != TOTPCounter(now, p.Period) {
		t.Errorf("returned counter = %d, want %d", counter, TOTPCounter(now, p.Period))
	}
}

func TestVerifyTOTPRejectsWrongCode(t *testing.T) {
	t.Parallel()

	secret, _ := GenerateSecret()
	p := DefaultTOTPParams("OAuth Server", "user@example.com")
	p.Secret = secret
	now := time.Unix(1_700_000_000, 0).UTC()

	// Generate the real code, then change one digit.
	real, err := TOTPCode(p, now)
	if err != nil {
		t.Fatal(err)
	}
	wrong := "000000"
	if real == wrong {
		wrong = "111111"
	}

	if _, err := VerifyTOTP(p, wrong, now, 0); err == nil {
		t.Error("VerifyTOTP accepted a wrong code")
	}
	if _, err := VerifyTOTP(p, "", now, 0); err == nil {
		t.Error("VerifyTOTP accepted an empty code")
	}
	if _, err := VerifyTOTP(p, "abcdef", now, 0); err == nil {
		t.Error("VerifyTOTP accepted a non-numeric code")
	}
}

func TestVerifyTOTPReplayIsRefused(t *testing.T) {
	t.Parallel()

	secret, _ := GenerateSecret()
	p := DefaultTOTPParams("OAuth Server", "user@example.com")
	p.Secret = secret
	now := time.Unix(1_700_000_000, 0).UTC()

	code, err := TOTPCode(p, now)
	if err != nil {
		t.Fatal(err)
	}

	counter, err := VerifyTOTP(p, code, now, 0)
	if err != nil {
		t.Fatal(err)
	}

	// The same code inside its own validity window must be refused the second
	// time. Without the persisted counter this succeeds, and a shoulder-surfed
	// code is usable for the rest of the window.
	_, err = VerifyTOTP(p, code, now, counter)
	if err == nil {
		t.Fatal("a TOTP code was accepted twice, so it is not single-use")
	}
}

func TestVerifyTOTPSkewWidensTheWindow(t *testing.T) {
	t.Parallel()

	secret, _ := GenerateSecret()
	p := DefaultTOTPParams("OAuth Server", "user@example.com")
	p.Secret = secret
	p.Skew = 1

	now := time.Unix(1_700_000_000, 0).UTC()

	// A code from the previous step is accepted when skew allows it.
	previous, err := TOTPCode(p, now.Add(-30*time.Second))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := VerifyTOTP(p, previous, now, 0); err != nil {
		t.Errorf("skew=1 rejected the previous step's code: %v", err)
	}

	// With skew at 0, the default, the same code is refused. This is why the
	// configured default is 0.
	p.Skew = 0
	if _, err := VerifyTOTP(p, previous, now, 0); err == nil {
		t.Error("skew=0 accepted a code from the previous step")
	}
}

func TestVerifyTOTPMalformedSecretIsAnError(t *testing.T) {
	t.Parallel()

	// A corrupt enrolment record, not a wrong code. These must be different
	// errors so the caller can log them differently.
	p := DefaultTOTPParams("OAuth Server", "user@example.com")
	p.Secret = "not!valid!base32!"

	_, err := VerifyTOTP(p, "123456", time.Now(), 0)
	if err == nil {
		t.Fatal("VerifyTOTP with a malformed secret = nil, want an error")
	}
	if errors.Is(err, ErrTOTPInvalid) {
		t.Error("a malformed secret reported as ErrTOTPInvalid, which would tell the user their authenticator is wrong")
	}
}

func TestTOTPCounterMonotonic(t *testing.T) {
	t.Parallel()

	start := time.Unix(1_700_000_000, 0).UTC()
	previous := TOTPCounter(start, 30)

	// The counter is a step index, not a tick: it must NEVER go backwards, and it
	// must advance exactly once per period. Asserting a strict increase every
	// second would be wrong, since 29 consecutive seconds legitimately share a
	// counter value. What must hold is monotonicity across every second, and
	// exactly two advances across a 60 second span.
	advances := 0
	for i := 1; i <= 60; i++ {
		got := TOTPCounter(start.Add(time.Duration(i)*time.Second), 30)
		if got < previous {
			t.Fatalf("counter went backwards at second %d: %d then %d", i, previous, got)
		}
		if got > previous {
			advances++
		}
		previous = got
	}
	if advances != 2 {
		t.Errorf("counter advanced %d times in 60 seconds, want exactly 2 for a 30 second period", advances)
	}
}

func TestTOTPCounterFormula(t *testing.T) {
	t.Parallel()

	// counter = floor(unix / period). Verified explicitly so a change to the
	// formula cannot silently invalidate every persisted counter.
	tests := []struct {
		unix   int64
		period uint
		want   uint64
	}{
		{unix: 0, period: 30, want: 0},
		{unix: 29, period: 30, want: 0},
		{unix: 30, period: 30, want: 1},
		{unix: 59, period: 30, want: 1},
		{unix: 60, period: 30, want: 2},
		{unix: 1_700_000_000, period: 30, want: 56_666_666},
		{unix: 1_700_000_000, period: 60, want: 28_333_333},
	}

	for _, tc := range tests {
		got := TOTPCounter(time.Unix(tc.unix, 0), tc.period)
		if got != tc.want {
			t.Errorf("TOTPCounter(unix=%d, period=%d) = %d, want %d", tc.unix, tc.period, got, tc.want)
		}
	}
}

func TestBackupCodeGeneration(t *testing.T) {
	t.Parallel()

	plaintexts, hashes, err := GenerateBackupCodes(10)
	if err != nil {
		t.Fatal(err)
	}

	if len(plaintexts) != 10 || len(hashes) != 10 {
		t.Fatalf("got %d plaintexts and %d hashes, want 10 each", len(plaintexts), len(hashes))
	}

	// Every hash must correspond to its own plaintext, and no two codes may be
	// identical.
	unique := make(map[string]bool, 10)
	for i, code := range plaintexts {
		if unique[code] {
			t.Fatal("two backup codes are identical")
		}
		unique[code] = true

		if HashBackupCode(code) != hashes[i] {
			t.Errorf("hash %d does not match its plaintext", i)
		}
		if strings.Contains(code, " ") {
			t.Errorf("backup code %q contains a space, which breaks manual entry", code)
		}
	}
}

func TestBackupCodeHashIsNotPasswordHash(t *testing.T) {
	t.Parallel()

	// A backup code is 128 bits of CSPRNG output. It is hashed with SHA-256, not
	// argon2id, so this asserts the PHC prefix is absent rather than asserting a
	// timing property.
	code, _ := RandomTokenN(16)
	if strings.HasPrefix(HashBackupCode(code), "$argon2id$") {
		t.Error("a backup code was hashed as a password")
	}
	if len(HashBackupCode(code)) != 64 {
		t.Errorf("len(HashBackupCode) = %d, want 64 hex characters", len(HashBackupCode(code)))
	}
}

func TestGenerateBackupCodesRejectsBadCounts(t *testing.T) {
	t.Parallel()

	if _, _, err := GenerateBackupCodes(0); err == nil {
		t.Error("GenerateBackupCodes(0) = nil, want an error")
	}
	if _, _, err := GenerateBackupCodes(-1); err == nil {
		t.Error("GenerateBackupCodes(-1) = nil, want an error")
	}
	// Bounded, because an unbounded count is a brute-force bound and a caller
	// asking for a million codes has a bug.
	if _, _, err := GenerateBackupCodes(21); err == nil {
		t.Error("GenerateBackupCodes(21) = nil, want an error")
	}
}

func TestProvisioningURI(t *testing.T) {
	t.Parallel()

	secret, _ := GenerateSecret()
	p := DefaultTOTPParams("OAuth Server", "user@example.com")
	p.Secret = secret

	uri, err := ProvisioningURI(p)
	if err != nil {
		t.Fatal(err)
	}

	// The otpauth format is otpauth://totp/ISSUER:ACCOUNT?...
	if !strings.HasPrefix(uri, "otpauth://totp/") {
		t.Errorf("URI %q does not start with otpauth://totp/", uri)
	}
	if !strings.Contains(uri, "secret="+secret) {
		t.Error("URI does not carry the secret")
	}
	if !strings.Contains(uri, "issuer=OAuth+Server") && !strings.Contains(uri, "issuer=OAuth%20Server") {
		t.Error("URI does not carry the issuer")
	}
	if !strings.Contains(uri, "algorithm=SHA1") {
		t.Error("URI does not pin the algorithm")
	}
	if !strings.Contains(uri, "period=30") {
		t.Error("URI does not carry the period")
	}
}

func TestProvisioningURIRejectsColonInIssuer(t *testing.T) {
	t.Parallel()

	secret, _ := GenerateSecret()

	// A colon in the issuer would inject a different label into the
	// authenticator app, since the format separates issuer and account with one.
	p := DefaultTOTPParams("evil:issuer", "user@example.com")
	p.Secret = secret
	if _, err := ProvisioningURI(p); err == nil {
		t.Error("an issuer containing a colon was accepted")
	}

	p = DefaultTOTPParams("OAuth Server", "evil:account")
	p.Secret = secret
	if _, err := ProvisioningURI(p); err == nil {
		t.Error("an account name containing a colon was accepted")
	}
}

func TestParseDigits(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		in      string
		want    otp.Digits
		wantErr bool
	}{
		{name: "six", in: "6", want: otp.DigitsSix},
		{name: "eight", in: "8", want: otp.DigitsEight},
		{name: "zero is refused", in: "0", wantErr: true},
		{name: "seven is refused", in: "7", wantErr: true},
		{name: "not a number", in: "six", wantErr: true},
		{name: "empty", in: "", wantErr: true},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			got, err := ParseDigits(tc.in)
			if tc.wantErr {
				if err == nil {
					t.Errorf("ParseDigits(%q) = %v, nil, want an error", tc.in, got)
				}
				return
			}
			if err != nil {
				t.Fatalf("ParseDigits(%q): %v", tc.in, err)
			}
			if got != tc.want {
				t.Errorf("ParseDigits(%q) = %v, want %v", tc.in, got, tc.want)
			}
		})
	}
}
