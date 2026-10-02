package crypto

// Argon2id password hashing in PHC string format.
//
// Argon2id is for low-entropy, user-chosen passwords ONLY. It must not be used
// for tokens, codes or any other high-entropy value: a memory-hard KDF costs
// real CPU by design, and spending 64 MiB and ~100ms to protect a value that
// cannot be guessed anyway turns every /token call into a denial-of-service
// lever. See hash.go for the high-entropy case.

import (
	"crypto/rand"
	"crypto/subtle"
	"encoding/base64"
	"errors"
	"fmt"
	"strconv"
	"strings"

	"golang.org/x/crypto/argon2"
)

// Argon2Params are the cost parameters for a password hash.
//
// Every field is encoded into the stored hash string. That is what makes cost
// raisable: raising these values affects only newly created hashes, existing
// ones keep verifying with the parameters they were created with, and a user
// who logs in successfully has their hash transparently rewritten. Hard-coding
// the cost in code means old hashes either become unverifiable or force a
// rehash-everything migration.
type Argon2Params struct {
	// Memory is the amount of memory in KiB. RFC 9106's second recommended
	// option is 64 MiB. The value is the primary cost lever: it is what makes
	// each guess expensive in hardware rather than in time.
	Memory uint32

	// Iterations is the number of passes. Raising it multiplies the cost of
	// every guess. RFC 9106 recommends 3 for the second option.
	Iterations uint32

	// Parallelism is the number of lanes. It trades memory for latency and
	// should be tuned to the target hardware, not maximised: 4 lanes is the
	// RFC 9106 recommendation for the second option.
	Parallelism uint8

	// SaltLength is the salt size in bytes. 16 bytes is the standard choice.
	SaltLength uint32

	// KeyLength is the derived key size in bytes. 32 bytes matches SHA-256
	// output and is what an attacker needs to guess.
	KeyLength uint32
}

// DefaultArgon2Params matches the security.argon2 block in config.yaml.
//
// These MUST be kept in step with config.yaml. The duplication is deliberate:
// config.yaml is read at boot and the parameters used for a hash must not depend
// on the config loader succeeding, or a malformed config file would make
// existing passwords unverifiable. The boot-time check in cmd/server compares
// the two and refuses to start on a mismatch.
func DefaultArgon2Params() Argon2Params {
	return Argon2Params{
		Memory:      64 * 1024, // 65536 KiB = 64 MiB
		Iterations:  3,
		Parallelism: 4,
		SaltLength:  16,
		KeyLength:   32,
	}
}

// Validate reports whether p is safe to use.
//
// The bounds are not arbitrary. A zero or tiny Memory defeats the entire point
// of a memory-hard function. A very large Memory is worse than it sounds: an
// attacker who can choose the parameters being used to verify a password they
// captured can turn verification into an out-of-memory condition. The upper
// bound here is a defensive check against a corrupt config, and the real
// protection against a parameter-flooding attack is that Verify reuses the
// parameters from the stored hash rather than from configuration.
func (p Argon2Params) Validate() error {
	if p.Memory < 8*1024 {
		return fmt.Errorf("crypto: argon2 memory %d KiB is below the 8 MiB minimum", p.Memory)
	}
	if p.Memory > 1024*1024 {
		return fmt.Errorf("crypto: argon2 memory %d KiB exceeds the 1 GiB safety ceiling", p.Memory)
	}
	if p.Iterations < 1 {
		return fmt.Errorf("crypto: argon2 iterations must be at least 1, got %d", p.Iterations)
	}
	if p.Iterations > 16 {
		return fmt.Errorf("crypto: argon2 iterations %d exceeds the ceiling of 16", p.Iterations)
	}
	if p.Parallelism < 1 {
		return fmt.Errorf("crypto: argon2 parallelism must be at least 1, got %d", p.Parallelism)
	}
	if p.Parallelism > 16 {
		return fmt.Errorf("crypto: argon2 parallelism %d exceeds the ceiling of 16", p.Parallelism)
	}
	if p.SaltLength < 16 {
		return fmt.Errorf("crypto: argon2 salt length %d is below the 16 byte minimum", p.SaltLength)
	}
	if p.KeyLength < 16 {
		return fmt.Errorf("crypto: argon2 key length %d is below the 16 byte minimum", p.KeyLength)
	}
	return nil
}

// HashPassword derives a hash for plaintext and returns it in PHC string format,
// e.g. $argon2id$v=19$m=65536,t=3,p=4$<salt>$<hash>.
//
// Each call uses a fresh random salt, so hashing the same password twice yields
// two different strings. That is required for correctness, not tidiness: a shared
// salt would make every user with the same password visibly identical in the
// database and let one precomputation attack all of them.
func HashPassword(plaintext string, p Argon2Params) (string, error) {
	if err := p.Validate(); err != nil {
		return "", err
	}

	salt := make([]byte, p.SaltLength)
	if _, err := rand.Read(salt); err != nil {
		return "", fmt.Errorf("crypto: generate argon2 salt: %w", err)
	}

	sum := argon2.IDKey([]byte(plaintext), salt, p.Iterations, p.Memory, p.Parallelism, p.KeyLength)

	return fmt.Sprintf("$argon2id$v=%d$m=%d,t=%d,p=%d$%s$%s",
		argon2.Version, p.Memory, p.Iterations, p.Parallelism,
		base64.RawStdEncoding.EncodeToString(salt),
		base64.RawStdEncoding.EncodeToString(sum),
	), nil
}

// ErrInvalidHash means the stored string is not a well-formed PHC argon2id hash.
var ErrInvalidHash = errors.New("crypto: malformed argon2id hash")

// VerifyPassword reports whether plaintext produced encodedHash.
//
// The parameters, salt and algorithm ALL come from the stored string, never from
// configuration. This is a security property rather than a convenience: if the
// cost parameters were read from config, an attacker who could influence the
// config (or an operator who lowered the cost to make tests fast) would control
// the cost of attacking the stored hashes, and an existing hash could become
// unverifiable by changing a YAML file.
//
// A malformed hash returns an error rather than false. The distinction matters:
// false means "wrong password", an error means "this user's record is corrupt",
// and collapsing them means a database problem presents as every user in the
// table having forgotten their password.
func VerifyPassword(plaintext, encodedHash string) (bool, error) {
	p, salt, want, err := decodeHash(encodedHash)
	if err != nil {
		return false, err
	}

	got := argon2.IDKey([]byte(plaintext), salt, p.Iterations, p.Memory, p.Parallelism, p.KeyLength)

	// subtle.ConstantTimeCompare rather than bytes.Equal, for the same reason
	// as everywhere else in this package.
	if subtle.ConstantTimeCompare(got, want) != 1 {
		return false, nil
	}
	return true, nil
}

// NeedsRehash reports whether encodedHash was produced with weaker parameters
// than p, and so should be replaced with a new hash after a successful login.
//
// This is how the cost is raised without a migration: the check happens on the
// one occasion where the plaintext password is available, which is the only
// occasion a stronger hash can be computed.
func NeedsRehash(encodedHash string, p Argon2Params) (bool, error) {
	stored, _, _, err := decodeHash(encodedHash)
	if err != nil {
		return false, err
	}
	if err := p.Validate(); err != nil {
		return false, err
	}
	return stored.Memory < p.Memory ||
			stored.Iterations < p.Iterations ||
			stored.KeyLength < p.KeyLength,
		nil
}

// decodeHash parses a PHC string into its parts.
func decodeHash(encodedHash string) (Argon2Params, []byte, []byte, error) {
	var p Argon2Params

	// The format is:
	//   $argon2id$v=19$m=...,t=...,p=...$salt$hash
	//
	// There are FIVE '$'-separated values after the leading marker, so Split
	// yields 6 elements: an empty first element plus the five fields. An earlier
	// version of this check required 7, which rejected every hash this package
	// itself produced, so no user could ever have logged in.
	parts := strings.Split(encodedHash, "$")
	if len(parts) != 6 || parts[0] != "" {
		return p, nil, nil, fmt.Errorf("%w: expected 5 fields, got %d", ErrInvalidHash, len(parts)-1)
	}
	if parts[1] != "argon2id" {
		// argon2i and argon2d are not accepted. argon2i is side-channel
		// resistant but slower per unit of memory, argon2d is faster and
		// therefore weaker. Only argon2id is both.
		return p, nil, nil, fmt.Errorf("%w: algorithm is %q, want argon2id", ErrInvalidHash, parts[1])
	}

	var version int
	if _, err := fmt.Sscanf(parts[2], "v=%d", &version); err != nil {
		return p, nil, nil, fmt.Errorf("%w: bad version field %q", ErrInvalidHash, parts[2])
	}
	if version != argon2.Version {
		return p, nil, nil, fmt.Errorf("%w: version %d, want %d", ErrInvalidHash, version, argon2.Version)
	}

	var err error
	if p.Memory, p.Iterations, p.Parallelism, err = parseCost(parts[3]); err != nil {
		return p, nil, nil, err
	}

	salt, err := base64.RawStdEncoding.DecodeString(parts[4])
	if err != nil {
		return p, nil, nil, fmt.Errorf("%w: bad salt encoding: %v", ErrInvalidHash, err)
	}
	sum, err := base64.RawStdEncoding.DecodeString(parts[5])
	if err != nil {
		return p, nil, nil, fmt.Errorf("%w: bad hash encoding: %v", ErrInvalidHash, err)
	}

	// Derived from the stored data rather than from config, so a hash written
	// under any parameter set verifies correctly.
	p.SaltLength = uint32(len(salt))
	p.KeyLength = uint32(len(sum))

	return p, salt, sum, nil
}

// parseCost reads the m=,t=,p= triplet.
func parseCost(s string) (memory, iterations uint32, parallelism uint8, err error) {
	for _, field := range strings.Split(s, ",") {
		key, value, found := strings.Cut(field, "=")
		if !found {
			return 0, 0, 0, fmt.Errorf("%w: cost field %q has no '='", ErrInvalidHash, field)
		}
		n, convErr := strconv.ParseUint(value, 10, 32)
		if convErr != nil {
			return 0, 0, 0, fmt.Errorf("%w: cost value %q is not a number: %v", ErrInvalidHash, value, convErr)
		}
		switch key {
		case "m":
			memory = uint32(n)
		case "t":
			iterations = uint32(n)
		case "p":
			// Bounded by ParseUint above, then narrowed. Values above 255 are
			// rejected here rather than silently wrapping.
			if n > 255 {
				return 0, 0, 0, fmt.Errorf("%w: parallelism %d exceeds 255", ErrInvalidHash, n)
			}
			parallelism = uint8(n)
		default:
			return 0, 0, 0, fmt.Errorf("%w: unknown cost key %q", ErrInvalidHash, key)
		}
	}
	if memory == 0 || iterations == 0 || parallelism == 0 {
		return 0, 0, 0, fmt.Errorf("%w: cost %q is missing a component", ErrInvalidHash, s)
	}
	return memory, iterations, parallelism, nil
}
