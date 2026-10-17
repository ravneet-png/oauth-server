package domain

// Device Authorization Grant (RFC 8628) domain model.
//
// Two credentials live on one row and they are deliberately different shapes.
// device_code is a high-entropy secret the device holds and never shows to a
// person; it is the only value that can redeem tokens, so only its digest is
// stored. user_code is a short, human-typed string read off a screen — it is NOT
// a secret. It is guessable by design, and what protects it is that the browser
// step must authenticate the user, take an explicit consent decision, and happen
// inside the code's short lifetime, not the entropy of eight characters.

import (
	cryptorand "crypto/rand"
	"math/big"
	"strings"
	"time"
)

// Device code statuses. The transitions are pending -> approved -> consumed, or
// pending -> denied, and nothing else: a denied request never becomes approved,
// and a consumed one is terminal.
const (
	DeviceStatusPending  = "pending"
	DeviceStatusApproved = "approved"
	DeviceStatusDenied   = "denied"
	DeviceStatusConsumed = "consumed"
)

// DeviceUserCodeAlphabet is the base-20 alphabet RFC 8628 section 6.1
// recommends: the consonants, with every vowel removed so a random string cannot
// spell a word, and with the glyphs a person confuses (0/O, 1/I/L, 2/Z, 5/S,
// 8/B) resolved by keeping only one of each pair.
const DeviceUserCodeAlphabet = "BCDFGHJKLMNPQRSTVWXZ"

// DeviceUserCodeLength is the number of significant characters, excluding the
// display hyphen. Eight symbols from a 20-letter alphabet is ~34.6 bits, which
// RFC 8628 section 6.1 calls adequate given the short lifetime, the enforced poll
// interval and the rate limit on the verification endpoint.
const DeviceUserCodeLength = 8

// GenerateUserCode returns a fresh user_code in display form, "XXXX-XXXX".
//
// Each character is drawn with crypto/rand.Int rather than by reducing a random
// byte modulo the alphabet size. 256 is not a multiple of 20, so modulo reduction
// would make the first 16 symbols more likely than the last 4; the unbiased form
// costs one call per character and removes the argument entirely.
func GenerateUserCode() (string, error) {
	var b strings.Builder
	b.Grow(DeviceUserCodeLength + 1)
	bound := big.NewInt(int64(len(DeviceUserCodeAlphabet)))
	for i := 0; i < DeviceUserCodeLength; i++ {
		if i == DeviceUserCodeLength/2 {
			b.WriteByte('-')
		}
		n, err := cryptorand.Int(cryptorand.Reader, bound)
		if err != nil {
			return "", err
		}
		b.WriteByte(DeviceUserCodeAlphabet[n.Int64()])
	}
	return b.String(), nil
}

// NormalizeUserCode reduces user input to the canonical stored form: upper-case,
// with every character that is not in the alphabet removed.
//
// The canonical form drops the display hyphen and any spacing the user typed, so
// "wdjb-mjht", "WDJBMJHT" and "WDJB MJHT" all address the same row. Only the
// alphabet survives, so an input containing a character the generator can never
// produce (a vowel, a digit, punctuation) cannot be folded onto a real code.
func NormalizeUserCode(input string) string {
	var b strings.Builder
	b.Grow(len(input))
	for _, r := range strings.ToUpper(strings.TrimSpace(input)) {
		if strings.ContainsRune(DeviceUserCodeAlphabet, r) {
			b.WriteRune(r)
		}
	}
	return b.String()
}

// DeviceCode is one in-progress device authorization.
type DeviceCode struct {
	// DeviceCodeHash is the SHA-256 hex of the device_code. Only the digest is
	// stored: the raw value is a bearer credential as strong as a client secret,
	// and a database read must not yield a usable one.
	DeviceCodeHash string

	// UserCode is the canonical (upper-case, hyphen-free) form the user types.
	// Stored canonical so lookup is a plain equality on one form.
	UserCode string

	ClientID string
	Scope    []string
	Status   string

	// UserID is set when the request is approved and NULL until then, enforced
	// by the device_codes_subject_chk constraint.
	UserID *string

	// Interval is the minimum delay the client must leave between polls.
	Interval time.Duration

	LastPolledAt *time.Time
	CreatedAt    time.Time
	ExpiresAt    time.Time
	ApprovedAt   *time.Time
	ConsumedAt   *time.Time
}

// IsPending reports whether the request still awaits a user decision.
func (d *DeviceCode) IsPending() bool { return d.Status == DeviceStatusPending }

// IsApproved reports whether the user approved and the token is not yet redeemed.
func (d *DeviceCode) IsApproved() bool { return d.Status == DeviceStatusApproved }

// IsDenied reports whether the user refused the request.
func (d *DeviceCode) IsDenied() bool { return d.Status == DeviceStatusDenied }

// IsConsumed reports whether the code has already been exchanged for tokens.
func (d *DeviceCode) IsConsumed() bool { return d.Status == DeviceStatusConsumed }

// IsExpired reports whether the code has outlived its TTL at now.
// An expired code is refused before its status is considered: a lapsed approval
// must not be redeemable just because the user once said yes.
func (d *DeviceCode) IsExpired(now time.Time) bool { return !d.ExpiresAt.After(now) }

// OwnedBy reports whether the code was issued to clientID. Checked before any
// redemption: a device_code is only redeemable by the client it was issued to.
func (d *DeviceCode) OwnedBy(clientID string) bool { return d.ClientID == clientID }
