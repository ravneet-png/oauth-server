package crypto

// TOTP (RFC 6238) with a persisted counter, so a code cannot be replayed inside
// its own validity window.
//
// The counter is the entire point of this file. Plain TOTP accepts a code for a
// window of +/- one step, so a code is valid for up to 90 seconds and, without
// extra state, it can be used several times inside that window. An attacker who
// shoulder-surfs a code has a usable credential until the window closes. Storing
// the highest counter accepted for a user and refusing anything lower makes each
// code single-use regardless of the window.

import (
	"crypto/hmac"
	"crypto/sha1"
	"crypto/subtle"
	"encoding/base32"
	"encoding/base64"
	"encoding/binary"
	"errors"
	"fmt"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/pquerna/otp"
	"github.com/pquerna/otp/totp"
	"github.com/skip2/go-qrcode"
)

// ErrTOTPInvalid means the code did not verify.
var ErrTOTPInvalid = errors.New("crypto: totp code invalid")

// ErrTOTPReplay means the code is mathematically valid but its counter has
// already been consumed.
var ErrTOTPReplay = errors.New("crypto: totp code already used")

// TOTPParams configure generation and verification.
type TOTPParams struct {
	// Issuer appears in the authenticator app. It is shown to the user, so it
	// must not contain a colon, which the otpauth URI format uses as a
	// separator and which would otherwise let a crafted issuer rewrite the
	// label.
	Issuer string

	// AccountName is the user's login. It goes in the otpauth URI and is shown
	// in the app; it must not contain a colon for the same reason.
	AccountName string

	// Period is the TOTP timestep. 30s is the RFC 6238 recommendation and the
	// only value the authenticator apps assume by default.
	Period uint

	// Skew is how many steps on either side of the current one are accepted.
	//
	// The config default is 0, and that is the security-relevant choice. Skew
	// exists to tolerate clock drift on a user's phone, but every step of skew
	// multiplies the window in which a shoulder-surfed code is valid. With the
	// persisted counter making replay impossible, a user whose clock is wrong
	// gets a clear failure and can fix it; with skew, they get a silent
	// acceptance of a code that is valid far longer than intended.
	Skew uint

	// Digits is the code length. 6 is the standard; 8 is available but makes
	// the app's entry harder to shoulder-surf-proof, not easier.
	Digits otp.Digits

	// Secret is the base32-encoded shared secret, as stored in users.mfa_secret_enc.
	// It is decrypted from that column before use; this package never encrypts
	// it and the field name makes the provenance explicit at the call site.
	Secret string
}

// DefaultTOTPParams returns parameters matching the security block of
// config.yaml: 30 second period, zero skew, 6 digits.
func DefaultTOTPParams(issuer, account string) TOTPParams {
	return TOTPParams{
		Issuer:      issuer,
		AccountName: account,
		Period:      30,
		Skew:        0,
		Digits:      otp.DigitsSix,
	}
}

// GenerateSecret returns a new base32 TOTP shared secret.
//
// 20 bytes is the RFC 4226 recommendation (160 bits) and is what
// pquerna/otp generates by default. The secret is the entire second factor: a
// 10-digit code is only safe because the secret behind it cannot be guessed, and
// shortening the secret to make the provisioning URI shorter would cut that.
// GenerateSecret returns a new base32 TOTP shared secret.
//
// The randomness comes from RandomBytes rather than from the library's Generate
// helper. That helper builds a complete provisioning URI and therefore requires
// an issuer and an account name, and it fails with "Issuer must be set" when
// they are absent. At enrolment time the user may not have a confirmed address
// yet, so the secret cannot depend on one; drawing the bytes directly keeps
// secret generation independent of every other field in the enrolment form.
func GenerateSecret() (string, error) {
	// 20 bytes is the RFC 4226 recommendation (160 bits) and is what a standard
	// authenticator app assumes. The secret is the entire second factor: a
	// 6-digit code is only safe because the secret behind it cannot be guessed.
	raw, err := RandomBytes(20)
	if err != nil {
		return "", fmt.Errorf("crypto: generate totp secret: %w", err)
	}
	// StdEncoding with no padding, uppercase. This is the encoding the otpauth
	// URI format specifies and the one pquerna/otp expects back.
	return base32.StdEncoding.WithPadding(base32.NoPadding).EncodeToString(raw), nil
}

// ProvisioningURI returns the otpauth:// URI for an authenticator app.
//
// The issuer is validated for a colon because the URI format is
// otpauth://totp/ISSUER:ACCOUNT. A colon in the issuer would let a crafted value
// inject a different label into the app and, more practically, produce a URI
// that no app can parse correctly.
func ProvisioningURI(p TOTPParams) (string, error) {
	if strings.Contains(p.Issuer, ":") {
		return "", fmt.Errorf("crypto: totp issuer must not contain a colon")
	}
	if strings.Contains(p.AccountName, ":") {
		return "", fmt.Errorf("crypto: totp account name must not contain a colon")
	}
	if p.Period == 0 {
		return "", fmt.Errorf("crypto: totp period must be positive")
	}
	if p.Secret == "" {
		return "", fmt.Errorf("crypto: totp secret is empty")
	}

	// The URI is assembled here rather than through otp.NewKeyFromURL. That
	// round trip re-parses the string to obtain the key and renders it again,
	// which means a bug in either direction is invisible; more concretely, the
	// library's own rendering escapes the label differently from the format
	// specification, so a round trip silently rewrites the issuer. Building it
	// directly keeps exactly one encoder.
	//
	// The label and issuer are percent-encoded because both are caller-supplied
	// and the URI is a query-bearing string; an unescaped "&" or "?" in an
	// account name would otherwise inject parameters into the URI.
	label := p.AccountName
	if p.Issuer != "" {
		label = p.Issuer + ":" + p.AccountName
	}
	digits := p.Digits
	if digits == 0 {
		digits = otp.DigitsSix
	}
	period := p.Period

	uri := fmt.Sprintf("otpauth://totp/%s?secret=%s&issuer=%s&algorithm=SHA1&digits=%d&period=%d",
		url.PathEscape(label),
		p.Secret,
		url.QueryEscape(p.Issuer),
		digits,
		period,
	)

	// Parsed back so a malformed URI is caught here rather than by the user's
	// authenticator app, which reports it as a scan failure with no detail.
	if _, err := otp.NewKeyFromURL(uri); err != nil {
		return "", fmt.Errorf("crypto: provisioning uri is not parseable: %w", err)
	}
	return uri, nil
}

// TOTPCode generates the code for a point in time. Used by tests and by the
// enrolment confirmation screen, never by the verification path.
func TOTPCode(p TOTPParams, t time.Time) (string, error) {
	if p.Secret == "" {
		return "", fmt.Errorf("crypto: totp secret is empty")
	}
	period := p.Period
	if period == 0 {
		period = 30
	}
	code, err := totp.GenerateCodeCustom(p.Secret, t, totp.ValidateOpts{
		Period:    period,
		Skew:      uint(p.Skew),
		Digits:    p.Digits,
		Algorithm: otp.AlgorithmSHA1,
	})
	if err != nil {
		return "", fmt.Errorf("crypto: generate totp code: %w", err)
	}
	return code, nil
}

// TOTPCounter returns the counter value for a point in time.
//
// counter = floor(unix_seconds / period). This is the number persisted on
// users.mfa_totp_counter, and it is what makes a code single-use: accepting a
// code advances the stored counter, and any code from an equal or earlier step
// is then refused.
func TOTPCounter(t time.Time, period uint) uint64 {
	if period == 0 {
		period = 30
	}
	// The division is on a signed value cast to uint64. A pre-1970 timestamp is
	// not reachable from a real clock, and truncating toward zero keeps the
	// counter monotonic rather than wrapping to a huge number.
	return uint64(t.Unix()) / uint64(period)
}

// VerifyTOTP checks a code and returns the counter it matched.
//
// lastCounter is the highest counter already accepted for this user, or 0 if
// none. The returned counter MUST be persisted if and only if the verification
// succeeded, in the same transaction that consumed the challenge.
//
// The two failure modes are separate errors on purpose, and both must map to
// the same response to the client. ErrTOTPReplay exists for the audit log and
// the metrics, not for the user: telling someone their code was correct but
// already used is more information than any attacker needs, and it is the
// difference between "your phone clock is wrong" and "your second factor is
// compromised" that they need to act on. Both return invalid_grant.
func VerifyTOTP(p TOTPParams, code string, now time.Time, lastCounter uint64) (uint64, error) {
	if p.Secret == "" {
		return 0, fmt.Errorf("crypto: totp secret is empty")
	}
	if code == "" {
		return 0, ErrTOTPInvalid
	}

	period := p.Period
	if period == 0 {
		period = 30
	}
	digits := p.Digits
	if digits == 0 {
		digits = otp.DigitsSix
	}

	current := TOTPCounter(now, period)

	// Candidate counters, nearest first: the current step, then one step either
	// side, then two, up to the configured skew.
	//
	// The current step is offset 0 and MUST be included unconditionally. An
	// earlier version of this loop derived its offsets as {+delta, -delta} for
	// delta in [0, Skew] and skipped zero, which meant that with the configured
	// default of Skew=0 the candidate set was empty and NO code could ever be
	// accepted. Every user with MFA would have been locked out, and the failure
	// would have looked like a bad enrolment rather than a logic error.
	offsets := make([]int64, 0, 2*int64(p.Skew)+1)
	offsets = append(offsets, 0)
	for d := int64(1); d <= int64(p.Skew); d++ {
		offsets = append(offsets, -d, d)
	}

	// Every step in the window is tried, and each comparison is constant time.
	// Iterating rather than trusting the library's own Validate is what lets the
	// replay check be applied per-step: a code from the previous window is
	// mathematically valid but must be refused once a later step has been
	// consumed.
	for _, step := range offsets {
		candidate := int64(current) + step
		if candidate < 0 {
			continue
		}

		expected, err := hotpCode(p.Secret, uint64(candidate), digits)
		if err != nil {
			return 0, err
		}

		// Constant time, and compared against a same-length expectation so the
		// comparison does not short-circuit on a length mismatch.
		if subtle.ConstantTimeCompare([]byte(code), []byte(expected)) != 1 {
			continue
		}

		// Mathematically valid. Now the replay check.
		if uint64(candidate) <= lastCounter {
			return 0, ErrTOTPReplay
		}
		return uint64(candidate), nil
	}

	return 0, ErrTOTPInvalid
}

// hotpCode is a local HMAC-based TOTP code generator.
//
// Implemented here rather than taken from the library because the library's
// Validate function reports only a boolean and does not expose which counter
// matched, and the matched counter is precisely the value that has to be
// persisted to make the code single-use. RFC 4226 and RFC 6238 are short enough
// that a local implementation is less risky than working around the API.
func hotpCode(secret string, counter uint64, digits otp.Digits) (string, error) {
	raw, err := base32.StdEncoding.WithPadding(base32.NoPadding).DecodeString(strings.ToUpper(strings.TrimSpace(secret)))
	if err != nil {
		// A malformed secret is a corrupt row, not a wrong code. Returning
		// ErrTOTPInvalid here would tell a user their authenticator is wrong
		// when their enrolment record is damaged, and the caller would have no
		// way to tell the two apart to log them differently.
		return "", fmt.Errorf("crypto: decode totp secret: %w", err)
	}
	if len(raw) == 0 {
		return "", fmt.Errorf("crypto: totp secret decoded to zero bytes")
	}

	// The 8-byte big-endian counter is the whole HMAC message.
	msg := make([]byte, 8)
	binary.BigEndian.PutUint64(msg, counter)

	mac := hmac.New(sha1.New, raw)
	// SHA-1 is not a choice here. RFC 6238 specifies HMAC-SHA-1 and every
	// authenticator app in existence implements it. The security of TOTP does
	// not rest on the collision resistance of SHA-1, it rests on HMAC's
	// pseudorandomness and on the 160-bit secret; RFC 6238 also defines
	// SHA-256 and SHA-512 variants, but no client supports them.
	_, _ = mac.Write(msg)
	sum := mac.Sum(nil)

	// Dynamic truncation, RFC 4226 section 5.4.
	offset := sum[len(sum)-1] & 0x0f
	truncated := (uint32(sum[offset])&0x7f)<<24 |
		uint32(sum[offset+1])<<16 |
		uint32(sum[offset+2])<<8 |
		uint32(sum[offset+3])

	mod := uint32(1)
	for i := otp.Digits(0); i < digits; i++ {
		mod *= 10
	}
	return fmt.Sprintf("%0*d", digits, truncated%mod), nil
}

// HashBackupCode returns the digest stored in mfa_backup_codes.code_hash.
//
// SHA-256, not argon2id, and this is the same reasoning as hash.go applied to a
// second place. A backup code is 128 bits of CSPRNG output, so there is no
// dictionary to slow down; what argon2id would add is roughly 100ms of CPU on
// every MFA submission, and what it would cost is a denial-of-service lever
// against the one endpoint an attacker most wants to slow down.
//
// The caller generates the code with RandomTokenN(16) and shows it once.
func HashBackupCode(code string) string {
	return SHA256Hex(code)
}

// GenerateBackupCodes returns n fresh backup codes, hashed, along with the
// plaintexts to display exactly once.
//
// The two return values have wildly different lifetimes and the caller must not
// conflate them: the plaintext slice exists only long enough to render a
// template, and the hashed slice is what is stored. Returning them separately
// makes it obvious at the call site which is which, and returning only hashes
// would make the enrolment flow impossible to implement.
func GenerateBackupCodes(n int) (plaintexts []string, hashes []string, err error) {
	const maxCodes = 20
	if n <= 0 {
		return nil, nil, fmt.Errorf("crypto: backup code count must be positive, got %d", n)
	}
	if n > maxCodes {
		// A bounded count is a brute-force bound. Codes are 128 bits so this is
		// not the primary defence, but a caller asking for a million codes has
		// a bug and the allocation should not succeed.
		return nil, nil, fmt.Errorf("crypto: refusing to generate %d backup codes, maximum is %d", n, maxCodes)
	}

	plaintexts = make([]string, 0, n)
	hashes = make([]string, 0, n)
	for i := 0; i < n; i++ {
		code, err := RandomTokenN(16)
		if err != nil {
			return nil, nil, err
		}
		plaintexts = append(plaintexts, code)
		hashes = append(hashes, HashBackupCode(code))
	}
	return plaintexts, hashes, nil
}

// QRCodeDataURL generates a PNG QR code from the otpauth URI and returns it as a
// data: URL ready for an <img src="...">.
//
// The PNG is generated at 256x256 (M level error correction, quiet zone 4), which
// is the sweet spot: large enough to scan reliably on desktop and mobile cameras,
// small enough to inline without bloating the HTML.
func QRCodeDataURL(uri string) (string, error) {
	png, err := qrcode.Encode(uri, qrcode.Medium, 256)
	if err != nil {
		return "", fmt.Errorf("crypto: qr encode: %w", err)
	}
	return "data:image/png;base64," + base64.StdEncoding.EncodeToString(png), nil
}

// ParseDigits is a small helper for reading a digit count from configuration,
// so an invalid value is rejected at boot rather than producing zero-width codes.
func ParseDigits(s string) (otp.Digits, error) {
	n, err := strconv.Atoi(s)
	if err != nil {
		return 0, fmt.Errorf("crypto: totp digits %q is not a number: %w", s, err)
	}
	switch otp.Digits(n) {
	case otp.DigitsSix, otp.DigitsEight:
		return otp.Digits(n), nil
	default:
		return 0, fmt.Errorf("crypto: totp digits must be 6 or 8, got %d", n)
	}
}
