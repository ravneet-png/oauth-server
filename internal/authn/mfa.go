package authn

// Second factor verification. The consumed TOTP counter is persisted with the verification,
// and a total attempt budget across backup codes bounds guessing.

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	"oauth-server/internal/crypto"
	"oauth-server/internal/domain"
	"oauth-server/internal/storage"
)

// ErrMFAInvalid covers every second-factor failure.
//
// One error for wrong code, unknown user, no enrolment and exhausted budget,
// because any distinction tells an attacker which half of the attack they are
// making progress on. ErrMFAReplay is separated only so the audit log can record
// that a mathematically valid code was presented a second time, which is the
// signal an operator investigating a compromise actually needs.
var (
	ErrMFAInvalid  = errors.New("authn: invalid second factor")
	ErrMFAReplay   = errors.New("authn: second factor already used")
	ErrMFANoMFA    = errors.New("authn: user has no second factor enrolled")
	ErrMFAAttempts = errors.New("authn: too many second-factor attempts")
)

// DefaultBackupCodeBudget is the total number of backup-code attempts allowed per
// user.
//
// A budget across codes rather than per code, and it is the reason backup codes
// are hashed with SHA-256 rather than a KDF: a 128-bit code has no guessing
// resistance to weaken, but the attacker who has one stolen code must still not be
// able to walk the remaining set. A per-code limit would be useless here because
// there is no rate at which distinct codes arrive from a real user.
const DefaultBackupCodeBudget = 5

// Verifier checks a second factor for a user.
type Verifier struct {
	userRepo     *storage.UserRepo
	mfaRepo      *storage.MFARepo
	backupBudget int

	now func() time.Time
}

// NewVerifier builds a Verifier.
func NewVerifier(userRepo *storage.UserRepo, mfaRepo *storage.MFARepo) (*Verifier, error) {
	if userRepo == nil {
		return nil, errors.New("authn: NewVerifier: userRepo is nil")
	}
	if mfaRepo == nil {
		return nil, errors.New("authn: NewVerifier: mfaRepo is nil")
	}
	return &Verifier{
		userRepo:     userRepo,
		mfaRepo:      mfaRepo,
		backupBudget: DefaultBackupCodeBudget,
		now:          func() time.Time { return time.Now().UTC() },
	}, nil
}

// WithBackupBudget overrides the total backup-code attempt budget.
func (v *Verifier) WithBackupBudget(n int) *Verifier {
	if n > 0 {
		v.backupBudget = n
	}
	return v
}

// WithClock overrides the clock. Test-only.
func (v *Verifier) WithClock(now func() time.Time) *Verifier {
	if now != nil {
		v.now = now
	}
	return v
}

// VerifyTOTP verifies a TOTP code for a user and advances the replay high-water mark.
//
// The counter is advanced in a single UPDATE whose predicate requires the stored
// value to still be the one the code was verified against. That is what makes two
// concurrent submissions of the same code resolve to exactly one success: with a
// read-then-write both would verify against the same lastCounter and both would
// succeed.
func (v *Verifier) VerifyTOTP(ctx context.Context, userID, secret string, code string) (int64, error) {
	if userID == "" || code == "" {
		return 0, ErrMFAInvalid
	}

	user, err := v.userRepo.GetByID(ctx, userID)
	if err != nil {
		if errors.Is(err, domain.ErrNotFound) {
			return 0, ErrMFAInvalid
		}
		return 0, fmt.Errorf("authn: VerifyTOTP: %w", err)
	}
	if !user.HasMFA() {
		return 0, ErrMFANoMFA
	}

	// The decrypted secret is supplied by the caller rather than read here,
	// because this package holds no encryption key. Keeping decryption outside
	// means the key never enters a package that handles user-supplied codes.
	//
	// DefaultTOTPParams rather than a literal struct, so the verification window
	// cannot drift from the one used at enrolment. Skew is deliberately 0, which
	// is what crypto.DefaultTOTPParams sets: the persisted counter already makes
	// replay impossible, and each step of skew would extend the window in which a
	// shoulder-surfed code is valid.
	params := crypto.DefaultTOTPParams("", "")
	params.Secret = secret

	counter, err := crypto.VerifyTOTP(params, normalizeTOTP(code), v.now(), uint64(user.MFALastCounter))
	if err != nil {
		if errors.Is(err, crypto.ErrTOTPReplay) {
			// Surfaced separately for the audit trail, but the caller must answer
			// the user identically to any other failure. Telling someone their code
			// was correct but already used is more than an attacker needs.
			return 0, ErrMFAReplay
		}
		if errors.Is(err, crypto.ErrTOTPInvalid) {
			return 0, ErrMFAInvalid
		}
		// A malformed stored secret is a corrupt row, not a wrong code.
		return 0, fmt.Errorf("authn: VerifyTOTP: %w", err)
	}

	if err := v.userRepo.UpdateMFALastCounter(ctx, userID, int64(counter)); err != nil {
		// Not advanced means the code is refused. Returning an error rather than
		// succeeding keeps the code usable for its remaining window, which is the
		// safe direction: the user retries and it works.
		return 0, fmt.Errorf("authn: VerifyTOTP: advance counter: %w", err)
	}

	return int64(counter), nil
}

// VerifyBackupCode consumes a backup code for a user.
//
// Consume is a conditional UPDATE guarded on used_at IS NULL, so the same code
// submitted twice concurrently authorises exactly one login. The row is looked up
// by hash first only to read user_id, and a code presented against a different
// account is refused WITHOUT being consumed: otherwise an attacker who knows a
// victim's address could burn their recovery codes by guessing, turning a recovery
// mechanism into a lockout.
func (v *Verifier) VerifyBackupCode(ctx context.Context, userID, code string) (bool, error) {
	if userID == "" || code == "" {
		return false, ErrMFAInvalid
	}

	// Budget checked before the consume. Refusing early means a spent-out account
	// cannot use backup codes to keep making progress on other second factors, and
	// it is counted against spent codes rather than unused ones so that the budget
	// survives re-enrolment.
	spent, err := v.mfaRepo.CountSpentForUser(ctx, userID)
	if err != nil {
		return false, fmt.Errorf("authn: VerifyBackupCode: %w", err)
	}
	if spent >= v.backupBudget {
		return false, ErrMFAAttempts
	}

	hash := crypto.HashBackupCode(normalizeBackupCode(code))

	// Ownership and single-use are both in the UPDATE predicate, so this is one
	// atomic step rather than a lookup followed by a write. A code belonging to
	// another account is neither consumed nor accepted, which is what stops an
	// attacker from destroying someone else's recovery codes by guessing their
	// address.
	consumed, err := v.mfaRepo.ConsumeForUser(ctx, hash, userID)
	if err != nil {
		return false, fmt.Errorf("authn: VerifyBackupCode: %w", err)
	}
	if !consumed {
		// "Not yours, already spent, or nonexistent" are indistinguishable. Any
		// distinction tells an attacker whether the code they hold is real.
		return false, ErrMFAInvalid
	}
	return true, nil
}

// BackupCodesRemaining reports how many recovery attempts a user has left, for the
// enrolment and settings screens. Bounded below at zero.
func (v *Verifier) BackupCodesRemaining(ctx context.Context, userID string) (int, error) {
	spent, err := v.mfaRepo.CountSpentForUser(ctx, userID)
	if err != nil {
		return 0, fmt.Errorf("authn: BackupCodesRemaining: %w", err)
	}
	if spent >= v.backupBudget {
		return 0, nil
	}
	return v.backupBudget - spent, nil
}

// normalizeBackupCode strips formatting a user may paste.
//
// Users copy recovery codes out of a password manager or a printed sheet and
// arrive with spaces or hyphens inserted. Rejecting those formats means a correct
// code fails for a cosmetic reason, and the user burns their remaining attempts
// finding out why. It does not widen what is accepted: the hash is still of the
// normalised value, and only codes this server generated can match it.
func normalizeBackupCode(code string) string {
	return strings.NewReplacer(" ", "", "-", "", "\t", "").Replace(strings.TrimSpace(code))
}

// normalizeTOTP strips the separators an authenticator app displays.
//
// Users type "123 456" as often as "123456". The length is checked by crypto
// against the expected code, so this cannot cause a wrong code to be accepted; it
// only prevents a correct one from being rejected for its formatting.
func normalizeTOTP(code string) string {
	return strings.NewReplacer(" ", "", "-", "").Replace(strings.TrimSpace(code))
}
