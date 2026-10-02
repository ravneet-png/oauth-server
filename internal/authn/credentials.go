// Password authentication as a service, separate from the HTTP handler. A lookup miss
// performs the same work as a lookup hit against a fixed dummy hash, so response time
// cannot be used to enumerate accounts.

package authn

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

// Login failure modes.
//
// Deliberately not distinguishable to the caller. Every one of these returns the
// same ErrInvalidCredentials so that a handler cannot tell "no such account" from
// "wrong password" from "account disabled", which is the enumeration oracle the
// dummy-hash work below exists to close.
var (
	// ErrInvalidCredentials covers unknown address, wrong password, and disabled
	// account alike. One value for all three, on purpose.
	ErrInvalidCredentials = errors.New("authn: invalid credentials")

	// ErrAccountLocked is returned when the account exists and is inside its
	// lockout window. Separate only so a handler can show a useful message; the
	// distinction itself is safe because it reveals nothing an account holder has
	// not already been told.
	ErrAccountLocked = errors.New("authn: account temporarily locked")
)

// Lockout policy defaults.
const (
	DefaultFailedThreshold = 5
	DefaultLockoutDuration = 15 * time.Minute
)

// dummyHash is a valid Argon2id hash verified against when no account matches.
//
// The point is that a miss costs a full Argon2id verification, the same CPU as a
// hit. Without it an attacker times /login and learns which addresses have
// accounts: a miss returns in microseconds, a wrong password takes the full
// derivation.
//
// It must be a real parseable hash. A placeholder that VerifyPassword rejects
// immediately returns fast, which is the exact bug this replaces.
//
// The hash is computed once at init rather than per request so the miss path does
// not pay for key derivation on top of verification. Deriving per request would
// make a miss SLOWER than a hit, which reintroduces the same signal inverted and
// lets an attacker identify real accounts as the faster ones.
var dummyHash string

func init() {
	h, err := crypto.HashPassword("no-such-account-placeholder-value", crypto.DefaultArgon2Params())
	if err != nil {
		// There is no safe fallback. A cheap path would restore the timing oracle,
		// so failing at init surfaces the problem at startup instead.
		panic(fmt.Sprintf("authn: could not build dummy hash: %v", err))
	}
	dummyHash = h
}

// Result carries what a handler needs after a successful authentication.
//
// The user is returned rather than a bare bool so the handler does not re-read the
// row, which would return a user whose FailedLoginCount has not been reset and
// could disagree with the one that was verified.
type Result struct {
	User     *domain.User
	AuthTime time.Time

	// AMR is the authentication method that just succeeded, and ACR the assurance level
	// it establishes. Both are carried here rather than filled in by the caller: `amr`
	// is the evidence a later step-up is judged against (Session.IsMFA), and it is
	// published in the ID token, so a login that recorded neither is a login the server
	// cannot later tell apart from one that was never verified.
	AMR []string
	ACR string
}

// Authenticator verifies passwords against stored hashes.
type Authenticator struct {
	userRepo    *storage.UserRepo
	argonParams crypto.Argon2Params

	failedThreshold int
	lockoutDuration time.Duration

	// now is injected so lockout decisions are testable and so one request cannot
	// disagree with itself across a slow round trip.
	now func() time.Time
}

// NewAuthenticator builds an Authenticator.
func NewAuthenticator(userRepo *storage.UserRepo, params crypto.Argon2Params) (*Authenticator, error) {
	if userRepo == nil {
		return nil, errors.New("authn: NewAuthenticator: userRepo is nil")
	}
	if err := params.Validate(); err != nil {
		return nil, fmt.Errorf("authn: NewAuthenticator: %w", err)
	}
	return &Authenticator{
		userRepo:        userRepo,
		argonParams:     params,
		failedThreshold: DefaultFailedThreshold,
		lockoutDuration: DefaultLockoutDuration,
		now:             func() time.Time { return time.Now().UTC() },
	}, nil
}

// WithLockoutPolicy overrides the failure threshold and lockout duration.
func (a *Authenticator) WithLockoutPolicy(threshold int, duration time.Duration) *Authenticator {
	if threshold > 0 {
		a.failedThreshold = threshold
	}
	if duration > 0 {
		a.lockoutDuration = duration
	}
	return a
}

// WithClock overrides the clock. Test-only.
func (a *Authenticator) WithClock(now func() time.Time) *Authenticator {
	if now != nil {
		a.now = now
	}
	return a
}

// VerifyPassword authenticates email and password.
//
// Returns ErrInvalidCredentials for an unknown address, a wrong password, and a
// disabled account alike.
//
// The failure counter is incremented only when a password is actually wrong. A
// locked account does not increment it further, because otherwise an attacker
// could hold an account locked indefinitely just by continuing to guess.
func (a *Authenticator) VerifyPassword(ctx context.Context, email, password string) (*Result, error) {
	if email == "" || password == "" {
		// Still burn the equivalent CPU: an empty password is a guess like any
		// other, and returning early is a measurable difference.
		verifyDummy(password)
		return nil, ErrInvalidCredentials
	}

	user, err := a.userRepo.GetByEmail(ctx, NormalizeEmail(email))
	if err != nil {
		if errors.Is(err, domain.ErrNotFound) {
			verifyDummy(password)
			return nil, ErrInvalidCredentials
		}
		// A genuine database failure, not masked as invalid credentials. Reporting
		// a database outage as "wrong password" sends the user to reset a password
		// that was never at risk.
		return nil, fmt.Errorf("authn: VerifyPassword: %w", err)
	}

	now := a.now()

	// A locked account skips verification. That is a real timing difference, but
	// it only distinguishes accounts that exist, and a lockout has already been
	// reported to the account holder.
	if user.IsLocked(now) {
		return nil, ErrAccountLocked
	}

	if !user.IsEnabled() {
		// Verified anyway so that a disabled account and a wrong password take the
		// same time. The counter is not touched: a re-enabled account must not
		// start life already locked.
		verifyDummy(password)
		return nil, ErrInvalidCredentials
	}

	ok, err := crypto.VerifyPassword(password, user.PasswordHash)
	if err != nil {
		// A malformed stored hash is a server-side defect, surfaced as an error so
		// it reaches the log. The caller still reports a generic failure.
		return nil, fmt.Errorf("authn: VerifyPassword: stored hash unusable: %w", err)
	}
	if !ok {
		verifyDummy(password)
		if _, lerr := a.userRepo.RecordLoginFailure(ctx, user.UserID, a.failedThreshold, a.lockoutDuration); lerr != nil {
			return nil, fmt.Errorf("authn: VerifyPassword: record failure: %w", lerr)
		}
		return nil, ErrInvalidCredentials
	}

	if err := a.userRepo.RecordLoginSuccess(ctx, user.UserID); err != nil {
		// The password WAS correct. Reporting this to the user as a failed login
		// would have them retry a working password.
		return nil, fmt.Errorf("authn: VerifyPassword: record success: %w", err)
	}

	// Transparently strengthen a hash stored under weaker parameters. This is the
	// only moment the plaintext is available, which is what makes raising the cost
	// possible without a rehash-everything migration. Best effort: failing to
	// upgrade a hash must not fail a login.
	if needs, nerr := crypto.NeedsRehash(user.PasswordHash, a.argonParams); nerr == nil && needs {
		if newHash, herr := crypto.HashPassword(password, a.argonParams); herr == nil {
			_ = a.userRepo.UpdatePasswordHash(ctx, user.UserID, newHash)
		}
	}

	user.FailedLoginCount = 0
	user.LockedUntil = nil
	user.LastLoginAt = &now

	return &Result{
		User:     user,
		AuthTime: now,
		AMR:      []string{domain.AMRPwd},
	}, nil
}

// verifyDummy performs the work of a real verification, for lookup misses.
//
// The result is ignored deliberately. There is nothing to decide on a miss; the
// call exists only to consume the same CPU.
func verifyDummy(password string) {
	_, _ = crypto.VerifyPassword(password, dummyHash)
}

// NormalizeEmail lower-cases and trims an address for lookup.
//
// Both operations matter. The unique index is on lower(email), so an untrimmed or
// mixed-case lookup misses a row that exists, and the user is told their address is
// unknown when it is registered.
func NormalizeEmail(email string) string {
	return strings.ToLower(strings.TrimSpace(email))
}
