package crypto

import (
	"context"
	"crypto/rand"
	"crypto/subtle"
	"encoding/binary"
	"fmt"
	"sync"
	"time"
)

// Timing helpers.
//
// Two distinct problems are addressed here and they must not be confused:
//
//  1. A check-then-respond loop leaks whether an account EXISTS. The fix is
//     uniform jitter, so a fast "no such user" and a slow "wrong password" are
//     indistinguishable by duration.
//
//  2. A byte comparison leaks how much of a secret was guessed correctly. The
//     fix is constant-time comparison. See hash.go.

// There is deliberately no "not configured" error state. An earlier version
// declared ErrTimingNotConfigured on the reasoning that a server which boots
// without jitter should fail loudly. That was the wrong call for two reasons.
//
// First, it was unimplementable as written: init() below installs a default
// window, so the unconfigured state is unreachable, which left the error as dead
// code whose doc comment described behaviour the package did not have. A reader
// auditing the failure paths would reasonably conclude something was checked
// that was not.
//
// Second, failing closed on a missing configuration is the wrong default here.
// The realistic way to reach this code is a partially-initialised server or a
// new call site added before its wiring landed. Making that a startup failure
// converts a security control into an availability dependency, and the natural
// response to a server that will not boot is to disable the control.
//
// Instead the package is secure-by-default: jitter is on unless an operator
// explicitly turns it off. Losing the control is possible, but only as a
// deliberate, greppable act.

// jitter bounds. The window is applied to FAILED authentication responses only.
//
// Applying jitter to successful logins would be self-defeating: the success path
// is followed immediately by a session cookie and a redirect, so padding it just
// adds latency for a user who did nothing wrong, and it does not help, because an
// attacker probing for account existence cannot see another user's success.
const (
	// defaultJitterMin and defaultJitterMax bracket a uniform random delay.
	// 50ms to 250ms is wide enough to swamp the timing signal from a password
	// hash (argon2id at 64 MiB takes roughly 50-100ms and is itself variable)
	// and short enough that a real user does not notice.
	defaultJitterMin = 50 * time.Millisecond
	defaultJitterMax = 250 * time.Millisecond
)

// jitterCfg holds the response-jitter window.
//
// The mutex is load-bearing. ConfigureTiming is called once at boot but SleepJitter
// is called from every failed login, and a configuration reload or a test
// mutating the window while requests are in flight is an unsynchronised read and
// write of a struct that contains a func value. A torn func pointer is a crash,
// not a wrong answer, so this cannot be left to the assumption that it is only
// written during start-up.
var (
	jitterMu  sync.RWMutex
	jitterCfg struct {
		min, max time.Duration
		enabled  bool
		// randRead is indirected so tests can make it deterministic. Production
		// always uses crypto/rand.
		randRead func(p []byte) (int, error)
	}
)

// ConfigureTiming enables response jitter with the given bounds. A max of zero
// disables jitter, which is only correct in tests.
func ConfigureTiming(min, max time.Duration) error {
	if min < 0 || max < min {
		return fmt.Errorf("crypto: invalid jitter window %v..%v", min, max)
	}

	jitterMu.Lock()
	defer jitterMu.Unlock()

	jitterCfg.min = min
	jitterCfg.max = max
	jitterCfg.enabled = max > 0
	jitterCfg.randRead = rand.Read
	return nil
}

// TimingStatus reports the currently active jitter window.
//
// It exists so a running server can be asked whether the control is live,
// rather than that being a matter of reading the source and trusting it. A
// security control with no observable state is one that cannot be asserted on in
// a health check or an operational runbook. Intended for diagnostics and startup
// logging; it is not a secret and does not leak the window to clients.
func TimingStatus() (min, max time.Duration, enabled bool) {
	min, max, enabled, _ = currentJitter()
	return min, max, enabled
}

// currentJitter returns a snapshot of the window. The copy is what makes the
// unlocked portion of SleepJitter safe: it never touches jitterCfg directly.
func currentJitter() (min, max time.Duration, enabled bool, read func([]byte) (int, error)) {
	jitterMu.RLock()
	defer jitterMu.RUnlock()
	return jitterCfg.min, jitterCfg.max, jitterCfg.enabled, jitterCfg.randRead
}

func init() {
	// Enabled by default with the standard window, so a caller that forgets to
	// configure this still gets protection. A server that boots without jitter
	// because nobody called a setup function is a silent downgrade.
	_ = ConfigureTiming(defaultJitterMin, defaultJitterMax)
}

// SleepJitter pauses for a uniformly random duration in the configured window.
//
// The delay is drawn from crypto/rand, not math/rand. This is not about
// unpredictability against an attacker who can observe the timing: a PRNG would
// be fine for that. It is that a seeded PRNG produces the same delay sequence on
// every process, so an attacker who measures a few failures learns the sequence
// and can subtract the jitter from subsequent measurements.
func SleepJitter(ctx context.Context) error {
	min, max, enabled, read := currentJitter()
	if !enabled || read == nil {
		return nil
	}
	span := max - min
	if span <= 0 {
		return nil
	}

	var buf [8]byte
	if _, err := read(buf[:]); err != nil {
		return fmt.Errorf("crypto: read jitter randomness: %w", err)
	}
	n := binary.BigEndian.Uint64(buf[:])

	// Rejection sampling for an unbiased range. The number of uint64 values
	// that must be discarded is (2^64 mod span), computed as -span mod span in
	// two's complement so it does not overflow. A plain n % span would bias the
	// low end of the range, which does not matter for jitter but is the kind of
	// shortcut that gets copied somewhere it does.
	spanU := uint64(span)
	threshold := -spanU % spanU
	for n < threshold {
		if _, err := read(buf[:]); err != nil {
			return fmt.Errorf("crypto: read jitter randomness: %w", err)
		}
		n = binary.BigEndian.Uint64(buf[:])
	}

	delay := min + time.Duration(n%spanU)

	timer := time.NewTimer(delay)
	defer timer.Stop()
	select {
	case <-ctx.Done():
		// The context is cancelled, so the caller is shutting down or the
		// client went away. Returning early here is correct and skips the sleep
		// rather than holding the request open.
		return ctx.Err()
	case <-timer.C:
		return nil
	}
}

// ConstantTimeEqual reports whether a and b are equal, without leaking their
// contents through timing.
//
// Unlike hmac.Equal, this does not require the inputs to be of equal length:
// unequal lengths are reported as false immediately. That is a deliberate
// deviation and is safe only for values whose length is NOT secret. Token and
// digest lengths are fixed by construction, so nothing is learned; use
// VerifySHA256Hex for the stored-digest case where the length is known-fixed
// anyway.
func ConstantTimeEqual(a, b string) bool {
	return subtle.ConstantTimeCompare([]byte(a), []byte(b)) == 1
}

// ConstantTimeEqualBytes is ConstantTimeEqual for byte slices.
func ConstantTimeEqualBytes(a, b []byte) bool {
	return subtle.ConstantTimeCompare(a, b) == 1
}
