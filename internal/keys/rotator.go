package keys

// Background key rotation and retention.
//
// The two jobs are separate and run on separate schedules. Rotation replaces the
// key that signs; retention destroys the private halves of keys that stopped
// signing long enough ago. Conflating them is how a server ends up destroying a key
// while tokens it signed are still valid, so they are separate methods and a
// failure in one does not stop the other.

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"time"

	"oauth-server/internal/domain"
)

// DefaultCheckInterval is how often the rotator wakes up.
//
// 24 hours. A daily check against a rotation interval measured in days means a key
// is rotated within a day of its configured age rather than exactly at it, which
// is the only granularity that matters: the age is a policy threshold, not a
// deadline that a token expires against.
const DefaultCheckInterval = 24 * time.Hour

// Config parameterises a Rotator.
//
// Retention is validated against the longest access token lifetime by the caller,
// not here, because the Rotator has no way to know it. The invariant it must not
// violate is that a key outlives every token it signed, and only the token issuer
// knows that number.
type Config struct {
	// RotationAfter is how old the active key may get before it is replaced.
	RotationAfter time.Duration

	// Retention is how long a retiring key keeps its private half, which must
	// exceed the longest access token TTL plus clock skew.
	Retention time.Duration

	// CheckInterval is how often to run. Zero means DefaultCheckInterval.
	CheckInterval time.Duration

	// Logger receives rotation and retention events. Nil means the default logger.
	Logger *slog.Logger
}

func (c Config) withDefaults() (Config, error) {
	if c.RotationAfter <= 0 {
		return c, errors.New("keys: Config.RotationAfter must be positive; a zero value would rotate on every check")
	}
	if c.Retention <= 0 {
		return c, errors.New("keys: Config.Retention must be positive; a zero value would destroy private keys the moment they stop signing")
	}
	if c.CheckInterval <= 0 {
		c.CheckInterval = DefaultCheckInterval
	}
	if c.Logger == nil {
		c.Logger = slog.Default()
	}
	return c, nil
}

// Rotator performs scheduled key rotation and private key destruction in the
// background.
type Rotator struct {
	mgr  *Manager
	cfg  Config
	stop chan struct{}
	done chan struct{}
}

// NewRotator builds a Rotator.
func NewRotator(mgr *Manager, cfg Config) (*Rotator, error) {
	if mgr == nil {
		return nil, errors.New("keys: NewRotator: manager is nil")
	}
	resolved, err := cfg.withDefaults()
	if err != nil {
		return nil, err
	}
	return &Rotator{
		mgr:  mgr,
		cfg:  resolved,
		stop: make(chan struct{}),
		done: make(chan struct{}),
	}, nil
}

// Start launches the background loop and returns immediately.
//
// The loop runs its first check after one full interval rather than immediately at
// startup. A check at t=0 on a fresh deployment is harmless, but on a restart it
// would race with the boot path that is still loading the active key, and two
// processes both deciding to rotate produces a burst of key generation for no
// benefit. The boot sequence calls LoadActive itself, so nothing is lost by
// waiting.
func (r *Rotator) Start(ctx context.Context) {
	go r.loop(ctx)
}

// Stop shuts the loop down and waits for it to exit.
//
// Waits, because a rotator that is still mid-rotation when the process exits can
// leave a key retired with no successor. The commit is atomic so that cannot leave
// the server unable to sign, but Stop returning before the goroutine has finished
// would still let the caller tear down the pool underneath an in-flight query.
func (r *Rotator) Stop(ctx context.Context) error {
	select {
	case <-r.stop:
		// Already stopped; fall through to waiting on done.
	default:
		close(r.stop)
	}
	select {
	case <-r.done:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

func (r *Rotator) loop(ctx context.Context) {
	defer close(r.done)

	ticker := time.NewTicker(r.cfg.CheckInterval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-r.stop:
			return
		case <-ticker.C:
			if err := r.RunOnce(ctx); err != nil {
				// Logged, not fatal. A rotation that fails must not take the server
				// down: the existing key is still valid and still signing, and the
				// next tick tries again. The opposite behaviour, exiting, would turn
				// a transient database blip into an outage.
				r.cfg.Logger.Error("key rotation check failed", "error", err)
			}
		}
	}
}

// RunOnce performs one rotation check and one retention sweep.
//
// Exported and separated from the loop so that both are testable without waiting 24
// hours, and so an operator can trigger a rotation from a command rather than
// waiting for the schedule. The two halves are independent: a retention failure
// does not prevent rotation, and the reverse.
func (r *Rotator) RunOnce(ctx context.Context) error {
	var errs []error

	if err := r.rotateIfDue(ctx); err != nil {
		errs = append(errs, err)
	}
	if err := r.sweepRetired(ctx); err != nil {
		errs = append(errs, err)
	}
	return errors.Join(errs...)
}

// rotateIfDue generates a replacement when the active key is older than
// RotationAfter.
func (r *Rotator) rotateIfDue(ctx context.Context) error {
	active, err := r.loadActiveForRotation(ctx)
	if err != nil {
		return err
	}

	// Measure age from the stored created_at rather than from when this process
	// loaded the key, so restarting the server every hour does not reset the clock
	// and postpone rotation indefinitely.
	keys, err := r.mgr.repo.GetByKID(ctx, active.KID)
	if err != nil {
		return fmt.Errorf("keys: rotation check: read key %q: %w", active.KID, err)
	}
	age := keys.Age(time.Now())
	if age < r.cfg.RotationAfter {
		return nil
	}

	return r.rotateNow(ctx, active, age)
}

// ForceRotate replaces the active signing key regardless of its age.
//
// Used by the administrative endpoint. It performs the same swap as a scheduled
// rotation, including publishing the new key inside the transaction that retires the old
// one, so a forced rotation cannot differ from a routine one in any way that matters.
func (r *Rotator) ForceRotate(ctx context.Context) (*domain.SigningKey, error) {
	active, err := r.loadActiveForRotation(ctx)
	if err != nil {
		return nil, err
	}

	keys, err := r.mgr.repo.GetByKID(ctx, active.KID)
	if err != nil {
		return nil, fmt.Errorf("keys: force rotation: read key %q: %w", active.KID, err)
	}

	retireAt := time.Now().UTC().Add(r.cfg.Retention)
	rec, err := r.mgr.Generate()
	if err != nil {
		return nil, fmt.Errorf("keys: generate replacement key: %w", err)
	}
	retired, err := r.mgr.repo.Rotate(ctx, rec, retireAt)
	if err != nil {
		return nil, fmt.Errorf("keys: rotate %q -> %q: %w", active.KID, rec.KID, err)
	}
	if _, err := r.mgr.LoadActive(ctx); err != nil {
		return nil, fmt.Errorf("keys: rotated to %q but failed to reload the active key: %w", rec.KID, err)
	}

	var retiredKID string
	if retired != nil {
		retiredKID = retired.KID
	}
	r.cfg.Logger.Info("signing key forcibly rotated",
		"old_kid", retiredKID,
		"new_kid", rec.KID,
		"old_age", keys.Age(time.Now()).String(),
		"retire_at", retireAt.Format(time.RFC3339),
	)
	return rec, nil
}

// loadActiveForRotation reads the active key and maps the no-active-key case to a
// message that names the real problem.
func (r *Rotator) loadActiveForRotation(ctx context.Context) (*ActiveKey, error) {
	active, err := r.mgr.LoadActive(ctx)
	if err != nil {
		if errors.Is(err, ErrNoActiveKey) {
			// Nothing to rotate. The boot path generates a first key, so reaching
			// here means either the first key was deleted by hand or the deployment
			// never completed startup. Generating one here would paper over a real
			// operational problem, so it is reported instead.
			return nil, fmt.Errorf("keys: rotation skipped, no active key exists: %w", err)
		}
		return nil, fmt.Errorf("keys: rotation check: %w", err)
	}
	return active, nil
}

// rotateNow performs the swap for an active key whose age has already been measured.
func (r *Rotator) rotateNow(ctx context.Context, active *ActiveKey, age time.Duration) error {
	retireAt := time.Now().UTC().Add(r.cfg.Retention)
	// Generate, not GenerateAndStore. The replacement must not be persisted as active
	// first: signing_keys allows exactly one active row per algorithm, so an insert
	// here would be rejected by the partial unique index and rotation would fail on
	// every tick. Rotate writes the row inside the transaction that retires the old
	// key, which is the only point at which the swap is legal.
	rec, err := r.mgr.Generate()
	if err != nil {
		return fmt.Errorf("keys: generate replacement key: %w", err)
	}

	// Rotate, not two separate calls. The repository's partial unique index allows
	// exactly one active key per algorithm, so the replacement cannot be activated
	// until the old one is retiring, and doing that as two statements leaves a
	// window in which the server can sign with nothing.
	retired, err := r.mgr.repo.Rotate(ctx, rec, retireAt)
	if err != nil {
		// The generated key was never activated, so the old one is still signing and
		// the database still holds exactly one active key. Nothing to clean up, and
		// the next tick will generate a fresh key.
		return fmt.Errorf("keys: rotate %q -> %q: %w", active.KID, rec.KID, err)
	}

	// Swap the cache only after the commit, so the manager never points at a key the
	// database has not accepted. Doing it before would mean signing with a key that
	// is not actually active, and a token signed by it would carry a kid that no
	// relying party can resolve.
	if _, err := r.mgr.LoadActive(ctx); err != nil {
		// The rotation committed, so the old key is retiring and the new one is
		// active. Failing to reload means this process cannot sign until the next
		// reload, which is a serious but recoverable condition, and it is reported
		// rather than swallowed.
		return fmt.Errorf("keys: rotated to %q but failed to reload the active key: %w", rec.KID, err)
	}

	var retiredKID string
	if retired != nil {
		retiredKID = retired.KID
	}
	r.cfg.Logger.Info("signing key rotated",
		"old_kid", retiredKID,
		"new_kid", rec.KID,
		"old_age", age.String(),
		"retire_at", retireAt.Format(time.RFC3339),
	)
	return nil
}

// sweepRetired destroys the private halves of keys whose retention window closed.
func (r *Rotator) sweepRetired(ctx context.Context) error {
	due, err := r.mgr.repo.DueForDestruction(ctx)
	if err != nil {
		return fmt.Errorf("keys: retention sweep: %w", err)
	}
	for _, k := range due {
		if err := r.mgr.repo.DestroyPrivateKey(ctx, k.KID); err != nil {
			// One failure does not stop the sweep. The remaining keys are
			// independent, and returning early would let a single stuck row defer
			// every other destruction indefinitely.
			r.cfg.Logger.Error("failed to destroy retired private key", "kid", k.KID, "error", err)
			continue
		}
		r.cfg.Logger.Info("retired signing key private half destroyed", "kid", k.KID)
	}
	return nil
}
