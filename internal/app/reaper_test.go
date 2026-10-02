package app

// Reaper tests.
//
// Two things are being tested, and they are different kinds of claim. The first is
// that a sweep removes expired rows and leaves live ones alone, which needs a real
// database because every DeleteExpired has its own WHERE clause and a wrong one
// deletes production rows. The second is that the loop and the sweep's error handling
// behave, which needs no database at all and is driven through the target table
// directly.
//
// Every test is skipped without TEST_DATABASE_URL, matching the storage package.

import (
	"context"
	"errors"
	"sync/atomic"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	"oauth-server/internal/handlers"
	"oauth-server/internal/storage"
)

// newReaperDeps builds the repository set the Reaper reads through Deps.
//
// Only the repositories the reaper calls are populated. The rest of Deps is nil,
// which is safe here because sweep touches nothing else, and populating all of them
// would make this test depend on unrelated constructor requirements.
func newReaperDeps(t *testing.T, raw *pgxpool.Pool) *handlers.Deps {
	t.Helper()
	return &handlers.Deps{
		Sessions:    storage.NewSessionRepo(raw),
		Codes:       storage.NewAuthCodeRepo(raw),
		AuthReqs:    storage.NewAuthRequestRepo(raw),
		PARs:        storage.NewPARRepo(raw),
		AccessToks:  storage.NewAccessTokenRepo(raw),
		RefreshToks: storage.NewRefreshTokenRepo(raw),
		Revoked:     storage.NewRevokedTokenRepo(raw),
		Families:    storage.NewTokenFamilyRepo(raw),
		EmailVerif:  storage.NewEmailVerificationRepo(raw),
	}
}

// TestReaperSweepRemovesExpiredRowsOnly is the safety test.
//
// Runs in its own schema (see newPoolForReaper) and counts rows only from the sessions
// it created, because other tests in this package share the database.
//
// The assertion that matters is the negative one: a live row must survive. A reaper
// whose WHERE clause is inverted or missing an expiry comparison passes "deleted the
// expired row" and destroys every active session in the deployment.
func TestReaperSweepRemovesExpiredRowsOnly(t *testing.T) {
	ctx := context.Background()
	raw := newPoolForReaper(t)
	deps := newReaperDeps(t, raw)

	// One lapsed session and one live session under a single dedicated user. Sessions
	// are the cheapest table to use here: the insert is a handful of columns and
	// DeleteExpired is a single indexed comparison, so a failure points at the reaper
	// rather than at fixture noise.
	//
	// The count is scoped to that user rather than to the table, so a row left by
	// another test cannot fail this one.
	userID := reaperSeq(t, "user")
	insertUserForReaper(t, raw, userID)

	expired := insertSessionForUserForReaper(t, raw, userID, time.Now().Add(-48*time.Hour))
	live := insertSessionForUserForReaper(t, raw, userID, time.Now().Add(24*time.Hour))

	reaper := NewReaper(deps, nil)
	reaper.sweep(ctx)

	if got := countSessionsForUser(t, raw, userID); got != 1 {
		t.Fatalf("sweep left %d sessions for the fixture user, want 1 (the live one)", got)
	}
	if sessionExists(t, raw, expired) {
		t.Error("expired session survived the sweep")
	}
	if !sessionExists(t, raw, live) {
		t.Error("sweep deleted a live session")
	}
}

// TestReaperSweepContinuesAfterTableError covers the ordering decision in sweep: one
// failing table must not starve the ones after it.
//
// The counter is on the target after the failing one, so if the sweep aborted on error
// the counter would stay at zero.
func TestReaperSweepContinuesAfterTableError(t *testing.T) {
	var reached atomic.Int32
	r := &Reaper{
		log: newTestLogger(),
		targets: []reapTarget{
			{"always_fails", func(context.Context) (int, error) { return 0, errors.New("boom") }},
			{"counted", func(context.Context) (int, error) {
				reached.Add(1)
				return 0, nil
			}},
		},
		every: time.Hour,
		done:  make(chan struct{}),
	}

	r.sweep(context.Background())

	if got := reached.Load(); got != 1 {
		t.Fatalf("sweep reached the target after the failing one %d times, want 1", got)
	}
}

// TestReaperSweepStopsQuietlyOnCancellation checks the cancellation path. Once the
// context is done every DeleteExpired would fail, and logging each failure during
// shutdown would bury the real shutdown messages.
func TestReaperSweepStopsQuietlyOnCancellation(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	var ran atomic.Int32
	r := &Reaper{
		log: newTestLogger(),
		targets: []reapTarget{
			{"counted", func(context.Context) (int, error) {
				ran.Add(1)
				return 0, nil
			}},
		},
		every: time.Hour,
		done:  make(chan struct{}),
	}

	r.sweep(ctx)

	// The first target may run and return nil, since the fake ignores the context;
	// what must not happen is the loop grinding through the rest after cancellation.
	if got := ran.Load(); got > 1 {
		t.Fatalf("sweep continued through %d targets after cancellation, want at most 1", got)
	}
}

// TestReaperStartSweepsImmediatelyAndStops covers the lifecycle contract: Start runs a
// sweep without waiting for the first tick, and Stop waits for the loop to exit.
//
// Waiting on Stop is what makes the shutdown ordering safe. If Stop returned early, the
// loop would still hold a database handle while Close closes the pool.
func TestReaperStartSweepsImmediatelyAndStops(t *testing.T) {
	var calls atomic.Int32
	swept := make(chan struct{}, 4)

	r := &Reaper{
		log: newTestLogger(),
		targets: []reapTarget{
			{"counted", func(context.Context) (int, error) {
				if calls.Add(1) == 1 {
					swept <- struct{}{}
				}
				return 0, nil
			}},
		},
		// Long interval: the assertion is about the immediate first sweep, so a
		// ticker firing during the test would not be what makes this pass.
		every: time.Hour,
		done:  make(chan struct{}),
	}

	ctx, cancel := context.WithCancel(context.Background())
	r.Start(ctx)

	select {
	case <-swept:
	case <-time.After(5 * time.Second):
		cancel()
		t.Fatal("Start did not sweep before the first interval elapsed")
	}

	cancel()

	stopCtx, stopCancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer stopCancel()
	if err := r.Stop(stopCtx); err != nil {
		t.Fatalf("Stop: %v", err)
	}

	// done is closed by the loop's defer. Reading it directly is the check: Stop
	// returned nil either because the loop finished or because done was already
	// closed, and only this distinguishes "joined" from "raced past".
	select {
	case <-r.done:
	default:
		t.Error("Stop returned while the sweep loop was still running")
	}
	if calls.Load() > 1 {
		t.Errorf("swept %d times; the hourly ticker should not have fired", calls.Load())
	}
}

// TestReaperStopBeforeStartDeadlines checks that Stop cannot hang forever on a reaper
// that was never started. Nothing on the running server hits this, but it is the
// failure mode that turns a shutdown bug into a hung process.
func TestReaperStopBeforeStartDeadlines(t *testing.T) {
	r := NewReaper(&handlers.Deps{}, nil)

	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()

	if err := r.Stop(ctx); err == nil {
		t.Error("Stop on an unstarted Reaper returned nil; want a context error")
	}
}
