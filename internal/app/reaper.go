package app

// Expiry reaper.
//
// Every repository exposes DeleteExpired and every one of them deletes in bounded
// batches, but nothing on the server was calling them. Expired rows were therefore
// accumulating forever: authorization codes, pushed authorization requests, lapsed
// sessions, issued-access-token records and deny-list entries all grow monotonically,
// and the tables they sit in are indexed on the columns the reaper filters by. A
// deployment that ran for a month would have a month of dead rows.
//
// Deliberately in this package rather than in main: main owns process lifecycle, and a
// loop that must be stopped and joined belongs next to the pool it borrows, so that
// App.Close can guarantee it is no longer running before the pool closes under it.

import (
	"context"
	"log/slog"
	"time"

	"oauth-server/internal/handlers"
)

// ReaperInterval is how often a full sweep runs.
//
// An hour is chosen against the shortest-lived row it removes: a PAR request lives 60
// seconds, so an hourly sweep bounds that table at roughly 60 sweeps of traffic rather
// than the 86400x the same table would hold at a daily cadence. Sweeping more often
// costs one indexed DELETE per table per run, which is cheaper than the bloat it
// prevents.
const ReaperInterval = time.Hour

// reapTarget is one table the reaper sweeps.
//
// Named by a string rather than held as an interface value so the sweep table is one
// declaration and adding a table is one line. The DeleteExpired methods all share a
// signature and all return (rows, error), so a function field is the whole contract.
type reapTarget struct {
	name string
	run  func(context.Context) (int, error)
}

// Reaper deletes expired rows on an interval.
type Reaper struct {
	targets []reapTarget
	every   time.Duration
	log     *slog.Logger

	// done is closed when the loop has returned, so Stop can wait for it. A reaper
	// still mid-sweep when Close closes the pool would delete rows through a closed
	// pool, which is an error rather than a crash, but the shutdown log would be
	// full of it and the guarantee would be gone.
	done chan struct{}
}

// NewReaper builds a Reaper over the repositories' DeleteExpired methods.
func NewReaper(d *handlers.Deps, log *slog.Logger) *Reaper {
	if log == nil {
		log = slog.Default()
	}
	return &Reaper{
		// The order is deliberate: rows that reference other rows go first, so a sweep
		// never leaves an orphan behind for the next one to clean. Refresh tokens and
		// token families cascade-delete on users and clients, and codes reference
		// families, so the families go after the codes that point at them.
		targets: []reapTarget{
			{"auth_codes", d.Codes.DeleteExpired},
			{"par_requests", d.PARs.DeleteExpired},
			{"auth_requests", d.AuthReqs.DeleteExpired},
			{"email_verifications", d.EmailVerif.DeleteExpired},
			{"sessions", d.Sessions.DeleteExpired},
			{"revoked_tokens", d.Revoked.DeleteExpired},
			{"refresh_tokens", d.RefreshToks.DeleteExpired},
			{"token_families", d.Families.DeleteExpired},
			{"issued_access_tokens", d.AccessToks.DeleteExpired},
		},
		every: ReaperInterval,
		log:   log,
		done:  make(chan struct{}),
	}
}

// Start runs the sweep loop until ctx is cancelled.
//
// The first sweep runs immediately rather than after one interval. A server that has
// just been restarted after a long outage is exactly the case where the tables are
// largest, and waiting an hour to start shrinking them is the wrong order.
func (r *Reaper) Start(ctx context.Context) {
	go func() {
		defer close(r.done)

		r.sweep(ctx)

		ticker := time.NewTicker(r.every)
		defer ticker.Stop()

		for {
			select {
			case <-ctx.Done():
				r.log.Info("expiry reaper stopped")
				return
			case <-ticker.C:
				r.sweep(ctx)
			}
		}
	}()
}

// Stop waits for the loop to return.
//
// Wait, not fire-and-forget: the caller is shutting down and the loop holds database
// handles. Returning while it still runs hands it a pool that is about to close.
func (r *Reaper) Stop(ctx context.Context) error {
	select {
	case <-r.done:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

// sweep runs one pass over every table.
//
// Bounded batches mean a single pass is not enough to empty a badly backlogged table.
// That is fine and intended: each table gets one batch per hour, so a large backlog
// drains over hours while live traffic is never blocked by a long DELETE. The count is
// logged so an operator can see the backlog shrinking rather than having to query for
// it.
//
// A failing table does not stop the sweep. The alternative is that one persistent error
// on the first table starves the other eight forever, and a table that cannot be
// cleaned is not a reason to stop cleaning the ones that can.
func (r *Reaper) sweep(ctx context.Context) {
	for _, target := range r.targets {
		rows, err := target.run(ctx)
		if err != nil {
			// Cancelled means shutdown, not failure. Reporting it as an error on the
			// way out of every shutdown is noise that trains people to ignore the log.
			if ctx.Err() != nil {
				return
			}
			r.log.Error("expiry reaper failed", "table", target.name, "error", err)
			continue
		}
		if rows > 0 {
			r.log.Info("expiry reaper removed rows", "table", target.name, "rows", rows)
		}
	}
}
