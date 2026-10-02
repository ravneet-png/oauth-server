package storage

// Shared repository plumbing: error translation and the column/struct mappings
// shared by more than one repo.
//
// Three decisions here are load-bearing, and each one exists because the obvious
// alternative is wrong in a way that is invisible until it is exploited:
//
//  1. ErrNotFound is returned for a zero-row result, and single-use consumption
//     additionally reports ErrAlreadyConsumed. These are deliberately
//     distinguishable, because the reuse-detection path in Prompt 8 must be able
//     to tell "this authorization code was already redeemed" (a stolen token,
//     revoke the family) from "this code never existed" (an attacker guessing
//     values, do nothing). Collapsing them into one sentinel means a brute-force
//     attempt can trigger mass family revocation, which is a denial-of-service
//     primitive against every user whose token an attacker can name.
//
//  2. Every timestamp is TIMESTAMPTZ and travels as time.Time. The schema stores
//     epoch seconds in exactly two columns, client_id_issued_at and
//     client_secret_expires_at, because RFC 7591's client metadata model is
//     defined in numeric date form. Those two are converted at the boundary and
//     nowhere else, in this file, so there is exactly one implementation of the
//     conversion rather than one per repository.
//
//  3. Arrays are TEXT[] and are read and written as []string. pgx handles
//     []string <-> TEXT[] directly; the alternative is a hand-written
//     comma-joined string, which is why a scope containing a comma is a bug
//     nobody writes a test for.

import (
	"context"
	"errors"
	"fmt"
	"math"
	"net/netip"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"

	"oauth-server/internal/domain"
)

// PostgreSQL SQLSTATE codes, referenced by name rather than as bare strings.
//
// 23505 unique_violation, 23503 foreign_key_violation, 23514 check_violation.
// These are stable, documented constants, not internal error numbers, so naming
// them is safe; a bare "23505" in a switch is not.
const (
	sqlStateUniqueViolation     = "23505"
	sqlStateForeignKeyViolation = "23503"
	sqlStateCheckViolation      = "23514"
	sqlStateNotNullViolation    = "23502"
)

// queryer is satisfied by both *pgxpool.Pool and pgx.Tx, so every method here
// works unchanged inside or outside a transaction.
//
// This is what lets a caller compose repositories into one transaction without
// every repository gaining a parallel "Tx" variant. The two atomic-consume
// methods below are the only ones that must NOT be wrapped: they rely on a single
// statement being atomic, and wrapping them in a transaction that holds another
// row's lock is how a deadlock gets written. A transaction is still correct for
// them, but it must not span other contended work.
type queryer interface {
	Exec(ctx context.Context, sql string, args ...any) (pgconn.CommandTag, error)
	Query(ctx context.Context, sql string, args ...any) (pgx.Rows, error)
	QueryRow(ctx context.Context, sql string, args ...any) pgx.Row
}

// compile-time proof that the pool satisfies queryer. If a pgx upgrade changes
// either signature this fails here rather than at the first call site.
var _ queryer = (*pgxpool.Pool)(nil)

// classifyError translates a driver error into a domain sentinel.
//
// pgx returns *pgconn.PgError for anything the server rejected, and every one of
// those is a normal, expected outcome here: a duplicate client_id, a client
// registering a redirect URI the CHECK constraint rejects, a session pointing at
// a user deleted a millisecond earlier. Treating them as unexpected turns routine
// concurrency into a 500 and fills the log with text nobody will ever read.
//
// The sentinel is wrapped with %w so errors.Is still works, and the underlying
// PgError is retained for the constraint name, which is what an operator needs
// to diagnose a rejected registration.
func classifyError(err error, op string) error {
	if err == nil {
		return nil
	}
	// Context errors pass through unwrapped-by-classification so that a caller
	// can still distinguish "cancelled" from "the database said no". Losing that
	// turns a client disconnect into what looks like a constraint violation.
	if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
		return domain.Wrapf(err, "storage: %s", op)
	}

	var pgErr *pgconn.PgError
	if errors.As(err, &pgErr) {
		switch pgErr.Code {
		case sqlStateUniqueViolation:
			return domain.Wrapf(domain.ErrConflict, "storage: %s: unique violation on %s", op, pgErr.ConstraintName)
		case sqlStateForeignKeyViolation:
			// A dangling FK is a conflict from the caller's point of view: the
			// row it referenced is gone. Distinct from a unique violation only
			// in the log, not in the sentinel, because there is nothing the
			// caller can do differently about either.
			return domain.Wrapf(domain.ErrConflict, "storage: %s: foreign key violation on %s", op, pgErr.ConstraintName)
		case sqlStateCheckViolation:
			return domain.Wrapf(domain.ErrConflict, "storage: %s: check constraint %s rejected the row", op, pgErr.ConstraintName)
		case sqlStateNotNullViolation:
			return domain.Wrapf(domain.ErrConflict, "storage: %s: NOT NULL violated on %s", op, pgErr.ConstraintName)
		}
	}

	// pgx.ErrNoRows is the zero-row case, handled by the caller before reaching
	// here, but a Query-based scan can surface it.
	if errors.Is(err, pgx.ErrNoRows) {
		return domain.Wrapf(domain.ErrNotFound, "storage: %s", op)
	}

	return domain.Wrapf(err, "storage: %s", op)
}

// notFound builds the canonical zero-row error. A separate constructor so the
// message is identical everywhere and a log grep finds every miss.
func notFound(op string) error {
	return domain.Wrapf(domain.ErrNotFound, "storage: %s", op)
}

// rowNotFound maps pgx.ErrNoRows to ErrNotFound and passes everything else
// through classifyError. Used after a QueryRow scan.
func rowNotFound(err error, op string) error {
	if errors.Is(err, pgx.ErrNoRows) {
		return notFound(op)
	}
	return classifyError(err, op)
}

// epochToTime converts RFC 7591 numeric-date seconds to a time.Time.
//
// The two client columns that store epoch seconds exist because that is how the
// client registration spec expresses them, and they are converted here rather
// than in the repository so there is one implementation. A value of 0 means
// "never", per RFC 7591, and maps to the zero time rather than to 1970: a
// client whose secret has no expiry must not read as having expired 56 years ago.
func epochToTime(sec int64) time.Time {
	if sec == 0 {
		return time.Time{}
	}
	return time.Unix(sec, 0).UTC()
}

// timeToEpoch is the inverse of epochToTime. The zero time maps to 0, matching
// the schema's DEFAULT 0 and the "never" semantics above.
func timeToEpoch(t time.Time) int64 {
	if t.IsZero() {
		return 0
	}
	return t.Unix()
}

// addrToString renders a netip.Addr for an INET parameter, or nil for NULL.
//
// An *Addr pointer is passed straight through to pgx, which encodes INET
// natively, so this exists for the places that build a value rather than pass a
// domain field: it makes the nil case explicit at the call site instead of
// relying on a typed-nil interface being encoded as NULL (which it is not; a
// typed nil pointer in an interface is a non-nil interface holding a nil pointer,
// and pgx will happily try to read through it).
func addrToString(addr *netip.Addr) *string {
	if addr == nil || !addr.IsValid() {
		return nil
	}
	s := addr.String()
	return &s
}

// jsonOrNil prepares a JSON document for a parameter position.
//
// It returns *string rather than []byte on purpose. The pool runs in
// QueryExecModeExec, so pgx never sees the prepared statement's parameter OIDs
// and cannot pick a codec: it encodes a plain []byte as a bytea literal, and
// PostgreSQL then rejects "\x7b7d" as json. json.RawMessage survives that mode
// because pgx special-cases it, but accepting []byte here erased that
// distinction at the call site and every JSON write failed with SQLSTATE 22P02.
//
// The paired `::jsonb` cast at each call site makes the intent explicit and
// keeps the encoding correct if the exec mode ever changes. A nil pointer is
// sent as SQL NULL, which is what an absent document means; an empty slice is
// treated as absent rather than written as invalid JSON.
func jsonOrNil(raw []byte) *string {
	if len(raw) == 0 {
		return nil
	}
	s := string(raw)
	return &s
}

// affectedRows converts a command tag to an int, returning -1 for a statement
// that reports no count. Callers that need the count check for -1 rather than
// treating it as zero, so a future SQLMODE that stops reporting rows cannot
// silently read as "nothing matched, all good".
func affectedRows(tag pgconn.CommandTag) int {
	n := tag.RowsAffected()
	if n < 0 || n > math.MaxInt32 {
		return -1
	}
	return int(n)
}

// nullString converts a nullable string column to the pointer form the domain
// uses. The domain distinguishes "absent" from "empty" throughout, so this
// conversion appears on every nullable text column and getting it wrong on one
// turns a NULL into a pointer-to-empty-string, which reads as a present value.
func nullString(s *string) *string { return s }

// stringPtr is the inverse, for the many columns that are written as parameters.
// Taking a pointer to a parameter is a copy, so callers can pass a loop
// variable's address safely.
func stringPtr(s string) *string { return &s }

// timePtr returns a pointer to t, or nil for the zero time, which is how the
// domain spells "no expiry" and "not yet".
func timePtr(t time.Time) *time.Time {
	if t.IsZero() {
		return nil
	}
	return &t
}

// scanStrings is a helper for reading TEXT[] into []string, tolerating a NULL
// column as an empty slice.
//
// The schema marks scope-bearing columns NOT NULL, so a nil here means the column
// was added by a later migration with no default and the row predates it.
// Returning an empty slice rather than nil means callers can range over it and
// compare it with len() without a nil check that is easy to omit.
func scanStrings(raw []string) []string {
	if raw == nil {
		return []string{}
	}
	return raw
}

// wrapRowsErr converts a rows iteration error, which is the shape pgx uses for
// mid-iteration failures such as a connection dropping. The error only surfaces
// at rows.Err(), so every scan that can fail partway must check it; forgetting to
// is how a truncated result set becomes a confidently wrong empty one.
func wrapRowsErr(err error, op string) error {
	if err == nil {
		return nil
	}
	return classifyError(err, op)
}

// isNoRows reports whether err is pgx's zero-row result, which is an expected
// outcome for optional lookups rather than a failure.
func isNoRows(err error) bool {
	return errors.Is(err, pgx.ErrNoRows)
}

// ctxErr reports whether err is a context error, so callers can avoid
// translating a cancelled request into a domain sentinel.
func ctxErr(err error) bool {
	return errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded)
}

// ErrNoRowsAffected is returned by methods documented as "returns nil if the row
// was already consumed" when the caller asked for a hard error instead. Kept
// separate from ErrNotFound because the prompt's contract for AtomicMarkUsed and
// AtomicRotate is a nil result with a nil error, and this is the sentinel a
// caller uses to opt into the stricter behaviour.
var ErrNoRowsAffected = errors.New("storage: no rows affected")

// assertPoolNonNil guards a constructor against a nil pool.
//
// Every constructor stores the pool without dereferencing it, so a nil pool would
// otherwise survive until the first query and surface as a nil-pointer panic in a
// request handler rather than at wiring time. A constructor that panics on a
// programming error is correct here; there is no legitimate nil pool.
func assertPoolNonNil(pool *pgxpool.Pool, name string) {
	if pool == nil {
		panic("storage: " + name + " requires a non-nil pool")
	}
}

// reaperSQL is the shared shape of every DeleteExpired method: a bounded DELETE
// with a LIMIT, returning the number of rows removed.
//
// The LIMIT is the point. A reaper that deletes every expired row in one
// statement takes a long-lived lock and can block live traffic on the same table
// for as long as it runs, so the work is chunked and the caller runs it
// repeatedly. Without the bound, a table that has been un-reaped for a long
// outage turns the first reaper run into an outage of its own.
const reaperBatch = 1000

// formatOp builds a consistent operation label for error messages, so a log line
// identifies the statement rather than the method that ran it.
func formatOp(parts ...string) string {
	out := ""
	for i, p := range parts {
		if i > 0 {
			out += "."
		}
		out += p
	}
	return out
}

// ensure fmt is referenced even if every helper above stops using it, which
// keeps the import list stable across future edits.
var _ = fmt.Sprintf
