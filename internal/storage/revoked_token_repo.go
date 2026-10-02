package storage

// Revocation list persistence. Postgres is the durable source; Redis mirrors it
// for latency, and may be lost without loss of correctness.

import (
	"context"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	"oauth-server/internal/domain"
)

// RevokedTokenRepo reads and writes the revoked_tokens table.
type RevokedTokenRepo struct {
	pool *pgxpool.Pool
}

// NewRevokedTokenRepo builds a RevokedTokenRepo over pool.
func NewRevokedTokenRepo(pool *pgxpool.Pool) *RevokedTokenRepo {
	assertPoolNonNil(pool, "RevokedTokenRepo")
	return &RevokedTokenRepo{pool: pool}
}

const revokedTokenColumns = `jti, expires_at, reason, revoked_at`

func scanRevokedToken(row interface{ Scan(...any) error }) (*domain.RevokedToken, error) {
	var t domain.RevokedToken

	// reason is nullable in the schema and a plain string in the domain, where
	// the zero value means "not recorded". Scanning straight into the string
	// fails on every row written by Add, which stores NULL, so the NULL is
	// absorbed here instead of making the domain nullable.
	var reason *string
	if err := row.Scan(&t.JTI, &t.ExpiresAt, &reason, &t.RevokedAt); err != nil {
		return nil, err
	}
	if reason != nil {
		t.Reason = *reason
	}
	return &t, nil
}

// RevocationEntry is one element of a batch insert.
//
// A named type rather than the anonymous struct the prompt wrote. An anonymous
// struct in a public method signature is unnameable by a caller, so the only way
// to build one is to write the identical anonymous struct again, and a field
// reorder then fails to compile at every call site instead of one.
type RevocationEntry struct {
	JTI       string
	ExpiresAt time.Time
	Reason    string
}

// Add records one revoked jti.
//
// ON CONFLICT DO NOTHING. The deny list is a set: recording the same jti twice is
// not an error and must not overwrite the first entry, because the first entry
// carries the earliest revoked_at and the original reason. An upsert that replaced
// the row would let a later low-information revocation overwrite an
// incident-relevant one.
//
// expires_at is the expiry of the DENIED TOKEN, not of this row, so the reaper can
// drop the entry the instant the token it denies could no longer be presented.
// That is what keeps the table small: a row outliving its token is pure write
// amplification on every deny-list check.
func (r *RevokedTokenRepo) Add(ctx context.Context, jti string, expiresAt time.Time) error {
	const q = `
		INSERT INTO revoked_tokens (jti, expires_at, reason)
		VALUES ($1, $2, $3)
		ON CONFLICT (jti) DO NOTHING`

	_, err := r.pool.Exec(ctx, q, jti, expiresAt, nil)
	if err != nil {
		return classifyError(err, formatOp("revoked_tokens", "add"))
	}
	return nil
}

// AddBatch records many revoked jtis in one round trip.
//
// One statement rather than a loop of Add calls: a family revocation can touch
// hundreds of tokens, and 300 round trips inside a request that already holds
// connections is how a token endpoint starts timing out. The whole batch is
// atomic, so a partial deny list is not a reachable state.
//
// The jti list is a parameter array, so it is still a single prepared statement
// with a fixed shape regardless of batch size, which is what makes it safe under
// a pooler in transaction mode.
func (r *RevokedTokenRepo) AddBatch(ctx context.Context, entries []RevocationEntry) error {
	if len(entries) == 0 {
		// Not a no-op by accident: an empty batch is a legitimate call from a
		// revocation sweep that found nothing, and building a statement with an
		// empty array is a syntax error rather than a no-op.
		return nil
	}

	jtis := make([]string, 0, len(entries))
	expiries := make([]time.Time, 0, len(entries))
	for _, e := range entries {
		jtis = append(jtis, e.JTI)
		expiries = append(expiries, e.ExpiresAt)
	}

	const q = `
		INSERT INTO revoked_tokens (jti, expires_at, reason)
		SELECT jti, expires_at, NULL
		  FROM unnest($1::text[], $2::timestamptz[]) AS t(jti, expires_at)
		ON CONFLICT (jti) DO NOTHING`

	if _, err := r.pool.Exec(ctx, q, jtis, expiries); err != nil {
		return classifyError(err, formatOp("revoked_tokens", "add_batch"))
	}
	return nil
}

// IsRevoked reports whether a jti is currently denied.
//
// Expired entries are treated as NOT denied, in the query, rather than by
// trusting the reaper to have run. A deny-list entry for an expired token denies
// nothing, so answering true for one is a false revocation that breaks a
// legitimate request; answering from a stale cache is worse. The predicate
// therefore carries expires_at > now(), and the table can be arbitrarily behind
// without the answer being wrong.
func (r *RevokedTokenRepo) IsRevoked(ctx context.Context, jti string) (bool, error) {
	const q = `
		SELECT EXISTS (
			SELECT 1 FROM revoked_tokens
			 WHERE jti = $1 AND expires_at > now()
		)`

	var revoked bool
	if err := r.pool.QueryRow(ctx, q, jti).Scan(&revoked); err != nil {
		return false, rowNotFound(err, formatOp("revoked_tokens", "is_revoked"))
	}
	return revoked, nil
}

// Get returns a deny-list entry regardless of expiry, for diagnostics and audit.
func (r *RevokedTokenRepo) Get(ctx context.Context, jti string) (*domain.RevokedToken, error) {
	row := r.pool.QueryRow(ctx, `SELECT `+revokedTokenColumns+` FROM revoked_tokens WHERE jti = $1`, jti)
	t, err := scanRevokedToken(row)
	if err != nil {
		return nil, rowNotFound(err, formatOp("revoked_tokens", "get"))
	}
	return t, nil
}

// DeleteExpired removes entries whose denied token has lapsed, one bounded batch.
//
// The only predicate. An entry for a token that can no longer be presented denies
// nothing, so deleting it is always safe, and the index idx_revoked_expires makes
// the batch selection an index scan.
func (r *RevokedTokenRepo) DeleteExpired(ctx context.Context) (int, error) {
	const q = `
		DELETE FROM revoked_tokens
		 WHERE jti IN (
		     SELECT jti FROM revoked_tokens
		      WHERE expires_at < now()
		      LIMIT $1
		 )`

	tag, err := r.pool.Exec(ctx, q, reaperBatch)
	if err != nil {
		return 0, classifyError(err, formatOp("revoked_tokens", "delete_expired"))
	}
	return int(tag.RowsAffected()), nil
}

// Count live entries, for metrics and for asserting the reaper keeps up.
func (r *RevokedTokenRepo) Count(ctx context.Context) (int, error) {
	const q = `SELECT count(*) FROM revoked_tokens WHERE expires_at > now()`
	var n int64
	if err := r.pool.QueryRow(ctx, q).Scan(&n); err != nil {
		return 0, rowNotFound(err, formatOp("revoked_tokens", "count"))
	}
	return int(n), nil
}
