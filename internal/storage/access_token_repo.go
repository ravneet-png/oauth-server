package storage

// Access token record persistence. The row exists so a self-contained JWT can be
// resolved back to its origin for revocation, introspection and audit.

import (
	"context"

	"github.com/jackc/pgx/v5/pgxpool"

	"oauth-server/internal/domain"
)

// AccessTokenRepo reads and writes the issued_access_tokens table.
type AccessTokenRepo struct {
	pool *pgxpool.Pool
}

// NewAccessTokenRepo builds an AccessTokenRepo over pool.
func NewAccessTokenRepo(pool *pgxpool.Pool) *AccessTokenRepo {
	assertPoolNonNil(pool, "AccessTokenRepo")
	return &AccessTokenRepo{pool: pool}
}

const accessTokenColumns = `
	jti, user_id, client_id, session_id, source_auth_code_hash,
	scope, issued_at, expires_at`

func scanAccessToken(row interface{ Scan(...any) error }) (*domain.IssuedAccessToken, error) {
	var (
		t     domain.IssuedAccessToken
		scope []string
	)
	err := row.Scan(
		&t.JTI, &t.UserID, &t.ClientID, &t.SessionID, &t.SourceAuthCodeHash,
		&scope, &t.IssuedAt, &t.ExpiresAt,
	)
	if err != nil {
		return nil, err
	}
	t.Scope = scanStrings(scope)
	return &t, nil
}

// Track records an issued access token.
//
// The record is written for every token, including client_credentials ones that
// have no user and no session. It is cheap insurance: a token whose row was never
// written cannot be revoked, and a resource server that has cached its
// validation will keep accepting it until expiry. Writing the row is what makes
// the deny list complete.
func (r *AccessTokenRepo) Track(ctx context.Context, t *domain.IssuedAccessToken) error {
	const q = `
		INSERT INTO issued_access_tokens (
			jti, user_id, client_id, session_id, source_auth_code_hash,
			scope, issued_at, expires_at
		) VALUES ($1, $2, $3, $4, $5, $6, $7, $8)`

	_, err := r.pool.Exec(ctx, q,
		t.JTI, t.UserID, t.ClientID, t.SessionID, t.SourceAuthCodeHash,
		t.Scope, t.IssuedAt, t.ExpiresAt,
	)
	if err != nil {
		return classifyError(err, formatOp("issued_access_tokens", "track"))
	}
	return nil
}

// GetActiveBySession returns every unexpired token attached to a session.
//
// Scoped logout. Filters on expiry in SQL rather than returning all rows for the
// caller to filter: a session can accumulate thousands of expired tokens over its
// lifetime, and the index idx_issued_tokens_session is a partial index over
// session_id, so this stays cheap. The predicate carries the check so no caller
// can forget it.
func (r *AccessTokenRepo) GetActiveBySession(ctx context.Context, sessionID string) ([]*domain.IssuedAccessToken, error) {
	const q = `SELECT ` + accessTokenColumns + `
		FROM issued_access_tokens
		WHERE session_id = $1
		  AND expires_at > now()
		ORDER BY issued_at`

	return r.queryAccess(ctx, q, sessionID, formatOp("issued_access_tokens", "by_session"))
}

// GetActiveByUserID returns every unexpired token for a user, across all clients
// and sessions. Account-wide revocation and erasure.
func (r *AccessTokenRepo) GetActiveByUserID(ctx context.Context, userID string) ([]*domain.IssuedAccessToken, error) {
	const q = `SELECT ` + accessTokenColumns + `
		FROM issued_access_tokens
		WHERE user_id = $1
		  AND expires_at > now()
		ORDER BY issued_at`

	return r.queryAccess(ctx, q, userID, formatOp("issued_access_tokens", "by_user"))
}

// GetBySourceAuthCode returns every token issued from a given authorization code.
//
// Authorization code reuse detection. The code is re-presented after its tokens
// were already issued, and this finds what must be revoked: RFC 6749 section
// 10.5 and the OAuth 2.1 security BCP both require that a replayed code revoke
// everything descended from the original grant, not just the code itself.
//
// The index idx_issued_tokens_source is partial over source_auth_code_hash, so
// this is an index scan. A nil or empty result is a legitimate answer: a code
// might have been redeemed for a refresh token only, or been revoked before any
// access token was minted.
func (r *AccessTokenRepo) GetBySourceAuthCode(ctx context.Context, codeHash string) ([]*domain.IssuedAccessToken, error) {
	const q = `SELECT ` + accessTokenColumns + `
		FROM issued_access_tokens
		WHERE source_auth_code_hash = $1
		ORDER BY issued_at`

	return r.queryAccess(ctx, q, codeHash, formatOp("issued_access_tokens", "by_source"))
}

// GetByJTI returns one token record regardless of expiry.
func (r *AccessTokenRepo) GetByJTI(ctx context.Context, jti string) (*domain.IssuedAccessToken, error) {
	row := r.pool.QueryRow(ctx, `SELECT `+accessTokenColumns+` FROM issued_access_tokens WHERE jti = $1`, jti)
	t, err := scanAccessToken(row)
	if err != nil {
		return nil, rowNotFound(err, formatOp("issued_access_tokens", "get"))
	}
	return t, nil
}

// DeleteExpired removes expired token records in one bounded batch.
//
// A plain expiry comparison is safe here, unlike for authorization codes: an
// expired access token is not presentable to anyone, and the deny-list entry that
// might still reference it carries its own expiry and is reaped separately. There
// is no reuse-detection evidence to lose, because the jti is the only handle and
// an expired token needs no revocation.
func (r *AccessTokenRepo) DeleteExpired(ctx context.Context) (int, error) {
	const q = `
		DELETE FROM issued_access_tokens
		 WHERE jti IN (
		     SELECT jti FROM issued_access_tokens
		      WHERE expires_at < now()
		      LIMIT $1
		 )`

	tag, err := r.pool.Exec(ctx, q, reaperBatch)
	if err != nil {
		return 0, classifyError(err, formatOp("issued_access_tokens", "delete_expired"))
	}
	return int(tag.RowsAffected()), nil
}

// DetachUser nulls user_id on a user's tokens.
//
// Erasure. ON DELETE SET NULL handles the cascade when the user row goes, but
// erasure also has to fan out back-channel logout BEFORE deleting, and that
// gathering step is easier to reason about when the association is explicitly
// broken. The record survives with a null user, which is what keeps the token
// revocable: an access token that outlives its user must still be deny-listed.
func (r *AccessTokenRepo) DetachUser(ctx context.Context, userID string) (int, error) {
	const q = `UPDATE issued_access_tokens SET user_id = NULL WHERE user_id = $1`
	tag, err := r.pool.Exec(ctx, q, userID)
	if err != nil {
		return 0, classifyError(err, formatOp("issued_access_tokens", "detach_user"))
	}
	return int(tag.RowsAffected()), nil
}

func (r *AccessTokenRepo) queryAccess(ctx context.Context, q string, arg any, op string) ([]*domain.IssuedAccessToken, error) {
	rows, err := r.pool.Query(ctx, q, arg)
	if err != nil {
		return nil, classifyError(err, op)
	}
	defer rows.Close()

	var out []*domain.IssuedAccessToken
	for rows.Next() {
		t, err := scanAccessToken(rows)
		if err != nil {
			return nil, wrapRowsErr(err, op+".scan")
		}
		out = append(out, t)
	}
	if err := rows.Err(); err != nil {
		// Partial results here mean some tokens escape a revocation sweep and stay
		// valid, so this is never downgraded to a warning.
		return nil, wrapRowsErr(err, op+".iterate")
	}
	return out, nil
}
