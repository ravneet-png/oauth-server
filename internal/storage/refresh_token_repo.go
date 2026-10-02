package storage

// Refresh token persistence.
//
// Rotation is a single conditional UPDATE, and the distinction between
// "rotated" and every other revocation reason is what keeps a benign concurrent
// refresh from being read as theft.

import (
	"context"

	"github.com/jackc/pgx/v5/pgxpool"

	"oauth-server/internal/domain"
)

// RefreshTokenRepo reads and writes the refresh_tokens table.
type RefreshTokenRepo struct {
	pool *pgxpool.Pool
}

// NewRefreshTokenRepo builds a RefreshTokenRepo over pool.
func NewRefreshTokenRepo(pool *pgxpool.Pool) *RefreshTokenRepo {
	assertPoolNonNil(pool, "RefreshTokenRepo")
	return &RefreshTokenRepo{pool: pool}
}

// nolint:gosec // G101 matches on the word "token"; these are column names.
const refreshTokenColumns = `
	token_hash, family_id, client_id, user_id, session_id,
	source_auth_code_hash, replaced_by_hash,
	scope, expires_at, revoked_at, revocation_reason, created_at`

func scanRefreshToken(row interface{ Scan(...any) error }) (*domain.RefreshToken, error) {
	var (
		t     domain.RefreshToken
		scope []string
	)
	err := row.Scan(
		&t.TokenHash, &t.FamilyID, &t.ClientID, &t.UserID, &t.SessionID,
		&t.SourceAuthCodeHash, &t.ReplacedByHash,
		&scope, &t.ExpiresAt, &t.RevokedAt, &t.RevocationReason, &t.CreatedAt,
	)
	if err != nil {
		return nil, err
	}
	t.Scope = scanStrings(scope)
	return &t, nil
}

// Create inserts a refresh token.
func (r *RefreshTokenRepo) Create(ctx context.Context, t *domain.RefreshToken) error {
	const q = `
		INSERT INTO refresh_tokens (
			token_hash, family_id, client_id, user_id, session_id,
			source_auth_code_hash, replaced_by_hash,
			scope, expires_at
		) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)`

	_, err := r.pool.Exec(ctx, q,
		t.TokenHash, t.FamilyID, t.ClientID, t.UserID, t.SessionID,
		t.SourceAuthCodeHash, t.ReplacedByHash,
		t.Scope, t.ExpiresAt,
	)
	if err != nil {
		return classifyError(err, formatOp("refresh_tokens", "create"))
	}
	return nil
}

// GetByHash returns the token with the given digest, revoked or not.
//
// As with authorization codes, revoked rows are returned on purpose. Reuse
// detection reads a revoked token to discover its family, and
// domain.RefreshToken.WasRotated is what separates a stolen token being replayed
// from a token the user deliberately revoked. A repository that filtered on
// revoked_at would make both look like an unknown token, and the reuse cascade
// would never fire.
func (r *RefreshTokenRepo) GetByHash(ctx context.Context, hash string) (*domain.RefreshToken, error) {
	row := r.pool.QueryRow(ctx, `SELECT `+refreshTokenColumns+` FROM refresh_tokens WHERE token_hash = $1`, hash)
	t, err := scanRefreshToken(row)
	if err != nil {
		return nil, rowNotFound(err, formatOp("refresh_tokens", "get_by_hash"))
	}
	return t, nil
}

// AtomicRotate revokes the presented token and returns it, or nil if it was
// already revoked.
//
//	UPDATE ... SET revoked_at = now(), revocation_reason = 'rotated'
//	 WHERE token_hash = $1 AND revoked_at IS NULL
//	 RETURNING ...
//
// Same three properties as AtomicMarkUsed, and for the same reasons:
//
//  1. revoked_at IS NULL in the predicate, not a preceding SELECT. Two concurrent
//     refreshes presenting the same token must produce exactly one success; with
//     a read-then-write both see an unrevoked row and both proceed, and the
//     client ends up with two descendants of one grant.
//
//  2. revocation_reason is set to 'rotated' in the same statement. The schema
//     CHECK requires revoked_at and revocation_reason to agree, and a write that
//     set only the timestamp would be rejected. More importantly the reason is
//     the input to the reuse decision, so it cannot be left to a later statement
//     that might not run.
//
//  3. Nil with a nil error means already revoked. The caller must then consult
//     GetByHash to learn whether it was rotated, and if so cascade a family
//     revocation. A caller that treats nil as an ordinary invalid_grant without
//     checking is a server that silently tolerates token theft.
//
// The prompt's text says "revoked=false"; this schema has no such column, for the
// same drift reason as auth_codes.used. Expiry is likewise not in the predicate,
// so the caller can distinguish an expired token from a replayed one and audit
// them differently.
func (r *RefreshTokenRepo) AtomicRotate(ctx context.Context, hash string) (*domain.RefreshToken, error) {
	const q = `
		UPDATE refresh_tokens
		   SET revoked_at = now(), revocation_reason = $2
		 WHERE token_hash = $1
		   AND revoked_at IS NULL
		RETURNING ` + refreshTokenColumns

	row := r.pool.QueryRow(ctx, q, hash, domain.RevocationReasonRotated)
	t, err := scanRefreshToken(row)
	if err != nil {
		// Zero rows is the replay case. Any other error is a genuine failure
		// and must not be reported as an ordinary invalid_grant, or token
		// theft detection is silently skipped exactly when the database is
		// unhealthy.
		if isNoRows(err) {
			return nil, nil
		}
		return nil, classifyError(err, formatOp("refresh_tokens", "rotate"))
	}
	return t, nil
}

// RevokeFamily revokes every live token in a family and returns the count.
//
// Used by reuse detection and by erasure. It marks only tokens that are not
// already revoked, so a token revoked as 'rotated' keeps that reason: the count
// therefore reflects what this call actually changed, which is what an
// operational query needs.
//
// The reason is passed in rather than fixed, because the two callers mean
// different things: a replay is 'reuse_cascade' and is evidence of compromise,
// while erasure is 'gdpr' and is a user's own request. Collapsing them would make
// the audit trail unable to say why a family died.
func (r *RefreshTokenRepo) RevokeFamily(ctx context.Context, familyID, reason string) (int, error) {
	const q = `
		UPDATE refresh_tokens
		   SET revoked_at = now(), revocation_reason = $2
		 WHERE family_id = $1
		   AND revoked_at IS NULL`

	tag, err := r.pool.Exec(ctx, q, familyID, reason)
	if err != nil {
		return 0, classifyError(err, formatOp("refresh_tokens", "revoke_family"))
	}
	return int(tag.RowsAffected()), nil
}

// RevokeBySession revokes every live token attached to a browser session.
//
// Scoped logout. The partial index idx_refresh_session covers session_id, so this
// is an index scan. A client_credentials token has a NULL session_id and is
// therefore untouched, which is correct: it has no browser session to log out
// of, and killing it on a human's logout would break machine access.
func (r *RefreshTokenRepo) RevokeBySession(ctx context.Context, sessionID, reason string) (int, error) {
	const q = `
		UPDATE refresh_tokens
		   SET revoked_at = now(), revocation_reason = $2
		 WHERE session_id = $1
		   AND revoked_at IS NULL`

	tag, err := r.pool.Exec(ctx, q, sessionID, reason)
	if err != nil {
		return 0, classifyError(err, formatOp("refresh_tokens", "revoke_by_session"))
	}
	return int(tag.RowsAffected()), nil
}

// RevokeAllForUser revokes every live token for a user, across all clients and
// sessions.
//
// The account-wide "sign out everywhere" and the erasure path. Deliberately not
// scoped by client: a user asking to be signed out of their own account means
// every device, and a client-scoped version would leave a token alive on a device
// nobody remembered to include.
func (r *RefreshTokenRepo) RevokeAllForUser(ctx context.Context, userID, reason string) (int, error) {
	const q = `
		UPDATE refresh_tokens
		   SET revoked_at = now(), revocation_reason = $2
		 WHERE user_id = $1
		   AND revoked_at IS NULL`

	tag, err := r.pool.Exec(ctx, q, userID, reason)
	if err != nil {
		return 0, classifyError(err, formatOp("refresh_tokens", "revoke_all_for_user"))
	}
	return int(tag.RowsAffected()), nil
}

// SetReplacedByHash links a rotated token to its successor.
//
// The grace window: a client that fires two refreshes concurrently gets one
// success and one ErrAlreadyConsumed, and this link is what lets the server tell
// that benign case apart from an attacker replaying a stolen token. Without it,
// every concurrent refresh looks like theft and cascades a family revocation, so a
// user with a flaky mobile network signs themselves out constantly.
func (r *RefreshTokenRepo) SetReplacedByHash(ctx context.Context, oldHash, newHash string) error {
	const q = `
		UPDATE refresh_tokens
		   SET replaced_by_hash = $2
		 WHERE token_hash = $1
		   AND revoked_at IS NOT NULL
		   AND revocation_reason = $3`

	tag, err := r.pool.Exec(ctx, q, oldHash, newHash, domain.RevocationReasonRotated)
	if err != nil {
		return classifyError(err, formatOp("refresh_tokens", "set_replaced_by"))
	}
	if tag.RowsAffected() == 0 {
		return notFound(formatOp("refresh_tokens", "set_replaced_by"))
	}
	return nil
}

// DeleteExpired removes expired tokens in one bounded batch and returns the count.
//
// Only rows that are both expired and revoked are eligible. An expired but
// unrevoked token is still evidence: it is what proves a family existed and when
// it died, and deleting it early means a later replay finds nothing and the
// reuse cascade has no family to revoke.
func (r *RefreshTokenRepo) DeleteExpired(ctx context.Context) (int, error) {
	const q = `
		DELETE FROM refresh_tokens
		 WHERE token_hash IN (
		     SELECT token_hash FROM refresh_tokens
		      WHERE expires_at < now()
		        AND revoked_at IS NOT NULL
		      LIMIT $1
		 )`

	tag, err := r.pool.Exec(ctx, q, reaperBatch)
	if err != nil {
		return 0, classifyError(err, formatOp("refresh_tokens", "delete_expired"))
	}
	return int(tag.RowsAffected()), nil
}

// DeleteFamily removes a family and its tokens outright, for erasure.
//
// Distinct from RevokeFamily: that keeps the rows as evidence with a revocation
// marker, this destroys them. A caller must be certain the family is being
// retired permanently, since the reuse cascade loses its anchor afterwards.
func (r *RefreshTokenRepo) DeleteFamily(ctx context.Context, familyID string) (int, error) {
	const q = `DELETE FROM refresh_tokens WHERE family_id = $1`
	tag, err := r.pool.Exec(ctx, q, familyID)
	if err != nil {
		return 0, classifyError(err, formatOp("refresh_tokens", "delete_family"))
	}
	return int(tag.RowsAffected()), nil
}
