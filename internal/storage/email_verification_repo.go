package storage

// Email verification token persistence. Tokens are single-use and bound to the
// address being claimed, not the one already on the account.

import (
	"context"

	"github.com/jackc/pgx/v5/pgxpool"

	"oauth-server/internal/domain"
)

// EmailVerificationRepo reads and writes the email_verifications table.
type EmailVerificationRepo struct {
	pool *pgxpool.Pool
}

// NewEmailVerificationRepo builds an EmailVerificationRepo over pool.
func NewEmailVerificationRepo(pool *pgxpool.Pool) *EmailVerificationRepo {
	assertPoolNonNil(pool, "EmailVerificationRepo")
	return &EmailVerificationRepo{pool: pool}
}

const emailVerificationColumns = `
	token_hash, user_id, purpose, target_email,
	expires_at, used_at, attempt_count, created_at`

func scanEmailVerification(row interface{ Scan(...any) error }) (*domain.EmailVerification, error) {
	var v domain.EmailVerification
	err := row.Scan(
		&v.TokenHash, &v.UserID, &v.Purpose, &v.TargetEmail,
		&v.ExpiresAt, &v.UsedAt, &v.AttemptCount, &v.CreatedAt,
	)
	if err != nil {
		return nil, err
	}
	return &v, nil
}

// Create stores a verification token.
//
// target_email must already be normalised by the caller; it is stored lower case
// so the idx_email_verif_email index on lower(target_email) can find it. The
// lookup side is where the lower() is applied again, so normalisation here is
// about the stored value being canonical rather than about the query working.
func (r *EmailVerificationRepo) Create(ctx context.Context, v *domain.EmailVerification) error {
	const q = `
		INSERT INTO email_verifications (token_hash, user_id, purpose, target_email, expires_at)
		VALUES ($1, $2, $3, $4, $5)`

	_, err := r.pool.Exec(ctx, q, v.TokenHash, v.UserID, v.Purpose, v.TargetEmail, v.ExpiresAt)
	if err != nil {
		return classifyError(err, formatOp("email_verifications", "create"))
	}
	return nil
}

// GetByHash returns the token with the given digest, used or not.
//
// Used rows are returned so a caller can tell "already verified" from "never
// issued", which is the difference between a helpful message and a user clicking
// the link again and being told nothing happened.
func (r *EmailVerificationRepo) GetByHash(ctx context.Context, hash string) (*domain.EmailVerification, error) {
	row := r.pool.QueryRow(ctx,
		`SELECT `+emailVerificationColumns+` FROM email_verifications WHERE token_hash = $1`, hash)
	v, err := scanEmailVerification(row)
	if err != nil {
		return nil, rowNotFound(err, formatOp("email_verifications", "get_by_hash"))
	}
	return v, nil
}

// GetActiveByEmail returns the live token for an address and purpose.
//
// purpose is part of the lookup, not a post-filter. A signup token and a
// password-reset token for the same address are different credentials with
// different consequences, and returning the wrong one because the query ignored
// purpose is how a signup link ends up resetting a password.
func (r *EmailVerificationRepo) GetActiveByEmail(ctx context.Context, email, purpose string) (*domain.EmailVerification, error) {
	const q = `SELECT ` + emailVerificationColumns + `
		FROM email_verifications
		WHERE lower(target_email) = lower($1)
		  AND purpose = $2
		  AND used_at IS NULL
		  AND expires_at > now()
		ORDER BY created_at DESC
		LIMIT 1`

	row := r.pool.QueryRow(ctx, q, email, purpose)
	v, err := scanEmailVerification(row)
	if err != nil {
		if isNoRows(err) {
			return nil, nil
		}
		return nil, classifyError(err, formatOp("email_verifications", "by_email"))
	}
	return v, nil
}

// MarkUsed consumes the token and returns whether this call was the one that did.
//
// The completed pattern again: guarded on used_at IS NULL, returning a boolean so
// the caller can branch without a racy re-read. Two concurrent submissions of the
// same verification link must verify the address once, not twice, and the second
// must be told the link was already used.
func (r *EmailVerificationRepo) MarkUsed(ctx context.Context, hash string) (bool, error) {
	const q = `
		UPDATE email_verifications
		   SET used_at = now()
		 WHERE token_hash = $1
		   AND used_at IS NULL
		   AND expires_at > now()`

	tag, err := r.pool.Exec(ctx, q, hash)
	if err != nil {
		return false, classifyError(err, formatOp("email_verifications", "mark_used"))
	}
	return tag.RowsAffected() > 0, nil
}

// IncrementAttempt records a failed submission against a token.
//
// One statement rather than "read then write", because the read-then-write version
// is a lost update: twenty parallel guesses all read attempt_count = 0, all
// believe they are within the limit, and all twenty are accepted. The bound then
// bounds nothing, which is the entire purpose of attempt_count for a 6-digit code
// that an attacker can spread across many source addresses to stay under a global
// rate limit.
func (r *EmailVerificationRepo) IncrementAttempt(ctx context.Context, hash string) (int, error) {
	const q = `
		UPDATE email_verifications
		   SET attempt_count = attempt_count + 1
		 WHERE token_hash = $1
		   AND used_at IS NULL
		RETURNING attempt_count`

	var count int
	if err := r.pool.QueryRow(ctx, q, hash).Scan(&count); err != nil {
		return 0, rowNotFound(err, formatOp("email_verifications", "increment_attempt"))
	}
	return count, nil
}

// DeleteExpired removes lapsed tokens in one bounded batch.
func (r *EmailVerificationRepo) DeleteExpired(ctx context.Context) (int, error) {
	const q = `
		DELETE FROM email_verifications
		 WHERE token_hash IN (
		     SELECT token_hash FROM email_verifications
		      WHERE expires_at < now()
		      LIMIT $1
		 )`

	tag, err := r.pool.Exec(ctx, q, reaperBatch)
	if err != nil {
		return 0, classifyError(err, formatOp("email_verifications", "delete_expired"))
	}
	return int(tag.RowsAffected()), nil
}

// DeleteForUser removes every outstanding token for a user, for erasure.
func (r *EmailVerificationRepo) DeleteForUser(ctx context.Context, userID string) (int, error) {
	const q = `DELETE FROM email_verifications WHERE user_id = $1`
	tag, err := r.pool.Exec(ctx, q, userID)
	if err != nil {
		return 0, classifyError(err, formatOp("email_verifications", "delete_for_user"))
	}
	return int(tag.RowsAffected()), nil
}
