package storage

// Token family persistence. A family is the lineage of refresh tokens descended
// from one authorization grant, and is what reuse detection revokes.

import (
	"context"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	"oauth-server/internal/domain"
)

// TokenFamilyRepo reads and writes the token_families table.
type TokenFamilyRepo struct {
	pool *pgxpool.Pool
}

// NewTokenFamilyRepo builds a TokenFamilyRepo over pool.
func NewTokenFamilyRepo(pool *pgxpool.Pool) *TokenFamilyRepo {
	assertPoolNonNil(pool, "TokenFamilyRepo")
	return &TokenFamilyRepo{pool: pool}
}

// nolint:gosec // G101 matches on the word "token"; these are column names.
const tokenFamilyColumns = `
	family_id, user_id, client_id, source_auth_code_hash,
	absolute_expires_at, revoked_at, revocation_reason, created_at`

func scanTokenFamily(row interface{ Scan(...any) error }) (*domain.TokenFamily, error) {
	var f domain.TokenFamily
	err := row.Scan(
		&f.FamilyID, &f.UserID, &f.ClientID, &f.SourceAuthCodeHash,
		&f.AbsoluteExpiresAt, &f.RevokedAt, &f.RevocationReason, &f.CreatedAt,
	)
	if err != nil {
		return nil, err
	}
	return &f, nil
}

// Create inserts a family.
//
// The family's absolute_expires_at is the ceiling that stops rotation extending a
// grant forever. It is set at creation, from the client registration's TTL, and
// never recomputed: a client rotating every 29 days against a 30-day refresh TTL
// would otherwise hold one grant open indefinitely, which is exactly what the
// ceiling exists to prevent.
func (r *TokenFamilyRepo) Create(ctx context.Context, f *domain.TokenFamily) error {
	const q = `
		INSERT INTO token_families (
			family_id, user_id, client_id, source_auth_code_hash,
			absolute_expires_at
		) VALUES ($1, $2, $3, $4, $5)`

	_, err := r.pool.Exec(ctx, q,
		f.FamilyID, f.UserID, f.ClientID, f.SourceAuthCodeHash, f.AbsoluteExpiresAt)
	if err != nil {
		return classifyError(err, formatOp("token_families", "create"))
	}
	return nil
}

// Ensure creates the family row if it is absent and leaves an existing one alone.
//
// Both issuance paths mint a family id before they have a row to point at: approve.go
// stamps it on the authorization code, and the authcode exchange stamps it on the
// first refresh token. auth_codes.family_id and refresh_tokens.family_id are both
// foreign keys, so a minted id with no row behind it is not a dangling reference, it
// is a rejected insert. ON CONFLICT DO NOTHING rather than a read-then-write because
// two requests racing on the same family must both succeed.
func (r *TokenFamilyRepo) Ensure(ctx context.Context, f *domain.TokenFamily) error {
	const q = `
		INSERT INTO token_families (
			family_id, user_id, client_id, source_auth_code_hash,
			absolute_expires_at
		) VALUES ($1, $2, $3, $4, $5)
		ON CONFLICT (family_id) DO NOTHING`

	_, err := r.pool.Exec(ctx, q,
		f.FamilyID, f.UserID, f.ClientID, f.SourceAuthCodeHash, f.AbsoluteExpiresAt)
	if err != nil {
		return classifyError(err, formatOp("token_families", "ensure"))
	}
	return nil
}

// GetByID returns the family with the given id, revoked or not.
func (r *TokenFamilyRepo) GetByID(ctx context.Context, familyID string) (*domain.TokenFamily, error) {
	row := r.pool.QueryRow(ctx, `SELECT `+tokenFamilyColumns+` FROM token_families WHERE family_id = $1`, familyID)
	f, err := scanTokenFamily(row)
	if err != nil {
		return nil, rowNotFound(err, formatOp("token_families", "get"))
	}
	return f, nil
}

// Revoke marks a family revoked and returns it, or nil if already revoked.
//
// Same conditional-UPDATE shape as the single-use consumers, for the same
// reason: a caller checking IsRevoked and then writing has a window, and two
// concurrent reuse detections both writing is harmless but two callers both
// believing they were first is how a grace-window decision gets made twice.
func (r *TokenFamilyRepo) Revoke(ctx context.Context, familyID, reason string) (*domain.TokenFamily, error) {
	const q = `
		UPDATE token_families
		   SET revoked_at = now(), revocation_reason = $2
		 WHERE family_id = $1
		   AND revoked_at IS NULL
		RETURNING ` + tokenFamilyColumns

	row := r.pool.QueryRow(ctx, q, familyID, reason)
	f, err := scanTokenFamily(row)
	if err != nil {
		if isNoRows(err) {
			return nil, nil
		}
		return nil, classifyError(err, formatOp("token_families", "revoke"))
	}
	return f, nil
}

// RevokeAllForUser revokes every live family for a user and returns the count.
func (r *TokenFamilyRepo) RevokeAllForUser(ctx context.Context, userID, reason string) (int, error) {
	const q = `
		UPDATE token_families
		   SET revoked_at = now(), revocation_reason = $2
		 WHERE user_id = $1
		   AND revoked_at IS NULL`

	tag, err := r.pool.Exec(ctx, q, userID, reason)
	if err != nil {
		return 0, classifyError(err, formatOp("token_families", "revoke_all_for_user"))
	}
	return int(tag.RowsAffected()), nil
}

// DeleteExpired removes families past their absolute ceiling, one bounded batch.
//
// Only revoked families are eligible. A family past its ceiling but not yet
// revoked may still hold live refresh tokens whose individual idle TTL has not
// lapsed, and deleting the parent cascades them away while the client still
// believes they work. Marking first, reaping second, keeps that from happening.
func (r *TokenFamilyRepo) DeleteExpired(ctx context.Context) (int, error) {
	const q = `
		DELETE FROM token_families
		 WHERE family_id IN (
		     SELECT family_id FROM token_families
		      WHERE absolute_expires_at < now()
		        AND revoked_at IS NOT NULL
		      LIMIT $1
		 )`

	tag, err := r.pool.Exec(ctx, q, reaperBatch)
	if err != nil {
		return 0, classifyError(err, formatOp("token_families", "delete_expired"))
	}
	return int(tag.RowsAffected()), nil
}

// timePtrUnused keeps the time import referenced if the column list changes.
var _ = time.Time{}
