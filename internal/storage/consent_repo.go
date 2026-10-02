package storage

// Consent persistence. A grant is a standing set of scopes, compared by
// containment so that narrowing a request does not re-prompt.

import (
	"context"

	"github.com/jackc/pgx/v5/pgxpool"

	"oauth-server/internal/domain"
)

// ConsentRepo reads and writes the consents table.
type ConsentRepo struct {
	pool *pgxpool.Pool
}

// NewConsentRepo builds a ConsentRepo over pool.
func NewConsentRepo(pool *pgxpool.Pool) *ConsentRepo {
	assertPoolNonNil(pool, "ConsentRepo")
	return &ConsentRepo{pool: pool}
}

const consentColumns = `user_id, client_id, scopes, granted_at, last_used_at, expires_at`

func scanConsent(row interface{ Scan(...any) error }) (*domain.Consent, error) {
	var (
		c      domain.Consent
		scopes []string
	)
	if err := row.Scan(&c.UserID, &c.ClientID, &scopes, &c.GrantedAt, &c.LastUsedAt, &c.ExpiresAt); err != nil {
		return nil, err
	}
	c.Scopes = scanStrings(scopes)
	return &c, nil
}

// Get returns the consent for this user and client.
//
// A lapsed grant is returned, not hidden, so the caller can distinguish "never
// consented" from "consented and it expired" and re-prompt with an explanation.
// domain.Consent.IsActive is the check that decides whether the grant is
// currently sufficient; filtering on expires_at in SQL would make those two cases
// indistinguishable and turn every expiry into a first-time consent screen.
//
// A nil consent with a nil error is the normal "no grant" case, not an error.
// Consent absence is an expected outcome on the majority of first visits, and
// making it an error would put a sentinel check on every authorization request.
func (r *ConsentRepo) Get(ctx context.Context, userID, clientID string) (*domain.Consent, error) {
	row := r.pool.QueryRow(ctx,
		`SELECT `+consentColumns+` FROM consents WHERE user_id = $1 AND client_id = $2`,
		userID, clientID)

	c, err := scanConsent(row)
	if err != nil {
		// No row is not an error. Distinguishing it from a real failure requires
		// checking for the driver's no-rows condition, which is what the sentinel
		// does. A consent miss is a normal "not yet granted" answer on the
		// authorization path, not a 500.
		if isNoRows(err) {
			return nil, nil
		}
		return nil, classifyError(err, formatOp("consents", "get"))
	}
	return c, nil
}

// Upsert writes a consent, replacing any existing grant for the pair.
//
// ON CONFLICT (user_id, client_id) DO UPDATE, replacing scopes wholesale.
//
// Wholesale replacement rather than a set union is the security-relevant choice. A
// union would mean a user's grant could only ever grow, so a client that once
// received `email` and `profile` would keep both for ever even after the consent
// screen showed a reduced set. Replacement means what the user last agreed to is
// exactly what is stored.
//
// granted_at is reset on update for the same reason: a grant that is re-affirmed
// is a new grant, and "last used" ordering on a revocation screen depends on the
// granted_at being honest.
func (r *ConsentRepo) Upsert(ctx context.Context, c *domain.Consent) error {
	const q = `
		INSERT INTO consents (user_id, client_id, scopes, granted_at, last_used_at, expires_at)
		VALUES ($1, $2, $3, COALESCE($4, now()), $5, $6)
		ON CONFLICT (user_id, client_id)
		DO UPDATE SET scopes = EXCLUDED.scopes,
		              granted_at = EXCLUDED.granted_at,
		              last_used_at = EXCLUDED.last_used_at,
		              expires_at = EXCLUDED.expires_at`

	_, err := r.pool.Exec(ctx, q, c.UserID, c.ClientID, c.Scopes, c.GrantedAt, c.LastUsedAt, c.ExpiresAt)
	if err != nil {
		return classifyError(err, formatOp("consents", "upsert"))
	}
	return nil
}

// TouchLastUsed records that this grant authorised a request.
//
// last_used_at is the signal a "revoke this app" screen sorts by, and the input
// to an inactivity-based revocation prompt. It is deliberately not granted_at: a
// grant the user still relies on every day is not stale, and re-prompting them for
// it trains them to click through the screen, which is the habit a malicious
// client wants.
func (r *ConsentRepo) TouchLastUsed(ctx context.Context, userID, clientID string) error {
	const q = `
		UPDATE consents
		   SET last_used_at = now()
		 WHERE user_id = $1 AND client_id = $2`

	tag, err := r.pool.Exec(ctx, q, userID, clientID)
	if err != nil {
		return classifyError(err, formatOp("consents", "touch"))
	}
	if tag.RowsAffected() == 0 {
		return notFound(formatOp("consents", "touch"))
	}
	return nil
}

// DeleteAllForUser revokes every consent a user has granted.
//
// Part of erasure, and deliberately the whole set rather than per-client: a user
// asking for their data to be removed does not consent to leaving standing
// grants behind for a client to keep exercising.
func (r *ConsentRepo) DeleteAllForUser(ctx context.Context, userID string) error {
	_, err := r.pool.Exec(ctx, `DELETE FROM consents WHERE user_id = $1`, userID)
	if err != nil {
		return classifyError(err, formatOp("consents", "delete_all_for_user"))
	}
	return nil
}

// Delete removes one consent grant. The "revoke this app" path.
func (r *ConsentRepo) Delete(ctx context.Context, userID, clientID string) error {
	tag, err := r.pool.Exec(ctx,
		`DELETE FROM consents WHERE user_id = $1 AND client_id = $2`, userID, clientID)
	if err != nil {
		return classifyError(err, formatOp("consents", "delete"))
	}
	if tag.RowsAffected() == 0 {
		return notFound(formatOp("consents", "delete"))
	}
	return nil
}

// ListForUser returns every consent a user has granted, most recently used first.
func (r *ConsentRepo) ListForUser(ctx context.Context, userID string) ([]*domain.Consent, error) {
	const q = `SELECT ` + consentColumns + `
		FROM consents
		WHERE user_id = $1
		ORDER BY COALESCE(last_used_at, granted_at) DESC`

	rows, err := r.pool.Query(ctx, q, userID)
	if err != nil {
		return nil, classifyError(err, formatOp("consents", "list"))
	}
	defer rows.Close()

	var out []*domain.Consent
	for rows.Next() {
		c, err := scanConsent(rows)
		if err != nil {
			return nil, wrapRowsErr(err, formatOp("consents", "list", "scan"))
		}
		out = append(out, c)
	}
	if err := rows.Err(); err != nil {
		return nil, wrapRowsErr(err, formatOp("consents", "list", "iterate"))
	}
	return out, nil
}
