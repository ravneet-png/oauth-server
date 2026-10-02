package storage

// In-flight authorization request persistence. Exists so validated parameters
// survive the redirect chain through login, MFA and consent.

import (
	"context"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	"oauth-server/internal/domain"
)

// AuthRequestRepo reads and writes the auth_requests table.
type AuthRequestRepo struct {
	pool *pgxpool.Pool
}

// NewAuthRequestRepo builds an AuthRequestRepo over pool.
func NewAuthRequestRepo(pool *pgxpool.Pool) *AuthRequestRepo {
	assertPoolNonNil(pool, "AuthRequestRepo")
	return &AuthRequestRepo{pool: pool}
}

const authRequestColumns = `
	id, client_id, redirect_uri, response_type,
	scope, state, nonce, code_challenge, code_challenge_method,
	user_id, session_id, auth_time, params_json,
	expires_at, completed_at, created_at`

func scanAuthRequest(row interface{ Scan(...any) error }) (*domain.AuthRequest, error) {
	var (
		r     domain.AuthRequest
		scope []string
	)
	err := row.Scan(
		&r.ID, &r.ClientID, &r.RedirectURI, &r.ResponseType,
		&scope, &r.State, &r.Nonce, &r.CodeChallenge, &r.CodeChallengeMethod,
		&r.UserID, &r.SessionID, &r.AuthTime, &r.ParamsJSON,
		&r.ExpiresAt, &r.CompletedAt, &r.CreatedAt,
	)
	if err != nil {
		return nil, err
	}
	r.Scope = scanStrings(scope)
	return &r, nil
}

// Create stores a validated authorization request.
//
// The parameter is named req rather than r because r is the receiver on every
// method here; two identifiers called r in one signature is a compile error, and
// renaming the receiver instead would be inconsistent with every other
// repository in this package.
//
// params_json carries the complete validated parameter set rather than a subset
// on columns. The columns are denormalised for indexing only; params_json is the
// authority, so there is exactly one parser for the request.
func (r *AuthRequestRepo) Create(ctx context.Context, req *domain.AuthRequest) error {
	const q = `
		INSERT INTO auth_requests (
			id, client_id, redirect_uri, response_type,
			scope, state, nonce, code_challenge, code_challenge_method,
			user_id, session_id, auth_time, params_json,
			expires_at
		) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13::jsonb, $14)`

	_, err := r.pool.Exec(ctx, q,
		req.ID, req.ClientID, req.RedirectURI, req.ResponseType,
		req.Scope, req.State, req.Nonce, req.CodeChallenge, req.CodeChallengeMethod,
		req.UserID, req.SessionID, req.AuthTime, jsonOrNil(req.ParamsJSON),
		req.ExpiresAt,
	)
	if err != nil {
		return classifyError(err, formatOp("auth_requests", "create"))
	}
	return nil
}

// GetByID returns a request regardless of expiry or completion.
//
// A completed or lapsed request is returned so the caller can derive the correct
// NextStep and produce a meaningful error. Filtering here would make a completed
// request indistinguishable from a missing one, and the double-submitted consent
// form case needs to be told apart from a stale cookie.
func (r *AuthRequestRepo) GetByID(ctx context.Context, id string) (*domain.AuthRequest, error) {
	row := r.pool.QueryRow(ctx, `SELECT `+authRequestColumns+` FROM auth_requests WHERE id = $1`, id)
	r2, err := scanAuthRequest(row)
	if err != nil {
		return nil, rowNotFound(err, formatOp("auth_requests", "get"))
	}
	return r2, nil
}

// SetUserID records that a user has been established for this request, and when
// they authenticated.
//
// auth_time is written in the same statement as the user id, so a request cannot
// end up with a user and no auth_time. That combination is what prompt=none and
// max_age evaluate, and a request missing auth_time would be treated as
// unauthenticated regardless of the user's actual login time.
func (r *AuthRequestRepo) SetUserID(ctx context.Context, id, userID string, authTime time.Time) error {
	const q = `
		UPDATE auth_requests
		   SET user_id = $2, auth_time = $3
		 WHERE id = $1
		   AND completed_at IS NULL`

	return r.execRequestUpdate(ctx, formatOp("auth_requests", "set_user"), q, id, userID, authTime)
}

// SetSessionID attaches a browser session to the request.
func (r *AuthRequestRepo) SetSessionID(ctx context.Context, id, sessionID string) error {
	const q = `
		UPDATE auth_requests
		   SET session_id = $2
		 WHERE id = $1
		   AND completed_at IS NULL`

	return r.execRequestUpdate(ctx, formatOp("auth_requests", "set_session"), q, id, sessionID)
}

// MarkCompleted sets the single-use marker and returns whether this call was the
// one that set it.
//
// The guard completed_at IS NULL is what stops a double-submitted consent form
// minting two authorization codes from one request. Without it both submissions
// succeed and the client receives two codes for a single user approval, one of
// which will sit unused and the other of which is a live credential the user never
// intended to issue twice.
//
// The boolean is what lets the caller branch. Returning only an error would force
// the loser of the race to discover the conflict by re-reading, which races again.
func (r *AuthRequestRepo) MarkCompleted(ctx context.Context, id string) (bool, error) {
	const q = `
		UPDATE auth_requests
		   SET completed_at = now()
		 WHERE id = $1
		   AND completed_at IS NULL`

	tag, err := r.pool.Exec(ctx, q, id)
	if err != nil {
		return false, classifyError(err, formatOp("auth_requests", "complete"))
	}
	if tag.RowsAffected() == 0 {
		// Either already completed or unknown. The caller treats both as "do not
		// issue a code", which is the safe direction.
		return false, nil
	}
	return true, nil
}

// DeleteExpired removes lapsed requests in one bounded batch.
//
// Eligible on expiry alone, and completed rows are eligible too: a completed
// request has served its purpose and holding it only delays the next login's
// params_json write from reusing the space. An incomplete-but-live request is not
// touched, because a user who left a login tab open must still be able to finish.
func (r *AuthRequestRepo) DeleteExpired(ctx context.Context) (int, error) {
	const q = `
		DELETE FROM auth_requests
		 WHERE id IN (
		     SELECT id FROM auth_requests
		      WHERE expires_at < now()
		      LIMIT $1
		 )`

	tag, err := r.pool.Exec(ctx, q, reaperBatch)
	if err != nil {
		return 0, classifyError(err, formatOp("auth_requests", "delete_expired"))
	}
	return int(tag.RowsAffected()), nil
}

func (r *AuthRequestRepo) execRequestUpdate(ctx context.Context, op, q string, args ...any) error {
	tag, err := r.pool.Exec(ctx, q, args...)
	if err != nil {
		return classifyError(err, op)
	}
	if tag.RowsAffected() == 0 {
		return notFound(op)
	}
	return nil
}
