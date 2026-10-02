package storage

// Pushed authorization request persistence. The request_uri is a bearer
// credential for the request itself, so it is single-use and short-lived.

import (
	"context"

	"github.com/jackc/pgx/v5/pgxpool"

	"oauth-server/internal/domain"
)

// PARRepo reads and writes the par_requests table.
type PARRepo struct {
	pool *pgxpool.Pool
}

// NewPARRepo builds a PARRepo over pool.
func NewPARRepo(pool *pgxpool.Pool) *PARRepo {
	assertPoolNonNil(pool, "PARRepo")
	return &PARRepo{pool: pool}
}

const parColumns = `request_uri, client_id, params_json, expires_at, consumed_at, created_at`

func scanPAR(row interface{ Scan(...any) error }) (*domain.PARRequest, error) {
	var p domain.PARRequest
	err := row.Scan(
		&p.RequestURI, &p.ClientID, &p.ParamsJSON,
		&p.ExpiresAt, &p.ConsumedAt, &p.CreatedAt,
	)
	if err != nil {
		return nil, err
	}
	return &p, nil
}

// Create stores a pushed authorization request.
//
// The schema's par_requests_params_chk refuses to store client credentials inside
// params_json, because the request_uri is handed to a browser and the row would
// otherwise hold a secret in a table the reaper only clears on expiry. A
// violation there is a programming error in the caller and surfaces as ErrConflict
// with the constraint name.
func (r *PARRepo) Create(ctx context.Context, p *domain.PARRequest) error {
	const q = `
		INSERT INTO par_requests (request_uri, client_id, params_json, expires_at)
		VALUES ($1, $2, $3::jsonb, $4)`

	_, err := r.pool.Exec(ctx, q, p.RequestURI, p.ClientID, jsonOrNil(p.ParamsJSON), p.ExpiresAt)
	if err != nil {
		return classifyError(err, formatOp("par_requests", "create"))
	}
	return nil
}

// GetAndDelete consumes a request atomically, returning it, or nil if it was
// already consumed, unknown, or expired.
//
// One conditional UPDATE ... RETURNING guarded on consumed_at IS NULL, rather
// than a DELETE whose row count the caller inspects. The difference is
// concurrency: a plain DELETE returns zero rows for the loser of the race, and
// then the winner's row is gone before the loser can read it, so the loser learns
// nothing and cannot tell a replay from a first presentation. With
// UPDATE ... RETURNING the loser gets nil, which is the correct answer, and the
// winner gets the payload from the same statement that consumed it.
//
// This is the single-use guarantee of RFC 9126. Without it the request_uri stays
// replayable for its whole lifetime, and an attacker who observes one in a
// browser can start an authorization with the victim's parameters.
//
// Expiry is in the predicate. A PAR is worthless once it lapses and, unlike an
// authorization code, carries no evidence a later replay would need: the
// distinction between "expired" and "already used" is not operationally useful
// here, and enforcing it in the database means no caller can forget.
func (r *PARRepo) GetAndDelete(ctx context.Context, requestURI string) (*domain.PARRequest, error) {
	const q = `
		UPDATE par_requests
		   SET consumed_at = now()
		 WHERE request_uri = $1
		   AND consumed_at IS NULL
		   AND expires_at > now()
		RETURNING ` + parColumns

	row := r.pool.QueryRow(ctx, q, requestURI)
	p, err := scanPAR(row)
	if err != nil {
		// Zero rows: unknown, already consumed, or expired. All three are the same
		// answer to the caller, which must not be able to tell them apart. A
		// connection failure is not: reporting it as "not found" would look like
		// a bad request_uri to the client instead of a server fault.
		if isNoRows(err) {
			return nil, nil
		}
		return nil, classifyError(err, formatOp("par_requests", "consume"))
	}
	return p, nil
}

// ClientIDFor reads the client_id of an unconsumed, unexpired request without
// consuming it.
//
// Read-only on purpose, and only for pre-consumption validation. The /authorize path
// needs to compare a client_id supplied next to a request_uri against the one the
// request was pushed under, and doing that after GetAndDelete would mean the check runs
// on a value already spent — the client would have to push again because of a
// malformed request it cannot fix, and any mismatch the check was meant to catch would
// arrive too late to prevent the consumption.
//
// Returns the empty string when the request_uri is unknown, consumed or expired, which
// is indistinguishable by design: those three must be one answer to the client.
func (r *PARRepo) ClientIDFor(ctx context.Context, requestURI string) (string, error) {
	const q = `
		SELECT client_id
		  FROM par_requests
		 WHERE request_uri = $1
		   AND consumed_at IS NULL
		   AND expires_at > now()`

	var clientID string
	if err := r.pool.QueryRow(ctx, q, requestURI).Scan(&clientID); err != nil {
		if isNoRows(err) {
			return "", nil
		}
		return "", classifyError(err, formatOp("par_requests", "client_id_for"))
	}
	return clientID, nil
}

// DeleteExpired removes lapsed requests in one bounded batch.
func (r *PARRepo) DeleteExpired(ctx context.Context) (int, error) {
	const q = `
		DELETE FROM par_requests
		 WHERE request_uri IN (
		     SELECT request_uri FROM par_requests
		      WHERE expires_at < now()
		      LIMIT $1
		 )`

	tag, err := r.pool.Exec(ctx, q, reaperBatch)
	if err != nil {
		return 0, classifyError(err, formatOp("par_requests", "delete_expired"))
	}
	return int(tag.RowsAffected()), nil
}
