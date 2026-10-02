package storage

// Client-to-session attachment persistence. The sid here is what appears in ID
// tokens and back-channel LogoutTokens, so its unguessability is a security
// property of this repository.

import (
	"context"

	"github.com/jackc/pgx/v5/pgxpool"

	"oauth-server/internal/domain"
)

// ClientSessionRepo reads and writes the client_sessions table.
type ClientSessionRepo struct {
	pool *pgxpool.Pool
}

// NewClientSessionRepo builds a ClientSessionRepo over pool.
func NewClientSessionRepo(pool *pgxpool.Pool) *ClientSessionRepo {
	assertPoolNonNil(pool, "ClientSessionRepo")
	return &ClientSessionRepo{pool: pool}
}

const clientSessionColumns = `sid, session_id, client_id, created_at`

func scanClientSession(row interface{ Scan(...any) error }) (*domain.ClientSession, error) {
	var cs domain.ClientSession
	if err := row.Scan(&cs.SID, &cs.SessionID, &cs.ClientID, &cs.CreatedAt); err != nil {
		return nil, err
	}
	return &cs, nil
}

// Upsert attaches a client to a session, or refreshes the existing attachment.
//
// ON CONFLICT (session_id, client_id) DO UPDATE, keyed on the unique constraint
// rather than on the sid primary key. That distinction is the whole point: the
// prompt's wording would suggest conflicting on the sid, but a repeat
// authorization for the same client and session generates a NEW sid, so
// conflicting on sid would insert a second row and the session would accumulate
// one attachment per authorization. Conflicting on (session_id, client_id) means
// the later sid replaces the earlier one, which is correct: the most recent
// authorization is the live one, and a client holding a stale sid is logging out a
// session that has already been superseded.
//
// DO UPDATE rather than DO NOTHING, because the sid must be refreshed to the new
// value. With DO NOTHING the insert would be silently skipped and the client would
// keep a sid that the server no longer recognises.
func (r *ClientSessionRepo) Upsert(ctx context.Context, cs *domain.ClientSession) error {
	const q = `
		INSERT INTO client_sessions (sid, session_id, client_id)
		VALUES ($1, $2, $3)
		ON CONFLICT (session_id, client_id)
		DO UPDATE SET sid = EXCLUDED.sid`

	_, err := r.pool.Exec(ctx, q, cs.SID, cs.SessionID, cs.ClientID)
	if err != nil {
		return classifyError(err, formatOp("client_sessions", "upsert"))
	}
	return nil
}

// GetBySessionID returns every client attached to a session.
//
// This is the query scoped logout and back-channel logout fan-out both need: the
// set of RPs that hold a sid for this session, and therefore the set that must be
// told the session ended.
//
// Ordered by client_id for a deterministic fan-out order. A logout broadcast that
// visits RPs in a different order on each run is harder to diagnose from RPs' own
// logs, and a caller that stops early on error behaves differently run to run.
func (r *ClientSessionRepo) GetBySessionID(ctx context.Context, sessionID string) ([]*domain.ClientSession, error) {
	const q = `SELECT ` + clientSessionColumns + `
		FROM client_sessions
		WHERE session_id = $1
		ORDER BY client_id`

	return r.query(ctx, q, sessionID, formatOp("client_sessions", "by_session"))
}

// GetByUserID returns every client attachment across all of a user's sessions.
//
// Requires a join through sessions, because client_sessions deliberately does not
// store user_id. The denormalised copy was removed in Prompt 2 for a specific
// reason: erasure gathers rows by user_id to fan out back-channel logout, and a
// stale copy means no logout is sent, so a client keeps believing a deleted user
// is still signed in. This query is the cost of that decision, and it is a join
// against an indexed column rather than a second source of truth to keep in sync.
//
// The column list is spelled out inline rather than reusing clientSessionColumns,
// because that constant is unqualified and this query joins two tables: reusing it
// would make `session_id` and `created_at` ambiguous and PostgreSQL would reject
// the statement at runtime.
func (r *ClientSessionRepo) GetByUserID(ctx context.Context, userID string) ([]*domain.ClientSession, error) {
	const q = `SELECT ` + `cs.sid, cs.session_id, cs.client_id, cs.created_at` + `
		FROM client_sessions cs
		JOIN sessions s ON s.session_id = cs.session_id
		WHERE s.user_id = $1
		ORDER BY cs.client_id`

	return r.query(ctx, q, userID, formatOp("client_sessions", "by_user"))
}

// GetBySID returns a single attachment by its sid.
//
// Back-channel logout: the LogoutToken carries a sid, and this resolves it to the
// session it belongs to. The lookup is by primary key and must therefore not
// confirm that the session is still live: a logout token is frequently delivered
// after the session row is gone, and refusing to act then would leave the client
// believing the user is still signed in, which is the failure this whole
// mechanism exists to prevent.
func (r *ClientSessionRepo) GetBySID(ctx context.Context, sid string) (*domain.ClientSession, error) {
	row := r.pool.QueryRow(ctx, `SELECT `+clientSessionColumns+` FROM client_sessions WHERE sid = $1`, sid)
	cs, err := scanClientSession(row)
	if err != nil {
		return nil, rowNotFound(err, formatOp("client_sessions", "get_by_sid"))
	}
	return cs, nil
}

// DeleteBySessionID removes every attachment for a session and returns the count.
// Scoped logout: a client may be told about a logout for one session while
// keeping its attachment to a different one.
func (r *ClientSessionRepo) DeleteBySessionID(ctx context.Context, sessionID string) (int, error) {
	const q = `DELETE FROM client_sessions WHERE session_id = $1`
	tag, err := r.pool.Exec(ctx, q, sessionID)
	if err != nil {
		return 0, classifyError(err, formatOp("client_sessions", "delete_by_session"))
	}
	return int(tag.RowsAffected()), nil
}

// DeleteByUserID removes every attachment across a user's sessions, live or not.
// Erasure. Uses the same join as GetByUserID, for the same reason.
func (r *ClientSessionRepo) DeleteByUserID(ctx context.Context, userID string) (int, error) {
	const q = `
		DELETE FROM client_sessions cs
		USING sessions s
		WHERE s.session_id = cs.session_id
		  AND s.user_id = $1`

	tag, err := r.pool.Exec(ctx, q, userID)
	if err != nil {
		return 0, classifyError(err, formatOp("client_sessions", "delete_by_user"))
	}
	return int(tag.RowsAffected()), nil
}

// query runs a multi-row select and collects the results.
func (r *ClientSessionRepo) query(ctx context.Context, q string, arg any, op string) ([]*domain.ClientSession, error) {
	rows, err := r.pool.Query(ctx, q, arg)
	if err != nil {
		return nil, classifyError(err, op)
	}
	defer rows.Close()

	var out []*domain.ClientSession
	for rows.Next() {
		cs, err := scanClientSession(rows)
		if err != nil {
			return nil, wrapRowsErr(err, op+".scan")
		}
		out = append(out, cs)
	}
	if err := rows.Err(); err != nil {
		// A partial result set here means some RPs are never told about a
		// logout, which is the exact outcome the fan-out exists to prevent.
		return nil, wrapRowsErr(err, op+".iterate")
	}
	return out, nil
}
