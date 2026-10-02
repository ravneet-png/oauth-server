package storage

// Browser session persistence.

import (
	"context"
	"net/netip"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	"oauth-server/internal/domain"
)

// SessionRepo reads and writes the sessions table.
type SessionRepo struct {
	pool *pgxpool.Pool
}

// NewSessionRepo builds a SessionRepo over pool.
func NewSessionRepo(pool *pgxpool.Pool) *SessionRepo {
	assertPoolNonNil(pool, "SessionRepo")
	return &SessionRepo{pool: pool}
}

const sessionColumns = `
	session_id, user_id, auth_time,
	expires_at, absolute_expires_at,
	acr, amr, ip_address, user_agent,
	created_at, last_seen_at`

func scanSession(row interface{ Scan(...any) error }) (*domain.Session, error) {
	var (
		s      domain.Session
		amr    []string
		ipText *string
	)
	err := row.Scan(
		&s.SessionID, &s.UserID, &s.AuthTime,
		&s.ExpiresAt, &s.AbsoluteExpiresAt,
		&s.Acr, &amr, &ipText, &s.UserAgent,
		&s.CreatedAt, &s.LastSeenAt,
	)
	if err != nil {
		return nil, err
	}
	s.Amr = scanStrings(amr)
	// The column is INET and pgx can decode it straight into a netip.Addr, but
	// scanning via text keeps the conversion in one place and avoids a pgx
	// version dependency in a security-relevant path.
	if ipText != nil {
		if addr, err := netip.ParseAddr(*ipText); err == nil {
			s.IPAddress = &addr
		}
	}
	return &s, nil
}

// Create inserts a session.
func (r *SessionRepo) Create(ctx context.Context, s *domain.Session) error {
	const q = `
		INSERT INTO sessions (
			session_id, user_id, auth_time,
			expires_at, absolute_expires_at,
			acr, amr, ip_address, user_agent,
			last_seen_at
		) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)`

	// sessions.amr is NOT NULL and a nil slice is encoded as SQL NULL, which the
	// database rejects. An empty array is the same claim made safely: no method was
	// recorded.
	amr := s.Amr
	if amr == nil {
		amr = []string{}
	}

	_, err := r.pool.Exec(ctx, q,
		s.SessionID, s.UserID, s.AuthTime,
		s.ExpiresAt, s.AbsoluteExpiresAt,
		s.Acr, amr, addrToString(s.IPAddress), s.UserAgent,
		s.LastSeenAt,
	)
	if err != nil {
		return classifyError(err, formatOp("sessions", "create"))
	}
	return nil
}

// GetByID returns a session only if it is within BOTH expiries.
//
// The predicate checks idle and absolute expiry together, in the database, rather
// than returning the row and letting the caller call domain.Session.IsValid. That
// is the difference between a session that is not found and a session that is
// found and must then be checked: if this method returned expired rows, every
// caller that forgot the check would accept a dead session, and the check is
// exactly the kind that gets forgotten in one code path out of twenty.
//
// It also means the caller cannot observe a session that exists but has lapsed,
// which is deliberate. The distinction is not useful to anyone: to a browser the
// cookie is simply not recognised.
func (r *SessionRepo) GetByID(ctx context.Context, sessionID string) (*domain.Session, error) {
	const q = `SELECT ` + sessionColumns + `
		FROM sessions
		WHERE session_id = $1
		  AND expires_at > now()
		  AND absolute_expires_at > now()`

	row := r.pool.QueryRow(ctx, q, sessionID)
	s, err := scanSession(row)
	if err != nil {
		return nil, rowNotFound(err, formatOp("sessions", "get"))
	}
	return s, nil
}

// GetByIDUnchecked returns a session regardless of expiry.
//
// For the reaper and for logout, both of which must act on sessions that have
// already lapsed. GetByID returning ErrNotFound for a dead session would make it
// impossible to clean one up or to revoke the tokens attached to it.
func (r *SessionRepo) GetByIDUnchecked(ctx context.Context, sessionID string) (*domain.Session, error) {
	row := r.pool.QueryRow(ctx, `SELECT `+sessionColumns+` FROM sessions WHERE session_id = $1`, sessionID)
	s, err := scanSession(row)
	if err != nil {
		return nil, rowNotFound(err, formatOp("sessions", "get_unchecked"))
	}
	return s, nil
}

// RefreshIdle slides the idle deadline forward.
//
// Bounded by the absolute ceiling in the same statement. Without that, a client
// sending requests just before the ceiling would keep sliding ExpiresAt past
// AbsoluteExpiresAt, which the schema's sessions_expiry_order_chk would reject
// with a check violation, and the session would break at exactly the moment it
// should be expiring. Bounding in SQL means the caller cannot get that wrong.
//
// The UPDATE is also guarded on the absolute ceiling, so a refresh that arrives
// after the ceiling has passed is a no-op returning zero rows, which surfaces as
// ErrNotFound. A caller treating that as a successful refresh would keep a client
// convinced it is logged in.
//
// The clamp subtracts one microsecond rather than pinning to the ceiling itself.
// sessions_expiry_order_chk is a STRICT inequality (absolute_expires_at >
// expires_at), so LEAST($2, absolute_expires_at) makes the two columns equal on
// exactly the refresh that tries to reach the ceiling, and the statement fails
// with a check violation. A session requesting the ceiling is asking for a
// deadline the schema forbids, so the latest instant it may actually hold is the
// ceiling minus the smallest representable step.
func (r *SessionRepo) RefreshIdle(ctx context.Context, sessionID string, newExpiry time.Time) error {
	const q = `
		UPDATE sessions
		   SET expires_at = LEAST($2, absolute_expires_at - interval '1 microsecond'),
		       last_seen_at = now()
		 WHERE session_id = $1
		   AND absolute_expires_at > now()`

	tag, err := r.pool.Exec(ctx, q, sessionID, newExpiry)
	if err != nil {
		return classifyError(err, formatOp("sessions", "refresh_idle"))
	}
	if tag.RowsAffected() == 0 {
		return notFound(formatOp("sessions", "refresh_idle"))
	}
	return nil
}

// UpdateAuthContext records the assurance established at login or MFA.
//
// Separate from Create because a step-up MFA changes acr and amr on a session
// that already exists. amr is replaced wholesale rather than appended, so a
// re-enrolled session reports the methods that actually applied to the current
// login and not a union of every factor ever presented.
func (r *SessionRepo) UpdateAuthContext(ctx context.Context, sessionID, acr string, amr []string) error {
	const q = `
		UPDATE sessions
		   SET acr = $2, amr = $3, auth_time = now(), last_seen_at = now()
		 WHERE session_id = $1
		   AND absolute_expires_at > now()`

	tag, err := r.pool.Exec(ctx, q, sessionID, acr, amr)
	if err != nil {
		return classifyError(err, formatOp("sessions", "update_auth_context"))
	}
	if tag.RowsAffected() == 0 {
		return notFound(formatOp("sessions", "update_auth_context"))
	}
	return nil
}

// Delete removes a session.
//
// client_sessions and any session-scoped auth_codes cascade, and refresh tokens
// and issued access tokens are SET NULL rather than deleted: the token records
// must outlive the session so they remain revocable afterwards. A user logging out
// must not erase the record that a token was ever issued.
func (r *SessionRepo) Delete(ctx context.Context, sessionID string) error {
	tag, err := r.pool.Exec(ctx, `DELETE FROM sessions WHERE session_id = $1`, sessionID)
	if err != nil {
		return classifyError(err, formatOp("sessions", "delete"))
	}
	if tag.RowsAffected() == 0 {
		return notFound(formatOp("sessions", "delete"))
	}
	return nil
}

// DeleteExpired removes lapsed sessions in one bounded batch and returns the count.
//
// Eligible on either expiry: a session past its absolute ceiling is dead even if
// its idle deadline has been slid forward by a client that kept sending requests.
func (r *SessionRepo) DeleteExpired(ctx context.Context) (int, error) {
	const q = `
		DELETE FROM sessions
		 WHERE session_id IN (
		     SELECT session_id FROM sessions
		      WHERE expires_at < now()
		         OR absolute_expires_at < now()
		      LIMIT $1
		 )`

	tag, err := r.pool.Exec(ctx, q, reaperBatch)
	if err != nil {
		return 0, classifyError(err, formatOp("sessions", "delete_expired"))
	}
	return int(tag.RowsAffected()), nil
}

// GetByUserID returns every live session for a user, for "sign out everywhere".
func (r *SessionRepo) GetByUserID(ctx context.Context, userID string) ([]*domain.Session, error) {
	const q = `SELECT ` + sessionColumns + `
		FROM sessions
		WHERE user_id = $1
		  AND expires_at > now()
		  AND absolute_expires_at > now()
		ORDER BY last_seen_at DESC`

	rows, err := r.pool.Query(ctx, q, userID)
	if err != nil {
		return nil, classifyError(err, formatOp("sessions", "by_user"))
	}
	defer rows.Close()

	var out []*domain.Session
	for rows.Next() {
		s, err := scanSession(rows)
		if err != nil {
			return nil, wrapRowsErr(err, formatOp("sessions", "by_user", "scan"))
		}
		out = append(out, s)
	}
	if err := rows.Err(); err != nil {
		return nil, wrapRowsErr(err, formatOp("sessions", "by_user", "iterate"))
	}
	return out, nil
}

// DeleteAllForUser removes every session belonging to a user, live or not.
// Erasure.
func (r *SessionRepo) DeleteAllForUser(ctx context.Context, userID string) (int, error) {
	const q = `DELETE FROM sessions WHERE user_id = $1`
	tag, err := r.pool.Exec(ctx, q, userID)
	if err != nil {
		return 0, classifyError(err, formatOp("sessions", "delete_all_for_user"))
	}
	return int(tag.RowsAffected()), nil
}
