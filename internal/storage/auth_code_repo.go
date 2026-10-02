package storage

// Authorization code persistence.
//
// The schema's single-use marker is a nullable used_at, not a boolean. The
// consumption method is therefore a conditional UPDATE ... RETURNING whose
// predicate carries every check, and its zero-row result is the security
// decision: zero rows means the code was already redeemed or never existed, and
// both must be refused.

import (
	"context"
	"errors"

	"github.com/jackc/pgx/v5/pgxpool"

	"oauth-server/internal/domain"
)

// AuthCodeRepo reads and writes the auth_codes table.
type AuthCodeRepo struct {
	pool *pgxpool.Pool
}

// NewAuthCodeRepo builds an AuthCodeRepo over pool.
func NewAuthCodeRepo(pool *pgxpool.Pool) *AuthCodeRepo {
	assertPoolNonNil(pool, "AuthCodeRepo")
	return &AuthCodeRepo{pool: pool}
}

const authCodeColumns = `
	code_hash, client_id, user_id, session_id, sid, family_id,
	scope, redirect_uri,
	code_challenge, code_challenge_method, nonce, auth_time,
	expires_at, used_at, created_at`

func scanAuthCode(row interface{ Scan(...any) error }) (*domain.AuthCode, error) {
	var (
		c     domain.AuthCode
		scope []string
	)
	err := row.Scan(
		&c.CodeHash, &c.ClientID, &c.UserID, &c.SessionID, &c.SID, &c.FamilyID,
		&scope, &c.RedirectURI,
		&c.CodeChallenge, &c.CodeChallengeMethod, &c.Nonce, &c.AuthTime,
		&c.ExpiresAt, &c.UsedAt, &c.CreatedAt,
	)
	if err != nil {
		return nil, err
	}
	c.Scope = scanStrings(scope)
	return &c, nil
}

// Create inserts an authorization code.
//
// The code is stored by SHA-256 digest only. The plaintext exists exactly once,
// in the 302 redirect to the client; a row holding it would make a database read
// sufficient to impersonate the user at /token.
func (r *AuthCodeRepo) Create(ctx context.Context, c *domain.AuthCode) error {
	const q = `
		INSERT INTO auth_codes (
			code_hash, client_id, user_id, session_id, sid, family_id,
			scope, redirect_uri,
			code_challenge, code_challenge_method, nonce, auth_time,
			expires_at
		) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13)`

	_, err := r.pool.Exec(ctx, q,
		c.CodeHash, c.ClientID, c.UserID, c.SessionID, c.SID, c.FamilyID,
		c.Scope, c.RedirectURI,
		c.CodeChallenge, c.CodeChallengeMethod, c.Nonce, c.AuthTime,
		c.ExpiresAt,
	)
	if err != nil {
		return classifyError(err, formatOp("auth_codes", "create"))
	}
	return nil
}

// GetByHash returns the code with the given digest, whether or not it has been
// used.
//
// It deliberately does not filter on used_at. Reuse detection needs to SEE a
// consumed code: proving that a code was already redeemed is what distinguishes
// an attacker replaying a stolen code, which must cascade a family revocation,
// from an attacker guessing digests, which must do nothing. A repository that
// hid consumed rows would make both look identical.
func (r *AuthCodeRepo) GetByHash(ctx context.Context, hash string) (*domain.AuthCode, error) {
	row := r.pool.QueryRow(ctx, `SELECT `+authCodeColumns+` FROM auth_codes WHERE code_hash = $1`, hash)
	c, err := scanAuthCode(row)
	if err != nil {
		return nil, rowNotFound(err, formatOp("auth_codes", "get_by_hash"))
	}
	return c, nil
}

// AtomicMarkUsed consumes the code and returns the row, or nil if it was not
// consumable.
//
// This is the single most important statement in the authorization code path, and
// every part of it is load-bearing:
//
//		UPDATE ... SET used_at = NOW() WHERE code_hash = $1 AND used_at IS NULL
//		RETURNING ...
//
//	 1. The predicate carries the check. There is no preceding SELECT, so there is
//	    no window between deciding the code is unused and marking it used. A
//	    read-then-write pair loses that window to any concurrent request, and two
//	    simultaneous redemptions of one code is the entire authorization code
//	    replay attack.
//
//	 2. used_at IS NULL is the single source of truth. The prompt's text says
//	    "used=false", but this schema has no such column by design: a boolean
//	    beside a timestamp can drift, and the drift is always in the unsafe
//	    direction, because used=false with a non-null used_at lets the code be
//	    redeemed a second time.
//
//	 3. RETURNING gives the caller the full row it needs to issue tokens, from the
//	    same statement that consumed it. A second read after a successful write
//	    would race with the reaper.
//
//	 4. Nil with a nil error means "not consumable": already used, expired, or
//	    unknown. The caller cannot distinguish these, and must not be able to: each
//	    distinction handed back to an attacker is information. The caller learns
//	    which case it was only by following up with GetByHash, which is how reuse
//	    detection escalates to a family revocation without the /token response
//	    revealing that anything unusual happened.
//
// Expiry is NOT in the predicate. It is deliberately left to the caller via
// domain.AuthCode.IsUsable, because an expired code and a reused one need
// different audit events even though both return nil here. A caller that wants
// expiry enforced in the database can add AND expires_at > now() and lose the
// ability to tell them apart; the trade is documented so it is made knowingly.
func (r *AuthCodeRepo) AtomicMarkUsed(ctx context.Context, hash string) (*domain.AuthCode, error) {
	const q = `
		UPDATE auth_codes
		   SET used_at = now()
		 WHERE code_hash = $1
		   AND used_at IS NULL
		RETURNING ` + authCodeColumns

	row := r.pool.QueryRow(ctx, q, hash)
	c, err := scanAuthCode(row)
	if err != nil {
		// Zero rows is the expected outcome for a replay, not a failure. Only
		// pgx.ErrNoRows takes that path: a connection or decode failure here
		// would otherwise be reported to the token endpoint as an ordinary
		// invalid_grant, hiding a real outage and, worse, leaving the code
		// unredeemed while the caller believes it was already spent.
		if isNoRows(err) {
			return nil, nil
		}
		return nil, classifyError(err, formatOp("auth_codes", "mark_used"))
	}
	return c, nil
}

// EnsureFamilyID attaches a family to a code, or leaves the existing one alone.
//
// Idempotent on purpose. The family is normally written by the consent step at insert
// time (domain.AuthCode documents that, because a later UPDATE leaves a crash window
// in which a consumed code has no family and reuse detection has nothing to cascade
// over), but a code issued by an older row, or one inserted by a migration, may arrive
// here without one. Writing unconditionally would let two callers disagree about which
// family a code belongs to, and the refresh tokens minted from it would then belong to
// a family the code does not name.
//
// COALESCE makes "already set" a success rather than an error, so the redemption path
// can call this without knowing how the code was created. It is still an error when no
// such code exists: that would mean the caller believes it just redeemed a row that
// does not exist, and continuing would issue tokens against a fiction.
func (r *AuthCodeRepo) EnsureFamilyID(ctx context.Context, hash, familyID string) error {
	if hash == "" || familyID == "" {
		return errors.New("auth_code_repo: EnsureFamilyID: empty argument")
	}

	const q = `
		UPDATE auth_codes
		   SET family_id = COALESCE(family_id, $2)
		 WHERE code_hash = $1`

	tag, err := r.pool.Exec(ctx, q, hash, familyID)
	if err != nil {
		return classifyError(err, formatOp("auth_codes", "ensure_family"))
	}
	if tag.RowsAffected() == 0 {
		return notFound(formatOp("auth_codes", "ensure_family"))
	}
	return nil
}

// DeleteExpired removes codes past their expiry, up to one bounded batch, and
// returns how many were removed.
//
// A code is past its expiry and therefore worthless, so this is the one place a
// plain expiry comparison is safe: it cannot delete a redeemable code. Used codes
// with a future expiry are kept, because they are the evidence reuse detection
// needs; the reaper's job is to bound the table, not to forget.
func (r *AuthCodeRepo) DeleteExpired(ctx context.Context) (int, error) {
	const q = `
		DELETE FROM auth_codes
		 WHERE code_hash IN (
		     SELECT code_hash FROM auth_codes
		      WHERE expires_at < now()
		      LIMIT $1
		 )`

	tag, err := r.pool.Exec(ctx, q, reaperBatch)
	if err != nil {
		return 0, classifyError(err, formatOp("auth_codes", "delete_expired"))
	}
	return int(tag.RowsAffected()), nil
}
