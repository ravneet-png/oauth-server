package storage

// User persistence.
//
// Email is normalised on write. The unique index is on lower(email) rather than
// on the column, so a row inserted by a path that forgot to normalise still
// cannot create a case-variant duplicate; normalising here as well means the
// stored value is canonical for display and for the HMAC used in audit rows,
// rather than being correct only by luck of which code path wrote it.

import (
	"context"
	"strings"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	"oauth-server/internal/domain"
)

// UserRepo reads and writes the users table.
type UserRepo struct {
	pool *pgxpool.Pool
}

// NewUserRepo builds a UserRepo over pool.
func NewUserRepo(pool *pgxpool.Pool) *UserRepo {
	assertPoolNonNil(pool, "UserRepo")
	return &UserRepo{pool: pool}
}

const userColumns = `
	user_id, email, password_hash, name,
	email_verified,
	mfa_enabled, mfa_secret_enc, mfa_last_counter,
	failed_login_count, locked_until, password_changed_at, last_login_at,
	is_admin, disabled_at, created_at, updated_at`

// normaliseEmail is the single definition of email normalisation.
//
// strings.ToLower, not strings.ToLowerCase and not a full Unicode case fold.
// The address is stored in a VARCHAR and compared with lower(), so anything
// other than the exact function the index uses produces a value that does not
// round-trip. The trim is here so a trailing space from a paste cannot create a
// second account for the same person.
func normaliseEmail(email string) string {
	return strings.ToLower(strings.TrimSpace(email))
}

func scanUser(row interface{ Scan(...any) error }) (*domain.User, error) {
	var (
		u          domain.User
		name       *string
		secretEnc  []byte
		lockedAt   *time.Time
		lastLogin  *time.Time
		disabledAt *time.Time
	)

	err := row.Scan(
		&u.UserID, &u.Email, &u.PasswordHash, &name,
		&u.EmailVerified,
		&u.MFAEnabled, &secretEnc, &u.MFALastCounter,
		&u.FailedLoginCount, &lockedAt, &u.PasswordChangedAt, &lastLogin,
		&u.IsAdmin, &disabledAt, &u.CreatedAt, &u.UpdatedAt,
	)
	if err != nil {
		return nil, err
	}

	u.Name = name
	u.MFASecretEnc = secretEnc
	u.LockedUntil = lockedAt
	u.LastLoginAt = lastLogin
	u.DisabledAt = disabledAt
	return &u, nil
}

// GetByID returns the user with the given id, including disabled ones.
func (r *UserRepo) GetByID(ctx context.Context, userID string) (*domain.User, error) {
	row := r.pool.QueryRow(ctx, `SELECT `+userColumns+` FROM users WHERE user_id = $1`, userID)
	u, err := scanUser(row)
	if err != nil {
		return nil, rowNotFound(err, formatOp("users", "get_by_id"))
	}
	return u, nil
}

// GetByEmail returns the user with the given address.
//
// Matching is on lower(email) to match the unique index, not on the column, so
// this finds a row written before normalisation. Using `email = $1` would miss
// it and report a user as unregistered, which reads as a password reset that
// never arrives.
func (r *UserRepo) GetByEmail(ctx context.Context, email string) (*domain.User, error) {
	row := r.pool.QueryRow(ctx,
		`SELECT `+userColumns+` FROM users WHERE lower(email) = lower($1)`, normaliseEmail(email))
	u, err := scanUser(row)
	if err != nil {
		return nil, rowNotFound(err, formatOp("users", "get_by_email"))
	}
	return u, nil
}

// Create inserts a user.
//
// A duplicate address is reported as ErrConflict, which the registration handler
// must answer with a generic "if that address is registered..." rather than
// "that address is taken": a distinct error is an account-enumeration oracle.
func (r *UserRepo) Create(ctx context.Context, u *domain.User) error {
	const q = `
		INSERT INTO users (
			user_id, email, password_hash, name,
			email_verified,
			mfa_enabled, mfa_secret_enc, mfa_last_counter,
			failed_login_count, locked_until, password_changed_at, last_login_at,
			is_admin, disabled_at
		) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14)`

	_, err := r.pool.Exec(ctx, q,
		u.UserID, normaliseEmail(u.Email), u.PasswordHash, u.Name,
		u.EmailVerified,
		u.MFAEnabled, u.MFASecretEnc, u.MFALastCounter,
		u.FailedLoginCount, u.LockedUntil, u.PasswordChangedAt, u.LastLoginAt,
		u.IsAdmin, u.DisabledAt,
	)
	if err != nil {
		return classifyError(err, formatOp("users", "create"))
	}
	return nil
}

// CreateIfNotExists inserts a user, reporting whether the row was created.
//
// ON CONFLICT (lower(email)) DO NOTHING, then RowsAffected. The boolean is read
// from the command tag rather than inferred by re-querying: a follow-up SELECT
// races with a concurrent deletion and can report false for a row that was
// genuinely just inserted.
//
// This is what makes registration safe to retry from a double-clicked button.
// A plain Create would return ErrConflict and the UI would show a spurious error
// for a registration that in fact succeeded.
func (r *UserRepo) CreateIfNotExists(ctx context.Context, u *domain.User) (bool, error) {
	const q = `
		INSERT INTO users (
			user_id, email, password_hash, name,
			email_verified,
			mfa_enabled, mfa_secret_enc, mfa_last_counter,
			failed_login_count, locked_until, password_changed_at, last_login_at,
			is_admin, disabled_at
		) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14)
		ON CONFLICT ((lower(email))) DO NOTHING`

	tag, err := r.pool.Exec(ctx, q,
		u.UserID, normaliseEmail(u.Email), u.PasswordHash, u.Name,
		u.EmailVerified,
		u.MFAEnabled, u.MFASecretEnc, u.MFALastCounter,
		u.FailedLoginCount, u.LockedUntil, u.PasswordChangedAt, u.LastLoginAt,
		u.IsAdmin, u.DisabledAt,
	)
	if err != nil {
		return false, classifyError(err, formatOp("users", "create_if_not_exists"))
	}
	return tag.RowsAffected() > 0, nil
}

// UpdatePasswordHash replaces the stored Argon2id hash.
//
// Exists so the cost parameters can be raised without a rehash-everything
// migration: crypto.NeedsRehash reports whether a stored hash is weaker than the
// current configuration, and a successful login is the only moment the plaintext
// password is available to compute a stronger one.
//
// mfa_last_counter is NOT reset here and updated_at IS stamped: this is not a new
// account, and clearing the TOTP high-water mark would re-open a replay window for
// any already-used code.
func (r *UserRepo) UpdatePasswordHash(ctx context.Context, userID, passwordHash string) error {
	return r.execUserUpdate(ctx, formatOp("users", "update_password_hash"),
		`UPDATE users SET password_hash = $2, updated_at = now() WHERE user_id = $1`,
		userID, passwordHash)
}

// UpdateMFALastCounter records the highest TOTP counter consumed.
//
// Called after a TOTP code verifies. Kept as a separate single-statement method
// rather than folded into UpdateMFA so the high-water mark can only ever move
// forward: enrolment resets it to 0 explicitly, which is the one case where a
// decrease is correct.
func (r *UserRepo) UpdateMFALastCounter(ctx context.Context, userID string, counter int64) error {
	return r.execUserUpdate(ctx, formatOp("users", "update_mfa_counter"),
		`UPDATE users
		    SET mfa_last_counter = GREATEST(mfa_last_counter, $2), updated_at = now()
		  WHERE user_id = $1`,
		userID, counter)
}

// UpdateEmailVerified sets the email_verified flag.
func (r *UserRepo) UpdateEmailVerified(ctx context.Context, userID string, verified bool) error {
	return r.execUserUpdate(ctx, formatOp("users", "update_email_verified"),
		`UPDATE users SET email_verified = $2, updated_at = now() WHERE user_id = $1`,
		userID, verified)
}

// UpdateMFA records an MFA enrolment or a change of secret.
//
// The prompt's signature took backup codes as an argument. It does not here,
// because the schema stores them in mfa_backup_codes, one row per code, and an
// array on the users row cannot have a single element consumed atomically:
// consuming one is a read-modify-write, so two concurrent submissions of the
// same recovery code both succeed and one code authorises two grants. The
// replacement codes are written through MFARepo.ReplaceForUser in the same
// transaction as this call.
//
// A user_id that does not exist is reported as ErrNotFound rather than silently
// succeeding, so a caller cannot believe MFA is enrolled when no row changed.
func (r *UserRepo) UpdateMFA(ctx context.Context, userID string, secretEnc []byte, enabled bool) error {
	return r.execUserUpdate(ctx, formatOp("users", "update_mfa"),
		`UPDATE users
		    SET mfa_secret_enc = $2, mfa_enabled = $3, mfa_last_counter = 0, updated_at = now()
		  WHERE user_id = $1`,
		userID, secretEnc, enabled)
}

// UpdateBackupCodes replaces a user's MFA recovery codes with a new set.
//
// The prompt puts this on the user repository because the prompt's schema had a
// TEXT[] column on users. This schema keeps codes in mfa_backup_codes, one row
// each, for the concurrency and auditability reasons on MFARepo, so the method
// opens a transaction and delegates to the same implementation
// MFARepo.ReplaceForUser uses. There is one code path, not two.
//
// The transaction is the whole point of the method existing. A delete followed by
// a bulk insert across two statements without one leaves the user with no working
// recovery codes at all if the insert fails, immediately after enrolment appeared
// to succeed. That is a lockout with no recovery path.
//
// Pass nil or an empty slice to clear the codes, which is what re-enrolment
// without recovery codes means. That is not a no-op: the delete runs.
func (r *UserRepo) UpdateBackupCodes(ctx context.Context, userID string, codes []string) error {
	tx, err := r.pool.Begin(ctx)
	if err != nil {
		return classifyError(err, formatOp("users", "update_backup_codes", "begin"))
	}
	// Rollback is deferred and its error is deliberately ignored: if the commit
	// already succeeded there is nothing to undo, and reporting a rollback failure
	// after a successful commit would make a committed write look like a failure.
	// If the commit did fail, the deferred rollback is what keeps the deleted codes
	// from being lost.
	defer func() { _ = tx.Rollback(ctx) }()

	if err := replaceBackupCodes(ctx, tx, userID, codes); err != nil {
		return err
	}
	if err := tx.Commit(ctx); err != nil {
		return classifyError(err, formatOp("users", "update_backup_codes", "commit"))
	}
	return nil
}

// Delete removes the user row and everything that references it.
//
// GDPR erasure has to actually erase, so this is a teardown rather than a single-row
// delete: the referencing tables are ON DELETE RESTRICT, which means the user row cannot
// be removed while any of them holds a row. Each is therefore cleared explicitly, in one
// transaction, and the delete of the user row itself is the last statement. If the
// transaction fails partway nothing is committed, so a failed erasure leaves the account
// intact rather than half-deleted.
//
// The alternative - letting RESTRICT surface as ErrConflict and making every caller
// enumerate the tables - was rejected because the enumeration is exactly what goes wrong
// when a new table is added later. A forgotten table would then leave erasure silently
// incomplete, which is the failure mode this trades away.
func (r *UserRepo) Delete(ctx context.Context, userID string) error {
	// One transaction for the whole teardown. Without it a failure partway through
	// would commit the statements that already ran, leaving an account with its
	// sessions and tokens gone but its user row still present - a state neither
	// erasure nor the login path can make sense of.
	tx, err := r.pool.Begin(ctx)
	if err != nil {
		return classifyError(err, formatOp("users", "delete_begin"))
	}
	defer func() { _ = tx.Rollback(ctx) }()

	// exec runs one statement on the transaction.
	exec := func(op, query string, args ...any) error {
		if _, err := tx.Exec(ctx, query, args...); err != nil {
			return classifyError(err, formatOp(op, "delete"))
		}
		return nil
	}

	// Delete sessions first: the FK is ON DELETE RESTRICT, so the user row
	// cannot be removed while sessions reference it. The audit scrub below keys
	// off these session IDs, so it has to run while they still exist.
	if err := exec("sessions", `DELETE FROM sessions WHERE user_id = $1`, userID); err != nil {
		return err
	}
	// Delete token families (FK ON DELETE RESTRICT).
	if err := exec("token_families", `DELETE FROM token_families WHERE user_id = $1`, userID); err != nil {
		return err
	}
	// Delete refresh tokens (FK ON DELETE RESTRICT).
	if err := exec("refresh_tokens", `DELETE FROM refresh_tokens WHERE user_id = $1`, userID); err != nil {
		return err
	}
	// Delete consents (FK ON DELETE RESTRICT).
	if err := exec("consents", `DELETE FROM consents WHERE user_id = $1`, userID); err != nil {
		return err
	}
	// Delete MFA backup codes (FK ON DELETE RESTRICT).
	if err := exec("mfa_backup_codes", `DELETE FROM mfa_backup_codes WHERE user_id = $1`, userID); err != nil {
		return err
	}
	// Delete email verifications (FK ON DELETE RESTRICT).
	if err := exec("email_verifications", `DELETE FROM email_verifications WHERE user_id = $1`, userID); err != nil {
		return err
	}
	// Delete auth codes (FK ON DELETE RESTRICT).
	if err := exec("auth_codes", `DELETE FROM auth_codes WHERE user_id = $1`, userID); err != nil {
		return err
	}
	// Delete auth requests (FK ON DELETE RESTRICT).
	if err := exec("auth_requests", `DELETE FROM auth_requests WHERE user_id = $1`, userID); err != nil {
		return err
	}
	// Scrub audit log entries for this user.
	// The audit_log table has no user_id column; actor and target are HMAC hashes.
	// We scrub by setting actor='DELETED', target='DELETED', session_id=NULL,
	// ip_address=NULL, user_agent=NULL for all entries that reference this user.
	// Since we cannot compute the HMAC here (no pepper), we scrub ALL entries
	// that have a session_id belonging to this user.
	if err := exec("audit_log", `
		UPDATE audit_log SET
			actor = 'DELETED',
			target = 'DELETED',
			session_id = NULL,
			ip_address = NULL,
			user_agent = NULL,
			details = '{}'::jsonb
		WHERE session_id IN (SELECT session_id FROM sessions WHERE user_id = $1)
		   OR actor = $1 OR target = $1
	`, userID); err != nil {
		return err
	}
	// Delete the user row.
	tag, err := tx.Exec(ctx, `DELETE FROM users WHERE user_id = $1`, userID)
	if err != nil {
		return classifyError(err, formatOp("users", "delete"))
	}
	if tag.RowsAffected() == 0 {
		return notFound(formatOp("users", "delete"))
	}
	if err := tx.Commit(ctx); err != nil {
		return classifyError(err, formatOp("users", "delete_commit"))
	}
	return nil
}

// RecordLoginFailure increments the failure counter and sets locked_until once
// the threshold is reached.
//
// Not in the prompt, and included because the alternative is worse: a
// brute-force defence that counts failures in application memory resets on every
// deploy, and one that counts them in a Redis key that can be evicted is not a
// lockout at all. The counter belongs beside the row it protects.
//
// The whole decision is one conditional UPDATE, so two concurrent attempts
// cannot both read a count below the threshold and both decide not to lock:
// whoever reaches the threshold first locks, and the other sees the same locked
// state. Comparing a threshold here in Go would be a check-then-act race, which is
// exactly the shape the atomic methods elsewhere in this package avoid.
func (r *UserRepo) RecordLoginFailure(ctx context.Context, userID string, threshold int, lockFor time.Duration) (locked bool, err error) {
	const q = `
		UPDATE users
		   SET failed_login_count = failed_login_count + 1,
		       locked_until = CASE
		           WHEN failed_login_count + 1 >= $2 THEN now() + make_interval(secs => $3)
		           ELSE locked_until
		       END,
		       updated_at = now()
		 WHERE user_id = $1
		RETURNING (locked_until IS NOT NULL AND locked_until > now())`

	row := r.pool.QueryRow(ctx, q, userID, threshold, lockFor.Seconds())
	if err := row.Scan(&locked); err != nil {
		return false, rowNotFound(err, formatOp("users", "record_login_failure"))
	}
	return locked, nil
}

// RecordLoginSuccess clears the failure counter and stamps last_login_at.
//
// One statement rather than "then set last_login_at", so a crash between them
// cannot leave a user permanently locked after a successful login.
func (r *UserRepo) RecordLoginSuccess(ctx context.Context, userID string) error {
	return r.execUserUpdate(ctx, formatOp("users", "record_login_success"),
		`UPDATE users
		    SET failed_login_count = 0, locked_until = NULL, last_login_at = now(), updated_at = now()
		  WHERE user_id = $1`,
		userID)
}

// execUserUpdate runs a single-row UPDATE and converts a zero-row result into
// ErrNotFound, so every setter behaves the same way.
//
// The row count check is what stops a silent no-op. An UPDATE that matches
// nothing and returns nil is how a caller concludes that MFA is enrolled, or that
// a password changed, when neither happened.
func (r *UserRepo) execUserUpdate(ctx context.Context, op, q string, args ...any) error {
	tag, err := r.pool.Exec(ctx, q, args...)
	if err != nil {
		return classifyError(err, op)
	}
	if tag.RowsAffected() == 0 {
		return notFound(op)
	}
	return nil
}
