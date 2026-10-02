package storage

// MFA backup code persistence. One row per code, individually hashed and
// individually consumable.

import (
	"context"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"oauth-server/internal/domain"
)

// MFARepo reads and writes the mfa_backup_codes table.
//
// A separate table rather than a TEXT[] on users, for three reasons that are each
// independently sufficient:
//
//  1. Consuming one code is a read-modify-write on an array, so two concurrent
//     submissions of the same recovery code both succeed and one code authorises
//     two grants.
//  2. There is no record of which code was used, so an incident cannot be
//     investigated.
//  3. Per-code rate limiting is impossible on a fixed-size array.
type MFARepo struct {
	pool *pgxpool.Pool
}

// NewMFARepo builds an MFARepo over pool.
func NewMFARepo(pool *pgxpool.Pool) *MFARepo {
	assertPoolNonNil(pool, "MFARepo")
	return &MFARepo{pool: pool}
}

const backupCodeColumns = `code_hash, user_id, used_at, created_at`

func scanBackupCode(row interface{ Scan(...any) error }) (*domain.MFABackupCode, error) {
	var c domain.MFABackupCode
	if err := row.Scan(&c.CodeHash, &c.UserID, &c.UsedAt, &c.CreatedAt); err != nil {
		return nil, err
	}
	return &c, nil
}

// CreateBatch stores a set of hashed backup codes for a user.
//
// One statement via unnest. A loop of single inserts is a round trip per code, and
// an enrolment that writes ten codes would be ten chances to fail halfway,
// leaving a user with a partially replaced set and no way to tell which codes
// survived. The batch is atomic, so either all codes land or none do.
//
// ON CONFLICT DO NOTHING on code_hash, because codes are 128 bits of CSPRNG
// output and a collision is not a thing that happens; the clause exists so a
// retried enrolment is idempotent rather than an error.
func (r *MFARepo) CreateBatch(ctx context.Context, userID string, hashes []string) error {
	if len(hashes) == 0 {
		return nil
	}
	const q = `
		INSERT INTO mfa_backup_codes (code_hash, user_id)
		SELECT h, $1 FROM unnest($2::text[]) AS h
		ON CONFLICT (code_hash) DO NOTHING`

	if _, err := r.pool.Exec(ctx, q, userID, hashes); err != nil {
		return classifyError(err, formatOp("mfa_backup_codes", "create_batch"))
	}
	return nil
}

// ReplaceForUser swaps a user's entire unused code set for a new one.
//
// DELETE then INSERT, and it MUST be called inside a transaction. Without one, a
// failure between the two halves leaves the user with no working recovery codes at
// all, having just been told enrolment succeeded. That is a lockout with no
// recovery path, and it is the single most damaging bug available in this area.
//
// The delete is scoped to used_at IS NULL, so a code that has already been spent
// keeps its row as evidence. Erasure and audit both need to know a code was used
// and when; dropping the record at re-enrolment time would erase the only trace.
func (r *MFARepo) ReplaceForUser(ctx context.Context, tx pgx.Tx, userID string, hashes []string) error {
	return replaceBackupCodes(ctx, tx, userID, hashes)
}

// replaceBackupCodes swaps a user's unspent code set for a new one.
//
// Takes a queryer rather than a concrete pool or tx so the one implementation
// serves both entry points: MFARepo.ReplaceForUser, called with a caller-supplied
// transaction so it can compose with the other halves of an enrolment, and
// UserRepo.UpdateBackupCodes, which opens its own because the prompt's signature
// does not take one.
//
// The user is checked first so a wrong id is reported as ErrNotFound rather than
// as a foreign key violation on the insert. Both mean "no codes were written", but
// one says the user does not exist and the other looks like a schema problem, and
// the caller of an enrolment flow needs to tell them apart.
//
// Empty hashes is a legitimate request: it clears the user's recovery codes, which
// is what re-enrolment without recovery codes means. The delete still runs, so this
// is not accidentally a no-op.
func replaceBackupCodes(ctx context.Context, q queryer, userID string, hashes []string) error {
	const exists = `SELECT 1 FROM users WHERE user_id = $1`
	var one int
	if err := q.QueryRow(ctx, exists, userID).Scan(&one); err != nil {
		return rowNotFound(err, formatOp("mfa_backup_codes", "replace", "user"))
	}

	// The delete is scoped to used_at IS NULL, so a code that has already been spent
	// keeps its row as evidence. Erasure and audit both need to know a code was used
	// and when; dropping the record at re-enrolment time would erase the only trace.
	const del = `DELETE FROM mfa_backup_codes WHERE user_id = $1 AND used_at IS NULL`
	if _, err := q.Exec(ctx, del, userID); err != nil {
		return classifyError(err, formatOp("mfa_backup_codes", "replace", "delete"))
	}
	if len(hashes) == 0 {
		return nil
	}

	const ins = `
		INSERT INTO mfa_backup_codes (code_hash, user_id)
		SELECT h, $1 FROM unnest($2::text[]) AS h
		ON CONFLICT (code_hash) DO NOTHING`
	if _, err := q.Exec(ctx, ins, userID, hashes); err != nil {
		return classifyError(err, formatOp("mfa_backup_codes", "replace", "insert"))
	}
	return nil
}

// Consume marks a code used and returns whether this call was the one that did.
//
//	UPDATE ... SET used_at = now() WHERE code_hash = $1 AND used_at IS NULL
//	RETURNING ...
//
// The single most important statement in the recovery-code path. A code is a
// bearer credential for a full MFA bypass, so two concurrent submissions of one
// code must authorise exactly one. A read-then-write has a window, and the failure
// mode is an attacker who captured a code using it twice to hold two sessions.
//
// False means the code was already spent. The caller must then refuse, and must
// not fall back to checking any other code in the same submission: doing so lets
// an attacker who has one spent code keep guessing the rest.
func (r *MFARepo) Consume(ctx context.Context, hash string) (bool, error) {
	const q = `
		UPDATE mfa_backup_codes
		   SET used_at = now()
		 WHERE code_hash = $1
		   AND used_at IS NULL
		RETURNING user_id`

	var userID string
	err := r.pool.QueryRow(ctx, q, hash).Scan(&userID)
	if err != nil {
		if ctxErr(err) {
			return false, classifyError(err, formatOp("mfa_backup_codes", "consume"))
		}
		if isNoRows(err) {
			return false, nil
		}
		return false, classifyError(err, formatOp("mfa_backup_codes", "consume"))
	}
	return true, nil
}

// ConsumeForUser marks a code used, but only if it belongs to userID, and reports
// whether this call was the one that did.
//
//	user_id is in the predicate rather than checked after the UPDATE. That is the
//	only way to get both properties at once: a read-then-write to learn the owner
//	reintroduces the race Consume exists to remove, and a write-then-check burns a
//	code that belonged to somebody else. With the owner in the predicate, a code
//	presented against the wrong account is neither consumed nor accepted, so an
//	attacker cannot destroy another user's recovery codes by guessing their
//	address, and two concurrent submissions of one code still resolve to exactly
//	one success.
//
// False means "not yours, or already spent". The two are deliberately
//
//	indistinguishable to the caller: telling them apart tells an attacker whether
//	the code they are holding is real.
func (r *MFARepo) ConsumeForUser(ctx context.Context, hash, userID string) (bool, error) {
	const q = `
		UPDATE mfa_backup_codes
		   SET used_at = now()
		 WHERE code_hash = $1
		   AND user_id = $2
		   AND used_at IS NULL
		RETURNING user_id`

	var owner string
	err := r.pool.QueryRow(ctx, q, hash, userID).Scan(&owner)
	if err != nil {
		if ctxErr(err) {
			return false, classifyError(err, formatOp("mfa_backup_codes", "consume_for_user"))
		}
		if isNoRows(err) {
			return false, nil
		}
		return false, classifyError(err, formatOp("mfa_backup_codes", "consume_for_user"))
	}
	return true, nil
}

// CountSpentForUser returns how many recovery codes a user has burned.
//
// Exists so a total attempt budget can be enforced across codes. A budget needs a
// count of spent codes, and there is no way to derive one from the unused set
// alone, because an attacker who presents a code belonging to a different account
// is correctly refused without consuming it and would otherwise reset nothing
// while still learning nothing, while a correct guess always appears here.
func (r *MFARepo) CountSpentForUser(ctx context.Context, userID string) (int, error) {
	const q = `SELECT count(*) FROM mfa_backup_codes WHERE user_id = $1 AND used_at IS NOT NULL`

	var n int64
	if err := r.pool.QueryRow(ctx, q, userID).Scan(&n); err != nil {
		return 0, rowNotFound(err, formatOp("mfa_backup_codes", "count_spent"))
	}
	return int(n), nil
}

// GetUnused returns every unspent code record for a user.
//
// For showing "you have N codes left", not for verifying a presented code: a
// verification must go through Consume. The partial index idx_backup_codes_unused
// covers this predicate.
func (r *MFARepo) GetUnused(ctx context.Context, userID string) ([]*domain.MFABackupCode, error) {
	const q = `SELECT ` + backupCodeColumns + `
		FROM mfa_backup_codes
		WHERE user_id = $1 AND used_at IS NULL
		ORDER BY created_at`

	rows, err := r.pool.Query(ctx, q, userID)
	if err != nil {
		return nil, classifyError(err, formatOp("mfa_backup_codes", "list_unused"))
	}
	defer rows.Close()

	var out []*domain.MFABackupCode
	for rows.Next() {
		c, err := scanBackupCode(rows)
		if err != nil {
			return nil, wrapRowsErr(err, formatOp("mfa_backup_codes", "list_unused", "scan"))
		}
		out = append(out, c)
	}
	if err := rows.Err(); err != nil {
		return nil, wrapRowsErr(err, formatOp("mfa_backup_codes", "list_unused", "iterate"))
	}
	return out, nil
}

// CountUnused returns how many unspent codes a user has left.
//
// Lets the enrolment UI warn when codes are running low without loading the rows.
func (r *MFARepo) CountUnused(ctx context.Context, userID string) (int, error) {
	const q = `SELECT count(*) FROM mfa_backup_codes WHERE user_id = $1 AND used_at IS NULL`
	var n int64
	if err := r.pool.QueryRow(ctx, q, userID).Scan(&n); err != nil {
		return 0, rowNotFound(err, formatOp("mfa_backup_codes", "count_unused"))
	}
	return int(n), nil
}

// DeleteForUser removes every code record for a user, used or not. Erasure.
func (r *MFARepo) DeleteForUser(ctx context.Context, userID string) (int, error) {
	const q = `DELETE FROM mfa_backup_codes WHERE user_id = $1`
	tag, err := r.pool.Exec(ctx, q, userID)
	if err != nil {
		return 0, classifyError(err, formatOp("mfa_backup_codes", "delete_for_user"))
	}
	return int(tag.RowsAffected()), nil
}
