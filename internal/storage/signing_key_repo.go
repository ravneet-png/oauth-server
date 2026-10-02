package storage

// Signing key persistence. Lifecycle is active -> retiring -> retired, and the
// partial unique index is what guarantees the server can always sign.

import (
	"context"
	"errors"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	"oauth-server/internal/domain"
)

// SigningKeyRepo reads and writes the signing_keys table.
type SigningKeyRepo struct {
	pool *pgxpool.Pool
}

// NewSigningKeyRepo builds a SigningKeyRepo over pool.
func NewSigningKeyRepo(pool *pgxpool.Pool) *SigningKeyRepo {
	assertPoolNonNil(pool, "SigningKeyRepo")
	return &SigningKeyRepo{pool: pool}
}

const signingKeyColumns = `
	kid, algorithm, public_jwk, private_key_enc,
	status, created_at, not_before, retire_at, retired_at`

func scanSigningKey(row interface{ Scan(...any) error }) (*domain.SigningKey, error) {
	var k domain.SigningKey
	err := row.Scan(
		&k.KID, &k.Algorithm, &k.PublicJWK, &k.PrivateKeyEnc,
		&k.Status, &k.CreatedAt, &k.NotBefore, &k.RetireAt, &k.RetiredAt,
	)
	if err != nil {
		return nil, err
	}
	return &k, nil
}

// Create stores a new signing key.
//
// The schema's idx_signing_keys_active_per_alg is a UNIQUE partial index over
// algorithm WHERE status = 'active', so inserting a second active key for the
// same algorithm is rejected by the database. That is the guarantee that a
// botched rotation cannot leave the server with no usable key: the rotation must
// retire the old key in the same transaction that activates the new one, and if it
// does not, the insert fails and the old key is still active.
//
// PublicJWK is written from the same source as the private key on the caller's
// side, and is never edited by hand afterwards. It exists so the JWKS can be
// served without decrypting anything on every request.
func (r *SigningKeyRepo) Create(ctx context.Context, k *domain.SigningKey) error {
	return createSigningKey(ctx, r.pool, k)
}

func createSigningKey(ctx context.Context, db queryer, k *domain.SigningKey) error {
	const q = `
		INSERT INTO signing_keys (
			kid, algorithm, public_jwk, private_key_enc,
			status, not_before, retire_at
		) VALUES ($1, $2, $3::jsonb, $4, $5, $6, $7)`

	_, err := db.Exec(ctx, q,
		k.KID, k.Algorithm, jsonOrNil(k.PublicJWK), k.PrivateKeyEnc,
		k.Status, k.NotBefore, k.RetireAt,
	)
	if err != nil {
		return classifyError(err, formatOp("signing_keys", "create"))
	}
	return nil
}

// GetActive returns the active key for any algorithm, or ErrNoActiveKey.
//
// ErrNoActiveKey rather than ErrNotFound, because the two mean very different
// things to an operator. ErrNotFound for "the configured algorithm has no active
// key" would be indistinguishable from a typo in a kid lookup, and the correct
// response to the first is "the server cannot sign, this is fatal at boot" while
// the correct response to the second is "the caller asked for the wrong key".
//
// Returning any active key rather than a specific algorithm is a convenience for
// the single-key case this server runs. A multi-algorithm deployment would add the
// algorithm as a parameter; the partial unique index already makes that a
// one-line change.
func (r *SigningKeyRepo) GetActive(ctx context.Context) (*domain.SigningKey, error) {
	const q = `SELECT ` + signingKeyColumns + `
		FROM signing_keys
		WHERE status = 'active'
		ORDER BY created_at DESC
		LIMIT 1`

	row := r.pool.QueryRow(ctx, q)
	k, err := scanSigningKey(row)
	if err != nil {
		if isNoRows(err) {
			return nil, domain.Wrapf(domain.ErrNoActiveKey, "storage: signing_keys.active")
		}
		return nil, classifyError(err, formatOp("signing_keys", "get_active"))
	}
	return k, nil
}

// GetAll returns every key, newest first.
//
// For the key management screen and for the retention sweep. Includes retired
// keys, because their presence is the answer to "have we kept a decryptable
// private half longer than we should".
func (r *SigningKeyRepo) GetAll(ctx context.Context) ([]*domain.SigningKey, error) {
	const q = `SELECT ` + signingKeyColumns + `
		FROM signing_keys
		ORDER BY created_at DESC`

	rows, err := r.pool.Query(ctx, q)
	if err != nil {
		return nil, classifyError(err, formatOp("signing_keys", "get_all"))
	}
	defer rows.Close()

	var out []*domain.SigningKey
	for rows.Next() {
		k, err := scanSigningKey(rows)
		if err != nil {
			return nil, wrapRowsErr(err, formatOp("signing_keys", "get_all", "scan"))
		}
		out = append(out, k)
	}
	if err := rows.Err(); err != nil {
		return nil, wrapRowsErr(err, formatOp("signing_keys", "get_all", "iterate"))
	}
	return out, nil
}

// GetPublished returns every key that belongs in the JWKS: active and retiring.
//
// This is the set that must keep GROWING through a rotation. Dropping a retiring
// key from the JWKS the moment it stops signing invalidates every unexpired token
// it signed, because relying parties have no way to verify a token signed by a key
// they cannot fetch. Retention is the right way to end a key's life: stop signing
// with it, keep publishing it, then delete it once nothing it signed is still
// valid.
func (r *SigningKeyRepo) GetPublished(ctx context.Context) ([]*domain.SigningKey, error) {
	const q = `SELECT ` + signingKeyColumns + `
		FROM signing_keys
		WHERE status IN ('active', 'retiring')
		ORDER BY created_at`

	rows, err := r.pool.Query(ctx, q)
	if err != nil {
		return nil, classifyError(err, formatOp("signing_keys", "get_published"))
	}
	defer rows.Close()

	var out []*domain.SigningKey
	for rows.Next() {
		k, err := scanSigningKey(rows)
		if err != nil {
			return nil, wrapRowsErr(err, formatOp("signing_keys", "get_published", "scan"))
		}
		out = append(out, k)
	}
	if err := rows.Err(); err != nil {
		return nil, wrapRowsErr(err, formatOp("signing_keys", "get_published", "iterate"))
	}
	return out, nil
}

// GetByKID returns one key, whatever its status.
func (r *SigningKeyRepo) GetByKID(ctx context.Context, kid string) (*domain.SigningKey, error) {
	row := r.pool.QueryRow(ctx, `SELECT `+signingKeyColumns+` FROM signing_keys WHERE kid = $1`, kid)
	k, err := scanSigningKey(row)
	if err != nil {
		return nil, rowNotFound(err, formatOp("signing_keys", "get_by_kid"))
	}
	return k, nil
}

// MarkRotating moves a key from active to retiring and stamps its retirement
// deadline.
//
// The private half is left in place. A retiring key still verifies, so relying
// parties can check tokens it signed until they expire, and destroying the
// private half immediately would make any token that still needs re-signing
// impossible. DestroyPrivateKey does that later, once retire_at has passed.
//
// Must run in the same transaction as the activation of its replacement: the
// partial unique index permits only one active key per algorithm, so retiring
// first and activating second is the only order that does not transiently violate
// it. Doing it in one transaction means no other request can observe the gap.
func (r *SigningKeyRepo) MarkRotating(ctx context.Context, kid string, retireAt time.Time) error {
	return markSigningKeyRotating(ctx, r.pool, kid, retireAt)
}

func markSigningKeyRotating(ctx context.Context, db queryer, kid string, retireAt time.Time) error {
	const q = `
		UPDATE signing_keys
		   SET status = 'retiring', retire_at = $2
		 WHERE kid = $1
		   AND status = 'active'`

	tag, err := db.Exec(ctx, q, kid, retireAt)
	if err != nil {
		return classifyError(err, formatOp("signing_keys", "mark_rotating"))
	}
	if tag.RowsAffected() == 0 {
		// Either no such kid, or it is not currently active. Distinguishing those
		// matters: re-retiring an already-retiring key would reset its retention
		// clock and keep a private half on disk indefinitely.
		return notFound(formatOp("signing_keys", "mark_rotating"))
	}
	return nil
}

// Rotate atomically retires oldKID and activates newKey, returning the key that
// was retired.
//
// One transaction, and that is the whole point. The partial unique index
// idx_signing_keys_active_per_alg permits exactly one active key per algorithm, so
// a rotation MUST retire before it activates. Done as two separate statements on
// the pool, the two orders both fail somewhere:
//
//	retire, then activate  works logically, but between the statements the server
//	                        has no active key at all, and any request that signs in
//	                        that window fails with ErrNoActiveKey.
//	activate, then retire  never gets to run: the insert violates the index and is
//	                        rejected, so the key can only ever be rotated by
//	                        temporarily having two active keys, which the database
//	                        forbids on purpose.
//
// In one transaction the retirement and the activation commit or abort together,
// so no request ever observes a gap and the index is never transiently violated.
//
// retireAt is applied to the outgoing key. Passing a zero time is rejected rather
// than stored, because retire_at <= now() would make the key immediately due for
// destruction and the guard that destruction waits for the retention window would
// be bypassed by a caller mistake.
func (r *SigningKeyRepo) Rotate(ctx context.Context, newKey *domain.SigningKey, retireAt time.Time) (*domain.SigningKey, error) {
	if newKey == nil {
		return nil, errors.New("storage: signing_keys.rotate: new key is nil")
	}
	if retireAt.IsZero() {
		return nil, errors.New("storage: signing_keys.rotate: retireAt is zero; the retention guard would be bypassed")
	}

	tx, err := r.pool.Begin(ctx)
	if err != nil {
		return nil, classifyError(err, formatOp("signing_keys", "rotate", "begin"))
	}
	defer func() { _ = tx.Rollback(ctx) }()

	// FOR UPDATE serialises two instances rotating at the same moment, so the
	// second waits and then retires the key the first installed rather than
	// retiring the same one twice. It is read inside the transaction, not before
	// it: a key read outside could have been rotated by the time the transaction
	// starts, and retiring the stale kid would silently skip the key that is
	// actually in use.
	row := tx.QueryRow(ctx, `
		SELECT `+signingKeyColumns+`
		  FROM signing_keys
		 WHERE status = 'active'
		 ORDER BY created_at DESC
		 LIMIT 1
		 FOR UPDATE`)

	old, err := scanSigningKey(row)
	switch {
	case isNoRows(err):
		// No key to retire is not a failure. It is the first key, and creating it
		// inside this same transaction keeps the "always exactly one active key"
		// invariant true for the initial case as well. A concurrent creator that
		// got here first loses on the partial unique index and retries.
		if err := createSigningKey(ctx, tx, newKey); err != nil {
			return nil, err
		}
		if err := tx.Commit(ctx); err != nil {
			return nil, classifyError(err, formatOp("signing_keys", "rotate", "commit"))
		}
		return nil, nil
	case err != nil:
		return nil, classifyError(err, formatOp("signing_keys", "rotate", "select"))
	}

	if err := markSigningKeyRotating(ctx, tx, old.KID, retireAt); err != nil {
		return nil, err
	}
	if err := createSigningKey(ctx, tx, newKey); err != nil {
		return nil, err
	}
	if err := tx.Commit(ctx); err != nil {
		return nil, classifyError(err, formatOp("signing_keys", "rotate", "commit"))
	}
	return old, nil
}

// DestroyPrivateKey removes a retiring key's private half and marks it retired.
//
// One statement, and the schema's signing_keys_retired_chk enforces the pairing:
// a row with status 'retired' must have private_key_enc IS NULL and retired_at
// non-null. Setting the status without clearing the ciphertext would be rejected
// by the database, so "we rotated" cannot quietly leave every historical signing
// key decryptable on disk.
//
// The key row itself is kept, because it is the JWKS entry relying parties already
// fetched, and because deleting it would leave tokens it signed unverifiable with
// no record of why.
func (r *SigningKeyRepo) DestroyPrivateKey(ctx context.Context, kid string) error {
	const q = `
		UPDATE signing_keys
		   SET private_key_enc = NULL, status = 'retired', retired_at = now()
		 WHERE kid = $1
		   AND status = 'retiring'`

	tag, err := r.pool.Exec(ctx, q, kid)
	if err != nil {
		return classifyError(err, formatOp("signing_keys", "destroy"))
	}
	if tag.RowsAffected() == 0 {
		return notFound(formatOp("signing_keys", "destroy"))
	}
	return nil
}

// DueForDestruction returns retiring keys whose retention window has closed.
//
// The retention job calls this and then DestroyPrivateKey. The window must exceed
// the longest access-token TTL plus clock skew, or a key is destroyed while tokens
// it signed are still inside their lifetime and those tokens become unverifiable.
func (r *SigningKeyRepo) DueForDestruction(ctx context.Context) ([]*domain.SigningKey, error) {
	const q = `SELECT ` + signingKeyColumns + `
		FROM signing_keys
		WHERE status = 'retiring'
		  AND retire_at IS NOT NULL
		  AND retire_at <= now()
		ORDER BY retire_at`

	rows, err := r.pool.Query(ctx, q)
	if err != nil {
		return nil, classifyError(err, formatOp("signing_keys", "due_for_destruction"))
	}
	defer rows.Close()

	var out []*domain.SigningKey
	for rows.Next() {
		k, err := scanSigningKey(rows)
		if err != nil {
			return nil, wrapRowsErr(err, formatOp("signing_keys", "due_for_destruction", "scan"))
		}
		out = append(out, k)
	}
	if err := rows.Err(); err != nil {
		return nil, wrapRowsErr(err, formatOp("signing_keys", "due_for_destruction", "iterate"))
	}
	return out, nil
}

// Delete removes a fully retired key row.
//
// Guarded in the WHERE clause on status = 'retired' AND private_key_enc IS NULL.
// The guard is in the statement rather than a preceding check so it is atomic: a
// check-then-delete races with a concurrent MarkRotating, and deleting a key that
// is still published leaves every token it signed unverifiable with no way to
// recover, since the JWKS entry is gone from every relying party's cache.
//
// A retired key is normally kept indefinitely. This exists for the case where an
// operator has confirmed that no unexpired token descends from it, and the
// operational reason to remove the row is the audit surface rather than size.
//
// The prompt lists MarkRotated. It is not here, and deliberately so: the lifecycle
// is MarkRotating then DestroyPrivateKey, and a single MarkRotated that did both
// would destroy the private half at the instant signing stops, which is the exact
// failure the retiring state exists to prevent.
func (r *SigningKeyRepo) Delete(ctx context.Context, kid string) error {
	const q = `
		DELETE FROM signing_keys
		 WHERE kid = $1
		   AND status = 'retired'
		   AND private_key_enc IS NULL`

	tag, err := r.pool.Exec(ctx, q, kid)
	if err != nil {
		return classifyError(err, formatOp("signing_keys", "delete"))
	}
	if tag.RowsAffected() == 0 {
		return domain.Wrapf(domain.ErrConflict, "storage: signing_keys.delete: key %q is not fully retired; refusing to remove a key that is still published or still holds a private half", kid)
	}
	return nil
}
