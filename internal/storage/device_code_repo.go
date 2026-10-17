package storage

// Device Authorization Grant persistence (RFC 8628). The device_code is a bearer
// credential carried by the device, so only its digest is stored; the user_code
// is the human-typed handle the verification page looks up.

import (
	"context"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	"oauth-server/internal/domain"
)

// DeviceCodeRepo reads and writes the device_codes table.
type DeviceCodeRepo struct {
	pool *pgxpool.Pool
}

// NewDeviceCodeRepo builds a DeviceCodeRepo over pool.
func NewDeviceCodeRepo(pool *pgxpool.Pool) *DeviceCodeRepo {
	assertPoolNonNil(pool, "DeviceCodeRepo")
	return &DeviceCodeRepo{pool: pool}
}

const deviceCodeColumns = `device_code_hash, user_code, client_id, scope, status,
	user_id, interval_seconds, last_polled_at, created_at, expires_at, approved_at, consumed_at`

func scanDeviceCode(row interface{ Scan(...any) error }) (*domain.DeviceCode, error) {
	var (
		d           domain.DeviceCode
		intervalSec int
	)
	err := row.Scan(
		&d.DeviceCodeHash, &d.UserCode, &d.ClientID, &d.Scope, &d.Status,
		&d.UserID, &intervalSec, &d.LastPolledAt, &d.CreatedAt, &d.ExpiresAt,
		&d.ApprovedAt, &d.ConsumedAt,
	)
	if err != nil {
		return nil, err
	}
	d.Interval = time.Duration(intervalSec) * time.Second
	return &d, nil
}

// Create stores a new device authorization in the pending state.
//
// A unique violation on the live user_code index surfaces as ErrConflict with the
// constraint name; the caller retries with a fresh code, after clearing any
// expired row that is holding it.
func (r *DeviceCodeRepo) Create(ctx context.Context, d *domain.DeviceCode) error {
	scope := d.Scope
	if scope == nil {
		scope = []string{}
	}

	const q = `
		INSERT INTO device_codes
		    (device_code_hash, user_code, client_id, scope, status,
		     interval_seconds, expires_at)
		VALUES ($1, $2, $3, $4, $5, $6, $7)`

	_, err := r.pool.Exec(ctx, q,
		d.DeviceCodeHash, d.UserCode, d.ClientID, scope,
		d.Status, int(d.Interval.Seconds()), d.ExpiresAt)
	if err != nil {
		return classifyError(err, formatOp("device_codes", "create"))
	}
	return nil
}

// GetByHash reads a device code by the digest of its device_code. Returns
// (nil, nil) when no row matches, which the caller treats as expired_token.
func (r *DeviceCodeRepo) GetByHash(ctx context.Context, hash string) (*domain.DeviceCode, error) {
	const q = `SELECT ` + deviceCodeColumns + ` FROM device_codes WHERE device_code_hash = $1`

	d, err := scanDeviceCode(r.pool.QueryRow(ctx, q, hash))
	if err != nil {
		if isNoRows(err) {
			return nil, nil
		}
		return nil, classifyError(err, formatOp("device_codes", "get_by_hash"))
	}
	return d, nil
}

// GetLiveByUserCode reads the pending or approved device code addressed by a
// canonical user_code, ignoring any that has expired. Returns (nil, nil) when
// there is no such live row.
//
// Only live rows are returned so an expired request cannot be approved on the
// verification page, and a code whose request is finished does not block reuse.
func (r *DeviceCodeRepo) GetLiveByUserCode(ctx context.Context, userCode string) (*domain.DeviceCode, error) {
	const q = `
		SELECT ` + deviceCodeColumns + `
		  FROM device_codes
		 WHERE user_code = $1
		   AND status IN ('pending','approved')
		   AND expires_at > now()`

	d, err := scanDeviceCode(r.pool.QueryRow(ctx, q, userCode))
	if err != nil {
		if isNoRows(err) {
			return nil, nil
		}
		return nil, classifyError(err, formatOp("device_codes", "get_live_by_user_code"))
	}
	return d, nil
}

// Approve moves a pending device code to approved and binds the user. Returns
// (nil, nil) if the code was already decided or has expired, so a double submit
// of the consent form cannot approve twice.
func (r *DeviceCodeRepo) Approve(ctx context.Context, hash, userID string) (*domain.DeviceCode, error) {
	const q = `
		UPDATE device_codes
		   SET status = 'approved', user_id = $2, approved_at = now()
		 WHERE device_code_hash = $1
		   AND status = 'pending'
		   AND expires_at > now()
		RETURNING ` + deviceCodeColumns

	d, err := scanDeviceCode(r.pool.QueryRow(ctx, q, hash, userID))
	if err != nil {
		if isNoRows(err) {
			return nil, nil
		}
		return nil, classifyError(err, formatOp("device_codes", "approve"))
	}
	return d, nil
}

// Deny records that the user refused the request. A no-op when the code is not
// pending: the only correct response to a second denial is the same denial.
func (r *DeviceCodeRepo) Deny(ctx context.Context, hash string) error {
	const q = `
		UPDATE device_codes
		   SET status = 'denied'
		 WHERE device_code_hash = $1
		   AND status = 'pending'`

	if _, err := r.pool.Exec(ctx, q, hash); err != nil {
		return classifyError(err, formatOp("device_codes", "deny"))
	}
	return nil
}

// RecordPoll stamps a poll and reports whether it arrived within the advertised
// interval.
//
// A false return is the slow_down condition of RFC 8628 section 3.5. It is one
// conditional UPDATE rather than a read-then-write so two concurrent polls cannot
// both see an elapsed interval and both be admitted; the row is only stamped by
// the statement that passed the predicate.
func (r *DeviceCodeRepo) RecordPoll(ctx context.Context, hash string) (bool, error) {
	const q = `
		UPDATE device_codes
		   SET last_polled_at = now()
		 WHERE device_code_hash = $1
		   AND status = 'pending'
		   AND (last_polled_at IS NULL
		        OR last_polled_at + make_interval(secs => interval_seconds) <= now())
		RETURNING device_code_hash`

	var got string
	if err := r.pool.QueryRow(ctx, q, hash).Scan(&got); err != nil {
		if isNoRows(err) {
			return false, nil
		}
		return false, classifyError(err, formatOp("device_codes", "record_poll"))
	}
	return true, nil
}

// BumpInterval widens the poll interval recorded on a pending code, as RFC 8628
// section 3.5 instructs after a slow_down, so a misbehaving client does not keep
// hitting the floor.
func (r *DeviceCodeRepo) BumpInterval(ctx context.Context, hash string, add time.Duration) error {
	const q = `
		UPDATE device_codes
		   SET interval_seconds = interval_seconds + $2
		 WHERE device_code_hash = $1
		   AND status = 'pending'`

	if _, err := r.pool.Exec(ctx, q, hash, int(add.Seconds())); err != nil {
		return classifyError(err, formatOp("device_codes", "bump_interval"))
	}
	return nil
}

// Consume atomically redeems an approved device code, returning the claimed row
// or (nil, nil) when it was already consumed or was never approved.
//
// The approved -> consumed transition is the single-use guard: two concurrent
// polls of the same approved code produce one row here and one nil, so exactly
// one token set is minted.
func (r *DeviceCodeRepo) Consume(ctx context.Context, hash string) (*domain.DeviceCode, error) {
	const q = `
		UPDATE device_codes
		   SET status = 'consumed', consumed_at = now()
		 WHERE device_code_hash = $1
		   AND status = 'approved'
		   AND expires_at > now()
		RETURNING ` + deviceCodeColumns

	d, err := scanDeviceCode(r.pool.QueryRow(ctx, q, hash))
	if err != nil {
		if isNoRows(err) {
			return nil, nil
		}
		return nil, classifyError(err, formatOp("device_codes", "consume"))
	}
	return d, nil
}

// DeleteExpiredByUserCode removes an expired row holding userCode so a fresh
// code can reuse it. Called only after a unique violation on Create, which can
// only mean an un-reaped expired row still holds the code.
func (r *DeviceCodeRepo) DeleteExpiredByUserCode(ctx context.Context, userCode string) error {
	const q = `DELETE FROM device_codes WHERE user_code = $1 AND expires_at < now()`

	if _, err := r.pool.Exec(ctx, q, userCode); err != nil {
		return classifyError(err, formatOp("device_codes", "delete_expired_by_user_code"))
	}
	return nil
}

// DeleteExpired removes lapsed device codes in one bounded batch.
func (r *DeviceCodeRepo) DeleteExpired(ctx context.Context) (int, error) {
	const q = `
		DELETE FROM device_codes
		 WHERE device_code_hash IN (
		     SELECT device_code_hash FROM device_codes
		      WHERE expires_at < now()
		      LIMIT $1
		 )`

	tag, err := r.pool.Exec(ctx, q, reaperBatch)
	if err != nil {
		return 0, classifyError(err, formatOp("device_codes", "delete_expired"))
	}
	return int(tag.RowsAffected()), nil
}
