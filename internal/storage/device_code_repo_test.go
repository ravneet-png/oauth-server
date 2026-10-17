package storage

// Device Authorization Grant repository tests, against a live PostgreSQL.
//
// Skipped without TEST_DATABASE_URL, like the rest of this package. The
// interesting behaviour here is the database's: the single-use transitions, the
// conditional poll update and the CHECK constraints are all enforced in SQL, so a
// mock would only prove that the mock does what the test says.

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"

	"oauth-server/internal/domain"
)

// shortUserCode returns a canonical user_code of the right shape for the column.
//
// uniqueID is too long for VARCHAR(32), and the whole point of the column is that
// it holds a short, human-typed code, so it is generated the way the flow will
// generate it: display form normalised back to the stored form.
func shortUserCode(t *testing.T) string {
	t.Helper()
	code, err := domain.GenerateUserCode()
	if err != nil {
		t.Fatalf("GenerateUserCode: %v", err)
	}
	return domain.NormalizeUserCode(code)
}

// newPendingDeviceCode builds a valid pending row for the schema's constraints.
func newPendingDeviceCode(t *testing.T, clientID string) *domain.DeviceCode {
	t.Helper()
	return &domain.DeviceCode{
		DeviceCodeHash: uniqueHash(t, "devicecode"),
		UserCode:       shortUserCode(t),
		ClientID:       clientID,
		Scope:          []string{"openid", "email"},
		Status:         domain.DeviceStatusPending,
		Interval:       5 * time.Second,
		ExpiresAt:      time.Now().UTC().Add(10 * time.Minute),
	}
}

func TestDeviceCodeRepoCreateAndGetByHash(t *testing.T) {
	pool := newTestPool(t)
	repo := NewDeviceCodeRepo(pool)
	ctx := context.Background()

	clientID := uniqueID(t, "client")
	mustCreateClient(t, pool, newTestClient(t, clientID))

	want := newPendingDeviceCode(t, clientID)
	if err := repo.Create(ctx, want); err != nil {
		t.Fatalf("Create: %v", err)
	}

	got, err := repo.GetByHash(ctx, want.DeviceCodeHash)
	if err != nil {
		t.Fatalf("GetByHash: %v", err)
	}
	if got == nil {
		t.Fatal("GetByHash returned nil for a row that was just created")
	}
	if got.DeviceCodeHash != want.DeviceCodeHash || got.UserCode != want.UserCode || got.ClientID != clientID {
		t.Errorf("round trip mismatch: got %+v", got)
	}
	if !got.IsPending() {
		t.Errorf("status = %q, want %q", got.Status, domain.DeviceStatusPending)
	}
	if got.UserID != nil {
		t.Errorf("pending row carries a subject: %v", *got.UserID)
	}
	if len(got.Scope) != 2 || got.Scope[0] != "email" && got.Scope[0] != "openid" {
		t.Errorf("scope = %v, want the two stored values", got.Scope)
	}
	// The interval is stored as integer seconds and must come back as a Duration,
	// not as that integer interpreted as nanoseconds.
	if got.Interval != 5*time.Second {
		t.Errorf("interval = %v, want 5s", got.Interval)
	}
}

func TestDeviceCodeRepoGetByHashMissingReturnsNil(t *testing.T) {
	pool := newTestPool(t)
	repo := NewDeviceCodeRepo(pool)

	got, err := repo.GetByHash(context.Background(), uniqueHash(t, "absent"))
	if err != nil {
		t.Fatalf("GetByHash: %v", err)
	}
	if got != nil {
		t.Errorf("GetByHash on an absent hash = %+v, want nil", got)
	}
}

func TestDeviceCodeRepoGetLiveByUserCode(t *testing.T) {
	pool := newTestPool(t)
	repo := NewDeviceCodeRepo(pool)
	ctx := context.Background()

	clientID := uniqueID(t, "client")
	mustCreateClient(t, pool, newTestClient(t, clientID))

	live := newPendingDeviceCode(t, clientID)
	if err := repo.Create(ctx, live); err != nil {
		t.Fatalf("Create: %v", err)
	}

	got, err := repo.GetLiveByUserCode(ctx, live.UserCode)
	if err != nil {
		t.Fatalf("GetLiveByUserCode: %v", err)
	}
	if got == nil || got.DeviceCodeHash != live.DeviceCodeHash {
		t.Fatalf("GetLiveByUserCode did not find the live row: %+v", got)
	}

	// An expired row is not live, even though it is still present.
	expired := newPendingDeviceCode(t, clientID)
	expired.ExpiresAt = time.Now().UTC().Add(-time.Minute)
	if err := repo.Create(ctx, expired); err != nil {
		t.Fatalf("Create expired: %v", err)
	}
	got, err = repo.GetLiveByUserCode(ctx, expired.UserCode)
	if err != nil {
		t.Fatalf("GetLiveByUserCode expired: %v", err)
	}
	if got != nil {
		t.Errorf("GetLiveByUserCode returned an expired row: %+v", got)
	}

	// An unknown code is a miss, not an error.
	got, err = repo.GetLiveByUserCode(ctx, shortUserCode(t))
	if err != nil {
		t.Fatalf("GetLiveByUserCode unknown: %v", err)
	}
	if got != nil {
		t.Errorf("GetLiveByUserCode unknown = %+v, want nil", got)
	}
}

func TestDeviceCodeRepoApprove(t *testing.T) {
	pool := newTestPool(t)
	repo := NewDeviceCodeRepo(pool)
	ctx := context.Background()

	clientID := uniqueID(t, "client")
	userID := uniqueID(t, "user")
	mustCreateClient(t, pool, newTestClient(t, clientID))
	mustCreateUser(t, pool, userID, userID+"@example.com")

	dc := newPendingDeviceCode(t, clientID)
	if err := repo.Create(ctx, dc); err != nil {
		t.Fatalf("Create: %v", err)
	}

	got, err := repo.Approve(ctx, dc.DeviceCodeHash, userID)
	if err != nil {
		t.Fatalf("Approve: %v", err)
	}
	if got == nil {
		t.Fatal("Approve returned nil for a pending row")
	}
	if !got.IsApproved() {
		t.Errorf("status = %q, want %q", got.Status, domain.DeviceStatusApproved)
	}
	if got.UserID == nil || *got.UserID != userID {
		t.Errorf("approved row subject = %v, want %q", got.UserID, userID)
	}
	if got.ApprovedAt == nil {
		t.Error("approved row has no approved_at")
	}

	// A second approval is a miss: the decision is already made, and consent must
	// not be re-applied on a double submit of the form.
	again, err := repo.Approve(ctx, dc.DeviceCodeHash, userID)
	if err != nil {
		t.Fatalf("second Approve: %v", err)
	}
	if again != nil {
		t.Errorf("second Approve = %+v, want nil", again)
	}
}

func TestDeviceCodeRepoApproveRejectsExpiredAndNonPending(t *testing.T) {
	pool := newTestPool(t)
	repo := NewDeviceCodeRepo(pool)
	ctx := context.Background()

	clientID := uniqueID(t, "client")
	userID := uniqueID(t, "user")
	mustCreateClient(t, pool, newTestClient(t, clientID))
	mustCreateUser(t, pool, userID, userID+"@example.com")

	expired := newPendingDeviceCode(t, clientID)
	expired.ExpiresAt = time.Now().UTC().Add(-time.Minute)
	if err := repo.Create(ctx, expired); err != nil {
		t.Fatalf("Create expired: %v", err)
	}
	got, err := repo.Approve(ctx, expired.DeviceCodeHash, userID)
	if err != nil {
		t.Fatalf("Approve expired: %v", err)
	}
	if got != nil {
		t.Errorf("Approve of an expired row = %+v, want nil", got)
	}

	denied := newPendingDeviceCode(t, clientID)
	if err := repo.Create(ctx, denied); err != nil {
		t.Fatalf("Create: %v", err)
	}
	if err := repo.Deny(ctx, denied.DeviceCodeHash); err != nil {
		t.Fatalf("Deny: %v", err)
	}
	got, err = repo.Approve(ctx, denied.DeviceCodeHash, userID)
	if err != nil {
		t.Fatalf("Approve denied: %v", err)
	}
	if got != nil {
		t.Errorf("Approve of a denied row = %+v, want nil", got)
	}
}

func TestDeviceCodeRepoDeny(t *testing.T) {
	pool := newTestPool(t)
	repo := NewDeviceCodeRepo(pool)
	ctx := context.Background()

	clientID := uniqueID(t, "client")
	mustCreateClient(t, pool, newTestClient(t, clientID))

	dc := newPendingDeviceCode(t, clientID)
	if err := repo.Create(ctx, dc); err != nil {
		t.Fatalf("Create: %v", err)
	}
	if err := repo.Deny(ctx, dc.DeviceCodeHash); err != nil {
		t.Fatalf("Deny: %v", err)
	}
	got, err := repo.GetByHash(ctx, dc.DeviceCodeHash)
	if err != nil {
		t.Fatalf("GetByHash: %v", err)
	}
	if got == nil || !got.IsDenied() {
		t.Fatalf("status after Deny = %+v, want denied", got)
	}

	// Denying again is a no-op, not an error.
	if err := repo.Deny(ctx, dc.DeviceCodeHash); err != nil {
		t.Fatalf("second Deny: %v", err)
	}
}

func TestDeviceCodeRepoRecordPoll(t *testing.T) {
	pool := newTestPool(t)
	repo := NewDeviceCodeRepo(pool)
	ctx := context.Background()

	clientID := uniqueID(t, "client")
	mustCreateClient(t, pool, newTestClient(t, clientID))

	dc := newPendingDeviceCode(t, clientID)
	if err := repo.Create(ctx, dc); err != nil {
		t.Fatalf("Create: %v", err)
	}

	// First poll: last_polled_at is NULL, so it is admitted.
	ok, err := repo.RecordPoll(ctx, dc.DeviceCodeHash)
	if err != nil {
		t.Fatalf("RecordPoll first: %v", err)
	}
	if !ok {
		t.Error("first poll was refused; a null last_polled_at must admit")
	}

	// Second poll immediately: inside the interval, so refused (slow_down).
	ok, err = repo.RecordPoll(ctx, dc.DeviceCodeHash)
	if err != nil {
		t.Fatalf("RecordPoll second: %v", err)
	}
	if ok {
		t.Error("poll inside the interval was admitted; want slow_down")
	}

	// Rewind last_polled_at past the interval and poll again: admitted.
	if _, err := pool.Exec(ctx,
		`UPDATE device_codes SET last_polled_at = now() - interval '1 minute' WHERE device_code_hash = $1`,
		dc.DeviceCodeHash); err != nil {
		t.Fatalf("rewind last_polled_at: %v", err)
	}
	ok, err = repo.RecordPoll(ctx, dc.DeviceCodeHash)
	if err != nil {
		t.Fatalf("RecordPoll after interval: %v", err)
	}
	if !ok {
		t.Error("poll after the interval elapsed was refused")
	}

	// Terminal states are never admitted, and are not an error.
	if err := repo.Deny(ctx, dc.DeviceCodeHash); err != nil {
		t.Fatalf("Deny: %v", err)
	}
	ok, err = repo.RecordPoll(ctx, dc.DeviceCodeHash)
	if err != nil {
		t.Fatalf("RecordPoll denied: %v", err)
	}
	if ok {
		t.Error("poll on a denied row was admitted")
	}

	// An absent row is a refused poll, not an error.
	ok, err = repo.RecordPoll(ctx, uniqueHash(t, "absent"))
	if err != nil {
		t.Fatalf("RecordPoll absent: %v", err)
	}
	if ok {
		t.Error("poll on an absent row was admitted")
	}
}

func TestDeviceCodeRepoBumpInterval(t *testing.T) {
	pool := newTestPool(t)
	repo := NewDeviceCodeRepo(pool)
	ctx := context.Background()

	clientID := uniqueID(t, "client")
	mustCreateClient(t, pool, newTestClient(t, clientID))

	dc := newPendingDeviceCode(t, clientID)
	if err := repo.Create(ctx, dc); err != nil {
		t.Fatalf("Create: %v", err)
	}
	if err := repo.BumpInterval(ctx, dc.DeviceCodeHash, 5*time.Second); err != nil {
		t.Fatalf("BumpInterval: %v", err)
	}
	got, err := repo.GetByHash(ctx, dc.DeviceCodeHash)
	if err != nil {
		t.Fatalf("GetByHash: %v", err)
	}
	if got == nil || got.Interval != 10*time.Second {
		t.Fatalf("interval after bump = %v, want 10s", got.Interval)
	}
}

func TestDeviceCodeRepoConsume(t *testing.T) {
	pool := newTestPool(t)
	repo := NewDeviceCodeRepo(pool)
	ctx := context.Background()

	clientID := uniqueID(t, "client")
	userID := uniqueID(t, "user")
	mustCreateClient(t, pool, newTestClient(t, clientID))
	mustCreateUser(t, pool, userID, userID+"@example.com")

	// A pending row is not redeemable.
	pending := newPendingDeviceCode(t, clientID)
	if err := repo.Create(ctx, pending); err != nil {
		t.Fatalf("Create: %v", err)
	}
	got, err := repo.Consume(ctx, pending.DeviceCodeHash)
	if err != nil {
		t.Fatalf("Consume pending: %v", err)
	}
	if got != nil {
		t.Errorf("Consume of a pending row = %+v, want nil", got)
	}

	// Approve then consume: one row, status consumed, subject preserved.
	if _, err := repo.Approve(ctx, pending.DeviceCodeHash, userID); err != nil {
		t.Fatalf("Approve: %v", err)
	}
	got, err = repo.Consume(ctx, pending.DeviceCodeHash)
	if err != nil {
		t.Fatalf("Consume approved: %v", err)
	}
	if got == nil {
		t.Fatal("Consume of an approved row returned nil")
	}
	if !got.IsConsumed() {
		t.Errorf("status = %q, want %q", got.Status, domain.DeviceStatusConsumed)
	}
	if got.UserID == nil || *got.UserID != userID {
		t.Errorf("consumed row subject = %v, want %q", got.UserID, userID)
	}
	if got.ConsumedAt == nil {
		t.Error("consumed row has no consumed_at")
	}

	// The single-use guard: a second consume is a miss.
	again, err := repo.Consume(ctx, pending.DeviceCodeHash)
	if err != nil {
		t.Fatalf("second Consume: %v", err)
	}
	if again != nil {
		t.Errorf("second Consume = %+v, want nil", again)
	}
}

func TestDeviceCodeRepoDeleteExpired(t *testing.T) {
	pool := newTestPool(t)
	repo := NewDeviceCodeRepo(pool)
	ctx := context.Background()

	clientID := uniqueID(t, "client")
	mustCreateClient(t, pool, newTestClient(t, clientID))

	expired := newPendingDeviceCode(t, clientID)
	expired.ExpiresAt = time.Now().UTC().Add(-time.Minute)
	if err := repo.Create(ctx, expired); err != nil {
		t.Fatalf("Create expired: %v", err)
	}
	live := newPendingDeviceCode(t, clientID)
	if err := repo.Create(ctx, live); err != nil {
		t.Fatalf("Create live: %v", err)
	}

	n, err := repo.DeleteExpired(ctx)
	if err != nil {
		t.Fatalf("DeleteExpired: %v", err)
	}
	if n < 1 {
		t.Errorf("DeleteExpired removed %d rows, want at least 1", n)
	}

	gotExpired, err := repo.GetByHash(ctx, expired.DeviceCodeHash)
	if err != nil {
		t.Fatalf("GetByHash expired: %v", err)
	}
	if gotExpired != nil {
		t.Error("DeleteExpired left an expired row behind")
	}
	gotLive, err := repo.GetByHash(ctx, live.DeviceCodeHash)
	if err != nil {
		t.Fatalf("GetByHash live: %v", err)
	}
	if gotLive == nil {
		t.Error("DeleteExpired removed a live row")
	}
}

func TestDeviceCodeRepoDeleteExpiredByUserCode(t *testing.T) {
	pool := newTestPool(t)
	repo := NewDeviceCodeRepo(pool)
	ctx := context.Background()

	clientID := uniqueID(t, "client")
	mustCreateClient(t, pool, newTestClient(t, clientID))

	expired := newPendingDeviceCode(t, clientID)
	expired.ExpiresAt = time.Now().UTC().Add(-time.Minute)
	if err := repo.Create(ctx, expired); err != nil {
		t.Fatalf("Create expired: %v", err)
	}
	live := newPendingDeviceCode(t, clientID)
	if err := repo.Create(ctx, live); err != nil {
		t.Fatalf("Create live: %v", err)
	}

	if err := repo.DeleteExpiredByUserCode(ctx, expired.UserCode); err != nil {
		t.Fatalf("DeleteExpiredByUserCode: %v", err)
	}
	gotExpired, err := repo.GetByHash(ctx, expired.DeviceCodeHash)
	if err != nil {
		t.Fatalf("GetByHash expired: %v", err)
	}
	if gotExpired != nil {
		t.Error("DeleteExpiredByUserCode left the expired row behind")
	}
	gotLive, err := repo.GetByHash(ctx, live.DeviceCodeHash)
	if err != nil {
		t.Fatalf("GetByHash live: %v", err)
	}
	if gotLive == nil {
		t.Error("DeleteExpiredByUserCode removed a live row")
	}
}

// assertRejected runs a statement that must be refused by a constraint, and
// reports the SQLSTATE so a failure names the wrong reason rather than just
// "an error occurred".
func assertRejected(t *testing.T, pool *pgxpool.Pool, wantState, label, query string, args ...any) {
	t.Helper()
	_, err := pool.Exec(context.Background(), query, args...)
	if err == nil {
		t.Errorf("%s was ACCEPTED but should have been rejected", label)
		return
	}
	var pgErr *pgconn.PgError
	if errors.As(err, &pgErr) && pgErr.Code != wantState {
		t.Errorf("%s rejected with SQLSTATE %s, want %s", label, pgErr.Code, wantState)
	}
}

func TestDeviceCodeConstraints(t *testing.T) {
	pool := newTestPool(t)
	repo := NewDeviceCodeRepo(pool)
	ctx := context.Background()

	clientID := uniqueID(t, "client")
	userID := uniqueID(t, "user")
	mustCreateClient(t, pool, newTestClient(t, clientID))
	mustCreateUser(t, pool, userID, userID+"@example.com")

	const insert = `
		INSERT INTO device_codes
		    (device_code_hash, user_code, client_id, status, user_id,
		     interval_seconds, expires_at, approved_at)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8)`

	// A pending request must not name a subject.
	assertRejected(t, pool, sqlStateCheckViolation, "pending device code with a subject",
		insert, uniqueHash(t, "bad"), shortUserCode(t), clientID, "pending", userID, 5, time.Now().Add(time.Hour), nil)

	// An approved request must name a subject.
	assertRejected(t, pool, sqlStateCheckViolation, "approved device code with no subject",
		insert, uniqueHash(t, "bad"), shortUserCode(t), clientID, "approved", nil, 5, time.Now().Add(time.Hour), time.Now())

	// An unknown status is refused.
	assertRejected(t, pool, sqlStateCheckViolation, "unknown device code status",
		insert, uniqueHash(t, "bad"), shortUserCode(t), clientID, "redeemed", nil, 5, time.Now().Add(time.Hour), nil)

	// The poll floor must be positive.
	assertRejected(t, pool, sqlStateCheckViolation, "non-positive device code interval",
		insert, uniqueHash(t, "bad"), shortUserCode(t), clientID, "pending", nil, 0, time.Now().Add(time.Hour), nil)

	// A live user_code is unique, but a finished request frees it for reuse.
	live := newPendingDeviceCode(t, clientID)
	if err := repo.Create(ctx, live); err != nil {
		t.Fatalf("Create: %v", err)
	}
	assertRejected(t, pool, sqlStateUniqueViolation, "duplicate live user_code",
		insert, uniqueHash(t, "bad"), live.UserCode, clientID, "pending", nil, 5, time.Now().Add(time.Hour), nil)

	if _, err := pool.Exec(ctx, insert,
		uniqueHash(t, "reuse"), live.UserCode, clientID, "consumed", userID, 5,
		time.Now().Add(time.Hour), time.Now()); err != nil {
		t.Errorf("a consumed row should free its user_code for reuse: %v", err)
	}
}

// TestUserRepoDeleteClearsDeviceCodes: an approved device code references the user
// with ON DELETE RESTRICT, so erasure must clear it. This is the property that
// makes a forgotten table in the erasure teardown fail loudly rather than destroy
// the account halfway.
func TestUserRepoDeleteClearsDeviceCodes(t *testing.T) {
	pool := newTestPool(t)
	repo := NewDeviceCodeRepo(pool)
	ctx := context.Background()

	clientID := uniqueID(t, "client")
	userID := uniqueID(t, "user")
	mustCreateClient(t, pool, newTestClient(t, clientID))
	mustCreateUser(t, pool, userID, userID+"@example.com")

	approved := newPendingDeviceCode(t, clientID)
	if err := repo.Create(ctx, approved); err != nil {
		t.Fatalf("Create: %v", err)
	}
	if _, err := repo.Approve(ctx, approved.DeviceCodeHash, userID); err != nil {
		t.Fatalf("Approve: %v", err)
	}

	// A pending request with no subject does not reference the user and is not
	// erasure's business; it must survive the delete.
	pending := newPendingDeviceCode(t, clientID)
	if err := repo.Create(ctx, pending); err != nil {
		t.Fatalf("Create pending: %v", err)
	}

	if err := NewUserRepo(pool).Delete(ctx, userID); err != nil {
		t.Fatalf("Delete user with an approved device code: %v", err)
	}

	gotApproved, err := repo.GetByHash(ctx, approved.DeviceCodeHash)
	if err != nil {
		t.Fatalf("GetByHash approved: %v", err)
	}
	if gotApproved != nil {
		t.Error("erasure left an approved device code behind")
	}
	gotPending, err := repo.GetByHash(ctx, pending.DeviceCodeHash)
	if err != nil {
		t.Fatalf("GetByHash pending: %v", err)
	}
	if gotPending == nil {
		t.Error("erasure removed a device code that had no subject")
	}
}
