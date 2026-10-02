// Key rotation against a real database. The reason these are here and not unit tests
// with a mocked repository is that the invariant under test IS a database invariant:
// signing_keys permits exactly one active row per algorithm, enforced by a partial
// unique index. A mock cannot express that constraint, and the bug this suite was
// written for — persisting a replacement as active before retiring the old one — is
// invisible until the index rejects the insert.

package storage

import (
	"context"
	"errors"
	"fmt"
	"sync/atomic"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	"oauth-server/internal/domain"
)

// clearSigningKeys empties the signing_keys table.
//
// These tests each need to observe the empty case, and the table holds exactly one
// active key per algorithm across the whole suite. Unlike the other repository tests,
// which isolate themselves with unique IDs and never count rows table-wide, these
// cannot: "there is no active key" is the precondition several of them assert, and no
// unique ID can make that true when a neighbour has installed a key.
//
// Safe because Go runs tests in a package sequentially unless they call t.Parallel,
// and nothing here does.
func clearSigningKeys(t *testing.T, pool *pgxpool.Pool) {
	t.Helper()
	if _, err := pool.Exec(context.Background(), `DELETE FROM signing_keys`); err != nil {
		t.Fatalf("clear signing_keys: %v", err)
	}
}

// keyKID builds a kid that fits the column.
//
// kid is varchar(64) and t.Name() is long enough to overflow it once the prefix is
// added, so the test name is abbreviated and the uniqueness comes from a counter and
// the process-scoped timestamp rather than the full name.
func keyKID(t *testing.T, prefix string) string {
	t.Helper()
	return fmt.Sprintf("%s%d", prefix, nextKeySeq())
}

var keySeq atomic.Int64

func nextKeySeq() int64 { return keySeq.Add(1) }

// makeSigningKey builds a syntactically valid key row. The JWK and ciphertext are
// opaque to these tests because rotation never decrypts; what matters is the kid,
// algorithm and status pairing.
func makeSigningKey(t *testing.T, kid string) *domain.SigningKey {
	t.Helper()
	now := time.Now().UTC()
	return &domain.SigningKey{
		KID:           kid,
		Algorithm:     domain.AlgRS256,
		PublicJWK:     []byte(`{"kty":"RSA","kid":"` + kid + `","alg":"RS256","n":"AQAB","e":"AQAB"}`),
		PrivateKeyEnc: []byte("encrypted-" + kid),
		Status:        domain.KeyStatusActive,
		CreatedAt:     now,
		NotBefore:     now,
	}
}

func TestGenerateAndStoreIsRefusedWhenAKeyIsAlreadyActive(t *testing.T) {
	pool := newTestPool(t)
	ctx := context.Background()
	repo := NewSigningKeyRepo(pool)

	clearSigningKeys(t, pool)

	first := makeSigningKey(t, keyKID(t, "first-"))
	if err := repo.Create(ctx, first); err != nil {
		t.Fatalf("create first key: %v", err)
	}

	second := makeSigningKey(t, keyKID(t, "second-"))
	// This is the failure the rotator used to hit on every tick. Asserted directly so
	// the constraint's behaviour is pinned: if this ever starts succeeding, the
	// rotator's generate-then-rotate shape became safe by accident rather than by
	// design, and something else is relying on the wrong invariant.
	err := repo.Create(ctx, second)
	if !errors.Is(err, domain.ErrConflict) {
		t.Fatalf("second active key: error = %v, want domain.ErrConflict", err)
	}
}

func TestRotateSwapsTheActiveKeyAtomically(t *testing.T) {
	pool := newTestPool(t)
	ctx := context.Background()
	repo := NewSigningKeyRepo(pool)
	clearSigningKeys(t, pool)

	oldKey := makeSigningKey(t, keyKID(t, "old-"))
	if err := repo.Create(ctx, oldKey); err != nil {
		t.Fatalf("create old key: %v", err)
	}

	// The replacement carries status active, exactly as Generate would produce it. It
	// is legal here only because it is written in the same transaction that flips the
	// old key to retiring.
	newKey := makeSigningKey(t, keyKID(t, "new-"))
	retireAt := time.Now().UTC().Add(24 * time.Hour)

	retired, err := repo.Rotate(ctx, newKey, retireAt)
	if err != nil {
		t.Fatalf("Rotate: %v", err)
	}
	if retired == nil {
		t.Fatal("Rotate returned no retired key, want the key it displaced")
	}
	if retired.KID != oldKey.KID {
		t.Errorf("retired kid = %q, want %q", retired.KID, oldKey.KID)
	}

	// The invariant that matters: exactly one active key, and it is the new one.
	active, err := repo.GetActive(ctx)
	if err != nil {
		t.Fatalf("GetActive: %v", err)
	}
	if active.KID != newKey.KID {
		t.Errorf("active kid = %q, want %q", active.KID, newKey.KID)
	}

	// And the old key is retiring with a retention deadline, not retired outright.
	// Tokens it signed are still inside their TTL, so its public half has to stay
	// published while its private half becomes destroyable.
	stored, err := repo.GetByKID(ctx, oldKey.KID)
	if err != nil {
		t.Fatalf("GetByKID(old): %v", err)
	}
	if stored.Status != domain.KeyStatusRetiring {
		t.Errorf("old key status = %q, want %q", stored.Status, domain.KeyStatusRetiring)
	}
	if stored.RetireAt == nil {
		t.Error("old key has no retire_at; rotation would destroy it while its tokens verify")
	}
}

func TestRotateOnAnEmptyTableCreatesTheFirstKey(t *testing.T) {
	pool := newTestPool(t)
	ctx := context.Background()
	repo := NewSigningKeyRepo(pool)

	clearSigningKeys(t, pool)

	first := makeSigningKey(t, keyKID(t, "first-"))
	retireAt := time.Now().UTC().Add(24 * time.Hour)

	// No active key exists, so this is the boot path. It must not fail with "nothing
	// to rotate": creating the first key inside Rotate keeps the exactly-one-active
	// invariant true from the very first row rather than only after the second.
	retired, err := repo.Rotate(ctx, first, retireAt)
	if err != nil {
		t.Fatalf("Rotate on empty table: %v", err)
	}
	if retired != nil {
		t.Errorf("Rotate on empty table retired %q, want nil", retired.KID)
	}

	active, err := repo.GetActive(ctx)
	if err != nil {
		t.Fatalf("GetActive: %v", err)
	}
	if active.KID != first.KID {
		t.Errorf("active kid = %q, want %q", active.KID, first.KID)
	}
}

func TestRotateRefusesAZeroRetention(t *testing.T) {
	pool := newTestPool(t)
	ctx := context.Background()
	repo := NewSigningKeyRepo(pool)

	clearSigningKeys(t, pool)

	existing := makeSigningKey(t, keyKID(t, "existing-"))
	if err := repo.Create(ctx, existing); err != nil {
		t.Fatalf("create key: %v", err)
	}

	// A zero retire_at means DueForDestruction's `retire_at <= now()` matches
	// immediately, so the rotation would publish a replacement and destroy the old
	// key's private half in the same tick. Refused rather than honoured.
	if _, err := repo.Rotate(ctx, makeSigningKey(t, keyKID(t, "new-")), time.Time{}); err == nil {
		t.Fatal("Rotate with a zero retire_at = nil error, want a refusal")
	}

	// The existing key must be untouched by the refusal.
	active, err := repo.GetActive(ctx)
	if err != nil {
		t.Fatalf("GetActive: %v", err)
	}
	if active.KID != existing.KID {
		t.Errorf("active kid = %q, want the pre-rotation key %q", active.KID, existing.KID)
	}
}

func TestRotateRefusesANilReplacement(t *testing.T) {
	pool := newTestPool(t)
	ctx := context.Background()
	repo := NewSigningKeyRepo(pool)

	if _, err := repo.Rotate(ctx, nil, time.Now().UTC().Add(time.Hour)); err == nil {
		t.Fatal("Rotate with a nil key = nil error, want a refusal")
	}
}

func TestDestroyPrivateKeyClearsTheCiphertext(t *testing.T) {
	pool := newTestPool(t)
	ctx := context.Background()
	repo := NewSigningKeyRepo(pool)

	clearSigningKeys(t, pool)

	oldKey := makeSigningKey(t, keyKID(t, "old-"))
	if err := repo.Create(ctx, oldKey); err != nil {
		t.Fatalf("create old key: %v", err)
	}
	// A retention window in the future: the schema's signing_keys_timing_chk refuses a
	// retire_at in the past, which is the right rule — a rotation may not destroy the
	// outgoing key's private half on the spot — but it means the clock has to be moved
	// forward to reach the due state.
	if _, err := repo.Rotate(ctx, makeSigningKey(t, keyKID(t, "new-")),
		time.Now().UTC().Add(24*time.Hour)); err != nil {
		t.Fatalf("Rotate: %v", err)
	}
	// Backdate created_at as well as retire_at. The constraint is retire_at >=
	// created_at, so moving only retire_at into the past is rejected, and that
	// rejection is itself worth having: a rotation cannot schedule a key's private
	// half for destruction before the key existed.
	if _, err := pool.Exec(ctx,
		`UPDATE signing_keys
		    SET created_at = now() - interval '2 days',
		        retire_at  = now() - interval '1 second'
		  WHERE kid = $1`,
		oldKey.KID); err != nil {
		t.Fatalf("advance old key's retire_at: %v", err)
	}

	// Retention has now elapsed, so the key is due.
	due, err := repo.DueForDestruction(ctx)
	if err != nil {
		t.Fatalf("DueForDestruction: %v", err)
	}
	var sawOld bool
	for _, k := range due {
		if k.KID == oldKey.KID {
			sawOld = true
		}
	}
	if !sawOld {
		t.Fatalf("old key is not due for destruction; got %d due keys", len(due))
	}

	if err := repo.DestroyPrivateKey(ctx, oldKey.KID); err != nil {
		t.Fatalf("DestroyPrivateKey: %v", err)
	}

	// The private half must be gone from disk. The schema's retired-row check also
	// enforces this pairing, so a successful update means the ciphertext was cleared.
	destroyed, err := repo.GetByKID(ctx, oldKey.KID)
	if err != nil {
		t.Fatalf("GetByKID: %v", err)
	}
	if destroyed.PrivateKeyEnc != nil {
		t.Error("private key ciphertext survived destruction")
	}
	if destroyed.Status != domain.KeyStatusRetired {
		t.Errorf("status = %q, want %q", destroyed.Status, domain.KeyStatusRetired)
	}

	// The row itself survives: it is the JWKS entry relying parties already fetched,
	// and deleting it would leave tokens it signed unverifiable with no record why.
	if destroyed.PublicJWK == nil {
		t.Error("public JWK was destroyed with the private half; published tokens stop verifying")
	}
}

func TestGetPublishedExcludesRetiredKeysButKeepsRetiringOnes(t *testing.T) {
	pool := newTestPool(t)
	ctx := context.Background()
	repo := NewSigningKeyRepo(pool)

	clearSigningKeys(t, pool)

	oldKey := makeSigningKey(t, keyKID(t, "old-"))
	if err := repo.Create(ctx, oldKey); err != nil {
		t.Fatalf("create old key: %v", err)
	}
	newKey := makeSigningKey(t, keyKID(t, "new-"))
	if _, err := repo.Rotate(ctx, newKey, time.Now().UTC().Add(24*time.Hour)); err != nil {
		t.Fatalf("Rotate: %v", err)
	}

	// While retiring, the old key must stay published: tokens it signed are still
	// valid and a relying party holding only that kid has to be able to verify them.
	published, err := repo.GetPublished(ctx)
	if err != nil {
		t.Fatalf("GetPublished: %v", err)
	}
	var sawRetiring bool
	for _, k := range published {
		if k.KID == oldKey.KID {
			sawRetiring = true
		}
	}
	if !sawRetiring {
		t.Error("a retiring key is absent from the published set; its live tokens become unverifiable")
	}

	if err := repo.DestroyPrivateKey(ctx, oldKey.KID); err != nil {
		t.Fatalf("DestroyPrivateKey: %v", err)
	}

	published, err = repo.GetPublished(ctx)
	if err != nil {
		t.Fatalf("GetPublished after destroy: %v", err)
	}
	for _, k := range published {
		if k.KID == oldKey.KID {
			t.Error("a retired key is still published")
		}
	}
}
